#!/usr/bin/env python3
"""Read-only NAS inventory, exact-duplicate, and optional placement audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CHUNK_SIZE = 1024 * 1024
# Set this to the NAS directory to scan; a smaller subfolder is useful for a test run.
ROOT = Path("/mnt/nas")
EXTENSIONS = {
    "photos": {".jpg", ".jpeg", ".png", ".gif", ".tif", ".tiff", ".bmp", ".heic", ".webp", ".raw", ".dng"},
    "videos": {".mp4", ".mov", ".avi", ".mkv", ".m4v", ".wmv", ".mpg", ".mpeg", ".3gp", ".mts"},
    "music": {".mp3", ".flac", ".wav", ".aac", ".m4a", ".ogg", ".wma", ".alac", ".aiff"},
    "website": {".html", ".htm", ".css", ".js", ".php", ".asp", ".aspx", ".jsp"},
    "documents": {".pdf", ".doc", ".docx", ".odt", ".txt", ".rtf", ".xls", ".xlsx", ".ppt", ".pptx"},
    "backups": {".bak", ".backup", ".dump", ".sql"},
}
FOLDER_LABELS = {
    "photos": {"photo", "photos", "picture", "pictures", "image", "images", "afbeeldingen"},
    "videos": {"video", "videos", "movie", "movies", "film", "films"},
    "music": {"music", "audio", "song", "songs"},
    "website": {"website", "websites", "web", "www", "public", "public_html", "htdocs"},
    "backups": {"backup", "backups", "back-up", "back-ups"},
    "documents": {"document", "documents", "doc", "docs"},
}


def category_for(path: str) -> str | None:
    extension = Path(path).suffix.lower()
    return next((name for name, extensions in EXTENSIONS.items() if extension in extensions), None)


def category_for_folder(name: str) -> str | None:
    words = set(re.findall(r"[a-z0-9_'-]+", name.casefold()))
    return next(
        (category for category, labels in FOLDER_LABELS.items() if words & labels),
        None,
    )


def outside_root(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return False
    except ValueError:
        return True


def jsonl_write(handle, value) -> None:
    handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")


def utc_timestamp(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc).isoformat()


def hash_file(path: Path, expected_stat: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise OSError("file type changed during scan")
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            expected_stat.st_dev, expected_stat.st_ino, expected_stat.st_size, expected_stat.st_mtime_ns
        ):
            raise OSError("file changed before hashing")
        digest = hashlib.sha256()
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise OSError("file changed while hashing")
        return digest.hexdigest()


def write_report(root: Path, output: Path, progress_every: int) -> None:
    root = root.resolve(strict=True)
    output = output.resolve()
    if not root.is_dir():
        raise ValueError(f"scan root is not a directory: {root}")
    if not outside_root(output, root):
        raise ValueError(f"report output must be outside the scan root: {root}")

    output.mkdir(parents=True, exist_ok=True)
    names = ("inventory.jsonl", "duplicate_groups.jsonl", "possible_misplacements.jsonl",
             "scan_errors.jsonl", "summary.md", "audit-index.sqlite")
    existing = [name for name in names if (output / name).exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite existing output: {', '.join(existing)}")

    database = output / "audit-index.sqlite"
    connection = sqlite3.connect(database)
    connection.executescript("""
        CREATE TABLE files (
            path TEXT PRIMARY KEY, kind TEXT NOT NULL, size INTEGER NOT NULL,
            mtime_ns INTEGER, mtime_utc TEXT, category TEXT, sha256 TEXT,
            hash_status TEXT NOT NULL, expected_category TEXT, placement_note TEXT
        );
        CREATE TABLE directories (
            path TEXT PRIMARY KEY, expected_category TEXT, label_source TEXT,
            direct_file_count INTEGER NOT NULL, categorized_file_count INTEGER NOT NULL,
            category_counts TEXT NOT NULL, finding TEXT, confidence TEXT
        );
        CREATE TABLE errors (path TEXT NOT NULL, operation TEXT NOT NULL, error TEXT NOT NULL);
        CREATE INDEX files_by_size ON files(size);
        CREATE INDEX files_by_hash ON files(sha256);
    """)

    file_count = total_bytes = directory_count = symlink_count = 0
    directory_categories = {".": category_for_folder(root.name)}
    directory_sources = {".": "." if directory_categories["."] else None}
    direct_stats: dict[str, Counter] = {".": Counter()}
    stack = [(root, directory_categories["."])]
    try:
        while stack:
            directory, inherited_category = stack.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        path = Path(entry.path)
                        relative = path.relative_to(root).as_posix()
                        try:
                            info = entry.stat(follow_symlinks=False)
                            if stat.S_ISDIR(info.st_mode):
                                directory_count += 1
                                local_category = category_for_folder(path.name)
                                expected_category = local_category or inherited_category
                                directory_categories[relative] = expected_category
                                directory_sources[relative] = (
                                    relative if local_category else
                                    directory_sources.get(directory.relative_to(root).as_posix() or ".")
                                )
                                direct_stats[relative] = Counter()
                                stack.append((path, expected_category))
                                continue
                            if stat.S_ISLNK(info.st_mode):
                                kind, size = "symlink", info.st_size
                                symlink_count += 1
                            elif stat.S_ISREG(info.st_mode):
                                kind, size = "file", info.st_size
                            else:
                                kind, size = "special", info.st_size
                            category = category_for(relative) if kind == "file" else None
                            parent = Path(relative).parent.as_posix()
                            if parent == ".":
                                parent = "."
                            if kind == "file":
                                direct_stats.setdefault(parent, Counter())["total"] += 1
                                if category:
                                    direct_stats[parent][category] += 1
                            expected_category = inherited_category if kind == "file" else None
                            note = None
                            if category and expected_category and category != expected_category:
                                note = (
                                    f"file type suggests {category}; enclosing folder names suggest "
                                    f"{expected_category}"
                                )
                            connection.execute(
                                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
                                (relative, kind, size, info.st_mtime_ns, utc_timestamp(info.st_mtime_ns),
                                 category, "not_hashed", expected_category, note),
                            )
                            file_count += 1
                            total_bytes += size
                            if progress_every and file_count % progress_every == 0:
                                print(f"Inventoried {file_count:,} entries...", file=sys.stderr)
                        except OSError as error:
                            connection.execute(
                                "INSERT INTO errors VALUES (?, ?, ?)",
                                (relative, "stat", str(error)),
                            )
            except OSError as error:
                connection.execute(
                    "INSERT INTO errors VALUES (?, ?, ?)",
                    (directory.relative_to(root).as_posix() or ".", "list_directory", str(error)),
                )
            connection.commit()

        candidate_sizes = connection.execute(
            "SELECT size FROM files WHERE kind = 'file' GROUP BY size HAVING COUNT(*) > 1"
        )
        hashed_count = 0
        for size_row in candidate_sizes:
            size = size_row[0]
            rows = connection.execute(
                "SELECT path, mtime_ns FROM files WHERE kind = 'file' AND size = ? AND sha256 IS NULL",
                (size,),
            )
            for relative, mtime_ns in rows:
                path = root / relative
                try:
                    expected = path.lstat()
                    digest = hash_file(path, expected)
                    connection.execute(
                        "UPDATE files SET sha256 = ?, hash_status = 'hashed' WHERE path = ?",
                        (digest, relative),
                    )
                except OSError as error:
                    connection.execute(
                        "UPDATE files SET hash_status = 'hash_error' WHERE path = ?", (relative,)
                    )
                    connection.execute(
                        "INSERT INTO errors VALUES (?, ?, ?)", (relative, "hash", str(error))
                    )
                hashed_count += 1
                if progress_every and hashed_count % progress_every == 0:
                    print(f"Hashed {hashed_count:,} duplicate-size candidates...", file=sys.stderr)
            connection.commit()

        with (output / "inventory.jsonl").open("x", encoding="utf-8") as inventory:
            for row in connection.execute(
                "SELECT path, kind, size, mtime_utc, category, sha256, hash_status, "
                "expected_category, placement_note "
                "FROM files ORDER BY path"
            ):
                keys = ("path", "kind", "size_bytes", "mtime_utc", "category", "sha256",
                        "hash_status", "inferred_folder_category", "placement_note")
                jsonl_write(inventory, dict(zip(keys, row)))

        with (output / "possible_misplacements.jsonl").open("x", encoding="utf-8") as findings:
            for row in connection.execute(
                "SELECT path, category, expected_category, placement_note "
                "FROM files WHERE placement_note IS NOT NULL ORDER BY path"
            ):
                jsonl_write(findings, dict(zip(
                    ("path", "file_category", "inferred_folder_category", "reason"), row
                )))

        folder_findings = 0
        for directory, expected_category in directory_categories.items():
            stats = direct_stats.get(directory, Counter())
            total = stats["total"]
            categorized_count = sum(stats[category] for category in EXTENSIONS)
            if not expected_category or not categorized_count:
                finding = confidence = None
            else:
                matching = stats[expected_category]
                matching_ratio = matching / categorized_count
                if matching_ratio < 0.5:
                    finding = (
                        f"folder name suggests {expected_category}, but only "
                        f"{matching}/{categorized_count} categorized direct files match"
                    )
                    confidence = "medium" if categorized_count >= 3 else "low"
                    folder_findings += 1
                else:
                    finding = confidence = None
            label_source = directory_sources.get(directory)
            connection.execute(
                "INSERT INTO directories VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (directory, expected_category, label_source, total, categorized_count,
                 json.dumps({category: stats[category] for category in EXTENSIONS if stats[category]},
                            sort_keys=True),
                 finding, confidence),
            )
        connection.commit()

        with (output / "folder_placement_findings.jsonl").open("x", encoding="utf-8") as findings:
            for row in connection.execute(
                "SELECT path, expected_category, label_source, direct_file_count, "
                "categorized_file_count, category_counts, finding, confidence "
                "FROM directories WHERE finding IS NOT NULL ORDER BY path"
            ):
                keys = ("folder", "inferred_category", "label_source", "direct_file_count",
                        "categorized_file_count", "file_categories", "finding", "confidence")
                record = dict(zip(keys, row))
                record["file_categories"] = json.loads(record["file_categories"])
                jsonl_write(findings, record)

        duplicate_groups = 0
        duplicate_bytes = 0
        with (output / "duplicate_groups.jsonl").open("x", encoding="utf-8") as duplicates:
            hashes = connection.execute(
                "SELECT sha256, size, COUNT(*) FROM files WHERE sha256 IS NOT NULL "
                "GROUP BY sha256, size HAVING COUNT(*) > 1 ORDER BY size DESC"
            )
            for digest, size, count in hashes:
                duplicate_groups += 1
                duplicate_bytes += size * (count - 1)
                record = {
                    "sha256": digest, "size_bytes": size, "count": count,
                    "potential_redundant_bytes": size * (count - 1),
                }
                duplicates.write(json.dumps(record, ensure_ascii=False, sort_keys=True)[:-1])
                duplicates.write(',"paths":[')
                first = True
                for (path,) in connection.execute(
                    "SELECT path FROM files WHERE sha256 = ? ORDER BY path", (digest,)
                ):
                    if not first:
                        duplicates.write(",")
                    duplicates.write(json.dumps(path, ensure_ascii=False))
                    first = False
                duplicates.write("]}\n")

        with (output / "scan_errors.jsonl").open("x", encoding="utf-8") as errors:
            for row in connection.execute("SELECT path, operation, error FROM errors ORDER BY path"):
                jsonl_write(errors, dict(zip(("path", "operation", "error"), row)))

        error_count = connection.execute("SELECT COUNT(*) FROM errors").fetchone()[0]
        misplaced_file_count = connection.execute(
            "SELECT COUNT(*) FROM files WHERE placement_note IS NOT NULL"
        ).fetchone()[0]
        nonregular_count = connection.execute(
            "SELECT COUNT(*) FROM files WHERE kind != 'file'"
        ).fetchone()[0]
        with (output / "summary.md").open("x", encoding="utf-8") as summary:
            summary.write(f"""# NAS Read-Only Audit Summary

- Scan root: `{root}`
- Completed: `{datetime.now(timezone.utc).isoformat()}`
- Regular files and other entries inventoried: {file_count:,}
- Directories inventoried: {directory_count:,}
- Symbolic links: {symlink_count:,}
- Total entry sizes (not unique storage usage): {total_bytes:,} bytes
- Files hashed because their size occurred more than once: {hashed_count:,}
- Confirmed exact duplicate groups: {duplicate_groups:,}
- Potential redundant bytes within exact duplicate groups: {duplicate_bytes:,}
- Possible misplaced-folder hints: {folder_findings:,}
- Files whose type conflicts with inferred folder category: {misplaced_file_count:,}
- Scan/hash errors: {error_count:,}
- Non-regular entries (symlinks and special files): {nonregular_count:,}

## Interpretation and limitations

- The scan only reads directory entries, metadata, and file contents for
  same-size regular-file candidates; it does not follow symbolic links.
- Exact duplicate groups require a matching SHA-256 hash and file size.
- Placement hints infer broad categories from directory names and compare them
  with direct file extensions. They are heuristic, can miss unusual naming,
  and are not proof that a folder or file is misplaced.
- Folder placement findings are based on directly contained files, not
  descendants, to avoid treating intentionally categorized subfolders as
  misplaced.
- Same-size files that could not be hashed appear in `scan_errors.jsonl` and
  are not confirmed duplicates. Other files are not hashed.
- The SQLite database and JSONL files are report outputs, not NAS changes.
- No NAS file or directory was moved, renamed, deleted, or modified by this
  program. Review `inventory.jsonl`, `duplicate_groups.jsonl`,
  `possible_misplacements.jsonl`, and `scan_errors.jsonl` for details.
""")
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only NAS inventory, exact duplicate report, and inferred placement hints."
    )
    parser.add_argument("--root", default=str(ROOT), help=f"NAS directory to inspect (default: {ROOT})")
    parser.add_argument("--output", required=True, help="new report directory outside the scanned NAS")
    parser.add_argument(
        "--progress-every", type=int, default=10000,
        help="print progress every N inventoried/hashed entries; 0 disables progress",
    )
    args = parser.parse_args()
    if args.progress_every < 0:
        parser.error("--progress-every must be zero or greater")
    try:
        write_report(Path(args.root), Path(args.output), args.progress_every)
    except (OSError, ValueError) as error:
        print(f"nas_audit: {error}", file=sys.stderr)
        return 2
    print(f"Read-only audit complete. Reports saved to: {Path(args.output).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
