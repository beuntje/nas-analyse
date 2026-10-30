# NAS Read-Only File Audit

## Goal

Produce a report describing duplicate files, potentially misplaced files, and
other organization issues across the NAS. This is an inspection and
documentation task only.

## Strict read-only boundary

- Do not move, rename, delete, overwrite, edit, or reorganize any NAS files or
  directories.
- Do not create scan output, temporary files, indexes, or other artifacts on
  the NAS. Save the final report outside the scanned NAS locations.
- Use read-only listing, metadata inspection, and content hashing. Do not run
  tools with cleanup, repair, tagging, normalization, or automatic
  deduplication options.
- Do not alter permissions, ownership, timestamps, links, snapshots, backup
  jobs, or application configuration.
- If a scan method cannot be confirmed read-only, do not use it; document the
  limitation in the report.

## Running the audit

The accompanying `nas_audit.py` script runs on the server that can read the
NAS. Set `ROOT` near the top of the script to the NAS directory or a smaller
subfolder for a test scan. The command-line `--root` option can override it.
The script only reads NAS metadata and contents; report files are written to
a new directory outside the scan root. It never follows symbolic links and
only hashes regular files whose size is shared by at least one other file.

Example (replace paths with the actual NAS mount and a local report location):

```sh
python3 nas_audit.py \
  --output /var/tmp/nas-audit-2026-10-30
```

To override the configured root for one run:

```sh
python3 nas_audit.py --root /mnt/nas/small-test-folder \
  --output /var/tmp/nas-audit-test
```

The output directory must be outside the scanned NAS tree and must not already
contain this audit's output files. Start with a representative subset if the
NAS is exceptionally large, and allow for a potentially long read-only scan.
The server account needs read/list access to the paths being audited.

## Audit steps

1. **Inventory:** Read the shares and directory structure, recording paths,
   file counts, sizes, and available timestamps. Note relevant categories such
   as website files, backups, photos, videos, music, documents, and archives.
2. **Exact duplicates:** Identify candidate groups by size, then compare
   content using a strong hash (such as SHA-256). Record the hash and every
   matching path. Names and sizes alone are not proof of a duplicate.
3. **Similar or versioned files:** Where read-only tools permit, identify
   likely variants such as resized or re-encoded media and similarly named
   revisions. Mark these as review candidates, not confirmed duplicates.
4. **Potentially misplaced files and folders:** Infer broad categories from
   folder names and file extensions. Compare a folder's inferred category with
   the types of files directly inside it; flag mismatches as low- or
   medium-confidence review suggestions, not definitive judgments. Also mark
   individual files whose extension category conflicts with their enclosing
   folder's inferred category. No expected paths need to be configured.
5. **Exceptions and uncertainty:** Mark intentional-looking copies (including
   backup generations), inaccessible or encrypted content, special files, and
   any paths not scanned. Do not inspect or alter application-managed data in
   ways that could affect its operation.
6. **Document findings:** Review the generated summary and structured outputs.
   The JSONL files are suitable for filtering or selected LLM investigation;
   they may contain private filenames and directory structure, so do not send
   them to an external service without authorization.

## Report contents

- **Confirmed exact duplicates:** group identifier/hash, file size, all paths,
  and estimated redundant bytes. Note that identical content may still be an
  intentional backup or required copy.
- **Possible variants:** paths and the basis for similarity, clearly separated
  from exact matches.
- **Potentially misplaced items:** current path, observed category or context,
  and reason for flagging.
- **Inventory summary:** scanned locations, counts, sizes, and excluded or
  unreadable locations.
- **Limitations:** any checks that could not be performed and any conclusions
  that need human context.

The script produces `summary.md`, `inventory.jsonl`, `duplicate_groups.jsonl`,
`possible_misplacements.jsonl`, `folder_placement_findings.jsonl`,
`scan_errors.jsonl`, and `audit-index.sqlite`.
The SQLite database is useful for querying large inventories without loading
the full dataset into memory. The JSONL files are structured, line-oriented
records; an LLM should receive only the relevant, reviewed subset rather than
the entire inventory when it is very large. Folder-placement results are
heuristic: a folder may be intentionally mixed, and folder names can be
ambiguous or misleading.

The report is informational only. It must not include or trigger a move,
rename, delete, link, cleanup, or other change to NAS data.
