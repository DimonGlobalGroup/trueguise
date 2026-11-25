# TrueGuise

**Audit a file tree for files whose bytes disagree with their names.**

Every operating system decides what opens a file by its extension —
and extensions lie. Sometimes it's an accident: a JPEG saved as
`.png`, a DOCX renamed to `.zip`. Sometimes it's the classic
disguise: an executable wearing a document's name. TrueGuise walks
a whole tree, reads only each file's header bytes, identifies what
each file *really* is from its signature, and reports every
disagreement in one deterministic pass — with the dangerous case,
a disguised executable, as its own high-severity finding.

Read-only by design: TrueGuise never renames, converts, repairs,
or executes anything. It is a gate, not a fixer.

## Install

Single file, Python 3.10+, standard library only. No dependencies,
no network, no telemetry.

```sh
cp trueguise.py ~/bin/        # or anywhere on your PATH
```

## Usage

```sh
python3 trueguise.py scan PATH [PATH ...] [--json] \
    [--min-severity low|medium|high] \
    [--fail-on low|medium|high|never]
```

Each `PATH` may be a regular file or a directory (walked
recursively, in sorted order; symlinks are counted and never
followed). For ZIP containers, TrueGuise also reads the
central-directory entry *names* — never extracting anything — so
a DOCX, XLSX, PPTX, EPUB, JAR, or APK is told apart from a plain
ZIP instead of being flattened into "ZIP, fine".

### Example

A folder with a JPEG named `.png` and a Windows executable named
`.pdf`:

```
$ python3 trueguise.py scan /tmp/tg-demo
HIGH disguised-executable /tmp/tg-demo/invoice.pdf [detected pe wears extension '.pdf']
MEDIUM extension-mismatch /tmp/tg-demo/photo.png [detected jpeg, expected one of .jpeg/.jpg, found '.png']
file /tmp/tg-demo/invoice.pdf: pe
file /tmp/tg-demo/notes.txt: text
file /tmp/tg-demo/photo.png: jpeg
trueguise: 1 dirs scanned, 3 files matched, 3 files identified, 2 findings (1 high, 1 medium, 0 low), 0 links skipped, 0 errors
```

Exit code is `1` here because a high-severity finding meets the
default `--fail-on high` gate.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `disguised-executable` | high | An ELF, PE, or Mach-O executable under a non-executable extension |
| `extension-mismatch` | medium | Detected format's expected extensions don't include the file's |
| `text-mismatch` | medium | The file is plain text but its extension claims a binary format |
| `empty-file` | medium | The file is zero bytes |
| `missing-extension` | low | A known binary format with no extension (extensionless ELF/Mach-O is normal and not flagged) |
| `unknown-type` | low | No known signature, and not text |

Formats detected: PNG, JPEG, GIF, PDF, ZIP with subtypes (DOCX,
XLSX, PPTX, EPUB, JAR, APK, ODP, ODS, OTT), gzip, bzip2, xz, zstd,
7z, RAR, ELF, PE, Mach-O (including fat binaries), SQLite, WebP,
WAV, AVI, MP3, FLAC, Ogg, ISO-BMFF (MP4, M4A, MOV, HEIC, AVIF),
BMP (with the header size cross-checked against the real size),
TAR, and plain text.

## Exit codes

- `0` — no finding at or above `--fail-on` (default: `high`)
- `1` — at least one finding at or above `--fail-on`
- `2` — usage error or a scan root that doesn't exist

`--min-severity` filters findings from the report and the exit
decision; `--json` emits the same report as stable JSON for
pipelines. Output is deterministic: two runs over the same tree
produce byte-identical reports.

## What it is not

- Not a malware scanner. A signature says what a file *is*, never
  whether it is safe. A correctly-named executable can still be
  hostile, and a mismatched one can be an innocent rename.
- Not a validator. It reads headers, not whole structures; a file
  can carry a perfect PNG signature and still be corrupt later.
- Not a fixer. Renaming is your call, with the report in hand.

## Tests

```sh
python3 -m unittest test_trueguise -v
```

28 tests over synthetic byte fixtures: every rule, ZIP subtyping,
the BMP size cross-check, gating thresholds, symlink handling,
determinism, and a read-only proof (scanned bytes and directory
contents identical before and after).

## License

MIT — see `LICENSE`. © 2026 Dimon Global Group.
