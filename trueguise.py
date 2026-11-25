#!/usr/bin/env python3
"""TrueGuise — audit a file tree for files whose bytes disagree with their names.

Reads only header bytes (and, for ZIP containers, the central-directory
entry names), identifies each file's real format from its signature,
and reports where the extension lies — including the high-severity
case of an executable wearing a document's name. Read-only: it never
renames, converts, repairs, or executes anything.
"""
import argparse
import io
import json
import os
import sys
import zipfile
from pathlib import Path

VERSION = "1.0.0"
HEADER_BYTES = 1024

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

# type -> (expected extensions, is_executable)
TYPES = {
    "png": ({".png"}, False),
    "jpeg": ({".jpg", ".jpeg"}, False),
    "gif": ({".gif"}, False),
    "pdf": ({".pdf"}, False),
    "zip": ({".zip"}, False),
    "docx": ({".docx"}, False),
    "xlsx": ({".xlsx"}, False),
    "pptx": ({".pptx"}, False),
    "epub": ({".epub"}, False),
    "jar": ({".jar", ".war", ".ear"}, False),
    "apk": ({".apk"}, False),
    "odp": ({".odp"}, False),
    "ods": ({".ods"}, False),
    "ott": ({".ott"}, False),
    "gzip": ({".gz", ".tgz"}, False),
    "bzip2": ({".bz2", ".tbz2"}, False),
    "xz": ({".xz", ".txz"}, False),
    "zstd": ({".zst"}, False),
    "7z": ({".7z"}, False),
    "rar": ({".rar"}, False),
    "elf": ({".exe", ".dll", ".scr", ".com", ".so", ".dylib", ".elf"}, True),
    "pe": ({".exe", ".dll", ".scr", ".com", ".so", ".dylib", ".elf"}, True),
    "macho": ({".exe", ".dll", ".scr", ".com", ".so", ".dylib", ".elf"}, True),
    "sqlite": ({".db", ".sqlite", ".sqlite3"}, False),
    "webp": ({".webp"}, False),
    "wav": ({".wav"}, False),
    "avi": ({".avi"}, False),
    "mp3": ({".mp3"}, False),
    "flac": ({".flac"}, False),
    "ogg": ({".ogg", ".oga", ".ogv", ".opus"}, False),
    "mp4": ({".mp4", ".m4v"}, False),
    "m4a": ({".m4a"}, False),
    "mov": ({".mov"}, False),
    "heic": ({".heic", ".heix"}, False),
    "avif": ({".avif"}, False),
    "bmp": ({".bmp"}, False),
    "tar": ({".tar"}, False),
}

EXECUTABLE_EXTS = {".exe", ".dll", ".scr", ".com", ".so", ".dylib", ".elf"}

TEXT_EXTS = {
    ".txt", ".md", ".py", ".json", ".jsonl", ".ndjson", ".csv", ".tsv",
    ".xml", ".html", ".htm", ".css", ".js", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".log", ".sh", ".c", ".h", ".java", ".rs", ".go",
}

# every extension claimed by some known binary type
BINARY_EXTS = set()
for _exts, _is_exec in TYPES.values():
    BINARY_EXTS |= _exts
BINARY_EXTS -= TEXT_EXTS


def detect_zip_subtype(path):
    """Return the ZIP subtype for a file, from entry names / mimetype."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            name_set = set(names)
            if "mimetype" in name_set:
                try:
                    content = zf.read("mimetype")[:128].decode("ascii", "replace").strip()
                except Exception:
                    content = ""
                if content == "application/epub+zip":
                    return "epub"
                if content.startswith("application/vnd.oasis.opendocument."):
                    kind = content.rsplit(".", 1)[-1]
                    if kind == "presentation":
                        return "odp"
                    if kind == "spreadsheet":
                        return "ods"
                    if kind == "text":
                        return "ott"
            if any(n.startswith("word/") for n in names):
                return "docx"
            if any(n.startswith("xl/") for n in names):
                return "xlsx"
            if any(n.startswith("ppt/") for n in names):
                return "pptx"
            if "AndroidManifest.xml" in name_set:
                return "apk"
            if "META-INF/MANIFEST.MF" in name_set:
                return "jar"
    except Exception:
        return "zip"
    return "zip"


def detect(header, size, path):
    """Identify the real type from header bytes. Returns a type name."""
    h = header
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if h.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if h.startswith(b"GIF87a") or h.startswith(b"GIF89a"):
        return "gif"
    if h.startswith(b"%PDF-"):
        return "pdf"
    if h.startswith(b"PK\x03\x04") or h.startswith(b"PK\x05\x06") or h.startswith(b"PK\x07\x08"):
        return detect_zip_subtype(path)
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"BZh"):
        return "bzip2"
    if h.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if h.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if h.startswith(b"\x7fELF"):
        return "elf"
    if h.startswith(b"MZ"):
        return "pe"
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                 b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                 b"\xca\xfe\xba\xbe"):
        return "macho"
    if h.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if len(h) >= 12 and h[:4] == b"RIFF":
        form = h[8:12]
        if form == b"WEBP":
            return "webp"
        if form == b"WAVE":
            return "wav"
        if form == b"AVI ":
            return "avi"
    if h.startswith(b"ID3") or (len(h) >= 2 and h[0] == 0xFF and h[1] in (0xFB, 0xF3, 0xF2)):
        return "mp3"
    if h.startswith(b"fLaC"):
        return "flac"
    if h.startswith(b"OggS"):
        return "ogg"
    if len(h) >= 12 and h[4:8] == b"ftyp":
        brand = h[8:12].decode("ascii", "replace")
        if brand in ("isom", "iso2", "mp41", "mp42", "avc1", "M4V "):
            return "mp4"
        if brand == "M4A ":
            return "m4a"
        if brand == "qt  ":
            return "mov"
        if brand in ("heic", "heix", "heim", "heis"):
            return "heic"
        if brand in ("avif", "avis"):
            return "avif"
        return "mp4"
    if h.startswith(b"BM") and len(h) >= 6:
        declared = int.from_bytes(h[2:6], "little")
        if declared == size:
            return "bmp"
    if len(h) >= 262 and h[257:262] == b"ustar":
        return "tar"
    if b"\x00" not in h:
        try:
            h.decode("utf-8")
            return "text"
        except UnicodeDecodeError:
            pass
    return "unknown"


def audit_file(path, display):
    """Return (detected, extension, findings list) for one file."""
    findings = []
    ext = Path(path).suffix.lower()
    try:
        size = os.path.getsize(path)
    except OSError:
        return "unknown", ext, findings, True
    if size == 0:
        findings.append(("empty-file", "medium", "file is empty"))
        return "empty", ext, findings, False
    try:
        with open(path, "rb") as fh:
            header = fh.read(HEADER_BYTES)
    except OSError:
        return "unknown", ext, findings, True
    detected = detect(header, size, path)
    if detected == "unknown":
        findings.append(("unknown-type", "low", "no known signature, not text"))
    elif detected == "text":
        if ext and ext in BINARY_EXTS:
            findings.append((
                "text-mismatch", "medium",
                f"file is text but extension '{ext}' claims a binary format"))
    else:
        expected, is_exec = TYPES[detected]
        if not ext:
            if detected not in ("elf", "macho"):
                findings.append((
                    "missing-extension", "low",
                    f"detected {detected}, no extension"))
        elif ext not in expected:
            if is_exec:
                findings.append((
                    "disguised-executable", "high",
                    f"detected {detected} wears extension '{ext}'"))
            else:
                expected_str = "/".join(sorted(expected))
                findings.append((
                    "extension-mismatch", "medium",
                    f"detected {detected}, expected one of {expected_str}, found '{ext}'"))
    return detected, ext, findings, False


def scan(roots):
    files = []      # (display, detected, extension)
    findings = []   # (path, rule, severity, detail)
    counts = {"dirs_scanned": 0, "files_matched": 0, "files_identified": 0,
              "links_skipped": 0, "errors": 0}

    def examine(full, display):
        detected, ext, fnds, had_error = audit_file(full, display)
        if had_error:
            counts["errors"] += 1
            return
        counts["files_matched"] += 1
        if detected not in ("unknown", "empty"):
            counts["files_identified"] += 1
        files.append((display, detected, ext))
        for rule, severity, detail in fnds:
            findings.append((display, rule, severity, detail))

    for root in roots:
        p = Path(root)
        if p.is_symlink():
            counts["links_skipped"] += 1
            continue
        if p.is_file():
            examine(str(p), str(p))
        elif p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
                counts["dirs_scanned"] += 1
                dirnames.sort()
                kept = []
                for d in dirnames:
                    if os.path.islink(os.path.join(dirpath, d)):
                        counts["links_skipped"] += 1
                    else:
                        kept.append(d)
                dirnames[:] = kept
                for name in sorted(filenames):
                    full = os.path.join(dirpath, name)
                    if os.path.islink(full):
                        counts["links_skipped"] += 1
                        continue
                    if not os.path.isfile(full):
                        continue
                    examine(full, full)
        else:
            return None
    files.sort()
    findings.sort(key=lambda f: (f[0], f[1], f[3]))
    return files, findings, counts


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="trueguise",
        description="Audit a file tree for files whose bytes disagree with their names.")
    parser.add_argument("--version", action="version", version=f"trueguise {VERSION}")
    sub = parser.add_subparsers(dest="command")
    scan_p = sub.add_parser("scan", help="scan one or more files or directories")
    scan_p.add_argument("paths", nargs="+")
    scan_p.add_argument("--json", action="store_true")
    scan_p.add_argument("--min-severity", choices=["low", "medium", "high"], default="low")
    scan_p.add_argument("--fail-on", choices=["low", "medium", "high", "never"], default="high")
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_usage(sys.stderr)
        return 2
    for root in args.paths:
        p = Path(root)
        if p.is_symlink():
            continue
        if not p.is_file() and not p.is_dir():
            print(f"trueguise: scan root not found or not a file/directory: {root}",
                  file=sys.stderr)
            return 2
    result = scan(args.paths)
    if result is None:
        print("trueguise: scan failed", file=sys.stderr)
        return 2
    files, findings, counts = result
    min_rank = SEVERITY_ORDER[args.min_severity]
    shown = [f for f in findings if SEVERITY_ORDER[f[2]] >= min_rank]
    sev_counts = {"high": 0, "medium": 0, "low": 0}
    for f in shown:
        sev_counts[f[2]] += 1
    if args.json:
        payload = {
            "tool": "trueguise",
            "version": VERSION,
            "roots": list(args.paths),
            "counts": {
                "dirs_scanned": counts["dirs_scanned"],
                "files_matched": counts["files_matched"],
                "files_identified": counts["files_identified"],
                "findings": len(shown),
                "high": sev_counts["high"],
                "medium": sev_counts["medium"],
                "low": sev_counts["low"],
                "links_skipped": counts["links_skipped"],
                "errors": counts["errors"],
            },
            "files": [
                {"path": path, "detected": detected, "extension": ext}
                for path, detected, ext in files
            ],
            "findings": [
                {"path": path, "rule": rule, "severity": severity, "detail": detail}
                for path, rule, severity, detail in shown
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for path, rule, severity, detail in shown:
            print(f"{severity.upper()} {rule} {path} [{detail}]")
        for path, detected, ext in files:
            print(f"file {path}: {detected}")
        print(f"trueguise: {counts['dirs_scanned']} dirs scanned, "
              f"{counts['files_matched']} files matched, "
              f"{counts['files_identified']} files identified, "
              f"{len(shown)} findings ({sev_counts['high']} high, "
              f"{sev_counts['medium']} medium, {sev_counts['low']} low), "
              f"{counts['links_skipped']} links skipped, "
              f"{counts['errors']} errors")
    if args.fail_on == "never":
        return 0
    fail_rank = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f[2]] >= fail_rank for f in shown) else 0


if __name__ == "__main__":
    sys.exit(main())
