#!/usr/bin/env python3
"""Tests for trueguise.py — synthetic byte fixtures only."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE / "trueguise.py"
sys.path.insert(0, str(HERE))
import trueguise  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
GIF = b"GIF89a" + b"\x00" * 32
PDF = b"%PDF-1.7\n" + b"\x00" * 32
GZIP = b"\x1f\x8b\x08" + b"\x00" * 32
ELF = b"\x7fELF" + b"\x00" * 32
PE = b"MZ" + b"\x00" * 32
SQLITE = b"SQLite format 3\x00" + b"\x00" * 32
TEXT = b"just some plain text\nwith two lines\n"


def make_zip(path, names, mimetype=None):
    with zipfile.ZipFile(path, "w") as zf:
        if mimetype is not None:
            zf.writestr("mimetype", mimetype)
        for n in names:
            zf.writestr(n, b"x")


def run_cli(*argv):
    return subprocess.run(
        [sys.executable, str(TOOL), *argv],
        capture_output=True, text=True)


class TrueGuiseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, data):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def scan_json(self, *paths, extra=()):
        r = run_cli("scan", *[str(p) for p in paths], "--json", *extra)
        return r, json.loads(r.stdout)

    # --- happy paths: no findings -------------------------------------
    def test_matching_png_clean(self):
        self.write("a.png", PNG)
        r, data = self.scan_json(self.root)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["files"][0]["detected"], "png")

    def test_matching_jpeg_both_extensions(self):
        self.write("a.jpg", JPEG)
        self.write("b.jpeg", JPEG)
        r, data = self.scan_json(self.root)
        self.assertEqual(data["findings"], [])

    def test_text_file_clean(self):
        self.write("notes.txt", TEXT)
        self.write("code.py", b"print('hi')\n")
        r, data = self.scan_json(self.root)
        self.assertEqual(data["findings"], [])

    def test_extensionless_elf_is_normal(self):
        self.write("mytool", ELF)
        r, data = self.scan_json(self.root)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["files"][0]["detected"], "elf")

    def test_docx_subtype_matches(self):
        make_zip(self.root / "report.docx", ["word/document.xml"])
        r, data = self.scan_json(self.root)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["files"][0]["detected"], "docx")

    def test_epub_subtype_matches(self):
        make_zip(self.root / "book.epub", ["META-INF/container.xml"],
                 mimetype="application/epub+zip")
        r, data = self.scan_json(self.root)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["files"][0]["detected"], "epub")

    # --- findings ------------------------------------------------------
    def test_disguised_executable_high_and_exit_1(self):
        self.write("invoice.pdf", PE)
        r, data = self.scan_json(self.root)
        self.assertEqual(r.returncode, 1)
        f = data["findings"][0]
        self.assertEqual(f["rule"], "disguised-executable")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["detail"], "detected pe wears extension '.pdf'")

    def test_disguised_elf_as_image(self):
        self.write("photo.png", ELF)
        r, data = self.scan_json(self.root)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(data["findings"][0]["rule"], "disguised-executable")

    def test_extension_mismatch_medium_exit_0_by_default(self):
        self.write("picture.png", JPEG)
        r, data = self.scan_json(self.root)
        self.assertEqual(r.returncode, 0)
        f = data["findings"][0]
        self.assertEqual(f["rule"], "extension-mismatch")
        self.assertEqual(
            f["detail"],
            "detected jpeg, expected one of .jpeg/.jpg, found '.png'")

    def test_docx_named_zip_is_mismatch(self):
        make_zip(self.root / "bundle.zip", ["word/document.xml"])
        r, data = self.scan_json(self.root)
        f = data["findings"][0]
        self.assertEqual(f["rule"], "extension-mismatch")
        self.assertIn("detected docx", f["detail"])

    def test_plain_zip_named_docx_is_mismatch(self):
        make_zip(self.root / "fake.docx", ["readme.txt"])
        r, data = self.scan_json(self.root)
        self.assertEqual(data["files"][0]["detected"], "zip")
        self.assertEqual(data["findings"][0]["rule"], "extension-mismatch")

    def test_text_in_binary_clothes(self):
        self.write("fake.png", TEXT)
        r, data = self.scan_json(self.root)
        f = data["findings"][0]
        self.assertEqual(f["rule"], "text-mismatch")
        self.assertEqual(
            f["detail"],
            "file is text but extension '.png' claims a binary format")

    def test_missing_extension_low(self):
        self.write("download", PNG)
        r, data = self.scan_json(self.root)
        f = data["findings"][0]
        self.assertEqual(f["rule"], "missing-extension")
        self.assertEqual(f["detail"], "detected png, no extension")

    def test_unknown_type_low(self):
        self.write("blob.bin", bytes(range(256)) * 2)
        r, data = self.scan_json(self.root)
        self.assertEqual(data["findings"][0]["rule"], "unknown-type")
        self.assertEqual(data["counts"]["files_identified"], 0)

    def test_empty_file_medium(self):
        self.write("zero.dat", b"")
        r, data = self.scan_json(self.root)
        self.assertEqual(data["files"][0]["detected"], "empty")
        self.assertEqual(data["findings"][0]["rule"], "empty-file")

    def test_sqlite_and_gzip_detected(self):
        self.write("data.db", SQLITE)
        self.write("pack.tar.gz", GZIP)
        r, data = self.scan_json(self.root)
        kinds = {f["path"].split("/")[-1]: f["detected"] for f in data["files"]}
        self.assertEqual(kinds["data.db"], "sqlite")
        self.assertEqual(kinds["pack.tar.gz"], "gzip")
        self.assertEqual(data["findings"], [])

    def test_bmp_requires_size_match(self):
        good = b"BM" + (58).to_bytes(4, "little") + b"\x00" * 52
        self.write("img.bmp", good)
        self.write("notbmp.bmp", b"BM" + b"\xff" * 20)
        r, data = self.scan_json(self.root)
        kinds = {f["path"].split("/")[-1]: f["detected"] for f in data["files"]}
        self.assertEqual(kinds["img.bmp"], "bmp")
        self.assertNotEqual(kinds["notbmp.bmp"], "bmp")

    def test_tar_detected_by_ustar(self):
        buf = bytearray(512)
        buf[257:262] = b"ustar"
        self.write("arch.tar", bytes(buf))
        r, data = self.scan_json(self.root)
        self.assertEqual(data["files"][0]["detected"], "tar")
        self.assertEqual(data["findings"], [])

    # --- gating / filtering -------------------------------------------
    def test_fail_on_medium_exits_1_on_mismatch(self):
        self.write("picture.png", JPEG)
        r = run_cli("scan", str(self.root), "--fail-on", "medium")
        self.assertEqual(r.returncode, 1)

    def test_fail_on_never_exits_0_on_disguise(self):
        self.write("invoice.pdf", PE)
        r = run_cli("scan", str(self.root), "--fail-on", "never")
        self.assertEqual(r.returncode, 0)

    def test_min_severity_hides_low(self):
        self.write("download", PNG)
        r, data = self.scan_json(self.root, extra=("--min-severity", "medium"))
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["counts"]["findings"], 0)

    # --- walking / errors ----------------------------------------------
    def test_symlink_never_followed(self):
        target = self.write("real.png", PNG)
        os.symlink(target, self.root / "link.png")
        r, data = self.scan_json(self.root)
        self.assertEqual(data["counts"]["links_skipped"], 1)
        self.assertEqual(data["counts"]["files_matched"], 1)

    def test_missing_root_exit_2_no_traceback(self):
        r = run_cli("scan", str(self.root / "nope"))
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("Traceback", r.stderr)

    def test_explicit_file_root(self):
        p = self.write("one.gif", GIF)
        r, data = self.scan_json(p)
        self.assertEqual(data["counts"]["files_matched"], 1)
        self.assertEqual(data["files"][0]["detected"], "gif")

    # --- output shape ----------------------------------------------------
    def test_text_summary_line(self):
        self.write("a.png", PNG)
        r = run_cli("scan", str(self.root))
        self.assertIn(
            "trueguise: 1 dirs scanned, 1 files matched, 1 files identified, "
            "0 findings (0 high, 0 medium, 0 low), 0 links skipped, 0 errors",
            r.stdout)
        self.assertIn("file ", r.stdout)

    def test_determinism_two_json_runs_identical(self):
        self.write("b.png", JPEG)
        self.write("a.pdf", PE)
        r1 = run_cli("scan", str(self.root), "--json")
        r2 = run_cli("scan", str(self.root), "--json")
        self.assertEqual(r1.stdout, r2.stdout)

    def test_read_only_scan_changes_nothing(self):
        p = self.write("invoice.pdf", PE)
        before = p.read_bytes()
        before_names = sorted(os.listdir(self.root))
        run_cli("scan", str(self.root))
        self.assertEqual(p.read_bytes(), before)
        self.assertEqual(sorted(os.listdir(self.root)), before_names)

    def test_version(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("1.0.0", r.stdout)


if __name__ == "__main__":
    unittest.main()
