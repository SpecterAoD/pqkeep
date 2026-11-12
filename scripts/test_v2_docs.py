#!/usr/bin/env python3
"""V10: Testkatalog und Links in docs/V2_DRAFT.md und docs/V2_TESTS.md / catalogue and links."""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ("docs/V2_DRAFT.md", "docs/V2_TESTS.md")


class V2DocTests(unittest.TestCase):
    def test_V10_catalogue_and_links(self):
        rows = re.findall(r"^\| ([A-Z]\d\d) \|.*\| (reference|core|planned) \|$",
                          (ROOT / "docs/V2_TESTS.md").read_text(encoding="utf-8"), re.M)
        ids = [r[0] for r in rows]
        self.assertEqual(len(ids), len(set(ids)), "doppelte IDs / duplicate IDs")
        reference = {i for i, status in rows if status == "reference"}
        tests = "".join((ROOT / "scripts" / n).read_text(encoding="utf-8")
                        for n in ("test_v2_spec.py", "test_v2_vectors.py", "test_v2_docs.py"))
        for case in reference:
            self.assertIn(f"test_{case}_", tests, case)
        # DE: `core`-Zeilen müssen in einem Rust-Test genannt sein. EN: `core` rows need a Rust test.
        rust = "".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / "tests").glob("*.rs")))
        for case in (i for i, status in rows if status == "core"):
            self.assertIn(case, rust, case)
        for doc in DOCS:
            text = (ROOT / doc).read_text(encoding="utf-8")
            for link in re.findall(r"\]\(([^)#:]+)(?:#[^)]*)?\)", text):
                self.assertTrue((ROOT / "docs" / link).exists(), f"{doc}: {link}")


if __name__ == "__main__":
    unittest.main()
