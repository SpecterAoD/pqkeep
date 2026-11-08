"""DE: R14: prüft Nachverfolgbarkeit und lokale Referenzen des Entwurfs.
EN: R14: checks traceability and local references of the draft.
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ("U0-1.md", "U0-1_FORMAT.md", "U0-1_PROVIDERS.md", "U0-1_TESTS.md")


class FactorDocumentationTests(unittest.TestCase):
    def test_R14_catalogue_and_links(self):
        catalogue = (ROOT / "docs/U0-1_TESTS.md").read_text(encoding="utf-8")
        rows = [line.split("|")[1:-1] for line in catalogue.splitlines()
                if re.match(r"\| [RCTFWUS]\d{2} \|", line)]
        identifiers = []
        for row in rows:
            self.assertEqual(len(row), 5)
            identifier, case, expected, phase, status = (value.strip() for value in row)
            self.assertTrue(case and expected)
            self.assertIn(phase, ("#39", "#40", "#41", "simulator"))
            self.assertEqual(status, "reference" if phase == "#39" else "planned")
            identifiers.append(identifier)
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual(set(identifiers), {
            f"{prefix}{index:02}" for prefix, count in
            (("R", 14), ("C", 18), ("T", 5), ("F", 9), ("W", 5), ("U", 7), ("S", 3))
            for index in range(1, count + 1)
        })
        test_text = "\n".join(path.read_text(encoding="utf-8")
                              for path in (ROOT / "scripts").glob("test_factor_spec*.py"))
        for index in range(1, 15):
            self.assertRegex(test_text, rf"def test_R{index:02}_")
        for name in DOCS:
            text = (ROOT / "docs" / name).read_text(encoding="utf-8")
            self.assertIn("DE:", text)
            self.assertIn("EN:", text)
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if not target.startswith(("https://", "#")):
                    with self.subTest(document=name, target=target):
                        self.assertTrue((ROOT / "docs" / target.split("#")[0]).is_file())

    def test_recovery_documented_size_matches_grammar(self):
        text = (ROOT / "docs/U0-1_FORMAT.md").read_text(encoding="utf-8")
        expected_length = len(b"PQKEEP-RECOVERY-1:") + 44 + 1
        self.assertIn(f"Exakt {expected_length} Bytes", text)
        self.assertIn(f"Exactly {expected_length} bytes", text)


if __name__ == "__main__":
    unittest.main()
