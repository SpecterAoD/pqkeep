#!/usr/bin/env python3
"""Tests der Hilfsfunktionen für den Paket-Lebenszyklus; keine Systeminstallation."""

from pathlib import Path
import subprocess
import tempfile
import unittest

import release_deb_fixtures as fixtures
import release_deb_lifecycle as lifecycle


def sample_package(work: Path) -> Path:
    """Kleines synthetisches Paket; wird nur gelesen und umgepackt, nie installiert."""
    tree = work / "sample"
    (tree / "usr/bin").mkdir(parents=True)
    (tree / "usr/bin/pqkeep").write_bytes(b"synthetic binary " * 4096)
    (tree / "DEBIAN").mkdir()
    (tree / "DEBIAN/control").write_text(
        "Package: pqkeep\nVersion: 0.1.0-1~ci.1\nArchitecture: all\n"
        "Maintainer: Test <test@pqkeep.invalid>\nDepends: libc6 (>= 2.34)\n"
        "Description: synthetic\n")
    for path in (tree, *tree.rglob("*")):
        path.chmod(0o755 if path.is_dir() else 0o644)
    return fixtures.build(tree, work / "sample.deb")


def contents(package: Path) -> bytes:
    return subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])


class LifecycleTests(unittest.TestCase):
    def test_state_distinguishes_installed_from_removed(self):
        self.assertEqual(lifecycle.parse_state("ii \t0.1.0-1"), ("ii", "0.1.0-1"))
        self.assertEqual(lifecycle.parse_state("iU \t0.1.0-2"), ("iU", "0.1.0-2"))
        self.assertEqual(lifecycle.parse_state("rc \t0.1.0-1"), ("rc", "0.1.0-1"))
        for removed in ("un \t", "pn \t0.1.0-1", "", "\t"):
            self.assertIsNone(lifecycle.parse_state(removed))

    def test_dpkg_options_include_files_and_parents(self):
        options = lifecycle.dpkg_includes({"usr/share/doc/pqkeep/NOTICE": b"x"})
        self.assertEqual(options, ["--path-include=/" + path for path in (
            "usr", "usr/share", "usr/share/doc", "usr/share/doc/pqkeep",
            "usr/share/doc/pqkeep/NOTICE")])

    def test_rejection_is_required(self):
        lifecycle.must_fail("scheitert", "false")
        with self.assertRaises(ValueError):
            lifecycle.must_fail("gelingt", "true")

    def test_damaged_packages_are_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            package = sample_package(work)
            original = package.read_bytes()
            damaged = fixtures.damaged(package, work)
            self.assertEqual(set(damaged), {"abgeschnitten", "verfälscht"})
            self.assertEqual(package.read_bytes(), original)
            self.assertEqual(len(damaged["verfälscht"].read_bytes()), len(original))
            for path in damaged.values():
                self.assertNotEqual(path.read_bytes(), original)
                result = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(path)], capture_output=True)
                self.assertNotEqual(result.returncode, 0, path.name)

    def test_missing_dependency_keeps_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            package = sample_package(work)
            broken = fixtures.missing_dependency(package, work)
            self.assertEqual(fixtures.field(broken, "Depends"),
                             f"libc6 (>= 2.34), {fixtures.MISSING} (>= 1)")
            for name in ("Package", "Version", "Architecture"):
                self.assertEqual(fixtures.field(broken, name), fixtures.field(package, name))
            self.assertEqual(contents(broken), contents(package))
            with self.assertRaises(FileExistsError):
                fixtures.build(work / "missing-dependency", broken)

    def test_conflict_package_owns_only_the_binary_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = fixtures.conflicting(Path(tmp))
            self.assertEqual(fixtures.field(package, "Package"), fixtures.CONFLICT)
            listing = subprocess.check_output(["dpkg-deb", "--contents", str(package)], text=True)
            files = [line.split()[-1] for line in listing.splitlines() if line.startswith("-")]
            self.assertEqual(files, ["./usr/bin/pqkeep"])
            self.assertIn("root/root", listing)


if __name__ == "__main__":
    unittest.main()
