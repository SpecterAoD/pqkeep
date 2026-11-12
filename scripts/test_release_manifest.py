#!/usr/bin/env python3
"""Tests für release_manifest.py und die Paket-SBOM / tests for the manifest and package SBOM.

Aufruf / usage: python3 -B -m unittest discover -s scripts -p 'test_release_*.py'
"""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import release_manifest as rm  # noqa: E402
import release_sbom as rb  # noqa: E402

VERSION, COMMIT, DEB = "1.2.3-beta.1", "a" * 40, "1.2.3~beta.1-1"
BASE = f"pqkeep-{VERSION}-"
AMD, ARM = "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"
SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"timestamp": "now"}}


def archive(target: str) -> tuple[bytes, str]:
    binary, buffer = b"\x7fELF " + target.encode(), io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(f"{BASE}{target}/pqkeep")
        info.size = len(binary)
        tar.addfile(info, io.BytesIO(binary))
    return buffer.getvalue(), hashlib.sha256(binary).hexdigest()


def tree(root: Path) -> Path:
    """Vollständige Build-Artefakte / complete build artifacts."""
    downloads = root / "downloads"
    for name, files in rm.manifest(VERSION).items():
        directory, target = downloads / name, name.removeprefix("dist-")
        directory.mkdir(parents=True)
        sbom = rb.complete(json.loads(json.dumps(SBOM)), VERSION, target, COMMIT)
        (directory / f"{BASE}{target}.cdx.json").write_text(json.dumps(sbom))
        arch = rm.TARGETS.get(target)
        if arch is None:
            (directory / f"{BASE}{target}.zip").write_bytes(b"PK zip")
            continue
        data, digest = archive(target)
        (directory / f"{BASE}{target}.tar.gz").write_bytes(data)
        (directory / f"{BASE}{arch}.deb").write_bytes(b"!<arch> " + arch.encode())
        deb_sbom = rb.for_deb(sbom, DEB, arch, digest, COMMIT)
        (directory / f"{BASE}{arch}.deb.cdx.json").write_text(json.dumps(deb_sbom))
        assert set(files) == {p.name for p in directory.iterdir()}
    return downloads


def identity(package: Path, arch: str, binary_sha256: str) -> str:
    """Ersatz für dpkg-deb: Architektur aus dem Testinhalt / stand-in for dpkg-deb."""
    if package.read_bytes() != b"!<arch> " + arch.encode():
        raise ValueError("Paketname oder Architektur falsch")
    return DEB


def bundle(root: Path) -> Path:
    dist = root / "dist"
    rm.collect(tree(root), dist, VERSION, COMMIT)
    listed = sorted(p.name for p in dist.iterdir())
    sums = "".join(f"{hashlib.sha256((dist / n).read_bytes()).hexdigest()}  {n}\n" for n in listed)
    (dist / rm.SUMS).write_text(sums)
    for name in [*rm.names(VERSION, ("archive", "deb")), rm.SUMS]:
        (dist / (name + ".sigstore.json")).write_text('{"bundle": "%s"}' % name)
    return dist


@patch.object(rm, "deb_identity", identity)
class ManifestTest(unittest.TestCase):
    def setUp(self):
        os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_manifest_lists_five_artifacts(self):
        artifacts = rm.names("0.1.0-beta.2", ("archive", "deb"))
        self.assertEqual(artifacts, {
            "pqkeep-0.1.0-beta.2-x86_64-unknown-linux-gnu.tar.gz", "pqkeep-0.1.0-beta.2-amd64.deb",
            "pqkeep-0.1.0-beta.2-aarch64-unknown-linux-gnu.tar.gz", "pqkeep-0.1.0-beta.2-arm64.deb",
            "pqkeep-0.1.0-beta.2-x86_64-pc-windows-msvc.zip"})
        self.assertEqual(len(rm.names("0.1.0-beta.2", ("sbom", "deb-sbom"))), 5)

    def test_collect_copies_complete_set(self):
        dist = self.root / "dist"
        rm.collect(tree(self.root), dist, VERSION, COMMIT)
        self.assertEqual(len(list(dist.iterdir())), 10)
        self.assertEqual(rm.main(["collect", str(self.root / "downloads"), str(dist), VERSION, COMMIT]), 1)

    def broken(self, change) -> None:
        downloads = tree(self.root)
        change(downloads, downloads / f"dist-{AMD}", downloads / f"dist-{ARM}")
        code = rm.main(["collect", str(downloads), str(self.root / "dist"), VERSION, COMMIT])
        self.assertEqual(code, 1)
        self.assertFalse((self.root / "dist").exists())
        shutil.rmtree(downloads)

    def test_collect_rejects_missing_additional_duplicate_and_misassigned(self):
        amd_deb, arm_deb = f"{BASE}amd64.deb", f"{BASE}arm64.deb"
        cases = {
            "fehlende Datei": lambda d, amd, arm: (amd / amd_deb).unlink(),
            "fehlendes Artefakt": lambda d, amd, arm: shutil.rmtree(arm),
            "zusätzliche Datei": lambda d, amd, arm: (amd / "extra.txt").write_text("x"),
            "zusätzliches Artefakt": lambda d, amd, arm: (d / "dist-extra").mkdir(),
            "Kandidat statt Release": lambda d, amd, arm: arm.rename(d / f"candidate-{ARM}"),
            "leere Datei": lambda d, amd, arm: (amd / amd_deb).write_bytes(b""),
            "Link": lambda d, amd, arm: ((amd / amd_deb).unlink(), (amd / amd_deb).symlink_to(arm / arm_deb)),
            "doppelter Inhalt": lambda d, amd, arm: shutil.copyfile(
                d / f"dist-{rm.WINDOWS}" / f"{BASE}{rm.WINDOWS}.zip", amd / "copy.zip"),
            "Paket falscher Architektur": lambda d, amd, arm: shutil.copyfile(arm / arm_deb, amd / amd_deb),
            "SBOM vertauscht": lambda d, amd, arm: shutil.copyfile(
                arm / f"{BASE}{ARM}.cdx.json", amd / f"{BASE}{AMD}.cdx.json"),
            "Paket-SBOM vertauscht": lambda d, amd, arm: shutil.copyfile(
                arm / f"{arm_deb}.cdx.json", amd / f"{amd_deb}.cdx.json"),
            "Archiv ohne Programm": lambda d, amd, arm: (amd / f"{BASE}{AMD}.tar.gz").write_bytes(
                archive("other")[0]),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.broken(change)

    def test_collect_rejects_other_commit_and_changed_binary(self):
        downloads = tree(self.root)
        self.assertEqual(rm.main(["collect", str(downloads), str(self.root / "dist"), VERSION, "b" * 40]), 1)
        with patch.object(rm, "deb_identity", side_effect=ValueError("Binary im Debian-Paket wurde verändert")):
            self.assertEqual(rm.main(["collect", str(downloads), str(self.root / "dist"), VERSION, COMMIT]), 1)
        self.assertFalse((self.root / "dist").exists())

    def test_verify_accepts_complete_bundle_only(self):
        dist = bundle(self.root)
        self.assertEqual(len(list(dist.iterdir())), 17)
        self.assertEqual(rm.main(["verify", str(dist), VERSION]), 0)
        deb, sums = dist / f"{BASE}arm64.deb", dist / rm.SUMS
        original, text = deb.read_bytes(), sums.read_text()
        changes = {
            "zusätzliche Datei": lambda: (dist / "extra").write_text("x"),
            "fehlendes Bundle": lambda: (dist / (deb.name + ".sigstore.json")).unlink(),
            "verändertes Paket": lambda: deb.write_bytes(original + b"x"),
            "Prüfsummenzeile fehlt": lambda: sums.write_text("".join(text.splitlines(True)[1:])),
            "Prüfsummenzeile zusätzlich": lambda: sums.write_text(text + "0" * 64 + "  extra\n"),
            "Prüfsummenzeile doppelt": lambda: sums.write_text(text + text.splitlines(True)[0]),
        }
        for name, change in changes.items():
            with self.subTest(name):
                saved = self.root / "saved"
                shutil.copytree(dist, saved)
                change()
                self.assertEqual(rm.main(["verify", str(dist), VERSION]), 1)
                shutil.rmtree(dist)
                saved.rename(dist)

    def test_usage(self):
        self.assertEqual(rm.main([]), 2)
        self.assertEqual(rm.main(["verify", "x"]), 2)


class DebSbomTest(unittest.TestCase):
    def test_package_sbom_has_own_identity(self):
        os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
        source = rb.complete(json.loads(json.dumps(SBOM)), VERSION, AMD, COMMIT)
        source["metadata"]["properties"] = [{"name": "cdx:x", "value": "kept"}]
        result = rb.for_deb(source, DEB, "amd64", "c" * 64, COMMIT)
        self.assertNotEqual(result["serialNumber"], source["serialNumber"])
        self.assertNotEqual(result["serialNumber"], rb.for_deb(source, DEB, "arm64", "c" * 64, COMMIT)["serialNumber"])
        self.assertEqual(result, rb.for_deb(result, DEB, "amd64", "c" * 64, COMMIT))
        self.assertEqual(result["metadata"]["properties"], [
            {"name": "cdx:x", "value": "kept"}, *rb.deb_properties(DEB, "amd64", "c" * 64)])
        self.assertEqual(source["metadata"]["properties"], [{"name": "cdx:x", "value": "kept"}])
        for bad in [(DEB, "armhf", "c" * 64), (DEB, "amd64", "C" * 64), ("../x", "amd64", "c" * 64)]:
            with self.assertRaises(ValueError):
                rb.for_deb(source, *bad, COMMIT)
        with self.assertRaises(ValueError):
            rb.for_deb({"spdxVersion": "SPDX-2.3"}, DEB, "amd64", "c" * 64, COMMIT)

    def test_cli_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = os.path.join(tmp, "a.json"), os.path.join(tmp, "b.json")
            with open(source, "w", encoding="utf-8") as f:
                json.dump(SBOM, f)
            args = ["--deb", source, out, DEB, "arm64", "d" * 64, COMMIT]
            self.assertEqual(rb.main(args), 0)
            self.assertEqual(json.load(open(out, encoding="utf-8"))["serialNumber"], rb.deb_serial(DEB, "arm64", COMMIT))
            with self.assertRaises(FileExistsError):
                rb.main(args)
            self.assertEqual(rb.main(["--deb", source]), 2)


if __name__ == "__main__":
    unittest.main()
