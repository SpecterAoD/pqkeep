#!/usr/bin/env python3
"""Tests für release_package.py und release_smoke.py / tests for the release scripts.

DE: Prüft Archivnamen, Inhalt und Reproduzierbarkeit (zweimal packen = bitgleich) für tar.gz und
    zip sowie die Trockenlauf-Ausgabe des Rauchtests. Aufruf: python3 scripts/test_release_scripts.py
EN: Checks archive names, content and reproducibility (packing twice = bit-identical) for tar.gz
    and zip, and the smoke test dry run. Usage: python3 scripts/test_release_scripts.py
"""

import hashlib
import os
import sys
import tarfile
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import release_package as rp  # noqa: E402
import release_smoke as rs  # noqa: E402
import release_sbom as rb  # noqa: E402


def digest(path: str) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def pack(binary: str, target: str, out: str) -> str:
    assert rp.main([binary, "1.2.3-beta.1", target, out]) == 0
    return os.path.join(out, rp.archive_name("1.2.3-beta.1", target))


def test_names() -> None:
    assert rp.archive_name("0.1.0", "x86_64-unknown-linux-gnu") == "pqkeep-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
    assert rp.archive_name("0.1.0", "x86_64-pc-windows-msvc") == "pqkeep-0.1.0-x86_64-pc-windows-msvc.zip"


def test_reproducible_and_content() -> None:
    os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
    with tempfile.TemporaryDirectory() as tmp:
        for target, exe in [("x86_64-unknown-linux-gnu", "pqkeep"), ("x86_64-pc-windows-msvc", "pqkeep.exe")]:
            binary = os.path.join(tmp, exe)
            with open(binary, "wb") as f:
                f.write(b"\x7fELF fake binary")
            extra = ["pqkeepw.exe"] if "windows" in target else []
            for name in extra:
                with open(os.path.join(tmp, name), "wb") as f:
                    f.write(b"MZ fake launcher")
            a = pack(binary, target, os.path.join(tmp, "a"))
            b = pack(binary, target, os.path.join(tmp, "b"))
            assert digest(a) == digest(b), f"nicht reproduzierbar / not reproducible: {target}"
            prefix = f"pqkeep-1.2.3-beta.1-{target}/"
            if a.endswith(".zip"):
                names = zipfile.ZipFile(a).namelist()
            else:
                with tarfile.open(a) as t:
                    names = t.getnames()
                    assert all(m.uid == 0 and m.mtime == 1700000000 for m in t.getmembers())
            expected = [exe, *extra, "LICENSE", "NOTICE", "README.md", "LICENSES-wordlists.md"]
            assert sorted(names) == sorted(prefix + n for n in expected), names


def test_sbom_completion() -> None:
    import json
    os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "x.cdx.json")
        for _ in range(2):
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"timestamp": "now"}}, open(path, "w"))
            assert rb.main([path, "1.0.0", "t", "abc123"]) == 0
            d = json.load(open(path))
            assert d["serialNumber"].startswith("urn:uuid:") and d["metadata"]["timestamp"] == "2023-11-14T22:13:20Z"
        assert rb.serial("1.0.0", "t", "abc123") == d["serialNumber"]
        assert rb.serial("1.0.0", "t", "abc124") != d["serialNumber"]
        json.dump({"spdxVersion": "SPDX-2.3"}, open(path, "w"))
        try:
            rb.main([path, "1.0.0", "t", "abc123"])
            raise AssertionError("SPDX hätte abgelehnt werden müssen / should be rejected")
        except ValueError:
            pass


def test_windows_package_requires_launcher() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        binary = os.path.join(tmp, "pqkeep.exe")
        with open(binary, "wb") as f:
            f.write(b"MZ fake")
        assert rp.main([binary, "1.0.0", "x86_64-pc-windows-msvc", os.path.join(tmp, "out")]) == 2
        assert not os.path.exists(os.path.join(tmp, "out"))


def test_smoke_dry_run() -> None:
    assert rs.main(["pqkeep", "--dry-run"]) == 0
    assert rs.main([]) == 2


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("alle Tests bestanden / all tests passed")
