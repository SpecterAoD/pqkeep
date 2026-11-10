#!/usr/bin/env python3
"""Negative Paket-/Versions-/Pfadtests; keine Systeminstallation."""

import io
import hashlib
from pathlib import Path
import subprocess
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import release_deb as deb
import release_deb_check as check
from release_deb_licenses import crate_notice, license_files


def fixture_tar(files: dict) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tar:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if name == "usr/bin/pqkeep" else 0o644
            member.size = len(content)
            tar.addfile(member, io.BytesIO(content))
    return data.getvalue()


class DebianTests(unittest.TestCase):
    def test_package_content_architecture_and_checksums(self):
        elf = bytearray(64)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", elf, 16, 3, 62)
        for case in ("valid", "missing", "extra", "script", "wrong-elf", "wrong-arch", "bad-md5", "bad-sha"):
            data = {name: b"documentation" for name in check.REQUIRED}
            data["usr/bin/pqkeep"] = bytes(elf)
            if case == "missing":
                del data[check.DOC + "copyright"]
            if case == "extra":
                data["etc/cron.d/pqkeep"] = b"unexpected"
            if case == "wrong-elf":
                wrong = bytearray(elf)
                struct.pack_into("<H", wrong, 18, 183)
                data["usr/bin/pqkeep"] = bytes(wrong)
            arch = "arm64" if case == "wrong-arch" else "amd64"
            sums = "".join(hashlib.md5(data[n], usedforsecurity=False).hexdigest() + "  " + n + "\n"
                           for n in sorted(data))
            controls = {"control": f"Package: pqkeep\nArchitecture: {arch}\n".encode(),
                        "md5sums": b"broken" if case == "bad-md5" else sums.encode()}
            if case == "script":
                controls["postinst"] = b"#!/bin/sh\nexit 0\n"
            expected_sha = "0" * 64 if case == "bad-sha" else hashlib.sha256(elf).hexdigest()
            with self.subTest(case=case), patch.object(check.subprocess, "check_output",
                                                       side_effect=[fixture_tar(controls), fixture_tar(data)]):
                if case == "valid":
                    self.assertEqual(check.check_package(Path("test.deb"), "amd64", expected_sha), data)
                else:
                    with self.assertRaises(ValueError):
                        check.check_package(Path("test.deb"), "amd64", expected_sha)

    def test_versions_and_order(self):
        candidate = deb.deb_version("0.1.0-beta.1", "1", 1700000000, "abcdef0")
        self.assertEqual(candidate, "0.1.0~beta.1-1~ci.20231114221320.abcdef0")
        self.assertEqual(deb.deb_version("1.2.3", "2", 1700000000, "abcdef0"),
                         "1.2.3-2~ci.20231114221320.abcdef0")
        for older, newer in [(candidate, "0.1.0~beta.1-1"), ("0.1.0~beta.1-1", "0.1.0-1"),
                             (candidate, deb.deb_version("0.1.0-beta.1", "1", 1700000001, "0000000"))]:
            subprocess.run(["dpkg", "--compare-versions", older, "lt", newer], check=True)

    def test_invalid_versions(self):
        for version in ("../1", "01.2.3", "1.2", "1.2.3+meta", "1.2.3-beta..1",
                        "1.2.3-01", "1.2.3-", "1.2.3\nPackage: evil", "1:2.3.4"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                deb.deb_version(version, "1", 1700000000, "abcdef0")
        for revision, stamp, sha in [("0", 0, "abcdef0"), ("1", -1, "abcdef0"),
                                      ("1", 0, "../evil"), ("1\n", 0, "abcdef0")]:
            with self.assertRaises(ValueError):
                deb.deb_version("1.2.3", revision, stamp, sha)

    def test_regular_rejects_missing_symlink_and_writable_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "binary"
            with self.assertRaises(ValueError):
                deb.regular(p)
            p.write_bytes(b"test")
            p.chmod(0o755)
            self.assertEqual(deb.regular(p), p)
            link = p.with_name("link")
            link.symlink_to(p)
            with self.assertRaises(ValueError):
                deb.regular(link)
            p.chmod(0o777)
            with self.assertRaises(ValueError):
                deb.regular(p)

    def test_dependencies_fail_closed(self):
        for output in ("", "shlibs:Depends=\n", "shlibs:Depends=libc6\n",
                       "shlibs:Depends=libc6 (>= 2.34)\nPackage: evil\n",
                       "shlibs:Depends=libc6 (>= 2.34), evil; echo\n"):
            with tempfile.TemporaryDirectory() as tmp, self.subTest(output=output):
                with patch.object(deb.subprocess, "check_output", return_value=output):
                    with self.assertRaises(ValueError):
                        deb.dependencies(Path(tmp), Path(tmp))
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(deb.subprocess, "check_output", return_value="shlibs:Depends=libc6 (>= 2.34), libgcc-s1 (>= 4.2)\n"):
                self.assertEqual(deb.dependencies(Path(tmp), Path(tmp)), "libc6 (>= 2.34), libgcc-s1 (>= 4.2)")

    def test_tar_rejects_unsafe_members(self):
        for name, mode, kind, uid in [("../escape", 0o644, tarfile.REGTYPE, 0),
                                     ("/absolute", 0o644, tarfile.REGTYPE, 0),
                                     ("usr/bin/pqkeep", 0o4755, tarfile.REGTYPE, 0),
                                     ("usr/bin/pqkeep", 0o755, tarfile.SYMTYPE, 0),
                                     ("usr/bin/pqkeep", 0o755, tarfile.REGTYPE, 1000)]:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as tar:
                member = tarfile.TarInfo(name)
                member.mode, member.type, member.uid = mode, kind, uid
                tar.addfile(member)
            with self.subTest(name=name, mode=mode), self.assertRaises(ValueError):
                check.read_tar(data.getvalue())

    def test_tar_rejects_duplicates(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as tar:
            for _ in range(2):
                tar.addfile(tarfile.TarInfo("file"))
        with self.assertRaises(ValueError):
            check.read_tar(data.getvalue())

    def test_missing_and_symlinked_license(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                license_files(root)
            (root / "LICENSE").symlink_to("missing")
            with self.assertRaises(ValueError):
                license_files(root)

    def test_verbatim_license_and_copyright(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            text = "Copyright 2026 Example authors\n\nPermission to use.\n"
            (root / "LICENSE").write_text(text)
            stanza, record = crate_notice({"name": "example", "version": "1.0.0", "license": "MIT",
                                           "source": "registry+example", "manifest_path": str(root / "Cargo.toml")})
            self.assertIn("Copyright: Copyright 2026 Example authors", stanza)
            self.assertIn(" Permission to use.", stanza)
            self.assertEqual(set(record["license_files"]), {"LICENSE"})


if __name__ == "__main__":
    unittest.main()
