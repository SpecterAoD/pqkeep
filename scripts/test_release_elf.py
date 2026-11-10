#!/usr/bin/env python3
"""Positive und negative Ziel-/ABI-/Archivprüfungen ohne fremdes Binary auszuführen."""

import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import release_elf as elf


ARM = "aarch64-unknown-linux-gnu"
AMD = "x86_64-unknown-linux-gnu"


def header(machine=183, kind=3):
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, kind, machine)
    return bytes(data)


def loader(target=ARM):
    return f"[Requesting program interpreter: {elf.TARGETS[target][2]}]"


class ElfTests(unittest.TestCase):
    def test_both_architectures(self):
        elf.check_header(header(), ARM)
        elf.check_header(header(62), AMD)

    def test_invalid_header_and_machine(self):
        for data in (b"MZ" + bytes(100), header()[:20], header(62), header(kind=2),
                     header()[:4] + b"\x01" + header()[5:],
                     header()[:5] + b"\x02" + header()[6:]):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):
                elf.check_header(data, ARM)

    def test_glibc_baseline(self):
        for target in (ARM, AMD):
            self.assertEqual(elf.check_abi(loader(target),
                             "Name: GLIBC_2.2.5\nName: GLIBC_2.35", target), "GLIBC_2.35")

    def test_glibc_newer_missing_or_unknown(self):
        for versions in ("", "Name: GLIBC_2.36", "Name: GLIBC_2.35.1",
                         "Name: GLIBC_PRIVATE", "Name: GLIBC_ABI_DT_RELR"):
            with self.subTest(versions=versions), self.assertRaises(ValueError):
                elf.check_abi(loader(), versions, ARM)

    def test_wrong_or_missing_loader(self):
        for headers in ("", loader(AMD), "[Requesting program interpreter: /lib/ld-musl-aarch64.so.1]",
                        loader() + "\n" + loader()):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                elf.check_abi(headers, "Name: GLIBC_2.17", ARM)

    def test_native_host(self):
        with patch.object(elf.platform, "system", return_value="Linux"):
            with patch.object(elf.platform, "machine", return_value="aarch64"):
                elf.check_native(ARM)
            with patch.object(elf.platform, "machine", return_value="x86_64"):
                with self.assertRaises(ValueError):
                    elf.check_native(ARM)
        with patch.object(elf.platform, "system", return_value="Darwin"):
            with self.assertRaises(ValueError):
                elf.check_native(ARM)

    def test_archive_identity_and_rejections(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "pqkeep"
            binary.write_bytes(header())
            archive = Path(tmp) / "pqkeep-test-aarch64-unknown-linux-gnu.tar.gz"
            for mode in ("valid", "changed", "missing", "duplicate", "symlink"):
                with self.subTest(mode=mode):
                    with tarfile.open(archive, "w:gz") as tar:
                        member = tarfile.TarInfo(archive.name.removesuffix(".tar.gz") + "/pqkeep")
                        data = b"changed" if mode == "changed" else header()
                        member.size = len(data)
                        if mode == "symlink":
                            member.type, member.linkname, member.size = tarfile.SYMTYPE, "/etc/passwd", 0
                        if mode != "missing":
                            tar.addfile(member, io.BytesIO(data))
                        if mode == "duplicate":
                            tar.addfile(member, io.BytesIO(data))
                    if mode == "valid":
                        self.assertEqual(elf.check_archive(binary, archive),
                                         elf.hashlib.sha256(header()).hexdigest())
                    else:
                        with self.assertRaises(ValueError):
                            elf.check_archive(binary, archive)

    def test_cli_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "pqkeep"
            binary.write_bytes(header(62))
            self.assertEqual(elf.main([str(binary), ARM]), 1)
            self.assertEqual(elf.main([str(binary) + "-missing", ARM]), 1)


if __name__ == "__main__":
    unittest.main()
