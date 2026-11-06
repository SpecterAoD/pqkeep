#!/usr/bin/env python3
"""Tests für check_binary.py (ohne echtes Binary) / tests for check_binary.py (no real binary).

DE: Prüft die PE-Auswertung mit künstlich erzeugten Headern und die ELF-Auswertung mit
    beispielhafter readelf-Ausgabe. Aufruf: python3 scripts/test_check_binary.py
EN: Checks PE parsing with synthetic headers and ELF parsing with sample readelf output.
    Usage: python3 scripts/test_check_binary.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_binary as cb  # noqa: E402


def fake_pe(characteristics: int) -> bytes:
    data = bytearray(1024)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x80 + 24, 0x20B)
    struct.pack_into("<H", data, 0x80 + 24 + 70, characteristics)
    return bytes(data)


def test_pe() -> None:
    all_flags = sum(cb.PE_FLAGS.values())
    assert all(cb.pe_features(fake_pe(all_flags)).values())
    no_cfg = cb.pe_features(fake_pe(all_flags & ~0x4000))
    assert not no_cfg["GUARD_CF (Control Flow Guard)"]
    assert sum(no_cfg.values()) == 3
    for bad in (b"XX" + bytes(100), fake_pe(0)[:0x80] + b"NOPE" + bytes(200)):
        try:
            cb.pe_features(bad)
        except ValueError:
            continue
        raise AssertionError("ungültiges PE nicht erkannt / invalid PE not detected")


def test_elf() -> None:
    header = "  Type:                              DYN (Position-Independent Executable file)"
    dynamic = " 0x1e (FLAGS) BIND_NOW\n 0x6ffffffb (FLAGS_1) Flags: NOW PIE"
    headers = ("  GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW  0x10\n"
               "  GNU_RELRO 0x1 0x2 0x3 0x4 0x5 R   0x1")
    assert all(cb.elf_features(dynamic, headers, header).values())
    partial = cb.elf_features("", headers, header)
    assert not partial["BIND_NOW (Full RELRO)"] and not partial["PIE"]
    exec_stack = headers.replace("RW ", "RWE")
    assert not cb.elf_features(dynamic, exec_stack, header)["NX stack"]


if __name__ == "__main__":
    test_pe()
    test_elf()
    print("OK: check_binary.py verhält sich wie erwartet / behaves as expected")
