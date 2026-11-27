#!/usr/bin/env python3
"""DE/EN: Tests der PADMÉ-Referenz und ihres Abgleichs mit den Rust-Werten (#316, P06)."""
import subprocess
import sys
import unittest
from pathlib import Path

import v4_padme_reference as ref


class PadmeTests(unittest.TestCase):
    def test_known_values_and_overhead(self):
        self.assertEqual(ref.padme(1000), 1024)
        self.assertEqual(ref.padme(1_000_000), 1_015_808)
        for n in range(24, 200_000, 97):
            p = ref.padme(n)
            self.assertGreaterEqual(p, n)
            self.assertLess((p - n) / n, 0.12)

    def test_rust_vectors_match(self):
        script = Path(__file__).with_name("v4_padme_reference.py")
        result = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
