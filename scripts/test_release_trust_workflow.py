"""DE: Release-Jobgraph und minimale Rechte. EN: Release job graph and minimum permissions."""
from pathlib import Path
import re
import unittest


def contract(text):
    """DE/EN: Absichtliche strukturelle Invarianten / deliberate structural invariants."""
    jobs = {m[1]: m[2] for m in re.finditer(r'(?ms)^  (\w+):\n(.*?)(?=^  \w+:\n|\Z)', text.split('\njobs:', 1)[1])}
    assert 'needs: [prepare, verify]' in jobs['draft']
    assert 'needs: [prepare, publish]' in jobs['verify']
    assert 'needs: [prepare, build]' in jobs['publish']
    assert 'run: python3 scripts/release_ref.py' in jobs['prepare']
    assert 'gh release create' not in jobs['publish']
    assert 'contents: write' not in jobs['publish']
    assert 'id-token: write' in jobs['publish']
    assert 'id-token: write' not in jobs['draft']
    for name in ['verify', 'draft']:
        assert 'python3 scripts/release_trust.py' in jobs[name]
        assert 'EXPECTED_COMMIT: ${{ github.sha }}' in jobs[name]
        assert 'EXPECTED_REF: ${{ github.ref }}' in jobs[name]
    for name in ['publish', 'draft']:
        assert "    if: github.event_name != 'pull_request'" in jobs[name]
        assert 'environment: release' in jobs[name]
    assert "if: needs.prepare.outputs.is_tag == 'true'" in jobs['draft']
    assert jobs['draft'].index('scripts/release_trust.py') < jobs['draft'].index('gh release create')


class WorkflowTests(unittest.TestCase):
    def test_repository_contract_and_mutations(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/release.yml').read_text()
        contract(text)
        for old, bad in [('needs: [prepare, verify]', 'needs: [prepare, build]'),
                          ('needs: [prepare, publish]', 'needs: prepare'),
                          ('contents: read\n      id-token: write', 'contents: write\n      id-token: write'),
                          ('EXPECTED_COMMIT: ${{ github.sha }}', 'EXPECTED_COMMIT: untrusted'),
                          ('scripts/release_ref.py', 'scripts/skip.py'),
                          ("if: needs.prepare.outputs.is_tag == 'true'", 'if: always()')]:
            with self.subTest(old=old), self.assertRaises(AssertionError):
                contract(text.replace(old, bad))


if __name__ == '__main__':
    unittest.main()
