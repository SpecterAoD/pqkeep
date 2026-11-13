"""Tests for pre-apply Git patch header policy."""
import unittest

from validate_opencode_patch_headers import validate_headers

EDIT = (b"diff --git a/docs/guide.md b/docs/guide.md\n"
        b"index 1111111..2222222 100644\n"
        b"--- a/docs/guide.md\n+++ b/docs/guide.md\n"
        b"@@ -1 +1 @@\n-before\n+after\n")
ADD = (b"diff --git a/docs/new.md b/docs/new.md\n"
       b"new file mode 100644\nindex 0000000..2222222\n"
       b"--- /dev/null\n+++ b/docs/new.md\n"
       b"@@ -0,0 +1 @@\n+hello\n")


class HeaderTests(unittest.TestCase):
    def test_allow_plain_edit_and_add(self):
        self.assertEqual(validate_headers(EDIT + ADD),
                         ["docs/guide.md", "docs/new.md"])

    def test_reject_malicious_headers(self):
        variants = [
            EDIT.replace(b"docs/guide.md", b"src/lib.rs"),
            EDIT.replace(b"docs/guide.md", b"docs/../evil.md"),
            EDIT.replace(b"docs/guide.md", b"docs/OPENCODE_AGENT_ISOLATION.md"),
            EDIT.replace(b"docs/guide.md", b"docs/OPENCODE_PR171_MERGE_CHECKLIST.md"),
            EDIT.replace(b"index 1111111..2222222 100644",
                         b"old mode 100644\nnew mode 100755"),
            EDIT.replace(b"--- a/docs/guide.md", b"--- /dev/null"),
            EDIT.replace(b"+++ b/docs/guide.md", b"+++ b/docs/other.md"),
            EDIT.replace(b"@@ -1 +1 @@", b"GIT binary patch"),
            EDIT.replace(b"index 1111111..2222222 100644",
                         b"rename from docs/guide.md"),
            EDIT.replace(b"docs/guide.md", b"docs\\guide.md"),
            EDIT.replace(b"docs/guide.md", b"docs/guide.md\t"),
            EDIT + EDIT,
            b"garbage\n" + EDIT,
            EDIT + b"evil trailing line\n",
            EDIT.replace(b"\n", b"\r\n"),
            EDIT + b"\0",
        ]
        for value in variants:
            with self.subTest(value=value[:80]):
                with self.assertRaises((ValueError, UnicodeError)):
                    validate_headers(value)


if __name__ == "__main__":
    unittest.main()
