"""Test credential isolation and strict artifact download bounds."""
import io
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request

from download_opencode_artifact import approved_download_url, download


class FakeResponse:
    status = 200
    def __init__(self, content):
        self.stream = io.BytesIO(content)
    def read(self, n):
        return self.stream.read(n)
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.destination = Path(self.tmp.name) / "artifact.zip"
        self.requests = []

    def fake(self, request, timeout):
        self.requests.append(request)
        if len(self.requests) == 1:
            raise HTTPError(
                request.full_url, 302, "Found",
                {"Location": "https://objects.githubusercontent.com/a?sig=x"},
                None,
            )
        return FakeResponse(b"ZIP")

    def test_download_no_credential_leak(self):
        self.assertEqual(
            download(456, "secret-token", self.destination, self.fake), 3
        )
        self.assertEqual(self.destination.read_bytes(), b"ZIP")
        self.assertEqual(len(self.requests), 2)
        self.assertIn("Authorization", self.requests[0].headers)
        self.assertNotIn("Authorization", self.requests[1].headers)

    def test_existing_destination_denied(self):
        self.destination.write_bytes(b"old")
        with self.assertRaises(ValueError):
            download(456, "token", self.destination, self.fake)

    def test_invalid_artifact_id(self):
        with self.assertRaises(ValueError):
            download(True, "token", self.destination, self.fake)

    def test_oversized_response(self):
        def oversized(request, timeout):
            if request.full_url.startswith("https://api.github.com/"):
                return self.fake(request, timeout)
            return FakeResponse(b"x" * 120_001)
        with self.assertRaises(ValueError):
            download(456, "token", self.destination, oversized)
        self.assertFalse(self.destination.exists())

    def test_bad_redirect_host(self):
        self.assertFalse(approved_download_url(
            "https://objects.githubusercontent.com.evil.test/file"
        ))

    def test_non_https_denied(self):
        self.assertFalse(approved_download_url(
            "http://objects.githubusercontent.com/file"
        ))

    def test_userinfo_denied(self):
        self.assertFalse(approved_download_url(
            "https://user@objects.githubusercontent.com/file"
        ))


if __name__ == "__main__":
    unittest.main()
