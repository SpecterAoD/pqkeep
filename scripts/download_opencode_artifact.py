#!/usr/bin/env python3
"""Download an exact Actions artifact with bounded, credential-free redirect.

Read-only. The expected artifact ID must come from an independent trusted
source and must pass verify_opencode_artifact_origin before this is called.
"""
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from verify_opencode_artifact_origin import verify_artifact_listing

API = "https://api.github.com/repos/SpecterAoD/pqkeep/actions/artifacts/"
MAX_ZIP_BYTES = 120_000
SAFE_HOSTS = {"objects.githubusercontent.com"}
SAFE_SUFFIXES = (".blob.core.windows.net",)
ID = re.compile(r"[1-9][0-9]*\Z")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def approved_download_url(url: str) -> bool:
    """Only permit HTTPS to explicitly recognized artifact storage hosts."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        return bool(
            parsed.scheme == "https"
            and host
            and (host in SAFE_HOSTS or any(
                host.endswith(suffix) for suffix in SAFE_SUFFIXES
            ))
            and parsed.port in (None, 443)
            and not parsed.username and not parsed.password
            and not parsed.fragment
        )
    except ValueError:
        return False


def download(artifact_id: int, token: str, destination: Path,
             open_request=None) -> int:
    """Fetch artifact via API redirect; never forward GitHub token to storage."""
    if type(artifact_id) is not int or artifact_id <= 0:
        raise ValueError("invalid artifact ID")
    if not isinstance(token, str) or not token:
        raise ValueError("missing read token")
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination exists")
    if open_request is None:
        open_request = build_opener(NoRedirect).open
    request = Request(
        API + str(artifact_id) + "/zip",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        response = open_request(request, timeout=15)
    except HTTPError as exc:
        if exc.code not in (302, 303, 307, 308):
            raise ValueError("unexpected GitHub API response") from None
        location = exc.headers.get("Location", "")
    else:
        with response:
            raise ValueError("expected GitHub artifact redirect")
    if not approved_download_url(location):
        raise ValueError("untrusted artifact download location")
    # Crucially: this second request carries NO Authorization header.
    storage_request = Request(location, method="GET")
    with open_request(storage_request, timeout=30) as response:
        if response.status != 200:
            raise ValueError("artifact storage rejected request")
        content = response.read(MAX_ZIP_BYTES + 1)
    if not 0 < len(content) <= MAX_ZIP_BYTES:
        raise ValueError("artifact exceeds size limit")
    # Atomic creation prevents overwriting a previously reviewed artifact.
    fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return len(content)


def main() -> int:
    """Verify artifact listing before downloading; no bypass flag."""
    if len(sys.argv) != 2:
        return 1
    try:
        artifact_text = os.environ["OPENCODE_EXPECTED_ARTIFACT_ID"]
        run_text = os.environ["OPENCODE_EXPECTED_RUN_ID"]
        issue_text = os.environ["OPENCODE_EXPECTED_ISSUE"]
        if not all(ID.fullmatch(value) for value in (
            artifact_text, run_text, issue_text
        )):
            raise ValueError("invalid expected identifiers")
        artifact, run, issue = map(int, (
            artifact_text, run_text, issue_text
        ))
        base = os.environ["OPENCODE_EXPECTED_BASE_SHA"]
        token = os.environ["GH_READ_TOKEN"]
        if not verify_artifact_listing(issue, run, base, artifact, token):
            raise ValueError("artifact origin not verified")
        size = download(artifact, token, Path(sys.argv[1]))
    except (OSError, ValueError, HTTPError, KeyError):
        print("DENIED: artifact download failed", file=sys.stderr)
        return 1
    print(f"PASS: downloaded {size} bytes without forwarding GitHub token")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
