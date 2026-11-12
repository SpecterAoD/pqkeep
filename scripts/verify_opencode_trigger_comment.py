#!/usr/bin/env python3
"""Read-only revalidation of a trusted issue-comment identity.

The comment ID must originate from a separately trusted event binding.
This module does NOT establish that binding by itself.
"""
from urllib.error import HTTPError, URLError

OWNER_ID = 77644070
REPOSITORY = "SpecterAoD/pqkeep"


def verify_comment(issue: int, comment_id: int, token: str, get) -> bool:
    """Fail closed if the /oc trigger was edited, deleted, or reassigned."""
    if (type(issue) is not int or issue <= 0
            or type(comment_id) is not int or comment_id <= 0
            or not isinstance(token, str) or not token):
        return False
    try:
        status, comment = get(f"/issues/comments/{comment_id}", token)
        if status != 200 or not isinstance(comment, dict):
            return False
        author = comment.get("user")
        issue_url = comment.get("issue_url")
        expected_url = (
            f"https://api.github.com/repos/{REPOSITORY}/issues/{issue}"
        )
        return (
            type(comment.get("id")) is int
            and comment["id"] == comment_id
            and isinstance(author, dict)
            and type(author.get("id")) is int
            and author["id"] == OWNER_ID
            and comment.get("body") == "/oc"
            and comment.get("created_at")
            and comment["created_at"] == comment.get("updated_at")
            and issue_url == expected_url
        ) is True
    except (HTTPError, URLError, OSError, ValueError, TypeError, KeyError):
        return False
