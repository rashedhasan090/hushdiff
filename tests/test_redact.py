from __future__ import annotations

from hushdiff.redact import redact_diff, redact_text


def test_aws_access_key():
    text = "key = AKIAIOSFODNN7EXAMPLE"
    out, s = redact_text(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "AKIA" in out
    assert s.counts.get("aws_access_key") == 1


def test_github_pat():
    fake = "ghp_" + ("A" * 36)
    out, s = redact_text(f"token={fake}")
    assert fake not in out
    assert s.counts.get("github_pat") == 1


def test_slack_token():
    fake = "xoxb-1234567890-abcdefghij"
    out, s = redact_text(fake)
    assert fake not in out
    assert s.counts.get("slack_token") == 1


def test_jwt():
    # syntactically jwt-shaped, not a real token
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepartxx"
    out, s = redact_text(f"Authorization: Bearer {jwt}")
    assert jwt not in out
    assert "[REDACTED:jwt]" in out
    assert s.counts.get("jwt") == 1


def test_private_key_block():
    block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKFAKESECRETDATAHEREONLYFORTESTSXXXX\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out, s = redact_text(block)
    assert "BEGIN RSA PRIVATE KEY" not in out
    assert "[REDACTED:private_key_block]" in out
    assert s.counts.get("private_key_block") == 1


def test_secret_assignment():
    out, s = redact_text('api_key="supersecretvalue123"')
    assert "supersecretvalue123" not in out
    assert "[REDACTED:secret_assignment]" in out
    assert s.counts.get("secret_assignment") == 1


def test_no_false_positive_on_normal_code():
    code = '''
def add(a, b):
    """Return a + b."""
    total = a + b
    return total
'''
    out, s = redact_text(code)
    assert out == code
    assert s.total == 0


def test_redact_diff_preserves_headers():
    patch = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,3 +1,3 @@
-token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
+token = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"""
    out, s = redact_diff(patch)
    assert out.startswith("diff --git")
    assert "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in out
    assert "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" not in out
    assert s.total >= 2
