#!/usr/bin/env python3
"""
Tests for the milter's webhook signing path.

Covers:
- Reserved-header startup validation with sys.exit(2) on collision.
- webhook-id derivation stability across retries and distinctness across
  recipients or queue ids.
- Outbound header set on a live signed call.
- Contract round-trip: sign with the milter's helpers, verify with the SDK.
"""

import importlib
import json
import os
import sys
import uuid
from unittest.mock import MagicMock, patch

import pytest
from urllib.error import HTTPError, URLError


# Mock pymilter before import, same pattern as test_milter.py.
mock_milter = MagicMock()
mock_milter.Base = object
mock_milter.CONTINUE = 0
mock_milter.ACCEPT = 1
mock_milter.REJECT = 2
mock_milter.TEMPFAIL = 3
mock_milter.CHGHDRS = 1
mock_milter.ADDHDRS = 2
mock_milter.noreply = lambda f: f
mock_milter.uniqueID = MagicMock(return_value=1)
mock_milter_utils = MagicMock()
mock_milter_utils.parse_addr = lambda a: tuple(a.strip("<>").rsplit("@", 1))
sys.modules["Milter"] = mock_milter
sys.modules["Milter.utils"] = mock_milter_utils
os.environ.setdefault("TLDEXTRACT_CACHE", "/tmp/primitivemail-test-tldextract")

import primitivemail_milter as pm
from primitive import verify_standard_webhooks_signature


VALID_SECRET = "whsec_dGVzdHNlY3JldHNob3VsZGJlMzJieXRlc2xvbmcxMjM0NTY="


@pytest.fixture(autouse=True)
def _restore_pm_after_reload(monkeypatch):
    """Reload-based tests can partially mutate the `pm` module when a
    module-level `sys.exit(...)` fires. Tests that run afterward would
    otherwise see a half-initialized module. Reload once post-test under a
    known-good env to restore a clean state.
    """
    yield
    # Restore to standalone mode (the simplest valid config) so subsequent
    # tests, including ones in other files, see a consistent `pm`.
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("WEBHOOK_EXTRA_HEADERS", raising=False)
    try:
        importlib.reload(pm)
    except SystemExit:
        # Recovery reload should not fail under standalone mode. If it does,
        # it is a real bug and should surface on the next test, not here.
        pass


# ---------------------------------------------------------------------------
# Reserved-header startup validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header_name",
    [
        "authorization",
        "Authorization",
        "AUTHORIZATION",
        "content-type",
        "Content-Type",
        "webhook-id",
        "Webhook-Id",
        "webhook-timestamp",
        "webhook-signature",
        "WEBHOOK-SIGNATURE",
    ],
)
def test_reserved_header_in_extra_headers_exits_2(header_name, monkeypatch, capsys):
    """Reserved header collision in WEBHOOK_EXTRA_HEADERS must fail startup."""
    monkeypatch.setenv("WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("WEBHOOK_SECRET", VALID_SECRET)
    monkeypatch.setenv(
        "WEBHOOK_EXTRA_HEADERS", json.dumps({header_name: "attacker-value"})
    )

    with pytest.raises(SystemExit) as excinfo:
        importlib.reload(pm)

    assert excinfo.value.code == 2


def test_non_reserved_extra_header_does_not_exit(monkeypatch):
    """A non-reserved header must not block startup."""
    monkeypatch.setenv("WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("WEBHOOK_SECRET", VALID_SECRET)
    monkeypatch.setenv(
        "WEBHOOK_EXTRA_HEADERS", json.dumps({"x-vercel-protection-bypass": "ok"})
    )

    importlib.reload(pm)

    assert "x-vercel-protection-bypass" in pm.WEBHOOK_EXTRA_HEADERS


# ---------------------------------------------------------------------------
# Secret format fail-fast
# ---------------------------------------------------------------------------


def test_invalid_secret_format_exits_at_startup(monkeypatch):
    """A raw-ASCII secret without whsec_ prefix / base64 must not start."""
    monkeypatch.setenv("WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("WEBHOOK_SECRET", "not-a-valid-secret-format-!!!")
    monkeypatch.delenv("WEBHOOK_EXTRA_HEADERS", raising=False)

    with pytest.raises(SystemExit) as excinfo:
        importlib.reload(pm)

    assert excinfo.value.code == 1


# ---------------------------------------------------------------------------
# webhook-id derivation
# ---------------------------------------------------------------------------


def _webhook_id(message_id: str, recipient: str, queue_id: str) -> str:
    return str(
        uuid.uuid5(
            pm.WEBHOOK_ID_NAMESPACE,
            f"{message_id}:{recipient}:{queue_id}",
        )
    )


def test_webhook_id_stable_across_retries():
    """Same (message_id, recipient, queue_id) produces the same id."""
    a = _webhook_id("msg-1", "alice@example.com", "ABC123")
    b = _webhook_id("msg-1", "alice@example.com", "ABC123")
    assert a == b


def test_webhook_id_differs_by_recipient():
    """Different recipients of the same message get distinct ids."""
    a = _webhook_id("msg-1", "alice@example.com", "ABC123")
    b = _webhook_id("msg-1", "bob@example.com", "ABC123")
    assert a != b


def test_webhook_id_differs_by_queue_id():
    """Independently-resubmitted messages (new queue id) get distinct ids."""
    a = _webhook_id("msg-1", "alice@example.com", "ABC123")
    b = _webhook_id("msg-1", "alice@example.com", "XYZ789")
    assert a != b


def test_webhook_id_namespace_is_pinned():
    """The namespace UUID is load-bearing for operator reproducibility."""
    assert pm.WEBHOOK_ID_NAMESPACE == uuid.UUID(
        "6f79e4a8-a494-4f7e-9124-90d94cb26d5d"
    )


# ---------------------------------------------------------------------------
# Live call: header set + SDK contract round-trip
# ---------------------------------------------------------------------------


class _CapturingResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def read(self):
        return json.dumps({"status": "accepted"}).encode()


def _build_milter_for_webhook_call(monkeypatch):
    """Reload pm under a webhook config and return a configured instance."""
    monkeypatch.setenv("WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("WEBHOOK_SECRET", VALID_SECRET)
    monkeypatch.delenv("WEBHOOK_EXTRA_HEADERS", raising=False)
    importlib.reload(pm)

    m = pm.PrimitiveMailMilter()
    m.client_ip = "203.0.113.10"
    m.helo = "mail.example.com"
    m.sender = "alice@example.com"
    m.subject = "hi"
    m.message_id = "<stable-message-id@example.com>"
    m.from_header = "Alice <alice@example.com>"
    m.getsymval = MagicMock(return_value="QID-1234")
    m.log = lambda *a, **kw: None
    return m


def test_live_call_emits_standard_webhooks_headers_and_bearer(monkeypatch):
    """Signature headers present; Bearer present for primitive.dev mx_main
    receiver compatibility. Legacy primitive-signature NOT emitted."""
    m = _build_milter_for_webhook_call(monkeypatch)
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = req.data
        captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
        return _CapturingResponse()

    with patch("primitivemail_milter.urllib.request.urlopen", fake_urlopen):
        m._call_webhook_for_recipient(
            recipient="bob@example.com",
            domain="example.com",
            raw_bytes=b"From: a\n\nhi",
            size=10,
        )

    assert "webhook-id" in captured["headers"]
    assert "webhook-timestamp" in captured["headers"]
    assert "webhook-signature" in captured["headers"]
    assert captured["headers"]["content-type"] == "application/json"
    # Bearer header is required by primitive.dev's current mx_main receiver.
    # Stays until that receiver migrates to SDK verification.
    assert captured["headers"]["authorization"] == f"Bearer {VALID_SECRET}"
    # Legacy primitive-signature is still NOT emitted; only used for the
    # hosted primitive.dev -> customer webhook flow, not MX -> mx_main.
    assert "primitive-signature" not in captured["headers"]
    assert captured["headers"]["webhook-signature"].startswith("v1,")


def test_live_call_passes_sdk_standard_webhooks_verify(monkeypatch):
    """Sign with milter helpers; verify with the SDK's handle_webhook."""
    m = _build_milter_for_webhook_call(monkeypatch)
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = req.data
        # urllib normalizes header casing to Title-lower (e.g. Webhook-signature).
        # Normalize to lowercase for a stable lookup.
        captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
        return _CapturingResponse()

    with patch("primitivemail_milter.urllib.request.urlopen", fake_urlopen):
        m._call_webhook_for_recipient(
            recipient="bob@example.com",
            domain="example.com",
            raw_bytes=b"From: a\n\nhi",
            size=10,
        )

    # The low-level verifier is the stable contract: handle_webhook wraps it
    # with additional payload validation we don't need here.
    ok = verify_standard_webhooks_signature(
        raw_body=captured["body"],
        secret=VALID_SECRET,
        signature_header=captured["headers"]["webhook-signature"],
        msg_id=captured["headers"]["webhook-id"],
        timestamp=captured["headers"]["webhook-timestamp"],
    )
    assert ok is True


def test_live_call_rejects_tampered_body(monkeypatch):
    """Mutating the body after signing must fail SDK verification."""
    m = _build_milter_for_webhook_call(monkeypatch)
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = req.data
        captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
        return _CapturingResponse()

    with patch("primitivemail_milter.urllib.request.urlopen", fake_urlopen):
        m._call_webhook_for_recipient(
            recipient="bob@example.com",
            domain="example.com",
            raw_bytes=b"From: a\n\nhi",
            size=10,
        )

    from primitive import WebhookVerificationError

    tampered = captured["body"] + b'{"injected": true}'
    with pytest.raises(WebhookVerificationError):
        verify_standard_webhooks_signature(
            raw_body=tampered,
            secret=VALID_SECRET,
            signature_header=captured["headers"]["webhook-signature"],
            msg_id=captured["headers"]["webhook-id"],
            timestamp=captured["headers"]["webhook-timestamp"],
        )
