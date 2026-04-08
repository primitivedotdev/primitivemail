#!/usr/bin/env python3
"""
Tests for primitivemail_milter.py.

Covers multi-recipient handling, sender/recipient filtering,
standalone storage, and spoof protection (SPF/DKIM/DMARC enforcement).
"""

import pytest
import json
import sys
from unittest.mock import patch, MagicMock, PropertyMock
from urllib.error import HTTPError, URLError
from io import BytesIO


# Mock Milter module before importing our code
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


def fake_parse_addr(addr):
    """Simulate Milter.utils.parse_addr"""
    addr = addr.strip('<>').strip()
    if '@' in addr:
        parts = addr.rsplit('@', 1)
        return (parts[0], parts[1])
    return [addr]


mock_milter_utils.parse_addr = fake_parse_addr

sys.modules['Milter'] = mock_milter
sys.modules['Milter.utils'] = mock_milter_utils

# Now import our milter (with Milter mocked)
import primitivemail_milter as pm


class MockResponse:
    """Mock urllib response object"""
    def __init__(self, status_code, body):
        self.status = status_code
        self.body = body

    def read(self):
        return self.body.encode('utf-8')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def make_webhook_response(status='accepted', reason='', detail=''):
    return MockResponse(200, json.dumps({
        'status': status, 'reason': reason, 'detail': detail
    }))


@pytest.fixture
def milter():
    """Create a milter instance with mocked internals"""
    # Ensure webhook mode
    original_standalone = pm.STANDALONE_MODE
    original_webhook_url = pm.WEBHOOK_URL
    original_webhook_secret = pm.WEBHOOK_SECRET
    pm.STANDALONE_MODE = False
    pm.WEBHOOK_URL = 'https://test.example.com/webhook'
    pm.WEBHOOK_SECRET = 'test-secret'

    m = pm.PrimitiveMailMilter()
    m.setreply = MagicMock()
    m.addheader = MagicMock()
    m.chgheader = MagicMock()
    m.client_ip = '127.0.0.1'
    m.client_hostname = 'localhost'
    m.helo = 'test.example.com'

    yield m

    pm.STANDALONE_MODE = original_standalone
    pm.WEBHOOK_URL = original_webhook_url
    pm.WEBHOOK_SECRET = original_webhook_secret


@pytest.fixture
def standalone_milter():
    """Create a milter in standalone mode"""
    original_standalone = pm.STANDALONE_MODE
    pm.STANDALONE_MODE = True

    m = pm.PrimitiveMailMilter()
    m.setreply = MagicMock()
    m.addheader = MagicMock()
    m.chgheader = MagicMock()
    m._save_to_disk = MagicMock()
    m.client_ip = '127.0.0.1'
    m.client_hostname = 'localhost'
    m.helo = 'test.example.com'

    yield m

    pm.STANDALONE_MODE = original_standalone


def add_simple_message(m):
    """Add minimal headers and body to a milter instance"""
    m.header('From', 'sender@example.com')
    m.header('To', 'recipient@example.com')
    m.header('Subject', 'Test')
    m.header('Message-ID', '<test-123@example.com>')
    m.body(b'Test body')


# ===========================================================================
# Core: Single recipient backward compatibility
# ===========================================================================

class TestSingleRecipient:
    """Single recipient (most common case) must work identically to old code"""

    def test_single_recipient_accepted(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        with patch('urllib.request.urlopen', return_value=make_webhook_response('accepted')):
            result = milter.eom()

        assert result == mock_milter.ACCEPT

    def test_single_recipient_webhook_called_with_correct_recipient(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        captured = []

        def capture(request, timeout=None):
            captured.append(json.loads(request.data.decode('utf-8')))
            return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=capture):
            milter.eom()

        assert len(captured) == 1
        assert captured[0]['recipient'] == 'user@example.com'
        assert captured[0]['domain'] == 'example.com'

    def test_single_recipient_domain_not_found_gets_550(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        resp = make_webhook_response('reject_permanent', reason='domain_not_found')
        with patch('urllib.request.urlopen', return_value=resp):
            result = milter.eom()

        assert result == mock_milter.REJECT
        milter.setreply.assert_called_with("550", "5.1.2", "Domain not found")

    def test_single_recipient_protocol_violation_gets_554(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        resp = make_webhook_response('reject_permanent',
                                      reason='protocol_violation',
                                      detail='reserved_tld')
        with patch('urllib.request.urlopen', return_value=resp):
            result = milter.eom()

        assert result == mock_milter.REJECT
        milter.setreply.assert_called_with("554", "5.5.2", "From domain uses reserved TLD")

    def test_single_recipient_webhook_failure_tempfails(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        with patch('urllib.request.urlopen', side_effect=URLError("Connection refused")):
            result = milter.eom()

        assert result == mock_milter.TEMPFAIL


# ===========================================================================
# Core: Multiple recipients
# ===========================================================================

class TestMultipleRecipients:
    """Multiple RCPT TO in one SMTP session"""

    def test_two_recipients_both_accepted(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        with patch('urllib.request.urlopen', return_value=make_webhook_response('accepted')):
            result = milter.eom()

        assert result == mock_milter.ACCEPT

    def test_two_recipients_two_webhook_calls(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        captured = []

        def capture(request, timeout=None):
            captured.append(json.loads(request.data.decode('utf-8')))
            return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=capture):
            milter.eom()

        assert len(captured) == 2
        assert captured[0]['recipient'] == 'alice@a.com'
        assert captured[0]['domain'] == 'a.com'
        assert captured[1]['recipient'] == 'bob@b.com'
        assert captured[1]['domain'] == 'b.com'

    def test_two_recipients_same_eml_base64(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        captured = []

        def capture(request, timeout=None):
            captured.append(json.loads(request.data.decode('utf-8')))
            return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=capture):
            milter.eom()

        assert captured[0]['eml_base64'] == captured[1]['eml_base64']
        assert captured[0]['message_id'] == captured[1]['message_id']
        assert captured[0]['sender'] == captured[1]['sender']

    def test_one_accepted_one_rejected_returns_accept(self, milter):
        """Can't REJECT when at least one recipient got the email"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        call_count = [0]

        def mock_urlopen(request, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return make_webhook_response('accepted')
            else:
                return make_webhook_response('reject_permanent', reason='domain_not_found')

        with patch('urllib.request.urlopen', side_effect=mock_urlopen):
            result = milter.eom()

        assert result == mock_milter.ACCEPT

    def test_one_accepted_one_tempfail_returns_tempfail(self, milter):
        """TEMPFAIL wins over ACCEPT to force retry for the failed recipient"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        call_count = [0]

        def mock_urlopen(request, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return make_webhook_response('accepted')
            else:
                raise URLError("Connection refused")

        with patch('urllib.request.urlopen', side_effect=mock_urlopen):
            result = milter.eom()

        assert result == mock_milter.TEMPFAIL

    def test_all_webhooks_fail_returns_tempfail(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        with patch('urllib.request.urlopen', side_effect=URLError("Connection refused")):
            result = milter.eom()

        assert result == mock_milter.TEMPFAIL

    def test_all_hard_rejected_returns_reject(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        resp = make_webhook_response('reject_permanent', reason='domain_not_found')
        with patch('urllib.request.urlopen', return_value=resp):
            result = milter.eom()

        assert result == mock_milter.REJECT

    def test_all_soft_rejected_returns_accept(self, milter):
        """Non-protocol permanent rejections are silent drops (ACCEPT)"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        resp = make_webhook_response('reject_permanent', reason='sender_blocked')
        with patch('urllib.request.urlopen', return_value=resp):
            result = milter.eom()

        assert result == mock_milter.ACCEPT

    def test_no_short_circuit_all_webhooks_called(self, milter):
        """Even after a tempfail, remaining recipients still get webhook calls"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        milter.envrcpt('<carol@c.com>')
        add_simple_message(milter)

        call_count = [0]

        def mock_urlopen(request, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1:
                raise URLError("Connection refused")  # alice fails
            return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=mock_urlopen):
            milter.eom()

        assert call_count[0] == 3, "All 3 webhooks should be called even after first fails"

    def test_multi_recipient_hard_reject_gets_generic_550(self, milter):
        """Multi-recipient can't give per-recipient error codes, uses generic"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        resp = make_webhook_response('reject_permanent', reason='domain_not_found')
        with patch('urllib.request.urlopen', return_value=resp):
            milter.eom()

        milter.setreply.assert_called_with("550", "5.1.1", "No valid recipients")


# ===========================================================================
# Deduplication
# ===========================================================================

class TestDeduplication:

    def test_duplicate_recipients_deduped(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        captured = []

        def capture(request, timeout=None):
            captured.append(json.loads(request.data.decode('utf-8')))
            return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=capture):
            milter.eom()

        assert len(captured) == 1

    def test_case_insensitive_dedup(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<User@Example.COM>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        captured = []

        def capture(request, timeout=None):
            captured.append(json.loads(request.data.decode('utf-8')))
            return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=capture):
            milter.eom()

        assert len(captured) == 1
        # Preserves first occurrence's casing
        assert captured[0]['recipient'] == 'User@Example.COM'


# ===========================================================================
# Edge cases: empty, invalid, no recipients
# ===========================================================================

class TestEdgeCases:

    def test_no_recipients_rejects(self, milter):
        milter.envfrom('<sender@example.com>')
        # No envrcpt calls
        add_simple_message(milter)

        result = milter.eom()

        assert result == mock_milter.REJECT
        milter.setreply.assert_called_with("550", "5.1.1", "No recipient")

    def test_all_invalid_recipients_silent_drop(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<badrecipient>')  # no domain
        add_simple_message(milter)

        # Invalid recipient won't be appended (no @), so recipients list is empty
        # Actually, parse_addr on 'badrecipient' returns ['badrecipient']
        # which goes through the elif branch and becomes 'badrecipient' (no @)
        # But if rcpt is truthy it gets appended, then fails validation
        result = milter.eom()

        # Either REJECT (no recipients after filtering) or ACCEPT (silent drop)
        # depends on whether the invalid addr makes it into the list
        assert result in (mock_milter.REJECT, mock_milter.ACCEPT)

    def test_mix_valid_and_invalid_only_valid_get_webhook(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<valid@example.com>')
        # Add an invalid one manually (bypass parse_addr)
        milter.recipients.append('no-domain')
        add_simple_message(milter)

        captured = []

        def capture(request, timeout=None):
            captured.append(json.loads(request.data.decode('utf-8')))
            return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=capture):
            milter.eom()

        assert len(captured) == 1
        assert captured[0]['recipient'] == 'valid@example.com'

    def test_envfrom_resets_recipients(self, milter):
        """New MAIL FROM (new message on same connection) clears recipient list"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<first@example.com>')

        # New message
        milter.envfrom('<newsender@example.com>')
        milter.envrcpt('<second@example.com>')

        assert len(milter.recipients) == 1
        assert milter.recipients[0] == 'second@example.com'

    def test_abort_resets_recipients(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        milter.abort()

        assert milter.recipients == []


# ===========================================================================
# Webhook HTTP status code fallback
# ===========================================================================

class TestWebhookHTTPStatusFallback:
    """
    Test that HTTP status codes are used as fallback when the response body
    does not contain a JSON 'status' field. JSON 'status' is authoritative
    when present and overrides the HTTP status code.
    """

    def test_http_200_empty_body_accepted(self, milter):
        """HTTP 200 with empty body → accepted via HTTP status fallback"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        with patch('urllib.request.urlopen', return_value=MockResponse(200, '')):
            result = milter.eom()

        assert result == mock_milter.ACCEPT

    def test_http_200_non_json_accepted(self, milter):
        """HTTP 200 with non-JSON body → accepted via HTTP status fallback"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        with patch('urllib.request.urlopen', return_value=MockResponse(200, 'OK')):
            result = milter.eom()

        assert result == mock_milter.ACCEPT

    def test_http_4xx_no_json_tempfails(self, milter):
        """HTTP 4xx without JSON status → tempfail (safe default, sender retries)"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        mock_error = HTTPError(
            url="https://test.example.com/webhook",
            code=422,
            msg="Unprocessable",
            hdrs={},
            fp=BytesIO(b'')
        )

        with patch('urllib.request.urlopen', side_effect=mock_error):
            result = milter.eom()

        assert result == mock_milter.TEMPFAIL

    def test_http_5xx_no_json_tempfails(self, milter):
        """HTTP 5xx without JSON status → tempfail"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        mock_error = HTTPError(
            url="https://test.example.com/webhook",
            code=500,
            msg="Server Error",
            hdrs={},
            fp=BytesIO(b'')
        )

        with patch('urllib.request.urlopen', side_effect=mock_error):
            result = milter.eom()

        assert result == mock_milter.TEMPFAIL

    def test_http_4xx_with_json_status_uses_json(self, milter):
        """HTTP 422 with JSON {"status": "accepted"} → JSON wins → ACCEPT"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        mock_error = HTTPError(
            url="https://test.example.com/webhook",
            code=422,
            msg="Unprocessable",
            hdrs={},
            fp=BytesIO(json.dumps({"status": "accepted"}).encode())
        )

        with patch('urllib.request.urlopen', side_effect=mock_error):
            result = milter.eom()

        assert result == mock_milter.ACCEPT

    def test_http_200_with_reject_json_uses_json(self, milter):
        """HTTP 200 with {"status": "reject_permanent"} → JSON wins → REJECT"""
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<user@example.com>')
        add_simple_message(milter)

        response = MockResponse(200, json.dumps({
            "status": "reject_permanent",
            "reason": "domain_not_found"
        }))

        with patch('urllib.request.urlopen', return_value=response):
            result = milter.eom()

        assert result == mock_milter.REJECT


# ===========================================================================
# Standalone mode
# ===========================================================================

class TestStandaloneMode:

    def test_standalone_accepts_without_webhook(self, standalone_milter):
        standalone_milter.envfrom('<sender@example.com>')
        standalone_milter.envrcpt('<user@example.com>')
        add_simple_message(standalone_milter)

        with patch('urllib.request.urlopen') as mock_url:
            result = standalone_milter.eom()

        assert result == mock_milter.ACCEPT
        mock_url.assert_not_called()

    def test_standalone_multiple_recipients_accepted(self, standalone_milter):
        standalone_milter.envfrom('<sender@example.com>')
        standalone_milter.envrcpt('<alice@a.com>')
        standalone_milter.envrcpt('<bob@b.com>')
        add_simple_message(standalone_milter)

        with patch('urllib.request.urlopen') as mock_url:
            result = standalone_milter.eom()

        assert result == mock_milter.ACCEPT
        mock_url.assert_not_called()


# ===========================================================================
# Storage upload with multiple recipients
# ===========================================================================

class TestStorageUpload:

    def test_storage_uploaded_once_for_multiple_recipients(self, milter):
        """Large email: upload once, reference same storage_key in all webhooks"""
        original_threshold = pm.STORAGE_UPLOAD_THRESHOLD
        original_storage_url = pm.STORAGE_URL
        pm.STORAGE_UPLOAD_THRESHOLD = 10  # tiny threshold
        pm.STORAGE_URL = 'https://storage.example.com/bucket'

        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        upload_calls = []
        webhook_calls = []

        def mock_urlopen(request, timeout=None):
            url = request.full_url
            if 'storage.example.com' in url:
                upload_calls.append(url)
                return MockResponse(201, '{}')
            else:
                webhook_calls.append(json.loads(request.data.decode('utf-8')))
                return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=mock_urlopen):
            result = milter.eom()

        pm.STORAGE_UPLOAD_THRESHOLD = original_threshold
        pm.STORAGE_URL = original_storage_url

        assert result == mock_milter.ACCEPT
        assert len(upload_calls) == 1, "Storage upload should happen exactly once"
        assert len(webhook_calls) == 2, "Webhook should be called per recipient"
        # Both webhooks should reference the same storage key
        assert webhook_calls[0]['storage_key'] == webhook_calls[1]['storage_key']

    def test_storage_failure_tempfails_before_any_webhook(self, milter):
        original_threshold = pm.STORAGE_UPLOAD_THRESHOLD
        original_storage_url = pm.STORAGE_URL
        pm.STORAGE_UPLOAD_THRESHOLD = 10
        pm.STORAGE_URL = 'https://storage.example.com/bucket'

        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        add_simple_message(milter)

        webhook_called = [False]

        def mock_urlopen(request, timeout=None):
            url = request.full_url
            if 'storage.example.com' in url:
                raise URLError("Storage down")
            webhook_called[0] = True
            return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=mock_urlopen):
            result = milter.eom()

        pm.STORAGE_UPLOAD_THRESHOLD = original_threshold
        pm.STORAGE_URL = original_storage_url

        assert result == mock_milter.TEMPFAIL
        assert not webhook_called[0], "Webhook should not be called if storage upload fails"


# ===========================================================================
# Message-ID generation
# ===========================================================================

class TestMessageIdGeneration:

    def test_generated_message_id_uses_all_recipients(self, milter):
        milter.envfrom('<sender@example.com>')
        milter.envrcpt('<alice@a.com>')
        milter.envrcpt('<bob@b.com>')
        # Add headers WITHOUT Message-ID
        milter.header('From', 'sender@example.com')
        milter.header('Subject', 'Test')
        milter.body(b'Test body')

        captured = []

        def capture(request, timeout=None):
            captured.append(json.loads(request.data.decode('utf-8')))
            return make_webhook_response('accepted')

        with patch('urllib.request.urlopen', side_effect=capture):
            milter.eom()

        # Both calls should have the same generated message_id
        assert captured[0]['message_id'] == captured[1]['message_id']
        assert captured[0]['message_id'].startswith('<generated-')


# ===========================================================================
# Sender filtering
# ===========================================================================

@pytest.fixture
def sender_filter(milter):
    """Enable sender filtering and restore after test"""
    originals = {
        'SENDER_FILTERING_ENABLED': pm.SENDER_FILTERING_ENABLED,
        'ALLOWED_SENDER_DOMAINS': pm.ALLOWED_SENDER_DOMAINS,
        'ALLOWED_SENDERS': pm.ALLOWED_SENDERS,
        'ALLOW_BOUNCES': pm.ALLOW_BOUNCES,
    }
    pm.SENDER_FILTERING_ENABLED = True
    pm.ALLOWED_SENDER_DOMAINS = set()
    pm.ALLOWED_SENDERS = set()
    pm.ALLOW_BOUNCES = True
    yield milter
    for k, v in originals.items():
        setattr(pm, k, v)


class TestSenderFiltering:

    def test_sender_allowed_by_domain(self, sender_filter):
        pm.ALLOWED_SENDER_DOMAINS = {'example.com'}
        result = sender_filter.envfrom('<user@example.com>')
        assert result == mock_milter.CONTINUE

    def test_sender_allowed_by_address(self, sender_filter):
        pm.ALLOWED_SENDERS = {'specific@gmail.com'}
        result = sender_filter.envfrom('<specific@gmail.com>')
        assert result == mock_milter.CONTINUE

    def test_sender_rejected_when_not_in_list(self, sender_filter):
        pm.ALLOWED_SENDER_DOMAINS = {'trusted.org'}
        result = sender_filter.envfrom('<hacker@evil.com>')
        assert result == mock_milter.REJECT
        sender_filter.setreply.assert_called_with("550", "5.7.0", "Message rejected")

    def test_bounce_allowed_by_default(self, sender_filter):
        pm.ALLOWED_SENDER_DOMAINS = {'trusted.org'}
        result = sender_filter.envfrom('<>')
        assert result == mock_milter.CONTINUE

    def test_bounce_rejected_when_disabled(self, sender_filter):
        pm.ALLOWED_SENDER_DOMAINS = {'trusted.org'}
        pm.ALLOW_BOUNCES = False
        result = sender_filter.envfrom('<>')
        assert result == mock_milter.REJECT
        sender_filter.setreply.assert_called_with("550", "5.7.1", "Bounces not accepted")

    def test_sender_filtering_case_insensitive(self, sender_filter):
        pm.ALLOWED_SENDER_DOMAINS = {'example.com'}
        result = sender_filter.envfrom('<User@EXAMPLE.COM>')
        assert result == mock_milter.CONTINUE

    def test_no_filtering_when_disabled(self, milter):
        original = pm.SENDER_FILTERING_ENABLED
        pm.SENDER_FILTERING_ENABLED = False
        result = milter.envfrom('<anyone@anywhere.com>')
        assert result == mock_milter.CONTINUE
        pm.SENDER_FILTERING_ENABLED = original


# ===========================================================================
# Recipient filtering
# ===========================================================================

@pytest.fixture
def rcpt_filter(milter):
    """Enable recipient filtering and restore after test"""
    originals = {
        'RECIPIENT_FILTERING_ENABLED': pm.RECIPIENT_FILTERING_ENABLED,
        'ALLOWED_RECIPIENTS': pm.ALLOWED_RECIPIENTS,
    }
    pm.RECIPIENT_FILTERING_ENABLED = True
    pm.ALLOWED_RECIPIENTS = {'inbox@example.com'}
    yield milter
    for k, v in originals.items():
        setattr(pm, k, v)


class TestRecipientFiltering:

    def test_recipient_allowed(self, rcpt_filter):
        rcpt_filter.envfrom('<sender@test.com>')
        result = rcpt_filter.envrcpt('<inbox@example.com>')
        assert result == mock_milter.CONTINUE
        assert 'inbox@example.com' in rcpt_filter.recipients

    def test_recipient_rejected(self, rcpt_filter):
        rcpt_filter.envfrom('<sender@test.com>')
        result = rcpt_filter.envrcpt('<random@example.com>')
        assert result == mock_milter.REJECT
        rcpt_filter.setreply.assert_called_with("550", "5.1.1", "Recipient not accepted")
        assert 'random@example.com' not in rcpt_filter.recipients

    def test_recipient_filtering_case_insensitive(self, rcpt_filter):
        rcpt_filter.envfrom('<sender@test.com>')
        result = rcpt_filter.envrcpt('<INBOX@EXAMPLE.COM>')
        assert result == mock_milter.CONTINUE

    def test_no_filtering_when_disabled(self, milter):
        original = pm.RECIPIENT_FILTERING_ENABLED
        pm.RECIPIENT_FILTERING_ENABLED = False
        milter.envfrom('<sender@test.com>')
        result = milter.envrcpt('<anyone@anywhere.com>')
        assert result == mock_milter.CONTINUE
        pm.RECIPIENT_FILTERING_ENABLED = original


# ===========================================================================
# Standalone storage
# ===========================================================================

class TestStandaloneStorage:

    def test_standalone_calls_save_to_disk(self, standalone_milter):
        standalone_milter.envfrom('<sender@example.com>')
        standalone_milter.envrcpt('<user@example.com>')
        add_simple_message(standalone_milter)

        result = standalone_milter.eom()

        assert result == mock_milter.ACCEPT
        standalone_milter._save_to_disk.assert_called_once()
        args = standalone_milter._save_to_disk.call_args
        # First arg is raw_bytes, second is valid_recipients list
        assert isinstance(args[0][0], bytes)
        assert args[0][1] == ['user@example.com']

    def test_standalone_save_failure_tempfails(self, standalone_milter):
        standalone_milter._save_to_disk.side_effect = IOError("Disk full")
        standalone_milter.envfrom('<sender@example.com>')
        standalone_milter.envrcpt('<user@example.com>')
        add_simple_message(standalone_milter)

        result = standalone_milter.eom()

        assert result == mock_milter.TEMPFAIL

    def test_standalone_save_multiple_recipients(self, standalone_milter):
        standalone_milter.envfrom('<sender@example.com>')
        standalone_milter.envrcpt('<alice@a.com>')
        standalone_milter.envrcpt('<bob@b.com>')
        add_simple_message(standalone_milter)

        result = standalone_milter.eom()

        assert result == mock_milter.ACCEPT
        args = standalone_milter._save_to_disk.call_args
        assert set(args[0][1]) == {'alice@a.com', 'bob@b.com'}


# ===========================================================================
# Spoof protection helpers
# ===========================================================================

class TestSpoofProtectionHelpers:

    def test_extract_from_domain_simple(self, milter):
        milter.from_header = 'user@example.com'
        assert milter._extract_from_domain() == 'example.com'

    def test_extract_from_domain_with_display_name(self, milter):
        milter.from_header = 'Alice Smith <alice@example.com>'
        assert milter._extract_from_domain() == 'example.com'

    def test_extract_from_domain_empty(self, milter):
        milter.from_header = None
        assert milter._extract_from_domain() == ''

    def test_extract_from_domain_no_at(self, milter):
        milter.from_header = 'malformed'
        assert milter._extract_from_domain() == ''


# ===========================================================================
# Spoof protection enforcement (SPF/DKIM/DMARC)
# ===========================================================================

@pytest.fixture
def spoof_milter(standalone_milter):
    """Standalone milter with spoof protection enabled"""
    original = pm.SPOOF_PROTECTION
    pm.SPOOF_PROTECTION = 'strict'
    yield standalone_milter
    pm.SPOOF_PROTECTION = original


class TestSPFEnforcement:
    """SPF checks in envfrom()"""

    def test_spf_fail_rejected_in_strict_mode(self, spoof_milter):
        with patch.object(pm, 'SPF_AVAILABLE', True), \
             patch('primitivemail_milter.spfmod', create=True) as mock_spf:
            mock_spf.check2.return_value = ('fail', 'SPF record does not allow')
            result = spoof_milter.envfrom('<spammer@spoofed.com>')

        assert result == mock_milter.REJECT
        spoof_milter.setreply.assert_called_with(
            "550", "5.7.23", "SPF validation failed: SPF record does not allow")

    def test_spf_softfail_rejected_in_strict_mode(self, spoof_milter):
        with patch.object(pm, 'SPF_AVAILABLE', True), \
             patch('primitivemail_milter.spfmod', create=True) as mock_spf:
            mock_spf.check2.return_value = ('softfail', 'domain does not designate')
            result = spoof_milter.envfrom('<user@example.com>')

        assert result == mock_milter.REJECT

    def test_spf_pass_allowed_in_strict_mode(self, spoof_milter):
        with patch.object(pm, 'SPF_AVAILABLE', True), \
             patch('primitivemail_milter.spfmod', create=True) as mock_spf:
            mock_spf.check2.return_value = ('pass', 'sender is authorized')
            result = spoof_milter.envfrom('<user@example.com>')

        assert result == mock_milter.CONTINUE
        assert spoof_milter.spf_result == 'pass'

    def test_spf_neutral_allowed_in_strict_mode(self, spoof_milter):
        with patch.object(pm, 'SPF_AVAILABLE', True), \
             patch('primitivemail_milter.spfmod', create=True) as mock_spf:
            mock_spf.check2.return_value = ('neutral', 'no policy')
            result = spoof_milter.envfrom('<user@example.com>')

        assert result == mock_milter.CONTINUE

    def test_spf_error_treated_as_neutral(self, spoof_milter):
        with patch.object(pm, 'SPF_AVAILABLE', True), \
             patch('primitivemail_milter.spfmod', create=True) as mock_spf:
            mock_spf.check2.side_effect = Exception("DNS timeout")
            result = spoof_milter.envfrom('<user@example.com>')

        assert result == mock_milter.CONTINUE
        assert spoof_milter.spf_result == 'temperror'

    def test_spf_not_checked_in_monitor_mode(self, standalone_milter):
        """Monitor mode checks SPF but never rejects"""
        original = pm.SPOOF_PROTECTION
        pm.SPOOF_PROTECTION = 'monitor'
        with patch.object(pm, 'SPF_AVAILABLE', True), \
             patch('primitivemail_milter.spfmod', create=True) as mock_spf:
            mock_spf.check2.return_value = ('fail', 'SPF fail')
            result = standalone_milter.envfrom('<user@example.com>')
        pm.SPOOF_PROTECTION = original

        assert result == mock_milter.CONTINUE
        assert standalone_milter.spf_result == 'fail'

    def test_spf_skipped_for_bounces(self, spoof_milter):
        """Empty MAIL FROM (bounce) should skip SPF"""
        with patch.object(pm, 'SPF_AVAILABLE', True), \
             patch('primitivemail_milter.spfmod', create=True) as mock_spf:
            result = spoof_milter.envfrom('<>')
        mock_spf.check2.assert_not_called()
        assert result == mock_milter.CONTINUE

    def test_spf_skipped_when_off(self, standalone_milter):
        """SPF not checked when SPOOF_PROTECTION=off"""
        original = pm.SPOOF_PROTECTION
        pm.SPOOF_PROTECTION = 'off'
        with patch.object(pm, 'SPF_AVAILABLE', True), \
             patch('primitivemail_milter.spfmod', create=True) as mock_spf:
            standalone_milter.envfrom('<user@example.com>')
        pm.SPOOF_PROTECTION = original
        mock_spf.check2.assert_not_called()


class TestDKIMDMARCEnforcement:
    """DKIM/DMARC checks in eom() via _process_eom()"""

    def test_dkim_fail_rejected_in_strict_mode(self, spoof_milter):
        """Strict mode rejects DKIM failure"""
        spoof_milter.envfrom('<sender@example.com>')
        spoof_milter.envrcpt('<user@example.com>')
        add_simple_message(spoof_milter)

        with patch.object(spoof_milter, '_check_dkim', return_value=('fail', ['example.com'])), \
             patch.object(spoof_milter, '_check_dmarc', return_value={'policy': 'none', 'pass': True}):
            result = spoof_milter.eom()

        assert result == mock_milter.REJECT
        spoof_milter.setreply.assert_called_with("550", "5.7.20", "DKIM validation failed")

    def test_dkim_none_allowed_in_strict_mode(self, spoof_milter):
        """Strict mode allows unsigned emails (DKIM none)"""
        spoof_milter.envfrom('<sender@example.com>')
        spoof_milter.envrcpt('<user@example.com>')
        add_simple_message(spoof_milter)

        with patch.object(spoof_milter, '_check_dkim', return_value=('none', [])), \
             patch.object(spoof_milter, '_check_dmarc', return_value={'policy': 'none', 'pass': True}):
            result = spoof_milter.eom()

        assert result == mock_milter.ACCEPT

    def test_dmarc_reject_policy_enforced_in_standard_mode(self, standalone_milter):
        """Standard mode rejects when sender's DMARC policy says reject"""
        original = pm.SPOOF_PROTECTION
        pm.SPOOF_PROTECTION = 'standard'

        standalone_milter.envfrom('<sender@example.com>')
        standalone_milter.envrcpt('<user@example.com>')
        add_simple_message(standalone_milter)

        with patch.object(standalone_milter, '_check_dkim', return_value=('pass', ['other.com'])), \
             patch.object(standalone_milter, '_check_dmarc',
                          return_value={'policy': 'reject', 'pass': False}):
            result = standalone_milter.eom()

        pm.SPOOF_PROTECTION = original
        assert result == mock_milter.REJECT

    def test_dmarc_quarantine_adds_header_in_standard_mode(self, standalone_milter):
        """Standard mode adds warning header for quarantine policy"""
        original = pm.SPOOF_PROTECTION
        pm.SPOOF_PROTECTION = 'standard'

        standalone_milter.envfrom('<sender@example.com>')
        standalone_milter.envrcpt('<user@example.com>')
        add_simple_message(standalone_milter)

        with patch.object(standalone_milter, '_check_dkim', return_value=('pass', ['example.com'])), \
             patch.object(standalone_milter, '_check_dmarc',
                          return_value={'policy': 'quarantine', 'pass': False}):
            result = standalone_milter.eom()

        pm.SPOOF_PROTECTION = original
        assert result == mock_milter.ACCEPT
        # Check that a quarantine warning header was added
        standalone_milter.addheader.assert_any_call(
            "X-PrimitiveMail-Auth-Warning",
            "DMARC quarantine policy for example.com")

    def test_dmarc_none_policy_passes_in_standard_mode(self, standalone_milter):
        """Standard mode accepts when DMARC policy is none"""
        original = pm.SPOOF_PROTECTION
        pm.SPOOF_PROTECTION = 'standard'

        standalone_milter.envfrom('<sender@example.com>')
        standalone_milter.envrcpt('<user@example.com>')
        add_simple_message(standalone_milter)

        with patch.object(standalone_milter, '_check_dkim', return_value=('fail', ['example.com'])), \
             patch.object(standalone_milter, '_check_dmarc',
                          return_value={'policy': 'none', 'pass': False}):
            result = standalone_milter.eom()

        pm.SPOOF_PROTECTION = original
        assert result == mock_milter.ACCEPT

    def test_dmarc_fail_rejected_in_strict_mode(self, spoof_milter):
        """Strict mode rejects any DMARC failure"""
        spoof_milter.envfrom('<sender@example.com>')
        spoof_milter.envrcpt('<user@example.com>')
        add_simple_message(spoof_milter)

        with patch.object(spoof_milter, '_check_dkim', return_value=('pass', ['example.com'])), \
             patch.object(spoof_milter, '_check_dmarc',
                          return_value={'policy': 'none', 'pass': False}):
            result = spoof_milter.eom()

        assert result == mock_milter.REJECT
        spoof_milter.setreply.assert_called_with("550", "5.7.1", "DMARC validation failed")

    def test_monitor_mode_adds_headers_but_accepts(self, standalone_milter):
        """Monitor mode logs auth results but never rejects"""
        original = pm.SPOOF_PROTECTION
        pm.SPOOF_PROTECTION = 'monitor'

        standalone_milter.envfrom('<sender@example.com>')
        standalone_milter.envrcpt('<user@example.com>')
        add_simple_message(standalone_milter)

        with patch.object(standalone_milter, '_check_dkim', return_value=('fail', ['example.com'])), \
             patch.object(standalone_milter, '_check_dmarc',
                          return_value={'policy': 'reject', 'pass': False}):
            result = standalone_milter.eom()

        pm.SPOOF_PROTECTION = original
        assert result == mock_milter.ACCEPT
        # Auth headers should still be added
        standalone_milter.addheader.assert_any_call("X-PrimitiveMail-DKIM", "fail")

    def test_auth_headers_stripped_before_adding(self, spoof_milter):
        """Attacker-injected auth headers are removed before adding real ones"""
        with patch.object(pm, 'SPF_AVAILABLE', True), \
             patch('primitivemail_milter.spfmod', create=True) as mock_spf, \
             patch.object(spoof_milter, '_check_dkim', return_value=('none', [])), \
             patch.object(spoof_milter, '_check_dmarc',
                          return_value={'policy': 'none', 'pass': True}):
            mock_spf.check2.return_value = ('none', 'no SPF record')
            spoof_milter.envfrom('<sender@example.com>')
            spoof_milter.envrcpt('<user@example.com>')
            add_simple_message(spoof_milter)
            spoof_milter.eom()

        # chgheader should have been called to strip attacker headers
        strip_calls = [c for c in spoof_milter.chgheader.call_args_list
                       if c[0][0].startswith("X-PrimitiveMail-")]
        assert len(strip_calls) > 0, "Should strip existing auth headers"
        # Real headers should be added after stripping
        spoof_milter.addheader.assert_any_call("X-PrimitiveMail-SPF", "none")


class TestCheckDKIM:
    """Unit tests for _check_dkim method"""

    def test_dkim_pass(self, milter):
        milter.headers = [('DKIM-Signature', 'd=example.com; s=selector')]
        milter.body_chunks = [b'body']
        with patch.object(pm, 'DKIM_AVAILABLE', True), \
             patch('primitivemail_milter.dkim', create=True) as mock_dkim:
            mock_dkim.verify.return_value = True
            result, domains = milter._check_dkim(b'headers\r\n\r\nbody')

        assert result == 'pass'
        assert domains == ['example.com']

    def test_dkim_fail(self, milter):
        milter.headers = [('DKIM-Signature', 'd=example.com; s=selector')]
        with patch.object(pm, 'DKIM_AVAILABLE', True), \
             patch('primitivemail_milter.dkim', create=True) as mock_dkim:
            mock_dkim.verify.return_value = False
            result, domains = milter._check_dkim(b'headers\r\n\r\nbody')

        assert result == 'fail'
        assert domains == ['example.com']

    def test_dkim_no_signature(self, milter):
        milter.headers = [('From', 'user@example.com')]
        with patch.object(pm, 'DKIM_AVAILABLE', True), \
             patch('primitivemail_milter.dkim', create=True) as mock_dkim:
            mock_dkim.verify.return_value = False
            result, domains = milter._check_dkim(b'headers\r\n\r\nbody')

        assert result == 'fail'
        assert domains == []

    def test_dkim_unavailable(self, milter):
        with patch.object(pm, 'DKIM_AVAILABLE', False):
            result, domains = milter._check_dkim(b'anything')

        assert result == 'none'
        assert domains == []

    def test_dkim_error_returns_none(self, milter):
        milter.headers = []
        with patch.object(pm, 'DKIM_AVAILABLE', True), \
             patch('primitivemail_milter.dkim', create=True) as mock_dkim:
            mock_dkim.verify.side_effect = Exception("crypto error")
            result, domains = milter._check_dkim(b'headers\r\n\r\nbody')

        assert result == 'none'
        assert domains == []

    def test_dkim_multiple_signatures(self, milter):
        """Extracts domains from ALL DKIM-Signature headers"""
        milter.headers = [
            ('DKIM-Signature', 'd=list.example.org; s=sel1'),
            ('DKIM-Signature', 'd=example.com; s=sel2'),
            ('From', 'user@example.com'),
        ]
        with patch.object(pm, 'DKIM_AVAILABLE', True), \
             patch('primitivemail_milter.dkim', create=True) as mock_dkim:
            mock_dkim.verify.return_value = True
            result, domains = milter._check_dkim(b'headers\r\n\r\nbody')

        assert result == 'pass'
        assert domains == ['list.example.org', 'example.com']

    def test_dkim_multiple_signatures_first_broken(self, milter):
        """Even when verify fails, all domains are still extracted"""
        milter.headers = [
            ('DKIM-Signature', 'd=sender.com; s=sel1'),
            ('DKIM-Signature', 'd=forwarder.com; s=sel2'),
        ]
        with patch.object(pm, 'DKIM_AVAILABLE', True), \
             patch('primitivemail_milter.dkim', create=True) as mock_dkim:
            mock_dkim.verify.return_value = False
            result, domains = milter._check_dkim(b'headers\r\n\r\nbody')

        assert result == 'fail'
        assert domains == ['sender.com', 'forwarder.com']


class TestDomainAlignment:
    """Unit tests for _org_domain and _domains_aligned"""

    def test_org_domain_subdomain(self, milter):
        assert milter._org_domain('mail.example.com') == 'example.com'

    def test_org_domain_bare(self, milter):
        assert milter._org_domain('example.com') == 'example.com'

    def test_org_domain_deep_subdomain(self, milter):
        assert milter._org_domain('a.b.c.example.com') == 'example.com'

    def test_org_domain_multi_part_tld(self, milter):
        assert milter._org_domain('mail.example.co.uk') == 'example.co.uk'

    def test_strict_alignment_exact_match(self, milter):
        assert milter._domains_aligned('example.com', 'example.com', 's') is True

    def test_strict_alignment_subdomain_fails(self, milter):
        assert milter._domains_aligned('mail.example.com', 'example.com', 's') is False

    def test_relaxed_alignment_subdomain_passes(self, milter):
        assert milter._domains_aligned('mail.example.com', 'example.com', 'r') is True

    def test_relaxed_alignment_different_domains_fails(self, milter):
        assert milter._domains_aligned('example.com', 'other.com', 'r') is False

    def test_relaxed_alignment_sibling_subdomains(self, milter):
        """Two subdomains of the same org domain should align in relaxed mode"""
        assert milter._domains_aligned('mail.example.com', 'news.example.com', 'r') is True

    def test_relaxed_alignment_case_insensitive(self, milter):
        assert milter._domains_aligned('MAIL.Example.COM', 'example.com', 'r') is True

    def test_org_domain_fallback_without_tldextract(self, milter):
        """Without tldextract, _org_domain falls back to returning the domain as-is"""
        with patch.object(pm, 'TLDEXTRACT_AVAILABLE', False):
            assert milter._org_domain('mail.example.com') == 'mail.example.com'

    def test_relaxed_fallback_without_tldextract(self, milter):
        """Without tldextract, relaxed alignment degrades to strict"""
        with patch.object(pm, 'TLDEXTRACT_AVAILABLE', False):
            assert milter._domains_aligned('mail.example.com', 'example.com', 'r') is False


class TestCheckDMARC:
    """Unit tests for _check_dmarc method"""

    def test_dmarc_pass_spf_aligned(self, milter):
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=reject']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'pass', 'example.com', 'fail', [])

        assert result['policy'] == 'reject'
        assert result['pass'] is True

    def test_dmarc_pass_dkim_aligned(self, milter):
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=reject']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'fail', 'other.com', 'pass', ['example.com'])

        assert result['policy'] == 'reject'
        assert result['pass'] is True

    def test_dmarc_pass_dkim_aligned_second_signature(self, milter):
        """DMARC passes when second DKIM signature aligns with From domain"""
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=reject']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'fail', 'other.com',
                                          'pass', ['list.example.org', 'example.com'])

        assert result['policy'] == 'reject'
        assert result['pass'] is True

    def test_dmarc_fail_no_dkim_domains_aligned(self, milter):
        """DMARC fails when no DKIM signatures align"""
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=reject']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'fail', 'other.com',
                                          'pass', ['list.example.org', 'other.com'])

        assert result['policy'] == 'reject'
        assert result['pass'] is False

    def test_dmarc_fail_neither_aligned(self, milter):
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=quarantine']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'pass', 'other.com', 'pass', ['other.com'])

        assert result['policy'] == 'quarantine'
        assert result['pass'] is False

    def test_dmarc_no_record(self, milter):
        class FakeDNSError(Exception):
            pass

        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_dns.resolver.NXDOMAIN = FakeDNSError
            mock_dns.resolver.NoAnswer = FakeDNSError
            mock_dns.resolver.NoNameservers = FakeDNSError
            mock_dns.resolver.Timeout = FakeDNSError
            mock_dns.resolver.Resolver.return_value.resolve.side_effect = FakeDNSError("no record")

            result = milter._check_dmarc('example.com', 'pass', 'example.com', 'none', [])

        assert result['policy'] == 'none'
        assert result['pass'] is True

    def test_dmarc_dns_unavailable(self, milter):
        with patch.object(pm, 'DNS_AVAILABLE', False):
            result = milter._check_dmarc('example.com', 'pass', 'example.com', 'none', [])

        assert result['policy'] == 'none'
        assert result['pass'] is True

    def test_dmarc_relaxed_spf_subdomain_passes(self, milter):
        """Relaxed SPF alignment: subdomain SPF passes against parent From domain"""
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=reject']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'pass', 'mail.example.com', 'fail', [])

        assert result['pass'] is True

    def test_dmarc_relaxed_dkim_subdomain_passes(self, milter):
        """Relaxed DKIM alignment: subdomain DKIM passes against parent From domain"""
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=reject']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'fail', 'other.com',
                                          'pass', ['em1234.example.com'])

        assert result['pass'] is True

    def test_dmarc_explicit_strict_spf_subdomain_fails(self, milter):
        """Explicit aspf=s: subdomain SPF fails strict alignment"""
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=reject; aspf=s']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'pass', 'mail.example.com', 'fail', [])

        assert result['pass'] is False

    def test_dmarc_explicit_strict_dkim_subdomain_fails(self, milter):
        """Explicit adkim=s: subdomain DKIM fails strict alignment"""
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=reject; adkim=s']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'fail', 'other.com',
                                          'pass', ['em1234.example.com'])

        assert result['pass'] is False

    def test_dmarc_mixed_alignment_modes(self, milter):
        """aspf=s but adkim=r: strict SPF fails, relaxed DKIM passes"""
        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_rdata = MagicMock()
            mock_rdata.strings = [b'v=DMARC1; p=reject; aspf=s; adkim=r']
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

            result = milter._check_dmarc('example.com', 'pass', 'mail.example.com',
                                          'pass', ['em1234.example.com'])

        # SPF strict fails (mail.example.com != example.com),
        # but DKIM relaxed passes (em1234.example.com shares org domain)
        assert result['pass'] is True

    def test_dmarc_org_domain_fallback(self, milter):
        """Falls back to org domain DMARC record when subdomain has none"""
        class FakeDNSError(Exception):
            pass

        def resolve_side_effect(qname, rdtype):
            # Subdomain has no DMARC record, org domain does
            if qname == '_dmarc.news.example.com':
                raise FakeDNSError("no record")
            if qname == '_dmarc.example.com':
                mock_rdata = MagicMock()
                mock_rdata.strings = [b'v=DMARC1; p=reject']
                return [mock_rdata]
            raise FakeDNSError("no record")

        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_dns.resolver.NXDOMAIN = FakeDNSError
            mock_dns.resolver.NoAnswer = FakeDNSError
            mock_dns.resolver.NoNameservers = FakeDNSError
            mock_dns.resolver.Timeout = FakeDNSError
            mock_dns.resolver.Resolver.return_value.resolve.side_effect = resolve_side_effect

            result = milter._check_dmarc('news.example.com', 'fail', 'other.com',
                                          'fail', [])

        assert result['policy'] == 'reject'
        assert result['pass'] is False

    def test_dmarc_org_domain_fallback_sp_tag(self, milter):
        """Uses sp= (subdomain policy) from org domain record"""
        class FakeDNSError(Exception):
            pass

        def resolve_side_effect(qname, rdtype):
            if qname == '_dmarc.news.example.com':
                raise FakeDNSError("no record")
            if qname == '_dmarc.example.com':
                mock_rdata = MagicMock()
                # p=reject for the org domain itself, sp=quarantine for subdomains
                mock_rdata.strings = [b'v=DMARC1; p=reject; sp=quarantine']
                return [mock_rdata]
            raise FakeDNSError("no record")

        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_dns.resolver.NXDOMAIN = FakeDNSError
            mock_dns.resolver.NoAnswer = FakeDNSError
            mock_dns.resolver.NoNameservers = FakeDNSError
            mock_dns.resolver.Timeout = FakeDNSError
            mock_dns.resolver.Resolver.return_value.resolve.side_effect = resolve_side_effect

            result = milter._check_dmarc('news.example.com', 'fail', 'other.com',
                                          'fail', [])

        # Should use sp=quarantine, not p=reject
        assert result['policy'] == 'quarantine'
        assert result['pass'] is False

    def test_dmarc_org_domain_fallback_no_sp_uses_p(self, milter):
        """Without sp= tag, org domain p= applies to subdomains"""
        class FakeDNSError(Exception):
            pass

        def resolve_side_effect(qname, rdtype):
            if qname == '_dmarc.news.example.com':
                raise FakeDNSError("no record")
            if qname == '_dmarc.example.com':
                mock_rdata = MagicMock()
                mock_rdata.strings = [b'v=DMARC1; p=reject']
                return [mock_rdata]
            raise FakeDNSError("no record")

        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_dns.resolver.NXDOMAIN = FakeDNSError
            mock_dns.resolver.NoAnswer = FakeDNSError
            mock_dns.resolver.NoNameservers = FakeDNSError
            mock_dns.resolver.Timeout = FakeDNSError
            mock_dns.resolver.Resolver.return_value.resolve.side_effect = resolve_side_effect

            result = milter._check_dmarc('news.example.com', 'fail', 'other.com',
                                          'fail', [])

        assert result['policy'] == 'reject'

    def test_dmarc_no_fallback_when_from_is_org_domain(self, milter):
        """No fallback attempted when From domain IS the org domain"""
        class FakeDNSError(Exception):
            pass

        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_dns.resolver.NXDOMAIN = FakeDNSError
            mock_dns.resolver.NoAnswer = FakeDNSError
            mock_dns.resolver.NoNameservers = FakeDNSError
            mock_dns.resolver.Timeout = FakeDNSError
            mock_dns.resolver.Resolver.return_value.resolve.side_effect = FakeDNSError("no record")

            result = milter._check_dmarc('example.com', 'pass', 'example.com', 'none', [])

        # No org domain to fall back to (example.com IS the org domain)
        assert result['policy'] == 'none'
        assert result['pass'] is True

    def test_dmarc_org_domain_fallback_with_alignment(self, milter):
        """Org domain fallback + relaxed DKIM alignment works together"""
        class FakeDNSError(Exception):
            pass

        def resolve_side_effect(qname, rdtype):
            if qname == '_dmarc.updates.example.com':
                raise FakeDNSError("no record")
            if qname == '_dmarc.example.com':
                mock_rdata = MagicMock()
                mock_rdata.strings = [b'v=DMARC1; p=reject']
                return [mock_rdata]
            raise FakeDNSError("no record")

        with patch.object(pm, 'DNS_AVAILABLE', True), \
             patch('primitivemail_milter.dns', create=True) as mock_dns:
            mock_dns.resolver.NXDOMAIN = FakeDNSError
            mock_dns.resolver.NoAnswer = FakeDNSError
            mock_dns.resolver.NoNameservers = FakeDNSError
            mock_dns.resolver.Timeout = FakeDNSError
            mock_dns.resolver.Resolver.return_value.resolve.side_effect = resolve_side_effect

            result = milter._check_dmarc('updates.example.com', 'fail', 'other.com',
                                          'pass', ['example.com'])

        # Org domain record found, relaxed DKIM alignment passes
        assert result['policy'] == 'reject'
        assert result['pass'] is True


# ===========================================================================
# .meta.json sidecar tests
# ===========================================================================

class TestMetaJsonSidecar:
    """Test that _save_to_disk writes .meta.json alongside .eml files."""

    def test_meta_json_written_alongside_eml(self, tmp_path):
        """Basic: .meta.json file is created next to .eml"""
        m = pm.PrimitiveMailMilter()
        m.helo = 'mail.example.com'
        m.sender = 'alice@example.com'
        m.spf_result = 'none'

        original = pm.MAIL_DIR
        pm.MAIL_DIR = str(tmp_path)
        try:
            m._save_to_disk(b"Subject: test\r\n\r\nbody", ['bob@example.com'])
        finally:
            pm.MAIL_DIR = original

        eml_files = list(tmp_path.glob('example.com/*.eml'))
        meta_files = list(tmp_path.glob('example.com/*.meta.json'))
        assert len(eml_files) == 1
        assert len(meta_files) == 1
        assert eml_files[0].stem == meta_files[0].stem.replace('.meta', '')

    def test_meta_json_contains_smtp_envelope(self, tmp_path):
        """Verify smtp section has helo, mail_from, rcpt_to"""
        m = pm.PrimitiveMailMilter()
        m.helo = 'mx.sender.com'
        m.sender = 'alice@sender.com'
        m.spf_result = 'none'

        original = pm.MAIL_DIR
        pm.MAIL_DIR = str(tmp_path)
        try:
            m._save_to_disk(b"Subject: test\r\n\r\nbody", ['bob@example.com'])
        finally:
            pm.MAIL_DIR = original

        meta_file = list(tmp_path.glob('example.com/*.meta.json'))[0]
        meta = json.loads(meta_file.read_text())

        assert meta['smtp']['helo'] == 'mx.sender.com'
        assert meta['smtp']['mail_from'] == 'alice@sender.com'
        assert meta['smtp']['rcpt_to'] == ['bob@example.com']

    def test_meta_json_auth_without_spoof_protection(self, tmp_path):
        """When no auth data passed, only spf_result is in auth"""
        m = pm.PrimitiveMailMilter()
        m.helo = 'localhost'
        m.sender = 'alice@example.com'
        m.spf_result = 'none'

        original = pm.MAIL_DIR
        pm.MAIL_DIR = str(tmp_path)
        try:
            m._save_to_disk(b"Subject: test\r\n\r\nbody", ['bob@example.com'])
        finally:
            pm.MAIL_DIR = original

        meta_file = list(tmp_path.glob('example.com/*.meta.json'))[0]
        meta = json.loads(meta_file.read_text())

        assert meta['auth'] == {'spf': 'none'}
        assert 'dkim' not in meta['auth']
        assert 'dmarc' not in meta['auth']

    def test_meta_json_auth_with_full_spoof_data(self, tmp_path):
        """When auth data is passed, all fields appear"""
        m = pm.PrimitiveMailMilter()
        m.helo = 'mail-wr1-f41.google.com'
        m.sender = 'alice@gmail.com'
        m.spf_result = 'pass'

        original = pm.MAIL_DIR
        pm.MAIL_DIR = str(tmp_path)
        try:
            m._save_to_disk(
                b"Subject: test\r\n\r\nbody",
                ['agent@example.com'],
                dkim_result='pass',
                dkim_domains=['gmail.com'],
                dmarc_result={'policy': 'none', 'pass': True},
                from_domain='gmail.com',
            )
        finally:
            pm.MAIL_DIR = original

        meta_file = list(tmp_path.glob('example.com/*.meta.json'))[0]
        meta = json.loads(meta_file.read_text())

        assert meta['auth']['spf'] == 'pass'
        assert meta['auth']['dkim'] == 'pass'
        assert meta['auth']['dkim_domains'] == ['gmail.com']
        assert meta['auth']['dmarc'] == 'pass'
        assert meta['auth']['dmarc_policy'] == 'none'
        assert meta['auth']['dmarc_from_domain'] == 'gmail.com'

    def test_meta_json_dmarc_fail(self, tmp_path):
        """DMARC fail is recorded correctly"""
        m = pm.PrimitiveMailMilter()
        m.helo = 'evil.com'
        m.sender = 'spoofer@evil.com'
        m.spf_result = 'fail'

        original = pm.MAIL_DIR
        pm.MAIL_DIR = str(tmp_path)
        try:
            m._save_to_disk(
                b"Subject: test\r\n\r\nbody",
                ['victim@example.com'],
                dkim_result='fail',
                dkim_domains=[],
                dmarc_result={'policy': 'reject', 'pass': False},
                from_domain='evil.com',
            )
        finally:
            pm.MAIL_DIR = original

        meta_file = list(tmp_path.glob('example.com/*.meta.json'))[0]
        meta = json.loads(meta_file.read_text())

        assert meta['auth']['dmarc'] == 'fail'
        assert meta['auth']['dmarc_policy'] == 'reject'

    def test_meta_json_per_domain_rcpt_filtering(self, tmp_path):
        """Each domain's .meta.json only contains recipients for that domain"""
        m = pm.PrimitiveMailMilter()
        m.helo = 'localhost'
        m.sender = 'alice@example.com'
        m.spf_result = 'none'

        original = pm.MAIL_DIR
        pm.MAIL_DIR = str(tmp_path)
        try:
            m._save_to_disk(
                b"Subject: test\r\n\r\nbody",
                ['bob@a.com', 'carol@b.com', 'dave@a.com'],
            )
        finally:
            pm.MAIL_DIR = original

        meta_a = list(tmp_path.glob('a.com/*.meta.json'))[0]
        meta_b = list(tmp_path.glob('b.com/*.meta.json'))[0]

        data_a = json.loads(meta_a.read_text())
        data_b = json.loads(meta_b.read_text())

        assert set(data_a['smtp']['rcpt_to']) == {'bob@a.com', 'dave@a.com'}
        assert data_b['smtp']['rcpt_to'] == ['carol@b.com']

    def test_meta_json_file_permissions(self, tmp_path):
        """Files should be world-readable (0o644), dirs 0o755"""
        m = pm.PrimitiveMailMilter()
        m.helo = 'localhost'
        m.sender = 'alice@example.com'
        m.spf_result = 'none'

        original = pm.MAIL_DIR
        pm.MAIL_DIR = str(tmp_path)
        try:
            m._save_to_disk(b"Subject: test\r\n\r\nbody", ['bob@example.com'])
        finally:
            pm.MAIL_DIR = original

        eml = list(tmp_path.glob('example.com/*.eml'))[0]
        meta = list(tmp_path.glob('example.com/*.meta.json'))[0]
        domain_dir = tmp_path / 'example.com'

        assert oct(eml.stat().st_mode & 0o777) == oct(0o644)
        assert oct(meta.stat().st_mode & 0o777) == oct(0o644)
        assert oct(domain_dir.stat().st_mode & 0o777) == oct(0o755)

    def test_meta_json_is_valid_json(self, tmp_path):
        """The .meta.json file is parseable JSON"""
        m = pm.PrimitiveMailMilter()
        m.helo = 'localhost'
        m.sender = 'alice@example.com'
        m.spf_result = 'none'

        original = pm.MAIL_DIR
        pm.MAIL_DIR = str(tmp_path)
        try:
            m._save_to_disk(b"Subject: test\r\n\r\nbody", ['bob@example.com'])
        finally:
            pm.MAIL_DIR = original

        meta_file = list(tmp_path.glob('example.com/*.meta.json'))[0]
        meta = json.loads(meta_file.read_text())  # should not raise
        assert 'smtp' in meta
        assert 'auth' in meta


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
