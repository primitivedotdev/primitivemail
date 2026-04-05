#!/usr/bin/env python3
"""
CRITICAL TESTS for store_mail.py ingestion API integration
These tests verify that SMTP response codes are correctly mapped.

SMTP Exit Codes (Postfix):
  0  → 250 OK (message accepted)
  67 → 550 5.1.1 (permanent rejection, no such user)
  75 → 451 4.3.0 (temporary failure, try again later)

Ingestion API Responses:
  HTTP 200 + {"status": "accepted"} → exit 0 (250)
  HTTP 200 + {"status": "reject_permanent"} → exit 67 (550)
  HTTP 401/500/timeout/network error → exit 75 (451)
"""

import pytest
import json
from unittest.mock import patch, MagicMock, Mock
from urllib.error import HTTPError, URLError
from io import BytesIO
from store_mail import EmailProcessor


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


class TestIngestionAPIResponses:
    """Test all ingestion API response scenarios"""

    @pytest.fixture
    def processor(self):
        """Create processor with webhook configured"""
        return EmailProcessor(
            webhook_url="https://test.example.com/api/inbound",
            webhook_secret="test-secret-123"
        )

    def make_email(self, to="test@example.com"):
        """Create a minimal valid email"""
        return f"""From: sender@example.com
To: {to}
Subject: Test
X-Original-To: {to}
Message-ID: <test123@example.com>

Test email body.
"""

    # ========================================================================
    # TEST 1: ACCEPTED (Most important - this is the happy path)
    # ========================================================================
    def test_accepted_response_returns_exit_0(self, processor):
        """
        CRITICAL: API returns 'accepted' → script must exit 0 → Postfix sends 250 OK
        """
        email = self.make_email()

        # Mock successful API response
        mock_response = MockResponse(200, json.dumps({
            "status": "accepted"
        }))

        with patch('urllib.request.urlopen', return_value=mock_response):
            exit_code = processor.process_email(email)

        assert exit_code == 0, "Accepted email must return exit 0 (250 OK)"

    # ========================================================================
    # TEST 2: PERMANENT REJECTION (Domain not verified, blocklist, etc.)
    # ========================================================================
    @pytest.mark.parametrize("reason", [
        "domain_not_found",
        "domain_unverified",
        "domain_inactive",
        "sender_blocked",
        "sender_not_whitelisted",
    ])
    def test_reject_permanent_returns_exit_67(self, processor, reason):
        """
        CRITICAL: API returns 'reject_permanent' → script must exit 67 → Postfix sends 550
        """
        email = self.make_email()

        mock_response = MockResponse(200, json.dumps({
            "status": "reject_permanent",
            "reason": reason
        }))

        with patch('urllib.request.urlopen', return_value=mock_response):
            exit_code = processor.process_email(email)

        assert exit_code == 67, f"Permanent rejection ({reason}) must return exit 67 (550)"

    # ========================================================================
    # TEST 3: HTTP errors without JSON status → tempfail (exit 75)
    # ========================================================================
    @pytest.mark.parametrize("http_status", [400, 401, 403, 404, 422, 500, 502, 503])
    def test_http_errors_without_json_status_return_exit_75(self, processor, http_status):
        """
        HTTP 4xx/5xx without a JSON 'status' field → tempfail → exit 75 (451)
        Safe default: sender retries, no mail lost from webhook misconfiguration.
        """
        email = self.make_email()

        mock_error = HTTPError(
            url="https://test.example.com/api/inbound",
            code=http_status,
            msg="Error",
            hdrs={},
            fp=BytesIO(b'{"error": "Something went wrong"}')
        )

        with patch('urllib.request.urlopen', side_effect=mock_error):
            exit_code = processor.process_email(email)

        assert exit_code == 75, f"HTTP {http_status} without JSON status must return exit 75 (451 tempfail)"

    # ========================================================================
    # TEST 4: NETWORK ERRORS (Timeout, connection refused, DNS failure)
    # ========================================================================
    @pytest.mark.parametrize("error_reason", [
        "Connection refused",
        "Connection timed out",
        "Name or service not known",
        "Network is unreachable",
    ])
    def test_network_errors_return_exit_75(self, processor, error_reason):
        """
        CRITICAL: Network errors → exit 75 → 451 tempfail
        """
        email = self.make_email()

        mock_error = URLError(error_reason)

        with patch('urllib.request.urlopen', side_effect=mock_error):
            exit_code = processor.process_email(email)

        assert exit_code == 75, f"Network error ({error_reason}) must return exit 75 (451)"

    # ========================================================================
    # TEST 5: HTTP 200 with non-JSON body → accepted (fallback to HTTP status)
    # ========================================================================
    def test_http_200_non_json_returns_exit_0(self, processor):
        """
        HTTP 200 with non-JSON body → falls back to HTTP status → accepted → exit 0
        Simplest possible webhook: just return 200.
        """
        email = self.make_email()

        mock_response = MockResponse(200, "NOT JSON")

        with patch('urllib.request.urlopen', return_value=mock_response):
            exit_code = processor.process_email(email)

        assert exit_code == 0, "HTTP 200 without JSON must return exit 0 (accepted via HTTP status fallback)"

    # ========================================================================
    # TEST 6: UNKNOWN STATUS IN RESPONSE
    # ========================================================================
    def test_unknown_status_returns_exit_75(self, processor):
        """
        CRITICAL: Unknown status → exit 75 → 451 tempfail (safe default)
        """
        email = self.make_email()

        mock_response = MockResponse(200, json.dumps({
            "status": "unknown_status_value"
        }))

        with patch('urllib.request.urlopen', return_value=mock_response):
            exit_code = processor.process_email(email)

        assert exit_code == 75, "Unknown status must return exit 75 (451 tempfail)"

    # ========================================================================
    # TEST 7: HTTP 200 with JSON missing 'status' → accepted (fallback)
    # ========================================================================
    def test_http_200_missing_status_field_returns_exit_0(self, processor):
        """
        HTTP 200 with JSON that has no 'status' field → falls back to HTTP status → accepted
        """
        email = self.make_email()

        mock_response = MockResponse(200, json.dumps({
            "some_other_field": "value"
        }))

        with patch('urllib.request.urlopen', return_value=mock_response):
            exit_code = processor.process_email(email)

        assert exit_code == 0, "HTTP 200 without status field must return exit 0 (accepted via HTTP status fallback)"

    # ========================================================================
    # TEST 8: MISSING WEBHOOK CONFIG
    # ========================================================================
    def test_missing_webhook_config_returns_exit_75(self):
        """
        CRITICAL: If webhook not configured → exit 75 (can't process)
        """
        processor_no_webhook = EmailProcessor(webhook_url=None, webhook_secret=None)
        email = self.make_email()

        exit_code = processor_no_webhook.process_email(email)

        assert exit_code == 75, "Missing webhook config must return exit 75"

    # ========================================================================
    # TEST 9: TIMEOUT (simulated)
    # ========================================================================
    def test_timeout_returns_exit_75(self, processor):
        """
        CRITICAL: Timeout → exit 75 → 451 tempfail
        """
        email = self.make_email()

        # Mock timeout exception
        mock_error = URLError("timed out")

        with patch('urllib.request.urlopen', side_effect=mock_error):
            exit_code = processor.process_email(email)

        assert exit_code == 75, "Timeout must return exit 75 (451 tempfail)"

    # ========================================================================
    # TEST 10: RESPONSE BODY PARSING
    # ========================================================================
    def test_parses_rejection_reason(self, processor):
        """
        Should parse and log rejection reason for debugging
        """
        email = self.make_email()

        mock_response = MockResponse(200, json.dumps({
            "status": "reject_permanent",
            "reason": "domain_unverified"
        }))

        with patch('urllib.request.urlopen', return_value=mock_response):
            exit_code = processor.process_email(email)

        assert exit_code == 67, "Should reject with exit 67"

    # ========================================================================
    # TEST 11: VERIFY REQUEST PAYLOAD FORMAT
    # ========================================================================
    def test_sends_correct_payload_format(self, processor):
        """
        Verify that the script sends the expected payload to the API
        """
        email = self.make_email(to="test@example.com")

        captured_request = None

        def mock_urlopen(request, timeout=None):
            nonlocal captured_request
            captured_request = request
            return MockResponse(200, json.dumps({"status": "accepted"}))

        with patch('urllib.request.urlopen', side_effect=mock_urlopen):
            processor.process_email(email)

        # Verify request was made
        assert captured_request is not None, "Request should be made"

        # Verify Authorization header
        assert captured_request.headers.get('Authorization') == 'Bearer test-secret-123'

        # Verify Content-Type
        assert captured_request.headers.get('Content-type') == 'application/json'

        # Verify payload structure
        payload = json.loads(captured_request.data.decode('utf-8'))
        assert 'recipient' in payload
        assert 'sender' in payload
        assert 'subject' in payload
        assert 'message_id' in payload
        assert 'domain' in payload
        assert 'size' in payload
        assert 'eml_base64' in payload

        # Verify recipient is correct
        assert payload['recipient'] == 'test@example.com'
        assert payload['domain'] == 'example.com'

    # ========================================================================
    # TEST 12: VERIFY BASE64 ENCODING
    # ========================================================================
    def test_encodes_email_as_base64(self, processor):
        """
        Verify email content is base64-encoded in payload
        """
        email = "From: test@test.com\n\nTest body with special chars: 你好 🎉"

        captured_payload = None

        def mock_urlopen(request, timeout=None):
            nonlocal captured_payload
            captured_payload = json.loads(request.data.decode('utf-8'))
            return MockResponse(200, json.dumps({"status": "accepted"}))

        with patch('urllib.request.urlopen', side_effect=mock_urlopen):
            with patch.object(processor, 'determine_recipient', return_value='test@test.com'):
                processor.process_email(email)

        # Verify base64 encoding
        import base64
        decoded = base64.b64decode(captured_payload['eml_base64']).decode('utf-8')
        assert decoded == email, "Email should be correctly base64-encoded and decodable"

    # ========================================================================
    # TEST 13: HTTP 200 empty body → accepted (HTTP status fallback)
    # ========================================================================
    def test_http_200_empty_body_returns_exit_0(self, processor):
        """HTTP 200 with empty body → accepted via HTTP status fallback"""
        email = self.make_email()

        mock_response = MockResponse(200, "")

        with patch('urllib.request.urlopen', return_value=mock_response):
            exit_code = processor.process_email(email)

        assert exit_code == 0, "HTTP 200 with empty body must return exit 0 (accepted)"

    # ========================================================================
    # TEST 14: HTTP 4xx with JSON status overrides HTTP status
    # ========================================================================
    def test_http_4xx_with_json_accepted_returns_exit_0(self, processor):
        """HTTP 422 with JSON {"status": "accepted"} → JSON wins → exit 0"""
        email = self.make_email()

        mock_error = HTTPError(
            url="https://test.example.com/api/inbound",
            code=422,
            msg="Unprocessable",
            hdrs={},
            fp=BytesIO(json.dumps({"status": "accepted"}).encode())
        )

        with patch('urllib.request.urlopen', side_effect=mock_error):
            exit_code = processor.process_email(email)

        assert exit_code == 0, "HTTP 4xx with JSON status=accepted must return exit 0 (JSON overrides HTTP)"

    # ========================================================================
    # TEST 15: HTTP 5xx with JSON status overrides HTTP status
    # ========================================================================
    def test_http_5xx_with_json_accepted_returns_exit_0(self, processor):
        """HTTP 500 with JSON {"status": "accepted"} → JSON wins → exit 0"""
        email = self.make_email()

        mock_error = HTTPError(
            url="https://test.example.com/api/inbound",
            code=500,
            msg="Server Error",
            hdrs={},
            fp=BytesIO(json.dumps({"status": "accepted"}).encode())
        )

        with patch('urllib.request.urlopen', side_effect=mock_error):
            exit_code = processor.process_email(email)

        assert exit_code == 0, "HTTP 5xx with JSON status=accepted must return exit 0 (JSON overrides HTTP)"

    # ========================================================================
    # TEST 16: HTTP 200 with reject JSON → JSON overrides HTTP status
    # ========================================================================
    def test_http_200_with_reject_json_returns_exit_67(self, processor):
        """HTTP 200 with JSON {"status": "reject_permanent"} → JSON wins → exit 67"""
        email = self.make_email()

        mock_response = MockResponse(200, json.dumps({
            "status": "reject_permanent",
            "reason": "sender_blocked"
        }))

        with patch('urllib.request.urlopen', return_value=mock_response):
            exit_code = processor.process_email(email)

        assert exit_code == 67, "HTTP 200 with JSON status=reject_permanent must return exit 67 (JSON overrides HTTP)"


class TestEmailProcessorExitCodeContract:
    """
    CRITICAL: Verify the exit code contract that Postfix relies on

    Exit codes map to SMTP responses:
      0  → 250 OK
      67 → 550 (permanent rejection)
      75 → 451 (temporary failure)

    This contract MUST be maintained or emails will be lost.
    """

    @pytest.fixture
    def processor(self):
        return EmailProcessor(
            webhook_url="https://test.example.com/api/inbound",
            webhook_secret="secret"
        )

    def test_exit_0_only_on_accepted(self, processor):
        """CRITICAL: Exit 0 ONLY when API returns 'accepted'"""
        email = "From: test@test.com\nTo: test@test.com\nX-Original-To: test@test.com\n\nBody"

        # Test: Only 'accepted' should return 0
        mock_response = MockResponse(200, json.dumps({"status": "accepted"}))
        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(processor, 'determine_recipient', return_value='test@test.com'):
                assert processor.process_email(email) == 0

        # Test: reject_permanent should NOT return 0
        mock_response = MockResponse(200, json.dumps({"status": "reject_permanent"}))
        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(processor, 'determine_recipient', return_value='test@test.com'):
                assert processor.process_email(email) != 0

    def test_exit_67_only_on_reject_permanent(self, processor):
        """CRITICAL: Exit 67 ONLY when API returns 'reject_permanent'"""
        email = "From: test@test.com\nTo: test@test.com\nX-Original-To: test@test.com\n\nBody"

        mock_response = MockResponse(200, json.dumps({"status": "reject_permanent", "reason": "test"}))
        with patch('urllib.request.urlopen', return_value=mock_response):
            with patch.object(processor, 'determine_recipient', return_value='test@test.com'):
                assert processor.process_email(email) == 67

    def test_exit_75_on_all_errors(self, processor):
        """CRITICAL: All errors must return exit 75 (tempfail, never lose email)"""
        email = "From: test@test.com\nTo: test@test.com\nX-Original-To: test@test.com\n\nBody"

        # HTTP error
        http_error = HTTPError("url", 500, "Error", {}, BytesIO(b"error"))
        with patch('urllib.request.urlopen', side_effect=http_error):
            with patch.object(processor, 'determine_recipient', return_value='test@test.com'):
                assert processor.process_email(email) == 75

        # Network error
        network_error = URLError("Connection refused")
        with patch('urllib.request.urlopen', side_effect=network_error):
            with patch.object(processor, 'determine_recipient', return_value='test@test.com'):
                assert processor.process_email(email) == 75

        # Timeout
        timeout_error = URLError("timed out")
        with patch('urllib.request.urlopen', side_effect=timeout_error):
            with patch.object(processor, 'determine_recipient', return_value='test@test.com'):
                assert processor.process_email(email) == 75

    def test_never_exit_0_on_errors(self, processor):
        """
        CRITICAL SAFETY: NEVER exit 0 (250 OK) on server errors or network failures.

        Note: HTTP 200 with no JSON status is now intentionally accepted (exit 0)
        via HTTP status code fallback — that is not an error scenario.
        """
        email = "From: test@test.com\nTo: test@test.com\nX-Original-To: test@test.com\n\nBody"

        error_scenarios = [
            # HTTP 5xx errors (no JSON status → tempfail)
            HTTPError("url", 500, "Error", {}, BytesIO(b'{"error": "server error"}')),

            # HTTP 4xx errors (no JSON status → reject, not exit 0)
            HTTPError("url", 401, "Unauth", {}, BytesIO(b'{"error": "unauthorized"}')),

            # Network errors
            URLError("Connection refused"),
            URLError("timed out"),

            # Unknown status (JSON with status field → status authoritative → tempfail)
            MockResponse(200, json.dumps({"status": "unknown"})),
        ]

        for error in error_scenarios:
            if isinstance(error, MockResponse):
                with patch('urllib.request.urlopen', return_value=error):
                    with patch.object(processor, 'determine_recipient', return_value='test@test.com'):
                        exit_code = processor.process_email(email)
                        assert exit_code != 0, f"Error scenario {error} must NOT return 0"
            else:
                with patch('urllib.request.urlopen', side_effect=error):
                    with patch.object(processor, 'determine_recipient', return_value='test@test.com'):
                        exit_code = processor.process_email(email)
                        assert exit_code != 0, f"Error scenario {error} must NOT return 0"


class TestPayloadGeneration:
    """Test that payload sent to API is correct"""

    @pytest.fixture
    def processor(self):
        return EmailProcessor(
            webhook_url="https://test.example.com/api/inbound",
            webhook_secret="secret"
        )

    def test_payload_has_all_required_fields(self, processor):
        """Verify all required fields are present in payload"""
        email = """From: sender@example.com
To: recipient@example.com
Subject: Test Subject
X-Original-To: recipient@example.com
Message-ID: <test123@example.com>

Email body here.
"""

        captured_payload = None

        def capture_request(request, timeout=None):
            nonlocal captured_payload
            captured_payload = json.loads(request.data.decode('utf-8'))
            return MockResponse(200, json.dumps({"status": "accepted"}))

        with patch('urllib.request.urlopen', side_effect=capture_request):
            processor.process_email(email)

        # Verify all required fields
        assert captured_payload is not None
        assert 'recipient' in captured_payload
        assert 'sender' in captured_payload
        assert 'subject' in captured_payload
        assert 'message_id' in captured_payload
        assert 'domain' in captured_payload
        assert 'size' in captured_payload
        assert 'eml_base64' in captured_payload

        # Verify values
        assert captured_payload['recipient'] == 'recipient@example.com'
        assert captured_payload['sender'] == 'sender@example.com'
        assert captured_payload['subject'] == 'Test Subject'
        assert captured_payload['domain'] == 'example.com'
        assert captured_payload['size'] > 0

        # Verify base64 is valid
        import base64
        decoded = base64.b64decode(captured_payload['eml_base64']).decode('utf-8')
        assert decoded == email


class TestSecurityValidation:
    """Test security validation still works"""

    @pytest.fixture
    def processor(self):
        return EmailProcessor(webhook_url="https://test.com/api", webhook_secret="secret")

    def test_path_traversal_still_blocked(self, processor):
        """Path traversal in recipient should be silently dropped"""
        email = """From: test@test.com
To: user@../../etc/passwd
X-Original-To: user@../../etc/passwd
Subject: Test

Body
"""
        exit_code = processor.process_email(email)
        assert exit_code == 0, "Path traversal should be silently dropped (exit 0)"


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "-s"])
