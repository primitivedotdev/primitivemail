#!/usr/bin/env python3
"""
Integration tests for store_mail.py
Tests the full email processing pipeline with security validation.
"""

import pytest
import tempfile
import os
import json
from unittest.mock import patch, MagicMock
from store_mail import EmailProcessor


class TestEmailProcessorSecurity:
    """Security-focused tests for EmailProcessor"""

    @pytest.fixture
    def processor(self):
        """Create processor with webhook configured"""
        return EmailProcessor(
            webhook_url="https://test.example.com/api/inbound",
            webhook_secret="test-secret"
        )

    def make_email(self, to: str, from_addr: str = "sender@example.com", subject: str = "Test") -> str:
        """Create a minimal valid email"""
        return f"""From: {from_addr}
To: {to}
Subject: {subject}
X-Original-To: {to}
Message-ID: <test@example.com>

This is a test email body.
"""

    # Path traversal attacks
    @pytest.mark.parametrize("malicious_recipient", [
        "user@../../../etc/passwd",
        "user@../../../etc/cron.d",
        "user@foo/../../../root",
        "user@..\\..\\windows\\system32",
        "user@legit.com/../../../etc/shadow",
    ])
    def test_path_traversal_silently_dropped(self, processor, malicious_recipient):
        """CRITICAL: Path traversal attempts must be silently dropped (exit 0)"""
        email = self.make_email(to=malicious_recipient)
        exit_code = processor.process_email(email)
        assert exit_code == 0, f"Path traversal must be silently dropped: {malicious_recipient}"

    # Invalid email formats
    @pytest.mark.parametrize("invalid_recipient", [
        "notanemail",
        "@nodomain",
        "nolocal@",
        "two@@at.com",
    ])
    def test_invalid_emails_silently_dropped(self, processor, invalid_recipient):
        """Invalid email formats must be silently dropped (exit 0)"""
        email = self.make_email(to=invalid_recipient)
        exit_code = processor.process_email(email)
        assert exit_code == 0, f"Invalid email must be silently dropped: {invalid_recipient}"

    # Valid emails should work
    @pytest.mark.parametrize("valid_recipient", [
        "user@example.com",
        "user.name@example.com",
        "user+tag@example.com",
        "user@sub.domain.com",
    ])
    def test_valid_emails_accepted(self, processor, valid_recipient):
        """Valid emails should be processed when API accepts them"""
        email = self.make_email(to=valid_recipient)

        # Mock successful API response
        from test_ingestion_api import MockResponse
        mock_response = MockResponse(200, json.dumps({"status": "accepted"}))

        with patch('urllib.request.urlopen', return_value=mock_response):
            exit_code = processor.process_email(email)
            assert exit_code == 0, f"Valid email should be accepted: {valid_recipient}"


class TestEmailProcessorDomainNormalization:
    """Tests for domain case normalization (DNS is case-insensitive per RFC 1035)"""

    @pytest.fixture
    def processor(self):
        """Create processor with webhook configured"""
        return EmailProcessor(
            webhook_url="https://test.example.com/api/inbound",
            webhook_secret="test-secret"
        )

    def make_email(self, to: str) -> str:
        """Create a minimal valid email"""
        return f"""From: sender@example.com
To: {to}
Subject: Test
X-Original-To: {to}
Message-ID: <test@example.com>

This is a test email body.
"""

    @pytest.mark.parametrize("recipient,expected_domain", [
        ("user@EXAMPLE.COM", "example.com"),
        ("user@Example.Com", "example.com"),
        ("user@SUBDOMAIN.EXAMPLE.COM", "subdomain.example.com"),
        ("user@MixedCase.IO", "mixedcase.io"),
    ])
    def test_domain_normalized_to_lowercase_in_webhook(self, processor, recipient, expected_domain):
        """Domain must be lowercased before sending to API (RFC 1035 compliance)"""
        email = self.make_email(to=recipient)

        captured_payload = None

        def capture_request(req, **kwargs):
            nonlocal captured_payload
            captured_payload = json.loads(req.data.decode('utf-8'))
            # Return mock response
            from test_ingestion_api import MockResponse
            return MockResponse(200, json.dumps({"status": "accepted"}))

        with patch('urllib.request.urlopen', side_effect=capture_request):
            processor.process_email(email)

        assert captured_payload is not None, "Webhook should have been called"
        assert captured_payload['domain'] == expected_domain, \
            f"Domain should be lowercase: expected {expected_domain}, got {captured_payload['domain']}"


class TestEmailProcessorIntegration:
    """Integration tests for normal operation"""

    @pytest.fixture
    def processor(self):
        return EmailProcessor(webhook_url=None, webhook_secret=None)

    def test_extracts_recipient_from_x_original_to(self, processor):
        """Should prefer X-Original-To header"""
        email = """From: sender@example.com
To: wrong@example.com
X-Original-To: correct@example.com
Subject: Test

Body
"""
        recipient = processor.determine_recipient(email)
        assert recipient == "correct@example.com"

    def test_extracts_headers_correctly(self, processor):
        """Should extract standard headers"""
        email = """From: sender@example.com
To: recipient@example.com
Subject: Test Subject
Message-ID: <abc123@example.com>

Body
"""
        assert processor.extract_header(email, "From") == "sender@example.com"
        assert processor.extract_header(email, "Subject") == "Test Subject"
        assert processor.extract_header(email, "Message-ID") == "<abc123@example.com>"


class TestSaveToDiskMetaJson:
    """Tests for save_to_disk .meta.json sidecar and write_bytes."""

    def test_eml_written_as_bytes(self, tmp_path):
        """save_to_disk writes .eml as bytes, not text"""
        processor = EmailProcessor()
        processor.base_dir = tmp_path
        email = "From: alice@example.com\nTo: bob@test.com\nSubject: Hi\n\nBody"

        filepath = processor.save_to_disk(email, "bob@test.com")

        assert filepath.read_bytes() == email.encode('utf-8')

    def test_meta_json_created(self, tmp_path):
        """save_to_disk creates .meta.json alongside .eml"""
        processor = EmailProcessor()
        processor.base_dir = tmp_path
        email = "From: alice@example.com\nTo: bob@test.com\nSubject: Hi\n\nBody"

        filepath = processor.save_to_disk(email, "bob@test.com")
        meta_path = filepath.with_suffix('.meta.json')

        assert meta_path.exists()

    def test_meta_json_content(self, tmp_path):
        """Verify .meta.json has correct structure and values"""
        processor = EmailProcessor()
        processor.base_dir = tmp_path
        email = "From: alice@example.com\nTo: bob@test.com\nSubject: Hi\n\nBody"

        filepath = processor.save_to_disk(email, "bob@test.com")
        meta_path = filepath.with_suffix('.meta.json')
        meta = json.loads(meta_path.read_text())

        assert meta['smtp']['helo'] is None
        assert meta['smtp']['mail_from'] == 'alice@example.com'
        assert meta['smtp']['rcpt_to'] == ['bob@test.com']
        assert meta['auth'] == {'spf': 'none'}

    def test_meta_json_permissions(self, tmp_path):
        """Files are 0o644, dirs are 0o755"""
        processor = EmailProcessor()
        processor.base_dir = tmp_path
        email = "From: alice@example.com\nTo: bob@test.com\nSubject: Hi\n\nBody"

        filepath = processor.save_to_disk(email, "bob@test.com")
        meta_path = filepath.with_suffix('.meta.json')

        assert oct(filepath.stat().st_mode & 0o777) == oct(0o644)
        assert oct(meta_path.stat().st_mode & 0o777) == oct(0o644)
        assert oct(filepath.parent.stat().st_mode & 0o777) == oct(0o755)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
