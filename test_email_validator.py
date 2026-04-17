#!/usr/bin/env python3
"""
Unit tests for email_validator.py
Run with: python3 -m pytest test_email_validator.py -v
"""

import pytest
from email_validator import EmailValidator, validate_recipient, validate_domain


class TestEmailValidation:
    """Test email address validation"""

    @pytest.fixture
    def validator(self):
        return EmailValidator()

    # Valid emails
    @pytest.mark.parametrize("email", [
        "user@example.com",
        "user.name@example.com",
        "user+tag@example.com",
        "user@sub.example.com",
        "user@example.co.uk",
        "a@b.co",
        "test123@domain123.com",
        "UPPERCASE@DOMAIN.COM",
        "mixed.Case@Example.Com",
    ])
    def test_valid_emails(self, validator, email):
        result = validator.validate_email_address(email)
        assert result.valid, f"Should accept {email}: {result.error}"

    # Invalid emails
    @pytest.mark.parametrize("email,reason", [
        ("", "empty"),
        ("noatsign", "no @"),
        ("two@@signs.com", "double @"),
        ("@nodomain.com", "no local part"),
        ("nolocal@", "no domain"),
        ("user@", "no domain"),
        ("@", "just @"),
        ("user@.com", "domain starts with dot"),
        ("user@domain", "no TLD"),
        ("user@-invalid.com", "domain starts with hyphen"),
        ("user@invalid-.com", "domain label ends with hyphen"),
    ])
    def test_invalid_emails(self, validator, email, reason):
        result = validator.validate_email_address(email)
        assert not result.valid, f"Should reject {email} ({reason})"

    def test_email_too_long(self, validator):
        long_email = "a" * 250 + "@b.com"
        result = validator.validate_email_address(long_email)
        assert not result.valid
        assert "too long" in result.error.lower()

    def test_local_part_too_long(self, validator):
        long_local = "a" * 65 + "@example.com"
        result = validator.validate_email_address(long_local)
        assert not result.valid


class TestPathTraversalPrevention:
    """CRITICAL: Test that path traversal attacks are blocked"""

    @pytest.fixture
    def validator(self):
        return EmailValidator()

    @pytest.mark.parametrize("malicious_email", [
        # Path traversal attempts
        "user@../../../etc/passwd",
        "user@..%2F..%2Fetc",
        "user@foo/../../../etc/cron.d",
        "user@....//....//etc",
        # Backslash variants
        "user@..\\..\\windows\\system32",
        "user@foo\\..\\..\\etc",
        # Hidden in subdomains
        "user@legit.com/../../../etc/passwd",
        "user@../legit.com",
    ])
    def test_path_traversal_blocked(self, validator, malicious_email):
        result = validator.validate_email_address(malicious_email)
        assert not result.valid, f"SECURITY: Must reject path traversal: {malicious_email}"

    @pytest.mark.parametrize("malicious_domain", [
        "../../../etc/passwd",
        "..\\..\\windows",
        "foo/../bar",
        "foo/bar",
        "foo\\bar",
        "..",
        "...",
        "legit.com/..",
    ])
    def test_dangerous_domains_blocked(self, validator, malicious_domain):
        result = validator.validate_domain(malicious_domain)
        assert not result.valid, f"SECURITY: Must reject dangerous domain: {malicious_domain}"


class TestDomainValidation:
    """Test domain validation specifically"""

    @pytest.fixture
    def validator(self):
        return EmailValidator()

    @pytest.mark.parametrize("domain", [
        "example.com",
        "sub.example.com",
        "a.b.c.d.example.com",
        "example.co.uk",
        "123.com",
        "test-domain.com",
        "a.co",
    ])
    def test_valid_domains(self, validator, domain):
        result = validator.validate_domain(domain)
        assert result.valid, f"Should accept {domain}: {result.error}"

    @pytest.mark.parametrize("domain", [
        "",
        "nodot",
        ".startsdot.com",
        "endsdot.com.",
        "-startshyphen.com",
        "endshyphen-.com",
        "has space.com",
        "has\ttab.com",
        "has\nnewline.com",
    ])
    def test_invalid_domains(self, validator, domain):
        result = validator.validate_domain(domain)
        assert not result.valid, f"Should reject {domain}"

    def test_domain_label_too_long(self, validator):
        long_label = "a" * 64 + ".com"
        result = validator.validate_domain(long_label)
        assert not result.valid
        assert "too long" in result.error.lower()


class TestSizeValidation:
    """Test email size validation"""

    @pytest.fixture
    def validator(self):
        return EmailValidator()

    def test_valid_sizes(self, validator):
        assert validator.validate_size(1).valid
        assert validator.validate_size(1000).valid
        assert validator.validate_size(1024 * 1024).valid  # 1 MiB
        assert validator.validate_size(10 * 1024 * 1024).valid  # 10 MiB
        assert validator.validate_size(40 * 1024 * 1024).valid  # 40 MiB
        assert validator.validate_size(50 * 1024 * 1024).valid  # 50 MiB (boundary)

    def test_invalid_sizes(self, validator):
        assert not validator.validate_size(0).valid
        assert not validator.validate_size(-1).valid
        assert not validator.validate_size(50 * 1024 * 1024 + 1).valid  # just over limit
        assert not validator.validate_size(100 * 1024 * 1024).valid  # 100 MiB


class TestSubjectSanitization:
    """Test subject line sanitization"""

    @pytest.fixture
    def validator(self):
        return EmailValidator()

    def test_normal_subject(self, validator):
        assert validator.sanitize_subject("Hello World") == "Hello World"

    def test_empty_subject(self, validator):
        assert validator.sanitize_subject("") == ""
        assert validator.sanitize_subject(None) == ""

    def test_control_characters_removed(self, validator):
        result = validator.sanitize_subject("Hello\x00World\x1fTest")
        assert "\x00" not in result
        assert "\x1f" not in result
        assert "Hello" in result
        assert "World" in result

    def test_newlines_removed(self, validator):
        result = validator.sanitize_subject("Line1\nLine2\rLine3")
        assert "\n" not in result
        assert "\r" not in result

    def test_long_subject_truncated(self, validator):
        long_subject = "A" * 2000
        result = validator.sanitize_subject(long_subject)
        assert len(result) <= validator.MAX_SUBJECT_LENGTH
        assert result.endswith("...")


class TestFullValidation:
    """Test the complete validate_and_sanitize function"""

    @pytest.fixture
    def validator(self):
        return EmailValidator()

    def test_valid_email_data(self, validator):
        result, errors = validator.validate_and_sanitize(
            recipient="user@example.com",
            sender="sender@other.com",
            subject="Test Subject",
            size_bytes=1000
        )
        assert result is not None
        assert len(errors) == 0
        assert result.recipient == "user@example.com"
        assert result.recipient_domain == "example.com"
        assert result.recipient_local == "user"

    def test_normalizes_to_lowercase(self, validator):
        result, errors = validator.validate_and_sanitize(
            recipient="USER@EXAMPLE.COM",
            sender="SENDER@OTHER.COM",
            subject="Test",
            size_bytes=100
        )
        assert result.recipient == "user@example.com"
        assert result.recipient_domain == "example.com"

    def test_invalid_recipient_returns_errors(self, validator):
        result, errors = validator.validate_and_sanitize(
            recipient="not-an-email",
            sender="sender@example.com",
            subject="Test",
            size_bytes=100
        )
        assert result is None
        assert len(errors) > 0
        assert "recipient" in errors[0].lower()

    def test_path_traversal_rejected(self, validator):
        result, errors = validator.validate_and_sanitize(
            recipient="user@../../../etc/passwd",
            sender="sender@example.com",
            subject="Test",
            size_bytes=100
        )
        assert result is None
        assert len(errors) > 0


class TestConvenienceFunctions:
    """Test the module-level convenience functions"""

    def test_validate_recipient(self):
        assert validate_recipient("user@example.com").valid
        assert not validate_recipient("invalid").valid

    def test_validate_domain(self):
        assert validate_domain("example.com").valid
        assert not validate_domain("../etc").valid


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
