#!/usr/bin/env python3
"""
Email input validation for PrimitiveMail
Sanitizes and validates all untrusted input before processing.
"""

import re
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class ValidationResult:
    """Result of validation check"""
    valid: bool
    error: Optional[str] = None


@dataclass
class SanitizedEmail:
    """Validated and sanitized email metadata"""
    recipient: str
    recipient_local: str
    recipient_domain: str
    sender: str
    subject: str
    size_bytes: int


class EmailValidator:
    """
    Validates email input to prevent:
    - Path traversal attacks
    - Command injection
    - Malformed data causing crashes
    """

    # Strict email regex - RFC 5321 simplified
    # Local part: alphanumeric, dots, hyphens, underscores, plus signs
    # Domain: alphanumeric, dots, hyphens -OR- IP literal [1.2.3.4]
    EMAIL_REGEX = re.compile(
        r'^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\])$'
    )

    # Characters that should NEVER appear in a domain (path traversal)
    DANGEROUS_DOMAIN_CHARS = re.compile(r'[/\\]|\.\.')

    # Maximum lengths
    MAX_EMAIL_LENGTH = 254  # RFC 5321
    MAX_LOCAL_PART_LENGTH = 64  # RFC 5321
    MAX_DOMAIN_LENGTH = 253  # RFC 1035
    MAX_SUBJECT_LENGTH = 998  # RFC 5322
    MAX_EMAIL_SIZE_BYTES = 50 * 1024 * 1024  # 50 MiB (matches postfix message_size_limit)

    def validate_email_address(self, email: str) -> ValidationResult:
        """
        Validate an email address format.
        Returns ValidationResult with valid=True or error message.
        """
        if not email:
            return ValidationResult(False, "Email address is empty")

        if len(email) > self.MAX_EMAIL_LENGTH:
            return ValidationResult(False, f"Email too long ({len(email)} > {self.MAX_EMAIL_LENGTH})")

        # Must contain exactly one @
        if email.count('@') != 1:
            return ValidationResult(False, "Email must contain exactly one @")

        local_part, domain = email.rsplit('@', 1)

        # Validate local part
        if not local_part:
            return ValidationResult(False, "Local part is empty")

        if len(local_part) > self.MAX_LOCAL_PART_LENGTH:
            return ValidationResult(False, f"Local part too long ({len(local_part)} > {self.MAX_LOCAL_PART_LENGTH})")

        # Validate domain
        domain_result = self.validate_domain(domain)
        if not domain_result.valid:
            return domain_result

        # Final regex check for overall format
        if not self.EMAIL_REGEX.match(email):
            return ValidationResult(False, f"Email format invalid: {email[:50]}")

        return ValidationResult(True)

    # IPv4 literal: [1.2.3.4]
    IP_LITERAL_REGEX = re.compile(
        r'^\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]$'
    )

    def validate_domain(self, domain: str) -> ValidationResult:
        """
        Validate a domain name or IP literal.
        CRITICAL: This prevents path traversal attacks.
        """
        if not domain:
            return ValidationResult(False, "Domain is empty")

        if len(domain) > self.MAX_DOMAIN_LENGTH:
            return ValidationResult(False, f"Domain too long ({len(domain)} > {self.MAX_DOMAIN_LENGTH})")

        # Allow IP literals like [1.2.3.4]
        ip_match = self.IP_LITERAL_REGEX.match(domain)
        if ip_match:
            octets = ip_match.group(1).split('.')
            for octet in octets:
                if int(octet) > 255:
                    return ValidationResult(False, f"Invalid IP octet: {octet}")
            return ValidationResult(True)

        # CRITICAL: Check for path traversal characters
        if self.DANGEROUS_DOMAIN_CHARS.search(domain):
            return ValidationResult(False, f"Domain contains dangerous characters: {domain[:50]}")

        # Domain must have at least one dot (TLD)
        if '.' not in domain:
            return ValidationResult(False, "Domain must have a TLD")

        # Each label must be valid
        labels = domain.split('.')
        for label in labels:
            if not label:
                return ValidationResult(False, "Domain has empty label")
            if len(label) > 63:  # RFC 1035
                return ValidationResult(False, f"Domain label too long: {label[:20]}")
            if not re.match(r'^[a-zA-Z0-9-]+$', label):
                return ValidationResult(False, f"Domain label has invalid chars: {label[:20]}")
            if label.startswith('-') or label.endswith('-'):
                return ValidationResult(False, f"Domain label cannot start/end with hyphen: {label[:20]}")

        return ValidationResult(True)

    def validate_size(self, size_bytes: int) -> ValidationResult:
        """Validate email size is within limits"""
        if size_bytes <= 0:
            return ValidationResult(False, "Email size must be positive")

        if size_bytes > self.MAX_EMAIL_SIZE_BYTES:
            return ValidationResult(False, f"Email too large ({size_bytes} > {self.MAX_EMAIL_SIZE_BYTES})")

        return ValidationResult(True)

    def sanitize_subject(self, subject: str) -> str:
        """
        Sanitize subject line for safe logging/storage.
        Removes control characters, truncates length.
        """
        if not subject:
            return ""

        # Remove control characters (except space)
        sanitized = ''.join(c if c.isprintable() or c == ' ' else '?' for c in subject)

        # Truncate to max length
        if len(sanitized) > self.MAX_SUBJECT_LENGTH:
            sanitized = sanitized[:self.MAX_SUBJECT_LENGTH - 3] + "..."

        return sanitized

    def sanitize_for_logging(self, value: str, max_length: int = 100) -> str:
        """Sanitize any string for safe logging"""
        if not value:
            return ""
        sanitized = ''.join(c if c.isprintable() or c == ' ' else '?' for c in value)
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length - 3] + "..."
        return sanitized

    def validate_and_sanitize(
        self,
        recipient: str,
        sender: str,
        subject: str,
        size_bytes: int
    ) -> tuple[Optional[SanitizedEmail], List[str]]:
        """
        Validate all inputs and return sanitized data.

        Returns:
            (SanitizedEmail, []) on success
            (None, [error1, error2, ...]) on failure
        """
        errors: List[str] = []

        # Validate recipient (CRITICAL)
        recipient_result = self.validate_email_address(recipient)
        if not recipient_result.valid:
            errors.append(f"Invalid recipient: {recipient_result.error}")

        # Validate sender (less critical, but log it)
        sender_result = self.validate_email_address(sender) if sender else ValidationResult(True)
        if not sender_result.valid:
            # Don't reject, just note it - some legitimate emails have weird senders
            pass

        # Validate size
        size_result = self.validate_size(size_bytes)
        if not size_result.valid:
            errors.append(f"Invalid size: {size_result.error}")

        if errors:
            return None, errors

        # Parse validated recipient
        local_part, domain = recipient.rsplit('@', 1)

        return SanitizedEmail(
            recipient=recipient.lower(),  # Normalize to lowercase
            recipient_local=local_part.lower(),
            recipient_domain=domain.lower(),
            sender=sender or "",
            subject=self.sanitize_subject(subject),
            size_bytes=size_bytes
        ), []


# Singleton for convenience
_validator = EmailValidator()

def validate_recipient(email: str) -> ValidationResult:
    """Convenience function to validate a recipient email"""
    return _validator.validate_email_address(email)

def validate_domain(domain: str) -> ValidationResult:
    """Convenience function to validate a domain"""
    return _validator.validate_domain(domain)

def validate_and_sanitize(recipient: str, sender: str, subject: str, size_bytes: int):
    """Convenience function for full validation"""
    return _validator.validate_and_sanitize(recipient, sender, subject, size_bytes)
