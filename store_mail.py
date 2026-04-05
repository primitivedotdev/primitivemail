#!/usr/bin/env python3
"""
Email storage script for PrimitiveMail
Reads email from stdin, saves to disk, and optionally sends webhook notification.
This is the pipe transport fallback (milter is the primary path).
"""

import sys
import os
import re
import json
import base64
import logging
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import urllib.request
import urllib.error

from email_validator import EmailValidator

# Configure logging
# Create handlers for both stderr (for direct runs) and file (for Postfix)
# Use /tmp which is writable by all users (Postfix runs as nobody:nogroup)
handlers = [logging.StreamHandler(sys.stderr)]

try:
    # Try to write to /tmp/store-mail.log (world-writable)
    handlers.append(logging.FileHandler('/tmp/store-mail.log', mode='a'))
except PermissionError:
    # If that fails, just use stderr
    pass

logging.basicConfig(
    level=logging.INFO,
    format='[store-mail.py] %(message)s',
    handlers=handlers
)
logger = logging.getLogger(__name__)

# Add Loki handler if configured (optional - works with any Loki-compatible endpoint)
try:
    if os.getenv('LOKI_URL'):
        from logging_loki import LokiHandler

        loki_handler = LokiHandler(
            url=os.getenv('LOKI_URL'),
            auth=(os.getenv('LOKI_USER'), os.getenv('LOKI_KEY')),
            tags={"job": "primitivemail", "service": "store-mail"},
            version="1"
        )
        logger.addHandler(loki_handler)
        logger.info("Loki handler enabled")
except ImportError:
    logger.warning("python-logging-loki not installed, Loki disabled")
except Exception as e:
    logger.warning(f"Failed to initialize Loki handler: {e}")

# Domain for generated message-IDs
MESSAGE_ID_DOMAIN = os.environ.get('MYDOMAIN', 'primitivemail')


def _interpret_webhook_response(http_status: int, body: str) -> dict:
    """Interpret a webhook response. JSON 'status' field is authoritative when
    present; otherwise fall back to HTTP status code mapping.

    Returns a dict compatible with the existing webhook result contract:
      {'success': True, 'status': ..., 'reason': ..., 'detail': ...}  or
      {'success': False, 'error': ...}
    """
    try:
        data = json.loads(body)
        if isinstance(data, dict) and 'status' in data:
            return {
                'success': True,
                'status': data['status'],
                'reason': data.get('reason', ''),
                'detail': data.get('detail', ''),
            }
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    # Fall back to HTTP status code
    if 200 <= http_status < 300:
        return {'success': True, 'status': 'accepted', 'reason': '', 'detail': ''}
    else:
        # 4xx/5xx without explicit JSON status = something went wrong on the
        # webhook side (auth failure, server error, bug). Tempfail so the
        # sender retries and no mail is lost.
        return {'success': False, 'error': f'HTTP {http_status}'}


class EmailProcessor:
    def __init__(self, webhook_url: Optional[str] = None, webhook_secret: Optional[str] = None):
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        self.base_dir = Path("/mail/incoming")
        self.validator = EmailValidator()

    def extract_header(self, email_content: str, header_name: str) -> str:
        """Extract a header value from email content"""
        pattern = rf'^{header_name}:\s*(.+)$'
        match = re.search(pattern, email_content, re.MULTILINE | re.IGNORECASE)
        return match.group(1).strip() if match else ''

    def determine_recipient(self, email_content: str, cli_arg: Optional[str] = None) -> str:
        """Determine recipient from X-Original-To, CLI arg, or To header"""
        # Try X-Original-To header (added by Postfix)
        recipient = self.extract_header(email_content, 'X-Original-To')

        if recipient:
            logger.info(f"Recipient from X-Original-To: {recipient}")
            return recipient

        # Fallback to CLI argument
        if cli_arg:
            logger.info(f"Recipient from CLI argument: {cli_arg}")
            return cli_arg

        # Last resort: parse To header
        to_header = self.extract_header(email_content, 'To')
        # Extract email from "Name <email@domain.com>" format
        email_match = re.search(r'<(.+@.+)>', to_header)
        if email_match:
            recipient = email_match.group(1)
        else:
            recipient = to_header

        logger.info(f"Recipient from To header: {recipient}")
        return recipient

    def save_to_disk(self, email_content: str, recipient: str) -> Path:
        """Save email to disk organized by domain"""
        domain = recipient.split('@')[1] if '@' in recipient else 'unknown'

        # Create domain directory
        domain_dir = self.base_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

        # Generate filename
        timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        random_id = os.urandom(4).hex()
        filename = f"{timestamp}-{random_id}.eml"

        filepath = domain_dir / filename

        # Atomic write: write to .tmp then rename
        tmp_path = filepath.with_suffix('.tmp')
        tmp_path.write_bytes(email_content.encode('utf-8'))
        tmp_path.rename(filepath)
        os.chmod(str(filepath), 0o644)

        logger.info(f"Saved to disk: {filepath}")

        # Write basic .meta.json sidecar (no auth data — pipe transport
        # doesn't have access to SPF/DKIM/DMARC from the milter process).
        # NOTE: mail_from is the From: header, NOT the SMTP envelope sender.
        # The pipe transport doesn't receive the envelope sender by default.
        meta = {
            "smtp": {
                "helo": None,
                "mail_from": self.extract_header(email_content, 'From'),
                "rcpt_to": [recipient]
            },
            "auth": {
                "spf": "none"
            }
        }
        meta_path = filepath.with_suffix('.meta.json')
        meta_tmp = meta_path.with_suffix('.tmp')
        meta_tmp.write_text(json.dumps(meta))
        meta_tmp.rename(meta_path)
        os.chmod(str(meta_path), 0o644)

        logger.info(f"Saved metadata: {meta_path}")
        return filepath

    def send_webhook(self, email_content: str, recipient: str, sender: str,
                    subject: str, message_id: str, size: int) -> bool:
        """Send webhook POST to configured endpoint"""
        if not self.webhook_url or not self.webhook_secret:
            logger.info("Webhook not configured (WEBHOOK_URL or WEBHOOK_SECRET missing)")
            return False

        logger.info(f"Webhook enabled, preparing payload...")

        # Lowercase domain - DNS is case-insensitive (RFC 1035)
        domain = recipient.split('@')[1].lower() if '@' in recipient else 'unknown'

        # Encode email as base64
        eml_base64 = base64.b64encode(email_content.encode('utf-8')).decode('ascii')

        payload = {
            'recipient': recipient,
            'sender': sender,
            'subject': subject,
            'message_id': message_id,
            'domain': domain,
            'size': size,
            'eml_base64': eml_base64
        }

        logger.info(f"Posting to webhook: {self.webhook_url}")

        # Measure webhook latency
        start_time = time.time()
        http_status = 0

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode('utf-8'),
                headers={
                    'Authorization': f'Bearer {self.webhook_secret}',
                    'Content-Type': 'application/json'
                },
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                latency_ms = (time.time() - start_time) * 1000
                http_status = response.status
                response_body = response.read().decode('utf-8')

                result = _interpret_webhook_response(http_status, response_body)

                logger.info(
                    f"Webhook responded: {result.get('status', 'N/A')}",
                    extra={
                        "event": "webhook_response",
                        "domain": domain,
                        "recipient": recipient,
                        "http_status": http_status,
                        "ingestion_status": result.get('status'),
                        "reason": result.get('reason', ''),
                        "latency_ms": round(latency_ms, 2),
                    }
                )

                return result

        except urllib.error.HTTPError as e:
            latency_ms = (time.time() - start_time) * 1000
            http_status = e.code
            error_body = e.read().decode('utf-8') if e.fp else ''

            logger.error(
                "Webhook HTTP error",
                extra={
                    "event": "webhook_failed",
                    "domain": domain,
                    "recipient": recipient,
                    "http_status": http_status,
                    "latency_ms": round(latency_ms, 2),
                    "error": error_body[:200],
                }
            )

            return _interpret_webhook_response(http_status, error_body)

        except urllib.error.URLError as e:
            latency_ms = (time.time() - start_time) * 1000

            logger.error(
                "Webhook network error",
                extra={
                    "event": "webhook_failed",
                    "domain": domain,
                    "recipient": recipient,
                    "latency_ms": round(latency_ms, 2),
                    "error": str(e.reason),
                }
            )
            return {
                'success': False,
                'error': str(e.reason)
            }

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000

            logger.error(
                "Webhook unexpected error",
                extra={
                    "event": "webhook_failed",
                    "domain": domain,
                    "recipient": recipient,
                    "latency_ms": round(latency_ms, 2),
                    "error": str(e),
                }
            )
            return {
                'success': False,
                'error': str(e)
            }

    def process_email(self, email_content: str, cli_recipient: Optional[str] = None) -> int:
        """Main processing pipeline"""
        logger.info("=" * 50)

        # Determine recipient
        recipient = self.determine_recipient(email_content, cli_recipient)

        if not recipient:
            logger.error("Could not determine recipient")
            return 75  # Temp fail - sender should retry

        # SECURITY: Validate recipient to prevent path traversal and other attacks
        recipient_validation = self.validator.validate_email_address(recipient)
        if not recipient_validation.valid:
            logger.error(
                f"SECURITY: Invalid recipient silently dropped: {recipient_validation.error}",
                extra={
                    "event": "email_rejected_invalid",
                    "recipient": self.validator.sanitize_for_logging(recipient),
                    "error": recipient_validation.error,
                    "exit_code": 0
                }
            )
            return 0  # Silent drop - don't reveal validation logic to attackers

        # Extract other metadata
        sender = self.extract_header(email_content, 'From')
        subject = self.extract_header(email_content, 'Subject')
        message_id_header = self.extract_header(email_content, 'Message-ID')
        size = len(email_content.encode('utf-8'))

        # Generate deterministic message_id if header missing
        if not message_id_header:
            body_start = email_content[email_content.find('\n\n')+2:][:100] if '\n\n' in email_content else ''
            hash_input = f"{recipient}|{sender}|{subject}|{body_start}".encode('utf-8')
            hash_hex = hashlib.sha256(hash_input).hexdigest()[:16]
            message_id = f"<generated-{hash_hex}@{MESSAGE_ID_DOMAIN}>"
            logger.info(f"Generated deterministic message_id: {message_id}")
        else:
            message_id = message_id_header

        # SECURITY: Validate size
        size_validation = self.validator.validate_size(size)
        if not size_validation.valid:
            logger.error(
                f"Email size silently dropped: {size_validation.error}",
                extra={
                    "event": "email_rejected_size",
                    "recipient": recipient,
                    "size_bytes": size,
                    "exit_code": 0
                }
            )
            return 0  # Silent drop - don't reveal limits to attackers

        # Extract domain from validated recipient (safe now)
        domain = recipient.split('@')[1].lower()

        logger.info(
            f"Received email for: {recipient}",
            extra={
                "event": "email_received",
                "recipient": recipient,
                "sender": sender,
                "subject": subject,
                "domain": domain,
                "size_bytes": size
            }
        )
        logger.info(f"From: {sender}")
        logger.info(f"Subject: {subject}")
        logger.info(f"Size: {size} bytes")
        logger.info(f"Domain: {domain}")

        # Call webhook if configured
        if self.webhook_url and self.webhook_secret:
            result = self.send_webhook(email_content, recipient, sender, subject, message_id, size)

            if not result['success']:
                logger.error(
                    "Webhook FAILED - returning temp failure",
                    extra={
                        "event": "delivery_tempfail",
                        "domain": domain,
                        "recipient": recipient,
                        "exit_code": 75,
                        "reason": result.get('error', 'unknown'),
                    }
                )
                return 75  # CRITICAL: Temp fail (451) - sender retries, email not lost

            # Check ingestion status
            ingestion_status = result.get('status')

            if ingestion_status == 'accepted':
                logger.info(
                    "Email accepted by webhook",
                    extra={
                        "event": "delivery_success",
                        "domain": domain,
                        "recipient": recipient,
                        "exit_code": 0,
                    }
                )
                logger.info("=" * 50)
                return 0  # Success - Postfix sends 250 OK

            elif ingestion_status == 'reject_permanent':
                reason = result.get('reason', 'unknown')
                logger.info(
                    f"Email permanently rejected: {reason}",
                    extra={
                        "event": "delivery_rejected",
                        "domain": domain,
                        "recipient": recipient,
                        "reason": reason,
                        "exit_code": 67,
                    }
                )
                logger.info("=" * 50)
                return 67  # EX_NOUSER - Postfix sends 550

            else:
                # Unknown status - treat as tempfail to be safe
                logger.error(
                    f"Unknown webhook status: {ingestion_status}",
                    extra={
                        "event": "delivery_tempfail",
                        "domain": domain,
                        "recipient": recipient,
                        "status": ingestion_status,
                        "exit_code": 75,
                    }
                )
                return 75  # Temp fail
        else:
            logger.info("No webhook configured - saving email to disk (standalone mode)")
            try:
                self.save_to_disk(email_content, recipient)
            except Exception as e:
                logger.error(f"Failed to save email to disk: {e}")
                return 75  # Temp fail - sender should retry
            return 0  # Accept in standalone mode


def main():
    """Entry point"""
    # Read email from stdin
    email_content = sys.stdin.read()

    # Get recipient from CLI argument if provided
    cli_recipient = sys.argv[1] if len(sys.argv) > 1 else None

    # Get webhook config from environment
    webhook_url = os.environ.get('WEBHOOK_URL')
    webhook_secret = os.environ.get('WEBHOOK_SECRET')

    # Process email
    processor = EmailProcessor(webhook_url, webhook_secret)
    exit_code = processor.process_email(email_content, cli_recipient)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
