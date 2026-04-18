#!/usr/bin/env python3
"""
SMTP Milter for PrimitiveMail
Intercepts emails DURING the SMTP transaction (before 250 OK).

Two modes:
- Webhook mode: Calls a configured webhook URL and returns ACCEPT/REJECT based on response.
- Standalone mode: Accepts all valid emails (when no WEBHOOK_URL is configured).

Security features (all configurable):
- Sender filtering: ALLOWED_SENDER_DOMAINS / ALLOWED_SENDERS
- Recipient filtering: ALLOWED_RECIPIENTS
- Spoof protection: SPF / DKIM / DMARC verification
"""

import os
import sys
import re
import json
import base64
import logging
import time
import hashlib
import ipaddress
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Optional, Dict, Any
import urllib.request
import urllib.error

import Milter
from Milter.utils import parse_addr

from email_validator import EmailValidator

from primitive import (
    PRIMITIVE_SIGNATURE_HEADER,
    STANDARD_WEBHOOK_ID_HEADER,
    STANDARD_WEBHOOK_SIGNATURE_HEADER,
    STANDARD_WEBHOOK_TIMESTAMP_HEADER,
    sign_standard_webhooks_payload,
    sign_webhook_payload,
)

# Fixed namespace UUID for webhook-id derivation. Stable across replicas and
# restarts. Published in AGENTS.md so operators can reproduce webhook-id values
# by hand: uuid.uuid5(WEBHOOK_ID_NAMESPACE, f"{message_id}:{recipient}:{queue_id}").
WEBHOOK_ID_NAMESPACE = uuid.UUID("6f79e4a8-a494-4f7e-9124-90d94cb26d5d")

# Reserved webhook header names. WEBHOOK_EXTRA_HEADERS cannot override these;
# the milter refuses to start if it tries. Comparison is ASCII case-folded.
RESERVED_WEBHOOK_HEADER_NAMES = frozenset({
    "authorization",
    "content-type",
    "webhook-id",
    "webhook-timestamp",
    "webhook-signature",
    "primitive-signature",
})

# SPF/DKIM/DMARC support (optional - only needed when SPOOF_PROTECTION != off)
try:
    import spf as spfmod
    SPF_AVAILABLE = True
except ImportError:
    SPF_AVAILABLE = False

try:
    import dkim
    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    class _NXDOMAINShim(Exception):
        pass

    class _NoAnswerShim(Exception):
        pass

    class _NoNameserversShim(Exception):
        pass

    dns = SimpleNamespace(
        resolver=SimpleNamespace(
            NXDOMAIN=_NXDOMAINShim,
            NoAnswer=_NoAnswerShim,
            NoNameservers=_NoNameserversShim,
            Timeout=TimeoutError,
            Resolver=None,
        )
    )
    DNS_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_CACHE_DIR = os.environ.get('TLDEXTRACT_CACHE', '/tmp/primitivemail-tldextract')
    TLDEXTRACT_EXTRACTOR = tldextract.TLDExtract(
        cache_dir=TLDEXTRACT_CACHE_DIR,
        suffix_list_urls=(),
    )
    TLDEXTRACT_AVAILABLE = True
except Exception:
    TLDEXTRACT_EXTRACTOR = None
    TLDEXTRACT_AVAILABLE = False

# Prometheus metrics (optional - degrades gracefully if not installed)
try:
    from prometheus_client import Counter, Histogram, Gauge, start_http_server

    DURATION_BUCKETS = [0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 25, 30, 60]
    SIZE_BUCKETS = [10_000, 100_000, 500_000, 1_000_000, 3_000_000, 5_000_000, 10_000_000, 25_000_000]

    EOM_DURATION = Histogram(
        'milter_eom_duration_seconds',
        'Total eom() processing time',
        ['result', 'path'],
        buckets=DURATION_BUCKETS,
    )
    STORAGE_UPLOAD_DURATION = Histogram(
        'milter_storage_upload_duration_seconds',
        'Storage upload time for large emails',
        ['status'],
        buckets=DURATION_BUCKETS,
    )
    WEBHOOK_DURATION = Histogram(
        'milter_webhook_duration_seconds',
        'Webhook call time',
        ['status', 'path'],
        buckets=DURATION_BUCKETS,
    )
    EMAIL_SIZE = Histogram(
        'milter_email_size_bytes',
        'Email size distribution',
        ['path'],
        buckets=SIZE_BUCKETS,
    )
    EMAILS_TOTAL = Counter(
        'milter_emails_total',
        'Total emails processed',
        ['result', 'path'],
    )
    STORAGE_UPLOADS_TOTAL = Counter(
        'milter_storage_uploads_total',
        'Total storage upload attempts',
        ['status'],
    )
    WEBHOOK_CALLS_TOTAL = Counter(
        'milter_webhook_calls_total',
        'Total webhook calls',
        ['status', 'path'],
    )
    ERRORS_TOTAL = Counter(
        'milter_errors_total',
        'Errors by stage',
        ['stage'],
    )
    IN_FLIGHT = Gauge(
        'milter_in_flight_emails',
        'Emails currently being processed in eom()',
    )
    METRICS_ENABLED = True
except ImportError:
    METRICS_ENABLED = False


def record_metrics(fn):
    """Safely record prometheus metrics. Never raises."""
    if METRICS_ENABLED:
        try:
            fn()
        except Exception:
            pass

# Datadog APM tracing (optional — install ddtrace and set DATADOG_TRACING_ENABLED=true)
TRACING_ENABLED = False
tracer = None
HTTPPropagator = None
try:
    if os.environ.get('DATADOG_TRACING_ENABLED', '').lower() == 'true':
        from ddtrace import tracer as _tracer
        from ddtrace.propagation.http import HTTPPropagator as _HTTPPropagator
        tracer = _tracer
        HTTPPropagator = _HTTPPropagator
        TRACING_ENABLED = True
except ImportError:
    pass
_TRACING_WANTED = os.environ.get('DATADOG_TRACING_ENABLED', '').lower() == 'true'

# Configure logging
handlers = [logging.StreamHandler(sys.stderr)]

try:
    handlers.append(logging.FileHandler('/var/log/milter.log', mode='a'))
except PermissionError:
    try:
        handlers.append(logging.FileHandler('/tmp/milter.log', mode='a'))
    except PermissionError:
        pass

logging.basicConfig(
    level=logging.INFO,
    format='[milter] %(asctime)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=handlers
)
logger = logging.getLogger(__name__)

# Deferred tracing log (after basicConfig so the message is visible)
if TRACING_ENABLED:
    logger.info("Datadog APM tracing enabled")
elif _TRACING_WANTED:
    logger.warning("DATADOG_TRACING_ENABLED=true but ddtrace not installed — tracing disabled")

# Add Loki handler if configured (optional - works with any Loki-compatible endpoint)
try:
    if os.getenv('LOKI_URL'):
        from logging_loki import LokiHandler
        loki_handler = LokiHandler(
            url=os.getenv('LOKI_URL'),
            auth=(os.getenv('LOKI_USER'), os.getenv('LOKI_KEY')),
            tags={"job": "primitivemail", "service": "milter"},
            version="1"
        )
        logger.addHandler(loki_handler)
        logger.info("Loki handler enabled")
except ImportError:
    pass
except Exception as e:
    logger.warning(f"Failed to initialize Loki handler: {e}")

# Configuration from environment
WEBHOOK_URL = os.environ.get('WEBHOOK_URL')
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET')

# Extra headers to include on webhook calls (JSON object, optional).
# Useful for deployment protection bypass, API gateway auth, etc.
# Example: WEBHOOK_EXTRA_HEADERS='{"x-vercel-protection-bypass": "secret123"}'
WEBHOOK_EXTRA_HEADERS = {}
try:
    raw = os.environ.get('WEBHOOK_EXTRA_HEADERS', '')
    if raw:
        WEBHOOK_EXTRA_HEADERS = json.loads(raw)
        if not isinstance(WEBHOOK_EXTRA_HEADERS, dict):
            logger.error("WEBHOOK_EXTRA_HEADERS must be a JSON object, ignoring")
            WEBHOOK_EXTRA_HEADERS = {}
        else:
            logger.info(f"Webhook extra headers configured: {list(WEBHOOK_EXTRA_HEADERS.keys())}")
except (json.JSONDecodeError, ValueError) as e:
    logger.error(f"Invalid WEBHOOK_EXTRA_HEADERS JSON: {e}")

# Reject reserved-header collisions at startup. A misconfigured env var should
# fail loud and fast, not produce tempfails on every delivery.
for _extra_key in WEBHOOK_EXTRA_HEADERS:
    if _extra_key.lower() in RESERVED_WEBHOOK_HEADER_NAMES:
        logger.error(f"WEBHOOK_EXTRA_HEADERS reserved name: {_extra_key.lower()}")
        sys.exit(2)

# Storage configuration for large email uploads
# Supports S3-compatible storage (AWS S3, R2, MinIO, Supabase Storage, etc.)
STORAGE_URL = os.environ.get('STORAGE_URL')        # e.g. https://s3.amazonaws.com/my-bucket
STORAGE_KEY = os.environ.get('STORAGE_KEY')          # Auth key/token
STORAGE_AUTH_STYLE = os.environ.get('STORAGE_AUTH_STYLE', 's3')  # "s3" or "supabase"

# Domain for generated message-IDs (falls back to MYDOMAIN or "primitivemail")
MESSAGE_ID_DOMAIN = os.environ.get('MYDOMAIN', 'primitivemail')

# Standalone mode: if no webhook URL configured, accept all valid emails
STANDALONE_MODE = not WEBHOOK_URL

# Mail storage directory for standalone mode
MAIL_DIR = os.environ.get('MAIL_DIR', '/mail/incoming')

if STANDALONE_MODE:
    logger.info("No WEBHOOK_URL configured - running in standalone mode (accept all valid emails)")
else:
    if not WEBHOOK_SECRET:
        logger.error("WEBHOOK_SECRET must be set when WEBHOOK_URL is configured")
        sys.exit(1)
    # Fail-fast on invalid secret format. sign_standard_webhooks_payload raises
    # WebhookVerificationError("MISSING_SECRET") if WEBHOOK_SECRET is not
    # base64 (optionally prefixed with whsec_). Better to crash at startup
    # than to tempfail every message.
    try:
        sign_standard_webhooks_payload(
            raw_body=b'{}',
            secret=WEBHOOK_SECRET,
            msg_id='startup-check',
            timestamp=int(time.time()),
        )
    except Exception as e:
        logger.error(
            "WEBHOOK_SECRET is not a Standard-Webhooks-compatible value. "
            "Rotate to whsec_<base64> format. Error: %s",
            e,
        )
        sys.exit(1)

# Storage upload (optional - only needed for large emails when webhook is configured)
if not STANDALONE_MODE and not STORAGE_URL:
    logger.info("STORAGE_URL not set - large emails (>3MB) will be sent inline via webhook")

# Size threshold for storage-first upload (bytes)
STORAGE_UPLOAD_THRESHOLD = 3_000_000

# --- Sender filtering ---
# Envelope-level allowlist. Not authentication -- sender can be forged.
# For real verification, use SPOOF_PROTECTION.
_sender_domains = os.environ.get('ALLOWED_SENDER_DOMAINS', '')
ALLOWED_SENDER_DOMAINS = {d.strip().lower() for d in _sender_domains.split(',') if d.strip()} if _sender_domains.strip() else set()

_senders = os.environ.get('ALLOWED_SENDERS', '')
ALLOWED_SENDERS = {s.strip().lower() for s in _senders.split(',') if s.strip()} if _senders.strip() else set()

ALLOW_BOUNCES = os.environ.get('ALLOW_BOUNCES', 'true').lower() == 'true'

SENDER_FILTERING_ENABLED = bool(ALLOWED_SENDER_DOMAINS or ALLOWED_SENDERS)

# --- Recipient filtering ---
_recipients = os.environ.get('ALLOWED_RECIPIENTS', '')
ALLOWED_RECIPIENTS = {r.strip().lower() for r in _recipients.split(',') if r.strip()} if _recipients.strip() else set()

RECIPIENT_FILTERING_ENABLED = bool(ALLOWED_RECIPIENTS)

# --- Spoof protection (SPF/DKIM/DMARC) ---
SPOOF_PROTECTION = os.environ.get('SPOOF_PROTECTION', 'off').lower()
if SPOOF_PROTECTION not in ('off', 'monitor', 'standard', 'strict'):
    logger.warning(f"Invalid SPOOF_PROTECTION value '{SPOOF_PROTECTION}' - defaulting to 'off'")
    SPOOF_PROTECTION = 'off'

if SPOOF_PROTECTION != 'off':
    missing = []
    if not SPF_AVAILABLE:
        missing.append('pyspf')
    if not DKIM_AVAILABLE:
        missing.append('dkimpy')
    if not DNS_AVAILABLE:
        missing.append('dnspython')
    if missing:
        logger.warning(f"SPOOF_PROTECTION={SPOOF_PROTECTION} but missing packages: {', '.join(missing)} - falling back to 'off'")
        SPOOF_PROTECTION = 'off'
    else:
        # DKIM verification uses headers reconstructed from milter callbacks,
        # which may differ from the original wire format. Most DKIM signers use
        # "relaxed" canonicalization which tolerates these differences, but some
        # signatures with "simple" canonicalization may fail verification.
        # Recommend "monitor" mode initially to observe results before enforcing.
        if SPOOF_PROTECTION in ('standard', 'strict'):
            logger.info("Note: DKIM verification uses reconstructed headers. "
                        "Consider 'monitor' mode first to verify accuracy.")

# DNS resolver timeout for SPF/DKIM/DMARC lookups
DNS_TIMEOUT = 3

# Spamhaus DNSBL (optional).
# Set SPAMHAUS_DNSBL_DOMAIN to the full query suffix, for example:
# - zen.spamhaus.org
# - <your_DQS_key>.zen.dq.spamhaus.net
# We only enforce the DROP return code (127.0.0.9) for now so the behavior
# matches the existing DROP-only cron policy.
SPAMHAUS_DNSBL_DOMAIN = os.environ.get('SPAMHAUS_DNSBL_DOMAIN', '').strip().lower().rstrip('.')
SPAMHAUS_DROP_CODE = '127.0.0.9'

if SPAMHAUS_DNSBL_DOMAIN and not DNS_AVAILABLE:
    logger.warning("SPAMHAUS_DNSBL_DOMAIN is set but dnspython is unavailable - DNSBL disabled")
    SPAMHAUS_DNSBL_DOMAIN = ''

if SENDER_FILTERING_ENABLED:
    logger.info(f"Sender filtering enabled: {len(ALLOWED_SENDER_DOMAINS)} domains, {len(ALLOWED_SENDERS)} addresses")
if RECIPIENT_FILTERING_ENABLED:
    logger.info(f"Recipient filtering enabled: {len(ALLOWED_RECIPIENTS)} addresses")
if SPOOF_PROTECTION != 'off':
    logger.info(f"Spoof protection: {SPOOF_PROTECTION}")
if SPAMHAUS_DNSBL_DOMAIN:
    logger.info(f"Spamhaus DNSBL enabled: {SPAMHAUS_DNSBL_DOMAIN} (enforcing {SPAMHAUS_DROP_CODE})")

validator = EmailValidator()


def _interpret_webhook_response(http_status: int, body: str) -> Dict[str, Any]:
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


class PrimitiveMailMilter(Milter.Base):
    """
    Milter that intercepts emails during SMTP.

    In webhook mode: calls the configured webhook and maps response to SMTP codes.
    In standalone mode: accepts all valid emails.

    Key callbacks:
    - envfrom: MAIL FROM (sender)
    - envrcpt: RCPT TO (recipient)
    - header: Each header
    - body: Body chunks
    - eom: End of message - where we decide accept/reject
    """

    def __init__(self):
        self.id = Milter.uniqueID()
        # Connection-level state (set in connect/hello, persists across messages)
        self.client_ip = None
        self.client_hostname = None
        self.helo = ''
        self.reset()

    def reset(self):
        """Reset state for new message"""
        self.sender = None
        self.recipients = []
        self.headers = []
        self.body_chunks = []
        self.subject = None
        self.message_id = None
        self.from_header = None
        self.spf_result = 'none'
        self._result_label = 'unknown'
        self._path_label = 'inline'
        self._trace_span = None

    def log(self, msg: str, **extra):
        """Log with connection ID for correlation"""
        logger.info(f"[{self.id}] {msg}", extra=extra)

    def log_error(self, msg: str, **extra):
        """Log error with connection ID"""
        logger.error(f"[{self.id}] {msg}", extra=extra)

    def _finish_trace(self, result: str, error: str = None):
        """Finish the APM trace span for this email (no-op if tracing disabled)"""
        span = getattr(self, '_trace_span', None)
        if span:
            span.set_tag("email.result", result)
            if error:
                span.set_tag("error", True)
                span.set_tag("error.message", error)
            span.finish()
            self._trace_span = None

    @staticmethod
    def _reverse_ipv4_for_dnsbl(ip: str) -> Optional[str]:
        """Reverse a global IPv4 address for DNSBL queries."""
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return None

        if parsed.version != 4 or not parsed.is_global:
            return None

        return '.'.join(reversed(str(parsed).split('.')))

    def _lookup_spamhaus_dnsbl(self) -> Optional[list]:
        """Return Spamhaus response codes for the client IP, or None if not listed.

        Fail open on lookup errors to avoid blocking legitimate mail when DNS is
        unavailable.
        """
        if not SPAMHAUS_DNSBL_DOMAIN or not self.client_ip:
            return None

        reversed_ip = self._reverse_ipv4_for_dnsbl(self.client_ip)
        if not reversed_ip:
            return None

        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        resolver.timeout = DNS_TIMEOUT
        query_name = f"{reversed_ip}.{SPAMHAUS_DNSBL_DOMAIN}"

        try:
            answers = resolver.resolve(query_name, 'A')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None
        except dns.resolver.Timeout as e:
            self.log_error(f"Spamhaus DNSBL lookup timed out for {self.client_ip}: {e}")
            return None
        except Exception as e:
            self.log_error(f"Spamhaus DNSBL lookup failed for {self.client_ip}: {e}")
            return None

        codes = sorted({rdata.to_text() for rdata in answers})

        # DQS-specific errors should fail open and be very visible in logs.
        if '127.255.255.250' in codes or '127.255.255.251' in codes:
            self.log_error(
                f"Spamhaus DNSBL returned DQS error codes for {self.client_ip}: {', '.join(codes)}"
            )
            return None

        return codes or None

    @Milter.noreply
    def connect(self, hostname, family, hostaddr):
        """Called when client connects"""
        self.client_ip = hostaddr[0] if hostaddr else None
        self.client_hostname = hostname
        self.log(f"Connect from {hostname} [{self.client_ip}]")
        return Milter.CONTINUE

    @Milter.noreply
    def hello(self, heloname):
        """HELO/EHLO command"""
        self.helo = heloname
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *params):
        """MAIL FROM command - get sender, apply DNSBL, sender filtering and SPF"""
        self.reset()  # New message, reset state
        # Parse sender address (handles <addr> format)
        # parse_addr returns (user, domain) tuple for normal addresses
        # For bounces (empty MAIL FROM <>), it returns [''] (list with empty string)
        parts = parse_addr(mailfrom)
        if isinstance(parts, (list, tuple)) and len(parts) == 2 and parts[0] and parts[1]:
            self.sender = f"{parts[0]}@{parts[1]}"
        elif isinstance(parts, (list, tuple)):
            # Bounce or malformed -- join non-empty parts, or empty string
            joined = '@'.join(p for p in parts if p)
            self.sender = joined if joined else ''
        else:
            self.sender = str(parts) if parts else ''
        self.log(f"MAIL FROM: {self.sender!r}")

        # Reject DROP-listed IPs early, before reading the message body.
        dnsbl_codes = self._lookup_spamhaus_dnsbl()
        if dnsbl_codes and SPAMHAUS_DROP_CODE in dnsbl_codes:
            self.log(
                f"Client IP {self.client_ip} listed in Spamhaus DNSBL: {', '.join(dnsbl_codes)}"
            )
            self.setreply("554", "5.7.1", "Rejected - client IP listed in Spamhaus DROP")
            return Milter.REJECT

        # --- Sender filtering ---
        if SENDER_FILTERING_ENABLED:
            if not self.sender:
                # Bounce message (empty MAIL FROM)
                if not ALLOW_BOUNCES:
                    self.log("Bounce rejected (ALLOW_BOUNCES=false)")
                    self.setreply("550", "5.7.1", "Bounces not accepted")
                    return Milter.REJECT
            else:
                sender_lower = self.sender.lower()
                sender_domain = sender_lower.split('@')[1] if '@' in sender_lower else ''
                if sender_lower not in ALLOWED_SENDERS and sender_domain not in ALLOWED_SENDER_DOMAINS:
                    self.log(f"Sender not authorized: {self.sender}")
                    self.setreply("550", "5.7.0", "Message rejected")
                    return Milter.REJECT

        # --- SPF check (earliest possible -- we have client_ip, sender, helo) ---
        if SPOOF_PROTECTION != 'off' and self.sender and SPF_AVAILABLE:
            try:
                result, explanation = spfmod.check2(
                    i=self.client_ip,
                    s=self.sender,
                    h=getattr(self, 'helo', ''),
                    timeout=DNS_TIMEOUT
                )
                self.spf_result = result
                self.log(f"SPF check: {result} ({explanation})")

                if SPOOF_PROTECTION == 'strict' and result in ('fail', 'softfail'):
                    self.setreply("550", "5.7.23", f"SPF validation failed: {explanation}")
                    return Milter.REJECT
            except Exception as e:
                self.log(f"SPF check error (treating as neutral): {e}")
                self.spf_result = 'temperror'

        return Milter.CONTINUE

    def envrcpt(self, to, *params):
        """RCPT TO command - collect recipient (called once per RCPT TO)"""
        parts = parse_addr(to)
        if isinstance(parts, (list, tuple)) and len(parts) == 2 and parts[0] and parts[1]:
            rcpt = f"{parts[0]}@{parts[1]}"
        elif isinstance(parts, (list, tuple)):
            joined = '@'.join(p for p in parts if p)
            rcpt = joined if joined else ''
        else:
            rcpt = str(parts) if parts else ''
        self.log(f"RCPT TO: {rcpt!r}")
        if rcpt:
            # --- Recipient filtering ---
            if RECIPIENT_FILTERING_ENABLED and rcpt.lower() not in ALLOWED_RECIPIENTS:
                self.log(f"Recipient not allowed: {rcpt}")
                self.setreply("550", "5.1.1", "Recipient not accepted")
                return Milter.REJECT
            self.recipients.append(rcpt)
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, value):
        """Called for each header"""
        self.headers.append((name, value))

        # Capture important headers
        name_lower = name.lower()
        if name_lower == 'subject':
            self.subject = value
        elif name_lower == 'message-id':
            self.message_id = value
        elif name_lower == 'from':
            self.from_header = value

        return Milter.CONTINUE

    @Milter.noreply
    def body(self, chunk):
        """Called for each body chunk"""
        self.body_chunks.append(chunk)
        return Milter.CONTINUE

    # --- Helper methods for spoof protection ---

    def _extract_from_domain(self) -> str:
        """Extract domain from RFC5322 From header (handles display names)"""
        if not self.from_header:
            return ''
        # Try to extract from "Display Name <user@domain>" format
        match = re.search(r'<([^>]+)>', self.from_header)
        addr = match.group(1) if match else self.from_header.strip()
        if '@' in addr:
            return addr.split('@')[1].strip().lower()
        return ''

    @staticmethod
    def _org_domain(domain: str) -> str:
        """Extract organizational domain using tldextract (e.g., mail.example.com -> example.com)."""
        if not TLDEXTRACT_AVAILABLE:
            return domain.lower()
        try:
            ext = TLDEXTRACT_EXTRACTOR(domain)
        except Exception:
            return domain.lower()
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return domain.lower()

    @staticmethod
    def _domains_aligned(domain_a: str, domain_b: str, mode: str) -> bool:
        """Check if two domains are aligned per DMARC rules.
        mode 's' = strict (exact match), mode 'r' = relaxed (org domain match)."""
        if mode == 's':
            return domain_a.lower() == domain_b.lower()
        return PrimitiveMailMilter._org_domain(domain_a) == PrimitiveMailMilter._org_domain(domain_b)

    def _check_dkim(self, raw_bytes: bytes) -> tuple:
        """Verify DKIM signature. Returns (result, [signing_domains])."""
        if not DKIM_AVAILABLE:
            return ('none', [])
        try:
            # dkimpy uses dnspython internally, which respects system DNS timeout
            verified = dkim.verify(raw_bytes)
            result = 'pass' if verified else 'fail'

            # Extract signing domains from ALL DKIM-Signature headers
            dkim_domains = []
            for name, value in self.headers:
                if name.lower() == 'dkim-signature':
                    for part in value.split(';'):
                        part = part.strip()
                        if part.startswith('d='):
                            dkim_domains.append(part[2:].strip().lower())
                            break

            return (result, dkim_domains)
        except Exception as e:
            self.log(f"DKIM check error (treating as neutral): {e}")
            return ('none', [])

    @staticmethod
    def _lookup_dmarc_record(resolver, domain: str) -> Optional[str]:
        """Look up DMARC TXT record for a domain. Returns record string or None."""
        try:
            answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in answers:
                txt = b''.join(rdata.strings).decode('utf-8')
                if txt.startswith('v=DMARC1'):
                    return txt
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.Timeout,
                UnicodeDecodeError):
            pass
        return None

    @staticmethod
    def _parse_dmarc_record(dmarc_record: str) -> Dict[str, str]:
        """Parse DMARC record tags into a dict."""
        tags = {}
        for part in dmarc_record.split(';'):
            part = part.strip()
            if '=' in part:
                key, _, value = part.partition('=')
                tags[key.strip().lower()] = value.strip().lower()
        return tags

    def _check_dmarc(self, from_domain: str, spf_result: str, spf_domain: str,
                     dkim_result: str, dkim_domains: list) -> Dict[str, Any]:
        """Check DMARC policy for the From header domain.
        Implements RFC 7489 Section 6.6.3 org-domain fallback."""
        if not DNS_AVAILABLE or not from_domain:
            return {'policy': 'none', 'pass': True}

        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = DNS_TIMEOUT
            resolver.timeout = DNS_TIMEOUT

            # Step 1: Look up exact From domain
            dmarc_record = self._lookup_dmarc_record(resolver, from_domain)
            is_subdomain_policy = False

            # Step 2: Fall back to org domain (RFC 7489 Section 6.6.3)
            if not dmarc_record:
                org_dom = self._org_domain(from_domain)
                if org_dom and org_dom.lower() != from_domain.lower():
                    dmarc_record = self._lookup_dmarc_record(resolver, org_dom)
                    if dmarc_record:
                        is_subdomain_policy = True
                        self.log(f"DMARC: no record for {from_domain}, "
                                 f"using org domain {org_dom}")

            if not dmarc_record:
                return {'policy': 'none', 'pass': True}

            # Step 3: Parse record
            tags = self._parse_dmarc_record(dmarc_record)

            # Use sp= (subdomain policy) when applying org domain record to a subdomain.
            # If sp= is absent, p= applies to subdomains as well (RFC 7489 Section 6.3).
            if is_subdomain_policy and 'sp' in tags:
                policy = tags['sp']
            else:
                policy = tags.get('p', 'none')

            aspf = tags.get('aspf', 'r')   # RFC 7489: default is relaxed
            adkim = tags.get('adkim', 'r')

            # DMARC alignment (relaxed by default per RFC 7489)
            spf_aligned = (spf_result == 'pass' and
                           self._domains_aligned(spf_domain, from_domain, aspf))
            dkim_aligned = (dkim_result == 'pass' and
                            any(self._domains_aligned(d, from_domain, adkim)
                                for d in dkim_domains))

            dmarc_pass = spf_aligned or dkim_aligned

            return {'policy': policy, 'pass': dmarc_pass}

        except Exception as e:
            self.log(f"DMARC check error (treating as none): {e}")
            return {'policy': 'none', 'pass': True}

    def _save_to_disk(self, raw_bytes: bytes, recipients: list,
                      dkim_result=None, dkim_domains=None,
                      dmarc_result=None, from_domain=None):
        """Save email to disk for standalone mode. One copy per unique domain."""
        mail_dir = Path(MAIL_DIR)
        timestamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        random_id = os.urandom(4).hex()

        saved_domains = set()
        for rcpt in recipients:
            domain = rcpt.split('@')[1].lower() if '@' in rcpt else 'unknown'
            if domain in saved_domains:
                continue
            saved_domains.add(domain)

            domain_dir = mail_dir / domain
            domain_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

            filename = f"{timestamp}-{random_id}.eml"
            filepath = domain_dir / filename
            tmp_path = filepath.with_suffix('.tmp')

            # Atomic write: write to .tmp then rename
            tmp_path.write_bytes(raw_bytes)
            tmp_path.rename(filepath)
            os.chmod(str(filepath), 0o644)

            self.log(f"Saved to disk: {filepath}")

            # Write .meta.json sidecar with envelope + auth data
            auth = {"spf": self.spf_result}
            if dkim_result is not None:
                auth["dkim"] = dkim_result
                auth["dkim_domains"] = dkim_domains or []
            if dmarc_result is not None:
                auth["dmarc"] = "pass" if dmarc_result['pass'] else "fail"
                auth["dmarc_policy"] = dmarc_result['policy']
                auth["dmarc_from_domain"] = from_domain

            domain_recipients = [r for r in recipients
                                 if '@' in r and r.split('@')[1].lower() == domain]

            meta = {
                "smtp": {
                    "helo": self.helo,
                    "mail_from": self.sender,
                    "rcpt_to": domain_recipients
                },
                "auth": auth
            }

            meta_path = filepath.with_suffix('.meta.json')
            meta_tmp = meta_path.with_suffix('.tmp')
            meta_tmp.write_text(json.dumps(meta))
            meta_tmp.rename(meta_path)
            os.chmod(str(meta_path), 0o644)

            self.log(f"Saved metadata: {meta_path}")

    def eom(self):
        """
        End of message - this is where we decide accept/reject.

        This runs BEFORE Postfix sends 250 OK.
        We must return:
        - ACCEPT: Send 250 OK (email accepted)
        - TEMPFAIL: Send 451 (temporary failure, sender should retry)
        - REJECT: Send 550 (permanent rejection)
        """
        self.log("=" * 50)
        self.log("End of message - processing")

        eom_start = time.time()
        self._eom_start = eom_start
        if METRICS_ENABLED:
            IN_FLIGHT.inc()

        try:
            return self._process_eom()
        finally:
            if METRICS_ENABLED:
                try:
                    IN_FLIGHT.dec()
                    duration = time.time() - eom_start
                    EOM_DURATION.labels(result=self._result_label, path=self._path_label).observe(duration)
                    EMAILS_TOTAL.labels(result=self._result_label, path=self._path_label).inc()
                except Exception as e:
                    self.log_error(f"Metrics recording failed: {e}")

    def _process_eom(self):
        """Inner eom logic, separated for metrics wrapping"""
        self._result_label = 'tempfail'
        self._path_label = 'inline'

        # Validate recipients
        if not self.recipients:
            self.log_error("No recipients - rejecting")
            self.setreply("550", "5.1.1", "No recipient")
            self._result_label = 'reject_permanent'
            return Milter.REJECT

        # De-duplicate recipients (case-insensitive, preserve first occurrence)
        seen = set()
        unique_recipients = []
        for r in self.recipients:
            r_lower = r.lower()
            if r_lower not in seen:
                seen.add(r_lower)
                unique_recipients.append(r)
        self.recipients = unique_recipients

        # Filter to valid recipients only
        valid_recipients = []
        for rcpt in self.recipients:
            rcpt_validation = validator.validate_email_address(rcpt)
            if rcpt_validation.valid:
                valid_recipients.append(rcpt)
            else:
                self.log_error(f"Invalid recipient filtered out: {rcpt} - {rcpt_validation.error}")

        if not valid_recipients:
            self.log("All recipients invalid - accepting (silent drop)")
            self._result_label = 'accept'
            return Milter.ACCEPT

        # Build the raw email as bytes (preserves binary attachment data)
        header_bytes = b"\r\n".join(
            f"{name}: {value}".encode('utf-8') for name, value in self.headers
        )
        body_bytes = b"".join(self.body_chunks)
        raw_email_bytes = header_bytes + b"\r\n\r\n" + body_bytes
        size = len(raw_email_bytes)

        # Lossy text version for message_id generation
        body_str = body_bytes.decode('utf-8', errors='replace')

        # Validate size
        size_validation = validator.validate_size(size)
        if not size_validation.valid:
            self.log_error(f"Email too large: {size} bytes")
            self.setreply("552", "5.3.4", "Message size exceeds fixed limit")
            self._result_label = 'reject_permanent'
            self.log(f"Returning REJECT (552) - size {size} exceeds limit")
            return Milter.REJECT

        # Determine path
        if size > STORAGE_UPLOAD_THRESHOLD:
            self._path_label = 'storage_first'

        # Record email size
        record_metrics(lambda: EMAIL_SIZE.labels(path=self._path_label).observe(size))

        # Generate message_id if missing
        if not self.message_id:
            body_start = body_str[:100] if body_str else ''
            recipients_str = ','.join(sorted(valid_recipients))
            hash_input = f"{recipients_str}|{self.sender}|{self.subject}|{body_start}".encode('utf-8')
            hash_hex = hashlib.sha256(hash_input).hexdigest()[:16]
            self.message_id = f"<generated-{hash_hex}@{MESSAGE_ID_DOMAIN}>"
            self.log(f"Generated message_id: {self.message_id}")

        self.log(f"Processing email:")
        self.log(f"  From: {self.sender}")
        self.log(f"  To: {', '.join(valid_recipients)} ({len(valid_recipients)} recipients)")
        self.log(f"  Subject: {self.subject}")
        self.log(f"  Size: {size} bytes")

        # Start APM trace span (no-op if tracing disabled)
        self._trace_span = None
        if TRACING_ENABLED:
            domain = valid_recipients[0].split('@')[1].lower() if valid_recipients else 'unknown'
            self._trace_span = tracer.trace(
                "milter.process_email",
                service="milter",
                resource=f"email:{domain}",
            )
            self._trace_span.set_tag("email.sender", self.sender or "")
            self._trace_span.set_tag("email.recipients", ", ".join(valid_recipients))
            self._trace_span.set_tag("email.recipient_count", len(valid_recipients))
            self._trace_span.set_tag("email.size_bytes", size)
            self._trace_span.set_tag("email.subject", self.subject or "")
            self._trace_span.set_tag("email.message_id", self.message_id or "")

        # --- DKIM + DMARC checks (need full message) ---
        if SPOOF_PROTECTION != 'off':
            dkim_result, dkim_domains = self._check_dkim(raw_email_bytes)
            self.log(f"DKIM check: {dkim_result} (domains: {dkim_domains})")

            from_domain = self._extract_from_domain()
            spf_domain = self.sender.split('@')[1].lower() if self.sender and '@' in self.sender else ''
            dmarc_result = self._check_dmarc(
                from_domain, self.spf_result, spf_domain,
                dkim_result, dkim_domains
            )
            self.log(f"DMARC check: policy={dmarc_result['policy']}, pass={dmarc_result['pass']}")

            # Strip any attacker-injected auth headers before adding ours
            # Remove up to 5 instances of each (attacker could inject multiple)
            for hdr in ("X-PrimitiveMail-SPF", "X-PrimitiveMail-DKIM",
                        "X-PrimitiveMail-DMARC", "X-PrimitiveMail-Auth-Warning"):
                for idx in range(5, 0, -1):
                    self.chgheader(hdr, idx, "")

            # Add real auth result headers
            self.addheader("X-PrimitiveMail-SPF", self.spf_result)
            self.addheader("X-PrimitiveMail-DKIM", dkim_result)
            self.addheader("X-PrimitiveMail-DMARC",
                           f"{dmarc_result['policy']}; pass={'true' if dmarc_result['pass'] else 'false'}")

            # Enforcement
            if SPOOF_PROTECTION == 'standard':
                if dmarc_result['policy'] == 'reject' and not dmarc_result['pass']:
                    self.setreply("550", "5.7.1", f"Failed DMARC policy for {from_domain}")
                    self._result_label = 'reject_permanent'
                    self._finish_trace("reject_permanent", f"dmarc_reject:{from_domain}")
                    self.log(f"Returning REJECT (550) - DMARC reject policy for {from_domain}")
                    self.log("=" * 50)
                    return Milter.REJECT
                if dmarc_result['policy'] == 'quarantine' and not dmarc_result['pass']:
                    self.addheader("X-PrimitiveMail-Auth-Warning",
                                   f"DMARC quarantine policy for {from_domain}")

            elif SPOOF_PROTECTION == 'strict':
                # SPF already checked in envfrom(), DKIM is new here
                if dkim_result == 'fail':
                    self.setreply("550", "5.7.20", "DKIM validation failed")
                    self._result_label = 'reject_permanent'
                    self._finish_trace("reject_permanent", "dkim_failed")
                    self.log("Returning REJECT (550) - DKIM validation failed")
                    self.log("=" * 50)
                    return Milter.REJECT
                if not dmarc_result['pass']:
                    self.setreply("550", "5.7.1", "DMARC validation failed")
                    self._result_label = 'reject_permanent'
                    self._finish_trace("reject_permanent", "dmarc_failed")
                    self.log("Returning REJECT (550) - DMARC validation failed")
                    self.log("=" * 50)
                    return Milter.REJECT

        # Standalone mode: save to disk and accept
        if STANDALONE_MODE:
            try:
                # Pass auth data if spoof protection ran (local vars from above)
                save_kwargs = {}
                if SPOOF_PROTECTION != 'off':
                    save_kwargs = {
                        'dkim_result': dkim_result,
                        'dkim_domains': dkim_domains,
                        'dmarc_result': dmarc_result,
                        'from_domain': from_domain,
                    }
                self._save_to_disk(raw_email_bytes, valid_recipients, **save_kwargs)
                self._result_label = 'accept'
                self._finish_trace("accepted")
                self.log("Standalone mode - email saved to disk")
                self.log("Returning ACCEPT (250)")
                self.log("=" * 50)
                return Milter.ACCEPT
            except Exception as e:
                self.log_error(f"Failed to save email to disk: {e}")
                self._result_label = 'tempfail'
                self._finish_trace("tempfail", f"disk write failed: {e}")
                self.setreply("451", "4.7.1", "Temporary failure saving email, please retry")
                self.log("Returning TEMPFAIL (451) - disk write failed")
                self.log("=" * 50)
                return Milter.TEMPFAIL

        # Webhook mode: upload large emails to storage ONCE (same bytes for all recipients)
        storage_result = None
        if size > STORAGE_UPLOAD_THRESHOLD and STORAGE_URL:
            storage_result = self.upload_to_storage(raw_email_bytes)
            if not storage_result['success']:
                self.log_error(f"Storage upload failed: {storage_result.get('error', 'unknown')}")
                self._finish_trace("tempfail", f"storage upload failed: {storage_result.get('error')}")
                self.setreply("451", "4.7.1", "Temporary failure, please retry")
                return Milter.TEMPFAIL
            self.log(f"Uploaded to storage: {storage_result['storage_key']} ({size} bytes)")

        # Call webhook once per recipient
        any_accepted = False
        any_tempfail = False
        hard_rejects = 0   # protocol_violation, domain_not_found, spamhaus_drop_listed
        soft_rejects = 0   # other reject_permanent reasons
        last_hard_reject_result = None  # preserve details for single-recipient reject codes

        if len(valid_recipients) > 5:
            self.log(f"Warning: {len(valid_recipients)} recipients - webhook calls will be sequential")

        use_inline = size > STORAGE_UPLOAD_THRESHOLD and not STORAGE_URL
        if use_inline:
            self.log(f"Large email ({size} bytes) but no STORAGE_URL - sending inline")

        for rcpt in valid_recipients:
            domain = rcpt.split('@')[1].lower()
            self.log(f"  Webhook for: {rcpt} (domain: {domain})")

            if size > STORAGE_UPLOAD_THRESHOLD and not use_inline:
                result = self._call_webhook_for_recipient(
                    rcpt, domain, None, size, storage_result)
            else:
                result = self._call_webhook_for_recipient(
                    rcpt, domain, raw_email_bytes, size, None)

            if not result['success']:
                any_tempfail = True
                self.log(f"    TEMPFAIL for {rcpt}: {result.get('error', 'unknown')}")
            elif result.get('status') == 'accepted':
                any_accepted = True
                self.log(f"    Result: accepted")
            elif result.get('status') == 'reject_permanent':
                reason = result.get('reason', '')
                detail = result.get('detail', '')
                self.log(f"    Result: reject_permanent (reason: {reason}, detail: {detail})")
                if reason in ('protocol_violation', 'domain_not_found', 'spamhaus_drop_listed'):
                    hard_rejects += 1
                    last_hard_reject_result = result
                else:
                    soft_rejects += 1
            else:
                any_tempfail = True  # unknown status = tempfail
                self.log(
                    f"    Result: unknown status '{result.get('status')}' - treating as TEMPFAIL "
                    f"(full response: {json.dumps(result)[:300]})"
                )

        # Decide SMTP response.
        # Milter can only return one verdict for the entire message.
        # TEMPFAIL > ACCEPT > REJECT to avoid losing mail.
        if any_tempfail:
            # At least one recipient had a transient failure. TEMPFAIL the
            # whole message so the sender retries. Already-accepted recipients
            # will be de-duplicated by the webhook receiver on (message_id, recipient).
            self._result_label = 'tempfail'
            self._finish_trace("tempfail", "webhook transient failure")
            self.setreply("451", "4.7.1", "Temporary failure, please retry")
            eom_elapsed = (time.time() - self._eom_start) * 1000 if hasattr(self, '_eom_start') else 0
            self.log(
                f"TEMPFAIL sender={self.sender} message_id={self.message_id} "
                f"recipients={len(valid_recipients)} accepted={1 if any_accepted else 0} "
                f"hard_rejects={hard_rejects} soft_rejects={soft_rejects} "
                f"eom_ms={eom_elapsed:.0f}"
            )
            self.log("=" * 50)
            return Milter.TEMPFAIL
        elif any_accepted:
            # At least one recipient was accepted. ACCEPT the message even if
            # some were permanently rejected (can't REJECT or sender thinks
            # nobody got it).
            self._result_label = 'accept'
            self._finish_trace("accepted")
            self.log("Returning ACCEPT (250)")
            self.log("=" * 50)
            return Milter.ACCEPT
        elif hard_rejects > 0 and soft_rejects == 0:
            # All recipients were hard-rejected. Use specific error codes
            # when there's only one recipient (most common case) for better
            # diagnostics. For multi-recipient, use generic.
            self._result_label = 'reject_permanent'
            self._finish_trace("reject_permanent", last_hard_reject_result.get('reason', '') if last_hard_reject_result else 'all_rejected')
            if len(valid_recipients) == 1 and last_hard_reject_result:
                reason = last_hard_reject_result.get('reason', '')
                detail = last_hard_reject_result.get('detail', '')
                if reason == 'protocol_violation':
                    if detail == 'reserved_tld':
                        self.setreply("554", "5.5.2", "From domain uses reserved TLD")
                    elif detail == 'malformed_domain':
                        self.setreply("554", "5.5.2", "Malformed From domain")
                    elif detail == 'ip_address_domain':
                        self.setreply("554", "5.5.2", "Raw IP address in From domain not allowed")
                    elif detail == 'missing_tld':
                        self.setreply("554", "5.5.2", "From domain has no valid TLD")
                    elif detail == 'domain_too_long':
                        self.setreply("554", "5.5.2", "From domain exceeds maximum length")
                    else:
                        self.setreply("554", "5.5.2", "Protocol violation")
                    self.log(f"Returning REJECT (554) - {detail}")
                elif reason == 'domain_not_found':
                    self.setreply("550", "5.1.2", "Domain not found")
                    self.log("Returning REJECT (550) - domain not found")
                elif reason == 'spamhaus_drop_listed':
                    self.setreply("554", "5.7.1", "Rejected - client IP listed in Spamhaus DROP")
                    self.log("Returning REJECT (554) - Spamhaus DROP")
                else:
                    self.setreply("550", "5.1.1", "Recipient rejected")
                    self.log(f"Returning REJECT (550) - {reason}")
            else:
                self.setreply("550", "5.1.1", "No valid recipients")
                self.log("Returning REJECT (550) - all recipients permanently rejected")
            self.log("=" * 50)
            return Milter.REJECT
        else:
            # All soft rejects or mix -- accept (silent drop, logged by webhook)
            self._result_label = 'accept'
            self._finish_trace("accepted")
            self.log("Returning ACCEPT (250) - all recipients soft-rejected (logged)")
            self.log("=" * 50)
            return Milter.ACCEPT

    def upload_to_storage(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Upload raw email to S3-compatible storage for large emails.

        Supports multiple auth styles via STORAGE_AUTH_STYLE:
        - "supabase": Bearer token + apikey header (Supabase Storage)
        - "s3": Bearer token only (generic S3-compatible)
        """
        upload_id = str(uuid.uuid4())
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        storage_key = f"incoming/{upload_id}.eml"
        url = f"{STORAGE_URL.rstrip('/')}/{storage_key}"

        # Build auth headers based on storage backend
        headers = {
            'Content-Type': 'message/rfc822',
        }
        if STORAGE_AUTH_STYLE == 'supabase':
            headers['Authorization'] = f'Bearer {STORAGE_KEY}'
            headers['apikey'] = STORAGE_KEY
        else:
            headers['Authorization'] = f'Bearer {STORAGE_KEY}'

        storage_span = None
        if TRACING_ENABLED:
            storage_span = tracer.trace(
                "milter.storage_upload",
                service="milter",
                resource="storage",
            )
            storage_span.set_tag("storage.upload_id", upload_id)
            storage_span.set_tag("storage.size_bytes", len(raw_bytes))
            storage_span.set_tag("storage.sha256", sha256)

        start = time.time()
        try:
            req = urllib.request.Request(
                url,
                data=raw_bytes,
                headers=headers,
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=15) as response:
                duration = time.time() - start
                if response.status in (200, 201):
                    record_metrics(lambda: (
                        STORAGE_UPLOAD_DURATION.labels(status='success').observe(duration),
                        STORAGE_UPLOADS_TOTAL.labels(status='success').inc(),
                    ))
                    if storage_span:
                        storage_span.set_tag('storage.status', 'success')
                    return {
                        'success': True,
                        'upload_id': upload_id,
                        'storage_key': storage_key,
                        'sha256': sha256,
                    }
                else:
                    record_metrics(lambda: (
                        STORAGE_UPLOAD_DURATION.labels(status='error').observe(duration),
                        STORAGE_UPLOADS_TOTAL.labels(status='error').inc(),
                        ERRORS_TOTAL.labels(stage='storage_upload').inc(),
                    ))
                    if storage_span:
                        storage_span.set_tag('error', True)
                        storage_span.set_tag('http.status_code', response.status)
                    return {'success': False, 'error': f'HTTP {response.status}'}

        except Exception as e:
            duration = time.time() - start
            record_metrics(lambda: (
                STORAGE_UPLOAD_DURATION.labels(status='error').observe(duration),
                STORAGE_UPLOADS_TOTAL.labels(status='error').inc(),
                ERRORS_TOTAL.labels(stage='storage_upload').inc(),
            ))
            if storage_span:
                storage_span.set_tag('error', True)
                storage_span.set_tag('error.message', str(e))
            return {'success': False, 'error': str(e)}

        finally:
            if storage_span:
                storage_span.finish()

    def _call_webhook_for_recipient(self, recipient: str, domain: str,
                                     raw_bytes: Optional[bytes], size: int,
                                     storage_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call the ingestion webhook for a single recipient"""
        self.log(f"Posting to webhook: {WEBHOOK_URL}")

        # Child trace span for webhook call
        webhook_span = None
        if TRACING_ENABLED:
            webhook_span = tracer.trace(
                "milter.webhook_call",
                service="milter",
                resource=WEBHOOK_URL,
            )
            webhook_span.set_tag("email.recipient", recipient)
            webhook_span.set_tag("email.domain", domain)

        payload = {
            'recipient': recipient,
            'sender': self.sender or '',
            'subject': self.subject or '',
            'message_id': self.message_id,
            'domain': domain,
            'size': size,
            # Include connection info
            'remote_ip': self.client_ip,
            'helo': getattr(self, 'helo', None),
            # From header (may include display name)
            'from_header': self.from_header,
        }

        if storage_result:
            # Large email: send metadata only (email is already in storage)
            payload['storage_key'] = storage_result['storage_key']
            payload['raw_sha256'] = storage_result['sha256']
            payload['raw_size_bytes'] = size
            timeout = 10
        else:
            # Small email: inline base64 (current flow)
            payload['eml_base64'] = base64.b64encode(raw_bytes).decode('ascii')
            timeout = 25

        start_time = time.time()

        # Delivery-level id. Stable across Postfix retries of the same
        # (message_id, recipient, queue_id). Distinct across recipients and
        # across independently-resubmitted messages (new queue id).
        queue_id = ''
        try:
            queue_id = self.getsymval("i") or ''
        except Exception:
            pass
        delivery_id = str(uuid.uuid5(
            WEBHOOK_ID_NAMESPACE,
            f"{self.message_id}:{recipient}:{queue_id}",
        ))

        raw_body = json.dumps(payload).encode('utf-8')
        timestamp = int(time.time())

        sw = sign_standard_webhooks_payload(
            raw_body=raw_body,
            secret=WEBHOOK_SECRET,
            msg_id=delivery_id,
            timestamp=timestamp,
        )
        legacy = sign_webhook_payload(
            raw_body=raw_body,
            secret=WEBHOOK_SECRET,
            timestamp=timestamp,
        )

        try:
            webhook_headers = {
                'Content-Type': 'application/json',
                STANDARD_WEBHOOK_ID_HEADER: sw['msg_id'],
                STANDARD_WEBHOOK_TIMESTAMP_HEADER: str(sw['timestamp']),
                STANDARD_WEBHOOK_SIGNATURE_HEADER: sw['signature'],
                PRIMITIVE_SIGNATURE_HEADER: legacy['header'],
                # Bearer is deprecated in v0.4; scheduled for removal in v0.5.
                'Authorization': f'Bearer {WEBHOOK_SECRET}',
            }
            # Safe: startup validation rejected any collision with reserved names.
            webhook_headers.update(WEBHOOK_EXTRA_HEADERS)

            if TRACING_ENABLED and webhook_span and HTTPPropagator:
                # Writes x-datadog-* keys. Not reserved, no conflict.
                HTTPPropagator.inject(webhook_span.context, webhook_headers)

            req = urllib.request.Request(
                WEBHOOK_URL,
                data=raw_body,
                headers=webhook_headers,
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                latency_ms = (time.time() - start_time) * 1000
                response_body = response.read().decode('utf-8')
                webhook_path = 'storage_first' if storage_result else 'inline'

                result = _interpret_webhook_response(response.status, response_body)
                self.log(
                    f"Webhook responded: {result.get('status', 'N/A')} "
                    f"(latency: {latency_ms:.0f}ms)"
                )
                record_metrics(lambda: (
                    WEBHOOK_DURATION.labels(status='success', path=webhook_path).observe(latency_ms / 1000),
                    WEBHOOK_CALLS_TOTAL.labels(status='success', path=webhook_path).inc(),
                ))
                return result

        except urllib.error.HTTPError as e:
            latency_ms = (time.time() - start_time) * 1000
            webhook_path = 'storage_first' if storage_result else 'inline'
            error_body = ''
            try:
                error_body = e.read().decode('utf-8') if e.fp else ''
            except Exception:
                error_body = '<unreadable>'

            result = _interpret_webhook_response(e.code, error_body)

            # Log based on the interpreted result, not the HTTP status
            if result.get('success') and result.get('status') == 'accepted':
                self.log(
                    f"Webhook responded: accepted "
                    f"(HTTP {e.code}, latency: {latency_ms:.0f}ms)"
                )
            elif result.get('success'):
                logger.warning(
                    f"[{self.id}] Webhook responded: {result.get('status')} "
                    f"(HTTP {e.code}, latency: {latency_ms:.0f}ms)"
                )
            else:
                self.log_error(
                    f"WEBHOOK_HTTP_ERROR recipient={recipient} "
                    f"http_status={e.code} latency_ms={latency_ms:.0f} "
                    f"body={error_body[:500]}"
                )

            metrics_status = 'success' if result.get('success') else 'error'
            record_metrics(lambda: (
                WEBHOOK_DURATION.labels(status=metrics_status, path=webhook_path).observe(latency_ms / 1000),
                WEBHOOK_CALLS_TOTAL.labels(status=metrics_status, path=webhook_path).inc(),
            ))
            if not result.get('success'):
                record_metrics(lambda: ERRORS_TOTAL.labels(stage='webhook').inc())
            return result

        except urllib.error.URLError as e:
            latency_ms = (time.time() - start_time) * 1000
            webhook_path = 'storage_first' if storage_result else 'inline'
            reason = str(e.reason)
            # Classify the network error for easier searching
            if 'timed out' in reason.lower() or 'timeout' in reason.lower():
                error_type = 'timeout'
            elif 'refused' in reason.lower():
                error_type = 'connection_refused'
            elif 'reset' in reason.lower():
                error_type = 'connection_reset'
            else:
                error_type = 'network_error'
            self.log_error(
                f"WEBHOOK_NETWORK_ERROR recipient={recipient} "
                f"error_type={error_type} reason={reason} "
                f"latency_ms={latency_ms:.0f} timeout_config={timeout}s"
            )
            record_metrics(lambda: (
                WEBHOOK_DURATION.labels(status='error', path=webhook_path).observe(latency_ms / 1000),
                WEBHOOK_CALLS_TOTAL.labels(status='error', path=webhook_path).inc(),
                ERRORS_TOTAL.labels(stage='webhook').inc(),
            ))
            if webhook_span:
                webhook_span.set_tag('error', True)
            return {'success': False, 'error': f'{error_type}: {reason}'}

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            webhook_path = 'storage_first' if storage_result else 'inline'
            self.log_error(
                f"WEBHOOK_UNEXPECTED_ERROR recipient={recipient} "
                f"exception={type(e).__name__} message={e} "
                f"latency_ms={latency_ms:.0f}"
            )
            record_metrics(lambda: (
                WEBHOOK_DURATION.labels(status='error', path=webhook_path).observe(latency_ms / 1000),
                WEBHOOK_CALLS_TOTAL.labels(status='error', path=webhook_path).inc(),
                ERRORS_TOTAL.labels(stage='webhook').inc(),
            ))
            if webhook_span:
                webhook_span.set_tag('error', True)
            return {'success': False, 'error': f'{type(e).__name__}: {e}'}

        finally:
            if webhook_span:
                webhook_span.finish()

    def close(self):
        """Connection closed"""
        self.log("Connection closed")
        return Milter.CONTINUE

    def abort(self):
        """Transaction aborted"""
        self.log("Transaction aborted")
        self.reset()
        return Milter.CONTINUE


def main():
    """Start the milter"""
    global METRICS_ENABLED

    # Socket configuration
    # Use TCP socket for easier Docker networking
    socket_spec = "inet:9900@0.0.0.0"

    # Start Prometheus metrics endpoint
    if METRICS_ENABLED:
        try:
            start_http_server(9901)
            logger.info("Prometheus metrics on :9901/metrics")
        except OSError as e:
            METRICS_ENABLED = False
            logger.warning(f"Failed to start metrics server: {e} - metrics disabled")

    logger.info("=" * 60)
    logger.info("PrimitiveMail Milter starting")
    logger.info(f"  Mode: {'standalone' if STANDALONE_MODE else 'webhook'}")
    logger.info(f"  Socket: {socket_spec}")
    if STANDALONE_MODE:
        logger.info(f"  Mail dir: {MAIL_DIR}")
    else:
        logger.info(f"  Webhook: {WEBHOOK_URL}")
        logger.info(f"  Storage: {STORAGE_URL or 'not configured (inline only)'}")
    if SENDER_FILTERING_ENABLED:
        logger.info(f"  Sender filter: {len(ALLOWED_SENDER_DOMAINS)} domains, {len(ALLOWED_SENDERS)} addresses")
    if RECIPIENT_FILTERING_ENABLED:
        logger.info(f"  Recipient filter: {len(ALLOWED_RECIPIENTS)} addresses")
    logger.info(f"  Spoof protection: {SPOOF_PROTECTION}")
    logger.info(f"  Spamhaus DNSBL: {SPAMHAUS_DNSBL_DOMAIN or 'disabled'}")
    logger.info(f"  Metrics: {'enabled' if METRICS_ENABLED else 'disabled'}")
    logger.info("=" * 60)

    # Set timeout (must be longer than webhook timeout)
    Milter.set_flags(Milter.CHGHDRS + Milter.ADDHDRS)

    Milter.factory = PrimitiveMailMilter

    try:
        Milter.runmilter("primitivemail", socket_spec, timeout=60)
    except Exception as e:
        logger.error(f"Milter failed: {e}")
        sys.exit(1)

    logger.info("Milter stopped")


if __name__ == "__main__":
    main()
