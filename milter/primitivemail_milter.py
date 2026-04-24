#!/usr/bin/env python3
"""
SMTP Milter for PrimitiveMail
Intercepts emails DURING the SMTP transaction (before 250 OK).

Two modes:
- Webhook mode: Calls a configured webhook URL and returns ACCEPT/REJECT based on response.
- Standalone mode: Accepts all valid emails (when no webhook_url is configured).

Security features (all configurable via config file or environment variables):
- Sender filtering: allowed_sender_domains / allowed_senders
- Recipient filtering: allowed_recipients
- Spoof protection: SPF / DKIM / DMARC verification
"""

import os
import sys
import re
import json
import base64
import logging
import signal
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
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

_s3_client = None

def _get_s3_client(region):
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client('s3', region_name=region)
    return _s3_client

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

# ---------------------------------------------------------------------------
# Configuration: config file (optional) with environment variable fallback
#
# If a JSON config file exists at CONFIG_FILE_PATH (default:
# /etc/primitive/milter.json), values are loaded from it. Any value not
# present in the file falls back to the corresponding environment variable.
# If no config file exists, all values come from environment variables —
# this is the original behaviour and remains fully supported.
#
# A subset of values can be reloaded at runtime by sending SIGHUP to the
# process. See the ReloadableConfig class for which values support hot
# reload, and _apply_config() for the reload logic.
# ---------------------------------------------------------------------------

CONFIG_FILE_PATH = os.environ.get('CONFIG_FILE', '/etc/primitive/milter.json')


class ReloadableConfig:
    """Holds all config values that can be hot-reloaded via SIGHUP.

    Bundled into a single object so that swapping the module-level reference
    (_rcfg) is one atomic pointer assignment under the GIL.  Handler threads
    snapshot this reference once per message (self._cfg = _rcfg) and use it
    for the duration of the request, guaranteeing they never see a
    partially-applied config.

    Non-reloadable values (mydomain, mail_dir, standalone_mode, etc.) are
    set once at startup as plain module-level globals and are NOT included
    here — they are safe because they never change.
    """

    def __init__(self, *, webhook_url=None, webhook_secret=None,
                 webhook_extra_headers=None, storage_url=None,
                 storage_key=None, storage_auth_style='s3',
                 allowed_sender_domains=None, allowed_senders=None,
                 allow_bounces=True, allowed_recipients=None,
                 spoof_protection='off'):
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        self.webhook_extra_headers = webhook_extra_headers or {}
        self.storage_url = storage_url
        self.storage_key = storage_key
        self.storage_auth_style = storage_auth_style
        self.allowed_sender_domains = allowed_sender_domains or set()
        self.allowed_senders = allowed_senders or set()
        self.allow_bounces = allow_bounces
        self.allowed_recipients = allowed_recipients or set()
        self.spoof_protection = spoof_protection

    @property
    def sender_filtering_enabled(self):
        return bool(self.allowed_sender_domains or self.allowed_senders)

    @property
    def recipient_filtering_enabled(self):
        return bool(self.allowed_recipients)


# The live config object.  Handler threads snapshot this at the start of
# each message (self._cfg = _rcfg) to get a consistent view.  The reload
# path builds a new ReloadableConfig and swaps this reference atomically.
_rcfg = ReloadableConfig()


def _read_config_file(path: str) -> dict:
    """Read a JSON config file.  Returns {} if the file does not exist or
    is not valid JSON (with a warning)."""
    try:
        with open(path) as f:
            data = json.load(f)
            if not isinstance(data, dict):
                logger.warning(f"Config file {path} is not a JSON object, ignoring")
                return {}
            return data
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, ValueError, OSError) as e:
        logger.warning(f"Failed to read config file {path}: {e}")
        return {}


def _cfg(file_data: dict, key: str, env_var: str, default=None):
    """Resolve a config value: config file wins, then env var, then default."""
    if key in file_data:
        return file_data[key]
    return os.environ.get(env_var, default)


def _parse_comma_set(value) -> set:
    """Parse a comma-separated string (or list) into a lowercase set."""
    if isinstance(value, list):
        return {v.strip().lower() for v in value if v.strip()}
    if isinstance(value, str) and value.strip():
        return {v.strip().lower() for v in value.split(',') if v.strip()}
    return set()


def _parse_extra_headers(value) -> dict:
    """Parse webhook extra headers from a dict or JSON string."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
            logger.error("WEBHOOK_EXTRA_HEADERS must be a JSON object, ignoring")
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Invalid WEBHOOK_EXTRA_HEADERS JSON: {e}")
    return {}


def _validate_spoof_protection(value: str) -> str:
    """Validate and return a spoof protection level, with dependency checks."""
    value = value.lower() if value else 'off'
    if value not in ('off', 'monitor', 'standard', 'strict'):
        logger.warning(f"Invalid SPOOF_PROTECTION value '{value}' - defaulting to 'off'")
        return 'off'
    if value != 'off':
        missing = []
        if not SPF_AVAILABLE:
            missing.append('pyspf')
        if not DKIM_AVAILABLE:
            missing.append('dkimpy')
        if not DNS_AVAILABLE:
            missing.append('dnspython')
        if missing:
            logger.warning(f"SPOOF_PROTECTION={value} but missing packages: {', '.join(missing)} - falling back to 'off'")
            return 'off'
        if value in ('standard', 'strict'):
            logger.info("Note: DKIM verification uses reconstructed headers. "
                        "Consider 'monitor' mode first to verify accuracy.")
    return value


def _build_reloadable_config(file_data: dict) -> ReloadableConfig:
    """Build a ReloadableConfig from file data + env var fallbacks."""
    extra = _parse_extra_headers(
        _cfg(file_data, 'webhook_extra_headers', 'WEBHOOK_EXTRA_HEADERS', ''))
    if extra:
        logger.info(f"Webhook extra headers configured: {list(extra.keys())}")

    return ReloadableConfig(
        webhook_url=_cfg(file_data, 'webhook_url', 'WEBHOOK_URL'),
        webhook_secret=_cfg(file_data, 'webhook_secret', 'WEBHOOK_SECRET'),
        webhook_extra_headers=extra,
        storage_url=_cfg(file_data, 'storage_url', 'STORAGE_URL'),
        storage_key=_cfg(file_data, 'storage_key', 'STORAGE_KEY'),
        storage_auth_style=_cfg(file_data, 'storage_auth_style', 'STORAGE_AUTH_STYLE', 's3'),
        allowed_sender_domains=_parse_comma_set(
            _cfg(file_data, 'allowed_sender_domains', 'ALLOWED_SENDER_DOMAINS', '')),
        allowed_senders=_parse_comma_set(
            _cfg(file_data, 'allowed_senders', 'ALLOWED_SENDERS', '')),
        allow_bounces=str(_cfg(file_data, 'allow_bounces', 'ALLOW_BOUNCES', 'true')).lower() == 'true',
        allowed_recipients=_parse_comma_set(
            _cfg(file_data, 'allowed_recipients', 'ALLOWED_RECIPIENTS', '')),
        spoof_protection=_validate_spoof_protection(
            _cfg(file_data, 'spoof_protection', 'SPOOF_PROTECTION', 'off')),
    )


def _apply_config(file_data: dict, reloadable_only: bool = False):
    """Apply configuration from file data + env var fallbacks.

    Reloadable values are bundled into a ReloadableConfig object and swapped
    atomically (single reference assignment, GIL-atomic).  Handler threads
    snapshot the reference at the start of each message so they always see a
    consistent config.

    When reloadable_only=True (SIGHUP), only the ReloadableConfig is swapped.
    When reloadable_only=False (startup), non-reloadable module globals are
    also set.
    """
    global _rcfg
    global MESSAGE_ID_DOMAIN, STANDALONE_MODE, MAIL_DIR
    global SPAMHAUS_DNSBL_DOMAIN
    global STORAGE_UPLOAD_THRESHOLD

    new_cfg = _build_reloadable_config(file_data)

    if reloadable_only:
        # Guard: don't allow reload to flip between standalone and webhook mode.
        was_webhook = not STANDALONE_MODE
        would_be_webhook = bool(new_cfg.webhook_url)
        if was_webhook != would_be_webhook:
            logger.error(f"Config reload rejected: cannot switch modes via SIGHUP "
                         f"(current: {'webhook' if was_webhook else 'standalone'}, "
                         f"new config would be: {'webhook' if would_be_webhook else 'standalone'}). "
                         f"Restart the milter to change modes.")
            return

        # Guard: webhook mode requires a secret
        if would_be_webhook and not new_cfg.webhook_secret:
            logger.error("Config reload rejected: webhook_url is set but webhook_secret is missing")
            return

    # Atomic swap — one pointer assignment, GIL-atomic.  Handler threads
    # that already hold a reference to the old _rcfg continue using it
    # for the current message; new messages will pick up this new object.
    _rcfg = new_cfg

    if reloadable_only:
        return

    # --- Non-reloadable values (startup only) ---
    MESSAGE_ID_DOMAIN = _cfg(file_data, 'mydomain', 'MYDOMAIN', 'primitivemail')
    MAIL_DIR = _cfg(file_data, 'mail_dir', 'MAIL_DIR', '/mail/incoming')
    STORAGE_UPLOAD_THRESHOLD = int(_cfg(file_data, 'storage_upload_threshold',
                                        'STORAGE_UPLOAD_THRESHOLD', '3000000'))

    STANDALONE_MODE = not _rcfg.webhook_url

    # Spamhaus DNSBL
    SPAMHAUS_DNSBL_DOMAIN = str(_cfg(file_data, 'spamhaus_dnsbl_domain',
                                      'SPAMHAUS_DNSBL_DOMAIN', '')).strip().lower().rstrip('.')
    if SPAMHAUS_DNSBL_DOMAIN and not DNS_AVAILABLE:
        logger.warning("SPAMHAUS_DNSBL_DOMAIN is set but dnspython is unavailable - DNSBL disabled")
        SPAMHAUS_DNSBL_DOMAIN = ''


def _log_config_summary():
    """Log the current configuration state."""
    cfg = _rcfg
    if STANDALONE_MODE:
        logger.info("No WEBHOOK_URL configured - running in standalone mode (accept all valid emails)")
    else:
        if not cfg.webhook_secret:
            logger.error("WEBHOOK_SECRET must be set when WEBHOOK_URL is configured")
            sys.exit(1)
    if not STANDALONE_MODE and not cfg.storage_url:
        logger.info("STORAGE_URL not set - large emails (>3MB) will be sent inline via webhook")
    if cfg.sender_filtering_enabled:
        logger.info(f"Sender filtering enabled: {len(cfg.allowed_sender_domains)} domains, {len(cfg.allowed_senders)} addresses")
    if cfg.recipient_filtering_enabled:
        logger.info(f"Recipient filtering enabled: {len(cfg.allowed_recipients)} addresses")
    if cfg.spoof_protection != 'off':
        logger.info(f"Spoof protection: {cfg.spoof_protection}")
    if SPAMHAUS_DNSBL_DOMAIN:
        logger.info(f"Spamhaus DNSBL enabled: {SPAMHAUS_DNSBL_DOMAIN} (enforcing {SPAMHAUS_DROP_CODE})")


def reload_config(signum=None, frame=None):
    """Reload hot-reloadable config values from the config file.

    Called on SIGHUP. Re-reads the config file and builds a new
    ReloadableConfig, then swaps it atomically.  Non-reloadable values
    (mydomain, mail_dir, etc.) are left unchanged.

    If the config file was present at startup but is now missing or
    unreadable, the reload is aborted to prevent accidentally clearing
    file-only settings.
    """
    logger.info("SIGHUP received - reloading configuration")
    file_data = _read_config_file(CONFIG_FILE_PATH)
    if not file_data and _initial_file_data:
        logger.warning("Config file is missing or unreadable; "
                       "aborting reload to preserve current state")
        return
    _apply_config(file_data, reloadable_only=True)
    cfg = _rcfg
    logger.info(f"Config reloaded (webhook_url={cfg.webhook_url}, "
                f"sender_filter={cfg.sender_filtering_enabled}, "
                f"recipient_filter={cfg.recipient_filtering_enabled}, "
                f"spoof_protection={cfg.spoof_protection})")


# --- Initial config load ---
_initial_file_data = _read_config_file(CONFIG_FILE_PATH)
if _initial_file_data:
    logger.info(f"Config file loaded: {CONFIG_FILE_PATH}")
_apply_config(_initial_file_data, reloadable_only=False)
_log_config_summary()


# DNS resolver timeout for SPF/DKIM/DMARC lookups
DNS_TIMEOUT = 3

SPAMHAUS_DROP_CODE = '127.0.0.9'

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
        # Snapshot the reloadable config for this message.  All handler
        # methods use self._cfg so they see a consistent config even if a
        # SIGHUP-triggered reload swaps _rcfg mid-message.
        self._cfg = _rcfg
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
        cfg = self._cfg
        if cfg.sender_filtering_enabled:
            if not self.sender:
                # Bounce message (empty MAIL FROM)
                if not cfg.allow_bounces:
                    self.log("Bounce rejected (ALLOW_BOUNCES=false)")
                    self.setreply("550", "5.7.1", "Bounces not accepted")
                    return Milter.REJECT
            else:
                sender_lower = self.sender.lower()
                sender_domain = sender_lower.split('@')[1] if '@' in sender_lower else ''
                if sender_lower not in cfg.allowed_senders and sender_domain not in cfg.allowed_sender_domains:
                    self.log(f"Sender not authorized: {self.sender}")
                    self.setreply("550", "5.7.0", "Message rejected")
                    return Milter.REJECT

        # --- SPF check (earliest possible -- we have client_ip, sender, helo) ---
        if cfg.spoof_protection != 'off' and self.sender and SPF_AVAILABLE:
            try:
                result, explanation = spfmod.check2(
                    i=self.client_ip,
                    s=self.sender,
                    h=getattr(self, 'helo', ''),
                    timeout=DNS_TIMEOUT
                )
                self.spf_result = result
                self.log(f"SPF check: {result} ({explanation})")

                if cfg.spoof_protection == 'strict' and result in ('fail', 'softfail'):
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
            if self._cfg.recipient_filtering_enabled and rcpt.lower() not in self._cfg.allowed_recipients:
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

        # Start APM trace span early so every exit path can emit one
        # (no-op if tracing disabled). Resource and tags that depend on
        # later processing (filtered recipients, byte size) are refined
        # once known.
        self._trace_span = None
        if TRACING_ENABLED:
            self._trace_span = tracer.trace(
                "milter.process_email",
                service="milter",
                resource="email:unknown",
            )
            self._trace_span.set_tag("email.sender", self.sender or "")
            self._trace_span.set_tag("email.subject", self.subject or "")
            self._trace_span.set_tag("email.message_id", self.message_id or "")

        # Validate recipients
        if not self.recipients:
            self.log_error("No recipients - rejecting")
            self.setreply("550", "5.1.1", "No recipient")
            self._result_label = 'reject_permanent'
            self._finish_trace("reject_permanent", "no_recipients")
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
            self._finish_trace("accepted")
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
            self._finish_trace("reject_permanent", "size_exceeds_limit")
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

        # Refine APM trace span now that recipients and size are known.
        # Span was opened at the top of _process_eom; here we set the tags
        # that depend on values computed downstream.
        if self._trace_span is not None:
            domain = valid_recipients[0].split('@')[1].lower()
            self._trace_span.resource = f"email:{domain}"
            self._trace_span.set_metric("email.recipient_count", len(valid_recipients))
            self._trace_span.set_metric("email.size_bytes", size)
            if self.message_id:
                self._trace_span.set_tag("email.message_id", self.message_id)

        # --- DKIM + DMARC checks (need full message) ---
        cfg = self._cfg
        if cfg.spoof_protection != 'off':
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
            if cfg.spoof_protection == 'standard':
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

            elif cfg.spoof_protection == 'strict':
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
                if cfg.spoof_protection != 'off':
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
        if size > STORAGE_UPLOAD_THRESHOLD and cfg.storage_url:
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

        use_inline = size > STORAGE_UPLOAD_THRESHOLD and not cfg.storage_url
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
        """Upload raw email to storage for large emails.

        Supports multiple auth styles via STORAGE_AUTH_STYLE:
        - "s3": AWS S3 via boto3 (uses IAM task role on ECS, no explicit creds)
        - "supabase": Bearer token + apikey header (Supabase Storage, legacy)
        """
        cfg = self._cfg
        upload_id = str(uuid.uuid4())
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        storage_key = f"incoming/{upload_id}.eml"

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
            storage_span.set_tag("storage.auth_style", cfg.storage_auth_style)

        start = time.time()
        try:
            if cfg.storage_auth_style == 's3':
                return self._upload_to_s3(cfg, raw_bytes, upload_id, storage_key, sha256, start, storage_span)
            else:
                return self._upload_to_http(cfg, raw_bytes, upload_id, storage_key, sha256, start, storage_span)

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

    def _upload_to_s3(self, cfg, raw_bytes: bytes, upload_id: str,
                      storage_key: str, sha256: str, start: float,
                      storage_span) -> Dict[str, Any]:
        """Upload to S3 using boto3 (IAM task role auth on ECS)."""
        if not BOTO3_AVAILABLE:
            duration = time.time() - start
            record_metrics(lambda: (
                STORAGE_UPLOAD_DURATION.labels(status='error').observe(duration),
                STORAGE_UPLOADS_TOTAL.labels(status='error').inc(),
                ERRORS_TOTAL.labels(stage='storage_upload').inc(),
            ))
            return {'success': False, 'error': 'boto3 not installed'}

        # Parse bucket from STORAGE_URL: accept "s3://bucket-name" or just "bucket-name"
        bucket = cfg.storage_url
        if bucket.startswith('s3://'):
            bucket = bucket[5:]
        bucket = bucket.strip('/')

        region = os.environ.get('AWS_DEFAULT_REGION', 'us-west-2')
        s3 = _get_s3_client(region)
        s3.put_object(
            Bucket=bucket,
            Key=storage_key,
            Body=raw_bytes,
            ContentType='message/rfc822',
        )

        duration = time.time() - start
        record_metrics(lambda: (
            STORAGE_UPLOAD_DURATION.labels(status='success').observe(duration),
            STORAGE_UPLOADS_TOTAL.labels(status='success').inc(),
        ))
        if storage_span:
            storage_span.set_tag('storage.status', 'success')
            storage_span.set_tag('storage.bucket', bucket)
        return {
            'success': True,
            'upload_id': upload_id,
            'storage_key': storage_key,
            'sha256': sha256,
        }

    def _upload_to_http(self, cfg, raw_bytes: bytes, upload_id: str,
                        storage_key: str, sha256: str, start: float,
                        storage_span) -> Dict[str, Any]:
        """Upload via HTTP PUT (Supabase Storage or generic S3-compatible)."""
        url = f"{cfg.storage_url.rstrip('/')}/{storage_key}"

        headers = {
            'Content-Type': 'message/rfc822',
        }
        if cfg.storage_auth_style == 'supabase':
            headers['Authorization'] = f'Bearer {cfg.storage_key}'
            headers['apikey'] = cfg.storage_key
        else:
            headers['Authorization'] = f'Bearer {cfg.storage_key}'

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

    def _call_webhook_for_recipient(self, recipient: str, domain: str,
                                     raw_bytes: Optional[bytes], size: int,
                                     storage_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call the ingestion webhook for a single recipient"""
        cfg = self._cfg
        self.log(f"Posting to webhook: {cfg.webhook_url}")

        # Child trace span for webhook call
        webhook_span = None
        if TRACING_ENABLED:
            webhook_span = tracer.trace(
                "milter.webhook_call",
                service="milter",
                resource=cfg.webhook_url,
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

        try:
            webhook_headers = {
                'Authorization': f'Bearer {cfg.webhook_secret}',
                'Content-Type': 'application/json',
                **cfg.webhook_extra_headers,
            }
            if TRACING_ENABLED and webhook_span and HTTPPropagator:
                HTTPPropagator.inject(webhook_span.context, webhook_headers)

            req = urllib.request.Request(
                cfg.webhook_url,
                data=json.dumps(payload).encode('utf-8'),
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

    # Register SIGHUP handler for config reload
    signal.signal(signal.SIGHUP, reload_config)

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
    if _initial_file_data:
        logger.info(f"  Config file: {CONFIG_FILE_PATH}")
    else:
        logger.info(f"  Config: environment variables (no config file)")
    cfg = _rcfg
    if STANDALONE_MODE:
        logger.info(f"  Mail dir: {MAIL_DIR}")
    else:
        logger.info(f"  Webhook: {cfg.webhook_url}")
        logger.info(f"  Storage: {cfg.storage_url or 'not configured (inline only)'}")
    if cfg.sender_filtering_enabled:
        logger.info(f"  Sender filter: {len(cfg.allowed_sender_domains)} domains, {len(cfg.allowed_senders)} addresses")
    if cfg.recipient_filtering_enabled:
        logger.info(f"  Recipient filter: {len(cfg.allowed_recipients)} addresses")
    logger.info(f"  Spoof protection: {cfg.spoof_protection}")
    logger.info(f"  Spamhaus DNSBL: {SPAMHAUS_DNSBL_DOMAIN or 'disabled'}")
    logger.info(f"  Metrics: {'enabled' if METRICS_ENABLED else 'disabled'}")
    logger.info(f"  SIGHUP reload: enabled")
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
