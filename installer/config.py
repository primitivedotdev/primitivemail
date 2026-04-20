"""Configuration logic for PrimitiveMail installer. No prompts."""

import ipaddress
import json
import secrets
import subprocess
import urllib.parse
import urllib.request
from typing import Optional

CLAIM_API_URL = "https://www.primitive.dev/api/v1/claim-subdomain"


def detect_public_ip() -> Optional[str]:
    """Try multiple IP detection services, return IPv4 string or None."""
    for url in ("https://ifconfig.me", "https://api.ipify.org", "https://icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PrimitiveMail-Installer"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                text = resp.read().decode("utf-8").strip()
                try:
                    ipaddress.IPv4Address(text)
                    return text
                except ValueError:
                    continue
        except Exception:
            continue
    return None


def generate_webhook_secret() -> str:
    """Generate a 64-char hex secret."""
    return secrets.token_hex(32)


def validate_spoof_protection(value: str) -> bool:
    return value in ("off", "monitor", "standard", "strict")


def map_spoof_choice(choice: int) -> str:
    return {1: "off", 2: "monitor", 3: "standard", 4: "strict"}.get(choice, "off")


def should_warn_sender_filtering(
    allowed_sender_domains: str,
    allowed_senders: str,
    spoof_protection: str,
) -> bool:
    """True if sender filtering is on but spoof protection is off."""
    has_filtering = bool(allowed_sender_domains.strip() or allowed_senders.strip())
    return has_filtering and spoof_protection == "off"


def generate_env_content(
    hostname: str,
    domain: str,
    enable_ip_literal: bool,
    ip_literal: str,
    webhook_url: str,
    webhook_secret: str,
    event_webhook_url: str,
    event_webhook_secret: str,
    allowed_sender_domains: str,
    allowed_senders: str,
    allowed_recipients: str,
    spoof_protection: str,
) -> str:
    """Generate .env file content. Unquoted values, one key per line."""
    enable = "true" if enable_ip_literal else "false"
    lines = [
        f"MYHOSTNAME={hostname}",
        f"MYDOMAIN={domain}",
        f"ENABLE_IP_LITERAL={enable}",
        f"IP_LITERAL={ip_literal}",
        f"WEBHOOK_URL={webhook_url}",
        f"WEBHOOK_SECRET={webhook_secret}",
        f"EVENT_WEBHOOK_URL={event_webhook_url}",
        f"EVENT_WEBHOOK_SECRET={event_webhook_secret}",
        f"ALLOWED_SENDER_DOMAINS={allowed_sender_domains}",
        f"ALLOWED_SENDERS={allowed_senders}",
        f"ALLOWED_RECIPIENTS={allowed_recipients}",
        "ALLOW_BOUNCES=true",
        f"SPOOF_PROTECTION={spoof_protection}",
    ]
    return "\n".join(lines) + "\n"


def validate_event_webhook_url(url: str) -> bool:
    """Minimal sanity check: http/https scheme and a host present."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    return True


def build_config_summary(
    hostname: str,
    domain: str,
    ip_literal: str,
    has_domain: bool,
    webhook_url: str,
    event_webhook_url: str,
    allowed_sender_domains: str,
    allowed_senders: str,
    allowed_recipients: str,
    spoof_protection: str,
    observability_enabled: bool = False,
) -> list:
    """Build config summary as plain text lines (no ANSI).

    `observability_enabled` drives a disclosure line about the Alloy +
    postfix-exporter containers. Off by default. Phase 1 installs never
    flip this to True on their own (the installer does not write
    COMPOSE_PROFILES); Phase 2's upgrade helper may set it when migrating
    existing PROMETHEUS_URL users. The summary needs both branches so
    the disclosure is truthful either way.
    """
    lines = []

    if ip_literal and not has_domain:
        lines.append(f"Receiving at:      <any-name>@[{ip_literal}]  (IP literal)")
    else:
        lines.append(f"Hostname:          {hostname}")
        lines.append(f"Domain:            {domain}")

    if not webhook_url:
        lines.append("Mode:              Standalone (local storage)")
    else:
        lines.append("Mode:              Webhook")
        lines.append(f"Webhook URL:       {webhook_url}")

    if event_webhook_url:
        lines.append(f"Event webhook:     {event_webhook_url}")

    if allowed_sender_domains or allowed_senders:
        parts = []
        if allowed_sender_domains:
            parts.append(allowed_sender_domains)
        if allowed_senders:
            parts.append(allowed_senders)
        lines.append(f"Allowed senders:   {', '.join(parts)}")
    else:
        lines.append("Allowed senders:   any")

    if allowed_recipients:
        lines.append(f"Allowed recipients: {allowed_recipients}")
    else:
        lines.append("Allowed recipients: any")

    spoof_labels = {
        "off": "Off",
        "monitor": "Monitor (log only)",
        "standard": "Standard (enforce DMARC policy)",
        "strict": "Strict (reject on any failure)",
    }
    lines.append(f"Spoof protection:  {spoof_labels.get(spoof_protection, 'Off')}")
    lines.append("TLS:               Self-signed (auto-generated)")

    if observability_enabled:
        lines.append("Observability:     enabled (Alloy + postfix-exporter)")
    else:
        lines.append("Observability:     disabled (default)")
        lines.append("                   Set COMPOSE_PROFILES=observability in .env")
        lines.append("                   and run `primitive restart` to enable.")

    return lines


def build_dns_instructions(hostname: str, domain: str) -> list:
    """Build DNS setup instructions as plain text lines."""
    return [
        f"Add these DNS records where you manage {domain}:",
        "",
        "MX record",
        f"{domain}    MX    10    {hostname}",
        "",
        "A record (point the hostname to this server's IP)",
        f"{hostname}    A    <your-server-ip>",
        "",
        "Mail won't arrive until these records propagate",
    ]


def build_next_steps(ip_literal: str, has_domain: bool, install_dir: str) -> list:
    """Build next-steps text as plain text lines."""
    lines = []

    if not has_domain and ip_literal:
        lines.append("Send a test email to:")
        lines.append(f"agent@[{ip_literal}]  (any local-part works)")
        lines.append("")

    lines.append("Useful commands:")
    if has_domain:
        # Lead with the end-to-end test. Blind-install users reach for it
        # first to confirm the whole pipeline works.
        lines.append("primitive emails test             # send a real test email end-to-end")
    lines.append("primitive emails list             # list recent emails")
    lines.append("primitive emails read --latest    # read the most recent email")
    lines.append("primitive emails status           # inbox status summary")
    lines.append("docker logs primitivemail -f     # watch logs")
    lines.append("primitive restart                # reload after config changes")
    lines.append(f"cat {install_dir}/.env            # view config")
    lines.append("")
    lines.append("Agent integration:")
    lines.append(f"cat {install_dir}/AGENTS.md        # how to consume email programmatically")
    lines.append("")
    lines.append("If running on a cloud provider (AWS, GCP, Azure, etc.):")
    lines.append("Make sure port 25 (TCP) is open in your security group / firewall rules.")
    lines.append("The install script can only open the OS-level firewall, not cloud firewalls.")

    return lines


def claim_subdomain() -> Optional[dict]:
    """Claim a free subdomain on primitive.email.
    Uses curl -4 to force IPv4 (mx-tools can only check IPv4 port 25).
    Returns {"subdomain": "cool-fox", "domain": "cool-fox.primitive.email", "ip": "..."} or None."""
    try:
        result = subprocess.run(
            ["curl", "-4", "-s", "-X", "POST", CLAIM_API_URL,
             "-H", "Content-Type: application/json",
             "-d", "{}",
             "--max-time", "30"],
            capture_output=True, text=True, timeout=35,
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        if data.get("ok"):
            return data
        return None
    except Exception:
        return None


def resolve_non_interactive_defaults(
    hostname: str, domain: str, ip_literal: str
) -> tuple:
    """Apply defaults for non-interactive mode.
    Returns (hostname, domain, ip_literal, has_domain)."""
    hostname = hostname or "localhost"
    domain = domain or "localhost"
    has_domain = hostname != "localhost"

    if hostname == "localhost" and not ip_literal:
        ip_literal = detect_public_ip() or ""

    return hostname, domain, ip_literal, has_domain
