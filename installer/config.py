"""Configuration logic for PrimitiveMail installer. No prompts."""

import ipaddress
import json
import secrets
import subprocess
import urllib.request
import urllib.error
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


RATE_LIMIT_PRESETS = {
    "normal": {"conn": "10", "msg": "50", "rcpt": "100"},
    "high": {"conn": "100", "msg": "500", "rcpt": "1000"},
    "off": {"conn": "0", "msg": "0", "rcpt": "0"},
}


def validate_rate_limit(value: str) -> bool:
    return value in RATE_LIMIT_PRESETS


def map_rate_limit_choice(choice: int) -> str:
    return {1: "normal", 2: "high", 3: "off"}.get(choice, "normal")


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
    allowed_sender_domains: str,
    allowed_senders: str,
    allowed_recipients: str,
    spoof_protection: str,
    rate_limit: str = "normal",
) -> str:
    """Generate .env file content. Unquoted values."""
    enable = "true" if enable_ip_literal else "false"
    preset = RATE_LIMIT_PRESETS.get(rate_limit, RATE_LIMIT_PRESETS["normal"])
    lines = [
        f"MYHOSTNAME={hostname}",
        f"MYDOMAIN={domain}",
        f"ENABLE_IP_LITERAL={enable}",
        f"IP_LITERAL={ip_literal}",
        f"WEBHOOK_URL={webhook_url}",
        f"WEBHOOK_SECRET={webhook_secret}",
        f"ALLOWED_SENDER_DOMAINS={allowed_sender_domains}",
        f"ALLOWED_SENDERS={allowed_senders}",
        f"ALLOWED_RECIPIENTS={allowed_recipients}",
        "ALLOW_BOUNCES=true",
        f"SPOOF_PROTECTION={spoof_protection}",
        f"SMTP_CONN_RATE_LIMIT={preset['conn']}",
        f"SMTP_MSG_RATE_LIMIT={preset['msg']}",
        f"SMTP_RCPT_RATE_LIMIT={preset['rcpt']}",
    ]
    return "\n".join(lines) + "\n"


def build_config_summary(
    hostname: str,
    domain: str,
    ip_literal: str,
    has_domain: bool,
    webhook_url: str,
    allowed_sender_domains: str,
    allowed_senders: str,
    allowed_recipients: str,
    spoof_protection: str,
    rate_limit: str = "normal",
) -> list:
    """Build config summary as plain text lines (no ANSI)."""
    lines = []

    if ip_literal and not has_domain:
        lines.append(f"Receiving at:      anything@[{ip_literal}]  (IP literal)")
    else:
        lines.append(f"Hostname:          {hostname}")
        lines.append(f"Domain:            {domain}")

    if not webhook_url:
        lines.append("Mode:              Standalone (local storage)")
    else:
        lines.append("Mode:              Webhook")
        lines.append(f"Webhook URL:       {webhook_url}")

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

    rate_labels = {
        "normal": "Normal (10 conn, 50 msg, 100 rcpt per min)",
        "high": "High (100 conn, 500 msg, 1000 rcpt per min)",
        "off": "Off (no limits)",
    }
    lines.append(f"Rate limiting:     {rate_labels.get(rate_limit, 'Normal')}")
    lines.append("TLS:               Self-signed (auto-generated)")

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
        lines.append(f"anything@[{ip_literal}]")
        lines.append("")

    lines.append("Useful commands:")
    lines.append("primitive emails-status           # check inbox status")
    lines.append("docker compose logs postfix -f  # watch logs")
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
