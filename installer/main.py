#!/usr/bin/env python3
"""PrimitiveMail installer — Python phase.

Called by install.sh after Docker, firewall, and clone are done.
"""

import argparse
import os
import sys

from installer import config, ui, server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="primitivemail-installer",
        description="PrimitiveMail installer",
    )
    parser.add_argument("--hostname", default="")
    parser.add_argument("--domain", default="")
    parser.add_argument("--webhook-url", default="", dest="webhook_url")
    parser.add_argument("--webhook-secret", default="", dest="webhook_secret")
    parser.add_argument("--ip-literal", default="", dest="ip_literal")
    parser.add_argument("--allowed-sender-domains", default="", dest="allowed_sender_domains")
    parser.add_argument("--allowed-senders", default="", dest="allowed_senders")
    parser.add_argument("--allowed-recipients", default="", dest="allowed_recipients")
    parser.add_argument("--spoof-protection", default="off", dest="spoof_protection")
    parser.add_argument("--no-prompt", "-y", action="store_true", dest="no_prompt")
    parser.add_argument("--no-start", action="store_true", dest="no_start")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def check_existing_install(install_dir: str, no_prompt: bool) -> None:
    env_path = os.path.join(install_dir, ".env")
    if not os.path.isfile(env_path):
        return
    print()
    ui.warn(f"PrimitiveMail is already configured at {install_dir}")
    print()
    if no_prompt:
        ui.info("Non-interactive mode: re-running full setup")
        return
    if not ui.prompt_yn("Start over with a fresh configuration?", "n", no_prompt=False):
        print()
        ui.info("Keeping existing configuration. Nothing to do.")
        sys.exit(0)
    print()


def configure(args: argparse.Namespace) -> dict:
    """Run the configuration flow. Returns a config dict."""
    if not args.no_prompt:
        print()
        print(f"  {ui.RED}{ui.BOLD}Before you start, make sure:{ui.NC}")
        print(f"  {ui.RED}-{ui.NC} This server has a {ui.BOLD}static public IP{ui.NC} {ui.MUTED}(dynamic IPs will break mail delivery){ui.NC}")
        print(f"  {ui.RED}-{ui.NC} {ui.BOLD}Port 25 (TCP){ui.NC} is open inbound {ui.MUTED}(check your cloud firewall / security group){ui.NC}")
        print(f"  {ui.RED}-{ui.NC} You are {ui.BOLD}NOT behind CGNAT{ui.NC} {ui.MUTED}(most cloud providers are fine, some home ISPs are not){ui.NC}")
        print()

    ui.step("Configuration")

    hostname = args.hostname
    domain = args.domain
    ip_literal = args.ip_literal
    webhook_url = args.webhook_url
    webhook_secret = args.webhook_secret
    allowed_sender_domains = args.allowed_sender_domains
    allowed_senders = args.allowed_senders
    allowed_recipients = args.allowed_recipients
    spoof_protection = args.spoof_protection

    if not config.validate_spoof_protection(spoof_protection):
        if args.no_prompt:
            ui.error(f"Invalid spoof protection level: {spoof_protection}")
            ui.info("Valid values: off, monitor, standard, strict")
            sys.exit(1)
        else:
            ui.warn(f"Invalid spoof protection level: {spoof_protection}")
            ui.info("Valid values: off, monitor, standard, strict")
            ui.info("Defaulting to: off")
            spoof_protection = "off"

    if args.no_prompt:
        hostname, domain, ip_literal, has_domain = config.resolve_non_interactive_defaults(
            hostname, domain, ip_literal,
        )
    else:
        # --- DNS setup ---
        print()
        if ui.prompt_yn("Do you have a domain name for receiving email?", "n", no_prompt=False):
            print()
            print(f"  {ui.BOLD}Hostname{ui.NC} {ui.MUTED}- the address of this mail server itself.{ui.NC}")
            print(f"  {ui.MUTED}Other mail servers connect to this when delivering email to you.{ui.NC}")
            print(f"  {ui.MUTED}Usually something like mx.yourdomain.com{ui.NC}")
            hostname = ui.prompt_value("Hostname", hostname or "mx.example.com", no_prompt=False)
            print()
            print(f"  {ui.BOLD}Domain{ui.NC} {ui.MUTED}- the domain you want to receive email for.{ui.NC}")
            print(f"  {ui.MUTED}If you want to receive mail at user@example.com, enter example.com{ui.NC}")
            domain = ui.prompt_value("Domain", domain or "example.com", no_prompt=False)
            has_domain = True
        else:
            print()
            print(f"  {ui.GREEN}+{ui.NC} {ui.BOLD}We'll give you a free domain once your server is running.{ui.NC}")
            print(f"    {ui.MUTED}Something like:{ui.NC} {ui.GREEN}anything@{ui.NC}{ui.YELLOW}<random-prefix>{ui.NC}{ui.GREEN}.primitive.email{ui.NC}")
            print(f"    {ui.YELLOW}(not active yet -- assigned after install completes){ui.NC}")
            print()
            ui.info("Detecting your public IP...")
            ip_literal = config.detect_public_ip() or ""
            if ip_literal:
                ui.success(f"Detected public IP: {ip_literal}")
            else:
                ui.warn("Could not detect public IP.")
            hostname = "localhost"
            domain = "localhost"
            has_domain = False

        # --- Webhook setup ---
        print()
        if ui.prompt_yn("Do you have a webhook URL to forward emails to?", "n", no_prompt=False):
            print()
            print(f"  {ui.MUTED}When an email arrives, PrimitiveMail will POST it to this URL.{ui.NC}")
            print(f"  {ui.MUTED}Without a webhook, emails are accepted and stored locally.{ui.NC}")
            webhook_url = ui.prompt_value("Webhook URL", "", no_prompt=False)
            if webhook_url:
                webhook_secret = ui.prompt_value("Webhook secret", "", no_prompt=False)
                if not webhook_secret:
                    webhook_secret = config.generate_webhook_secret()
                    print()
                    ui.warn("No secret provided - generated one automatically")
                    ui.info(f"Secret: {ui.BOLD}{webhook_secret}{ui.NC}")
                    ui.info("Save this - you'll need it to configure your webhook endpoint")

        # --- Sender security ---
        print()
        ui.step("Sender Security")
        print()
        print(f"  {ui.MUTED}Who should be allowed to send mail to this server?{ui.NC}")
        print()
        print(f"    {ui.BOLD}1{ui.NC}. Anyone         {ui.MUTED}- Accept mail from all senders{ui.NC}")
        print(f"    {ui.BOLD}2{ui.NC}. Specific senders {ui.MUTED}- Only accept from domains/addresses you specify{ui.NC}")
        print()
        sender_choice = ui.prompt_choice("Choice (1-2)", 2, 1, no_prompt=False)

        if sender_choice == 2:
            print()
            print(f"  {ui.MUTED}Allowed sender domains (comma-separated){ui.NC}")
            print(f"  {ui.MUTED}Accepts mail from *@domain -- any address at these domains.{ui.NC}")
            print(f"  {ui.MUTED}Example: example.com,trusted.org{ui.NC}")
            allowed_sender_domains = ui.prompt_value("Domains", "", no_prompt=False)
            print()
            print(f"  {ui.MUTED}Allowed sender addresses (comma-separated, optional){ui.NC}")
            print(f"  {ui.MUTED}Accepts mail from these specific addresses only.{ui.NC}")
            print(f"  {ui.MUTED}Use this for individual senders at domains you don't fully trust.{ui.NC}")
            print(f"  {ui.MUTED}Example: alerts@github.com,friend@gmail.com{ui.NC}")
            allowed_senders = ui.prompt_value("Addresses", "", no_prompt=False)

        # --- Recipient filtering ---
        print()
        ui.step("Recipient Filtering")
        print()
        if ui.prompt_yn("Do you want to restrict which addresses can receive mail?", "n", no_prompt=False):
            print()
            print(f"  {ui.MUTED}Which addresses on YOUR server can receive mail?{ui.NC}")
            print(f"  {ui.MUTED}Comma-separated list.{ui.NC}")
            print(f"  {ui.MUTED}Example: inbox@yourdomain.com,alerts@yourdomain.com{ui.NC}")
            allowed_recipients = ui.prompt_value("Allowed recipients", "", no_prompt=False)

        # --- Spoof protection ---
        print()
        ui.step("Spoof Protection")
        print()
        print(f"  {ui.MUTED}Spoof protection verifies that senders are who they claim to be{ui.NC}")
        print(f"  {ui.MUTED}using SPF, DKIM, and DMARC - industry-standard email authentication.{ui.NC}")
        print()
        print(f"    {ui.BOLD}1{ui.NC}. Off       {ui.MUTED}- No verification (for testing/development){ui.NC}")
        print(f"    {ui.BOLD}2{ui.NC}. Monitor   {ui.MUTED}- Verify and log results, but accept everything{ui.NC}")
        print(f"    {ui.BOLD}3{ui.NC}. Standard  {ui.MUTED}- Enforce the sender's own published policy (recommended){ui.NC}")
        print(f"    {ui.BOLD}4{ui.NC}. Strict    {ui.MUTED}- Reject on any authentication failure{ui.NC}")
        print()
        spoof_choice = ui.prompt_choice("Choice (1-4)", 4, 1, no_prompt=False)
        spoof_protection = config.map_spoof_choice(spoof_choice)

        # --- Sender filtering + spoof warning ---
        if config.should_warn_sender_filtering(allowed_sender_domains, allowed_senders, spoof_protection):
            print()
            ui.warn("Without spoof protection, sender filtering only checks the envelope")
            ui.warn("address, which can be easily forged. Consider enabling at least")
            ui.warn('"Standard" spoof protection for real security.')
            print()
            if not ui.prompt_yn("Continue anyway?", "n", no_prompt=False):
                spoof_protection = "standard"
                ui.success("Spoof protection set to: standard")

    # --- Webhook secret validation ---
    if webhook_url and not webhook_secret:
        webhook_secret = config.generate_webhook_secret()
        ui.warn(f"Webhook URL set without secret - generated one: {webhook_secret}")

    return {
        "hostname": hostname,
        "domain": domain,
        "ip_literal": ip_literal,
        "has_domain": has_domain,
        "webhook_url": webhook_url,
        "webhook_secret": webhook_secret,
        "allowed_sender_domains": allowed_sender_domains,
        "allowed_senders": allowed_senders,
        "allowed_recipients": allowed_recipients,
        "spoof_protection": spoof_protection,
    }


def write_env(install_dir: str, cfg: dict) -> None:
    content = config.generate_env_content(
        hostname=cfg["hostname"],
        domain=cfg["domain"],
        enable_ip_literal=bool(cfg["ip_literal"]),
        ip_literal=cfg["ip_literal"],
        webhook_url=cfg["webhook_url"],
        webhook_secret=cfg["webhook_secret"],
        allowed_sender_domains=cfg["allowed_sender_domains"],
        allowed_senders=cfg["allowed_senders"],
        allowed_recipients=cfg["allowed_recipients"],
        spoof_protection=cfg["spoof_protection"],
    )
    env_path = os.path.join(install_dir, ".env")
    with open(env_path, "w") as f:
        f.write(content)
    os.chmod(env_path, 0o600)
    ui.success(f"Configuration saved to {env_path}")


def print_config_summary(cfg: dict) -> None:
    lines = config.build_config_summary(
        hostname=cfg["hostname"],
        domain=cfg["domain"],
        ip_literal=cfg["ip_literal"],
        has_domain=cfg["has_domain"],
        webhook_url=cfg["webhook_url"],
        allowed_sender_domains=cfg["allowed_sender_domains"],
        allowed_senders=cfg["allowed_senders"],
        allowed_recipients=cfg["allowed_recipients"],
        spoof_protection=cfg["spoof_protection"],
    )
    print()
    ui.step("Configuration summary")
    print()
    for line in lines:
        print(f"  {line}")


def print_dns_instructions(cfg: dict) -> None:
    if cfg["has_domain"]:
        lines = config.build_dns_instructions(cfg["hostname"], cfg["domain"])
        print()
        ui.step("DNS setup required")
        print()
        for line in lines:
            print(f"  {line}")

    if cfg["spoof_protection"] != "off":
        print()
        ui.info("Spoof protection requires DNS lookups from this server.")
        ui.info("Ensure outbound DNS (port 53) is not blocked by your firewall.")


def try_claim_subdomain(install_dir: str, cfg: dict, no_prompt: bool) -> dict:
    """Claim a new free subdomain on primitive.email.
    Must be called after the server is running (port 25 must be open).
    Existing claims are handled earlier in configure().
    Returns updated cfg if successful, original cfg if not."""
    print()

    if not no_prompt:
        if not ui.prompt_yn(
            "Would you like a free email domain? (e.g. cool-fox.primitive.email)",
            "y",
            no_prompt=False,
        ):
            return cfg

    ui.info("Claiming a free subdomain...")
    result = config.claim_subdomain()

    if not result:
        ui.warn("Could not claim a subdomain. You can try again later or add your own domain.")
        ui.info("Continuing with IP literal mode.")
        return cfg

    domain = result["domain"]
    ui.success(f"Claimed: {domain}")
    print()
    print(f"  {ui.BOLD}Send email to:{ui.NC}")
    print(f"  {ui.GREEN}anything@{domain}{ui.NC}")
    print()

    cfg = {
        **cfg,
        "hostname": domain,
        "domain": domain,
        "ip_literal": "",
        "has_domain": True,
    }

    write_env(install_dir, cfg)
    ui.info("Restarting with new domain...")
    server.restart(install_dir)

    return cfg


def print_next_steps(cfg: dict, install_dir: str) -> None:
    lines = config.build_next_steps(
        ip_literal=cfg["ip_literal"],
        has_domain=cfg["has_domain"],
        install_dir=install_dir,
    )
    print()
    ui.step("PrimitiveMail is ready")
    print()
    for line in lines:
        print(f"  {line}")
    print()


def main() -> None:
    args = parse_args()
    install_dir = os.environ.get("PRIMITIVEMAIL_DIR", "./primitivemail")

    check_existing_install(install_dir, args.no_prompt)
    cfg = configure(args)
    write_env(install_dir, cfg)
    print_config_summary(cfg)
    print_dns_instructions(cfg)
    server.start_server(
        install_dir=install_dir,
        no_start=args.no_start,
        verbose=args.verbose,
        ip_literal=cfg["ip_literal"],
    )

    # After server is running (port 25 open), claim a free subdomain
    # if the user doesn't have their own domain
    if not cfg["has_domain"] and not args.no_start:
        cfg = try_claim_subdomain(install_dir, cfg, args.no_prompt)

    server.install_cli(install_dir)
    print_next_steps(cfg, install_dir)


if __name__ == "__main__":
    main()
