#!/usr/bin/env python3
"""PrimitiveMail installer — Python phase.

Called by install.sh after Docker, firewall, and clone are done.
"""

import argparse
import os
import shutil
import subprocess
import sys
from typing import Optional

from installer import config, ui, server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="primitivemail-installer",
        description="PrimitiveMail installer",
    )
    parser.add_argument("--hostname", default="")
    parser.add_argument("--domain", default="")
    parser.add_argument("--claim-subdomain", action="store_true", dest="claim_subdomain")
    parser.add_argument("--webhook-url", default="", dest="webhook_url")
    parser.add_argument("--webhook-secret", default="", dest="webhook_secret")
    parser.add_argument("--event-webhook-url", default="", dest="event_webhook_url")
    parser.add_argument("--event-webhook-secret", default="", dest="event_webhook_secret")
    parser.add_argument("--ip-literal", default="", dest="ip_literal")
    parser.add_argument("--allowed-sender-domains", default="", dest="allowed_sender_domains")
    parser.add_argument("--allowed-senders", default="", dest="allowed_senders")
    parser.add_argument("--allowed-recipients", default="", dest="allowed_recipients")
    parser.add_argument("--spoof-protection", default="off", dest="spoof_protection")
    parser.add_argument("--no-prompt", "-y", action="store_true", dest="no_prompt")
    parser.add_argument("--no-start", action="store_true", dest="no_start")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--verbose", action="store_true")
    # End-to-end verification. When a subdomain claim succeeds, the installer
    # asks primitive.dev to send a real external email to it and waits for
    # the message to land in the local journal. A passing verify turns
    # "containers are up" into "the full pipeline works", which is the
    # question an agent forwarding a status to a user actually needs
    # answered. `--skip-verify` is the escape hatch for people who want the
    # old fast path (no rate-limit spend, no extra ~2-5s).
    parser.add_argument("--skip-verify", action="store_true", dest="skip_verify",
                        help="Skip the post-install end-to-end test email "
                             "(runs by default when a subdomain was claimed)")
    args = parser.parse_args()
    # --json implies --no-prompt: agents don't have a TTY, _get_tty_input would hang.
    # --claim-subdomain implies --no-prompt: otherwise a user could interactively
    # enter a real domain and then have it silently overwritten by the post-start
    # claim step. If you want interactive mode, don't pass --claim-subdomain —
    # the interactive flow has its own "do you want a free subdomain?" prompt.
    if args.json_output or args.claim_subdomain:
        args.no_prompt = True
    return args


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

    if args.claim_subdomain and (args.hostname or args.domain):
        msg = "--claim-subdomain and --domain/--hostname are mutually exclusive"
        ui.error(msg)
        ui.info("--claim-subdomain lets us assign a domain for you.")
        ui.info("--domain tells us you already have one.")
        ui.json_event("step", name="config", status="fail")
        ui.json_event("error", step="config", message=msg)
        sys.exit(1)

    if args.event_webhook_url and not config.validate_event_webhook_url(args.event_webhook_url):
        msg = f"Invalid --event-webhook-url: {args.event_webhook_url}"
        ui.error(msg)
        ui.info("Must be http:// or https:// with a host.")
        ui.json_event("step", name="config", status="fail")
        ui.json_event("error", step="config", message=msg)
        sys.exit(1)

    if args.event_webhook_secret and not args.event_webhook_url:
        msg = "--event-webhook-secret requires --event-webhook-url"
        ui.error(msg)
        ui.json_event("step", name="config", status="fail")
        ui.json_event("error", step="config", message=msg)
        sys.exit(1)

    hostname = args.hostname
    domain = args.domain
    ip_literal = args.ip_literal
    webhook_url = args.webhook_url
    webhook_secret = args.webhook_secret
    event_webhook_url = args.event_webhook_url
    event_webhook_secret = args.event_webhook_secret
    allowed_sender_domains = args.allowed_sender_domains
    allowed_senders = args.allowed_senders
    allowed_recipients = args.allowed_recipients
    spoof_protection = args.spoof_protection

    if not config.validate_spoof_protection(spoof_protection):
        if args.no_prompt:
            msg = f"Invalid spoof protection level: {spoof_protection}"
            ui.error(msg)
            ui.info("Valid values: off, monitor, standard, strict")
            ui.json_event("step", name="config", status="fail")
            ui.json_event("error", step="config", message=msg)
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
            print(f"    {ui.MUTED}Something like:{ui.NC} {ui.GREEN}agent{ui.NC}{ui.MUTED}@{ui.NC}{ui.YELLOW}<random-prefix>{ui.NC}{ui.MUTED}.primitive.email {ui.NC}{ui.MUTED}(any local-part works){ui.NC}")
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

    if event_webhook_url and not event_webhook_secret:
        event_webhook_secret = config.generate_webhook_secret()
        ui.warn(f"Event webhook URL set without secret - generated one: {event_webhook_secret}")
        ui.info("Save this - you'll need it to verify event webhook deliveries")

    return {
        "hostname": hostname,
        "domain": domain,
        "ip_literal": ip_literal,
        "has_domain": has_domain,
        "webhook_url": webhook_url,
        "webhook_secret": webhook_secret,
        "event_webhook_url": event_webhook_url,
        "event_webhook_secret": event_webhook_secret,
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
        event_webhook_url=cfg.get("event_webhook_url", ""),
        event_webhook_secret=cfg.get("event_webhook_secret", ""),
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
    # Observability containers (alloy + postfix-exporter) are gated behind
    # the compose `observability` profile. The installer does not write
    # COMPOSE_PROFILES itself (Phase 1 stays out of the .env mutation
    # business; see .internal/13). Enabled state is determined from the
    # cfg dict and the process environment only; we do not re-parse the
    # .env file that write_env just wrote, so a pre-existing COMPOSE_PROFILES
    # line in .env that was not exported into the installing shell will be
    # reported as disabled here even though `docker compose up` would
    # activate the profile. Acceptable for Phase 1.
    observability_enabled = _observability_is_enabled(cfg)

    lines = config.build_config_summary(
        hostname=cfg["hostname"],
        domain=cfg["domain"],
        ip_literal=cfg["ip_literal"],
        has_domain=cfg["has_domain"],
        webhook_url=cfg["webhook_url"],
        event_webhook_url=cfg.get("event_webhook_url", ""),
        allowed_sender_domains=cfg["allowed_sender_domains"],
        allowed_senders=cfg["allowed_senders"],
        allowed_recipients=cfg["allowed_recipients"],
        spoof_protection=cfg["spoof_protection"],
        observability_enabled=observability_enabled,
    )
    print()
    ui.step("Configuration summary")
    print()
    for line in lines:
        print(f"  {line}")

    # Parallel NDJSON event for agents scripting the install. The disabled
    # message includes the exact remediation command so an agent reading
    # step events doesn't need to cross-reference .env.example.
    if observability_enabled:
        ui.json_event(
            "step",
            name="observability",
            status="ok",
            enabled=True,
            message="Observability containers enabled (Alloy + postfix-exporter).",
        )
    else:
        ui.json_event(
            "step",
            name="observability",
            status="ok",
            enabled=False,
            message=(
                "Observability containers disabled by default. Set "
                "COMPOSE_PROFILES=observability in .env and run "
                "`primitive restart` to enable."
            ),
        )


def _observability_is_enabled(cfg: dict) -> bool:
    """True if the upcoming `docker compose up` will activate the
    `observability` profile. Phase 1 never writes COMPOSE_PROFILES from
    the installer, so this is False for every fresh install today. A
    pre-set environment variable (exported before install.sh ran, or set
    in an existing .env that Phase 2's migration helper preserved) can
    still flip it to True — check that path so the summary and the NDJSON
    event remain truthful either way."""
    raw = cfg.get("compose_profiles") or os.environ.get("COMPOSE_PROFILES", "")
    profiles = [p.strip() for p in raw.split(",") if p.strip()]
    return "observability" in profiles


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


def try_claim_subdomain(install_dir: str, cfg: dict, no_prompt: bool, force: bool = False) -> dict:
    """Claim a new free subdomain on primitive.email.
    Must be called after the server is running (port 25 must be open).
    Existing claims are handled earlier in configure().
    When `force` is True (from --claim-subdomain), skip the confirm prompt.
    Returns updated cfg if successful, original cfg if not."""
    print()

    if not no_prompt and not force:
        if not ui.prompt_yn(
            "Would you like a free email domain? (e.g. cool-fox.primitive.email)",
            "y",
            no_prompt=False,
        ):
            return cfg

    ui.info("Claiming a free subdomain...")
    ui.json_event("step", name="claim", status="start")
    result = config.claim_subdomain()

    if not result:
        ui.warn("Could not claim a subdomain. You can try again later or add your own domain.")
        ui.info("Continuing with IP literal mode.")
        ui.json_event("step", name="claim", status="fail")
        return cfg

    domain = result["domain"]
    ui.success(f"Claimed: {domain}")
    cloud = server.detect_cloud_provider()
    ui.json_event("step", name="claim", status="ok", domain=domain, cloud=cloud)
    print()
    print(f"  {ui.BOLD}Send email to:{ui.NC}")
    print(f"  {ui.GREEN}agent@{domain}{ui.NC}  {ui.MUTED}(any local-part works){ui.NC}")
    print()
    print(f"  {ui.MUTED}Or verify end-to-end with:{ui.NC} {ui.BOLD}primitive emails test{ui.NC}")
    print()
    # Public-IP rotation warning for cloud providers where stop/start,
    # rebuilds, or unattached instances can swap the public IP. The claim
    # is anchored to the current IPv4; the subdomain silently detaches if
    # the IP changes. Call this out at claim time (and again in the post-
    # install summary) so operators pin an Elastic IP before publishing
    # anything that depends on the address.
    if cloud == "aws":
        print(f"  {ui.YELLOW}!{ui.NC} {ui.BOLD}AWS detected.{ui.NC} {ui.MUTED}The subdomain is anchored to this{ui.NC}")
        print(f"    {ui.MUTED}instance's current public IPv4. Attach an Elastic IP{ui.NC}")
        print(f"    {ui.MUTED}before publishing this address, or it will silently{ui.NC}")
        print(f"    {ui.MUTED}detach on the next stop/start.{ui.NC}")
        print()
    elif cloud in ("gcp", "azure"):
        print(f"  {ui.YELLOW}!{ui.NC} {ui.BOLD}{cloud.upper()} detected.{ui.NC} {ui.MUTED}Pin a static public IP before{ui.NC}")
        print(f"    {ui.MUTED}publishing this address; the claim is anchored to the{ui.NC}")
        print(f"    {ui.MUTED}current IPv4 and detaches if it rotates.{ui.NC}")
        print()
    print(f"  {ui.MUTED}Inbound only: PrimitiveMail receives mail, it does not{ui.NC}")
    print(f"  {ui.MUTED}send. For outbound or reply flows, bring your own domain{ui.NC}")
    print(f"  {ui.MUTED}(DKIM signing lives with the sending domain, not with{ui.NC}")
    print(f"  {ui.MUTED}*.primitive.email subdomains).{ui.NC}")
    print()

    cfg = {
        **cfg,
        "hostname": domain,
        "domain": domain,
        "ip_literal": "",
        "has_domain": True,
        "claimed_subdomain": True,
        "cloud": cloud,
    }

    write_env(install_dir, cfg)
    ui.info("Restarting with new domain...")
    server.restart(install_dir)

    return cfg


def run_end_to_end_verify(timeout_sec: int = 30) -> Optional[bool]:
    """Ask primitive.dev to send a real test email and wait for it to land.

    Returns True on a fully-verified install, False on any failure (dispatch
    error, delivery timeout, rate limit), or None when we could not run the
    check at all (no CLI on PATH). The installer treats False as a warning,
    not a hard error: the containers might be fine and a subsequent
    `primitive emails test` might succeed on retry. What we are buying with
    this step is a definitive "yes, mail works" signal that an agent
    forwarding a status to a user can trust without further prompting.

    Shells out to the already-installed `primitive` CLI rather than
    recalling the test endpoint directly, so the exit-code scheme stays in
    one place and future CLI changes (timeout handling, retries) propagate
    to the installer automatically.
    """
    cli_path = shutil.which("primitive") or "/usr/local/bin/primitive"
    if not os.path.exists(cli_path):
        ui.warn("primitive CLI not found on PATH; skipping end-to-end verify")
        ui.json_event("step", name="verify", status="skip",
                      reason="cli_not_found")
        return None

    ui.step("Verifying end-to-end")
    ui.info("Asking primitive.dev to send a test email and waiting for it to land...")
    ui.json_event("step", name="verify", status="start", timeout_sec=timeout_sec)

    try:
        result = subprocess.run(
            [cli_path, "emails", "test", "--timeout", str(timeout_sec), "--json"],
            capture_output=True,
            text=True,
            timeout=timeout_sec + 15,
        )
    except subprocess.TimeoutExpired:
        ui.warn("End-to-end verify hit a hard timeout; run `primitive emails test` to retry.")
        ui.json_event("step", name="verify", status="fail",
                      reason="subprocess_timeout")
        return False
    except Exception as exc:
        ui.warn(f"End-to-end verify could not run: {exc}")
        ui.json_event("step", name="verify", status="fail",
                      reason="subprocess_error", message=str(exc))
        return False

    if result.returncode == 0:
        ui.success("End-to-end verified: a real external email was received")
        ui.json_event("step", name="verify", status="ok")
        return True

    # Non-zero: classify via the CLI's documented exit codes so the NDJSON
    # event carries something an agent can decide on without re-parsing text.
    reason_by_code = {
        1: "no_subdomain_claimed",
        2: "cli_usage",
        4: "rate_limited",
        5: "journal_unreadable",
        6: "timeout_waiting_for_delivery",
        7: "transport",
    }
    reason = reason_by_code.get(result.returncode, "unknown")
    # Surface whatever the CLI said on stderr. Without this the operator
    # sees only "exit 6: timeout_waiting_for_delivery" and loses the text
    # that would tell them which upstream (dispatcher, DNS, watcher) the
    # CLI itself suspected. Truncate so a runaway CLI cannot blow up the
    # installer output, but include the first ~400 chars which is more
    # than enough for every documented error path.
    stderr_tail = (result.stderr or "").strip()
    if len(stderr_tail) > 400:
        stderr_tail = stderr_tail[:400] + "... (truncated)"
    ui.warn(
        f"End-to-end verify failed (exit {result.returncode}: {reason}); "
        "the box looks set up, but we could not confirm delivery. "
        "Run `primitive emails test` to retry."
    )
    if stderr_tail:
        ui.info(f"CLI said: {stderr_tail}")
    ui.json_event(
        "step", name="verify", status="fail",
        exit_code=result.returncode, reason=reason,
        cli_stderr=stderr_tail,
    )
    return False


def print_next_steps(cfg: dict, install_dir: str, verified: Optional[bool] = None) -> None:
    lines = config.build_next_steps(
        ip_literal=cfg["ip_literal"],
        has_domain=cfg["has_domain"],
        install_dir=install_dir,
        docker_cmd=server._docker_cmd(),
        cloud=cfg.get("cloud"),
        claimed_subdomain=cfg.get("claimed_subdomain", False),
        verified=verified,
    )
    print()
    ui.step("PrimitiveMail is ready")
    print()
    for line in lines:
        print(f"  {line}")
    print()


def main() -> None:
    args = parse_args()
    if args.json_output:
        ui.enable_json_mode()
    install_dir = os.environ.get("PRIMITIVEMAIL_DIR", "./primitivemail")

    check_existing_install(install_dir, args.no_prompt)
    ui.json_event("step", name="config", status="start")
    cfg = configure(args)
    write_env(install_dir, cfg)
    print_config_summary(cfg)
    print_dns_instructions(cfg)
    ui.json_event("step", name="config", status="ok")
    server.start_server(
        install_dir=install_dir,
        no_start=args.no_start,
        verbose=args.verbose,
        ip_literal=cfg["ip_literal"],
    )

    # After server is running (port 25 open), claim a free subdomain
    # if the user doesn't have their own domain or explicitly asked for one
    should_claim = (
        not args.no_start
        and (args.claim_subdomain or not cfg["has_domain"])
    )
    if should_claim:
        cfg = try_claim_subdomain(install_dir, cfg, args.no_prompt, force=args.claim_subdomain)

    ui.json_event("step", name="install_cli", status="start")
    server.install_cli(install_dir)
    ui.json_event("step", name="install_cli", status="ok")

    # End-to-end verification. Only runs when a fresh subdomain was
    # claimed in this install (bring-your-own-domain installs skip it
    # because the user's DNS may not have propagated yet, and the test
    # endpoint is identity-matched on source IP so it would look
    # "unclaimed" from an unrelated-domain install anyway).
    verified = None
    if cfg.get("claimed_subdomain") and not args.skip_verify:
        verified = run_end_to_end_verify()

    print_next_steps(cfg, install_dir, verified=verified)
    ui.json_event(
        "done",
        install_dir=os.path.abspath(install_dir),
        hostname=cfg["hostname"],
        domain=cfg["domain"],
        has_domain=cfg["has_domain"],
        ip_literal=cfg["ip_literal"],
        event_webhook_enabled=bool(cfg.get("event_webhook_url")),
        claimed_subdomain=cfg.get("claimed_subdomain", False),
        cloud=cfg.get("cloud"),
        verified=verified,
    )


if __name__ == "__main__":
    main()
