#!/usr/bin/env python3
"""Tests for installer/config.py pure functions."""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

from installer.config import (
    detect_public_ip,
    generate_env_content,
    generate_webhook_secret,
    validate_event_webhook_url,
    validate_spoof_protection,
    map_spoof_choice,
    should_warn_sender_filtering,
    build_config_summary,
    build_dns_instructions,
    build_next_steps,
    resolve_non_interactive_defaults,
)


# ===========================================================================
# .env generation
# ===========================================================================

class TestGenerateEnvContent:

    def test_basic_domain_setup(self):
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="", webhook_secret="",
            event_webhook_url="", event_webhook_secret="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        assert "MYHOSTNAME=mx.example.com" in result
        assert "MYDOMAIN=example.com" in result
        assert "ENABLE_IP_LITERAL=false" in result
        assert "ALLOW_BOUNCES=true" in result
        assert "SPOOF_PROTECTION=off" in result

    def test_ip_literal_mode(self):
        result = generate_env_content(
            hostname="localhost", domain="localhost",
            enable_ip_literal=True, ip_literal="203.0.113.10",
            webhook_url="", webhook_secret="",
            event_webhook_url="", event_webhook_secret="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        assert "ENABLE_IP_LITERAL=true" in result
        assert "IP_LITERAL=203.0.113.10" in result

    def test_webhook_config(self):
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="https://api.example.com/email", webhook_secret="secret123",
            event_webhook_url="", event_webhook_secret="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        assert "WEBHOOK_URL=https://api.example.com/email" in result
        assert "WEBHOOK_SECRET=secret123" in result

    def test_sender_filtering(self):
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="", webhook_secret="",
            event_webhook_url="", event_webhook_secret="",
            allowed_sender_domains="trusted.org,example.net",
            allowed_senders="alerts@github.com",
            allowed_recipients="inbox@example.com",
            spoof_protection="standard",
        )
        assert "ALLOWED_SENDER_DOMAINS=trusted.org,example.net" in result
        assert "ALLOWED_SENDERS=alerts@github.com" in result
        assert "ALLOWED_RECIPIENTS=inbox@example.com" in result
        assert "SPOOF_PROTECTION=standard" in result

    def test_line_count_stable(self):
        # Pin the line count so reorderings or accidental extra keys get caught.
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="", webhook_secret="",
            event_webhook_url="", event_webhook_secret="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        assert len(result.strip().split("\n")) == 13

    def test_event_webhook_written(self):
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="", webhook_secret="",
            event_webhook_url="https://ingest.example.com/hook",
            event_webhook_secret="e1b2c3",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        assert "EVENT_WEBHOOK_URL=https://ingest.example.com/hook" in result
        assert "EVENT_WEBHOOK_SECRET=e1b2c3" in result

    def test_event_webhook_absent_by_default(self):
        # When no event webhook is configured, the keys should still appear in
        # .env (so grep shows every tunable) but with empty values — not
        # missing, not with stale data leaking through.
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="", webhook_secret="",
            event_webhook_url="", event_webhook_secret="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        lines = result.strip().split("\n")
        env = dict(line.split("=", 1) for line in lines)
        assert env["EVENT_WEBHOOK_URL"] == ""
        assert env["EVENT_WEBHOOK_SECRET"] == ""

    def test_no_quoting(self):
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="https://example.com/hook", webhook_secret="s3cret",
            event_webhook_url="", event_webhook_secret="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        assert '"' not in result
        assert "'" not in result


# ===========================================================================
# Config summary
# ===========================================================================

class TestBuildConfigSummary:

    def test_ip_literal_mode(self):
        lines = build_config_summary(
            hostname="localhost", domain="localhost",
            ip_literal="1.2.3.4", has_domain=False,
            webhook_url="", event_webhook_url="",
            allowed_sender_domains="",
            allowed_senders="", allowed_recipients="",
            spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "1.2.3.4" in text
        assert "IP literal" in text

    def test_domain_mode(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="", event_webhook_url="",
            allowed_sender_domains="",
            allowed_senders="", allowed_recipients="",
            spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "mx.example.com" in text
        assert "example.com" in text

    def test_webhook_mode(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="https://api.example.com/email",
            event_webhook_url="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "Webhook" in text

    def test_standalone_mode(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="", event_webhook_url="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "Standalone" in text

    @pytest.mark.parametrize("level,expected", [
        ("off", "Off"),
        ("monitor", "Monitor"),
        ("standard", "Standard"),
        ("strict", "Strict"),
    ])
    def test_spoof_protection_labels(self, level, expected):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="", event_webhook_url="",
            allowed_sender_domains="",
            allowed_senders="", allowed_recipients="",
            spoof_protection=level,
        )
        text = "\n".join(lines)
        assert expected in text

    def test_sender_filtering_displayed(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="", event_webhook_url="",
            allowed_sender_domains="trusted.org",
            allowed_senders="ceo@big.com", allowed_recipients="",
            spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "trusted.org" in text
        assert "ceo@big.com" in text

    def test_tls_always_shown(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="", event_webhook_url="",
            allowed_sender_domains="",
            allowed_senders="", allowed_recipients="",
            spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "Self-signed" in text


# ===========================================================================
# DNS instructions
# ===========================================================================

class TestBuildDnsInstructions:

    def test_mx_record(self):
        lines = build_dns_instructions("mx.example.com", "example.com")
        text = "\n".join(lines)
        assert "MX" in text
        assert "example.com" in text
        assert "mx.example.com" in text
        assert "10" in text

    def test_a_record(self):
        lines = build_dns_instructions("mx.example.com", "example.com")
        text = "\n".join(lines)
        assert "A" in text
        assert "<your-server-ip>" in text

    def test_propagation_warning(self):
        lines = build_dns_instructions("mx.example.com", "example.com")
        text = "\n".join(lines)
        assert "propagate" in text


# ===========================================================================
# Validation
# ===========================================================================

class TestValidateSpoofProtection:

    @pytest.mark.parametrize("value", ["off", "monitor", "standard", "strict"])
    def test_valid(self, value):
        assert validate_spoof_protection(value) is True

    @pytest.mark.parametrize("value", ["", "invalid", "OFF", "Monitor", "1", "none"])
    def test_invalid(self, value):
        assert validate_spoof_protection(value) is False


class TestMapSpoofChoice:

    def test_all_choices(self):
        assert map_spoof_choice(1) == "off"
        assert map_spoof_choice(2) == "monitor"
        assert map_spoof_choice(3) == "standard"
        assert map_spoof_choice(4) == "strict"

    def test_invalid_defaults_to_off(self):
        assert map_spoof_choice(0) == "off"
        assert map_spoof_choice(5) == "off"
        assert map_spoof_choice(-1) == "off"


class TestShouldWarnSenderFiltering:

    def test_warns_with_domains_no_spoof(self):
        assert should_warn_sender_filtering("example.com", "", "off") is True

    def test_warns_with_senders_no_spoof(self):
        assert should_warn_sender_filtering("", "user@example.com", "off") is True

    def test_no_warn_with_spoof_enabled(self):
        assert should_warn_sender_filtering("example.com", "", "standard") is False
        assert should_warn_sender_filtering("example.com", "", "monitor") is False
        assert should_warn_sender_filtering("example.com", "", "strict") is False

    def test_no_warn_without_filtering(self):
        assert should_warn_sender_filtering("", "", "off") is False


# ===========================================================================
# Webhook secret
# ===========================================================================

class TestGenerateWebhookSecret:

    def test_length(self):
        assert len(generate_webhook_secret()) == 64

    def test_hex_only(self):
        secret = generate_webhook_secret()
        assert all(c in "0123456789abcdef" for c in secret)

    def test_unique(self):
        assert generate_webhook_secret() != generate_webhook_secret()


# ===========================================================================
# IP detection
# ===========================================================================

class TestDetectPublicIp:

    def test_returns_ip(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"203.0.113.42\n"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("installer.config.urllib.request.urlopen", return_value=mock_resp):
            assert detect_public_ip() == "203.0.113.42"

    def test_returns_none_on_all_failures(self):
        with patch("installer.config.urllib.request.urlopen", side_effect=Exception("fail")):
            assert detect_public_ip() is None

    def test_skips_invalid_responses(self):
        call_count = 0

        def mock_urlopen(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock = MagicMock()
            mock.__enter__ = lambda s: s
            mock.__exit__ = MagicMock(return_value=False)
            if call_count == 1:
                mock.read.return_value = b"not-an-ip"
            else:
                mock.read.return_value = b"10.0.0.1"
            return mock

        with patch("installer.config.urllib.request.urlopen", side_effect=mock_urlopen):
            assert detect_public_ip() == "10.0.0.1"


# ===========================================================================
# Non-interactive defaults
# ===========================================================================

class TestResolveNonInteractiveDefaults:

    def test_defaults_to_localhost(self):
        with patch("installer.config.detect_public_ip", return_value=None):
            h, d, ip, has = resolve_non_interactive_defaults("", "", "")
        assert h == "localhost"
        assert d == "localhost"
        assert has is False

    def test_preserves_provided_values(self):
        h, d, ip, has = resolve_non_interactive_defaults(
            "mx.example.com", "example.com", "",
        )
        assert h == "mx.example.com"
        assert d == "example.com"
        assert has is True

    def test_ip_detection_when_localhost(self):
        with patch("installer.config.detect_public_ip", return_value="1.2.3.4"):
            h, d, ip, has = resolve_non_interactive_defaults("", "", "")
        assert ip == "1.2.3.4"
        assert has is False

    def test_ip_preserved_when_provided(self):
        h, d, ip, has = resolve_non_interactive_defaults("", "", "5.6.7.8")
        assert ip == "5.6.7.8"


# ===========================================================================
# Next steps
# ===========================================================================

class TestBuildNextSteps:

    def test_ip_literal_test_address(self):
        lines = build_next_steps(ip_literal="1.2.3.4", has_domain=False, install_dir="/home/user/pm")
        text = "\n".join(lines)
        assert "1.2.3.4" in text

    def test_useful_commands(self):
        lines = build_next_steps(ip_literal="", has_domain=True, install_dir="/home/user/pm")
        text = "\n".join(lines)
        assert "primitive emails status" in text
        assert "primitive emails list" in text
        assert "primitive emails test" in text
        assert "docker logs" in text
        assert "primitive restart" in text

    def test_useful_commands_omits_emails_test_when_no_domain(self):
        # emails test requires a claimed subdomain; suggest it only when the
        # install actually has one (has_domain=True). Otherwise the command
        # is still available but would 404 until a claim happens, so skip it
        # in the post-install summary to avoid operator confusion.
        lines = build_next_steps(ip_literal="1.2.3.4", has_domain=False, install_dir="/home/user/pm")
        text = "\n".join(lines)
        assert "primitive emails test" not in text
        assert "primitive emails status" in text

    def test_agent_integration_hint(self):
        lines = build_next_steps(ip_literal="", has_domain=True, install_dir="/home/user/pm")
        text = "\n".join(lines)
        assert "AGENTS.md" in text

    def test_cloud_firewall_warning(self):
        lines = build_next_steps(ip_literal="", has_domain=True, install_dir="/home/user/pm")
        text = "\n".join(lines)
        assert "port 25" in text.lower() or "Port 25" in text

    def test_docker_logs_hint_prefixes_sudo_when_not_in_docker_group(self):
        # get.docker.com doesn't add the invoking user to the docker group,
        # so on a fresh VPS the installer runs docker via `sudo docker`. The
        # post-install hint has to carry the same prefix or operators copy
        # a command that exits with "permission denied on docker.sock".
        lines = build_next_steps(
            ip_literal="", has_domain=True, install_dir="/home/user/pm",
            docker_cmd=["sudo", "docker"],
        )
        text = "\n".join(lines)
        assert "sudo docker logs primitivemail -f" in text

    def test_docker_logs_hint_has_no_sudo_when_in_docker_group(self):
        lines = build_next_steps(
            ip_literal="", has_domain=True, install_dir="/home/user/pm",
            docker_cmd=["docker"],
        )
        text = "\n".join(lines)
        assert "docker logs primitivemail -f" in text
        assert "sudo docker logs" not in text


# ===========================================================================
# Event webhook URL validation
# ===========================================================================

class TestValidateEventWebhookUrl:

    @pytest.mark.parametrize("url", [
        "http://localhost:3000/hook",
        "http://127.0.0.1/hook",
        "https://ingest.example.com/webhooks/primitive",
        "http://host.docker.internal:4000/",
    ])
    def test_valid_urls(self, url):
        assert validate_event_webhook_url(url) is True

    @pytest.mark.parametrize("url", [
        "",
        "not a url",
        "ftp://example.com/hook",
        "example.com/hook",        # no scheme
        "https://",                 # scheme but no host
        "file:///etc/passwd",
    ])
    def test_invalid_urls(self, url):
        assert validate_event_webhook_url(url) is False


# ===========================================================================
# Event webhook surfaces in config summary
# ===========================================================================

class TestConfigSummaryEventWebhook:

    def test_event_webhook_line_shown_when_set(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="",
            event_webhook_url="https://ingest.example.com/hook",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "Event webhook" in text
        assert "https://ingest.example.com/hook" in text

    def test_event_webhook_hidden_when_empty(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="", event_webhook_url="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "Event webhook" not in text


# ===========================================================================
# Observability disclosure in config summary
# ===========================================================================

class TestConfigSummaryObservability:
    """Naive-agent feedback: an Alloy/postfix-exporter telemetry stack used
    to start unconditionally on every install with no opt-out flag and no
    mention in the install summary. Phase 1 of the fix gates those services
    behind a compose profile AND surfaces the state in the install summary.
    These tests pin the disclosure lines so a refactor cannot silently drop
    the remediation text."""

    def test_disclosure_disabled_by_default(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="", event_webhook_url="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "Observability:" in text
        assert "disabled (default)" in text
        # Remediation hint is the whole point of the disclosure.
        assert "COMPOSE_PROFILES=observability" in text
        assert "primitive restart" in text
        # And we must not claim it's enabled.
        assert "enabled (Alloy + postfix-exporter)" not in text

    def test_disclosure_enabled_when_profile_active(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="", event_webhook_url="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
            observability_enabled=True,
        )
        text = "\n".join(lines)
        assert "Observability:" in text
        assert "enabled (Alloy + postfix-exporter)" in text
        # When enabled, the remediation block is silenced.
        assert "disabled (default)" not in text
        assert "COMPOSE_PROFILES=observability" not in text


# ===========================================================================
# JSON output mode
# ===========================================================================

class TestJsonMode:

    def test_json_event_noop_when_disabled(self, capsys):
        from installer import ui
        # Ensure mode is off (module default)
        if ui.JSON_MODE:
            pytest.skip("test requires JSON_MODE off; earlier test leaked state")
        ui.json_event("step", name="config", status="ok")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_json_event_writes_ndjson(self, capsys):
        import json as _json
        from installer import ui
        ui.enable_json_mode()
        try:
            ui.json_event("step", name="config", status="ok")
            ui.json_event("done", install_dir="/tmp/x")
            captured = capsys.readouterr()
            lines = [l for l in captured.out.strip().split("\n") if l]
            assert len(lines) == 2
            first = _json.loads(lines[0])
            assert first == {"event": "step", "name": "config", "status": "ok"}
            second = _json.loads(lines[1])
            assert second == {"event": "done", "install_dir": "/tmp/x"}
        finally:
            # Reset module-level state so later tests see a clean slate.
            import sys
            ui.JSON_MODE = False
            if ui._JSON_STDOUT is not None:
                sys.stdout = ui._JSON_STDOUT
                ui._JSON_STDOUT = None

    def test_human_helpers_go_to_stderr_in_json_mode(self, capsys):
        from installer import ui
        ui.enable_json_mode()
        try:
            ui.info("a note")
            ui.success("good")
            captured = capsys.readouterr()
            assert captured.out == ""
            assert "a note" in captured.err
            assert "good" in captured.err
        finally:
            import sys
            ui.JSON_MODE = False
            if ui._JSON_STDOUT is not None:
                sys.stdout = ui._JSON_STDOUT
                ui._JSON_STDOUT = None

    def test_run_with_progress_emits_error_not_step_fail(self, capsys):
        # Contract: run_with_progress emits an `error` event keyed on step_name
        # when the subprocess fails in JSON mode. It deliberately does NOT emit
        # step:fail — that's the caller's responsibility (see start_server's
        # try/except SystemExit around the HeartbeatTicker). Emitting step:fail
        # here would (a) duplicate when the caller also emits it, and (b) race
        # a trailing heartbeat from the still-running ticker thread.
        import json as _json
        from installer import ui

        ui.enable_json_mode()
        try:
            # `sh -c 'exit 1'` is portable across macOS and Linux CI
            # (macOS has /usr/bin/false, not /bin/false).
            with pytest.raises(SystemExit) as exc:
                ui.run_with_progress(
                    ["sh", "-c", "exit 1"], "Building", step_name="build",
                )
            assert exc.value.code == 1

            captured = capsys.readouterr()
            lines = [l for l in captured.out.strip().split("\n") if l]
            events = [_json.loads(l) for l in lines]

            # Error event fires with the contract step name (not label.lower()).
            error_events = [
                e for e in events
                if e.get("event") == "error" and e.get("step") == "build"
            ]
            assert len(error_events) == 1, f"expected one error event, got {events}"

            # No step:fail emitted by run_with_progress — the caller owns that.
            fail_events = [
                e for e in events
                if e.get("event") == "step" and e.get("status") == "fail"
            ]
            assert fail_events == [], f"unexpected step:fail from run_with_progress: {fail_events}"
        finally:
            import sys
            ui.JSON_MODE = False
            if ui._JSON_STDOUT is not None:
                sys.stdout = ui._JSON_STDOUT
                ui._JSON_STDOUT = None

    def test_error_does_not_auto_emit_json_event(self, capsys):
        # Regression: ui.error() used to auto-emit `event: error` on every
        # call, which polluted successful runs where a recoverable error
        # path called ui.error() without exiting. Callers must now emit
        # json_event("error", ...) explicitly at terminal-exit sites.
        import json as _json
        from installer import ui
        ui.enable_json_mode()
        try:
            ui.error("something went wrong but we recovered")
            captured = capsys.readouterr()
            # Nothing on stdout — no stray NDJSON
            assert captured.out == ""
            # Human-readable line went to stderr
            assert "something went wrong" in captured.err
            # Explicit call DOES emit
            ui.json_event("error", step="config", message="explicit")
            captured = capsys.readouterr()
            line = captured.out.strip()
            parsed = _json.loads(line)
            assert parsed == {"event": "error", "step": "config", "message": "explicit"}
        finally:
            import sys
            ui.JSON_MODE = False
            if ui._JSON_STDOUT is not None:
                sys.stdout = ui._JSON_STDOUT
                ui._JSON_STDOUT = None


# ===========================================================================
# HeartbeatTicker
# ===========================================================================

class TestHeartbeatTicker:
    """The ticker emits step_progress events so agents consuming --json
    can tell "progressing" from "hung" during long steps (build, waits)."""

    @staticmethod
    def _reset_json_mode():
        import sys
        from installer import ui
        ui.JSON_MODE = False
        if ui._JSON_STDOUT is not None:
            sys.stdout = ui._JSON_STDOUT
            ui._JSON_STDOUT = None

    def test_fires_during_long_step(self, capsys):
        import json as _json
        import time as _time
        from installer import ui

        ui.enable_json_mode()
        try:
            with ui.HeartbeatTicker("build", interval=0.1):
                _time.sleep(0.35)
            captured = capsys.readouterr()
            events = [
                _json.loads(l) for l in captured.out.strip().split("\n") if l
            ]
            progress = [e for e in events if e["event"] == "step_progress"]
            # Should emit at ~0.1s, ~0.2s, ~0.3s
            assert len(progress) >= 2, progress
            for e in progress:
                assert e["name"] == "build"
                assert isinstance(e["elapsed_sec"], int)
                assert e["elapsed_sec"] >= 0
        finally:
            self._reset_json_mode()

    def test_silent_on_fast_step(self, capsys):
        # Step that finishes well before the first interval emits zero events.
        import time as _time
        from installer import ui

        ui.enable_json_mode()
        try:
            with ui.HeartbeatTicker("config", interval=5.0):
                _time.sleep(0.05)
            captured = capsys.readouterr()
            assert "step_progress" not in captured.out
        finally:
            self._reset_json_mode()

    def test_no_events_after_context_exit(self, capsys):
        # Contract: no step_progress fires after the with-block exits, even
        # if a subsequent interval would have been due.
        import json as _json
        import time as _time
        from installer import ui

        ui.enable_json_mode()
        try:
            with ui.HeartbeatTicker("wait_container", interval=0.1):
                _time.sleep(0.25)
            # Wait past multiple intervals — ticker must be stopped.
            _time.sleep(0.5)
            captured = capsys.readouterr()
            events = [
                _json.loads(l) for l in captured.out.strip().split("\n") if l
            ]
            progress = [e for e in events if e["event"] == "step_progress"]
            # We had ~2 ticks inside the with. After exit, we waited for 5
            # more intervals — none of them should have emitted.
            assert len(progress) <= 3, progress
            # Sanity: every elapsed_sec is from inside the with (~0.25s max).
            for e in progress:
                assert e["elapsed_sec"] < 2
        finally:
            self._reset_json_mode()

    def test_noop_when_json_mode_off(self, capsys):
        # Non-JSON mode: ticker spawns no thread, emits nothing.
        import time as _time
        from installer import ui

        assert not ui.JSON_MODE  # module default
        with ui.HeartbeatTicker("build", interval=0.05) as t:
            _time.sleep(0.15)
            assert t._thread is None
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_no_heartbeat_after_step_fail_under_forced_race(self, capsys, monkeypatch):
        # Deterministic race reproduction: monkeypatch _tick to sleep 0.3s
        # between wait() returning and the emit, widening the race window
        # from microseconds to something a test can observe. Then run the
        # CORRECT pattern (step:fail after with-exit) and assert no
        # trailing heartbeat.
        #
        # Without the fix (step:fail inside the with-block), the main
        # thread's step:fail emission happens DURING the ticker's 0.3s
        # pre-emit sleep, and the ticker's later emit lands after step:fail
        # — the exact bug greptile flagged. With the fix, __exit__'s join
        # blocks for that 0.3s until the ticker completes its in-flight
        # emit, THEN step:fail is emitted. Ordering preserved.
        import json as _json
        import time as _time
        from installer import ui

        original_tick = ui.HeartbeatTicker._tick

        def slow_tick(self):
            # Reproduce the exact race: between wait() returning and the
            # json_event call, insert a long enough sleep that the main
            # thread can raise + stop.set() + begin join before we emit.
            while not self._stop.wait(self._interval):
                elapsed = int(_time.monotonic() - (self._started_at or 0))
                _time.sleep(0.3)   # the race window, widened
                ui.json_event(
                    "step_progress", name=self._name, elapsed_sec=elapsed,
                )

        monkeypatch.setattr(ui.HeartbeatTicker, "_tick", slow_tick)

        ui.enable_json_mode()
        try:
            ui.json_event("step", name="build", status="start")
            try:
                with ui.HeartbeatTicker("build", interval=0.05):
                    # 0.08s lets the ticker fire wait() once (0.05s) and
                    # enter its 0.3s pre-emit sleep. We then raise — at
                    # this exact moment the ticker is past wait() but
                    # pre-emit: the race window is wide open.
                    _time.sleep(0.08)
                    raise SystemExit(1)
            except SystemExit:
                # __exit__'s join() MUST have waited for the ticker to
                # finish its in-flight emit before returning, so that this
                # step:fail emission is guaranteed to land AFTER any
                # heartbeat the ticker was mid-way through.
                ui.json_event("step", name="build", status="fail")

            captured = capsys.readouterr()
            events = [_json.loads(l) for l in captured.out.strip().split("\n") if l]
            fail_idx = next(
                i for i, e in enumerate(events)
                if e.get("event") == "step" and e.get("status") == "fail"
            )
            # The actual regression check: nothing after step:fail.
            trailing = [
                e for e in events[fail_idx + 1:]
                if e.get("event") == "step_progress"
            ]
            assert trailing == [], (
                f"fix failed — trailing heartbeat landed after step:fail: "
                f"{trailing}"
            )
            # Non-vacuous: the ticker's in-flight heartbeat DID fire. If
            # this assertion ever drops to zero, the monkeypatch is
            # broken and the test isn't exercising the race.
            preceding = [
                e for e in events[:fail_idx]
                if e.get("event") == "step_progress"
            ]
            assert len(preceding) >= 1, (
                f"test vacuous — ticker never fired: {events}"
            )
        finally:
            monkeypatch.setattr(ui.HeartbeatTicker, "_tick", original_tick)
            self._reset_json_mode()

    def test_no_heartbeat_after_step_fail_in_caller_pattern(self, capsys):
        # Pattern-level regression for the common (unforced) timing case.
        # The deterministic race is covered by the _under_forced_race test
        # above; this one locks in the try/except SystemExit shape used by
        # start_server so a refactor that removes the try/except would be
        # caught here.
        import json as _json
        import time as _time
        from installer import ui

        ui.enable_json_mode()
        try:
            ui.json_event("step", name="build", status="start")
            try:
                with ui.HeartbeatTicker("build", interval=0.1):
                    _time.sleep(0.25)   # let a couple heartbeats fire
                    raise SystemExit(1)
            except SystemExit:
                ui.json_event("step", name="build", status="fail")
            # Give a rogue trailing heartbeat plenty of time to surface.
            _time.sleep(0.3)

            captured = capsys.readouterr()
            events = [_json.loads(l) for l in captured.out.strip().split("\n") if l]
            fail_idx = next(
                i for i, e in enumerate(events)
                if e.get("event") == "step" and e.get("status") == "fail"
            )
            # Invariant: nothing but step:fail (and any explicit later events)
            # after the terminal. No step_progress.
            trailing_heartbeats = [
                e for e in events[fail_idx + 1:]
                if e.get("event") == "step_progress"
            ]
            assert trailing_heartbeats == [], (
                f"step_progress fired after step:fail (contract violation): "
                f"{trailing_heartbeats}"
            )
            # Proof heartbeats WERE firing — otherwise the test is vacuous.
            preceding_heartbeats = [
                e for e in events[:fail_idx]
                if e.get("event") == "step_progress"
            ]
            assert len(preceding_heartbeats) >= 1, (
                f"expected at least one heartbeat before fail; got {events}"
            )
        finally:
            self._reset_json_mode()


# ===========================================================================
# parse_args behavior
# ===========================================================================

class TestParseArgsImplications:

    def test_claim_subdomain_implies_no_prompt(self, monkeypatch):
        # --claim-subdomain is a "the agent wants us to assign a domain" signal;
        # going through the interactive flow would let the user set a real
        # domain which would then be clobbered by the post-start claim step.
        from installer.main import parse_args
        monkeypatch.setattr("sys.argv", ["installer", "--claim-subdomain"])
        args = parse_args()
        assert args.claim_subdomain is True
        assert args.no_prompt is True

    def test_json_implies_no_prompt(self, monkeypatch):
        from installer.main import parse_args
        monkeypatch.setattr("sys.argv", ["installer", "--json"])
        args = parse_args()
        assert args.json_output is True
        assert args.no_prompt is True

    def test_bare_invocation_stays_interactive(self, monkeypatch):
        from installer.main import parse_args
        monkeypatch.setattr("sys.argv", ["installer"])
        args = parse_args()
        assert args.no_prompt is False
        assert args.claim_subdomain is False
        assert args.json_output is False


# ===========================================================================
# _observability_is_enabled helper
# ===========================================================================

class TestObservabilityEnabledDetection:
    """The installer picks up pre-set COMPOSE_PROFILES from the environment
    so a user who set it before running install.sh gets truthful summary
    output. Phase 1 installs never write COMPOSE_PROFILES from the cfg,
    so fresh installs always resolve to False."""

    def test_fresh_install_is_disabled(self, monkeypatch):
        from installer.main import _observability_is_enabled
        monkeypatch.delenv("COMPOSE_PROFILES", raising=False)
        assert _observability_is_enabled({}) is False

    def test_env_profiles_including_observability_is_enabled(self, monkeypatch):
        from installer.main import _observability_is_enabled
        monkeypatch.setenv("COMPOSE_PROFILES", "observability")
        assert _observability_is_enabled({}) is True

    def test_env_profiles_comma_separated_is_parsed(self, monkeypatch):
        # Users can stack profiles. Ours must survive alongside custom ones.
        from installer.main import _observability_is_enabled
        monkeypatch.setenv("COMPOSE_PROFILES", "my-custom,observability,another")
        assert _observability_is_enabled({}) is True

    def test_env_profiles_without_observability_is_disabled(self, monkeypatch):
        from installer.main import _observability_is_enabled
        monkeypatch.setenv("COMPOSE_PROFILES", "my-custom,another")
        assert _observability_is_enabled({}) is False

    def test_env_profile_whitespace_tolerated(self, monkeypatch):
        # Operator-edited .env often has stray spaces. Be tolerant.
        from installer.main import _observability_is_enabled
        monkeypatch.setenv("COMPOSE_PROFILES", "  observability  ,  extra  ")
        assert _observability_is_enabled({}) is True

    def test_cfg_value_overrides_env(self, monkeypatch):
        # When the cfg dict carries an explicit value (Phase 2 territory),
        # prefer it over the env so the installer can surface what it
        # just wrote even if an ambient env var says otherwise.
        from installer.main import _observability_is_enabled
        monkeypatch.setenv("COMPOSE_PROFILES", "observability")
        assert _observability_is_enabled({"compose_profiles": "my-custom"}) is False


# ===========================================================================
# Preflight
# ===========================================================================

class TestPreflight:
    """Preflight emits a single JSON object with a stable shape. The check
    bodies are integration-tested against real infra (they hit /proc, network,
    docker) — these tests pin the wrapper's schema."""

    def test_run_all_has_expected_shape(self):
        from installer import preflight
        result = preflight.run_all()
        assert result["event"] == "preflight"
        assert result["overall"] in ("ok", "fail")
        assert isinstance(result["failed"], list)
        assert set(result["checks"].keys()) == {
            "ram", "disk", "port_25_inbound", "outbound_https", "docker",
        }
        # Every check must have a status
        for name, check in result["checks"].items():
            assert "status" in check, f"{name} missing status"
            assert check["status"] in ("ok", "fail", "skip"), (
                f"{name} has unexpected status {check['status']}"
            )

    def test_overall_fail_iff_any_check_fails(self):
        from installer import preflight
        result = preflight.run_all()
        has_fail = any(c.get("status") == "fail" for c in result["checks"].values())
        if has_fail:
            assert result["overall"] == "fail"
            assert len(result["failed"]) > 0
        else:
            assert result["overall"] == "ok"
            assert result["failed"] == []

    def test_disk_check_respects_install_dir_parent(self, tmp_path, monkeypatch):
        # Install dir doesn't exist yet — check should walk up to an ancestor
        # that does, not error out.
        from installer import preflight
        fake_dir = tmp_path / "does" / "not" / "exist"
        monkeypatch.setenv("PRIMITIVEMAIL_DIR", str(fake_dir))
        result = preflight.check_disk()
        assert result["status"] in ("ok", "fail")
        # Path resolved to an existing ancestor
        assert os.path.exists(result["path"])

    def test_disk_check_bare_relative_path_does_not_fall_to_root(self, tmp_path, monkeypatch):
        # Regression: a bare relative name like "primitivemail" (no ./) used
        # to fall through to "/" because os.path.dirname("primitivemail") == ""
        # exited the walk-up loop with an empty probe. Check now normalizes
        # via abspath first so the probe becomes a cwd-anchored path, never "/".
        #
        # Cubic flagged an earlier version: "path exists + isabs" also passes
        # for "/", so the assertion was vacuous. Strengthened: assert the
        # resolved path is a descendant of cwd (tmp_path), proving the fix
        # actually routed through abspath instead of the root fallback.
        from installer import preflight
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("PRIMITIVEMAIL_DIR", "primitivemail")  # bare relative
        result = preflight.check_disk()
        assert result["status"] in ("ok", "fail")
        probe = result["path"]
        # The whole point: not "/" and not any other absolute path unrelated
        # to our input. After abspath("primitivemail") + walk-up, the probe
        # should be tmp_path itself (its parent exists; primitivemail/ does not).
        assert probe == str(tmp_path.resolve()), (
            f"bare relative resolved to {probe!r}, expected {tmp_path.resolve()!r} "
            f"— regression: root fallback likely fired"
        )


# ===========================================================================
# _docker_cmd: sudo detection for docker calls from the Python installer
# ===========================================================================

class TestDockerCmd:
    """`get.docker.com` doesn't add the invoking user to the docker group,
    so on fresh VPS installs `docker info` hits EACCES on the socket. The
    installer now detects this at the install.sh layer (sets DOCKER_CMD env)
    and in the Python layer (auto-detect fallback). These tests pin that
    contract so a future refactor doesn't accidentally drop the sudo path."""

    def setup_method(self):
        # _docker_cmd caches its first resolution. Reset per-test so each
        # test sees a clean detect path — without this, test ordering
        # would silently affect outcomes (whichever test ran first would
        # poison the cache for the rest).
        from installer import server
        server._DOCKER_CMD_CACHED = None

    def test_env_var_parsed_and_split(self, monkeypatch):
        from installer import server
        monkeypatch.setenv("DOCKER_CMD", "sudo docker")
        assert server._docker_cmd() == ["sudo", "docker"]

    def test_env_var_plain_docker(self, monkeypatch):
        from installer import server
        monkeypatch.setenv("DOCKER_CMD", "docker")
        assert server._docker_cmd() == ["docker"]

    def test_auto_detect_direct_access(self, monkeypatch):
        # No DOCKER_CMD env → auto-detect. When `docker info` returns 0,
        # use plain docker.
        from installer import server
        monkeypatch.delenv("DOCKER_CMD", raising=False)

        class FakeResult:
            returncode = 0

        monkeypatch.setattr(server.subprocess, "run", lambda *a, **kw: FakeResult())
        assert server._docker_cmd() == ["docker"]

    def test_auto_detect_falls_back_to_sudo(self, monkeypatch):
        # When `docker info` returns non-zero (EACCES on the socket), fall
        # back to `sudo docker` — exactly the naive-agent VPS scenario.
        from installer import server
        monkeypatch.delenv("DOCKER_CMD", raising=False)

        class FakeResult:
            returncode = 1

        monkeypatch.setattr(server.subprocess, "run", lambda *a, **kw: FakeResult())
        assert server._docker_cmd() == ["sudo", "docker"]

    def test_auto_detect_handles_subprocess_exception(self, monkeypatch):
        # subprocess.run can throw (e.g. FileNotFoundError if docker isn't
        # in PATH, which shouldn't happen after check_docker but let's be
        # defensive). Fall back to sudo docker.
        from installer import server
        monkeypatch.delenv("DOCKER_CMD", raising=False)

        def boom(*a, **kw):
            raise FileNotFoundError("docker not found")

        monkeypatch.setattr(server.subprocess, "run", boom)
        assert server._docker_cmd() == ["sudo", "docker"]

    def test_result_is_cached_after_first_call(self, monkeypatch):
        # wait_for_container/smtp call _docker_cmd up to 35 times during
        # their polling loops. Without caching, each call re-spawns
        # `docker info` when DOCKER_CMD isn't set — 35 extra subprocesses
        # on every install. Cache ensures one detect, one subprocess.
        from installer import server
        monkeypatch.delenv("DOCKER_CMD", raising=False)
        call_count = {"n": 0}

        class FakeResult:
            returncode = 0

        def counting_run(*a, **kw):
            call_count["n"] += 1
            return FakeResult()

        monkeypatch.setattr(server.subprocess, "run", counting_run)
        # Call many times; subprocess.run must fire only once.
        for _ in range(10):
            assert server._docker_cmd() == ["docker"]
        assert call_count["n"] == 1, f"expected 1 subprocess.run, got {call_count['n']}"

    def test_returned_list_is_defensive_copy(self, monkeypatch):
        # Callers do `_docker_cmd() + ["subcmd", ...]` — if they ever
        # mutated the return value instead, a cached reference would get
        # polluted. Return a fresh list each call to prevent that.
        from installer import server
        monkeypatch.setenv("DOCKER_CMD", "sudo docker")
        a = server._docker_cmd()
        b = server._docker_cmd()
        assert a == b
        assert a is not b  # different instances
        a.append("x")
        assert server._docker_cmd() == ["sudo", "docker"]  # still clean


# ===========================================================================
# run_with_progress non-TTY spinner bypass
# ===========================================================================

class TestRunWithProgressNonTty:
    """When stderr isn't a TTY, the braille spinner can't redraw in place
    via \\r — each frame becomes a new line and fills install logs with
    thousands of "Building (Ns)" frames (the naive agent saw ~1100 in
    ~62 KB). The non-TTY path emits a single start + complete line pair
    instead. These tests lock that contract in."""

    def test_non_tty_success_emits_start_and_complete(self, capsys, monkeypatch):
        from installer import ui

        # Fake stderr as non-TTY for this test only.
        class FakeStderr:
            def __init__(self, real):
                self._real = real
            def isatty(self):
                return False
            def write(self, s):
                return self._real.write(s)
            def flush(self):
                return self._real.flush()

        monkeypatch.setattr(ui.sys, "stderr", FakeStderr(sys.stderr))
        ui.run_with_progress(["sh", "-c", "exit 0"], "Building")
        captured = capsys.readouterr()
        # _human_out + print go to stdout in non-JSON mode (the sys.stdout
        # swap only happens when JSON_MODE is enabled).
        combined = captured.out + captured.err
        assert "Building..." in combined
        assert "Building complete" in combined
        # No braille spinner characters anywhere.
        for frame_char in "\u280b\u2819\u2839\u283c\u2834":
            assert frame_char not in combined, (
                f"spinner frame {frame_char!r} leaked in non-TTY mode"
            )

    def test_non_tty_failure_prints_tail_and_exits(self, capsys, monkeypatch):
        from installer import ui

        class FakeStderr:
            def __init__(self, real):
                self._real = real
            def isatty(self):
                return False
            def write(self, s):
                return self._real.write(s)
            def flush(self):
                return self._real.flush()

        monkeypatch.setattr(ui.sys, "stderr", FakeStderr(sys.stderr))
        with pytest.raises(SystemExit) as exc:
            ui.run_with_progress(
                ["sh", "-c", "echo tail_line_one; echo tail_line_two; exit 2"],
                "Building",
            )
        assert exc.value.code == 1  # run_with_progress normalizes non-zero to 1

        captured = capsys.readouterr()
        combined = captured.out + captured.err
        # Failure marker + subprocess tail both written; both go to stdout
        # here (JSON-mode sys.stdout swap isn't active outside JSON mode).
        assert "Building failed" in combined
        assert "tail_line_one" in combined
        assert "tail_line_two" in combined
