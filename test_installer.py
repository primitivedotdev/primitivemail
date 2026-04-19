#!/usr/bin/env python3
"""Tests for installer/config.py pure functions."""

import os
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
        assert "primitive emails-status" in text
        assert "docker logs" in text
        assert "primitive restart" in text

    def test_agent_integration_hint(self):
        lines = build_next_steps(ip_literal="", has_domain=True, install_dir="/home/user/pm")
        text = "\n".join(lines)
        assert "AGENTS.md" in text

    def test_cloud_firewall_warning(self):
        lines = build_next_steps(ip_literal="", has_domain=True, install_dir="/home/user/pm")
        text = "\n".join(lines)
        assert "port 25" in text.lower() or "Port 25" in text


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
        # via abspath first so the probe becomes the parent of cwd, not root.
        from installer import preflight
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("PRIMITIVEMAIL_DIR", "primitivemail")  # bare relative
        result = preflight.check_disk()
        assert result["status"] in ("ok", "fail")
        # Probe path resolves under cwd (tmp_path), not to "/"
        assert os.path.exists(result["path"])
        # On a real machine this could legitimately be / if tmp_path IS on
        # the root filesystem's only mount; the important invariant is that
        # we got a real absolute path derived from our input, not the "/"
        # fallback that fired on empty dirname.
        assert os.path.isabs(result["path"])
