#!/usr/bin/env python3
"""Tests for installer/config.py pure functions."""

import pytest
from unittest.mock import patch, MagicMock

from installer.config import (
    detect_public_ip,
    generate_env_content,
    generate_webhook_secret,
    validate_spoof_protection,
    map_spoof_choice,
    should_warn_sender_filtering,
    build_config_summary,
    build_dns_instructions,
    build_next_steps,
    resolve_non_interactive_defaults,
)
from installer import server


# ===========================================================================
# .env generation
# ===========================================================================

class TestGenerateEnvContent:

    def test_basic_domain_setup(self):
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="", webhook_secret="",
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
            allowed_sender_domains="trusted.org,example.net",
            allowed_senders="alerts@github.com",
            allowed_recipients="inbox@example.com",
            spoof_protection="standard",
        )
        assert "ALLOWED_SENDER_DOMAINS=trusted.org,example.net" in result
        assert "ALLOWED_SENDERS=alerts@github.com" in result
        assert "ALLOWED_RECIPIENTS=inbox@example.com" in result
        assert "SPOOF_PROTECTION=standard" in result

    def test_exactly_11_lines(self):
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="", webhook_secret="",
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        assert len(result.strip().split("\n")) == 11

    def test_no_quoting(self):
        result = generate_env_content(
            hostname="mx.example.com", domain="example.com",
            enable_ip_literal=False, ip_literal="",
            webhook_url="https://example.com/hook", webhook_secret="s3cret",
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
            webhook_url="", allowed_sender_domains="",
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
            webhook_url="", allowed_sender_domains="",
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
            allowed_sender_domains="", allowed_senders="",
            allowed_recipients="", spoof_protection="off",
        )
        text = "\n".join(lines)
        assert "Webhook" in text

    def test_standalone_mode(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="",
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
            webhook_url="", allowed_sender_domains="",
            allowed_senders="", allowed_recipients="",
            spoof_protection=level,
        )
        text = "\n".join(lines)
        assert expected in text

    def test_sender_filtering_displayed(self):
        lines = build_config_summary(
            hostname="mx.example.com", domain="example.com",
            ip_literal="", has_domain=True,
            webhook_url="", allowed_sender_domains="trusted.org",
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
            webhook_url="", allowed_sender_domains="",
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
        assert "docker compose logs postfix" in text
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
# Server orchestration helpers
# ===========================================================================

class TestServerHelpers:

    def test_is_compose_plugin(self):
        assert server.is_compose_plugin(["docker", "compose"]) is True
        assert server.is_compose_plugin(["docker-compose"]) is False

    def test_get_local_images_up_args_for_compose_plugin(self):
        assert server.get_local_images_up_args(["docker", "compose"]) == [
            "up", "-d", "--pull", "never",
        ]

    def test_get_local_images_up_args_for_docker_compose_v1(self):
        assert server.get_local_images_up_args(["docker-compose"]) == ["up", "-d"]

    def test_wait_for_container_checks_running_state(self):
        compose_ps = MagicMock(returncode=0, stdout="abc123\n")
        inspect = MagicMock(returncode=0, stdout="true\n")

        with patch("installer.server.subprocess.run", side_effect=[compose_ps, inspect]) as run:
            assert server.wait_for_container(["docker", "compose"], timeout=1) is True

        assert run.call_args_list[0].args[0] == ["docker", "compose", "ps", "-q", "postfix"]
        assert run.call_args_list[1].args[0] == [
            "docker", "inspect", "--format", "{{.State.Running}}", "abc123",
        ]

    def test_wait_for_container_handles_multiple_container_ids(self):
        compose_ps = MagicMock(returncode=0, stdout="old123\nnew456\n")
        stopped_inspect = MagicMock(returncode=0, stdout="false\n")
        running_inspect = MagicMock(returncode=0, stdout="true\n")

        with patch(
            "installer.server.subprocess.run",
            side_effect=[compose_ps, stopped_inspect, running_inspect],
        ) as run:
            assert server.wait_for_container(["docker", "compose"], timeout=1) is True

        assert run.call_args_list[1].args[0] == [
            "docker", "inspect", "--format", "{{.State.Running}}", "old123",
        ]
        assert run.call_args_list[2].args[0] == [
            "docker", "inspect", "--format", "{{.State.Running}}", "new456",
        ]

    def test_restart_retry_uses_local_images_without_pull(self):
        failing_up = MagicMock(returncode=1, stderr=b"pull failed")
        retry_up = MagicMock(returncode=0, stderr=b"")

        with patch("installer.server.get_compose_cmd", return_value=["docker", "compose"]), \
                patch("installer.server.wait_for_container", return_value=True), \
                patch("installer.server.wait_for_smtp", return_value=True), \
                patch("installer.server.ui.warn"), \
                patch("installer.server.ui.success"), \
                patch(
                    "installer.server.subprocess.run",
                    side_effect=[MagicMock(returncode=0), failing_up, retry_up],
                ) as run:
            server.restart("/tmp/primitivemail")

        assert run.call_args_list[2].args[0] == ["docker", "compose", "up", "-d", "--pull", "never"]
