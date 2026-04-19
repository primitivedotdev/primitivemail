#!/usr/bin/env python3
"""Tests for the `primitive` CLI.

The CLI script has no .py extension and is not importable as a regular
module, so load it by path via importlib.
"""

import importlib.util
import os
import pwd
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# The CLI script has no .py extension, so importlib cannot infer a loader.
# Give it SourceFileLoader explicitly.
_CLI_PATH = Path(__file__).parent / "cli" / "primitive"
_SPEC = importlib.util.spec_from_loader(
    "primitive_cli", SourceFileLoader("primitive_cli", str(_CLI_PATH)),
)
primitive_cli = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(primitive_cli)


class TestInvokingUserHomeSudoAware:
    """When a user runs `sudo primitive restart`, sudo sets HOME=/root, so
    `Path.home()` returns `/root` and the CLI looks for `/root/primitivemail`
    which does not exist. These tests pin the sudo-aware fallback: prefer
    the pw_dir of `SUDO_USER` when we are root via sudo, so the CLI finds
    the real install in the invoking user's home."""

    def test_non_root_returns_path_home(self, monkeypatch):
        # Regular (non-sudo) invocation: Path.home() is already correct.
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.setattr(primitive_cli.os, "geteuid", lambda: 1000)
        result = primitive_cli._invoking_user_home()
        assert result == Path.home()

    def test_root_with_sudo_user_resolves_real_home(self, monkeypatch):
        # The exact bug: `sudo primitive restart`. SUDO_USER=ubuntu,
        # euid=0. Expect ubuntu's home (not /root).
        monkeypatch.setenv("SUDO_USER", "ubuntu")
        monkeypatch.setattr(primitive_cli.os, "geteuid", lambda: 0)
        fake_entry = MagicMock(pw_dir="/home/ubuntu")
        monkeypatch.setattr(primitive_cli.pwd, "getpwnam", lambda name: fake_entry)
        result = primitive_cli._invoking_user_home()
        assert result == Path("/home/ubuntu")

    def test_root_without_sudo_user_falls_through(self, monkeypatch):
        # Direct root invocation (no sudo). SUDO_USER is unset. We have
        # no other-user signal, so the caller accepts whatever HOME is.
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.setattr(primitive_cli.os, "geteuid", lambda: 0)
        result = primitive_cli._invoking_user_home()
        assert result == Path.home()

    def test_sudo_user_equals_root_does_not_self_resolve(self, monkeypatch):
        # Edge case: someone ran `sudo -u root primitive ...`. No point
        # re-resolving; fall through to Path.home().
        monkeypatch.setenv("SUDO_USER", "root")
        monkeypatch.setattr(primitive_cli.os, "geteuid", lambda: 0)
        # Even if pwd.getpwnam would succeed, we should not call it.
        boom = MagicMock(side_effect=AssertionError("should not be called"))
        monkeypatch.setattr(primitive_cli.pwd, "getpwnam", boom)
        result = primitive_cli._invoking_user_home()
        assert result == Path.home()

    def test_sudo_user_missing_from_passwd_falls_through(self, monkeypatch):
        # SUDO_USER set but not in /etc/passwd (unusual, but possible in
        # some container setups). Don't crash; fall through to Path.home().
        monkeypatch.setenv("SUDO_USER", "ghost")
        monkeypatch.setattr(primitive_cli.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            primitive_cli.pwd, "getpwnam",
            MagicMock(side_effect=KeyError("ghost")),
        )
        result = primitive_cli._invoking_user_home()
        assert result == Path.home()


class TestGetInstallPathSudoAware:
    """End-to-end check that get_install_path respects the sudo-aware
    resolver. PRIMITIVEMAIL_DIR always wins when set."""

    def test_env_var_wins(self, monkeypatch):
        monkeypatch.setenv("PRIMITIVEMAIL_DIR", "/opt/pm")
        # Sudo resolution should not even be consulted.
        monkeypatch.setattr(
            primitive_cli, "_invoking_user_home",
            MagicMock(side_effect=AssertionError("should not be called")),
        )
        assert primitive_cli.get_install_path() == Path("/opt/pm")

    def test_sudo_to_ubuntu_finds_ubuntu_install(self, monkeypatch):
        # Reproduce the observability-Phase-1 test scenario: user ran
        # `sudo primitive restart` after an install in /home/ubuntu.
        monkeypatch.delenv("PRIMITIVEMAIL_DIR", raising=False)
        monkeypatch.setenv("SUDO_USER", "ubuntu")
        monkeypatch.setattr(primitive_cli.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            primitive_cli.pwd, "getpwnam",
            lambda name: MagicMock(pw_dir="/home/ubuntu"),
        )
        assert primitive_cli.get_install_path() == Path("/home/ubuntu/primitivemail")

    def test_non_sudo_user_gets_own_home(self, monkeypatch):
        # Regular user invocation resolves against $HOME.
        monkeypatch.delenv("PRIMITIVEMAIL_DIR", raising=False)
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.setattr(primitive_cli.os, "geteuid", lambda: 1000)
        monkeypatch.setenv("HOME", "/home/alice")
        assert primitive_cli.get_install_path() == Path("/home/alice/primitivemail")


class TestGetMaildataPathSudoAware:
    """Maildata resolution uses the same sudo-aware helper, plus --path
    and PRIMITIVEMAIL_MAILDATA overrides."""

    def test_path_flag_wins(self, monkeypatch):
        args = MagicMock(path="/tmp/explicit")
        assert primitive_cli.get_maildata_path(args) == Path("/tmp/explicit")

    def test_env_var_second_priority(self, monkeypatch):
        monkeypatch.setenv("PRIMITIVEMAIL_MAILDATA", "/opt/mail")
        args = MagicMock(path=None)
        assert primitive_cli.get_maildata_path(args) == Path("/opt/mail")

    def test_sudo_to_ubuntu_finds_ubuntu_maildata(self, monkeypatch):
        monkeypatch.delenv("PRIMITIVEMAIL_MAILDATA", raising=False)
        monkeypatch.setenv("SUDO_USER", "ubuntu")
        monkeypatch.setattr(primitive_cli.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            primitive_cli.pwd, "getpwnam",
            lambda name: MagicMock(pw_dir="/home/ubuntu"),
        )
        args = MagicMock(path=None)
        assert primitive_cli.get_maildata_path(args) == Path(
            "/home/ubuntu/primitivemail/maildata",
        )
