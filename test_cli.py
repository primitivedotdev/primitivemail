#!/usr/bin/env python3
"""Tests for the `primitive` CLI.

The CLI script has no .py extension and is not importable as a regular
module, so load it by path via importlib.
"""

import importlib.util
import json
import os
import pwd
import select
import subprocess
import sys
import time
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
        # Edge case: root itself ran `sudo primitive` (root elevating to
        # root via sudo, effectively a no-op). SUDO_USER=root, euid=0. No
        # point re-resolving; fall through to Path.home().
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


# -----------------------------------------------------------------------------
# Shared fixture helpers for the `emails` command group. Builds a minimal,
# spec-accurate maildata tree: a journal with several entries and matching
# `<domain>/<id>.json` canonical files.
# -----------------------------------------------------------------------------


def _make_entry(seq, id_, domain, *, from_addr, received_at, subject="hi", extra=None):
    entry = {
        "seq": seq,
        "id": id_,
        "received_at": received_at,
        "domain": domain,
        "from": f'"{from_addr}" <{from_addr}>',
        "from_address": from_addr,
        "to": f"inbox@{domain}",
        "subject": subject,
        "path": f"{domain}/{id_}.json",
        "attachment_count": 0,
        "attachment_names": [],
    }
    if extra:
        entry.update(extra)
    return entry


def _make_canonical(id_, received_at, *, body_text="body", body_html=None):
    """Flat canonical shape: the watcher writes top-level keys (id,
    received_at, smtp, headers, auth, parsed, content) with NO `email`
    wrapper. The webhook-delivery shape has an `email` envelope; the
    on-disk canonical does not. This fixture matches the on-disk shape
    so `--format text|html` exercises real body access."""
    parsed = {"body_text": body_text}
    if body_html is not None:
        parsed["body_html"] = body_html
    return {
        "id": id_,
        "received_at": received_at,
        "parsed": parsed,
    }


def _seed_maildata(tmp_path, entries_and_bodies, *, extra_canonical=None):
    """entries_and_bodies: list of (entry_dict, canonical_dict_or_None).
    Writes the journal and per-domain canonical JSON files."""
    maildata = tmp_path / "maildata"
    maildata.mkdir()
    journal = maildata / "emails.jsonl"
    with open(journal, "w", encoding="utf-8") as fh:
        for entry, canonical in entries_and_bodies:
            fh.write(json.dumps(entry) + "\n")
            if canonical is not None:
                domain_dir = maildata / entry["domain"]
                domain_dir.mkdir(parents=True, exist_ok=True)
                (domain_dir / f"{entry['id']}.json").write_text(json.dumps(canonical))
    for domain, name, payload in extra_canonical or []:
        domain_dir = maildata / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        (domain_dir / name).write_text(payload)
    return maildata


def _run_cli(maildata, argv, *, capsys=None):
    """Invoke primitive_cli.main() with argv; return (exit_code, out, err)."""
    full_argv = ["primitive", "--path", str(maildata)] + list(argv)
    with patch.object(sys, "argv", full_argv):
        try:
            primitive_cli.main()
            code = 0
        except SystemExit as e:
            code = int(e.code or 0)
    out, err = capsys.readouterr()
    return code, out, err


# -----------------------------------------------------------------------------
# Helpers unit tests
# -----------------------------------------------------------------------------


class TestIterJournal:
    def test_yields_all_entries_in_order(self, tmp_path):
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"), None),
            (_make_entry(2, "20260101T000002Z-aaaaaaa2", "ex.com",
                         from_addr="b@x.com", received_at="2026-01-01T00:00:02Z"), None),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        seqs = [e["seq"] for _, _, e in primitive_cli._iter_journal(maildata / "emails.jsonl")]
        assert seqs == [1, 2]

    def test_since_seq_skips_lower_or_equal(self, tmp_path):
        entries = [
            (_make_entry(i, f"20260101T00000{i}Z-aaaaaaa{i}", "ex.com",
                         from_addr="a@x.com", received_at=f"2026-01-01T00:00:0{i}Z"), None)
            for i in range(1, 5)
        ]
        maildata = _seed_maildata(tmp_path, entries)
        seqs = [e["seq"] for _, _, e in
                primitive_cli._iter_journal(maildata / "emails.jsonl", since_seq=2)]
        assert seqs == [3, 4]

    def test_limit_caps_output(self, tmp_path):
        entries = [
            (_make_entry(i, f"20260101T00000{i}Z-aaaaaaa{i}", "ex.com",
                         from_addr="a@x.com", received_at=f"2026-01-01T00:00:0{i}Z"), None)
            for i in range(1, 6)
        ]
        maildata = _seed_maildata(tmp_path, entries)
        seqs = [e["seq"] for _, _, e in
                primitive_cli._iter_journal(maildata / "emails.jsonl", limit=2)]
        assert seqs == [1, 2]

    def test_corrupt_line_raises_valueerror(self, tmp_path):
        maildata = tmp_path / "maildata"
        maildata.mkdir()
        (maildata / "emails.jsonl").write_text('{"seq":1,"id":"x"}\nnot-json\n')
        with pytest.raises(ValueError, match="corrupt journal line"):
            list(primitive_cli._iter_journal(maildata / "emails.jsonl"))


class TestIsoTimestamp:
    def test_parses_z_suffix(self):
        ts = primitive_cli._iso_timestamp("2026-04-17T10:12:03Z")
        assert ts.year == 2026

    def test_rejects_naive(self):
        with pytest.raises(ValueError, match="UTC"):
            primitive_cli._iso_timestamp("2026-04-17T10:12:03")

    def test_rejects_non_utc_offset(self):
        with pytest.raises(ValueError, match="UTC"):
            primitive_cli._iso_timestamp("2026-04-17T10:12:03+05:00")

    def test_rejects_garbage(self):
        with pytest.raises(ValueError, match="not a valid"):
            primitive_cli._iso_timestamp("notatime")


class TestResolveId:
    """Id resolution is journal-authoritative per doc 08. These tests pin
    the key properties: the `.meta.json` sidecar is never matched as a
    canonical id, and multi-domain collisions exit 3 with `--domain`
    disambiguation available."""

    def test_full_id_no_domain_resolves_via_journal(self, tmp_path):
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical("20260101T000001Z-aaaaaaa1", "2026-01-01T00:00:01Z")),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        domain, id_ = primitive_cli._resolve_id(maildata, "20260101T000001Z-aaaaaaa1")
        assert (domain, id_) == ("ex.com", "20260101T000001Z-aaaaaaa1")

    def test_full_id_with_domain_uses_stat(self, tmp_path):
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical("20260101T000001Z-aaaaaaa1", "2026-01-01T00:00:01Z")),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        domain, id_ = primitive_cli._resolve_id(
            maildata, "20260101T000001Z-aaaaaaa1", domain="ex.com",
        )
        assert (domain, id_) == ("ex.com", "20260101T000001Z-aaaaaaa1")

    def test_not_full_id_exits_2_without_prefix(self, tmp_path):
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical("20260101T000001Z-aaaaaaa1", "2026-01-01T00:00:01Z")),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        with pytest.raises(primitive_cli.ResolveError) as exc:
            primitive_cli._resolve_id(maildata, "2026")
        assert exc.value.exit_code == 2

    def test_multi_domain_full_id_exits_3(self, tmp_path):
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical("20260101T000001Z-aaaaaaa1", "2026-01-01T00:00:01Z")),
            (_make_entry(2, "20260101T000001Z-aaaaaaa1", "ex.net",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical("20260101T000001Z-aaaaaaa1", "2026-01-01T00:00:01Z")),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        with pytest.raises(primitive_cli.ResolveError) as exc:
            primitive_cli._resolve_id(maildata, "20260101T000001Z-aaaaaaa1")
        assert exc.value.exit_code == 3

    def test_prefix_ambiguous_exits_3(self, tmp_path):
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical("20260101T000001Z-aaaaaaa1", "2026-01-01T00:00:01Z")),
            (_make_entry(2, "20260101T000001Z-aaaaaaa2", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:02Z"),
             _make_canonical("20260101T000001Z-aaaaaaa2", "2026-01-01T00:00:02Z")),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        with pytest.raises(primitive_cli.ResolveError) as exc:
            primitive_cli._resolve_id(maildata, "20260101", allow_prefix=True)
        assert exc.value.exit_code == 3

    def test_meta_json_sidecar_never_matches(self, tmp_path):
        """If a domain dir has <id>.meta.json but no <id>.json, `_resolve_id`
        must NOT treat that as a canonical match. The journal has no entry
        for a pre-canonical id; that's doc 05's orphan-canonical window and
        the CLI treats the id as not found (exit 1).
        """
        maildata = tmp_path / "maildata"
        maildata.mkdir()
        (maildata / "emails.jsonl").write_text("")
        dom = maildata / "ex.com"
        dom.mkdir()
        # only sidecar, no canonical .json
        (dom / "20260101T000001Z-aaaaaaa1.meta.json").write_text("{}")
        with pytest.raises(primitive_cli.ResolveError) as exc:
            primitive_cli._resolve_id(maildata, "20260101T000001Z-aaaaaaa1")
        assert exc.value.exit_code == 1

    def test_explicit_domain_with_only_meta_sidecar_exits_3(self, tmp_path):
        """Pre-canonical case: `--domain` given, meta.json exists, json does
        not. This is distinct from "not found" and exits 3 so the caller can
        retry once the watcher has finished."""
        maildata = tmp_path / "maildata"
        maildata.mkdir()
        (maildata / "emails.jsonl").write_text("")
        dom = maildata / "ex.com"
        dom.mkdir()
        (dom / "20260101T000001Z-aaaaaaa1.meta.json").write_text("{}")
        with pytest.raises(primitive_cli.ResolveError) as exc:
            primitive_cli._resolve_id(
                maildata, "20260101T000001Z-aaaaaaa1", domain="ex.com",
            )
        assert exc.value.exit_code == 3


# -----------------------------------------------------------------------------
# `emails list` command
# -----------------------------------------------------------------------------


class TestEmailsList:
    @pytest.fixture
    def seeded(self, tmp_path):
        entries = []
        for i in range(1, 6):
            id_ = f"20260417T10120{i}Z-aaaaaaa{i}"
            entries.append((
                _make_entry(i, id_, "ex.com" if i % 2 else "ex.net",
                            from_addr="billing@stripe.com" if i == 3 else f"u{i}@x.com",
                            received_at=f"2026-04-17T10:12:0{i}Z",
                            subject=f"msg {i}"),
                _make_canonical(id_, f"2026-04-17T10:12:0{i}Z"),
            ))
        return _seed_maildata(tmp_path, entries)

    def test_default_limit_is_twenty_and_human_format(self, seeded, capsys):
        code, out, _ = _run_cli(seeded, ["emails", "list"], capsys=capsys)
        assert code == 0
        # Header + 5 rows.
        lines = out.strip().splitlines()
        assert lines[0].startswith("seq")
        assert len(lines) == 6

    def test_limit(self, seeded, capsys):
        code, out, _ = _run_cli(seeded, ["emails", "list", "--limit", "2"], capsys=capsys)
        assert code == 0
        lines = out.strip().splitlines()
        assert len(lines) == 3  # header + 2 rows

    def test_limit_zero_is_unlimited(self, seeded, capsys):
        code, out, _ = _run_cli(seeded, ["emails", "list", "--limit", "0"], capsys=capsys)
        assert code == 0
        lines = out.strip().splitlines()
        assert len(lines) == 6

    def test_negative_limit_exits_2(self, seeded, capsys):
        code, _, err = _run_cli(seeded, ["emails", "list", "--limit", "-1"], capsys=capsys)
        assert code == 2
        assert "--limit" in err

    def test_since_seq_filter(self, seeded, capsys):
        code, out, _ = _run_cli(
            seeded, ["emails", "list", "--since", "3", "--json"], capsys=capsys,
        )
        assert code == 0
        rows = [json.loads(line) for line in out.strip().splitlines()]
        assert [r["seq"] for r in rows] == [4, 5]

    def test_domain_filter(self, seeded, capsys):
        code, out, _ = _run_cli(
            seeded, ["emails", "list", "--domain", "ex.net", "--json"], capsys=capsys,
        )
        assert code == 0
        rows = [json.loads(line) for line in out.strip().splitlines()]
        assert [r["seq"] for r in rows] == [2, 4]

    def test_from_substring_filter(self, seeded, capsys):
        code, out, _ = _run_cli(
            seeded, ["emails", "list", "--from", "stripe.com", "--json"], capsys=capsys,
        )
        assert code == 0
        rows = [json.loads(line) for line in out.strip().splitlines()]
        assert len(rows) == 1
        assert rows[0]["from_address"] == "billing@stripe.com"

    def test_json_matches_journal_line_shape(self, seeded, capsys):
        code, out, _ = _run_cli(seeded, ["emails", "list", "--json"], capsys=capsys)
        assert code == 0
        first = json.loads(out.splitlines()[0])
        # Required journal fields from AGENTS.md.
        for field in ("seq", "id", "received_at", "domain", "from_address", "path"):
            assert field in first

    def test_maildata_missing_exits_1(self, tmp_path, capsys):
        code, _, err = _run_cli(tmp_path / "nope", ["emails", "list"], capsys=capsys)
        assert code == 1
        assert "No maildata directory" in err

    def test_tombstone_is_skipped(self, tmp_path, capsys):
        """Forward-compatibility for doc 22's tombstone schema. list() must
        skip `type:"tombstone"` lines, count them nowhere."""
        id1 = "20260101T000001Z-aaaaaaa1"
        entries = [(
            _make_entry(1, id1, "ex.com",
                        from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
            _make_canonical(id1, "2026-01-01T00:00:01Z"),
        )]
        maildata = _seed_maildata(tmp_path, entries)
        # Hand-append a tombstone line so the fixture does not need a real
        # canonical file for seq 2.
        with open(maildata / "emails.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "seq": 2, "type": "tombstone",
                "id": "20260101T000002Z-aaaaaaa2", "domain": "ex.com",
                "deleted_at": "2026-01-02T00:00:00Z",
            }) + "\n")
        code, out, _ = _run_cli(maildata, ["emails", "list", "--json"], capsys=capsys)
        assert code == 0
        rows = [json.loads(l) for l in out.strip().splitlines()]
        assert len(rows) == 1
        assert rows[0]["seq"] == 1

    def test_corrupt_journal_exits_5(self, tmp_path, capsys):
        maildata = tmp_path / "maildata"
        maildata.mkdir()
        (maildata / "emails.jsonl").write_text(
            '{"seq":1,"id":"20260101T000001Z-aaaaaaa1","domain":"ex.com",'
            '"from_address":"a@x.com","received_at":"2026-01-01T00:00:01Z",'
            '"path":"ex.com/x.json","attachment_count":0,"attachment_names":[],'
            '"subject":"x","from":null,"to":null}\n'
            "not-json-this-is-corruption\n"
        )
        code, _, err = _run_cli(maildata, ["emails", "list", "--json"], capsys=capsys)
        assert code == 5
        assert "corrupt journal" in err


# -----------------------------------------------------------------------------
# `emails read` command
# -----------------------------------------------------------------------------


class TestEmailsRead:
    @pytest.fixture
    def seeded(self, tmp_path):
        entries = []
        id_a = "20260417T101201Z-aaaaaaaa"
        id_b = "20260417T101202Z-bbbbbbbb"
        entries.append((
            _make_entry(1, id_a, "ex.com",
                        from_addr="a@x.com", received_at="2026-04-17T10:12:01Z"),
            _make_canonical(id_a, "2026-04-17T10:12:01Z",
                            body_text="hello text", body_html="<p>hi</p>"),
        ))
        entries.append((
            _make_entry(2, id_b, "ex.com",
                        from_addr="b@x.com", received_at="2026-04-17T10:12:02Z"),
            _make_canonical(id_b, "2026-04-17T10:12:02Z", body_text="second"),
        ))
        maildata = _seed_maildata(tmp_path, entries)
        # Seed a raw .eml for id_a so --format raw has content.
        (maildata / "ex.com" / f"{id_a}.eml").write_bytes(b"From: a@x.com\r\n\r\nhi\r\n")
        return maildata, id_a, id_b

    def test_read_json_returns_canonical(self, seeded, capsys):
        maildata, id_a, _ = seeded
        code, out, _ = _run_cli(maildata, ["emails", "read", id_a], capsys=capsys)
        assert code == 0
        event = json.loads(out)
        assert event["id"] == id_a

    def test_read_text_format(self, seeded, capsys):
        maildata, id_a, _ = seeded
        code, out, _ = _run_cli(
            maildata, ["emails", "read", id_a, "--format", "text"], capsys=capsys,
        )
        assert code == 0
        assert out.strip() == "hello text"

    def test_read_html_format(self, seeded, capsys):
        maildata, id_a, _ = seeded
        code, out, _ = _run_cli(
            maildata, ["emails", "read", id_a, "--format", "html"], capsys=capsys,
        )
        assert code == 0
        assert "<p>hi</p>" in out

    def test_read_html_missing_body_exits_1(self, seeded, capsys):
        maildata, _, id_b = seeded
        code, _, err = _run_cli(
            maildata, ["emails", "read", id_b, "--format", "html"], capsys=capsys,
        )
        assert code == 1
        assert "body_html" in err

    def test_read_raw_format_bytes(self, seeded, capsys):
        maildata, id_a, _ = seeded
        code, out, _ = _run_cli(
            maildata, ["emails", "read", id_a, "--format", "raw"], capsys=capsys,
        )
        assert code == 0
        assert "From: a@x.com" in out

    def test_read_raw_missing_exits_1(self, seeded, capsys):
        maildata, _, id_b = seeded
        code, _, err = _run_cli(
            maildata, ["emails", "read", id_b, "--format", "raw"], capsys=capsys,
        )
        assert code == 1
        assert ".eml" in err

    def test_read_nonexistent_exits_1(self, seeded, capsys):
        maildata, _, _ = seeded
        code, _, err = _run_cli(
            maildata, ["emails", "read", "20991231T235959Z-deadbeef"], capsys=capsys,
        )
        assert code == 1
        assert "not found" in err

    def test_read_prefix_without_opt_in_exits_2(self, seeded, capsys):
        maildata, _, _ = seeded
        code, _, _ = _run_cli(maildata, ["emails", "read", "2026"], capsys=capsys)
        assert code == 2

    def test_read_ambiguous_multi_domain_exits_3(self, tmp_path, capsys):
        """Same id under two domains, no --domain: exit 3 per shared scheme."""
        shared_id = "20260101T000001Z-aaaaaaa1"
        entries = [
            (_make_entry(1, shared_id, "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical(shared_id, "2026-01-01T00:00:01Z")),
            (_make_entry(2, shared_id, "ex.net",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical(shared_id, "2026-01-01T00:00:01Z")),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        code, _, err = _run_cli(maildata, ["emails", "read", shared_id], capsys=capsys)
        assert code == 3
        assert "ex.com" in err and "ex.net" in err

    def test_read_with_domain_disambiguates(self, tmp_path, capsys):
        shared_id = "20260101T000001Z-aaaaaaa1"
        entries = [
            (_make_entry(1, shared_id, "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical(shared_id, "2026-01-01T00:00:01Z", body_text="in-com")),
            (_make_entry(2, shared_id, "ex.net",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical(shared_id, "2026-01-01T00:00:01Z", body_text="in-net")),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        code, out, _ = _run_cli(
            maildata, ["emails", "read", shared_id, "--domain", "ex.net",
                       "--format", "text"],
            capsys=capsys,
        )
        assert code == 0
        assert out.strip() == "in-net"

    def test_read_corrupt_canonical_exits_5(self, tmp_path, capsys):
        id_ = "20260101T000001Z-aaaaaaa1"
        entries = [(
            _make_entry(1, id_, "ex.com",
                        from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
            None,  # don't write a canonical via the helper
        )]
        maildata = _seed_maildata(tmp_path, entries)
        dom = maildata / "ex.com"
        dom.mkdir(parents=True, exist_ok=True)
        (dom / f"{id_}.json").write_text("this is not JSON {{{")
        code, _, err = _run_cli(maildata, ["emails", "read", id_], capsys=capsys)
        assert code == 5
        assert str(dom / f"{id_}.json") in err

    def test_read_text_with_missing_parsed_exits_1(self, tmp_path, capsys):
        # Canonical parses as a valid object but has no `parsed` key at
        # all. This is NOT malformed (canonicals may legitimately lack a
        # body during parse-fail recovery). Expect exit 1 ("no body_text
        # on this email"), not a crash.
        id_ = "20260101T000001Z-aaaaaaa1"
        entries = [(
            _make_entry(1, id_, "ex.com",
                        from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
            None,
        )]
        maildata = _seed_maildata(tmp_path, entries)
        dom = maildata / "ex.com"
        dom.mkdir(parents=True, exist_ok=True)
        (dom / f"{id_}.json").write_text(json.dumps({"id": id_}))
        code, _, err = _run_cli(
            maildata, ["emails", "read", id_, "--format", "text"], capsys=capsys,
        )
        assert code == 1
        assert "no body_text" in err

    def test_read_text_with_non_dict_parsed_exits_5(self, tmp_path, capsys):
        # `parsed` is a string instead of an object. Should exit 5 with
        # the malformed-canonical message, not raise AttributeError.
        id_ = "20260101T000001Z-aaaaaaa1"
        entries = [(
            _make_entry(1, id_, "ex.com",
                        from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
            None,
        )]
        maildata = _seed_maildata(tmp_path, entries)
        dom = maildata / "ex.com"
        dom.mkdir(parents=True, exist_ok=True)
        (dom / f"{id_}.json").write_text(
            json.dumps({"id": id_, "parsed": "not-an-object"}),
        )
        code, _, err = _run_cli(
            maildata, ["emails", "read", id_, "--format", "text"], capsys=capsys,
        )
        assert code == 5
        assert "parsed is not an object" in err

    def test_read_text_real_watcher_shape(self, tmp_path, capsys):
        # Regression guard: the real on-disk canonical is flat, NOT wrapped
        # in an `email` envelope. The original code used event["email"]["parsed"]
        # which made text/html broken on every real install even though the
        # test fixtures passed. Fixture now matches the watcher; this test
        # drops a fixture-shape file directly and confirms body extraction.
        id_ = "20260101T000001Z-aaaaaaa1"
        entries = [(
            _make_entry(1, id_, "ex.com",
                        from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
            None,
        )]
        maildata = _seed_maildata(tmp_path, entries)
        dom = maildata / "ex.com"
        dom.mkdir(parents=True, exist_ok=True)
        # Shape sampled from a real watcher-produced canonical.
        (dom / f"{id_}.json").write_text(json.dumps({
            "id": id_,
            "received_at": "2026-01-01T00:00:01Z",
            "smtp": {"mail_from": "a@x.com"},
            "headers": {"subject": "hi"},
            "auth": {"spf": "none"},
            "parsed": {"body_text": "hello world"},
            "content": {},
        }))
        code, out, _ = _run_cli(
            maildata, ["emails", "read", id_, "--format", "text"], capsys=capsys,
        )
        assert code == 0
        assert "hello world" in out


# -----------------------------------------------------------------------------
# `emails since` command
# -----------------------------------------------------------------------------


class TestEmailsSince:
    @pytest.fixture
    def seeded(self, tmp_path):
        entries = [
            (_make_entry(i, f"20260101T00000{i}Z-aaaaaaa{i}", "ex.com",
                         from_addr="a@x.com", received_at=f"2026-01-01T00:00:0{i}Z"), None)
            for i in range(1, 6)
        ]
        return _seed_maildata(tmp_path, entries)

    def test_since_tail_without_follow(self, seeded, capsys):
        code, out, _ = _run_cli(seeded, ["emails", "since", "3"], capsys=capsys)
        assert code == 0
        rows = [json.loads(l) for l in out.strip().splitlines()]
        assert [r["seq"] for r in rows] == [4, 5]

    def test_since_zero_yields_all(self, seeded, capsys):
        code, out, _ = _run_cli(seeded, ["emails", "since", "0"], capsys=capsys)
        assert code == 0
        rows = [json.loads(l) for l in out.strip().splitlines()]
        assert [r["seq"] for r in rows] == [1, 2, 3, 4, 5]

    def test_since_bad_seq_exits_2(self, seeded, capsys):
        code, _, err = _run_cli(seeded, ["emails", "since", "abc"], capsys=capsys)
        assert code == 2
        assert "<seq>" in err

    def test_since_catchup_corruption_reports_last_seq(self, tmp_path, capsys):
        # Catch-up corruption must emit `last_seq=<N>` on stderr before
        # exiting 5, matching the follow phase's resume-protocol guarantee.
        # Without this, a consumer that hit corruption during catch-up had
        # no way to know which entries had already streamed successfully.
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             None),
            (_make_entry(2, "20260101T000002Z-aaaaaaa2", "ex.com",
                         from_addr="b@x.com", received_at="2026-01-01T00:00:02Z"),
             None),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        # Append a corrupt line after the two valid entries.
        with open(maildata / "emails.jsonl", "a", encoding="utf-8") as fh:
            fh.write("not-json\n")
        code, _, err = _run_cli(maildata, ["emails", "since", "0"], capsys=capsys)
        assert code == 5
        assert "last_seq=2" in err
        assert "corrupt" in err.lower()

    def test_since_catchup_missing_seq_reports_last_seq(self, tmp_path, capsys):
        # Same guarantee for the other catch-up exit-5 path: a journal line
        # that parses as JSON but lacks an integer seq. The emit()d last_seq
        # before the bad line must appear on stderr.
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             None),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        with open(maildata / "emails.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"id": "no-seq"}) + "\n")
        code, _, err = _run_cli(maildata, ["emails", "since", "0"], capsys=capsys)
        assert code == 5
        assert "last_seq=1" in err
        assert "missing integer seq" in err

    def test_since_limit(self, seeded, capsys):
        code, out, _ = _run_cli(
            seeded, ["emails", "since", "0", "--limit", "2"], capsys=capsys,
        )
        assert code == 0
        rows = [json.loads(l) for l in out.strip().splitlines()]
        assert [r["seq"] for r in rows] == [1, 2]

    def test_since_tombstone_passthrough(self, tmp_path, capsys):
        """Forward-compat: `since` must emit tombstones verbatim so callers
        can react when doc 22 ships delete."""
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"),
             _make_canonical("20260101T000001Z-aaaaaaa1", "2026-01-01T00:00:01Z")),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        with open(maildata / "emails.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "seq": 2, "type": "tombstone",
                "id": "20260101T000002Z-aaaaaaa2", "domain": "ex.com",
                "deleted_at": "2026-01-02T00:00:00Z",
            }) + "\n")
        code, out, _ = _run_cli(
            maildata, ["emails", "since", "0", "--limit", "0"], capsys=capsys,
        )
        assert code == 0
        rows = [json.loads(l) for l in out.strip().splitlines()]
        assert [r.get("seq") for r in rows] == [1, 2]
        assert rows[1].get("type") == "tombstone"

    def test_since_follow_streams_new_entries(self, tmp_path):
        """`since --follow` must pick up a line appended mid-stream, flushed
        per line. Run the CLI as a subprocess so we can poll its stdout
        without blocking on buffering inside the test process."""
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"), None),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        cli_path = Path(__file__).parent / "cli" / "primitive"
        proc = subprocess.Popen(
            [sys.executable, str(cli_path), "--path", str(maildata),
             "emails", "since", "0", "--follow"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            # First line (catch-up).
            line = proc.stdout.readline()
            assert b'"seq": 1' in line or b'"seq":1' in line
            # Append a new entry; follow loop polls stat every 250ms.
            new_entry = _make_entry(2, "20260101T000002Z-aaaaaaa2", "ex.com",
                                    from_addr="a@x.com",
                                    received_at="2026-01-01T00:00:02Z")
            with open(maildata / "emails.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(new_entry) + "\n")
                fh.flush()
            # Wait up to 3 seconds for the next line. Use select so the
            # readline never blocks past the deadline if the child never
            # writes again (in which case the assert below fails cleanly
            # instead of the test hanging forever).
            deadline = time.time() + 3.0
            line = b""
            while time.time() < deadline:
                remaining = max(0, deadline - time.time())
                ready, _, _ = select.select([proc.stdout], [], [], remaining)
                if not ready:
                    continue
                line = proc.stdout.readline()
                if line:
                    break
            assert b'"seq": 2' in line or b'"seq":2' in line
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def test_since_follow_corruption_reports_last_seq(self, tmp_path):
        # Follow-mode corruption must emit `last_seq=<N>` before exiting 5,
        # matching the exit-4 paths (rotation / truncation / disappearance).
        # Without this, consumers parsing stderr cannot resume after a bad
        # line and are forced to re-scan from seq=0.
        entries = [
            (_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                         from_addr="a@x.com", received_at="2026-01-01T00:00:01Z"), None),
        ]
        maildata = _seed_maildata(tmp_path, entries)
        cli_path = Path(__file__).parent / "cli" / "primitive"
        proc = subprocess.Popen(
            [sys.executable, str(cli_path), "--path", str(maildata),
             "emails", "since", "0", "--follow"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            # Drain the catch-up line (seq=1) so last_seq is known to be 1
            # when the corrupt line lands.
            ready, _, _ = select.select([proc.stdout], [], [], 3.0)
            assert ready
            first = proc.stdout.readline()
            assert b'"seq": 1' in first or b'"seq":1' in first
            # Append a corrupt line. The follow loop will read it on the
            # next stat tick and should exit 5 with last_seq=1 on stderr.
            with open(maildata / "emails.jsonl", "a", encoding="utf-8") as fh:
                fh.write("not-json\n")
                fh.flush()
            rc = proc.wait(timeout=5)
            assert rc == 5
            err = proc.stderr.read().decode("utf-8", errors="replace")
            assert "last_seq=1" in err
            assert "corrupt" in err.lower()
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


# -----------------------------------------------------------------------------
# `emails count` command
# -----------------------------------------------------------------------------


class TestEmailsCount:
    def test_count_happy_path(self, tmp_path, capsys):
        entries = [
            (_make_entry(i, f"20260101T0000{i:02d}Z-aaaaaaa{i:02d}", "ex.com",
                         from_addr="a@x.com", received_at=f"2026-01-01T00:00:{i:02d}Z"), None)
            for i in range(1, 11)
        ]
        maildata = _seed_maildata(tmp_path, entries)
        code, out, _ = _run_cli(maildata, ["emails", "count"], capsys=capsys)
        assert code == 0
        assert out.strip() == "10"

    def test_count_with_from_filter(self, tmp_path, capsys):
        entries = []
        for i in range(1, 11):
            sender = "billing@stripe.com" if i <= 3 else f"u{i}@x.com"
            entries.append((
                _make_entry(i, f"20260101T0000{i:02d}Z-aaaaaaa{i:02d}", "ex.com",
                            from_addr=sender,
                            received_at=f"2026-01-01T00:00:{i:02d}Z"), None,
            ))
        maildata = _seed_maildata(tmp_path, entries)
        code, out, _ = _run_cli(
            maildata, ["emails", "count", "--from", "billing@stripe.com"], capsys=capsys,
        )
        assert code == 0
        assert out.strip() == "3"

    def test_count_with_domain_filter(self, tmp_path, capsys):
        # 4 entries on ex.com, 6 on ex.net. --domain restricts the count.
        entries = []
        for i in range(1, 11):
            domain = "ex.com" if i <= 4 else "ex.net"
            entries.append((
                _make_entry(i, f"20260101T0000{i:02d}Z-aaaaaaa{i:02d}", domain,
                            from_addr="a@x.com",
                            received_at=f"2026-01-01T00:00:{i:02d}Z"), None,
            ))
        maildata = _seed_maildata(tmp_path, entries)
        code, out, _ = _run_cli(
            maildata, ["emails", "count", "--domain", "ex.com"], capsys=capsys,
        )
        assert code == 0
        assert out.strip() == "4"

    def test_count_since_wall_clock(self, tmp_path, capsys):
        entries = []
        # 5 entries on 2026-04-16, 5 on 2026-04-17.
        # Zero-pad seconds to 2 digits: `0{i}` produced 3-digit seconds for
        # i=10 (`...:00:010Z`) which Python 3.11+ silently tolerates via the
        # relaxed fromisoformat but older runtimes miscount or reject.
        for i in range(1, 11):
            day = "16" if i <= 5 else "17"
            entries.append((
                _make_entry(i, f"20260417T0000{i:02d}Z-aaaaaaa{i:02d}", "ex.com",
                            from_addr="a@x.com",
                            received_at=f"2026-04-{day}T12:00:{i:02d}Z"), None,
            ))
        maildata = _seed_maildata(tmp_path, entries)
        code, out, _ = _run_cli(
            maildata, ["emails", "count", "--since", "2026-04-17T00:00:00Z"],
            capsys=capsys,
        )
        assert code == 0
        assert out.strip() == "5"

    def test_count_bad_timestamp_exits_2(self, tmp_path, capsys):
        maildata = _seed_maildata(tmp_path, [])
        code, _, err = _run_cli(
            maildata, ["emails", "count", "--since", "notatime"], capsys=capsys,
        )
        assert code == 2
        assert "--since" in err

    def test_count_maildata_missing_exits_1(self, tmp_path, capsys):
        code, _, err = _run_cli(tmp_path / "nope", ["emails", "count"], capsys=capsys)
        assert code == 1
        assert "No maildata directory" in err

    def test_count_skips_tombstones(self, tmp_path, capsys):
        entries = [
            (_make_entry(i, f"20260101T00000{i}Z-aaaaaaa{i}", "ex.com",
                         from_addr="a@x.com", received_at=f"2026-01-01T00:00:0{i}Z"), None)
            for i in range(1, 4)
        ]
        maildata = _seed_maildata(tmp_path, entries)
        with open(maildata / "emails.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "seq": 4, "type": "tombstone",
                "id": "20260101T000004Z-aaaaaaa4", "domain": "ex.com",
                "deleted_at": "2026-01-02T00:00:00Z",
            }) + "\n")
        code, out, _ = _run_cli(maildata, ["emails", "count"], capsys=capsys)
        assert code == 0
        assert out.strip() == "3"


# -----------------------------------------------------------------------------
# `emails test` command
# -----------------------------------------------------------------------------


class TestEmailsTest:
    """The CLI side of the external test-email flow. Doc 08b is the spec.

    All tests monkey-patch `_post_test_email` so no real network call is
    made; the helper's (status, body) return is the seam the CLI branches
    on. Journal writes are done directly via the maildata fixture.
    """

    def _stub_post(self, status, body, monkeypatch):
        monkeypatch.setattr(
            primitive_cli, "_post_test_email",
            lambda *a, **kw: (status, json.dumps(body) if isinstance(body, dict) else body),
        )

    def _journal_append_with_subject(self, maildata, subject, *, seq=1, delay=0.0):
        """Append a journal line with the given subject. Optionally wait
        `delay` seconds before doing so, so tests can exercise the poll loop."""
        if delay:
            time.sleep(delay)
        entry = _make_entry(seq, f"20260101T00000{seq}Z-aaaaaaa{seq}", "ex.com",
                            from_addr="postmaster@primitive.dev",
                            received_at=f"2026-01-01T00:00:0{seq}Z",
                            subject=subject)
        with open(maildata / "emails.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
            fh.flush()

    def test_bad_timeout_exits_2_without_network(self, tmp_path, capsys, monkeypatch):
        # Network stub that would fail loudly if called.
        def boom(*a, **kw):
            raise AssertionError("must not be called for bad --timeout")
        monkeypatch.setattr(primitive_cli, "_post_test_email", boom)
        maildata = _seed_maildata(tmp_path, [])
        code, _, err = _run_cli(
            maildata, ["emails", "test", "--timeout", "2"], capsys=capsys,
        )
        assert code == 2
        assert "5 and 120" in err

    def test_404_no_claim_exits_1(self, tmp_path, capsys, monkeypatch):
        self._stub_post(404, {
            "ok": False, "error": "no_subdomain_claimed",
            "message": "This IP has no claimed subdomain.",
            "docs_url": "https://primitive.dev/docs/claim-subdomain",
        }, monkeypatch)
        maildata = _seed_maildata(tmp_path, [])
        code, _, err = _run_cli(maildata, ["emails", "test"], capsys=capsys)
        assert code == 1
        assert "no claimed subdomain" in err or "no subdomain" in err.lower()

    def test_429_rate_limited_exits_4(self, tmp_path, capsys, monkeypatch):
        self._stub_post(429, {
            "ok": False, "error": "rate_limited",
            "message": "Test email rate limit reached.",
            "reset_at": "2026-04-19T22:00:00Z",
            "limit": 10, "window_seconds": 3600,
        }, monkeypatch)
        maildata = _seed_maildata(tmp_path, [])
        code, _, err = _run_cli(maildata, ["emails", "test"], capsys=capsys)
        assert code == 4
        assert "rate limit" in err.lower()

    def test_5xx_exits_7_with_body_truncated(self, tmp_path, capsys, monkeypatch):
        self._stub_post(502, {"ok": False, "error": "mail_send_failed",
                              "message": "Mail provider returned 500."}, monkeypatch)
        maildata = _seed_maildata(tmp_path, [])
        code, _, err = _run_cli(maildata, ["emails", "test"], capsys=capsys)
        assert code == 7
        assert "502" in err

    def test_malformed_200_exits_7(self, tmp_path, capsys, monkeypatch):
        # 200 but missing the required tag/subject fields.
        self._stub_post(200, {"ok": True}, monkeypatch)
        maildata = _seed_maildata(tmp_path, [])
        code, _, err = _run_cli(maildata, ["emails", "test"], capsys=capsys)
        assert code == 7
        assert "malformed" in err.lower()

    def test_network_error_exits_7(self, tmp_path, capsys, monkeypatch):
        def raises(*a, **kw):
            raise OSError("ECONNREFUSED")
        monkeypatch.setattr(primitive_cli, "_post_test_email", raises)
        maildata = _seed_maildata(tmp_path, [])
        code, _, err = _run_cli(maildata, ["emails", "test"], capsys=capsys)
        assert code == 7
        assert "ECONNREFUSED" in err

    def test_no_wait_exits_0_immediately(self, tmp_path, capsys, monkeypatch):
        # --no-wait returns as soon as the server ack is received. No
        # journal interaction required.
        self._stub_post(200, {
            "ok": True, "tag": "ab12cd34",
            "subject": "PrimitiveMail test ab12cd34",
            "dispatched_at": "2026-04-19T20:30:00Z",
            "to": "test+ab12cd34@pink-violet.primitive.email",
        }, monkeypatch)
        maildata = _seed_maildata(tmp_path, [])
        code, out, _ = _run_cli(
            maildata, ["emails", "test", "--no-wait"], capsys=capsys,
        )
        assert code == 0
        assert "ab12cd34" in out
        assert "Dispatched" in out

    def test_wait_matches_journal_entry_by_subject(self, tmp_path, capsys, monkeypatch):
        # Seed one pre-existing entry that happens to share the server
        # subject (stale state from a prior run). The CLI MUST ignore it
        # because we seek to EOF before matching; otherwise the polling
        # would false-positive before the real delivery lands.
        subject = "PrimitiveMail test ab12cd34"
        entries = [(_make_entry(1, "20260101T000001Z-aaaaaaa1", "ex.com",
                                from_addr="old@x.com",
                                received_at="2026-01-01T00:00:01Z",
                                subject=subject), None)]
        maildata = _seed_maildata(tmp_path, entries)

        # Schedule the real-delivery append FROM inside the stub. Starting
        # the timer here instead of before _run_cli anchors the 0.3s
        # countdown to the CLI's own clock (after dispatch returns, before
        # it records start_size). That removes the race where the test
        # setup's pre-CLI timer could fire while the CLI was still
        # spinning up, causing start_size to already include seq=2 and
        # the match to be missed.
        import threading
        pending_timer = {}

        def stub_post_and_schedule_append(*a, **kw):
            t = threading.Timer(
                0.3, self._journal_append_with_subject,
                args=(maildata, subject), kwargs={"seq": 2},
            )
            pending_timer["t"] = t
            t.start()
            return (200, json.dumps({
                "ok": True, "tag": "ab12cd34", "subject": subject,
                "dispatched_at": "2026-04-19T20:30:00Z",
                "to": "test+ab12cd34@pink-violet.primitive.email",
            }))

        monkeypatch.setattr(primitive_cli, "_post_test_email",
                            stub_post_and_schedule_append)

        try:
            code, out, _ = _run_cli(
                maildata, ["emails", "test", "--timeout", "5", "--json"],
                capsys=capsys,
            )
        finally:
            if "t" in pending_timer:
                pending_timer["t"].join()

        assert code == 0
        body = json.loads(out.strip())
        assert body["ok"] is True
        assert body["seq"] == 2  # seq 1 is the stale entry the CLI ignored
        assert body["tag"] == "ab12cd34"

    def test_wait_timeout_exits_6(self, tmp_path, capsys, monkeypatch):
        # No journal append within the timeout; expect exit 6 + timeout hint.
        # Fast-forward time so the test does not actually sleep --timeout
        # seconds. First monotonic() call records poll_start; subsequent
        # calls jump past the deadline so the while loop exits immediately.
        self._stub_post(200, {
            "ok": True, "tag": "ab12cd34",
            "subject": "PrimitiveMail test ab12cd34",
            "dispatched_at": "2026-04-19T20:30:00Z",
            "to": "test+ab12cd34@pink-violet.primitive.email",
        }, monkeypatch)
        counter = {"n": 0}

        def fake_monotonic():
            counter["n"] += 1
            # 1st: poll_start = 0. 2nd: first while check at 0 (< deadline
            # 5, enters loop body once). 3rd+: 100 (past deadline, exits).
            return 0.0 if counter["n"] <= 2 else 100.0

        monkeypatch.setattr(primitive_cli.time, "monotonic", fake_monotonic)
        monkeypatch.setattr(primitive_cli.time, "sleep", lambda s: None)

        maildata = _seed_maildata(tmp_path, [])
        code, _, err = _run_cli(
            maildata, ["emails", "test", "--timeout", "5"], capsys=capsys,
        )
        assert code == 6
        assert "not observed locally" in err

    def test_conflicting_wait_flags_exits_2(self, tmp_path, capsys, monkeypatch):
        def boom(*a, **kw):
            raise AssertionError("must not be called for flag conflict")
        monkeypatch.setattr(primitive_cli, "_post_test_email", boom)
        maildata = _seed_maildata(tmp_path, [])
        code, _, _ = _run_cli(
            maildata, ["emails", "test", "--wait", "--no-wait"], capsys=capsys,
        )
        assert code == 2


# -----------------------------------------------------------------------------
# `emails status` canonical + alias
# -----------------------------------------------------------------------------


class TestEmailsStatusRename:
    def test_canonical_form_is_emails_status(self, tmp_path, capsys):
        # Seed an .eml so the status command has something to report.
        maildata = tmp_path / "maildata"
        dom = maildata / "ex.com"
        dom.mkdir(parents=True)
        (dom / "20260101T000001Z-aaaaaaa1.eml").write_bytes(b"x")
        (dom / "20260101T000001Z-aaaaaaa1.meta.json").write_text(
            json.dumps({"smtp": {"mail_from": "a@x.com"}}),
        )
        code, out, _ = _run_cli(maildata, ["emails", "status"], capsys=capsys)
        assert code == 0
        assert "Total emails:" in out

    def test_alias_still_works_and_warns(self, tmp_path, capsys):
        maildata = tmp_path / "maildata"
        dom = maildata / "ex.com"
        dom.mkdir(parents=True)
        (dom / "20260101T000001Z-aaaaaaa1.eml").write_bytes(b"x")
        (dom / "20260101T000001Z-aaaaaaa1.meta.json").write_text(
            json.dumps({"smtp": {"mail_from": "a@x.com"}}),
        )
        code, out, err = _run_cli(maildata, ["emails-status"], capsys=capsys)
        assert code == 0
        assert "Total emails:" in out
        assert "deprecated" in err.lower()

    def test_alias_not_listed_in_primary_help(self, capsys):
        """The descriptive row for the deprecated alias must not appear in
        `primitive --help`. Argparse's top usage line enumerates command
        names in a brace list; that is tolerable, but the help table must
        not advertise it."""
        with patch.object(sys, "argv", ["primitive", "--help"]):
            with pytest.raises(SystemExit):
                primitive_cli.main()
        out, _ = capsys.readouterr()
        # `emails-status` should not appear as its own descriptive row.
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("emails-status "):
                raise AssertionError(
                    f"deprecated alias is described in --help: {stripped!r}",
                )

    def test_emails_status_appears_under_emails_help(self, capsys):
        with patch.object(sys, "argv", ["primitive", "emails", "--help"]):
            with pytest.raises(SystemExit):
                primitive_cli.main()
        out, _ = capsys.readouterr()
        assert "status " in out
