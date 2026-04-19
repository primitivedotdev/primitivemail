#!/usr/bin/env python3
"""Preflight checks for PrimitiveMail install.

Verifies that the environment can support a full install before committing
to the multi-minute docker build. Read-only: performs no mutation, installs
nothing, configures nothing. Emits one JSON object on stdout:

    {"event":"preflight","overall":"ok|fail","failed":[...],"checks":{...}}

Exits 0 if all required checks pass, 1 on any failure. Intended to be run
either from a git checkout via `python3 -m installer.preflight` or as a
standalone file fetched from the raw GitHub URL by install.sh's --preflight
flag, so this module must not import from anywhere else in the installer
package.

Checks:
    ram                 available memory (MemAvailable) >= 1024 MB
    disk                free space on install target >= 5 GB
    port_25_inbound     external reachability via mx-tools.primitive.dev
    outbound_https      can reach github.com, primitive.dev, api.cloudflare.com
    docker              status/version if present; skipped if absent
"""

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

REQUIRED_RAM_MB = 1024
REQUIRED_DISK_GB = 5


def _http_get(url: str, timeout: float = 5.0) -> "str | None":
    """GET and return body text, or None on any failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "primitivemail-preflight/1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def check_ram() -> dict:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    mb = int(line.split()[1]) // 1024
                    return {
                        "status": "ok" if mb >= REQUIRED_RAM_MB else "fail",
                        "available_mb": mb,
                        "required_mb": REQUIRED_RAM_MB,
                    }
        return {"status": "skip", "reason": "MemAvailable not in /proc/meminfo"}
    except Exception as e:
        # macOS / non-Linux kernels don't have /proc/meminfo; not fatal here.
        return {"status": "skip", "reason": f"{type(e).__name__}: {e}"}


def check_disk(target: "str | None" = None) -> dict:
    target = target or os.environ.get("PRIMITIVEMAIL_DIR", "/")
    # Normalize first — a bare relative name like "primitivemail" would
    # otherwise dirname() to "" and fall through to the "/" fallback,
    # checking the root filesystem instead of the intended target.
    target = os.path.abspath(target)
    # Walk up to an ancestor that exists — install dir may not be created yet.
    probe = target
    while probe != "/" and not os.path.exists(probe):
        probe = os.path.dirname(probe)
    if not os.path.exists(probe):
        probe = "/"
    try:
        stats = shutil.disk_usage(probe)
        gb = stats.free // (1024 ** 3)
        return {
            "status": "ok" if gb >= REQUIRED_DISK_GB else "fail",
            "path": probe,
            "available_gb": gb,
            "required_gb": REQUIRED_DISK_GB,
        }
    except Exception as e:
        return {"status": "skip", "reason": str(e), "path": probe}


def check_port_25() -> dict:
    # Resolve public IPv4 first (mx-tools only probes IPv4).
    ip = None
    for probe_url in ("https://ifconfig.me", "https://api.ipify.org", "https://icanhazip.com"):
        ip = _http_get(probe_url, timeout=5.0)
        if ip and all(p.isdigit() and 0 <= int(p) <= 255 for p in ip.split(".") if p) and ip.count(".") == 3:
            break
        ip = None
    if not ip:
        return {"status": "skip", "reason": "could not determine public IPv4"}

    body = _http_get(f"https://mx-tools.primitive.dev/check?ip={ip}", timeout=15.0)
    if not body:
        return {"status": "skip", "reason": "mx-tools.primitive.dev unreachable", "public_ip": ip}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {"status": "skip", "reason": "mx-tools returned non-JSON", "public_ip": ip}

    reachability = data.get("status", "unknown")
    # "open"   — listener will be reachable once mail server starts. PASS.
    # "closed" — firewall allows inbound, nothing listening yet. PASS (expected pre-install).
    # "blocked" — firewall (cloud security group, ISP) blocks inbound 25. FAIL.
    # "error"  — IP unreachable from mx-tools. FAIL.
    if reachability in ("open", "closed"):
        status = "ok"
    elif reachability == "blocked":
        status = "fail"
    else:
        status = "fail"
    return {
        "status": status,
        "public_ip": ip,
        "reachability": reachability,
        "message": data.get("message"),
    }


def check_outbound_https() -> dict:
    # Hosts the installer needs to reach during build + run.
    # We care about connectivity, not endpoint behavior — a 403 on
    # api.cloudflare.com means TCP+TLS worked and the host is reachable.
    # Treat HTTPError (non-2xx response) as reachable; only transport-level
    # failures (DNS, connect, TLS, timeout) count as unreachable.
    targets = [
        "https://github.com",
        "https://primitive.dev",
        "https://api.cloudflare.com",
    ]
    unreachable = []
    for url in targets:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "primitivemail-preflight/1"}
            )
            urllib.request.urlopen(req, timeout=5.0).close()
        except urllib.error.HTTPError:
            # Server answered us — non-2xx doesn't mean unreachable.
            pass
        except Exception:
            unreachable.append(url)
    return {
        "status": "ok" if not unreachable else "fail",
        "targets_checked": len(targets),
        "unreachable": unreachable,
    }


def check_docker() -> dict:
    if not shutil.which("docker"):
        # Not a fail — install.sh installs Docker automatically. Informational.
        return {"status": "skip", "installed": False, "message": "docker not installed (install.sh will install it)"}
    try:
        info = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        daemon_ok = info.returncode == 0
    except Exception as e:
        return {"status": "fail", "installed": True, "daemon_running": False, "error": str(e)}
    version = None
    try:
        v = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
        if v.returncode == 0:
            version = v.stdout.strip()
    except Exception:
        pass
    return {
        "status": "ok" if daemon_ok else "fail",
        "installed": True,
        "daemon_running": daemon_ok,
        "version": version,
    }


def run_all() -> dict:
    checks = {
        "ram": check_ram(),
        "disk": check_disk(),
        "port_25_inbound": check_port_25(),
        "outbound_https": check_outbound_https(),
        "docker": check_docker(),
    }
    failed = [name for name, c in checks.items() if c.get("status") == "fail"]
    return {
        "event": "preflight",
        "overall": "fail" if failed else "ok",
        "failed": failed,
        "checks": checks,
    }


def main() -> None:
    result = run_all()
    print(json.dumps(result, separators=(",", ":")))
    sys.stdout.flush()
    sys.exit(1 if result["overall"] == "fail" else 0)


if __name__ == "__main__":
    main()
