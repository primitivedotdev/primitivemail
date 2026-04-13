"""Docker and server operations for PrimitiveMail installer."""

import json
import os
import subprocess
import sys
import time
import urllib.request
from typing import Optional

from installer import ui
from installer.config import detect_public_ip


def get_compose_cmd() -> list:
    """Return the docker compose command as a list."""
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, check=True,
        )
        return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ["docker-compose"]


def is_first_build() -> bool:
    """True if no primitivemail docker image exists yet."""
    result = subprocess.run(
        ["docker", "images", "--format", "{{.Repository}}"],
        capture_output=True, text=True,
    )
    return "primitivemail" not in result.stdout


def build_and_start(
    install_dir: str,
    verbose: bool,
    first_build: bool,
    compose_cmd: list,
) -> None:
    if first_build:
        ui.step("Building PrimitiveMail")
        ui.info("First build -- this usually takes 1-2 minutes")
        print()
        ui.run_with_progress(
            compose_cmd + ["build", "--quiet"],
            "Building",
            verbose=verbose,
            cwd=install_dir,
        )
        print()
        ui.step("Starting PrimitiveMail")
        result = subprocess.run(
            compose_cmd + ["up", "-d", "--quiet-pull"],
            cwd=install_dir,
            capture_output=True,
        )
        if result.returncode != 0:
            ui.error("docker compose up failed")
            if result.stderr:
                print(result.stderr.decode("utf-8", errors="replace"))
            sys.exit(1)
    elif verbose:
        ui.step("Starting PrimitiveMail")
        result = subprocess.run(
            compose_cmd + ["up", "-d", "--build"],
            cwd=install_dir,
        )
        if result.returncode != 0:
            ui.error("docker compose up failed")
            sys.exit(1)
    else:
        ui.step("Starting PrimitiveMail")
        result = subprocess.run(
            compose_cmd + ["up", "-d", "--build", "--quiet-pull"],
            cwd=install_dir,
            capture_output=True,
        )
        if result.returncode != 0:
            ui.error("docker compose up failed")
            if result.stderr:
                print(result.stderr.decode("utf-8", errors="replace"))
            sys.exit(1)


def wait_for_container(timeout: int = 15) -> bool:
    for _ in range(timeout):
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True,
        )
        if "primitivemail" in result.stdout:
            return True
        time.sleep(1)
    return False


def wait_for_smtp(timeout: int = 20) -> bool:
    for _ in range(timeout):
        result = subprocess.run(
            ["docker", "exec", "primitivemail", "sh", "-c", "ss -tln | grep -q ':25 '"],
            capture_output=True,
        )
        if result.returncode == 0:
            return True
        time.sleep(1)
    return False


def check_port_25_reachable(ip: str) -> Optional[str]:
    """Check port 25 via external API. Returns 'open'|'closed'|'blocked'|'error'|None."""
    try:
        url = f"https://mx-tools.primitive.dev/check?ip={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "PrimitiveMail-Installer"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("status")
    except Exception:
        return None


def check_port_25_local_fallback(ip: str) -> Optional[bool]:
    """Fallback port check. Returns True (reachable), False (not), None (can't tell)."""
    # Check if IP is on a local interface
    result = subprocess.run(
        ["ip", "addr", "show"], capture_output=True, text=True,
    )
    if result.returncode == 0 and f" {ip}/" in result.stdout:
        return None  # Can't self-check a local IP

    # Try nc (pass ip as positional arg to avoid shell injection)
    try:
        result = subprocess.run(
            ["timeout", "5", "bash", "-c", 'echo QUIT | nc -w 3 "$1" 25', "_", ip],
            capture_output=True, timeout=10,
        )
        if result.returncode == 0:
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return False


def detect_cloud_provider() -> Optional[str]:
    """Detect AWS/GCP/Azure via metadata endpoints."""
    checks = [
        ("aws", "http://169.254.169.254/latest/meta-data/", {}),
        ("gcp", "http://metadata.google.internal/computeMetadata/v1/",
         {"Metadata-Flavor": "Google"}),
        ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         {"Metadata": "true"}),
    ]
    for provider, url, headers in checks:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=1):
                return provider
        except Exception:
            continue
    return None


def get_firewall_help(cloud: Optional[str]) -> list:
    """Return cloud-specific firewall instructions."""
    if cloud == "aws":
        return [
            "It looks like you're on AWS. To fix this:",
            "EC2 > Security Groups > Edit inbound rules > Add rule:",
            "Type: Custom TCP | Port: 25 | Source: 0.0.0.0/0",
        ]
    elif cloud == "gcp":
        return [
            "It looks like you're on Google Cloud. To fix this:",
            "VPC Network > Firewall > Create rule:",
            "Direction: Ingress | Protocol: TCP | Port: 25 | Source: 0.0.0.0/0",
        ]
    elif cloud == "azure":
        return [
            "It looks like you're on Azure. To fix this:",
            "Network Security Group > Inbound security rules > Add:",
            "Protocol: TCP | Destination port: 25 | Source: Any",
        ]
    return [
        "Check your cloud provider's security group / firewall settings",
        "and ensure inbound TCP on port 25 is allowed from 0.0.0.0/0.",
    ]


def start_server(
    install_dir: str,
    no_start: bool,
    verbose: bool,
    ip_literal: str,
) -> None:
    """Full server start orchestration."""
    if no_start:
        ui.info("Skipping start (--no-start)")
        return

    compose_cmd = get_compose_cmd()
    first_build = is_first_build()

    build_and_start(install_dir, verbose, first_build, compose_cmd)

    if not wait_for_container():
        ui.error("Container failed to start")
        print()
        print("  Check logs: docker logs primitivemail")
        raise SystemExit(1)

    if not wait_for_smtp():
        ui.error("PrimitiveMail started but SMTP did not become ready")
        print()
        print("  Check logs: docker logs primitivemail")
        raise SystemExit(1)

    ui.success("PrimitiveMail is running on port 25")

    # Port 25 reachability check
    check_ip = ip_literal or detect_public_ip() or ""
    if not check_ip:
        return

    ui.info(f"Checking port 25 reachability on {check_ip}...")
    status = check_port_25_reachable(check_ip)

    if status == "open":
        ui.success("Port 25 is reachable from the outside")
    elif status == "closed":
        print()
        ui.warn(f"Port 25 is not accepting connections on {check_ip}")
        print("  The host is reachable but nothing is listening on port 25.")
        print("  Check that the PrimitiveMail container is running:")
        print("    docker ps | grep primitivemail")
        print("    docker logs primitivemail")
        print()
    elif status == "blocked":
        print()
        ui.warn(f"Port 25 appears blocked by a firewall on {check_ip}")
        print("  PrimitiveMail is running, but external mail won't reach it until you")
        print("  allow inbound TCP on port 25 in your firewall settings.")
        print()
        cloud = detect_cloud_provider()
        for line in get_firewall_help(cloud):
            print(f"  {line}")
        print()
    elif status == "error":
        print()
        ui.warn(f"Port 25 check failed -- host unreachable at {check_ip}")
        print("  Verify that this is the correct public IP for your server.")
        print(f"  You can check manually at: {ui.BOLD}https://mx-tools.primitive.dev{ui.NC}")
        print()
    else:
        # API unreachable — local fallback
        ui.warn("Could not reach port check service -- falling back to local check")
        fallback = check_port_25_local_fallback(check_ip)
        if fallback is None:
            ui.info("Public IP is on a local interface -- cannot verify port 25 from here")
            print(f"  Check manually at: {ui.BOLD}https://mx-tools.primitive.dev{ui.NC}")
        elif fallback:
            ui.success("Port 25 is reachable from this host")
        else:
            print()
            ui.warn(f"Port 25 does not appear reachable on {check_ip}")
            print("  PrimitiveMail is running, but external mail may not be able to reach it.")
            print(f"  You can verify manually at: {ui.BOLD}https://mx-tools.primitive.dev{ui.NC}")
            print()


def _ensure_local_bin_on_path() -> None:
    """Ensure ~/.local/bin exists and is on PATH (current session + shell configs)."""
    local_bin = os.path.expanduser("~/.local/bin")
    os.makedirs(local_bin, exist_ok=True)

    # Add to current session
    path = os.environ.get("PATH", "")
    if local_bin not in path.split(os.pathsep):
        os.environ["PATH"] = f"{local_bin}{os.pathsep}{path}"

    # Add to shell config files for future sessions.
    # For .bashrc: prepend BEFORE the interactive guard so non-interactive
    # SSH commands (ssh user@host 'primitive ...') also pick it up.
    path_line = 'export PATH="$HOME/.local/bin:$PATH"'

    bashrc = os.path.expanduser("~/.bashrc")
    if os.path.isfile(bashrc):
        with open(bashrc) as f:
            contents = f.read()
        if path_line not in contents:
            with open(bashrc, "w") as f:
                f.write(f"{path_line}\n{contents}")

    # .profile and .zshrc: append is fine (no interactive guard issue)
    for rc in [
        os.path.expanduser("~/.profile"),
        os.path.expanduser("~/.zshrc"),
    ]:
        if not os.path.isfile(rc):
            continue
        with open(rc) as f:
            contents = f.read()
        if path_line not in contents:
            with open(rc, "a") as f:
                f.write(f"\n{path_line}\n")


def restart(install_dir: str) -> None:
    """Restart containers to pick up .env changes. Uses down + up (not restart)."""
    compose_cmd = get_compose_cmd()
    subprocess.run(
        compose_cmd + ["down"],
        cwd=install_dir,
        capture_output=True,
    )
    result = subprocess.run(
        compose_cmd + ["up", "-d", "--quiet-pull"],
        cwd=install_dir,
        capture_output=True,
    )
    if result.returncode != 0:
        ui.error("docker compose up failed during restart")
        if result.stderr:
            print(result.stderr.decode("utf-8", errors="replace"))
        return
    if wait_for_container() and wait_for_smtp():
        ui.success("PrimitiveMail restarted with new domain")
    else:
        ui.warn("Restart may have failed. Check: docker logs primitivemail")


def install_cli(install_dir: str) -> None:
    """Install the CLI to ~/.local/bin (no sudo), with /usr/local/bin as fallback."""
    ui.step("Installing CLI")

    cli_path = os.path.abspath(os.path.join(install_dir, "cli", "primitive"))
    os.chmod(cli_path, 0o755)

    # Primary: ~/.local/bin (always works, no sudo)
    _ensure_local_bin_on_path()
    local_bin = os.path.expanduser("~/.local/bin")
    local_link = os.path.join(local_bin, "primitive")
    try:
        if os.path.islink(local_link) or os.path.exists(local_link):
            os.remove(local_link)
        os.symlink(cli_path, local_link)
        ui.success("CLI installed: primitive")
    except OSError as e:
        ui.warn(f"Could not symlink to ~/.local/bin: {e}")

    # Best-effort fallback: /usr/local/bin (needs sudo, silent fail)
    result = subprocess.run(
        ["sudo", "-n", "ln", "-sf", cli_path, "/usr/local/bin/primitive"],
        capture_output=True,
    )
    if result.returncode == 0:
        ui.info("Also installed to /usr/local/bin/primitive")
