#!/bin/bash
set -euo pipefail

# PrimitiveMail Installer (bootstrap)
# Usage: curl -fsSL https://get.primitive.dev | bash
#   or:  ./install.sh [OPTIONS]
#
# This script handles Docker, firewall, and clone, then hands off
# to the Python installer for configuration and startup.

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[38;2;74;222;128m'
RED='\033[38;2;248;113;113m'
YELLOW='\033[38;2;250;204;21m'
BLUE='\033[38;2;96;165;250m'
MUTED='\033[38;2;113;113;122m'
NC='\033[0m'

# --- UI helpers ----------------------------------------------------------
#
# In --json mode, stdout is reserved for the NDJSON stream emitted by the
# Python installer. Everything that bash writes (banner, prerequisite steps,
# Docker install output) goes to stderr so agents can parse stdout cleanly
# while operators watching the terminal still see progress.

JSON_MODE=0
ENABLE_LETSENCRYPT=0
LE_EMAIL=""
LE_HOSTNAME=""
LE_SKIP_VERIFY=0
# Track whether the operator explicitly passed --tls-cert/--tls-key on this
# invocation. When they did, their value wins over any preservation logic;
# when they did not, preserve_existing_tls_paths may forward whatever the
# previous run wrote into .env so re-running the installer without
# --enable-letsencrypt does not silently wipe the existing TLS config.
TLS_CERT_EXPLICIT=0
TLS_KEY_EXPLICIT=0
# Tracks whether the operator passed --letsencrypt-host-dir explicitly.
# When set, their value wins over preservation logic; when unset,
# preserve_existing_tls_paths may forward whatever .env already declares
# (so a re-run does not silently drop the bind-mount path).
LETSENCRYPT_HOST_DIR_EXPLICIT=0
_ui_out() {
    if [[ "$JSON_MODE" == "1" ]]; then
        echo -e "$1" 1>&2
    else
        echo -e "$1"
    fi
}

info()    { _ui_out "${MUTED}.${NC} $*"; }
success() { _ui_out "${GREEN}+${NC} $*"; }
warn()    { _ui_out "${YELLOW}!${NC} $*"; }
error()   { _ui_out "${RED}x${NC} $*"; }
step()    { _ui_out "${BLUE}>${NC} ${BOLD}$*${NC}"; }
spacer()  { _ui_out ""; }
detail()  { _ui_out "  $*"; }

# --- Parse --dir and --help before forwarding to Python ------------------

INSTALL_DIR="${PRIMITIVEMAIL_DIR:-./primitivemail}"
# Branch to clone. The get.primitive.dev Worker prepends an override
# when serving install.sh from a non-main URL path (e.g. /my-branch), so
# `curl https://get.primitive.dev/my-branch | bash` installs from that
# branch end-to-end. Direct invocations can also set this env var.
PRIMITIVEMAIL_BRANCH="${PRIMITIVEMAIL_BRANCH:-main}"
PREFLIGHT_MODE=0
FORWARD_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --dir=*)
            INSTALL_DIR="${1#--dir=}"
            shift
            ;;
        --preflight)
            # Read-only environment check: RAM, disk, port 25 reachability,
            # outbound HTTPS, docker daemon state. Emits one JSON line and
            # exits without starting the full install.
            PREFLIGHT_MODE=1
            shift
            ;;
        --json)
            JSON_MODE=1
            FORWARD_ARGS+=("$1")
            shift
            ;;
        --enable-letsencrypt)
            ENABLE_LETSENCRYPT=1
            shift
            ;;
        --le-email)
            LE_EMAIL="$2"
            shift 2
            ;;
        --le-email=*)
            LE_EMAIL="${1#--le-email=}"
            shift
            ;;
        --le-skip-verify)
            # Default behavior runs `certbot renew --dry-run` after issuance,
            # which adds 10-20s and can fail transiently on flaky networks.
            # Opt-out flag for CI runs and pipelines that already test renewal
            # out-of-band.
            LE_SKIP_VERIFY=1
            shift
            ;;
        --hostname)
            # Captured for the LE preflight, which needs to know the public
            # DNS name before we hand control to the Python installer.
            # Still forwarded to Python so the existing flow is unchanged.
            LE_HOSTNAME="$2"
            FORWARD_ARGS+=("$1" "$2")
            shift 2
            ;;
        --hostname=*)
            LE_HOSTNAME="${1#--hostname=}"
            FORWARD_ARGS+=("$1")
            shift
            ;;
        --tls-cert)
            TLS_CERT_EXPLICIT=1
            FORWARD_ARGS+=("$1" "$2")
            shift 2
            ;;
        --tls-cert=*)
            TLS_CERT_EXPLICIT=1
            FORWARD_ARGS+=("$1")
            shift
            ;;
        --tls-key)
            TLS_KEY_EXPLICIT=1
            FORWARD_ARGS+=("$1" "$2")
            shift 2
            ;;
        --tls-key=*)
            TLS_KEY_EXPLICIT=1
            FORWARD_ARGS+=("$1")
            shift
            ;;
        --letsencrypt-host-dir)
            LETSENCRYPT_HOST_DIR_EXPLICIT=1
            FORWARD_ARGS+=("$1" "$2")
            shift 2
            ;;
        --letsencrypt-host-dir=*)
            LETSENCRYPT_HOST_DIR_EXPLICIT=1
            FORWARD_ARGS+=("$1")
            shift
            ;;
        --help|-h)
            echo "PrimitiveMail Installer"
            echo ""
            echo "Usage: curl -fsSL https://get.primitive.dev | bash"
            echo "   or: ./install.sh [OPTIONS]"
            echo ""
            echo "Domain:"
            echo "  --hostname HOST           Mail server hostname (e.g. mx.example.com)"
            echo "  --domain DOMAIN           Domain to receive mail for (e.g. example.com)"
            echo "  --claim-subdomain         Claim a free *.primitive.email subdomain after install"
            echo "                            (mutually exclusive with --hostname/--domain)"
            echo "  --ip-literal IP           Enable IP literal mail for this IP"
            echo ""
            echo "Webhooks:"
            echo "  --webhook-url URL         Legacy (milter) webhook endpoint"
            echo "  --webhook-secret SECRET   Legacy webhook secret"
            echo "  --event-webhook-url URL   Watcher push-delivery target (SDK-signed)"
            echo "  --event-webhook-secret S  Watcher HMAC signing key (auto-generated if omitted)"
            echo ""
            echo "Security:"
            echo "  --spoof-protection LEVEL  off|monitor|standard|strict (default: off)"
            echo ""
            echo "TLS (Let's Encrypt):"
            echo "  --enable-letsencrypt      Issue a Let's Encrypt cert for --hostname during install."
            echo "                            Requires public DNS pointing at this host and inbound :80."
            echo "  --le-email EMAIL          ACME account email (required with --enable-letsencrypt)"
            echo "  --le-skip-verify          Skip the post-issuance 'certbot renew --dry-run' check"
            echo "                            (default keeps it on; opt out for CI / flaky networks)."
            echo ""
            echo "TLS (Bring your own cert):"
            echo "  --tls-cert PATH           Absolute path to a TLS certificate file readable"
            echo "                            inside the container (e.g. corporate CA-issued cert)."
            echo "  --tls-key PATH            Absolute path to the matching private key."
            echo "                            Mount these into the container yourself, or pass"
            echo "                            --letsencrypt-host-dir to bind a cert tree."
            echo "  --letsencrypt-host-dir PATH"
            echo "                            Host directory bound read-only at /etc/letsencrypt"
            echo "                            inside the container. Set automatically by"
            echo "                            --enable-letsencrypt; useful for BYO cert layouts."
            echo ""
            echo "Output:"
            echo "  --json                    NDJSON progress events on stdout, human output on stderr."
            echo "                            Redirect streams separately (>stdout 2>stderr) to parse stdout"
            echo "                            as pure NDJSON. Implies --no-prompt."
            echo "  --verbose                 Show detailed output"
            echo "  --no-prompt, -y           Non-interactive mode"
            echo ""
            echo "Other:"
            echo "  --dir PATH                Install directory (default: ./primitivemail)"
            echo "  --preflight               Check environment (RAM, disk, port 25, outbound HTTPS)"
            echo "                            without installing. Emits one JSON line, exits 1 on failure."
            echo "  --skip-verify             Skip the post-install end-to-end test email (runs by"
            echo "                            default when --claim-subdomain succeeds)."
            echo "  --help, -h                Show this help"
            exit 0
            ;;
        *)
            FORWARD_ARGS+=("$1")
            shift
            ;;
    esac
done

# Absolutize INSTALL_DIR before export. run_preflight `cd`s to the
# installer module's directory before `exec`-ing Python, so a relative
# PRIMITIVEMAIL_DIR would get abspath()'d against the WRONG cwd and the
# disk check would probe the install.sh directory instead of the user's
# intended target. Using `$(pwd)/$INSTALL_DIR` instead of `cd && pwd`
# because the directory may not exist yet on first install.
if [[ "$INSTALL_DIR" != /* ]]; then
    # Strip a leading `./` so the default value `./primitivemail` prepended
    # with pwd does not render as `/home/ubuntu/./primitivemail` in the
    # "Cloned to ..." log line. Agents that grep the log for the install
    # path then get the tidy form, matching the `done` NDJSON event.
    INSTALL_DIR="${INSTALL_DIR#./}"
    INSTALL_DIR="$(pwd)/$INSTALL_DIR"
fi
export PRIMITIVEMAIL_DIR="$INSTALL_DIR"

# --- Banner --------------------------------------------------------------

LOGO='⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣿⡛⠛⠛⠛⠛⠛⣿⣧⣤⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⡶⠾⠛⠛⠀⠀⠀⢷⡆⠀⠀⠀⠀⠀⠀⠈⠛⢻⣷⣶⣆⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣾⠉⠀⠀⠀⠀⠀⠀⠀⠸⢷⡆⠀⠀⠀⠀⠀⠀⢀⣸⡇⠈⠹⢷⣆⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣶⠶⠶⣶⣀⡀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⢸⡏⠁⠀⠀⠈⠹⢷⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠉⠀⠀⠉⠹⠿⣧⣤⠀⠀⠀⠀⠀⠘⠃⠀⠀⠀⠀⠀⣤⠟⠁⠀⠀⠀⠀⠀⠈⣿⣤⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢰⣤⣬⣅⣀⠀⠀⠀⠀⠀⠀⠛⡇⠀⣀⣠⣤⣼⡟⠛⠿⣿⣤⣤⣀⠀⠀⠀⠀⠀⠀⢀⣠⡤⠿⣤⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣤⣄⣉⠉⠹⠶⢦⣤⡀⠀⠀⠀⢀⣶⠛⠛⠀⠀⠀⠀⠀⠀⠀⠛⠻⣆⡀⢀⣀⣀⡰⠾⠏⠁⠀⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣈⣉⠉⠉⠀⠀⠀⠀⠀⠛⠳⠆⢠⣿⠋⠀⠀⠀⠀⣰⡶⠶⢶⣆⠀⠀⠹⣷⠈⠉⠉⠁⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠛⠛⠻⠿⠿⣦⣤⡄⣀⣀⠀⢠⡼⠇⠀⠀⠀⠀⣶⠉⠁⣀⠈⢹⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢰⣶⣦⣤⣤⣤⡄⠀⠀⠉⠉⠃⢸⣷⠶⠏⠉⠉⠀⠿⣄⡀⠛⠛⠋⠀⢀⣰⡟⢀⣆⣀⠀⠀⠀⠀⣤⠿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣤⡄⠀⠀⣀⣀⣀⣤⣤⣤⡄⢸⣿⠀⠀⠀⠀⢠⡄⠹⢿⣤⣤⣤⣼⠟⠃⠀⠀⠀⠉⠛⠛⠛⣿⠛⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠰⠿⠿⠟⠛⠛⠉⠉⠀⠀⠀⠀⠀⠿⣆⡀⣀⣶⠛⠀⠀⠀⣠⠄⠀⠀⠿⣤⠀⠀⠀⠀⠀⢀⣶⠿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣷⣿⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠙⢧⣤⠀⣀⣰⠾⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠿⢦⣄⣀⣀⣿⡀⠀⠀⠀⣀⣀⡶⠶⠏⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠹⠿⠿⠿⠿⠿⠏⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀'

TEXT_LOGO='⢀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⡿⠿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠿⠿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠿⠀⠀⢀⣾⠀⠀⠀⠿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣇⣀⣼⣿⠀⢸⣿⣿⣿⣷ ⣶⣶⠀⣿⣿⣿⣿⣦⣾⣿⣷⡄⢰⣶⠀⢰⣾⣿⣶⣶⠀⣶⡆⠀⣿⡇⠀⠀⣿⡇⢠⣶⣿⣿⣿⣶⡄
⢸⣿⡿⠿⠿⠋⠀⢸⣿⠁⠀ ⠀⣿⣿⠀⣿⡏⠀⢸⣿⠀⢸⣿⡇⢸⣿⠀⠀⢸⣿⠀⠀⠀⣿⡇⠀⣿⣇⠀⣀⣿⡇⢸⣿⣧⣤⣼⣿⡇
⢸⣿⠀⠀⠀⠀⠀⢸⣿ ⠀⠀⠀⣿⣿⠀⣿⡇⠀⢸⣿⠀⢸⣿⡇⢸⣿⠀⠀⠸⣿⣦⣤⠀⣿⡇⠀⠘⢿⣿⣿⠟⠀⠸⣿⣷⣤⣤⣤⡄
⠈⠉⠀⠀⠀⠀⠀⠈⠉ ⠀⠀⠀⠉⠉⠀⠉⠁⠀⠈⠉⠀⠈⠉⠁⠈⠉⠀⠀⠀⠈⠉⠉⠀⠉⠁⠀⠀⠀⠉⠁⠀⠀⠀⠀⠉⠉⠉⠉⠀'

print_banner() {
    # JSON mode: no banner on stdout (it would break the NDJSON stream).
    # Keep stderr clean too; agents don't need decoration.
    if [[ "$JSON_MODE" == "1" ]]; then
        return
    fi
    local PGREEN='\033[38;2;90;247;142m'
    echo ""
    echo -e "${PGREEN}${LOGO}${NC}"
    echo -e "${PGREEN}${TEXT_LOGO}${NC}"
    echo ""
    echo -e "${MUTED}  Open-source mail server. Clone, run, receive email.${NC}"
    echo ""
}

# --- Docker --------------------------------------------------------------

install_docker() {
    spacer
    info "Installing Docker via get.docker.com..."
    if [[ "$JSON_MODE" == "1" ]]; then
        if ! curl -fsSL https://get.docker.com | sh 1>&2; then
            error "Docker installation failed"
            exit 1
        fi
    else
        if ! curl -fsSL https://get.docker.com | sh; then
            error "Docker installation failed"
            exit 1
        fi
    fi
    if command -v systemctl &> /dev/null; then
        sudo systemctl start docker 2>/dev/null || true
        sudo systemctl enable docker 2>/dev/null || true
    fi
    success "Docker installed"
    spacer
}

ensure_buildx() {
    local required_major=0 required_minor=17
    local buildx_version
    buildx_version="$($DOCKER_CMD buildx version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1 || true)"

    if [[ -z "$buildx_version" ]]; then
        warn "docker buildx not found — installing..."
    else
        local major minor
        major="$(echo "$buildx_version" | cut -d. -f1)"
        minor="$(echo "$buildx_version" | cut -d. -f2)"
        if (( major > required_major || (major == required_major && minor >= required_minor) )); then
            success "docker buildx $buildx_version (>= 0.17.0)"
            return
        fi
        warn "docker buildx $buildx_version is too old (need >= 0.17.0) — upgrading..."
    fi

    local BUILDX_VERSION="v0.21.2"
    local arch
    case "$(uname -m)" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l)  arch="arm-v7" ;;
        *)       error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    sudo mkdir -p /usr/local/lib/docker/cli-plugins
    if ! sudo curl -fSL "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-${arch}" \
        -o /usr/local/lib/docker/cli-plugins/docker-buildx; then
        error "Failed to download buildx ${BUILDX_VERSION}"
        exit 1
    fi
    sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx
    success "docker buildx upgraded to ${BUILDX_VERSION}"
}

check_docker() {
    step "Checking prerequisites"

    if ! command -v docker &> /dev/null; then
        warn "Docker is not installed — installing now..."
        install_docker
    fi
    success "Docker found"

    # Decide whether docker commands need `sudo`. `get.docker.com` doesn't
    # add the invoking user to the `docker` group, so on fresh-VPS installs
    # as a non-root user, `docker info` fails with EACCES on the socket.
    # Prior behavior misreported that as "daemon not running" and sent
    # users down a restart-docker rabbit hole. Now: try without sudo,
    # fall back to sudo. Export DOCKER_CMD so the Python installer
    # inherits the same decision.
    if docker info &>/dev/null; then
        DOCKER_CMD="docker"
    else
        DOCKER_CMD="sudo docker"
    fi
    export DOCKER_CMD

    # Prefer the v2 plugin (`docker compose ...`); fall back to the v1
    # legacy binary (`docker-compose ...`) on boxes where it's still the
    # only option. server.py's get_compose_cmd does the same fallback, so
    # keep them in sync. Modern get.docker.com installs ship the v2
    # plugin, so the fallback only kicks in on pre-existing installs
    # from distro packages (e.g. Ubuntu's `apt-get install docker-compose`).
    if ! $DOCKER_CMD compose version &>/dev/null && ! ${DOCKER_CMD}-compose version &>/dev/null; then
        error "Docker Compose is not available"
        detail "This usually means Docker installed without the compose plugin."
        detail "Try: sudo apt-get install docker-compose-plugin"
        exit 1
    fi
    success "Docker Compose found"

    # docker compose build requires buildx >= 0.17.0; Amazon Linux ships 0.12.1
    ensure_buildx

    if ! $DOCKER_CMD info &>/dev/null; then
        error "Docker daemon is not running"
        detail "Start Docker and try again."
        exit 1
    fi
    success "Docker daemon running"
}

# --- Firewall ------------------------------------------------------------

open_firewall() {
    # Always open 25/tcp for inbound SMTP. Also open 80/tcp when Let's
    # Encrypt is enabled: certbot --standalone needs inbound :80 for the
    # HTTP-01 challenge, and renewals every ~60 days hit the same port via
    # the systemd timer. The :80 rule stays in place after issuance — it
    # is required for renewal and operators sometimes use it for
    # health-check endpoints. We do not tear it down on subsequent runs.
    local ports=("25/tcp")
    if [[ "$ENABLE_LETSENCRYPT" == "1" ]]; then
        ports+=("80/tcp")
    fi

    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        for port in "${ports[@]}"; do
            if ! ufw status | grep -q "$port"; then
                info "Opening port $port in UFW firewall..."
                sudo ufw allow "$port" >/dev/null 2>&1
                success "Port $port opened in UFW"
            else
                success "Port $port already open in UFW"
            fi
        done
    fi

    if command -v firewall-cmd &> /dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then
        for port in "${ports[@]}"; do
            if ! firewall-cmd --list-ports 2>/dev/null | grep -q "$port"; then
                info "Opening port $port in firewalld..."
                sudo firewall-cmd --permanent --add-port="$port" >/dev/null 2>&1
                sudo firewall-cmd --reload >/dev/null 2>&1
                success "Port $port opened in firewalld"
            else
                success "Port $port already open in firewalld"
            fi
        done
    fi
}

# --- Let's Encrypt -------------------------------------------------------
#
# Optional, opt-in via --enable-letsencrypt. Issues a real cert with HTTP-01
# (port 80), wires it into .env, mounts /etc/letsencrypt into the
# primitivemail container, and installs a renewal deploy hook so postfix
# picks up renewed certs without operator intervention. Re-running with the
# flag is a no-op when a cert already exists at the target path.

letsencrypt_validate_args() {
    if [[ "$ENABLE_LETSENCRYPT" != "1" ]]; then
        return
    fi
    if [[ -z "$LE_EMAIL" ]]; then
        error "--enable-letsencrypt requires --le-email <address>"
        detail "Let's Encrypt requires an account email for expiration notices."
        exit 1
    fi
    if [[ -z "$LE_HOSTNAME" ]]; then
        error "--enable-letsencrypt requires --hostname <fqdn>"
        detail "The cert is issued for the public hostname of this mail server."
        exit 1
    fi
}

letsencrypt_preflight() {
    step "Let's Encrypt preflight"

    # Public DNS resolution of MYHOSTNAME. Without this the HTTP-01 challenge
    # cannot succeed, and certbot will fail several minutes into the run.
    local resolved=""
    if command -v getent &> /dev/null; then
        resolved="$(getent hosts "$LE_HOSTNAME" 2>/dev/null | awk '{print $1}' | head -1 || true)"
    fi
    if [[ -z "$resolved" ]] && command -v dig &> /dev/null; then
        resolved="$(dig +short A "$LE_HOSTNAME" 2>/dev/null | head -1 || true)"
    fi
    if [[ -z "$resolved" ]] && command -v host &> /dev/null; then
        resolved="$(host -t A "$LE_HOSTNAME" 2>/dev/null | awk '/has address/ {print $4}' | head -1 || true)"
    fi
    if [[ -z "$resolved" ]]; then
        error "Could not resolve $LE_HOSTNAME via public DNS"
        detail "Add an A record pointing $LE_HOSTNAME at this server's public IPv4 first."
        exit 1
    fi
    success "DNS: $LE_HOSTNAME resolves to $resolved"

    # Port 80 reachability. HTTP-01 needs inbound :80; certbot --standalone
    # will bind it during issuance, so it must be free on the host AND
    # reachable from the public internet. We can verify free-on-host
    # directly; reachability we can only attempt via a self-loopback test
    # which is best-effort (cloud firewalls block from the host itself in
    # some setups), so a failure here is a warning, not a hard error.
    if ss -tln 2>/dev/null | grep -qE ':80[[:space:]]' || netstat -tln 2>/dev/null | grep -qE ':80[[:space:]]'; then
        error "Port 80 is already in use on this host"
        detail "Certbot --standalone needs to bind :80 for the HTTP-01 challenge."
        detail "Stop whatever is listening on :80 (nginx, apache, another container) and retry."
        exit 1
    fi
    success "Port 80 is free on the host"

    # Soft check on port 25; the install opens it via UFW/firewalld, but a
    # cloud firewall in front of the box may still block it. Don't block on
    # this; the post-install verify path is the authoritative test.
    info "Port 25 is configured by the installer's firewall step; cloud security groups are out of scope here."
}

install_certbot() {
    if command -v certbot &> /dev/null; then
        success "certbot already installed"
        return
    fi

    info "Installing certbot..."
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
    fi

    if command -v dnf &> /dev/null; then
        # Amazon Linux 2023, Fedora, RHEL 8+
        sudo dnf install -y certbot >/dev/null 2>&1 || {
            error "Failed to install certbot via dnf"
            exit 1
        }
    elif command -v yum &> /dev/null; then
        # Amazon Linux 2, RHEL 7. EPEL is required for certbot on AL2.
        if [[ "${ID:-}" == "amzn" ]]; then
            sudo amazon-linux-extras install -y epel >/dev/null 2>&1 || true
        fi
        sudo yum install -y certbot >/dev/null 2>&1 || {
            error "Failed to install certbot via yum"
            detail "On Amazon Linux 2, ensure EPEL is enabled."
            exit 1
        }
    elif command -v apt-get &> /dev/null; then
        sudo apt-get update -qq >/dev/null 2>&1 || true
        sudo apt-get install -y -qq certbot >/dev/null 2>&1 || {
            error "Failed to install certbot via apt-get"
            exit 1
        }
    else
        error "No supported package manager found (dnf, yum, apt-get)"
        detail "Install certbot manually and re-run with --enable-letsencrypt."
        exit 1
    fi
    success "certbot installed"
}

issue_letsencrypt_cert() {
    local cert_path="/etc/letsencrypt/live/${LE_HOSTNAME}/fullchain.pem"

    if sudo test -f "$cert_path"; then
        success "Existing Let's Encrypt cert found at $cert_path; skipping issuance"
        return
    fi

    info "Issuing Let's Encrypt certificate for $LE_HOSTNAME..."
    if ! sudo certbot certonly --standalone \
        -d "$LE_HOSTNAME" \
        -m "$LE_EMAIL" \
        --non-interactive --agree-tos \
        --preferred-challenges http; then
        error "certbot failed to issue a certificate"
        detail "Common causes: DNS not pointing at this host, port 80 blocked, rate limits."
        detail "See /var/log/letsencrypt/letsencrypt.log for details."
        exit 1
    fi
    success "Issued certificate for $LE_HOSTNAME"
}

forward_letsencrypt_paths() {
    # Forward the LE cert paths to the Python installer via --tls-cert /
    # --tls-key, and the host directory that docker-compose should bind to
    # /etc/letsencrypt via --letsencrypt-host-dir. The Python installer's
    # generate_env_content writes all three into .env, which docker-compose
    # reads to populate TLS_CERT / TLS_KEY and resolve the bind-mount source
    # via the LETSENCRYPT_HOST_DIR env-var default in the volumes block.
    # Doing it via the Python installer (instead of appending lines to .env
    # after the fact) avoids the Python installer's write_env clobbering
    # these values during normal operation.
    local cert_path="/etc/letsencrypt/live/${LE_HOSTNAME}/fullchain.pem"
    local key_path="/etc/letsencrypt/live/${LE_HOSTNAME}/privkey.pem"
    FORWARD_ARGS+=(
        "--tls-cert" "$cert_path"
        "--tls-key" "$key_path"
        "--letsencrypt-host-dir" "/etc/letsencrypt"
    )
    success "Forwarding TLS_CERT=$cert_path to installer"
}

install_renewal_hook() {
    # Renewal deploy hook: certbot runs this after a successful renewal. We
    # reload postfix in the running container so the new cert chain is read
    # without dropping any in-flight SMTP connections.
    #
    # Implementation note: we use `docker exec primitivemail postfix reload`
    # rather than `docker compose exec ...`. This sidesteps the compose
    # v1/v2 split (older `docker-compose` boxes are still in the wild and
    # check_docker accepts them) and removes the `cd ${INSTALL_DIR}`
    # dependency, which was fragile if the operator later moved the install
    # dir. The container_name `primitivemail` is hardcoded in
    # docker-compose.yml, so addressing it directly is stable.
    #
    # Operator-edit safety: every hook we write carries the marker
    # "Managed by primitivemail" in its header. On re-run, if the file
    # exists but lacks the marker, we assume the operator hand-edited the
    # hook and we leave it alone (printing a warning). Re-running with a
    # marker-bearing hook overwrites it freely so future installer changes
    # to the hook body propagate.
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    local hook_path="${hook_dir}/reload-postfix.sh"
    local marker="Managed by primitivemail"

    if sudo test -f "$hook_path" && ! sudo grep -q "$marker" "$hook_path"; then
        warn "Existing renewal hook at $hook_path has no '$marker' marker; leaving it alone"
        detail "Delete the file or restore the marker comment to let install.sh refresh it."
        return
    fi

    sudo mkdir -p "$hook_dir"
    sudo tee "$hook_path" > /dev/null <<'EOF'
#!/bin/bash
# Managed by primitivemail install.sh --enable-letsencrypt.
# Reload postfix in the primitivemail container after Let's Encrypt renews.
# Re-run install.sh --enable-letsencrypt to refresh this file. If you need
# to customize it, remove the "Managed by primitivemail" marker line above
# and the installer will leave your edits in place on subsequent runs.
set -e

# Distinguish "docker daemon down" from "container intentionally stopped".
# The former should fail loudly so certbot's hook-failure surface catches
# the misconfiguration; the latter should exit 0 because the cert renewed
# fine and the operator chose to keep the container down.
if ! docker info >/dev/null 2>&1; then
    echo "reload-postfix.sh: docker daemon unreachable; postfix reload skipped" 1>&2
    exit 1
fi

# `docker container inspect` is preferred over `docker ps -q -f` here:
# the latter returns success even when the filter matches nothing.
state="$(docker container inspect -f '{{.State.Running}}' primitivemail 2>/dev/null || true)"
if [[ "$state" != "true" ]]; then
    # Container does not exist or is stopped. Treat as intentional and exit 0.
    exit 0
fi

docker exec primitivemail postfix reload
EOF
    sudo chmod +x "$hook_path"
    success "Installed renewal hook at $hook_path"
}

# Enable and start the certbot renewal systemd timer.
#
# Why this exists: certbot's deb postinst on Debian/Ubuntu enables
# `certbot.timer` automatically. The RPM packages on AL2023, RHEL,
# Rocky, AlmaLinux, and Fedora ship `certbot-renew.timer` (note the
# different unit name) but follow the RPM convention of leaving units
# disabled on install. Without this step, the cert issues fine, the
# renewal deploy hook is in place, but `certbot renew` is never invoked
# on a schedule and the cert silently expires 90 days later.
#
# Strategy: try both unit names, enable --now whichever one the
# installed certbot package shipped, and warn loudly with a cron
# fallback if neither is present.
ensure_certbot_timer_enabled() {
    local enabled=0
    local unit
    for unit in certbot-renew.timer certbot.timer; do
        if systemctl list-unit-files "$unit" 2>/dev/null | grep -q "^${unit}\b"; then
            if sudo systemctl enable --now "$unit" >/dev/null 2>&1; then
                success "Enabled ${unit} for automatic cert renewal"
                enabled=1
                break
            fi
        fi
    done
    if [[ $enabled -eq 0 ]]; then
        warn "Could not find or enable a certbot renewal timer."
        warn "Automatic renewal is NOT scheduled. Your cert will expire in 90 days."
        detail "As a fallback, add a cron entry:"
        detail "  0 4,16 * * * $(command -v certbot || echo certbot) renew --quiet"
    fi
}

# Surface the next scheduled renewal time so the operator can see it
# wired up. `certbot renew --dry-run` only proves the cert can renew;
# it says nothing about whether anything is scheduled to call renew.
verify_renewal_timer() {
    local next
    next=$(systemctl list-timers certbot.timer certbot-renew.timer --no-pager 2>/dev/null \
           | awk '/certbot/ {print $1, $2, $3, $4; exit}')
    if [[ -n "$next" ]]; then
        success "Renewal timer scheduled. Next fire: $next"
    else
        warn "No certbot timer visible in systemctl list-timers."
        warn "Renewal may not be scheduled. Investigate before relying on it."
    fi
}

verify_renewal() {
    if [[ "$LE_SKIP_VERIFY" == "1" ]]; then
        info "Skipping certbot renew --dry-run (--le-skip-verify)"
        return
    fi
    info "Verifying renewal config (certbot renew --dry-run)..."
    if sudo certbot renew --dry-run >/dev/null 2>&1; then
        success "Renewal dry-run succeeded"
    else
        warn "Renewal dry-run reported issues. Run 'sudo certbot renew --dry-run' to investigate."
    fi
}

setup_letsencrypt() {
    if [[ "$ENABLE_LETSENCRYPT" != "1" ]]; then
        return
    fi
    spacer
    letsencrypt_preflight
    install_certbot
    issue_letsencrypt_cert
    forward_letsencrypt_paths
    install_renewal_hook
    # Order matters: enable the timer BEFORE the dry-run verify so the
    # timer is live by the time we check anything, and run
    # verify_renewal_timer right after enable so its "next fire" output
    # reflects the unit we just enabled.
    ensure_certbot_timer_enabled
    verify_renewal_timer
    verify_renewal
    spacer
}

# Preserve TLS_CERT / TLS_KEY / LETSENCRYPT_HOST_DIR across re-runs.
#
# The Python installer's write_env recreates .env from CLI args every run, so
# an operator who set up Let's Encrypt last week and re-runs install.sh
# (without --enable-letsencrypt and without explicit --tls-cert/--tls-key/
# --letsencrypt-host-dir) would otherwise see those values silently dropped
# from .env. The container would fall back to the self-signed cert on the
# next restart, and the docker-compose LETSENCRYPT_HOST_DIR default would
# bind /var/empty over /etc/letsencrypt.
#
# Behavior (each of cert / key / host_dir is evaluated INDEPENDENTLY so
# passing only one of the flags does not silently drop the unflagged ones):
#   - If --enable-letsencrypt is set, forward_letsencrypt_paths handles the
#     forwarding and we do nothing here. LE owns all three.
#   - For each of cert / key / host_dir independently:
#       * If the corresponding --tls-cert / --tls-key /
#         --letsencrypt-host-dir flag was explicit on this invocation,
#         the operator's choice wins; do not preserve that side. Explicit
#         empty string still counts as explicit (the operator is asking to
#         clear that value), so we do not preserve over an empty arg.
#       * Otherwise, if the existing .env value points at a file/dir that
#         exists on disk, forward it via the matching --... flag.
#
# Pairing correctness (matching cert + key) is NOT enforced here; it never
# was. An operator who passes --tls-cert /new/cert without --tls-key will
# end up with /new/cert paired with the preserved old key, which may not
# verify. That is the same contract as before this fix: install.sh
# preserves values, the operator owns coherence between them.
preserve_existing_tls_paths() {
    if [[ "$ENABLE_LETSENCRYPT" == "1" ]]; then
        return
    fi
    local env_path="${INSTALL_DIR}/.env"
    if [[ ! -f "$env_path" ]]; then
        return
    fi

    # `|| true` on the pipeline tail is load-bearing: under `set -euo
    # pipefail`, grep's exit-1-on-no-match would propagate up and abort the
    # script. Old installs predating this PR have a .env with no TLS_CERT /
    # TLS_KEY lines at all, which is exactly the no-match case; without the
    # guard, the first re-install on those boxes exits before reaching the
    # Python installer.
    local existing_cert existing_key existing_host_dir
    existing_cert="$(grep -E '^TLS_CERT=' "$env_path" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
    existing_key="$(grep -E '^TLS_KEY=' "$env_path" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
    existing_host_dir="$(grep -E '^LETSENCRYPT_HOST_DIR=' "$env_path" 2>/dev/null | tail -1 | cut -d= -f2- || true)"

    # Use sudo for the on-disk check because /etc/letsencrypt/live/<host>/
    # is mode 700 root:root by default; a non-root operator running
    # install.sh under sudo would otherwise see the file as missing and we
    # would silently drop the LE config.
    local preserved_cert=""
    local preserved_key=""
    local preserved_host_dir=""

    if [[ "$TLS_CERT_EXPLICIT" != "1" && -n "$existing_cert" ]] && sudo test -f "$existing_cert"; then
        FORWARD_ARGS+=("--tls-cert" "$existing_cert")
        preserved_cert="$existing_cert"
    fi

    if [[ "$TLS_KEY_EXPLICIT" != "1" && -n "$existing_key" ]] && sudo test -f "$existing_key"; then
        FORWARD_ARGS+=("--tls-key" "$existing_key")
        preserved_key="$existing_key"
    fi

    # LETSENCRYPT_HOST_DIR is the bind-mount source resolved by docker-compose
    # at start time. Preserve independently so an operator who set up LE
    # previously does not lose the cert mount on a re-run that omits the
    # flag. Existence check uses sudo for the same reason as cert/key above.
    if [[ "$LETSENCRYPT_HOST_DIR_EXPLICIT" != "1" && -n "$existing_host_dir" ]] && sudo test -d "$existing_host_dir"; then
        FORWARD_ARGS+=("--letsencrypt-host-dir" "$existing_host_dir")
        preserved_host_dir="$existing_host_dir"
    fi

    if [[ -n "$preserved_cert" || -n "$preserved_key" || -n "$preserved_host_dir" ]]; then
        info "Preserving existing TLS config: cert=${preserved_cert:-<unchanged>}, key=${preserved_key:-<unchanged>}, host_dir=${preserved_host_dir:-<unchanged>}"
    fi
}

# --- Clone ---------------------------------------------------------------

clone_repo() {
    step "Setting up PrimitiveMail"

    # If this script lives alongside the project files, use that directory
    if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [[ -f "$script_dir/Dockerfile" && -f "$script_dir/docker-compose.yml" ]]; then
            INSTALL_DIR="$script_dir"
            export PRIMITIVEMAIL_DIR="$INSTALL_DIR"
            info "Using existing PrimitiveMail directory: $INSTALL_DIR"
            return
        fi
    fi

    if [[ -d "$INSTALL_DIR" ]]; then
        if [[ -d "$INSTALL_DIR/.git" ]]; then
            # Respect PRIMITIVEMAIL_BRANCH on the update path too. Without
            # this, re-running the installer on a VM that previously cloned
            # main would silently pull main even when the one-liner came
            # from a branch URL. The dogfooding flow for testing a branch
            # on an existing VM is exactly this case.
            local current_branch
            current_branch="$(git -C "$INSTALL_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
            if [[ -n "$current_branch" && "$current_branch" != "$PRIMITIVEMAIL_BRANCH" ]]; then
                info "Switching branch: $current_branch -> $PRIMITIVEMAIL_BRANCH"
                if ! git -C "$INSTALL_DIR" fetch --quiet origin "$PRIMITIVEMAIL_BRANCH" 2>/dev/null \
                    || ! git -C "$INSTALL_DIR" checkout --quiet "$PRIMITIVEMAIL_BRANCH" 2>/dev/null; then
                    warn "Could not switch to $PRIMITIVEMAIL_BRANCH; staying on $current_branch"
                fi
            else
                info "Directory exists, pulling latest"
            fi
            if git -C "$INSTALL_DIR" pull --quiet 2>/dev/null; then
                success "Updated $INSTALL_DIR"
            else
                info "Could not pull (offline or no remote). Using existing files."
            fi
            return
        elif [[ -f "$INSTALL_DIR/Dockerfile" ]]; then
            info "Directory exists with PrimitiveMail files. Using existing files."
            return
        else
            error "$INSTALL_DIR exists but does not contain PrimitiveMail files"
            exit 1
        fi
    fi

    if command -v git &> /dev/null; then
        if [[ "$PRIMITIVEMAIL_BRANCH" != "main" ]]; then
            info "Cloning branch: $PRIMITIVEMAIL_BRANCH"
        fi
        git clone --quiet --branch "$PRIMITIVEMAIL_BRANCH" \
            https://github.com/primitivedotdev/primitivemail.git "$INSTALL_DIR"
        success "Cloned to $INSTALL_DIR"
    else
        error "Git is not installed"
        detail "Install git and try again."
        exit 1
    fi
}

# --- Python check --------------------------------------------------------

check_python() {
    if command -v python3 &> /dev/null; then
        return
    fi

    warn "Python 3 is not installed — attempting to install..."

    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq python3 >/dev/null 2>&1 || true
    elif command -v yum &> /dev/null; then
        sudo yum install -y -q python3 >/dev/null 2>&1 || true
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y -q python3 >/dev/null 2>&1 || true
    fi

    if ! command -v python3 &> /dev/null; then
        error "Python 3.6+ is required but could not be installed."
        detail "Install Python 3 manually and re-run this script."
        exit 1
    fi
    success "Python 3 installed"
}

# --- Preflight (read-only env check) -------------------------------------

# Delegates to installer/preflight.py. When run via `curl ... | bash --preflight`
# there is no local checkout yet, so we fetch the preflight module from the
# repo into a tempfile and run it directly. When run from a checkout, use the
# local copy so branches can test their own preflight logic.
#
# This path is read-only: does NOT install Docker, does NOT install Python,
# does NOT clone the repo. The whole point is catching "this environment
# cannot support an install" before any of those mutations happen.
run_preflight() {
    if ! command -v python3 &> /dev/null; then
        printf '{"event":"preflight","overall":"fail","failed":["python"],"checks":{"python":{"status":"fail","installed":false,"message":"python3 is required for preflight"}}}\n'
        exit 1
    fi

    # Prefer a local checkout sitting alongside this script (dev / test).
    local script_dir=""
    if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi
    if [[ -n "$script_dir" && -f "$script_dir/installer/preflight.py" ]]; then
        cd "$script_dir"
        exec python3 -u -m installer.preflight
    fi
    if [[ -d "$INSTALL_DIR/installer" && -f "$INSTALL_DIR/installer/preflight.py" ]]; then
        cd "$INSTALL_DIR"
        exec python3 -u -m installer.preflight
    fi

    # curl|bash path: no checkout available — fetch the module directly.
    # Explicit cleanup rather than `trap ... EXIT` because bash's `set -u`
    # (nounset) treats the trap's `$tmp_preflight` expansion as an unbound
    # variable once the function's `local` has gone out of scope at
    # script-exit time — which printed "line 1: tmp_preflight: unbound
    # variable" after every curl-bash preflight run.
    local tmp_preflight
    tmp_preflight=$(mktemp)
    local raw_url="https://raw.githubusercontent.com/primitivedotdev/primitivemail/${PRIMITIVEMAIL_BRANCH}/installer/preflight.py"
    if ! curl -fsSL --max-time 10 "$raw_url" -o "$tmp_preflight"; then
        rm -f "$tmp_preflight"
        printf '{"event":"preflight","overall":"fail","failed":["fetch"],"checks":{"fetch":{"status":"fail","message":"could not fetch preflight module from %s"}}}\n' "$raw_url"
        exit 1
    fi
    python3 -u "$tmp_preflight"
    local rc=$?
    rm -f "$tmp_preflight"
    exit $rc
}

# --- Main ----------------------------------------------------------------

main() {
    # Preflight runs before any mutating step (Docker install, firewall, clone).
    # Emits a single JSON line and exits with 0/1 so agents can gate on it.
    if [[ "$PREFLIGHT_MODE" == "1" ]]; then
        run_preflight
    fi

    # Validate Let's Encrypt args early so an obviously bad invocation
    # fails before we install Docker / open the firewall / clone the repo.
    letsencrypt_validate_args

    print_banner
    check_docker
    open_firewall
    clone_repo
    check_python
    INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"
    export PRIMITIVEMAIL_DIR="$INSTALL_DIR"
    cd "$INSTALL_DIR"

    # Let's Encrypt provisioning runs after the clone (so docker-compose.yml
    # exists for the mount injection) but before the Python installer
    # (so the .env we write is the one the Python installer extends, and so
    # the cert is in place by the time `docker compose up` reads .env).
    setup_letsencrypt

    # If --enable-letsencrypt was not on the CLI this run but an existing
    # .env already declares a TLS_CERT path that exists on disk, forward
    # those paths so the re-run does not silently drop the previous run's
    # TLS config. setup_letsencrypt's own forward_letsencrypt_paths short-
    # circuits the preservation path when it already added --tls-cert.
    preserve_existing_tls_paths

    if [[ ! -d "installer" ]]; then
        error "Installer package not found. Your copy may be outdated."
        detail "Try: rm -rf $INSTALL_DIR && rerun the install script."
        exit 1
    fi

    # -u forces unbuffered stdio. Agents tailing /tmp/install.stderr (or any
    # log file redirection) otherwise see block-buffered output lagging
    # reality by minutes when stderr is a file instead of a TTY.
    exec python3 -u -m installer.main ${FORWARD_ARGS[@]+"${FORWARD_ARGS[@]}"}
}

main
