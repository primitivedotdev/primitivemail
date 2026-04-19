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
            echo "Output:"
            echo "  --json                    Emit NDJSON progress events on stdout (implies --no-prompt)"
            echo "  --verbose                 Show detailed output"
            echo "  --no-prompt, -y           Non-interactive mode"
            echo ""
            echo "Other:"
            echo "  --dir PATH                Install directory (default: ./primitivemail)"
            echo "  --preflight               Check environment (RAM, disk, port 25, outbound HTTPS)"
            echo "                            without installing. Emits one JSON line, exits 1 on failure."
            echo "  --help, -h                Show this help"
            exit 0
            ;;
        *)
            FORWARD_ARGS+=("$1")
            shift
            ;;
    esac
done

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
    buildx_version="$(docker buildx version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1 || true)"

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

    if ! docker compose version &> /dev/null && ! docker-compose version &> /dev/null; then
        error "Docker Compose is not available"
        detail "This usually means Docker installed without the compose plugin."
        detail "Try: sudo apt-get install docker-compose-plugin"
        exit 1
    fi
    success "Docker Compose found"

    # docker compose build requires buildx >= 0.17.0; Amazon Linux ships 0.12.1
    ensure_buildx

    if ! docker info &> /dev/null 2>&1; then
        error "Docker daemon is not running"
        detail "Start Docker and try again."
        exit 1
    fi
    success "Docker daemon running"
}

# --- Firewall ------------------------------------------------------------

open_firewall() {
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ! ufw status | grep -q "25/tcp"; then
            info "Opening port 25 in UFW firewall..."
            sudo ufw allow 25/tcp >/dev/null 2>&1
            success "Port 25 opened in UFW"
        else
            success "Port 25 already open in UFW"
        fi
    fi

    if command -v firewall-cmd &> /dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then
        if ! firewall-cmd --list-ports 2>/dev/null | grep -q "25/tcp"; then
            info "Opening port 25 in firewalld..."
            sudo firewall-cmd --permanent --add-port=25/tcp >/dev/null 2>&1
            sudo firewall-cmd --reload >/dev/null 2>&1
            success "Port 25 opened in firewalld"
        else
            success "Port 25 already open in firewalld"
        fi
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
            info "Directory exists, pulling latest"
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
        git clone --quiet https://github.com/primitivedotdev/primitivemail.git "$INSTALL_DIR"
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
    local tmp_preflight
    tmp_preflight=$(mktemp)
    trap 'rm -f "$tmp_preflight"' EXIT
    local raw_url="https://raw.githubusercontent.com/primitivedotdev/primitivemail/main/installer/preflight.py"
    if ! curl -fsSL --max-time 10 "$raw_url" -o "$tmp_preflight"; then
        printf '{"event":"preflight","overall":"fail","failed":["fetch"],"checks":{"fetch":{"status":"fail","message":"could not fetch preflight module from %s"}}}\n' "$raw_url"
        exit 1
    fi
    exec python3 -u "$tmp_preflight"
}

# --- Main ----------------------------------------------------------------

main() {
    # Preflight runs before any mutating step (Docker install, firewall, clone).
    # Emits a single JSON line and exits with 0/1 so agents can gate on it.
    if [[ "$PREFLIGHT_MODE" == "1" ]]; then
        run_preflight
    fi

    print_banner
    check_docker
    open_firewall
    clone_repo
    check_python
    INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"
    export PRIMITIVEMAIL_DIR="$INSTALL_DIR"
    cd "$INSTALL_DIR"

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
