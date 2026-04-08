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

info()    { echo -e "${MUTED}.${NC} $*"; }
success() { echo -e "${GREEN}+${NC} $*"; }
warn()    { echo -e "${YELLOW}!${NC} $*"; }
error()   { echo -e "${RED}x${NC} $*"; }
step()    { echo -e "${BLUE}>${NC} ${BOLD}$*${NC}"; }

# --- Parse --dir and --help before forwarding to Python ------------------

INSTALL_DIR="${PRIMITIVEMAIL_DIR:-./primitivemail}"
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
        --help|-h)
            echo "PrimitiveMail Installer"
            echo ""
            echo "Usage: curl -fsSL https://get.primitive.dev | bash"
            echo "   or: ./install.sh [OPTIONS]"
            echo ""
            echo "Common options:"
            echo "  --hostname HOST          Mail server hostname (e.g. mx.example.com)"
            echo "  --domain DOMAIN          Domain to receive mail for (e.g. example.com)"
            echo "  --webhook-url URL        Webhook endpoint for email processing"
            echo "  --webhook-secret SECRET  Secret for webhook authentication"
            echo "  --dir PATH               Install directory (default: ./primitivemail)"
            echo "  --ip-literal IP          Enable IP literal mail for this IP"
            echo "  --spoof-protection LEVEL off|monitor|standard|strict (default: off)"
            echo "  --no-prompt, -y          Non-interactive mode"
            echo "  --verbose                Show detailed output"
            echo "  --help, -h               Show this help"
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
    echo ""
    info "Installing Docker via get.docker.com..."
    if ! curl -fsSL https://get.docker.com | sh; then
        error "Docker installation failed"
        exit 1
    fi
    if command -v systemctl &> /dev/null; then
        sudo systemctl start docker 2>/dev/null || true
        sudo systemctl enable docker 2>/dev/null || true
    fi
    success "Docker installed"
    echo ""
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
    sudo mkdir -p /usr/local/lib/docker/cli-plugins
    if ! sudo curl -SL "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-amd64" \
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
        echo "  This usually means Docker installed without the compose plugin."
        echo "  Try: sudo apt-get install docker-compose-plugin"
        exit 1
    fi
    success "Docker Compose found"

    # docker compose build requires buildx >= 0.17.0; Amazon Linux ships 0.12.1
    ensure_buildx

    if ! docker info &> /dev/null 2>&1; then
        error "Docker daemon is not running"
        echo "  Start Docker and try again."
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
        echo "  Install git and try again."
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
        echo "  Install Python 3 manually and re-run this script."
        exit 1
    fi
    success "Python 3 installed"
}

# --- Main ----------------------------------------------------------------

main() {
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
        echo "  Try: rm -rf $INSTALL_DIR && rerun the install script."
        exit 1
    fi

    exec python3 -m installer.main ${FORWARD_ARGS[@]+"${FORWARD_ARGS[@]}"}
}

main
