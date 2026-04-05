#!/bin/bash
set -euo pipefail

# PrimitiveMail Installer
# Usage: curl -fsSL https://get.primitive.dev | bash
#   or:  ./install.sh --hostname mx.example.com --domain example.com

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[38;2;74;222;128m'
RED='\033[38;2;248;113;113m'
YELLOW='\033[38;2;250;204;21m'
BLUE='\033[38;2;96;165;250m'
MUTED='\033[38;2;113;113;122m'
NC='\033[0m'

# --- Defaults -----------------------------------------------------------

INSTALL_DIR="${PRIMITIVEMAIL_DIR:-./primitivemail}"
PM_HOSTNAME=""
PM_DOMAIN=""
PM_IP_LITERAL=""
WEBHOOK_URL=""
WEBHOOK_SECRET=""
ALLOWED_SENDER_DOMAINS=""
ALLOWED_SENDERS=""
ALLOWED_RECIPIENTS=""
SPOOF_PROTECTION="off"
NO_PROMPT=0
NO_START=0
VERBOSE=0

# --- Parse flags ---------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostname)     PM_HOSTNAME="$2"; shift 2 ;;
        --domain)       PM_DOMAIN="$2"; shift 2 ;;
        --webhook-url)  WEBHOOK_URL="$2"; shift 2 ;;
        --webhook-secret) WEBHOOK_SECRET="$2"; shift 2 ;;
        --dir)          INSTALL_DIR="$2"; shift 2 ;;
        --ip-literal)   PM_IP_LITERAL="$2"; shift 2 ;;
        --allowed-sender-domains) ALLOWED_SENDER_DOMAINS="$2"; shift 2 ;;
        --allowed-senders) ALLOWED_SENDERS="$2"; shift 2 ;;
        --allowed-recipients) ALLOWED_RECIPIENTS="$2"; shift 2 ;;
        --spoof-protection) SPOOF_PROTECTION="$2"; shift 2 ;;
        --no-prompt|-y) NO_PROMPT=1; shift ;;
        --no-start)     NO_START=1; shift ;;
        --verbose)      VERBOSE=1; shift ;;
        --help|-h)
            echo "Usage: install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --hostname HOST          Mail server hostname (e.g. mx.example.com)"
            echo "  --domain DOMAIN          Domain to receive mail for (e.g. example.com)"
            echo "  --webhook-url URL        Webhook endpoint for email processing"
            echo "  --webhook-secret S       Secret for webhook authentication"
            echo "  --ip-literal IP          Enable IP literal mail for this IP (auto-detected if omitted)"
            echo "  --allowed-sender-domains Comma-separated allowed sender domains"
            echo "  --allowed-senders        Comma-separated allowed sender addresses"
            echo "  --allowed-recipients     Comma-separated allowed recipient addresses"
            echo "  --spoof-protection LEVEL off|monitor|standard|strict (default: off)"
            echo "  --dir PATH               Install directory (default: ./primitivemail)"
            echo "  --no-prompt, -y          Non-interactive mode (skip all prompts)"
            echo "  --no-start               Clone and configure only, don't start"
            echo "  --verbose                Show detailed output"
            echo "  --help, -h               Show this help"
            echo ""
            echo "Examples:"
            echo "  # Quick start (standalone mode, accepts all mail):"
            echo "  curl -fsSL https://primitive.dev/install.sh | bash"
            echo ""
            echo "  # Non-interactive with webhook:"
            echo "  ./install.sh -y --hostname mx.example.com --domain example.com \\"
            echo "    --webhook-url https://api.example.com/email --webhook-secret mysecret"
            echo ""
            echo "  # Standalone with sender filtering and spoof protection:"
            echo "  ./install.sh -y --allowed-sender-domains trusted.org \\"
            echo "    --spoof-protection standard"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Run with --help for usage"
            exit 1
            ;;
    esac
done

# --- UI helpers ----------------------------------------------------------

info()    { echo -e "${MUTED}.${NC} $*"; }
success() { echo -e "${GREEN}+${NC} $*"; }
warn()    { echo -e "${YELLOW}!${NC} $*"; }
error()   { echo -e "${RED}x${NC} $*"; }
step()    { echo -e "${BLUE}>${NC} ${BOLD}$*${NC}"; }

prompt_value() {
    local var_name="$1" prompt_text="$2" default="$3"
    if [[ $NO_PROMPT -eq 1 ]]; then
        eval "$var_name=\"$default\""
        return
    fi
    local display_default=""
    if [[ -n "$default" ]]; then
        display_default=" ${DIM}(${default})${NC}"
    fi
    echo -ne "  ${prompt_text}${display_default}: "
    local input
    read -r input
    eval "$var_name=\"${input:-$default}\""
}

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

# --- Preflight checks ----------------------------------------------------

install_docker() {
    echo ""
    info "Installing Docker via get.docker.com..."
    if ! curl -fsSL https://get.docker.com | sh; then
        error "Docker installation failed"
        exit 1
    fi
    # Start Docker if not already running
    if command -v systemctl &> /dev/null; then
        sudo systemctl start docker 2>/dev/null || true
        sudo systemctl enable docker 2>/dev/null || true
    fi
    success "Docker installed"
    echo ""
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

    if ! docker info &> /dev/null 2>&1; then
        error "Docker daemon is not running"
        echo "  Start Docker and try again."
        exit 1
    fi
    success "Docker daemon running"
}

open_firewall() {
    # Open port 25 in UFW if active
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ! ufw status | grep -q "25/tcp"; then
            info "Opening port 25 in UFW firewall..."
            sudo ufw allow 25/tcp >/dev/null 2>&1
            success "Port 25 opened in UFW"
        else
            success "Port 25 already open in UFW"
        fi
    fi

    # Open port 25 in firewalld if active
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

# --- Clone / download ----------------------------------------------------

clone_repo() {
    step "Setting up PrimitiveMail"

    # If this script lives alongside the project files, use that directory
    if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [[ -f "$script_dir/Dockerfile" && -f "$script_dir/docker-compose.yml" ]]; then
            INSTALL_DIR="$script_dir"
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

# --- Progress spinner ----------------------------------------------------

run_with_progress() {
    local cmd="$1" label="$2"
    local spin_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0 elapsed=0 ticks=0

    # Run command in background, capture output for error reporting
    local logfile
    logfile=$(mktemp)
    eval "$cmd" > "$logfile" 2>&1 &
    local pid=$!

    # Spinner loop (10fps, update elapsed time every second)
    while kill -0 "$pid" 2>/dev/null; do
        local c="${spin_chars:i%10:1}"
        printf "\r  ${MUTED}%s${NC} %s ${DIM}(%ds)${NC}  " "$c" "$label" "$elapsed"
        sleep 0.1
        ticks=$((ticks + 1))
        elapsed=$((ticks / 10))
        i=$((i + 1))
    done

    # Check exit status
    wait "$pid"
    local status=$?
    printf "\r\033[K"  # Clear the spinner line

    if [[ $status -eq 0 ]]; then
        success "$label complete (${elapsed}s)"
    else
        error "$label failed"
        echo ""
        tail -20 "$logfile"
        rm -f "$logfile"
        exit 1
    fi
    rm -f "$logfile"
}

# --- IP detection --------------------------------------------------------

detect_public_ip() {
    local ip=""
    # Try multiple services in case one is down
    for url in "https://ifconfig.me" "https://api.ipify.org" "https://icanhazip.com"; do
        ip=$(curl -fsSL --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return
        fi
    done
}

# --- Configure -----------------------------------------------------------

prompt_yn() {
    local prompt_text="$1" default="$2"
    if [[ $NO_PROMPT -eq 1 ]]; then
        [[ "$default" == "y" ]] && return 0 || return 1
    fi
    local hint="y/n"
    [[ "$default" == "y" ]] && hint="Y/n" || hint="y/N"
    echo -ne "  ${prompt_text} ${DIM}(${hint})${NC}: "
    local input
    read -r input
    input="${input:-$default}"
    [[ "${input,,}" == "y" ]]
}

prompt_choice() {
    local prompt_text="$1" max="$2" default="$3"
    if [[ $NO_PROMPT -eq 1 ]]; then
        echo "$default"
        return
    fi
    # Prompt goes to stderr so it doesn't pollute the captured stdout
    echo -ne "  ${prompt_text} ${DIM}(default ${default})${NC}: " >&2
    local input
    read -r input
    input="${input:-$default}"
    # Validate
    if [[ "$input" =~ ^[0-9]+$ ]] && [[ "$input" -ge 1 ]] && [[ "$input" -le "$max" ]]; then
        echo "$input"
    else
        echo "$default"
    fi
}

configure() {
    step "Configuration"

    if [[ $NO_PROMPT -eq 1 ]]; then
        # Non-interactive: use whatever was passed via flags
        PM_HOSTNAME="${PM_HOSTNAME:-localhost}"
        PM_DOMAIN="${PM_DOMAIN:-localhost}"
        # Track whether user provided a real domain
        if [[ "$PM_HOSTNAME" != "localhost" ]]; then
            HAS_DOMAIN=1
        else
            HAS_DOMAIN=0
        fi
        # Auto-detect IP if no domain and no IP provided
        if [[ "$PM_HOSTNAME" == "localhost" && -z "$PM_IP_LITERAL" ]]; then
            PM_IP_LITERAL=$(detect_public_ip)
        fi
    else
        # --- DNS setup ---
        echo ""
        if prompt_yn "Do you have a domain name for receiving email?" "n"; then
            echo ""
            echo -e "  ${BOLD}Hostname${NC} ${MUTED}- the address of this mail server itself.${NC}"
            echo -e "  ${MUTED}Other mail servers connect to this when delivering email to you.${NC}"
            echo -e "  ${MUTED}Usually something like mx.yourdomain.com${NC}"
            prompt_value PM_HOSTNAME "Hostname" "${PM_HOSTNAME:-mx.example.com}"
            echo ""
            echo -e "  ${BOLD}Domain${NC} ${MUTED}- the domain you want to receive email for.${NC}"
            echo -e "  ${MUTED}If you want to receive mail at user@example.com, enter example.com${NC}"
            prompt_value PM_DOMAIN "Domain" "${PM_DOMAIN:-example.com}"

            HAS_DOMAIN=1
        else
            echo ""
            warn "No domain means this server can ONLY receive email via IP literal addresses."
            echo ""
            info "Instead of:  ${BOLD}user@example.com${NC}"
            info "You'll use:  ${BOLD}user@[1.2.3.4]${NC}  (with the brackets)"
            echo ""
            info "Gmail, Outlook, and most providers support this, but some may not."
            info "You can always add a domain later by editing .env and restarting."
            echo ""
            info "Detecting your public IP..."
            PM_IP_LITERAL=$(detect_public_ip)
            if [[ -n "$PM_IP_LITERAL" ]]; then
                success "Detected public IP: $PM_IP_LITERAL"
                echo ""
                echo -e "  ${BOLD}To send email to this server, use:${NC}"
                echo -e "  ${GREEN}anything@[${PM_IP_LITERAL}]${NC}"
                echo ""
                success "IP literal support will be enabled automatically"
            else
                warn "Could not detect public IP. Set ENABLE_IP_LITERAL=true and IP_LITERAL=<your-ip> in .env"
            fi
            PM_HOSTNAME="localhost"
            PM_DOMAIN="localhost"
            HAS_DOMAIN=0
        fi

        # --- Webhook setup ---
        echo ""
        if prompt_yn "Do you have a webhook URL to forward emails to?" "n"; then
            echo ""
            echo -e "  ${MUTED}When an email arrives, PrimitiveMail will POST it to this URL.${NC}"
            echo -e "  ${MUTED}Without a webhook, emails are accepted and stored locally.${NC}"
            prompt_value WEBHOOK_URL "Webhook URL" ""
            if [[ -n "$WEBHOOK_URL" ]]; then
                prompt_value WEBHOOK_SECRET "Webhook secret" ""
                if [[ -z "$WEBHOOK_SECRET" ]]; then
                    WEBHOOK_SECRET=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n' | head -c 64)
                    echo ""
                    warn "No secret provided - generated one automatically"
                    info "Secret: ${BOLD}${WEBHOOK_SECRET}${NC}"
                    info "Save this - you'll need it to configure your webhook endpoint"
                fi
            fi
        fi

        # --- Sender security ---
        echo ""
        step "Sender Security"
        echo ""
        echo -e "  ${MUTED}Who should be allowed to send mail to this server?${NC}"
        echo ""
        echo -e "    ${BOLD}1${NC}. Anyone         ${MUTED}- Accept mail from all senders${NC}"
        echo -e "    ${BOLD}2${NC}. Specific senders ${MUTED}- Only accept from domains/addresses you specify${NC}"
        echo ""
        local sender_choice
        sender_choice=$(prompt_choice "Choice (1-2)" 2 1)

        if [[ "$sender_choice" == "2" ]]; then
            echo ""
            echo -e "  ${MUTED}Allowed sender domains (comma-separated)${NC}"
            echo -e "  ${MUTED}Accepts mail from *@domain — any address at these domains.${NC}"
            echo -e "  ${MUTED}Example: example.com,trusted.org${NC}"
            prompt_value ALLOWED_SENDER_DOMAINS "Domains" ""
            echo ""
            echo -e "  ${MUTED}Allowed sender addresses (comma-separated, optional)${NC}"
            echo -e "  ${MUTED}Accepts mail from these specific addresses only.${NC}"
            echo -e "  ${MUTED}Use this for individual senders at domains you don't fully trust.${NC}"
            echo -e "  ${MUTED}Example: alerts@github.com,friend@gmail.com${NC}"
            prompt_value ALLOWED_SENDERS "Addresses" ""
        fi

        # --- Recipient filtering ---
        echo ""
        echo -e "  ${MUTED}Allowed recipient addresses (comma-separated, optional)${NC}"
        echo -e "  ${MUTED}If set, only these addresses can receive mail.${NC}"
        echo -e "  ${MUTED}Leave blank to accept mail for any address at your domain.${NC}"
        prompt_value ALLOWED_RECIPIENTS "Recipients" ""

        # --- Spoof protection ---
        echo ""
        step "Spoof Protection"
        echo ""
        echo -e "  ${MUTED}Spoof protection verifies that senders are who they claim to be${NC}"
        echo -e "  ${MUTED}using SPF, DKIM, and DMARC - industry-standard email authentication.${NC}"
        echo ""
        echo -e "    ${BOLD}1${NC}. Off       ${MUTED}- No verification (for testing/development)${NC}"
        echo -e "    ${BOLD}2${NC}. Monitor   ${MUTED}- Verify and log results, but accept everything${NC}"
        echo -e "    ${BOLD}3${NC}. Standard  ${MUTED}- Enforce the sender's own published policy (recommended)${NC}"
        echo -e "    ${BOLD}4${NC}. Strict    ${MUTED}- Reject on any authentication failure${NC}"
        echo ""
        local spoof_choice
        spoof_choice=$(prompt_choice "Choice (1-4)" 4 1)

        case "$spoof_choice" in
            1) SPOOF_PROTECTION="off" ;;
            2) SPOOF_PROTECTION="monitor" ;;
            3) SPOOF_PROTECTION="standard" ;;
            4) SPOOF_PROTECTION="strict" ;;
        esac

        # Warn if sender filtering + no spoof protection
        if [[ -n "$ALLOWED_SENDER_DOMAINS$ALLOWED_SENDERS" && "$SPOOF_PROTECTION" == "off" ]]; then
            echo ""
            warn "Without spoof protection, sender filtering only checks the envelope"
            warn "address, which can be easily forged. Consider enabling at least"
            warn "\"Standard\" spoof protection for real security."
            echo ""
            if ! prompt_yn "Continue anyway?" "n"; then
                SPOOF_PROTECTION="standard"
                success "Spoof protection set to: standard"
            fi
        fi
    fi

    # --- Webhook secret validation ---
    if [[ -n "$WEBHOOK_URL" && -z "$WEBHOOK_SECRET" ]]; then
        WEBHOOK_SECRET=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n' | head -c 64)
        warn "Webhook URL set without secret - generated one: $WEBHOOK_SECRET"
    fi

    # Write .env
    local enable_ip="false"
    if [[ -n "$PM_IP_LITERAL" ]]; then
        enable_ip="true"
    fi

    printf '%s\n' \
        "MYHOSTNAME=${PM_HOSTNAME}" \
        "MYDOMAIN=${PM_DOMAIN}" \
        "ENABLE_IP_LITERAL=${enable_ip}" \
        "IP_LITERAL=${PM_IP_LITERAL}" \
        "WEBHOOK_URL=${WEBHOOK_URL}" \
        "WEBHOOK_SECRET=${WEBHOOK_SECRET}" \
        "ALLOWED_SENDER_DOMAINS=${ALLOWED_SENDER_DOMAINS}" \
        "ALLOWED_SENDERS=${ALLOWED_SENDERS}" \
        "ALLOWED_RECIPIENTS=${ALLOWED_RECIPIENTS}" \
        "ALLOW_BOUNCES=true" \
        "SPOOF_PROTECTION=${SPOOF_PROTECTION}" \
        > "$INSTALL_DIR/.env"

    success "Configuration saved to $INSTALL_DIR/.env"

    # --- Configuration summary ---
    echo ""
    step "Configuration summary"
    echo ""
    if [[ -n "$PM_IP_LITERAL" && "${HAS_DOMAIN:-0}" -eq 0 ]]; then
        echo -e "  ${BOLD}Receiving at:${NC}      ${GREEN}anything@[${PM_IP_LITERAL}]${NC}  (IP literal)"
    else
        echo -e "  ${BOLD}Hostname:${NC}          ${PM_HOSTNAME}"
        echo -e "  ${BOLD}Domain:${NC}            ${PM_DOMAIN}"
    fi
    if [[ -z "$WEBHOOK_URL" ]]; then
        echo -e "  ${BOLD}Mode:${NC}              Standalone (local storage)"
    else
        echo -e "  ${BOLD}Mode:${NC}              Webhook"
        echo -e "  ${BOLD}Webhook URL:${NC}       ${WEBHOOK_URL}"
    fi
    if [[ -n "$ALLOWED_SENDER_DOMAINS$ALLOWED_SENDERS" ]]; then
        echo -e "  ${BOLD}Allowed senders:${NC}   ${ALLOWED_SENDER_DOMAINS}${ALLOWED_SENDERS:+, ${ALLOWED_SENDERS}}"
    else
        echo -e "  ${BOLD}Allowed senders:${NC}   ${MUTED}any${NC}"
    fi
    if [[ -n "$ALLOWED_RECIPIENTS" ]]; then
        echo -e "  ${BOLD}Allowed recipients:${NC} ${ALLOWED_RECIPIENTS}"
    else
        echo -e "  ${BOLD}Allowed recipients:${NC} ${MUTED}any${NC}"
    fi
    local spoof_label="Off"
    case "$SPOOF_PROTECTION" in
        monitor)  spoof_label="Monitor (log only)" ;;
        standard) spoof_label="Standard (enforce DMARC policy)" ;;
        strict)   spoof_label="Strict (reject on any failure)" ;;
    esac
    echo -e "  ${BOLD}Spoof protection:${NC}  ${spoof_label}"
    echo -e "  ${BOLD}TLS:${NC}               Self-signed (auto-generated)"

    # Show DNS instructions if they provided a domain
    if [[ "${HAS_DOMAIN:-0}" -eq 1 ]]; then
        echo ""
        step "DNS setup required"
        echo ""
        echo -e "  Add these DNS records where you manage ${BOLD}${PM_DOMAIN}${NC}:"
        echo ""
        echo -e "  ${BOLD}MX record${NC}"
        echo -e "  ${DIM}${PM_DOMAIN}    MX    10    ${PM_HOSTNAME}${NC}"
        echo ""
        echo -e "  ${BOLD}A record${NC} ${MUTED}(point the hostname to this server's IP)${NC}"
        echo -e "  ${DIM}${PM_HOSTNAME}    A    <your-server-ip>${NC}"
        echo ""
        info "Mail won't arrive until these records propagate"
    fi

    if [[ "$SPOOF_PROTECTION" != "off" ]]; then
        echo ""
        info "Spoof protection requires DNS lookups from this server."
        info "Ensure outbound DNS (port 53) is not blocked by your firewall."
    fi
}

# --- Start ---------------------------------------------------------------

print_firewall_help() {
    local cloud=""
    if curl -s -m 1 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        cloud="aws"
    elif curl -s -m 1 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/ &>/dev/null; then
        cloud="gcp"
    elif curl -s -m 1 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
        cloud="azure"
    fi
    case "$cloud" in
        aws)
            echo -e "  It looks like you're on ${BOLD}AWS${NC}. To fix this:"
            echo -e "  EC2 > Security Groups > Edit inbound rules > Add rule:"
            echo -e "  Type: Custom TCP | Port: 25 | Source: 0.0.0.0/0"
            ;;
        gcp)
            echo -e "  It looks like you're on ${BOLD}Google Cloud${NC}. To fix this:"
            echo -e "  VPC Network > Firewall > Create rule:"
            echo -e "  Direction: Ingress | Protocol: TCP | Port: 25 | Source: 0.0.0.0/0"
            ;;
        azure)
            echo -e "  It looks like you're on ${BOLD}Azure${NC}. To fix this:"
            echo -e "  Network Security Group > Inbound security rules > Add:"
            echo -e "  Protocol: TCP | Destination port: 25 | Source: Any"
            ;;
        *)
            echo -e "  Check your cloud provider's security group / firewall settings"
            echo -e "  and ensure inbound TCP on port 25 is allowed from 0.0.0.0/0."
            ;;
    esac
    echo ""
}

start_server() {
    if [[ $NO_START -eq 1 ]]; then
        info "Skipping start (--no-start)"
        return
    fi

    local compose_cmd="docker compose"
    if ! docker compose version &> /dev/null 2>&1; then
        compose_cmd="docker-compose"
    fi

    cd "$INSTALL_DIR"

    # Check if this is a first build (no image exists yet)
    local first_build=0
    if ! docker images --format '{{.Repository}}' | grep -q primitivemail; then
        first_build=1
    fi

    if [[ $first_build -eq 1 ]]; then
        step "Building PrimitiveMail"
        info "First build -- this usually takes 1-2 minutes"
        echo ""
        run_with_progress "$compose_cmd build --quiet" "Building"
        echo ""
        step "Starting PrimitiveMail"
        $compose_cmd up -d --quiet-pull 2>&1 | tail -5
    elif [[ $VERBOSE -eq 1 ]]; then
        step "Starting PrimitiveMail"
        $compose_cmd up -d --build
    else
        step "Starting PrimitiveMail"
        $compose_cmd up -d --build --quiet-pull 2>&1 | tail -5
    fi

    # Wait for container to start
    local attempts=0
    while [[ $attempts -lt 15 ]]; do
        if docker ps --format '{{.Names}}' | grep -q primitivemail; then
            break
        fi
        sleep 1
        attempts=$((attempts + 1))
    done

    if ! docker ps --format '{{.Names}}' | grep -q primitivemail; then
        error "Container failed to start"
        echo ""
        echo "  Check logs: docker logs primitivemail"
        exit 1
    fi

    # Wait for Postfix to bind to port 25 inside the container
    attempts=0
    while [[ $attempts -lt 20 ]]; do
        if docker exec primitivemail sh -c "ss -tln | grep -q ':25 '" &>/dev/null; then
            break
        fi
        sleep 1
        attempts=$((attempts + 1))
    done

    if [[ $attempts -lt 20 ]]; then
        success "PrimitiveMail is running on port 25"
    else
        error "PrimitiveMail started but SMTP did not become ready"
        echo ""
        echo "  Check logs: docker logs primitivemail"
        exit 1
    fi

    # Check if port 25 is reachable from the outside via external probe service.
    # Falls back to a local hairpin check if the API is unreachable (only works
    # when the public IP is NAT'd — see comment below).
    local check_ip="${PM_IP_LITERAL:-$(detect_public_ip)}"
    if [[ -n "$check_ip" ]]; then
        info "Checking port 25 reachability on $check_ip..."
        local check_result=""
        check_result=$(curl -fsSL --max-time 10 "https://mx-tools.primitive.dev/check?ip=$check_ip" 2>/dev/null) || true

        local port_status=""
        if [[ -n "$check_result" ]]; then
            # Parse status from JSON response (avoid jq dependency)
            port_status=$(echo "$check_result" | grep -o '"status" *: *"[^"]*"' | cut -d'"' -f4)
        fi

        case "$port_status" in
            open)
                success "Port 25 is reachable from the outside"
                ;;
            closed)
                echo ""
                warn "Port 25 is not accepting connections on $check_ip"
                echo -e "  The host is reachable but nothing is listening on port 25."
                echo -e "  Check that the PrimitiveMail container is running:"
                echo -e "    docker ps | grep primitivemail"
                echo -e "    docker logs primitivemail"
                echo ""
                ;;
            blocked)
                echo ""
                warn "Port 25 appears blocked by a firewall on $check_ip"
                echo -e "  PrimitiveMail is running, but external mail won't reach it until you"
                echo -e "  allow inbound TCP on port 25 in your firewall settings."
                echo ""
                print_firewall_help
                ;;
            error)
                echo ""
                warn "Port 25 check failed — host unreachable at $check_ip"
                echo -e "  Verify that this is the correct public IP for your server."
                echo -e "  You can check manually at: ${BOLD}https://mx-tools.primitive.dev${NC}"
                echo ""
                ;;
            *)
                # API unreachable or returned unexpected status — fall back to local
                # hairpin check (only reliable when the IP is NAT'd, not local)
                warn "Could not reach port check service — falling back to local check"
                if ip addr show 2>/dev/null | grep -qF " $check_ip/"; then
                    info "Public IP is on a local interface — cannot verify port 25 from here"
                    echo -e "  Check manually at: ${BOLD}https://mx-tools.primitive.dev${NC}"
                elif timeout 5 bash -c 'echo QUIT | nc -w 3 "$1" 25' _ "$check_ip" &>/dev/null; then
                    success "Port 25 is reachable from this host"
                elif timeout 5 bash -c 'cat < /dev/tcp/"$1"/25' _ "$check_ip" &>/dev/null; then
                    success "Port 25 is reachable from this host"
                else
                    echo ""
                    warn "Port 25 does not appear reachable on $check_ip"
                    echo -e "  PrimitiveMail is running, but external mail may not be able to reach it."
                    echo -e "  You can verify manually at: ${BOLD}https://mx-tools.primitive.dev${NC}"
                    echo ""
                fi
                ;;
        esac
    fi
}

# --- CLI -----------------------------------------------------------------

install_cli() {
    step "Installing CLI"

    # Symlink cli/primitivemail to /usr/local/bin
    chmod +x "$INSTALL_DIR/cli/primitive"
    if sudo ln -sf "$INSTALL_DIR/cli/primitive" /usr/local/bin/primitive 2>/dev/null; then
        success "CLI installed: primitive"
    else
        warn "Could not install to /usr/local/bin. Add $INSTALL_DIR/cli to your PATH manually."
    fi
}

# --- Done ----------------------------------------------------------------

print_next_steps() {
    echo ""
    step "PrimitiveMail is ready"
    echo ""
    if [[ "${HAS_DOMAIN:-0}" -eq 0 && -n "$PM_IP_LITERAL" ]]; then
        echo -e "  ${BOLD}Send a test email to:${NC}"
        echo -e "  ${DIM}anything@[${PM_IP_LITERAL}]${NC}"
        echo ""
    fi
    echo -e "  ${BOLD}Useful commands:${NC}"
    echo -e "  ${DIM}primitive emails-status           ${MUTED}# check inbox status${NC}"
    echo -e "  ${DIM}docker logs primitivemail -f     ${MUTED}# watch logs${NC}"
    echo -e "  ${DIM}primitive restart                ${MUTED}# reload after config changes${NC}"
    echo -e "  ${DIM}cat $INSTALL_DIR/.env            ${MUTED}# view config${NC}"
    echo ""
    echo -e "  ${BOLD}Agent integration:${NC}"
    echo -e "  ${DIM}cat $INSTALL_DIR/AGENTS.md        ${MUTED}# how to consume email programmatically${NC}"
    echo ""
    echo -e "  ${YELLOW}!${NC} ${BOLD}If running on a cloud provider (AWS, GCP, Azure, etc.):${NC}"
    echo -e "    Make sure port 25 (TCP) is open in your security group / firewall rules."
    echo -e "    The install script can only open the OS-level firewall, not cloud firewalls."
    echo ""
}

# --- Main ----------------------------------------------------------------

check_existing_install() {
    if [[ -f "$INSTALL_DIR/.env" ]]; then
        echo ""
        warn "PrimitiveMail is already configured at $INSTALL_DIR"
        echo ""
        if [[ $NO_PROMPT -eq 1 ]]; then
            info "Non-interactive mode: re-running full setup"
            return
        fi
        if ! prompt_yn "Start over with a fresh configuration?" "n"; then
            echo ""
            info "Keeping existing configuration. Nothing to do."
            exit 0
        fi
        echo ""
    fi
}

main() {
    print_banner
    check_docker
    open_firewall
    clone_repo
    check_existing_install
    configure
    start_server
    install_cli
    print_next_steps
}

main
