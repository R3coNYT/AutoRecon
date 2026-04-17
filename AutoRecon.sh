#!/usr/bin/env bash

set -Eeuo pipefail

# ======================================
# AutoRecon Professional Installer
# Linux + macOS
# ======================================

REPO_URL="https://github.com/R3coNYT/AutoRecon.git"
REPO_RAW="https://raw.githubusercontent.com/R3coNYT/AutoRecon/main"
INSTALL_ROOT_LINUX="/opt/autorecon"
INSTALL_ROOT_MACOS="$HOME/Tools/AutoRecon"
GO_VERSION="1.26.1"
HTTPX_VERSION="1.9.0"
NUCLEI_VERSION="3.7.1"
SUBLIST3R_REPO="https://github.com/aboul3la/Sublist3r.git"

COLOR_RED="\033[1;31m"
COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_RESET="\033[0m"

log() {
    echo -e "${COLOR_BLUE}[+]${COLOR_RESET} $*"
}

ok() {
    echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $*"
}

warn() {
    echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $*"
}

err() {
    echo -e "${COLOR_RED}[✗]${COLOR_RESET} $*" >&2
}

cleanup_on_error() {
    err "Installation failed on line $1"
    exit 1
}
trap 'cleanup_on_error $LINENO' ERR

retry() {
    local attempts="$1"
    shift
    local count=1
    until "$@"; do
        if [ "$count" -ge "$attempts" ]; then
            return 1
        fi
        warn "Command failed. Retry $count/$attempts..."
        count=$((count + 1))
        sleep 2
    done
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

detect_platform() {
    local uname_s
    uname_s="$(uname -s)"

    case "$uname_s" in
        Linux)
            PLATFORM="linux"
            ;;
        Darwin)
            PLATFORM="macos"
            ;;
        *)
            err "Unsupported platform: $uname_s"
            exit 1
            ;;
    esac

    ok "Detected platform: $PLATFORM"
}

detect_arch() {
    local arch
    arch="$(uname -m)"

    case "$arch" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            err "Unsupported architecture: $arch"
            exit 1
            ;;
    esac

    ok "Detected architecture: $ARCH"
}

set_install_root() {
    if [ "$PLATFORM" = "linux" ]; then
        INSTALL_DIR="$INSTALL_ROOT_LINUX"
    else
        INSTALL_DIR="$INSTALL_ROOT_MACOS"
    fi
    ok "Install directory: $INSTALL_DIR"
}

get_sudo() {
    if [ "$PLATFORM" = "linux" ]; then
        if need_cmd sudo; then
            SUDO="sudo"
        else
            err "sudo is required on Linux"
            exit 1
        fi
    else
        SUDO=""
    fi
}

install_base_deps_linux() {
    log "Installing Linux dependencies"

    retry 3 $SUDO apt update

    local deps=(
        git curl wget unzip tar python3 python3-pip python3-venv nmap masscan ca-certificates
    )

    for pkg in "${deps[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            ok "$pkg already installed"
        else
            retry 3 $SUDO apt install -y "$pkg"
            ok "$pkg installed"
        fi
    done

    if command -v masscan >/dev/null 2>&1; then
        $SUDO setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v masscan)" || true
        ok "masscan capabilities configured"
    fi
}

install_base_deps_macos() {
    log "Installing macOS dependencies"

    if ! need_cmd brew; then
        err "Homebrew is required on macOS: https://brew.sh"
        exit 1
    fi

    local deps=(
        git curl wget unzip python3 nmap masscan
    )

    for pkg in "${deps[@]}"; do
        if brew list "$pkg" >/dev/null 2>&1; then
            ok "$pkg already installed"
        else
            retry 3 brew install "$pkg"
            ok "$pkg installed"
        fi
    done
}

install_go_linux() {
    local current_go=""
    if need_cmd go; then
        current_go="$(go version | awk '{print $3}' | sed 's/go//')"
    fi

    if [ "$current_go" = "$GO_VERSION" ]; then
        ok "Go $GO_VERSION already installed"
        return
    fi

    log "Installing Go $GO_VERSION"

    local url="https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz"
    local archive="/tmp/go${GO_VERSION}.linux-${ARCH}.tar.gz"

    retry 3 curl -L "$url" -o "$archive"
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "$archive"

    $SUDO tee /etc/profile.d/golang.sh >/dev/null <<'EOF'
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
EOF

    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
    hash -r
    ok "Go installed"
}

install_go_macos() {
    local current_go=""
    if need_cmd go; then
        current_go="$(go version | awk '{print $3}' | sed 's/go//')"
    fi

    if [ "$current_go" = "$GO_VERSION" ]; then
        ok "Go $GO_VERSION already installed"
        return
    fi

    log "Installing Go $GO_VERSION with Homebrew"
    retry 3 brew install go || retry 3 brew upgrade go || true
    ok "Go installed"
}

download_and_install_httpx() {
    if need_cmd httpx; then
        ok "httpx already installed"
        return
    fi

    log "Installing httpx $HTTPX_VERSION"

    local tmp_dir
    tmp_dir="$(mktemp -d)"

    local filename=""
    if [ "$PLATFORM" = "linux" ]; then
        filename="httpx_${HTTPX_VERSION}_linux_${ARCH}.zip"
    else
        filename="httpx_${HTTPX_VERSION}_macOS_${ARCH}.zip"
    fi

    local url="https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/${filename}"

    retry 3 curl -L "$url" -o "$tmp_dir/httpx.zip"
    unzip -o "$tmp_dir/httpx.zip" -d "$tmp_dir" >/dev/null

    if [ "$PLATFORM" = "linux" ]; then
        $SUDO install -m 755 "$tmp_dir/httpx" /usr/local/bin/httpx
    else
        mkdir -p "$HOME/.local/bin"
        install -m 755 "$tmp_dir/httpx" "$HOME/.local/bin/httpx"
        export PATH="$HOME/.local/bin:$PATH"
    fi

    rm -rf "$tmp_dir"
    ok "httpx installed"
}

download_and_install_nuclei() {
    if need_cmd nuclei; then
        ok "nuclei already installed"
        return
    fi

    log "Installing nuclei $NUCLEI_VERSION"

    local tmp_dir
    tmp_dir="$(mktemp -d)"

    local filename=""
    if [ "$PLATFORM" = "linux" ]; then
        filename="nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip"
    else
        filename="nuclei_${NUCLEI_VERSION}_macOS_${ARCH}.zip"
    fi

    local url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${filename}"

    retry 3 curl -L "$url" -o "$tmp_dir/nuclei.zip"
    unzip -o "$tmp_dir/nuclei.zip" -d "$tmp_dir" >/dev/null

    if [ "$PLATFORM" = "linux" ]; then
        $SUDO install -m 755 "$tmp_dir/nuclei" /usr/local/bin/nuclei
    else
        mkdir -p "$HOME/.local/bin"
        install -m 755 "$tmp_dir/nuclei" "$HOME/.local/bin/nuclei"
        export PATH="$HOME/.local/bin:$PATH"
    fi

    rm -rf "$tmp_dir"
    ok "nuclei installed"
}

update_nuclei_templates() {
    if need_cmd nuclei; then
        log "Updating nuclei templates"
        nuclei -update-templates || warn "Unable to update nuclei templates right now"
    fi
}

clone_or_update_repo() {
    log "Installing AutoRecon files"

    if [ "$PLATFORM" = "linux" ]; then
        $SUDO mkdir -p "$INSTALL_DIR"
        $SUDO chown -R "$USER":"$USER" "$INSTALL_DIR"
    else
        mkdir -p "$INSTALL_DIR"
    fi

    if [ -d "$INSTALL_DIR/.git" ]; then
        ok "Repository already present, updating"
        git -C "$INSTALL_DIR" pull
    else
        retry 3 git clone "$REPO_URL" "$INSTALL_DIR"
    fi
}

install_sublist3r() {
    log "Installing Sublist3r"
    if [ ! -d "$INSTALL_DIR/Sublist3r" ]; then
        retry 3 git clone "$SUBLIST3R_REPO" "$INSTALL_DIR/Sublist3r"
    else
        ok "Sublist3r already present"
    fi
}

install_sqlmap() {
    log "Installing sqlmap"
    if [ ! -d "$INSTALL_DIR/sqlmap-dev" ]; then
        retry 3 git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$INSTALL_DIR/sqlmap-dev"
    else
        ok "sqlmap already present"
    fi
}

create_venv() {
    log "Creating Python virtual environment"

    cd "$INSTALL_DIR"

    if [ ! -d "$INSTALL_DIR/autorecon_env" ]; then
        python3 -m venv autorecon_env
    else
        ok "Virtual environment already exists"
    fi

    # shellcheck disable=SC1091
    source "$INSTALL_DIR/autorecon_env/bin/activate"

    retry 3 pip install --upgrade pip
    retry 3 pip install -r requirements.txt

    # Install Playwright browser (required for DOM XSS scanning)
    if python3 -c "import playwright" &>/dev/null 2>&1; then
        log "Installing Playwright Chromium browser"
        playwright install chromium --with-deps 2>/dev/null || \
            warn "playwright install chromium failed (DOM XSS scanning will be skipped)"
    fi

    deactivate
    ok "Python environment ready"
}

install_optional_tools() {
    # Go-based tools — Go must already be installed at this point
    if ! command -v go &>/dev/null; then
        warn "Go not found — skipping gowitness, subfinder, gobuster installation"
    else
        if ! command -v gowitness &>/dev/null; then
            log "Installing gowitness (screenshot tool)"
            go install github.com/sensepost/gowitness@latest || warn "gowitness install failed (screenshots will be skipped)"
        else
            ok "gowitness already installed"
        fi

        if ! command -v subfinder &>/dev/null; then
            log "Installing subfinder (subdomain discovery)"
            go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || warn "subfinder install failed"
        else
            ok "subfinder already installed"
        fi

        if ! command -v gobuster &>/dev/null; then
            log "Installing gobuster (directory brute-force)"
            go install github.com/OJ/gobuster/v3@latest || warn "gobuster install failed"
        else
            ok "gobuster already installed"
        fi
    fi

    # theHarvester — apt (Kali), then GitHub clone
    if ! command -v theHarvester &>/dev/null && ! command -v theharvester &>/dev/null; then
        log "Installing theHarvester (OSINT)"
        if [ "$PLATFORM" = "linux" ]; then
            if $SUDO apt-get install -y theharvester 2>/dev/null; then
                ok "theHarvester installed via apt"
            else
                log "Cloning theHarvester from GitHub…"
                local _th_dir="/opt/theHarvester"
                $SUDO rm -rf "$_th_dir"
                $SUDO git clone --depth 1 https://github.com/laramies/theHarvester.git "$_th_dir" && \
                    $SUDO tee /usr/local/bin/theHarvester >/dev/null <<THEOF
#!/bin/bash
exec python3 /opt/theHarvester/theHarvester.py "\$@"
THEOF
                $SUDO chmod +x /usr/local/bin/theHarvester && ok "theHarvester installed from GitHub" || \
                    warn "theHarvester install failed — clone manually: git clone https://github.com/laramies/theHarvester.git"
            fi
        else
            brew install theharvester 2>/dev/null || {
                local _th_dir="$HOME/Tools/theHarvester"
                git clone --depth 1 https://github.com/laramies/theHarvester.git "$_th_dir" && \
                    tee "$HOME/.local/bin/theHarvester" >/dev/null <<THEOF
#!/bin/bash
exec python3 $_th_dir/theHarvester.py "\$@"
THEOF
                chmod +x "$HOME/.local/bin/theHarvester" && ok "theHarvester installed from GitHub" || \
                    warn "theHarvester install failed — clone manually: git clone https://github.com/laramies/theHarvester.git"
            }
        fi
    else
        ok "theHarvester already installed"
    fi
}

create_global_command_linux() {
    log "Creating global AutoRecon command"

    $SUDO tee /usr/local/bin/AutoRecon >/dev/null <<EOF
#!/bin/bash
source "$INSTALL_DIR/autorecon_env/bin/activate"
exec python3 "$INSTALL_DIR/AutoRecon.py"
EOF

    $SUDO chmod +x /usr/local/bin/AutoRecon
    ok "Global command created: AutoRecon"
}

create_global_command_macos() {
    log "Creating global AutoRecon command"

    mkdir -p "$HOME/.local/bin"

    cat > "$HOME/.local/bin/AutoRecon" <<EOF
#!/bin/bash
source "$INSTALL_DIR/autorecon_env/bin/activate"
exec python3 "$INSTALL_DIR/AutoRecon.py"
EOF

    chmod +x "$HOME/.local/bin/AutoRecon"

    if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.zshrc" 2>/dev/null &&
       ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc" 2>/dev/null || true
    fi

    export PATH="$HOME/.local/bin:$PATH"
    ok "Global command created: AutoRecon"
}

print_done() {
    echo
    echo "======================================"
    echo "       Installation Completed"
    echo "======================================"
    echo
    if [ "$PLATFORM" = "linux" ]; then
        echo "Run AutoRecon using:"
        echo "AutoRecon"
    else
        echo "Run AutoRecon using:"
        echo "AutoRecon"
        echo
        echo "If needed, reopen your terminal so PATH updates are loaded."
    fi
    echo
}

main() {
    detect_platform
    detect_arch
    set_install_root
    get_sudo

    if [ "$PLATFORM" = "linux" ]; then
        install_base_deps_linux
        install_go_linux
    else
        install_base_deps_macos
        install_go_macos
    fi

    clone_or_update_repo
    download_and_install_httpx
    download_and_install_nuclei
    update_nuclei_templates
    install_sublist3r
    install_sqlmap
    create_venv
    install_optional_tools

    if [ "$PLATFORM" = "linux" ]; then
        create_global_command_linux
    else
        create_global_command_macos
    fi

    print_done
}

main "$@"