#!/usr/bin/env bash
# ==============================================================================
#  AutoRecon — Update Script (Linux / macOS)
#
#  Pulls the latest AutoRecon code from GitHub while preserving:
#    • All scan results          (results/)
#    • Mapping plugin results    (plugins/mapping/results/)
#    • Ping plugin results, if any (plugins/ping/results/)
#    • Any user-created plugins  (plugins/<anything not official>/)
#    • Your PDF personalisation  (personalize_pdf/name.txt)
#
#  Only code files, core modules, wordlists and official plugin
#  scripts are updated.  No data is ever deleted or overwritten.
# ==============================================================================

set -Eeuo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────

COLOR_RED="\033[1;31m"
COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_CYAN="\033[1;36m"
COLOR_GRAY="\033[0;37m"
COLOR_RESET="\033[0m"

log()  { echo -e "${COLOR_CYAN}[+]${COLOR_RESET} $*"; }
ok()   { echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $*"; }
warn() { echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $*"; }
err()  { echo -e "${COLOR_RED}[✗]${COLOR_RESET} $*" >&2; }
info() { echo -e "${COLOR_GRAY}[i]${COLOR_RESET} $*"; }

# ── Error trap ─────────────────────────────────────────────────────────────────

cleanup_on_error() {
    err "Update failed at line $1."
    err "Your results and user plugins have NOT been modified."
    exit 1
}
trap 'cleanup_on_error $LINENO' ERR

# ── Official plugins shipped with AutoRecon ────────────────────────────────────
# Only these are updated from the remote repo.
# Any other folder found under plugins/ is treated as a user plugin and left alone.

OFFICIAL_PLUGINS=("mapping" "ping")

# ── Platform detection ─────────────────────────────────────────────────────────

detect_platform() {
    case "$(uname -s)" in
        Linux)  PLATFORM="linux"  ;;
        Darwin) PLATFORM="macos"  ;;
        *)
            err "Unsupported platform: $(uname -s)"
            exit 1
            ;;
    esac
}

# ── Locate install directory ───────────────────────────────────────────────────

find_install_dir() {
    # 1) Script's own directory
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$script_dir/AutoRecon.py" ] && [ -d "$script_dir/.git" ]; then
        INSTALL_DIR="$script_dir"
        return
    fi

    # 2) Platform-specific default paths
    local defaults=()
    if [ "$PLATFORM" = "linux" ]; then
        defaults=("/opt/autorecon" "$HOME/autorecon")
    else
        defaults=("$HOME/Tools/AutoRecon" "$HOME/autorecon")
    fi

    for d in "${defaults[@]}"; do
        if [ -f "$d/AutoRecon.py" ] && [ -d "$d/.git" ]; then
            INSTALL_DIR="$d"
            return
        fi
    done

    err "Could not locate the AutoRecon install directory."
    err "Run this script from inside the install directory, or install first with AutoRecon.sh"
    exit 1
}

# ── Verify prerequisites ───────────────────────────────────────────────────────

assert_git() {
    if ! command -v git &>/dev/null; then
        err "git is not installed or not in PATH."
        if [ "$PLATFORM" = "linux" ]; then
            err "Install it with:  sudo apt install git   (or your distro's package manager)"
        else
            err "Install it with:  brew install git"
        fi
        exit 1
    fi
}

# ── Preserve / restore user customisations ────────────────────────────────────

SAVED_NAME_CONTENT=""
NAME_PATH=""
APPLIED_COMMIT=""

save_user_data() {
    NAME_PATH="$INSTALL_DIR/personalize_pdf/name.txt"
    if [ -f "$NAME_PATH" ]; then
        SAVED_NAME_CONTENT="$(cat "$NAME_PATH")"
        info "Saved personalize_pdf/name.txt"
    fi
}

restore_user_data() {
    if [ -n "$SAVED_NAME_CONTENT" ] && [ -n "$NAME_PATH" ]; then
        # Ensure directory still exists
        mkdir -p "$(dirname "$NAME_PATH")"
        printf '%s' "$SAVED_NAME_CONTENT" > "$NAME_PATH"
        ok "Restored personalize_pdf/name.txt"
    fi
}

# ── Selective git update ───────────────────────────────────────────────────────

# Returns 0 if an update was applied, 1 if already up to date
update_code() {
    cd "$INSTALL_DIR"

    log "Fetching latest code from GitHub..."
    if ! git fetch origin main 2>/dev/null; then
        # Fallback to fetching all remotes
        if ! git fetch origin 2>/dev/null; then
            err "git fetch failed. Check your internet connection."
            exit 1
        fi
    fi

    local local_hash remote_hash
    local_hash="$(git rev-parse HEAD)"
    remote_hash="$(git rev-parse origin/main)"

    if [ "$local_hash" = "$remote_hash" ]; then
        ok "AutoRecon is already up to date  (commit: ${local_hash:0:7})"
        APPLIED_COMMIT="${local_hash:0:7}"
        return 1
    fi

    local old_short="${local_hash:0:7}"
    local new_short="${remote_hash:0:7}"
    log "Update available  ($old_short → $new_short) — applying..."

    # ── Root-level code files ─────────────────────────────────────────────────
    local root_files=("AutoRecon.py" "main.py" "requirements.txt" "README.md"
                      "AutoRecon.sh" "install.ps1" "update.ps1" "update.sh")
    for f in "${root_files[@]}"; do
        if git cat-file -e "origin/main:$f" 2>/dev/null; then
            git checkout origin/main -- "$f" 2>/dev/null || true
        fi
    done
    ok "Root files updated"

    # ── core/ directory ───────────────────────────────────────────────────────
    if git cat-file -e "origin/main:core" 2>/dev/null; then
        git checkout origin/main -- core/ 2>/dev/null
        ok "core/ updated"
    fi

    # ── wordlists/ directory ──────────────────────────────────────────────────
    if git cat-file -e "origin/main:wordlists" 2>/dev/null; then
        git checkout origin/main -- wordlists/ 2>/dev/null
        ok "wordlists/ updated"
    fi

    # ── Official plugins (code only; results/ sub-dirs are never git-tracked) ─
    for plugin in "${OFFICIAL_PLUGINS[@]}"; do
        if git cat-file -e "origin/main:plugins/$plugin" 2>/dev/null; then
            git checkout origin/main -- "plugins/$plugin/" 2>/dev/null
            ok "Plugin '$plugin' code updated"
        fi
    done

    # ── New official plugins added to repo that don't exist locally yet ───────
    if git ls-tree --name-only "origin/main:plugins" &>/dev/null; then
        while IFS= read -r remote_plugin; do
            remote_plugin="$(echo "$remote_plugin" | tr -d '[:space:]')"
            local is_official=false
            for op in "${OFFICIAL_PLUGINS[@]}"; do
                [ "$remote_plugin" = "$op" ] && is_official=true && break
            done
            if [ "$is_official" = false ] && [ ! -d "$INSTALL_DIR/plugins/$remote_plugin" ]; then
                git checkout origin/main -- "plugins/$remote_plugin/" 2>/dev/null || true
                ok "New official plugin '$remote_plugin' installed"
            fi
        done < <(git ls-tree --name-only "origin/main:plugins" 2>/dev/null)
    fi

    ok "Code update complete  (commit: $new_short)"
    APPLIED_COMMIT="$new_short"
    return 0
}

# ── Report untouched user plugins ─────────────────────────────────────────────

show_user_plugins() {
    local plugins_dir="$INSTALL_DIR/plugins"
    if [ ! -d "$plugins_dir" ]; then return; fi

    for dir in "$plugins_dir"/*/; do
        [ -d "$dir" ] || continue
        local pname
        pname="$(basename "$dir")"
        local is_official=false
        for op in "${OFFICIAL_PLUGINS[@]}"; do
            [ "$pname" = "$op" ] && is_official=true && break
        done
        if [ "$is_official" = false ]; then
            info "User plugin '$pname' — left untouched"
        fi
    done
}

# ── Update Python dependencies ─────────────────────────────────────────────────

update_deps() {
    log "Updating Python dependencies..."

    local pip=""

    # Look for pip in common venv locations
    local pip_candidates=(
        "$INSTALL_DIR/autorecon_env/bin/pip"
        "/opt/autorecon/autorecon_env/bin/pip"
        "$HOME/Tools/AutoRecon/autorecon_env/bin/pip"
        "$HOME/autorecon/autorecon_env/bin/pip"
    )
    for c in "${pip_candidates[@]}"; do
        if [ -f "$c" ]; then pip="$c"; break; fi
    done

    # Fall back to system pip
    if [ -z "$pip" ]; then
        if command -v pip3 &>/dev/null; then
            pip="pip3"
        elif command -v pip &>/dev/null; then
            pip="pip"
        fi
    fi

    if [ -z "$pip" ]; then
        warn "No pip found — skipping dependency update."
        warn "Run manually:  pip install -r requirements.txt --upgrade"
        return
    fi

    "$pip" install -r "$INSTALL_DIR/requirements.txt" --upgrade --quiet

    # Ensure Playwright browser is installed/updated
    local python_bin
    for py_candidate in \
        "$INSTALL_DIR/autorecon_env/bin/python3" \
        "$INSTALL_DIR/autorecon_env/bin/python"; do
        if [ -f "$py_candidate" ]; then python_bin="$py_candidate"; break; fi
    done
    if [ -n "${python_bin:-}" ]; then
        "$python_bin" -m playwright install chromium 2>/dev/null || \
            warn "playwright install chromium failed (DOM XSS scanning will be skipped)"
    fi

    ok "Python dependencies updated"
}

# ── Ensure optional binary tools are present ───────────────────────────────────

update_optional_tools() {
    # Go-based tools
    if command -v go &>/dev/null; then
        for tool_spec in \
            "gowitness:github.com/sensepost/gowitness@latest" \
            "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
            "gobuster:github.com/OJ/gobuster/v3@latest"; do
            local name="${tool_spec%%:*}"
            local module="${tool_spec##*:}"
            if ! command -v "$name" &>/dev/null; then
                log "Installing $name"
                go install "$module" || warn "$name install failed (optional)"
            else
                ok "$name already installed"
            fi
        done
    else
        warn "Go not found — skipping gowitness / subfinder / gobuster check"
    fi

    # theHarvester — apt (Kali), then GitHub clone
    if ! command -v theHarvester &>/dev/null && ! command -v theharvester &>/dev/null; then
        log "Installing theHarvester"
        if [ "$PLATFORM" = "linux" ]; then
            if ${SUDO:-} apt-get install -y theharvester 2>/dev/null; then
                ok "theHarvester installed via apt"
            else
                local _th_dir="/opt/theHarvester"
                ${SUDO:-} rm -rf "$_th_dir"
                ${SUDO:-} git clone --depth 1 https://github.com/laramies/theHarvester.git "$_th_dir" && \
                    ${SUDO:-} tee /usr/local/bin/theHarvester >/dev/null <<THEOF
#!/bin/bash
exec python3 /opt/theHarvester/theHarvester.py "\$@"
THEOF
                ${SUDO:-} chmod +x /usr/local/bin/theHarvester && ok "theHarvester installed from GitHub" || \
                    warn "theHarvester not installed — clone manually: git clone https://github.com/laramies/theHarvester.git"
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
                    warn "theHarvester not installed — clone manually: git clone https://github.com/laramies/theHarvester.git"
            }
        fi
    else
        ok "theHarvester already installed"
    fi
}

# ── Summary banner ─────────────────────────────────────────────────────────────

print_summary() {
    local updated=$1
    local commit="${APPLIED_COMMIT:-$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")}"

    echo
    echo "  =========================================="
    echo "       AutoRecon - Update Complete"
    echo "  =========================================="
    echo
    echo "  Install dir  : $INSTALL_DIR"
    echo "  Platform     : $PLATFORM"
    echo "  Commit       : $commit"
    if [ "$updated" = "yes" ]; then
        echo -e "  Status       : ${COLOR_GREEN}Code updated successfully${COLOR_RESET}"
    else
        echo -e "  Status       : ${COLOR_GREEN}Already up to date${COLOR_RESET}"
    fi
    echo
    echo "  Your scan results, plugin results and user plugins are intact."
    echo
    echo "  Run AutoRecon:  python3 AutoRecon.py"
    echo
}

# ── Main ───────────────────────────────────────────────────────────────────────

echo
echo "  =========================================="
echo "       AutoRecon Updater (Linux / macOS)"
echo "  =========================================="
echo

detect_platform
assert_git
find_install_dir
info "Install dir: $INSTALL_DIR"
info "Platform   : $PLATFORM"
echo

save_user_data

UPDATED="no"
if update_code; then
    UPDATED="yes"
fi

restore_user_data
show_user_plugins
update_deps
update_optional_tools
chmod +x "$INSTALL_DIR/update.sh"
print_summary "$UPDATED"
