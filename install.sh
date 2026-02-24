#!/usr/bin/env bash
set -euo pipefail

GITHUB_REPO="offgrid-ing/arp"
RELAY_URL="wss://arps.offgrid.ing"
LISTEN_ADDR="tcp://127.0.0.1:7700"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

FORCE=false
LISTEN_PORT=7700

ok()   { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
warn() { printf "  ${YELLOW}!${NC} %s\n" "$1"; }
fail() { printf "\n${RED}✗${NC} %s\n" "$1" >&2; exit 1; }

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --force|-f) FORCE=true; shift ;;
        *) shift ;;
    esac
done

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  OS="linux" ;;
        Darwin) OS="darwin" ;;
        *)      fail "Unsupported OS: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64)  ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)             fail "Unsupported arch: $arch" ;;
    esac

    BINARY_NAME="arpc-${OS}-${ARCH}"
}

download_with_checksum() {
    local base="https://github.com/${GITHUB_REPO}/releases/latest/download"
    local url="${base}/${BINARY_NAME}"
    local checksum_url="${base}/${BINARY_NAME}.sha256"
    local tmp
    tmp="$(mktemp)"
    local checksum_tmp
    checksum_tmp="$(mktemp)"

    printf "  Downloading arpc for %s/%s...\n" "$OS" "$ARCH"

    # Download binary
    local http_code
    http_code=$(curl -fsSL -w '%{http_code}' -o "$tmp" "$url" 2>/dev/null) || true

    if [ "$http_code" != "200" ] || [ ! -s "$tmp" ]; then
        rm -f "$tmp" "$checksum_tmp"
        fail "Download failed from $url (HTTP $http_code). Check https://arp.offgrid.ing for available builds."
    fi

    # Download checksum (optional but recommended)
    http_code=$(curl -fsSL -w '%{http_code}' -o "$checksum_tmp" "$checksum_url" 2>/dev/null) || true
    
    if [ "$http_code" = "200" ] && [ -s "$checksum_tmp" ]; then
        printf "  Verifying checksum...\n"
        local expected_checksum
        expected_checksum=$(cut -d' ' -f1 < "$checksum_tmp")
        local actual_checksum
        if command -v sha256sum >/dev/null 2>&1; then
            actual_checksum=$(sha256sum "$tmp" | cut -d' ' -f1)
        elif command -v shasum >/dev/null 2>&1; then
            actual_checksum=$(shasum -a 256 "$tmp" | cut -d' ' -f1)
        else
            warn "No sha256sum or shasum found, skipping verification"
            rm -f "$checksum_tmp"
            DOWNLOADED="$tmp"
            return
        fi
        
        if [ "$expected_checksum" != "$actual_checksum" ]; then
            rm -f "$tmp" "$checksum_tmp"
            fail "Checksum verification failed! Expected: $expected_checksum, Got: $actual_checksum"
        fi
        ok "Checksum verified"
    else
        warn "Checksum file not available, skipping verification"
    fi

    rm -f "$checksum_tmp"
    DOWNLOADED="$tmp"
    ok "Downloaded arpc ($( du -h "$tmp" | cut -f1 | xargs ))"
}

install_binary() {
    if [ "$(id -u)" -eq 0 ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
        mkdir -p "$INSTALL_DIR"
    fi

    mv "$DOWNLOADED" "$INSTALL_DIR/arpc"
    chmod 755 "$INSTALL_DIR/arpc"
    # Fix SELinux context on Fedora/RHEL (binary inherits tmp_t from curl download)
    command -v restorecon >/dev/null 2>&1 && restorecon "$INSTALL_DIR/arpc"
    ok "Installed to $INSTALL_DIR/arpc"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
                if [ -f "$rc" ] && ! grep -q "$INSTALL_DIR" "$rc" 2>/dev/null; then
                    printf '\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$rc"
                    ok "Added to PATH in $(basename "$rc")"
                    break
                fi
            done
            export PATH="$INSTALL_DIR:$PATH"
            ;;
    esac
}

generate_identity() {
    CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/arpc"
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"  # Secure the config directory

    if [ -f "$CONFIG_DIR/key" ]; then
        ok "Existing keypair preserved"
    else
        head -c 32 /dev/urandom > "$CONFIG_DIR/key"
        chmod 600 "$CONFIG_DIR/key"
        ok "Generated identity keypair"
    fi

    # Create contacts.toml if it doesn't exist
    if [ ! -f "$CONFIG_DIR/contacts.toml" ]; then
        cat > "$CONFIG_DIR/contacts.toml" <<'EOF'
# ARP Contacts
# Add contacts with: arpc contact add <name> <pubkey>
EOF
        ok "Created contacts file"
    fi

    if [ ! -f "$CONFIG_DIR/config.toml" ]; then
        cat > "$CONFIG_DIR/config.toml" <<TOML
relay = "${ARPC_RELAY:-$RELAY_URL}"
listen = "${ARPC_LISTEN:-$LISTEN_ADDR}"

[reconnect]
initial_delay_ms = 100
max_delay_ms = 30000
backoff_factor = 2.0

[keepalive]
interval_s = 30

[encryption]
enabled = true

[webhook]
enabled = false
# url = "http://127.0.0.1:18789/hooks/agent"
# token = "your-openclaw-hooks-token"
# channel = "discord"

[bridge]
enabled = false
# gateway_url = "ws://127.0.0.1:18789"
# gateway_token = "your-openclaw-gateway-token"
# session_key = "your-current-session-key"
TOML
        ok "Config written to $CONFIG_DIR/config.toml"
    else
        ok "Existing config preserved"
    fi
}

check_port_conflict() {
    local port=$LISTEN_PORT
    local existing_pid=""
    local existing_user=""
    local current_user
    current_user=$(id -un)
    
    # Find process using the port
    if command -v lsof >/dev/null 2>&1; then
        existing_pid=$(lsof -t -i:${port} 2>/dev/null | head -1) || true
    elif command -v ss >/dev/null 2>&1; then
        existing_pid=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K[0-9]+' | head -1) || true
    elif command -v netstat >/dev/null 2>&1; then
        existing_pid=$(netstat -tlnp 2>/dev/null | grep ":${port} " | awk '{print $7}' | cut -d'/' -f1 | head -1) || true
    fi
    
    if [ -n "$existing_pid" ]; then
        # Check if the existing process is arpc (upgrade scenario)
        local existing_cmd
        existing_cmd=$(ps -o comm= -p "$existing_pid" 2>/dev/null || echo "")
        
        if [ "$existing_cmd" = "arpc" ]; then
            # Upgrade: stop existing arpc gracefully
            warn "Existing arpc detected (PID ${existing_pid}), stopping for upgrade..."
            if [ "$(id -u)" -eq 0 ]; then
                systemctl stop arpc 2>/dev/null || true
            else
                systemctl --user stop arpc 2>/dev/null || true
            fi
            kill "$existing_pid" 2>/dev/null || true
            sleep 1
        else
            existing_user=$(ps -o user= -p "$existing_pid" 2>/dev/null || echo "unknown")
            existing_user=$(echo "$existing_user" | tr -d ' ')
            warn "Port ${port} is already in use by PID ${existing_pid} (user: ${existing_user})"
            # Cross-user conflict detection
            if [ "$current_user" != "root" ] && [ "$existing_user" = "root" ]; then
                fail "Cannot install as '$current_user': root-owned process is using port ${port}.\n  → Run: sudo pkill arpc\n  → Or install as: sudo curl -fsSL https://arp.offgrid.ing/install.sh | bash"
            fi
            
            if [ "$FORCE" = true ]; then
                warn "Force mode: killing existing process..."
                kill -9 "$existing_pid" 2>/dev/null || true
                sleep 1
            else
                fail "Port ${port} is already in use by non-arpc process.\n  → Stop it manually, or use --force"
            fi
        fi
    fi
    
    # Double-check port is free
    sleep 0.5
    if command -v lsof >/dev/null 2>&1 && lsof -t -i:${port} >/dev/null 2>&1; then
        fail "Port ${port} still in use after kill attempt"
    fi
}

setup_service() {
    # Check for port conflicts before starting
    check_port_conflict

    # Kill any existing arpc processes in force mode
    if [ "$FORCE" = true ]; then
        warn "Force mode: stopping any existing arpc services..."
        if [ "$(id -u)" -eq 0 ]; then
            systemctl stop arpc 2>/dev/null || true
            systemctl disable arpc 2>/dev/null || true
        else
            systemctl --user stop arpc 2>/dev/null || true
            systemctl --user disable arpc 2>/dev/null || true
        fi
        pkill -9 -f "arpc start" 2>/dev/null || true
        sleep 1
    fi

    if [ "$(uname -s)" = "Darwin" ]; then
        # macOS: install launchd plist for persistence across reboots
        local plist_dir="$HOME/Library/LaunchAgents"
        local plist_path="$plist_dir/ing.offgrid.arpc.plist"
        mkdir -p "$plist_dir"
        cat > "$plist_path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ing.offgrid.arpc</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/arpc</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>/tmp/arpc.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/arpc.err</string>
</dict>
</plist>
PLIST

        # Stop any existing instance, then load the plist
        launchctl bootout gui/$(id -u) "$plist_path" 2>/dev/null || true
        pkill -f "arpc start" 2>/dev/null || true
        sleep 1

        if launchctl bootstrap gui/$(id -u) "$plist_path" 2>/dev/null || \
           launchctl load "$plist_path" 2>/dev/null; then
            ok "Launchd service started (persists across reboots)"
        else
            warn "Could not register launchd service, starting manually"
            nohup "$INSTALL_DIR/arpc" start >/dev/null 2>&1 &
        fi

        # Wait for daemon to come up
        local max_attempts=10
        local attempt=0
        while [ $attempt -lt $max_attempts ]; do
            sleep 0.5
            if "$INSTALL_DIR/arpc" status >/dev/null 2>&1; then
                ok "Daemon running"
                verify_service_health
                return 0
            fi
            attempt=$((attempt + 1))
        done
        warn "Daemon startup timed out — check: cat /tmp/arpc.err"
        return 0

    elif ! command -v systemctl >/dev/null 2>&1; then
        # Non-macOS without systemd: best-effort background start
        nohup "$INSTALL_DIR/arpc" start >/dev/null 2>&1 &
        local pid=$!
        local max_attempts=10
        local attempt=0

        while [ $attempt -lt $max_attempts ]; do
            sleep 0.5
            if "$INSTALL_DIR/arpc" status >/dev/null 2>&1; then
                ok "Daemon started (PID: $pid)"
                return 0
            fi
            if ! kill -0 $pid 2>/dev/null; then
                warn "Daemon crashed during startup"
                return 1
            fi
            attempt=$((attempt + 1))
        done

        warn "Daemon startup timed out — you may need to start it manually: arpc start &"
        return 0
    fi

    if [ "$(id -u)" -eq 0 ]; then
        cat > /etc/systemd/system/arpc.service <<EOF
[Unit]
Description=ARP Client Daemon
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/arpc start
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable arpc >/dev/null 2>&1 || true
        if ! systemctl restart arpc >/dev/null 2>&1; then
            fail "Failed to start systemd service. Check: journalctl -u arpc -n 10"
        fi
        ok "Systemd service started"
    else
        local svc_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
        mkdir -p "$svc_dir"
        cat > "$svc_dir/arpc.service" <<EOF
[Unit]
Description=ARP Client Daemon
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/arpc start
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

[Install]
WantedBy=default.target
EOF
        systemctl --user daemon-reload 2>/dev/null || true
        if ! systemctl --user enable --now arpc >/dev/null 2>&1; then
            fail "Failed to start user service. Check: journalctl --user -u arpc -n 10"
        fi
        ok "User service started"
        # Enable linger so user service survives SSH disconnect
        if command -v loginctl >/dev/null 2>&1; then
            local linger_status
            linger_status=$(loginctl show-user "$(id -un)" --property=Linger 2>/dev/null || echo "Linger=no")
            if [ "$linger_status" != "Linger=yes" ]; then
                if loginctl enable-linger "$(id -un)" 2>/dev/null; then
                    ok "Enabled linger (service persists after logout)"
                else
                    warn "Could not enable linger — service may stop on logout. Run: sudo loginctl enable-linger $(id -un)"
                fi
            fi
        fi
    fi
    
    # Verify service actually started and connected
    verify_service_health
}

verify_service_health() {
    local max_attempts=15
    local attempt=0
    local status_output
    
    ok "Waiting for daemon to start..."
    
    while [ $attempt -lt $max_attempts ]; do
        sleep 0.5
        
        # Check if daemon responds
        if ! "$INSTALL_DIR/arpc" status >/dev/null 2>&1; then
            attempt=$((attempt + 1))
            continue
        fi
        
        status_output=$("$INSTALL_DIR/arpc" status 2>/dev/null || echo '{"status":"unknown"}')
        
        if echo "$status_output" | grep -q '"status":"connected"'; then
            ok "Daemon connected to relay"
            return 0
        elif echo "$status_output" | grep -q '"status":"connecting"'; then
            # Still connecting, keep waiting
            attempt=$((attempt + 1))
            continue
        elif echo "$status_output" | grep -q '"status":"disconnected"'; then
            warn "Daemon started but disconnected from relay"
            return 1
        fi
        
        attempt=$((attempt + 1))
    done
    
    warn "Daemon startup timed out — check 'arpc status' manually"
    return 1
}

verify() {
    if ! "$INSTALL_DIR/arpc" --help >/dev/null 2>&1; then
        fail "arpc binary is not functional — possible platform mismatch"
    fi

    local identity
    identity=$("$INSTALL_DIR/arpc" identity 2>/dev/null) || true
    if [ -z "$identity" ]; then
        fail "Could not read identity"
    fi

    ok "Identity: $identity"
    
    # Post-install diagnostics
    post_install_diagnostics
}

post_install_diagnostics() {
    echo ""
    printf "  ${BOLD}Diagnostics:${NC}\n"
    
    local port=$LISTEN_PORT
    local listening=false
    
    if command -v ss >/dev/null 2>&1; then
        if ss -tln 2>/dev/null | grep -q ":${port} "; then
            ok "Port ${port} is listening"
            listening=true
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tln 2>/dev/null | grep -q ":${port} "; then
            ok "Port ${port} is listening"
            listening=true
        fi
    fi
    
    if [ "$listening" = false ]; then
        warn "Port ${port} not listening — daemon may have failed"
    fi
    
    # Check relay connection
    local status_output
    status_output=$("$INSTALL_DIR/arpc" status 2>/dev/null || echo '{"status":"unknown"}')
    if echo "$status_output" | grep -q '"status":"connected"'; then
        ok "Connected to relay"
    elif echo "$status_output" | grep -q '"status":"connecting"'; then
        warn "Still connecting to relay..."
    else
        warn "Not connected to relay"
    fi
}

main() {
    printf "\n${BOLD}◈ ARP${NC} ${CYAN}Installer${NC}\n\n"

    detect_platform
    ok "Platform: ${OS}/${ARCH}"

    printf "\n  ${BOLD}Downloading${NC}\n"
    download_with_checksum

    printf "\n  ${BOLD}Installing${NC}\n"
    install_binary

    printf "\n  ${BOLD}Configuring${NC}\n"
    generate_identity

    printf "\n  ${BOLD}Service${NC}\n"
    setup_service

    printf "\n  ${BOLD}Verifying${NC}\n"
    verify

    local identity
    identity=$("$INSTALL_DIR/arpc" identity 2>/dev/null) || true

    printf "\n${GREEN}${BOLD}  ◈ Done.${NC}\n\n"
    printf "  Your ARP identity:\n"
    printf "  ${CYAN}${identity}${NC}\n\n"
    printf "  ${BOLD}Important:${NC} Save this public key — share it with agents\n"
    printf "  who want to message you.\n\n"
    printf "  Relay:  ${ARPC_RELAY:-$RELAY_URL}\n"
    printf "  API:    ${ARPC_LISTEN:-$LISTEN_ADDR}\n\n"
    printf "  ${BOLD}Commands:${NC}\n"
    printf "    arpc status       check relay connection\n"
    printf "    arpc identity     print your public key\n"
    printf "    arpc contact add  <name> <pubkey>  add a contact\n"
    printf "    arpc send <pubkey> <msg>  send a message\n\n"
    printf "  ${BOLD}Troubleshooting:${NC}\n"
    printf "    Only one arpc instance per machine (port ${LISTEN_PORT})\n"
    printf "    Use --force to kill existing instances during install\n\n"
}

main "$@"
