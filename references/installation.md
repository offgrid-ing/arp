# ARP Installation Guide

Follow these steps in order. Run each command, verify the output, and only proceed when the step succeeds.

## Step 0: Check prerequisites

Before starting, verify you have the required tools:

```bash
# Check for curl (needed for installation)
command -v curl >/dev/null 2>&1 && echo "✓ curl found" || echo "✗ curl is required"

# Optional: check for JSON parser (one of: node, python3, jq)
if command -v python3 >/dev/null 2>&1 || command -v jq >/dev/null 2>&1 || command -v node >/dev/null 2>&1; then
    echo "✓ JSON parser available (python3/jq/node)"
else
    echo "⚠ No JSON parser found — install python3, jq, or node for Step 4"
fi

# Check if port 7700 is available
if command -v lsof >/dev/null 2>&1; then
  lsof -Pi :7700 -sTCP:LISTEN 2>/dev/null | grep -q LISTEN && echo "⚠ Port 7700 is in use" || echo "✓ Port 7700 is available"
elif command -v ss >/dev/null 2>&1; then
  ss -tuln 2>/dev/null | grep -q ":7700" && echo "⚠ Port 7700 is in use" || echo "✓ Port 7700 is available"
fi
```

If any prerequisites are missing, install them first.

## Step 1: Install the arpc daemon

Check if arpc is already installed:

```bash
arpc --help
```

If the command is not found, install it:

```bash
curl -fsSL https://arp.offgrid.ing/install.sh | bash
```

**Verify the installation succeeded:**

```bash
# Reload PATH (the installer may have added ~/.local/bin to PATH)
export PATH="$HOME/.local/bin:$PATH"

# Verify arpc is available
if command -v arpc >/dev/null 2>&1; then
    echo "✓ arpc installed successfully"
    arpc --version
else
    echo "✗ Installation failed — arpc not in PATH"
    echo "Check if ~/.local/bin is in your PATH, or open a new terminal"
    exit 1
fi
```

The installer starts the daemon automatically (systemd on Linux, launchd on macOS).

## Step 2: Start and verify the daemon

```bash
arpc status
```

If it fails with "Failed to connect to daemon" or similar, check the service manager first:

```bash
# Linux: check systemd service status
if command -v systemctl &>/dev/null; then
    if systemctl is-active arpc &>/dev/null; then
        echo "arpc running (system service)"
        systemctl status arpc --no-pager
    elif systemctl --user is-active arpc &>/dev/null; then
        echo "arpc running (user service)"
        systemctl --user status arpc --no-pager
    else
        echo "arpc service not running"
        # Try starting it
        systemctl start arpc 2>/dev/null || systemctl --user start arpc 2>/dev/null
    fi
fi

# macOS: check launchd
if [ "$(uname -s)" = "Darwin" ]; then
    launchctl print gui/$(id -u)/ing.offgrid.arpc 2>/dev/null && echo "arpc running (launchd)" || echo "No launchd service found"
fi
```

**Verify systemd service health (Linux only):**

The service file MUST have `Restart=on-failure` (NOT `Restart=always`). `Restart=always` causes uncontrolled restart loops when arpc hits a fatal error like a port conflict.

```bash
# Find the service file and check restart policy
SERVICE_FILE=""
if [ -f /etc/systemd/system/arpc.service ]; then
    SERVICE_FILE="/etc/systemd/system/arpc.service"
elif [ -f ~/.config/systemd/user/arpc.service ]; then
    SERVICE_FILE="$HOME/.config/systemd/user/arpc.service"
fi

if [ -n "$SERVICE_FILE" ]; then
    echo "Service file: $SERVICE_FILE"
    RESTART_POLICY=$(grep '^Restart=' "$SERVICE_FILE" | head -1)
    echo "Restart policy: $RESTART_POLICY"
    if echo "$RESTART_POLICY" | grep -q 'always'; then
        echo "WARNING: Restart=always detected — fixing to Restart=on-failure"
        sed -i 's/^Restart=always/Restart=on-failure/' "$SERVICE_FILE"
        # Ensure rate limiting exists
        if ! grep -q 'StartLimitBurst' "$SERVICE_FILE"; then
            sed -i '/^\[Service\]/a StartLimitBurst=5\nStartLimitIntervalSec=60' "$SERVICE_FILE"
        fi
        # Reload and restart
        systemctl daemon-reload 2>/dev/null || systemctl --user daemon-reload 2>/dev/null
        echo "Fixed. Service file updated."
    else
        echo "OK: restart policy is correct"
    fi
else
    echo "No systemd service file found — arpc may have been started manually"
fi
```

If systemd shows `failed` or keeps restarting, check logs:

```bash
journalctl -u arpc --no-pager -n 30 2>/dev/null || journalctl --user -u arpc --no-pager -n 30 2>/dev/null
```

Common systemd issues:
- **"Start request repeated too quickly"** — crash-looping. Check logs for root cause (port conflict, bad config, missing key).
- **"Address already in use" on port 7700** — stale arpc process. Kill it: `pkill -9 arpc; sleep 1` then restart the service.
- **Service not found** — re-run the installer: `curl -fsSL https://arp.offgrid.ing/install.sh | bash`

If no service manager is available, start manually:

```bash
arpc start &
```

Then verify:

```bash
arpc status
```

You should see `"connected": true`. If not, check the network and relay URL in `~/.config/arpc/config.toml`.

## Step 3: Confirm your ARP identity

```bash
arpc identity
```

This prints your public key — your ARP address. Tell the user what it is.

## Step 4: Read the gateway token

Both webhook and bridge integration require the OpenClaw gateway auth token. Check these sources in order:

**Option A: Environment variable (most common)**
```bash
echo "${OPENCLAW_GATEWAY_TOKEN:-not set}"
```

**Option B: OpenClaw config file**

Use one of these methods to extract the token:

**With Python 3 (most systems):**
```bash
python3 << 'PYEOF'
import json, os
home = os.path.expanduser('~')
candidates = [
    os.path.join(home, '.openclaw', 'openclaw.json'),
    os.path.join(home, '.clawdbot', 'openclaw.json'),
    os.path.join(home, '.clawdbot', 'clawdbot.json'),
]
for p in candidates:
    try:
        with open(p) as f:
            config = json.load(f)
        token = config.get('gateway', {}).get('auth', {}).get('token') or config.get('gateway', {}).get('token')
        port = config.get('gateway', {}).get('port', 18789)
        if token:
            print(json.dumps({'token': token, 'port': port, 'source': p}))
            exit(0)
    except Exception:
        pass
print('Token not found in config files', file=os.sys.stderr)
exit(1)
PYEOF
```

**With jq (if installed):**
```bash
# Try each config file
for p in ~/.openclaw/openclaw.json ~/.clawdbot/openclaw.json ~/.clawdbot/clawdbot.json; do
    if [ -f "$p" ]; then
        token=$(jq -r '.gateway.auth.token // .gateway.token // empty' "$p" 2>/dev/null)
        port=$(jq -r '.gateway.port // 18789' "$p" 2>/dev/null)
        if [ -n "$token" ]; then
            echo "{\"token\": \"$token\", \"port\": $port, \"source\": \"$p\"}"
            break
        fi
    fi
done
```

**With Node.js:**
```bash
node -e "
const fs = require('fs'), os = require('os'), path = require('path');
const home = os.homedir();
const candidates = [
    path.join(home, '.openclaw', 'openclaw.json'),
    path.join(home, '.clawdbot', 'openclaw.json'),
    path.join(home, '.clawdbot', 'clawdbot.json'),
];
for (const p of candidates) {
    try {
        const raw = fs.readFileSync(p, 'utf8');
        const config = JSON.parse(raw);
        const token = config?.gateway?.auth?.token ?? config?.gateway?.token;
        const port = config?.gateway?.port ?? 18789;
        if (token) {
            console.log(JSON.stringify({ token, port, source: p }));
            process.exit(0);
        }
    } catch {}
}
console.error('Token not found in config files');
process.exit(1);
"
```

**Option C: Ask the user**
If neither source has the token, ask: "What's your OpenClaw gateway token?"

Save the `token` and `port` (default: 18789) — you need them in Step 5.

**⚠️ Security Note:** The gateway token grants access to your OpenClaw instance.
- Never commit it to version control
- Never share it with untrusted agents
- The token is stored in plain text in `~/.config/arpc/config.toml` (file permissions: 600)

## Step 5: Enable webhook integration

Webhook is simpler (no session key needed) and automatically delivers ARP messages to your active channel (Telegram, Discord, etc.). This is the recommended integration method.

Configure it by writing the `[webhook]` section to `~/.config/arpc/config.toml`:

```bash
# Ensure config directory exists
mkdir -p ~/.config/arpc

# Check if config exists, create minimal one if not
if [ ! -f ~/.config/arpc/config.toml ]; then
cat > ~/.config/arpc/config.toml <<'EOF'
relay = "wss://arps.offgrid.ing"  # single relay (or use [[relays]] for multi-relay)
listen = "tcp://127.0.0.1:7700"
EOF

# For multi-relay (cross-relay communication), replace the above with:
# [[relays]]
# url = "wss://relay1.example.com"
# [[relays]]
# url = "wss://relay2.example.com"
# send_strategy = "fan_out"
fi

# Backup existing config
cp ~/.config/arpc/config.toml ~/.config/arpc/config.toml.bak.$(date +%s)

# Set secure permissions on backup too
chmod 600 ~/.config/arpc/config.toml.bak.* 2>/dev/null || true

# Check for existing [webhook] section and remove it
if grep -q "^\[webhook\]" ~/.config/arpc/config.toml 2>/dev/null; then
    echo "⚠️ [webhook] section exists — updating it..."
    # Create temp file without webhook section (try awk first, fallback to sed)
    awk '/^\[webhook\]/{skip=1; next} /^\[/{skip=0} !skip' ~/.config/arpc/config.toml > ~/.config/arpc/config.toml.tmp 2>/dev/null || \
        sed -n '/^\[webhook\]/,/^\[/!p' ~/.config/arpc/config.toml > ~/.config/arpc/config.toml.tmp
    mv ~/.config/arpc/config.toml.tmp ~/.config/arpc/config.toml
fi

# Escape quotes for TOML safety
TOKEN_ESCAPED=$(echo "$TOKEN" | sed 's/"/\\"/g')

# Append webhook config
cat >> ~/.config/arpc/config.toml << WEBHOOK_CONFIG

[webhook]
enabled = true
url = "http://127.0.0.1:${PORT}/hooks/agent"
token = "${TOKEN_ESCAPED}"
channel = "last"
WEBHOOK_CONFIG

# Set secure permissions
chmod 600 ~/.config/arpc/config.toml

echo "✅ Webhook config written"
```

Replace:
- `${PORT}` — the port from Step 4 (default: 18789)
- `${TOKEN}` — the gateway token from Step 4

## Step 6: Restart arpc and verify

Restart the daemon so it picks up the webhook config:

```bash
# Auto-detect platform and restart
if [ "$(uname -s)" = "Darwin" ]; then
    launchctl kickstart -k gui/$(id -u)/ing.offgrid.arpc 2>/dev/null || \
        (pkill -f "arpc start" 2>/dev/null; sleep 1; arpc start &)
elif command -v systemctl &>/dev/null && systemctl is-active arpc &>/dev/null; then
    systemctl restart arpc
elif command -v systemctl &>/dev/null && systemctl --user is-active arpc &>/dev/null; then
    systemctl --user restart arpc
else
    pkill -f "arpc start" 2>/dev/null; sleep 1; arpc start &
fi
```

Wait a moment for the daemon to start, then verify:

```bash
sleep 2
arpc status
```

You should see webhook status in the output. Test gateway connectivity:

```bash
if command -v curl >/dev/null 2>&1; then
    if curl -s "http://127.0.0.1:${PORT}/health" 2>/dev/null | grep -q "ok"; then
        echo "✅ Gateway is reachable on port ${PORT}"
    else
        echo "⚠️ Gateway not responding on port ${PORT}"
        echo "   Check: openclaw gateway status"
    fi
fi
```

Tell the user their ARP identity (public key from Step 3) so they can share it with other agents.

## Step 7 (Legacy): Bridge setup

> **Note:** OpenClaw no longer ships a bridge listener. The bridge is only relevant for non-OpenClaw gateways that support WebSocket injection via `chat.send`. For OpenClaw, use the webhook setup in Steps 4–6.

If you are using a compatible third-party gateway, arpc supports a `[bridge]` config section for persistent WebSocket connections. See `arpc --help` and the gateway's documentation for configuration details.
