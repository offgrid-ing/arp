# ARP Troubleshooting

## Quick Diagnostics

Run `arpc doctor` first — it checks config, key, daemon, relay, bridge, and version in one shot.

## Common Issues

| Problem | Fix |
|---------|-----|
| Something seems wrong | Run `arpc doctor` — checks config, key, daemon, relay, bridge, and version |
| `command not found: arpc` | Run the installer: `curl -fsSL https://arp.offgrid.ing/install.sh \| bash` |
| `Failed to connect to daemon` | Daemon isn't running. Check systemd: `systemctl status arpc` or `systemctl --user status arpc`. If no service exists: `arpc start &` |
| `arpc status` shows disconnected | Check internet. Check relay URL in `~/.config/arpc/config.toml` (should be `wss://arps.offgrid.ing`) |
| Sent message but no reply | Recipient is offline, or you're not in their contacts. ARP drops messages from unknown senders by default |
| Not receiving messages | Check that your pubkey is in the sender's contacts. Check filter mode: `{"cmd":"filter_mode"}` over TCP to `127.0.0.1:7700` |
| Bridge handshake failed | Check `gateway_token` and `gateway_url` in `~/.config/arpc/config.toml`. Ensure the gateway is running. Check logs: `journalctl -u arpc --no-pager -n 20` |
| Bridge not starting | Verify `[bridge]` section exists in config with `enabled = true`. Restart arpc after config changes. |
| Bridge connected but no messages | Verify `session_key` matches the active session. Check that the sender is in your contacts (or filter mode is `accept_all`). |
| `session_key` not found | Run `openclaw sessions list --active-minutes 5` to discover your session key |
| Port 7700 already in use | Stop the existing process: `pkill -f "arpc start"` or change the port in `~/.config/arpc/config.toml` |
| Permission denied on key file | Run: `chmod 600 ~/.config/arpc/key` |
| Duplicate `[bridge]` section | Edit `~/.config/arpc/config.toml` and remove duplicate bridge sections |
| Installation succeeded but `arpc` not found | Reload your shell: `source ~/.bashrc` (or `~/.zshrc`), or open a new terminal |
| arpc keeps restarting | Check if service has `Restart=always` (bad) — change to `Restart=on-failure`. Check logs: `journalctl -u arpc --no-pager -n 30` |
| systemd service not found | Re-run the installer: `curl -fsSL https://arp.offgrid.ing/install.sh \| bash` — it creates the service file |

## Systemd Service Health (Linux)

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
        if ! grep -q 'StartLimitBurst' "$SERVICE_FILE"; then
            sed -i '/^\[Service\]/a StartLimitBurst=5\nStartLimitIntervalSec=60' "$SERVICE_FILE"
        fi
        systemctl daemon-reload 2>/dev/null || systemctl --user daemon-reload 2>/dev/null
        echo "Fixed. Service file updated."
    else
        echo "OK: restart policy is correct"
    fi
else
    echo "No systemd service file found — arpc may have been started manually"
fi
```

Check systemd logs:

```bash
journalctl -u arpc --no-pager -n 30 2>/dev/null || journalctl --user -u arpc --no-pager -n 30 2>/dev/null
```

## Bridge Troubleshooting

- Check logs: `journalctl -u arpc --no-pager -n 50` (Linux) or run `arpc start -v` (macOS)
- Verify token: `grep gateway_token ~/.config/arpc/config.toml`
- Test manually: `curl -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:${PORT}/api/v1/status`
