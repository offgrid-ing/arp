# ARP Uninstall & Maintenance

## Backup Before Uninstalling

```bash
# Save your identity key
cp ~/.config/arpc/key ~/.config/arpc/key.backup.$(date +%Y%m%d)
# Save contacts
cp ~/.config/arpc/contacts.toml ~/.config/arpc/contacts.toml.backup.$(date +%Y%m%d)
```

## Full Uninstall

To remove ARP completely:

```bash
# Stop daemon
if [ "$(uname -s)" = "Darwin" ]; then
    launchctl bootout gui/$(id -u)/ing.offgrid.arpc 2>/dev/null
    rm -f ~/Library/LaunchAgents/ing.offgrid.arpc.plist
fi
pkill -f "arpc start" 2>/dev/null
systemctl stop arpc 2>/dev/null          # Linux root systemd
systemctl --user stop arpc 2>/dev/null   # Linux user systemd

# Remove binary
rm -f ~/.local/bin/arpc /usr/local/bin/arpc

# Remove config and data (⚠️ This deletes your identity key!)
rm -rf ~/.config/arpc
```

## Disable Bridge Only (Keep arpc)

```bash
# Edit config and disable bridge
sed -i 's/^enabled = true/enabled = false/' ~/.config/arpc/config.toml
# Restart
arpc start &
```

## Update arpc

```bash
# Check for updates
arpc update --check

# Apply updates
arpc update

# Or just run the installer again — it will download the latest version
curl -fsSL https://arp.offgrid.ing/install.sh | bash
```
