# wing

Dead‑simple WireGuard userspace launcher for Linux + macOS that keeps routes/DNS untouched.

## What it does
- Creates a dedicated WG interface via `wireguard-go` (userspace).
- Sets a local /32 address.
- Configures peers and **only** host (/32) routes for peer WG IPs.
- Does **not** touch default routes or DNS.

## Requirements
- `wireguard-go` in `PATH`
- Linux: `ip` command (iproute2)
- macOS: `ifconfig` and `route`

On Linux, the kernel WireGuard driver is used automatically if available. `wireguard-go` is only needed when the kernel driver is missing.

## Run
```bash
sudo wing [-config config.example.json]
```
If `-config` is not provided, wing will use `~/.wing/self.json` by default.
If the config file does not exist (either the default or a specified path), wing will create it with defaults (same as `-init`) and then exit.

Quick setup (interactive defaults):
```bash
wing -setup
```
Non-interactive setup:
```bash
wing -setup -address 10.7.0.1 -listen-port 51821 -mtu 1420
```
`-setup` also prompts for `my_endpoint` in `host:port` form, and will use the current value as the default.

List peers:
```bash
wing -list-peers
```
Add a peer (interactive):
```bash
wing -add-peer
```
Remove a peer (interactive):
```bash
wing -remove-peer
```
Export this node as a peer JSON block:
```bash
wing -export
```
Import a peer JSON block:
```bash
wing -import
```

If `wireguard-go` is installed but not in `PATH`:
```bash
sudo wing -wireguard-go /full/path/to/wireguard-go -config config.example.json
```
If your distro installs it as `wireguard`, you can point to that binary:
```bash
sudo wing -wireguard-go /full/path/to/wireguard -config config.example.json
```

Take down a lingering interface (Linux):
```bash
sudo wing -config config.example.json -down
```
Take down a lingering interface (macOS):
```bash
sudo wing -config config.example.json -down
# If auto-detection fails:
sudo wing -config config.example.json -down -os-iface utunX
```
Take down all interfaces created by wing (uses state files):
```bash
sudo wing -down-all
```

Show status:
```bash
wing -config config.example.json -status
```

Return to prompt and leave the interface up:
```bash
sudo wing -config config.example.json -detach
# Use -down to tear it down later.
```

Generate keys without `wg`:
```bash
wing -genkey
wing -genpsk
```

Linux without full root (userspace):
```bash
sudo setcap cap_net_admin,cap_net_raw+ep ./wing
wing -config config.example.json
```

## Config
`config.example.json` shows the shape. Only /32 IPv4 `allowed_ips` are accepted in this minimal version.

## Notes
- macOS: `wireguard-go` creates a `utunX` interface. This tool detects the **newly created** `utun` and configures it. Don’t start multiple `wireguard-go` instances at the same time.
- `-reuse` is supported on Linux only; macOS cannot reliably map an existing WG device to a `utunX` interface.
- For a mesh, each node lists the other peers with their WG IPs and endpoints.
- Wing stores state files under `~/.wing` (or `WING_STATE_DIR`) for `-down-all`.
- `-down-all` only affects interfaces that were created by wing (state files are written only when wing creates a device).
- `-init` writes `~/.wing/self.json` and includes `my_public_key` for sharing with peers.

## Non‑interference guarantees
- No default route changes.
- No DNS changes.
- Only a dedicated WG interface is created and host routes are added for peer WG IPs.
