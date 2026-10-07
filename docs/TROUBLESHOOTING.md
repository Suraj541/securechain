# SecureChain Troubleshooting Guide

## 1. Common Operational Issues

### 1.1 "Windows administrator privileges are required"
- **Cause**: Attempting to run native Windows route table manipulation (`ROUTE.EXE`) or firewall rules (`netsh advfirewall`) without Administrator elevation.
- **Solution**: Run PowerShell / Terminal as Administrator, or execute within the default Virtual Simulation Mesh (`--mode simulation`) where elevated privileges are not required.

### 1.2 "Linux nftables permissions or binary missing"
- **Cause**: Linux native firewall enforcement requires `nft` installed and root / `sudo` privileges.
- **Solution**: Run SecureChain with `sudo`, or verify `nftables` is installed via `sudo apt install nftables` or `sudo dnf install nftables`. In non-root environments, SecureChain automatically falls back to `VirtualKillSwitch` containment.

### 1.3 "macOS pfctl permissions or binary missing"
- **Cause**: macOS Packet Filter (`pfctl`) manipulation requires root / `sudo` privileges.
- **Solution**: Execute with `sudo python -m securechain ...`. In unprivileged sessions, SecureChain defaults to `VirtualKillSwitch` protection.

### 1.4 "IPv6 disabled: Hop X does not support IPv6. External IPv6 blocked."
- **Cause**: One or more hops in the active multi-hop chain are IPv4-only. SecureChain enforces fail-closed containment to prevent unencrypted IPv6 leakage over your physical adapter.
- **Solution**: If IPv6 connectivity is strictly required, update candidate configurations to ensure all intermediate and exit hops support IPv6, or set `path_selection.require_ipv6: true` in `config.yaml` to automatically filter out IPv4-only paths.

### 1.5 "Kill Switch remains locked: Traffic is blocked"
- **Cause**: A tunnel in the active chain dropped, health verification failed, or maximum recovery retries were exhausted (`TRAFFIC_REMAINS_BLOCKED`).
- **Solution**: Run `securechain health` to inspect which hop failed. If the network link is permanently broken, execute `securechain stop` to safely release the lock and restore original default routes, or `securechain restart` to attempt rebuilding the chain.

### 1.6 "DNS Leak Detected"
- **Cause**: Host OS DNS resolver failed to bind to the tunnel exit interface, or a local application bypassed system DNS.
- **Solution**: Run `securechain test` to inspect canary query results. Ensure DHCP client settings on physical adapters do not overwrite DNS metrics.

### 1.7 "Privacy Proxy bind failed on 127.0.0.1:8118"
- **Cause**: Another service (such as Privoxy, Tor, or a local development server) is already listening on port 8118.
- **Solution**: Update `privacy.privacy_proxy.port` in `config.yaml` to an alternate unused port (e.g. `8119` or `8888`).

### 1.8 "Elevated latency with traffic shaping enabled"
- **Cause**: Traffic shaping applies deliberate timing jitter (e.g. 10–20ms) and packet padding to reduce burst signatures.
- **Solution**: Switch `privacy.traffic_shaping.mode` from `high` to `balanced` or `low`, or set `privacy.traffic_shaping.enabled: false` if latency sensitivity is paramount.
