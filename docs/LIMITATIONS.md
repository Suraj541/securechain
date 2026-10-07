# SecureChain Known Limitations & Unsupported Features

## 1. Known Technical Limitations

### 1.1 Host Privilege Boundaries
- Windows system routing table modification (`ROUTE.EXE add/delete`) and Windows Advanced Firewall rule management (`netsh advfirewall`) require Administrator elevation.
- When executed in non-elevated user contexts, SecureChain seamlessly delegates to the high-fidelity `VirtualNetworkMesh` and `VirtualKillSwitch` engine, allowing complete verification of routing algebra and security invariants.

### 1.2 WireGuard & External Daemon Requirements
- Production multi-hop WireGuard connections require the `wireguard.exe` daemon and elevated Windows tunnel driver installation (`/installtunnelservice`).
- In environments without external paid VPN infrastructure, the `SimulatedVPNProvider` models telemetry and network behavior.

### 1.3 IPv6 End-to-End Tunneling
- Due to the prevalence of IPv4-only intermediate VPN nodes, SecureChain defaults to the **Fail-Closed IPv6 Block** strategy rather than IPv6 dual-stack encapsulation.

---

## 2. Unsupported Features

### 2.1 Anonymity Guarantees
- SecureChain **does not** provide untraceability or anonymity against global timing correlation or sophisticated state adversaries.

### 2.2 Application-Layer Fingerprint Scrubbing
- SecureChain does not inspect, filter, or anonymize HTTP request headers, browser cookies, WebRTC candidates, or TLS client signatures.

### 2.3 Non-Windows Native Firewall Hooks
- Native OS firewall rules currently target Windows (`netsh advfirewall`). Linux (`iptables`/`nftables`) and macOS (`pf`) are supported via the cross-platform virtual mesh.
