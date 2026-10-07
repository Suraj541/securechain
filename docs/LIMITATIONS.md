# SecureChain Technical Limitations & Boundary Classifications

This document provides an honest, rigorous classification of SecureChain's capabilities, mitigations, and explicit boundaries. No false claims of absolute security, untraceability, or guaranteed anonymity are made.

---

## 1. Feature Classification Matrix

| Capability / Threat Domain | Classification | Current Technical Status & Scope |
|---|---|---|
| **Multi-Hop WireGuard Chaining (2–10 Hops)** | `IMPLEMENTED` | Sequential layer-by-layer encapsulation ($H_1 \to H_2 \dots \to H_N$) with dynamic MTU accounting. |
| **Fail-Closed Kill Switch (Windows)** | `IMPLEMENTED` | Native Windows Advanced Firewall rules (`netsh advfirewall`) with pre-connection lockdown. |
| **Fail-Closed Kill Switch (Linux)** | `IMPLEMENTED` | Native `nftables` in isolated table `inet securechain` with safe deletion on teardown. |
| **Fail-Closed Kill Switch (macOS)** | `IMPLEMENTED` | Native Packet Filter (`pf`) in isolated anchor `anchor "securechain"` with safe anchor flush. |
| **Cross-Platform Firewall Abstraction** | `IMPLEMENTED` | `CrossPlatformFirewallManager` auto-detects host OS; safely falls back to `VirtualKillSwitch` when non-elevated. |
| **IPv6 Leakage Prevention** | `IMPLEMENTED` | Per-hop capability detection. End-to-end IPv6 split routing (`::/1`, `8000::/1`) is enabled ONLY if 100% of selected hops support IPv6. If any hop is IPv4-only, IPv6 remains strictly fail-closed. |
| **Capability-Aware Path Selection** | `IMPLEMENTED` | Evaluates candidates against `require_ipv6` and telemetry metrics. Rejects paths with IPv4-only nodes when IPv6 is required; fails closed if no viable path exists. |
| **Race-Hardened Recovery Engine** | `IMPLEMENTED` | Threading mutex locks serialize concurrent recovery triggers; stale routes are cleared; fail-closed containment is atomic. |
| **Diagnostics & Reality Separation** | `IMPLEMENTED` | `doctor` and `diagnostics` clearly state whether features are `PASS`, `NOT AVAILABLE`, `DISABLED`, or `NOT CONFIGURED`, distinguishing real vs. simulated status. |
| **Traffic Shaping & Packet Padding** | `PARTIALLY MITIGATED` | Optional discrete bucket padding, adaptive padding, MTU ceiling, and timing jitter reduce observable packet-clustering and burst patterns. |
| **HTTP Tracking Header Exposure** | `PARTIALLY MITIGATED` | Optional local privacy proxy (`127.0.0.1:8118`) strips tracking headers (`X-Forwarded-For`, `Via`, etc.) and normalizes User-Agent. |
| **Global Passive Traffic Correlation** | `OUT OF SCOPE` | Adversaries observing both entry link ($H_1$) and exit link ($H_N$) simultaneously can execute statistical flow and timing correlation. Traffic shaping reduces, but CANNOT eliminate, this threat. |
| **Browser & Application Fingerprinting** | `OUT OF SCOPE` | Canvas, WebGL, AudioContext, System Font enumeration, WebRTC local IP enumeration, screen resolution, and TLS ClientHello (JA3/JA4) fingerprinting operate inside the browser/application and cannot be mitigated by the network layer. |
| **Compromised Host Endpoint** | `OUT OF SCOPE` | Rootkits, malware, kernel compromise, or physical host extraction render network-layer protections void. |
| **Malicious Exit Node / VPS Interception** | `OUT OF SCOPE` | The final hop terminates tunnel encryption. Cleartext HTTP or destination IP addresses of TLS connections are visible to the exit operator. |
| **Large-Scale Commercial Infrastructure at 10 Hops** | `NOT YET EXPERIMENTALLY VALIDATED` | Unit and simulation tests prove routing algebra and state containment up to 10 hops. Physical validation over 10 live cross-continental commercial data centers requires external deployment. |
| **Bare-Metal Linux/macOS Kernel Drop Benchmarks** | `NOT YET EXPERIMENTALLY VALIDATED` | Command emission, isolated table/anchor syntax, and failure recovery are unit and simulation verified; physical bare-metal hardware validation is pending dedicated Linux/macOS test nodes. |

---

## 2. Detailed Technical Explanations

### 2.1 IPv6 Capability-Aware Fail-Closed Strategy
- **Limitation**: Not all VPN server providers allocate IPv6 addresses or support dual-stack WireGuard configurations.
- **Mitigation**: Rather than globally disabling IPv6 or blindly forwarding IPv6 into an IPv4-only hop, SecureChain inspects the `supports_ipv6` attribute of every hop in the candidate chain:
  - If **Hop 1 = True, Hop 2 = True, Hop 3 = True**: Dual-stack routing is enabled with split default routes `::/1` and `8000::/1` bound to the exit tunnel interface.
  - If **any hop is False** (e.g., Hop 2 is IPv4-only): IPv6 remains strictly `BLOCKED_FAIL_CLOSED`. Outbound IPv6 is suppressed on the host adapter to prevent silent leakage over physical interfaces.
  - If the user configures `require_ipv6: true`, paths containing any IPv4-only intermediate hops are rejected during path selection.

### 2.2 Global Traffic & Timing Correlation (Passive Adversary)
- **Limitation**: WireGuard packets carry cleartext size and transmission timestamps. A state-level passive adversary monitoring the user's local ISP line and the exit server's uplink simultaneously can statistically correlate traffic bursts using flow watermarking or packet timing analysis.
- **Mitigation (Partial)**: The optional `traffic_shaping` module implements discrete packet size bucket padding (128B, 256B, 512B, 1024B, 1420B) and randomized timing jitter (0–20ms).
- **Explicit Boundary**: SecureChain **does not** claim to defeat global timing correlation. Packet padding introduces CPU and bandwidth overhead and cannot mask long-term flow duration.

### 2.3 Application & Browser Fingerprinting
- **Limitation**: Websites track users via application-layer characteristics independent of IP address.
- **Mitigation (Partial)**: The optional `privacy_proxy` provides local HTTP header sanitization, stripping proxy tracking headers and normalizing User-Agent strings.
- **Explicit Boundary**: Dedicated browser fingerprinting defenses (such as Canvas randomization, WebGL blocking, font enumeration protection, and JA3 TLS handshake normalization) must be handled by purpose-built browser engines (e.g., Tor Browser, Mullvad Browser). SecureChain does NOT perform TLS Man-in-the-Middle (MITM) inspection.

### 2.4 Cross-Platform Native Firewall Enforcement
- **Windows**: Implemented using Windows Advanced Firewall (`netsh advfirewall firewall`).
- **Linux**: Implemented using `nftables` in an isolated table (`table inet securechain`). Does not overwrite or flush unrelated user tables or Docker chains.
- **macOS**: Implemented using Packet Filter (`pf`) in an isolated anchor (`anchor "securechain"`). Safe cleanup flushes only the SecureChain anchor.
- **Safe Fallback**: If non-root or tools are missing, SecureChain safely falls back to `VirtualKillSwitch` and reports `NOT AVAILABLE` / `NOT CONFIGURED` in diagnostics.

---

## 3. Summary of Commitments

1. **Fail-Closed Over Convenience**: If an IPv6 route cannot be verified end-to-end, it is blocked, never leaked.
2. **Never Overwrite Host Configurations**: Firewall backends use isolated namespaces (`inet securechain` table, `securechain` anchor) and never flush user firewalls.
3. **No Exaggerated Privacy Claims**: We do not claim 100% anonymity, untraceability, or invulnerability.
