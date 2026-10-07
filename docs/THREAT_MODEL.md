# SecureChain Threat Model

## 1. Overview & System Purpose
SecureChain is an adaptive multi-hop network security orchestrator. Its core security objective is to eliminate accidental plaintext data leakage across untrusted physical access points, enforce strict fail-closed traffic containment across supported operating systems, and prevent single-provider link surveillance through multi-hop encapsulation.

SecureChain explicitly disclaims any guarantee of total online anonymity or untraceability against state-level global adversaries.

---

## 2. Protected Against (In Scope)

### 2.1 Untrusted Local Access Networks
- **Threat**: Eavesdropping, rogue APs, ARP poisoning, or packet sniffing on local Wi-Fi / LAN networks.
- **Protection**: All outbound client frames are encrypted within multi-hop tunnel envelopes before egressing the physical network adapter.

### 2.2 Accidental Direct Routing & Fallback Leaks
- **Threat**: If a VPN tunnel process crashes or disconnects unexpectedly, ordinary operating systems fall back to the default ISP gateway, leaking unencrypted packets.
- **Protection**: The Fail-Closed Kill Switch (`CrossPlatformFirewallManager`) maintains an active packet filter barrier blocking any direct traffic over physical interfaces unless an end-to-end chain is actively verified in the `PROTECTED` state.

### 2.3 Cross-Platform Firewall Invariant Preservation
- **Threat**: Firewall modifications that flush host rules, break user Docker/container setups, or fail to engage on non-Windows systems.
- **Protection**: Native implementations on Windows (`netsh`), Linux (`nftables` in isolated table `inet securechain`), and macOS (`pf` in isolated anchor `anchor "securechain"`). Existing rules outside the SecureChain namespace are never destroyed or flushed.

### 2.4 Single VPN Provider Trust Compromise
- **Threat**: A single VPN provider logging user connections or compromised by adversaries correlating client IP with destination activity.
- **Protection**: Multi-hop chaining ensures Hop 1 observes client IP but does not know final destination; intermediate hops only see predecessor and successor tunnel endpoints; and the final hop observes destination traffic but does not know client IP.

### 2.5 DNS Leakage
- **Threat**: Standard OS resolvers querying local router or ISP DNS servers over port 53, leaking domain lookup metadata.
- **Protection**: System DNS is explicitly bound to the internal resolver of the active exit tunnel node, and all non-tunnel DNS queries are dropped by the kill switch.

### 2.6 IPv6 Side-Channel Bypass & Capability Mismatch
- **Threat**: Dual-stack operating systems routing IPv6 packets directly over the physical network interface when VPN tunnels only provide IPv4 encapsulation, or intermediate hops drop IPv6 traffic.
- **Protection**: Per-hop capability inspection enables dual-stack tunneling strictly when 100% of selected hops support IPv6. If any hop is IPv4-only, IPv6 is forced into `BLOCKED_FAIL_CLOSED` mode on the host adapter, preventing side-channel leakage.

### 2.7 Recovery Race Conditions
- **Threat**: Concurrent failure events from health probes triggering simultaneous recovery attempts that interleave and leave routes or firewalls in an uncontained state.
- **Protection**: `RecoveryEngine` synchronizes failure handling with a mutex lock, guaranteeing serialized fail-closed containment, atomic state transitions, and safe stale route purging.

### 2.8 Packet Size & Timing Pattern Analysis (Partial)
- **Threat**: Adversaries observing packet sizes and burst intervals to infer application traffic types.
- **Protection (Optional)**: Traffic shaping module provides bucket padding (discrete 128B, 256B, 512B, 1024B, 1420B boundaries) and randomized timing jitter (0–20ms).

---

## 3. Not Protected Against (Out of Scope)

### 3.1 Global Passive Traffic Correlation
- **Threat**: Adversaries with global visibility into both ingress traffic entering Hop 1 and egress traffic leaving Hop $N$ executing statistical flow and timing correlation.
- **Boundary**: SecureChain cannot defeat global passive adversaries. Traffic shaping reduces discrete burst signatures but cannot mask long-term connection timing and flow duration.

### 3.2 Application & Browser Fingerprinting
- **Threat**: Browser tracking via Canvas, WebGL, AudioContext, System Fonts, WebRTC local IP enumeration, screen resolution, and TLS ClientHello (JA3/JA4) fingerprinting.
- **Boundary**: These execute inside the browser engine or transport layer and are out of scope for network orchestrators. Complete mitigation requires dedicated hardened browser distributions (Tor Browser, Mullvad Browser). SecureChain does NOT perform TLS MITM inspection.

### 3.3 Compromised Host Endpoint
- **Threat**: Malware, rootkits, keyloggers, or physical memory dumps on the local client machine.
- **Boundary**: If endpoint integrity is compromised, cleartext data and cryptographic keys can be intercepted prior to encryption.

### 3.4 Malicious Final Hop or VPS
- **Threat**: The exit node terminates tunnel encapsulation and can inspect unencrypted HTTP traffic or observe destination IP addresses of TLS connections.
- **Boundary**: End-to-end payload confidentiality for web traffic relies on TLS (`HTTPS`). Multi-hop VPN distributes provider trust along the path but does not eliminate trust in the exit node.

### 3.5 Hardware, Firmware, and Baseband Compromise
- **Threat**: Baseband processor backdoors, UEFI rootkits, or DMA bus exploits.
- **Boundary**: Out of scope for operating-system level network orchestration software.
