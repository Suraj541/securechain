# SecureChain Threat Model

## 1. Overview & System Purpose
SecureChain is an adaptive multi-hop network security orchestrator. Its core security objective is to eliminate accidental plaintext data leakage across untrusted physical access points, enforce strict fail-closed traffic containment, and prevent single-provider link surveillance through multi-hop encapsulation.

SecureChain explicitly disclaims any guarantee of total online anonymity or untraceability against state-level global adversaries.

---

## 2. Protected Against (In Scope)

### 2.1 Untrusted Local Access Networks
- **Threat**: Eavesdropping, rogue APs, ARP poisoning, or packet sniffing on local Wi-Fi / LAN networks.
- **Protection**: All outbound client frames are encrypted within multi-hop tunnel envelopes before egressing the physical network adapter.

### 2.2 Accidental Direct Routing & Fallback
- **Threat**: If a VPN tunnel process crashes or disconnects unexpectedly, ordinary operating systems fall back to the default ISP gateway, leaking unencrypted packets.
- **Protection**: The Fail-Closed Kill Switch maintains an active packet filter barrier blocking any direct traffic over physical interfaces unless an end-to-end chain is actively verified in the `PROTECTED` state.

### 2.3 Single VPN Provider Trust Compromise
- **Threat**: A single VPN provider logging user connections or compromised by subpoenas/adversaries can correlate user IP with destination activity.
- **Protection**: Multi-hop chaining ensures that Hop 1 observes client IP but does not know final destination; intermediate hops only see predecessor and successor tunnel endpoints; and the final hop observes destination traffic but does not know client IP.

### 2.4 DNS Leakage
- **Threat**: Standard OS resolvers querying local router or ISP DNS servers over port 53, leaking domain lookup metadata.
- **Protection**: System DNS is explicitly bound to the internal resolver of the active exit tunnel node, and all non-tunnel DNS queries are dropped by the kill switch.

### 2.5 IPv6 Side-Channel Bypass
- **Threat**: Dual-stack operating systems routing IPv6 packets directly over the physical network interface when VPN tunnels only provide IPv4 encapsulation.
- **Protection**: Enforces a fail-closed blocking strategy (`BLOCKED_FAIL_CLOSED`), dropping or disabling IPv6 on physical adapters.

### 2.6 Route Table Poisoning & Hijacking
- **Threat**: Unauthorized route additions by local processes attempting to divert traffic outside the VPN tunnel.
- **Protection**: Pre-flight route snapshotting, continuous route integrity verification, and automatic failure containment if unexpected default routes appear.

---

## 3. Not Protected Against (Out of Scope)

### 3.1 Compromised Host Endpoint
- Malware, keyloggers, screen scrapers, rootkits, or compromised host operating systems.
- If the endpoint kernel or user space is compromised, credentials and cleartext buffers can be extracted prior to encryption.

### 3.2 Application-Layer Fingerprinting
- Browser cookies, canvas fingerprinting, WebRTC IP leakage at the application layer, TLS client hello fingerprinting, and authenticated user logins.

### 3.3 Traffic Correlation by Global Passive Adversaries
- Adversaries with global visibility into both ingress traffic entering Hop 1 and egress traffic leaving Hop $N$ / VPS can execute packet-timing and packet-size correlation attacks. Multi-hop routing does not prevent timing correlation.

### 3.4 Malicious Final Hop or VPS
- The outermost egress node (Hop $N$ or VPS) terminates the encrypted tunnel and can inspect unencrypted HTTP traffic or observe destination IP addresses of TLS connections.

### 3.5 Malicious Hardware / Firmware
- Baseband processor attacks, UEFI rootkits, Intel ME / AMD PSP compromises, or DMA bus attacks.
