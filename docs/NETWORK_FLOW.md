# SecureChain Network Flow Architecture

## 1. Multi-Hop Packet Encapsulation Flow

The network flow coordinates layered encapsulation across $N$ hops (where $2 \le N \le 10$) with an optional VPS termination exit:

```text
Host Client Application
        │
        ▼ (Cleartext Payload / TLS App Traffic)
[Optional: Local Privacy Proxy - 127.0.0.1:8118]
  (Strips tracking headers; Transparent CONNECT without TLS MITM)
        │
        ▼
[Virtual Exit Interface: tunN / vps-exit-01]
        │ Encapsulated with Outer Tunnel Session Key
        ▼ (Outer Packet: Header Dest = Hop N)
[Virtual Hop N-1 Interface: tun(N-1)]
        │ Encapsulated with Hop N-1 Session Key
        ▼
       ...
        │
        ▼ (Encapsulated with Hop 1 Session Key)
[Physical Network Interface: Ethernet0]
        │ Physical Frame (Header Dest = Hop 1 Endpoint)
        ▼
Physical Default Gateway (GW0)
        │
        ▼ (Internet Transit)
Hop 1 VPN Gateway (E1) ── Decrypts Layer 1 ──► Forwards to Hop 2 (E2)
        │
        ▼
Hop 2 VPN Gateway (E2) ── Decrypts Layer 2 ──► Forwards to Hop 3 (E3)
        │
        ▼
Hop N VPN Gateway (En) ── Decrypts Layer N ──► [Optional VPS Termination]
        │
        ▼
Public Internet Target Destination
```

---

## 2. Layered Routing Sequence (IPv4)

To ensure that each tunnel encapsulates strictly through its predecessor:
1. **Hop 1 Endpoint Host Route**:
   - `route add <E1_IP>/32 mask 255.255.255.255 <GW0_IP> metric 10`
   - Traffic targeting Hop 1 traverses the physical default gateway.
2. **Hop 2 Endpoint Host Route**:
   - `route add <E2_IP>/32 mask 255.255.255.255 <GW1_IP> metric 10`
   - Traffic targeting Hop 2 is directed strictly into the virtual interface of Hop 1 (`tun1`).
3. **Hop $i$ Endpoint Host Route**:
   - `route add <Ei_IP>/32 mask 255.255.255.255 <GWi-1_IP> metric 10`
   - Traffic targeting Hop $i$ is directed strictly into the virtual interface of Hop $i-1$ (`tun(i-1)`).
4. **Split Default Egress Override (IPv4)**:
   - `route add 0.0.0.0/1 <GWn_IP> metric 5`
   - `route add 128.0.0.0/1 <GWn_IP> metric 5`
   - These two `/1` routes cover the entire IPv4 address space (`0.0.0.0` - `255.255.255.255`) with higher prefix specificity than the physical `0.0.0.0/0` default route, routing all internet traffic via the final tunnel without destroying baseline physical default gateway routes.

---

## 3. Capability-Aware IPv6 Routing Flows

### Scenario A: Full IPv6 Capability (100% of Hops Support IPv6)
```text
Client Application IPv6 Packet (e.g. 2606:4700::1)
        │
        ▼
Evaluated against routing table: matches split routes ::/1 or 8000::/1
        │
        ▼
Forwarded strictly over exit tunnel interface (tunN)
        │
        ▼
Encapsulated inside WireGuard dual-stack envelopes through all intermediate hops
        │
        ▼
Egresses to IPv6 Internet destination
```

### Scenario B: Mixed or Incomplete IPv6 Capability (e.g., Hop 2 is IPv4-Only)
```text
Client Application IPv6 Packet
        │
        ▼
Host Adapter IPv6 Packet Filter Barrier (Kill Switch)
        │
        ▼
VERDICT: DROP (BLOCKED_FAIL_CLOSED)
  - Split routes ::/1 and 8000::/1 are NOT installed.
  - Physical adapter IPv6 is suppressed to prevent direct bypass.
  - Packet is dropped locally with zero leakage to physical network.
```

---

## 4. Optional Local Privacy Proxy Flow

When enabled (`privacy.privacy_proxy.enabled: true`):
1. **HTTP Requests**: Proxy strips identifying tracking headers (`X-Forwarded-For`, `X-Real-IP`, `Via`, `CF-Connecting-IP`, `Client-IP`), normalizes `User-Agent`, and injects `Referrer-Policy: no-referrer`.
2. **HTTPS Requests**: Applications issue HTTP `CONNECT host:443`. The proxy establishes a transparent bidirectional TCP byte tunnel without TLS interception or certificate forgery.
