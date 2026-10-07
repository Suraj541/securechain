# SecureChain Network Flow Architecture

## 1. Multi-Hop Packet Encapsulation Flow

The network flow coordinates layered encapsulation across $N$ hops (where $2 \le N \le 10$) with an optional VPS termination exit:

```text
Host Client Application
        │
        ▼ (Cleartext Payload)
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

## 2. Layered Routing Sequence

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
4. **Split Default Egress Override**:
   - `route add 0.0.0.0/1 <GWn_IP> metric 5`
   - `route add 128.0.0.0/1 <GWn_IP> metric 5`
   - These two `/1` routes cover the entire IPv4 address space (`0.0.0.0` - `255.255.255.255`) with higher prefix specificity than the physical `0.0.0.0/0` default route, routing all internet traffic via the final tunnel without destroying baseline physical default gateway routes.
