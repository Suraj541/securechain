"""Security tests for Fail-Closed Kill Switch and Traffic Containment (P4)."""

import pytest
from securechain.networking.firewall.kill_switch import (
    KillSwitchState,
    Packet,
    VirtualKillSwitch,
    WindowsKillSwitch,
)


def test_kill_switch_lifecycle():
    ks = VirtualKillSwitch()
    assert ks.get_state() == KillSwitchState.DISABLED

    # When disabled, packet escapes
    pkt = Packet("192.168.1.100", "93.184.216.34", 443, "TCP", "Ethernet0")
    assert ks.evaluate_packet(pkt).allowed is True

    # 1. Engage lockdown
    ks.enable()
    assert ks.get_state() == KillSwitchState.ENGAGED

    # In lockdown, direct packet is DROPPED
    verdict = ks.evaluate_packet(pkt)
    assert verdict.allowed is False
    assert verdict.matched_rule == "BLOCK_DIRECT_INTERNET"

    # Loopback is ALLOWED
    loopback_pkt = Packet("127.0.0.1", "127.0.0.1", 8080, "TCP", "lo")
    assert ks.evaluate_packet(loopback_pkt).allowed is True

    # 2. Allow Hop 1 endpoint handshake via physical adapter
    ks.allow_hop1_endpoint("198.51.100.10", 51820)
    hop1_pkt = Packet("192.168.1.100", "198.51.100.10", 51820, "UDP", "Ethernet0")
    assert ks.evaluate_packet(hop1_pkt).allowed is True

    # Different IP is still blocked
    direct_pkt = Packet("192.168.1.100", "8.8.8.8", 53, "UDP", "Ethernet0")
    assert ks.evaluate_packet(direct_pkt).allowed is False

    # 3. Transition to FILTERED_PASS when verified exit tunnel exists
    ks.set_active_exit_interface("sim-vpn-03")
    assert ks.get_state() == KillSwitchState.FILTERED_PASS

    # Traffic traversing verified tunnel interface is ALLOWED
    tunnel_pkt = Packet("10.8.0.2", "93.184.216.34", 443, "TCP", "sim-vpn-03")
    assert ks.evaluate_packet(tunnel_pkt).allowed is True

    # Direct traffic over physical adapter remains BLOCKED even in FILTERED_PASS
    assert ks.evaluate_packet(direct_pkt).allowed is False

    # 4. Disable
    ks.disable()
    assert ks.get_state() == KillSwitchState.DISABLED
    assert ks.evaluate_packet(direct_pkt).allowed is True


def test_ten_consecutive_tunnel_failure_containment():
    """P4 requirement: 10 consecutive simulated tunnel-failure tests with 10/10 traffic containment."""
    ks = VirtualKillSwitch()

    for cycle in range(10):
        # 1. System in verified operational state
        ks.enable()
        ks.allow_hop1_endpoint("198.51.100.10", 51820)
        ks.set_active_exit_interface(f"sim-vpn-cycle-{cycle}")
        assert ks.get_state() == KillSwitchState.FILTERED_PASS

        # Verified packet passes
        verified_pkt = Packet("10.8.0.2", "1.1.1.1", 443, "TCP", f"sim-vpn-cycle-{cycle}")
        assert ks.evaluate_packet(verified_pkt).allowed is True

        # 2. TUNNEL FAILURE INJECTED -> Immediate lockdown
        ks.engage_lockdown()
        assert ks.get_state() == KillSwitchState.ENGAGED

        # Outbound packet attempting to escape is DROPPED
        leaking_pkt = Packet("192.168.1.100", "1.1.1.1", 443, "TCP", "Ethernet0")
        verdict = ks.evaluate_packet(leaking_pkt)
        assert verdict.allowed is False, f"Cycle {cycle}: Traffic escaped after failure!"

        # Previous exit tunnel packet is also rejected during lockdown
        assert ks.evaluate_packet(verified_pkt).allowed is False, f"Cycle {cycle}: Tunnel traffic released during lockdown!"

        # 3. Recovery mode: traffic remains safely blocked
        assert ks.evaluate_packet(leaking_pkt).allowed is False

        # Cleanup
        ks.disable()


def test_no_release_before_verification():
    """Verify traffic is never released during BUILDING, CONNECTING, or RECOVERING."""
    ks = VirtualKillSwitch()
    ks.enable()  # BUILDING / CONNECTING / RECOVERING
    ks.allow_hop1_endpoint("198.51.100.10", 51820)

    # General web packet attempting egress
    web_pkt = Packet("192.168.1.100", "142.250.190.46", 443, "TCP", "Ethernet0")
    assert ks.evaluate_packet(web_pkt).allowed is False

    # DNS packet attempting egress via physical network
    dns_pkt = Packet("192.168.1.100", "8.8.8.8", 53, "UDP", "Ethernet0")
    assert ks.evaluate_packet(dns_pkt).allowed is False


def test_windows_kill_switch_fallback_initialization():
    wks = WindowsKillSwitch()
    wks.enable()
    assert wks.get_state() == KillSwitchState.ENGAGED

    pkt = Packet("192.168.1.100", "8.8.8.8", 53, "UDP", "Ethernet0")
    assert wks.evaluate_packet(pkt).allowed is False
    wks.disable()
    assert wks.get_state() == KillSwitchState.DISABLED
