"""Security tests for DNS leak protection and resolver enforcement (P5)."""

import pytest
from securechain.networking.dns.manager import (
    DnsQueryResult,
    DnsResolver,
    VirtualDnsManager,
    WindowsDnsManager,
)


def test_dns_normal_and_tunnel_lifecycle():
    dns_mgr = VirtualDnsManager(isp_resolver="192.168.1.1")
    snapshot = dns_mgr.snapshot()
    assert dns_mgr.get_active_resolver() == "192.168.1.1"

    # Set tunnel DNS
    dns_mgr.set_tunnel_dns("10.8.0.1", "sim-vpn-01")
    assert dns_mgr.get_active_resolver() == "10.8.0.1"
    assert dns_mgr.verify_dns_protection("10.8.0.1") is True

    # Perform canary query
    res = dns_mgr.test_dns_leak("example.com")
    assert res.is_leak is False
    assert res.resolver_used == "10.8.0.1"

    # Restore
    dns_mgr.restore(snapshot)
    assert dns_mgr.get_active_resolver() == "192.168.1.1"


def test_dns_leak_detection():
    dns_mgr = VirtualDnsManager(isp_resolver="192.168.1.1")
    dns_mgr.set_tunnel_dns("10.8.0.1", "sim-vpn-01")

    # Inject simulated leak to ISP resolver
    dns_mgr.inject_dns_leak("192.168.1.1")
    res = dns_mgr.test_dns_leak("secret-query.internal")

    assert res.is_leak is True
    assert res.resolver_used == "192.168.1.1"
    assert dns_mgr.verify_dns_protection("10.8.0.1") is False


def test_ten_consecutive_dns_leak_tests():
    """P5 requirement: 10/10 DNS protection tests PASS with 0 unintended resolver usage."""
    dns_mgr = VirtualDnsManager(isp_resolver="192.168.1.1")

    for cycle in range(10):
        expected_resolver = f"10.8.{cycle}.1"
        dns_mgr.set_tunnel_dns(expected_resolver, f"sim-vpn-{cycle}")

        # Nominal test
        res = dns_mgr.test_dns_leak(f"test-cycle-{cycle}.org")
        assert res.is_leak is False
        assert res.resolver_used == expected_resolver

        # Simulated rogue injection must be 100% caught
        dns_mgr.inject_dns_leak("192.168.1.1")
        leak_res = dns_mgr.test_dns_leak(f"leak-cycle-{cycle}.org")
        assert leak_res.is_leak is True
        assert leak_res.resolver_used == "192.168.1.1"


def test_windows_dns_fallback():
    win_dns = WindowsDnsManager()
    snap = win_dns.snapshot()
    win_dns.set_tunnel_dns("10.8.0.1", "sim-vpn-01")
    assert win_dns.get_active_resolver() == "10.8.0.1"
    assert win_dns.verify_dns_protection("10.8.0.1") is True
    win_dns.restore(snap)
