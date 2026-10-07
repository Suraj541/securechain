"""Security tests for IPv6 handling and leak suppression (P5B)."""

import pytest
from securechain.networking.ipv6.controller import (
    Ipv6ProbeResult,
    Ipv6Status,
    VirtualIpv6Controller,
    WindowsIpv6Controller,
)


def test_ipv6_detection_and_blocking_lifecycle():
    ipv6_ctrl = VirtualIpv6Controller()
    snapshot = ipv6_ctrl.snapshot()
    assert ipv6_ctrl.get_status() == Ipv6Status.ENABLED_UNPROTECTED

    # Enforce fail-closed blocking strategy
    ipv6_ctrl.enforce_strategy("block")
    assert ipv6_ctrl.get_status() == Ipv6Status.BLOCKED_FAIL_CLOSED

    # Probe leak
    probe = ipv6_ctrl.probe_leak()
    assert probe.is_accessible is False
    assert probe.is_contained is True
    assert probe.verdict == "PASS_BLOCKED"

    # Restore snapshot
    ipv6_ctrl.restore(snapshot)
    assert ipv6_ctrl.get_status() == Ipv6Status.ENABLED_UNPROTECTED


def test_ipv6_leak_detection():
    ipv6_ctrl = VirtualIpv6Controller()
    ipv6_ctrl.enforce_strategy("block")

    # Injected rogue leak
    ipv6_ctrl.inject_ipv6_leak()
    probe = ipv6_ctrl.probe_leak()

    assert probe.is_contained is False
    assert probe.verdict == "FAIL_LEAK_DETECTED"
    assert probe.egress_ip is not None


def test_ten_consecutive_ipv6_leak_tests():
    """P5B requirement: 10/10 IPv6 protection tests PASS with 0 unintended IPv6 paths."""
    ipv6_ctrl = VirtualIpv6Controller()

    for cycle in range(10):
        # Enforce fail-closed blocking
        ipv6_ctrl.enforce_strategy("block")
        probe = ipv6_ctrl.probe_leak()
        assert probe.is_contained is True
        assert probe.is_accessible is False

        # Injected leak must be 100% caught
        ipv6_ctrl.inject_ipv6_leak()
        leak_probe = ipv6_ctrl.probe_leak()
        assert leak_probe.is_contained is False
        assert leak_probe.verdict == "FAIL_LEAK_DETECTED"


def test_windows_ipv6_fallback():
    win_ipv6 = WindowsIpv6Controller()
    snap = win_ipv6.snapshot()
    win_ipv6.enforce_strategy("block")
    assert win_ipv6.get_status() == Ipv6Status.BLOCKED_FAIL_CLOSED
    probe = win_ipv6.probe_leak()
    assert probe.is_contained is True
    win_ipv6.restore(snap)
