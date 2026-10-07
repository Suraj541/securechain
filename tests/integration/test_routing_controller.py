"""Integration tests for Routing Controllers and Route Management (P3)."""

import pytest
from securechain.networking.routing.controller import RouteEntry
from securechain.networking.routing.virtual_routing import VirtualRoutingController
from securechain.networking.routing.windows_routing import WindowsRoutingController


def test_virtual_route_lifecycle():
    controller = VirtualRoutingController()
    snapshot = controller.snapshot()
    assert snapshot.default_gateway == "192.168.1.1"

    # 1. Add route for Hop 1
    added = controller.add_route("198.51.100.10/32", "192.168.1.1", "Ethernet0", metric=10)
    assert added is True

    # 2. Verify route
    assert controller.verify_route("198.51.100.10/32", "192.168.1.1") is True

    # 3. Add route for Hop 2 via Hop 1 virtual interface
    controller.add_route("203.0.113.20/32", "10.8.0.1", "sim-vpn-01", metric=15)
    assert controller.verify_route("203.0.113.20/32", "10.8.0.1") is True

    # 4. Longest-prefix matching
    next_hop = controller.resolve_next_hop("198.51.100.10")
    assert next_hop is not None
    assert next_hop.destination == "198.51.100.10/32"
    assert next_hop.gateway == "192.168.1.1"

    # 5. Cleanup temporary routes
    cleaned = controller.cleanup_temporary_routes()
    assert cleaned == 2
    assert controller.verify_route("198.51.100.10/32", "192.168.1.1") is False


def test_unexpected_route_detection():
    controller = VirtualRoutingController()
    snapshot = controller.snapshot()

    # Authorized route added by SecureChain
    controller.add_route("198.51.100.10/32", "192.168.1.1", "Ethernet0")

    # Injected rogue route by external process
    controller.inject_unauthorized_route("10.99.99.0/24", "192.168.1.254", "Ethernet0")

    unexpected = controller.detect_unexpected_changes(snapshot)
    assert len(unexpected) == 1
    assert unexpected[0].destination == "10.99.99.0/24"


def test_original_route_restoration():
    controller = VirtualRoutingController()
    initial_snapshot = controller.snapshot()
    initial_routes_count = len(controller.get_routes())

    # Add several routes
    controller.add_route("10.1.0.0/16", "192.168.1.1", "eth0")
    controller.add_route("10.2.0.0/16", "192.168.1.1", "eth0")
    assert len(controller.get_routes()) == initial_routes_count + 2

    # Restore snapshot
    controller.restore(initial_snapshot)
    assert len(controller.get_routes()) == initial_routes_count
    assert controller.resolve_next_hop("10.1.0.5").destination == "0.0.0.0/0"


def test_twenty_automated_route_cycles():
    """P3 requirement: 20 automated route-management cycles with 100% cleanup."""
    controller = VirtualRoutingController()
    baseline_snapshot = controller.snapshot()

    for cycle in range(20):
        # 1. Add layer of routes
        dest_hop1 = f"198.51.100.{cycle + 1}/32"
        dest_hop2 = f"203.0.113.{cycle + 1}/32"
        controller.add_route(dest_hop1, "192.168.1.1", "Ethernet0", metric=10)
        controller.add_route(dest_hop2, "10.8.0.1", "sim-vpn-01", metric=15)

        # 2. Verify
        assert controller.verify_route(dest_hop1, "192.168.1.1") is True
        assert controller.verify_route(dest_hop2, "10.8.0.1") is True

        # 3. Cleanup
        removed = controller.cleanup_temporary_routes()
        assert removed == 2, f"Cycle {cycle}: Expected 2 routes removed, got {removed}"

        # 4. Verify original baseline preserved
        assert len(controller.detect_unexpected_changes(baseline_snapshot)) == 0


def test_windows_route_inspection():
    """Test reading native Windows routes via ROUTE.EXE without modifying system state."""
    win_ctrl = WindowsRoutingController()
    routes = win_ctrl.get_routes()
    # On Windows, route print should return non-empty active routing table
    assert isinstance(routes, list)
    if routes:
        assert any(r.destination == "0.0.0.0/0" for r in routes)
