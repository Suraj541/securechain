"""Integration tests for VPS Termination Layer (P7)."""

import pytest
from pydantic import SecretStr
from securechain.networking.firewall.kill_switch import KillSwitchState, VirtualKillSwitch
from securechain.networking.routing.virtual_routing import VirtualRoutingController
from securechain.networking.vps.termination import (
    SimulatedVpsTerminationLayer,
    VpsConfig,
    VpsState,
)


def make_vps_config() -> VpsConfig:
    return VpsConfig(
        endpoint="exit-node.securechain.org:51820",
        protocol="wireguard",
        assigned_ip="10.99.0.2",
        gateway_ip="10.99.0.1",
        dns_server="10.99.0.1",
        auth_token=SecretStr("super_secret_vps_token_12345"),
    )


def test_ten_vps_lifecycle_cycles():
    """P7 requirement: 10 successful VPS lifecycle cycles."""
    routing = VirtualRoutingController()
    kill_switch = VirtualKillSwitch()
    kill_switch.enable()

    cfg = make_vps_config()
    vps = SimulatedVpsTerminationLayer(cfg, routing, kill_switch, base_latency_ms=20.0)

    for cycle in range(10):
        # 1. Connect
        status = vps.connect(underlying_gateway="10.8.3.1", underlying_interface="sim-hop-03")
        assert status.state == VpsState.CONNECTED
        assert status.interface.name == "vps-exit-01"
        assert kill_switch.get_state() == KillSwitchState.FILTERED_PASS

        # 2. Health check
        health = vps.health_check()
        assert health.is_reachable is True
        assert health.latency_ms == 20.0

        # 3. Route verification
        assert routing.verify_route("0.0.0.0/1", "10.99.0.1") is True
        assert routing.verify_route("128.0.0.0/1", "10.99.0.1") is True

        # 4. Disconnect & cleanup
        status_disc = vps.disconnect()
        assert status_disc.state == VpsState.DISCONNECTED
        vps.cleanup()
        routing.cleanup_temporary_routes()


def test_five_simulated_vps_failures():
    """P7 requirement: 5 simulated VPS failures with 5/5 failure detections and containment."""
    routing = VirtualRoutingController()
    kill_switch = VirtualKillSwitch()
    kill_switch.enable()

    cfg = make_vps_config()
    vps = SimulatedVpsTerminationLayer(cfg, routing, kill_switch)

    for cycle in range(5):
        # Establish connection
        vps.connect(underlying_gateway="10.8.3.1", underlying_interface="sim-hop-03")
        assert vps.status().state == VpsState.CONNECTED

        # INJECT FAILURE
        vps.inject_failure(f"VPS failure in cycle {cycle}")

        # 1. Verify failure detected
        assert vps.status().state == VpsState.FAILED
        assert vps.health_check().is_reachable is False

        # 2. Verify traffic contained (lockdown engaged)
        assert kill_switch.get_state() == KillSwitchState.ENGAGED

        # Cleanup
        vps.cleanup()
        routing.cleanup_temporary_routes()
