"""Integration test for single VPN provider lifecycle (P2)."""

import pytest
from pydantic import SecretStr
from securechain.core.exceptions import TunnelConnectionError, TunnelError
from securechain.providers.base import TunnelConfig, TunnelState
from securechain.providers.simulated import SimulatedVPNProvider


def make_test_config(tunnel_id: str = "vpn-01") -> TunnelConfig:
    return TunnelConfig(
        tunnel_id=tunnel_id,
        provider_type="simulated",
        endpoint_ip="198.51.100.10",
        endpoint_port=51820,
        public_key="AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+==",
        private_key=SecretStr("sUPeRSeCReTKey123456789012345678901234=="),
        assigned_ip="10.8.0.2",
        gateway_ip="10.8.0.1",
        dns_server="10.8.0.1",
        mtu=1420,
    )


def test_single_vpn_lifecycle():
    provider = SimulatedVPNProvider(base_latency_ms=22.0, base_loss_pct=0.0, base_jitter_ms=1.8)
    config = make_test_config()

    # 1. Connect
    status = provider.connect(config)
    assert status.state == TunnelState.CONNECTED
    assert status.tunnel_id == "vpn-01"
    assert status.interface is not None
    assert status.interface.name == "sim-vpn-01"
    assert status.interface.ip_address == "10.8.0.2"

    # 2. Health check
    health = provider.health_check()
    assert health.is_reachable is True
    assert health.latency_ms == 22.0
    assert health.packet_loss_pct == 0.0

    # 3. Interface exposure
    iface = provider.get_interface()
    assert iface.gateway_ip == "10.8.0.1"

    # 4. Disconnect
    status_disc = provider.disconnect()
    assert status_disc.state == TunnelState.DISCONNECTED
    assert status_disc.interface is None

    # 5. Cleanup
    provider.cleanup()
    assert provider.status().state == TunnelState.DISCONNECTED


def test_ten_consecutive_cycles():
    """P2 requirement: 10 consecutive successful connection/disconnection cycles."""
    provider = SimulatedVPNProvider(base_latency_ms=18.0)
    config = make_test_config()

    for cycle in range(10):
        # Connect
        status = provider.connect(config)
        assert status.state == TunnelState.CONNECTED, f"Failed connect on cycle {cycle}"
        assert provider.get_interface().name == "sim-vpn-01"

        # Verify health
        metric = provider.health_check()
        assert metric.is_reachable is True

        # Disconnect
        status_disc = provider.disconnect()
        assert status_disc.state == TunnelState.DISCONNECTED, f"Failed disconnect on cycle {cycle}"

        # Cleanup
        provider.cleanup()


def test_connection_failure_injection():
    provider = SimulatedVPNProvider(simulate_failure_on_connect=True)
    config = make_test_config()

    with pytest.raises(TunnelConnectionError):
        provider.connect(config)

    assert provider.status().state == TunnelState.FAILED
    health = provider.health_check()
    assert health.is_reachable is False
    assert health.packet_loss_pct == 100.0


def test_get_interface_unconnected_raises():
    provider = SimulatedVPNProvider()
    with pytest.raises(TunnelError):
        provider.get_interface()
