"""Unit tests for Per-Hop IPv6 Capability Detection and Fail-Closed Routing."""

import pytest
from securechain.configuration.schema import PathSelectionConfig
from securechain.core.chain_manager import MultiHopChainManager
from securechain.core.path_manager import AdaptivePathManager, CandidatePath
from securechain.core.scoring import PathTelemetry
from securechain.networking.dns.manager import VirtualDnsManager
from securechain.networking.firewall.kill_switch import VirtualKillSwitch
from securechain.networking.ipv6.controller import Ipv6Status, VirtualIpv6Controller
from securechain.networking.routing.virtual_routing import VirtualRoutingController
from securechain.providers.base import TunnelConfig
from securechain.providers.wireguard import WireGuardProvider


def test_chain_all_hops_ipv6_capable_enables_ipv6_routing():
    """When all hops in the chain support IPv6, IPv6 split routing is enabled."""
    routing = VirtualRoutingController()
    kill_switch = VirtualKillSwitch()
    dns = VirtualDnsManager()
    ipv6 = VirtualIpv6Controller()
    mgr = MultiHopChainManager(routing, kill_switch, dns, ipv6)

    # Build 3 configs all with supports_ipv6=True
    configs = mgr.build_candidate_configs(hop_count=3, supports_ipv6=True)
    assert all(c.supports_ipv6 for c in configs)

    chain = mgr.connect_chain(hop_count=3, configs=configs)
    assert chain.ipv6_enabled is True
    assert "All hops support IPv6" in chain.ipv6_reason
    assert mgr.ipv6.get_status() == Ipv6Status.TUNNELED

    # Check that IPv6 split default routes were registered in routing table
    routes = mgr.routing.get_routes()
    route_dests = [str(r.destination) for r in routes]
    assert "::/1" in route_dests
    assert "8000::/1" in route_dests

    # Teardown should re-enforce fail-closed block
    mgr.teardown_chain(chain)
    assert mgr.ipv6.get_status() == Ipv6Status.BLOCKED_FAIL_CLOSED


def test_chain_mixed_hops_ipv6_fails_closed():
    """When any intermediate or exit hop lacks IPv6, IPv6 remains fail-closed."""
    routing = VirtualRoutingController()
    kill_switch = VirtualKillSwitch()
    dns = VirtualDnsManager()
    ipv6 = VirtualIpv6Controller()
    mgr = MultiHopChainManager(routing, kill_switch, dns, ipv6)

    # Build 3 configs: Hop 1 and 3 support IPv6, Hop 2 is IPv4 only
    configs = mgr.build_candidate_configs(hop_count=3, supports_ipv6=True)
    configs[1].supports_ipv6 = False  # Hop 2 is IPv4-only
    configs[1].assigned_ipv6 = None
    configs[1].gateway_ipv6 = None

    chain = mgr.connect_chain(hop_count=3, configs=configs)
    assert chain.ipv6_enabled is False
    assert "Hop 2 (hop-02) does not support IPv6" in chain.ipv6_reason
    assert mgr.ipv6.get_status() == Ipv6Status.BLOCKED_FAIL_CLOSED

    # Check that no IPv6 default routes escaped to the tunnel
    routes = mgr.routing.get_routes()
    route_dests = [str(r.destination) for r in routes]
    assert "::/1" not in route_dests
    assert "8000::/1" not in route_dests

    mgr.teardown_chain(chain)
    assert mgr.ipv6.get_status() == Ipv6Status.BLOCKED_FAIL_CLOSED


def test_wireguard_config_generation_allowed_ips():
    """Verify WireGuard config includes ::/0 only when supports_ipv6 is True."""
    wg = WireGuardProvider()
    cfg_ipv6 = TunnelConfig(
        tunnel_id="wg-v6",
        provider_type="wireguard",
        endpoint_ip="198.51.100.10",
        endpoint_port=51820,
        assigned_ip="10.8.0.2",
        gateway_ip="10.8.0.1",
        dns_server="10.8.0.1",
        supports_ipv6=True,
        assigned_ipv6="fd00::2",
    )
    conf_text = wg.generate_config_content(cfg_ipv6)
    assert "0.0.0.0/0, ::/0" in conf_text
    assert "fd00::2/64" in conf_text

    cfg_ipv4 = TunnelConfig(
        tunnel_id="wg-v4",
        provider_type="wireguard",
        endpoint_ip="198.51.100.10",
        endpoint_port=51820,
        assigned_ip="10.8.0.2",
        gateway_ip="10.8.0.1",
        dns_server="10.8.0.1",
        supports_ipv6=False,
    )
    conf_text_ipv4 = wg.generate_config_content(cfg_ipv4)
    assert "0.0.0.0/0" in conf_text_ipv4
    assert "::/0" not in conf_text_ipv4


def test_path_selection_capability_filtering():
    """When require_ipv6 is True, paths with any IPv4-only hop must be rejected."""
    config = PathSelectionConfig(require_ipv6=True)

    # Path A has 2 hops, one is IPv4-only
    hop_a1 = TunnelConfig("h1", "simulated", "1.1.1.1", 51820, supports_ipv6=True)
    hop_a2 = TunnelConfig("h2", "simulated", "10.0.0.1", 51821, supports_ipv6=False)
    path_a = CandidatePath("path-mixed", [hop_a1, hop_a2], PathTelemetry(20.0, 0.0, 1.0))

    # Path B has 2 hops, both support IPv6
    hop_b1 = TunnelConfig("h1", "simulated", "1.1.1.1", 51820, supports_ipv6=True)
    hop_b2 = TunnelConfig("h2", "simulated", "10.0.0.1", 51821, supports_ipv6=True)
    path_b = CandidatePath("path-ipv6-ready", [hop_b1, hop_b2], PathTelemetry(35.0, 0.0, 1.0))

    mgr = AdaptivePathManager(config=config, candidate_paths=[path_a, path_b])
    selected = mgr.evaluate_and_select(current_time=0.0)

    # Despite path-mixed having lower latency (20ms vs 35ms), it MUST be rejected because require_ipv6=True
    assert selected is not None
    assert selected.path_id == "path-ipv6-ready"


def test_path_selection_require_ipv6_fails_closed_when_no_candidate_capable():
    """If require_ipv6 is True and no candidates support IPv6, selection returns None (fail-closed)."""
    config = PathSelectionConfig(require_ipv6=True)

    hop_a = TunnelConfig("h1", "simulated", "1.1.1.1", 51820, supports_ipv6=False)
    path_a = CandidatePath("path-v4-only", [hop_a], PathTelemetry(20.0, 0.0, 1.0))

    mgr = AdaptivePathManager(config=config, candidate_paths=[path_a])
    selected = mgr.evaluate_and_select(current_time=0.0)
    assert selected is None
