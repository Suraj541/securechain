"""Integration tests for Multi-Hop Chain Orchestration across 2, 3, 5, and 10 hops (P6)."""

import pytest
from securechain.core.chain_manager import MultiHopChainManager
from securechain.core.exceptions import TunnelConnectionError
from securechain.networking.dns.manager import VirtualDnsManager
from securechain.networking.firewall.kill_switch import KillSwitchState, VirtualKillSwitch
from securechain.networking.ipv6.controller import VirtualIpv6Controller
from securechain.networking.routing.virtual_routing import VirtualRoutingController
from securechain.providers.base import TunnelConfig


def create_chain_manager() -> MultiHopChainManager:
    routing = VirtualRoutingController()
    kill_switch = VirtualKillSwitch()
    dns = VirtualDnsManager()
    ipv6 = VirtualIpv6Controller()
    return MultiHopChainManager(routing, kill_switch, dns, ipv6)


@pytest.mark.parametrize("hop_count", [2, 3, 5, 10])
def test_hop_counts_five_cycles_each(hop_count: int):
    """P6 requirement: ≥ 5 successful cycles per supported hop configuration (2, 3, 5, 10)."""
    mgr = create_chain_manager()

    for cycle in range(5):
        # 1. Connect chain
        chain = mgr.connect_chain(hop_count=hop_count)
        assert chain.hop_count == hop_count
        assert chain.is_active is True
        assert len(chain.hops) == hop_count
        assert chain.exit_interface == f"sim-hop-{hop_count:02d}"

        # 2. Verify complete chain
        verified = mgr.verify_chain(chain)
        assert verified is True, f"Cycle {cycle} failed verification for {hop_count} hops"

        # 3. Teardown chain
        mgr.teardown_chain(chain)
        assert chain.is_active is False
        assert mgr.active_chain is None

        # 4. Verify clean routing & kill switch state
        assert mgr.kill_switch.get_state() == KillSwitchState.DISABLED
        assert len(mgr.routing.get_routes()) == 2  # Baseline routes only


def test_chain_invalid_hop_counts():
    mgr = create_chain_manager()
    # Less than 2
    with pytest.raises(ValueError):
        mgr.connect_chain(1)

    # Greater than 10
    with pytest.raises(ValueError):
        mgr.connect_chain(11)


def test_mid_chain_failure_and_rollback():
    """Verify that if Hop 3 fails during a 5-hop connection, prior hops are torn down and kill switch locks down."""
    mgr = create_chain_manager()
    configs = mgr.build_candidate_configs(5)

    # Corrupt Hop 3 config endpoint to trigger failure
    configs[2].endpoint_ip = "invalid_ip_format"

    with pytest.raises(TunnelConnectionError):
        mgr.connect_chain(5, configs=configs)

    # Verify fail-closed invariant
    assert mgr.active_chain is None
    assert mgr.kill_switch.get_state() == KillSwitchState.ENGAGED  # Must remain locked
    # Routing table cleaned
    assert len(mgr.routing.get_routes()) == 2
