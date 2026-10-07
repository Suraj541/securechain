"""Comprehensive Failure and Recovery tests (P10)."""

import pytest
from securechain.configuration.schema import RecoveryConfig
from securechain.core.chain_manager import MultiHopChainManager
from securechain.core.path_manager import AdaptivePathManager, CandidatePath
from securechain.core.recovery_engine import RecoveryEngine
from securechain.core.scoring import PathTelemetry
from securechain.core.state_machine import State, StateMachine
from securechain.networking.dns.manager import VirtualDnsManager
from securechain.networking.firewall.kill_switch import KillSwitchState, VirtualKillSwitch
from securechain.networking.ipv6.controller import VirtualIpv6Controller
from securechain.networking.routing.virtual_routing import VirtualRoutingController
from securechain.providers.base import TunnelConfig


def build_test_environment():
    sm = StateMachine()
    routing = VirtualRoutingController()
    kill_switch = VirtualKillSwitch()
    dns = VirtualDnsManager()
    ipv6 = VirtualIpv6Controller()
    chain_mgr = MultiHopChainManager(routing, kill_switch, dns, ipv6)

    # Establish baseline 3-hop chain and advance SM to PROTECTED
    sm.transition(State.INITIALIZING)
    sm.transition(State.BUILDING_CHAIN)
    sm.transition(State.CONNECTING)
    chain = chain_mgr.connect_chain(3)
    sm.transition(State.VERIFYING)
    sm.transition(State.PROTECTED)

    # Prepare alternative candidate path B in path manager
    alt_configs = chain_mgr.build_candidate_configs(3, chain_prefix="alt")
    path_b = CandidatePath("path-B", alt_configs, PathTelemetry(35.0, 0.0, 2.0), healthy_since=0.0)
    path_mgr = AdaptivePathManager(candidate_paths=[path_b])

    engine = RecoveryEngine(
        sm, chain_mgr, path_mgr, routing, kill_switch, dns, ipv6,
        config=RecoveryConfig(max_attempts=2, backoff_seconds=1.0, path_reselection=True),
    )
    return engine, sm, chain_mgr, kill_switch, path_mgr


def test_in_place_hop_recovery():
    engine, sm, chain_mgr, kill_switch, path_mgr = build_test_environment()

    # Drop Hop 2 (transient glitch)
    chain_mgr.active_chain.hops[1].provider.disconnect()

    # Recover
    recovered = engine.handle_failure("Transient hop 2 drop")

    assert recovered is True
    assert sm.current_state == State.PROTECTED
    assert sm.is_traffic_protected()
    assert kill_switch.get_state() == KillSwitchState.FILTERED_PASS

    chain_mgr.teardown_chain()


def test_alternative_path_failover_recovery():
    engine, sm, chain_mgr, kill_switch, path_mgr = build_test_environment()

    # Make Hop 1 permanently broken on in-place reconnect
    chain_mgr.active_chain.hops[0].provider.simulate_failure_on_connect = True
    chain_mgr.active_chain.hops[0].provider.inject_failure("Permanent hardware fault")

    # Handle failure
    recovered = engine.handle_failure("Permanent hop 1 failure")

    assert recovered is True
    assert sm.current_state == State.PROTECTED
    assert chain_mgr.active_chain.chain_id == "chain-3hop"
    assert "alt" in chain_mgr.active_chain.hops[0].config.tunnel_id
    assert kill_switch.get_state() == KillSwitchState.FILTERED_PASS

    chain_mgr.teardown_chain()


def test_unrecoverable_failure_safe_lockdown():
    sm = StateMachine()
    routing = VirtualRoutingController()
    kill_switch = VirtualKillSwitch()
    dns = VirtualDnsManager()
    ipv6 = VirtualIpv6Controller()
    chain_mgr = MultiHopChainManager(routing, kill_switch, dns, ipv6)

    sm.transition(State.INITIALIZING)
    sm.transition(State.BUILDING_CHAIN)
    sm.transition(State.CONNECTING)
    chain = chain_mgr.connect_chain(2)
    sm.transition(State.VERIFYING)
    sm.transition(State.PROTECTED)

    # Empty candidate paths and break current
    chain.hops[0].provider.simulate_failure_on_connect = True
    chain.hops[0].provider.inject_failure("Total ISP blackout")

    engine = RecoveryEngine(
        sm, chain_mgr, None, routing, kill_switch, dns, ipv6,
        config=RecoveryConfig(max_attempts=1, path_reselection=False),
    )

    recovered = engine.handle_failure("Total ISP blackout")

    # Invariant: Must report False and remain in safe terminal lockdown!
    assert recovered is False
    assert sm.current_state == State.TRAFFIC_REMAINS_BLOCKED
    assert sm.is_traffic_blocked()
    assert not sm.is_traffic_protected()
    assert kill_switch.get_state() == KillSwitchState.ENGAGED


def test_thirty_deterministic_failure_simulations():
    """P10 requirement: 30 deterministic failure simulations with 100% containment and ≥ 95% recovery rate."""
    recoverable_successes = 0
    total_recoverable = 28
    unrecoverable_contained = 0

    # 1. 28 Recoverable failure simulations across different hops and configurations
    for run in range(28):
        engine, sm, chain_mgr, kill_switch, path_mgr = build_test_environment()

        # Alternate failure targets: hop 1, hop 2, hop 3, or DNS
        target_idx = run % 3
        chain_mgr.active_chain.hops[target_idx].provider.disconnect()

        recovered = engine.handle_failure(f"Simulation run {run} on hop {target_idx}")
        if recovered and sm.current_state == State.PROTECTED:
            recoverable_successes += 1

        # Check traffic containment during clean
        assert kill_switch.get_state() in {KillSwitchState.FILTERED_PASS, KillSwitchState.ENGAGED}
        chain_mgr.teardown_chain()

    # 2. 2 Intentionally Unrecoverable simulations
    for unrec_run in range(2):
        sm = StateMachine()
        routing = VirtualRoutingController()
        kill_switch = VirtualKillSwitch()
        dns = VirtualDnsManager()
        ipv6 = VirtualIpv6Controller()
        chain_mgr = MultiHopChainManager(routing, kill_switch, dns, ipv6)

        sm.transition(State.INITIALIZING)
        sm.transition(State.BUILDING_CHAIN)
        sm.transition(State.CONNECTING)
        chain = chain_mgr.connect_chain(2)
        sm.transition(State.VERIFYING)
        sm.transition(State.PROTECTED)

        chain.hops[0].provider.simulate_failure_on_connect = True
        chain.hops[0].provider.inject_failure("Permanent drop")

        engine = RecoveryEngine(
            sm, chain_mgr, None, routing, kill_switch, dns, ipv6,
            config=RecoveryConfig(max_attempts=1, path_reselection=False),
        )
        recovered = engine.handle_failure("Catastrophic loss")
        if not recovered and sm.current_state == State.TRAFFIC_REMAINS_BLOCKED:
            unrecoverable_contained += 1

    total_runs = 28 + 2
    assert total_runs == 30
    assert recoverable_successes == 28, f"Expected 28 recoverable successes, got {recoverable_successes}"
    assert unrecoverable_contained == 2, f"Expected 2 unrecoverable safely contained, got {unrecoverable_contained}"
    recovery_rate = (recoverable_successes / total_recoverable) * 100
    assert recovery_rate >= 95.0
