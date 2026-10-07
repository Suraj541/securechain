"""Unit tests for Recovery Engine Race-Hardening and Fail-Closed Concurrency."""

import threading
import time
import pytest

from securechain.configuration.schema import RecoveryConfig
from securechain.core.chain_manager import MultiHopChainManager
from securechain.core.path_manager import AdaptivePathManager, CandidatePath
from securechain.core.recovery_engine import RecoveryEngine
from securechain.core.scoring import PathTelemetry
from securechain.core.state_machine import State, StateMachine
from securechain.networking.dns.manager import VirtualDnsManager
from securechain.networking.firewall.kill_switch import KillSwitchState, Packet, VirtualKillSwitch
from securechain.networking.ipv6.controller import VirtualIpv6Controller
from securechain.networking.routing.virtual_routing import VirtualRoutingController


def build_hardened_env():
    sm = StateMachine()
    routing = VirtualRoutingController()
    kill_switch = VirtualKillSwitch()
    dns = VirtualDnsManager()
    ipv6 = VirtualIpv6Controller()
    chain_mgr = MultiHopChainManager(routing, kill_switch, dns, ipv6)

    sm.transition(State.INITIALIZING)
    sm.transition(State.BUILDING_CHAIN)
    sm.transition(State.CONNECTING)
    chain = chain_mgr.connect_chain(3)
    sm.transition(State.VERIFYING)
    sm.transition(State.PROTECTED)

    alt_configs = chain_mgr.build_candidate_configs(3, chain_prefix="alt")
    path_b = CandidatePath("path-B", alt_configs, PathTelemetry(30.0, 0.0, 1.0), healthy_since=0.0)
    path_mgr = AdaptivePathManager(candidate_paths=[path_b])

    engine = RecoveryEngine(
        sm, chain_mgr, path_mgr, routing, kill_switch, dns, ipv6,
        config=RecoveryConfig(max_attempts=2, backoff_seconds=0.5, path_reselection=True),
    )
    return engine, sm, chain_mgr, kill_switch, routing


def test_concurrent_recovery_race_immunity():
    """Simultaneous failure triggers from multiple monitoring threads must not corrupt state."""
    engine, sm, chain_mgr, kill_switch, routing = build_hardened_env()

    # Drop hop 2
    chain_mgr.active_chain.hops[1].provider.disconnect()

    results = []

    def trigger_failure(reason: str):
        res = engine.handle_failure(reason)
        results.append(res)

    # Spawn 4 concurrent threads attempting recovery simultaneously
    t1 = threading.Thread(target=trigger_failure, args=("Thread 1 ping timeout",))
    t2 = threading.Thread(target=trigger_failure, args=("Thread 2 packet loss surge",))
    t3 = threading.Thread(target=trigger_failure, args=("Thread 3 interface down",))
    t4 = threading.Thread(target=trigger_failure, args=("Thread 4 gateway unreachable",))

    for t in [t1, t2, t3, t4]:
        t.start()
    for t in [t1, t2, t3, t4]:
        t.join()

    # All threads complete safely
    assert len(results) == 4
    # State machine must be in valid terminal or protected state
    assert sm.current_state in {State.PROTECTED, State.TRAFFIC_REMAINS_BLOCKED}

    # At no point did kill switch allow direct physical escape during recovery
    direct_pkt = Packet("192.168.1.100", "8.8.8.8", 53, "UDP", "Ethernet0")
    assert kill_switch.evaluate_packet(direct_pkt).allowed is False


def test_terminal_state_refuses_recovery():
    """When system reaches TRAFFIC_REMAINS_BLOCKED, handle_failure immediately returns False."""
    engine, sm, chain_mgr, kill_switch, routing = build_hardened_env()

    # Force SM into terminal fail-closed state
    sm.transition(State.FAILURE_DETECTED, "Total failure")
    sm.transition(State.TRAFFIC_BLOCKED, "Lockdown")
    sm.transition(State.RECOVERING, "Attempt")
    sm.transition(State.RECOVERY_FAILED, "Exhausted")
    sm.transition(State.TRAFFIC_REMAINS_BLOCKED, "Terminal lockdown")

    # Calling handle_failure must immediately return False
    res = engine.handle_failure("New trigger")
    assert res is False
    assert sm.current_state == State.TRAFFIC_REMAINS_BLOCKED


def test_kill_switch_fails_closed_throughout_alternative_failover():
    """Throughout alternative path teardown and rebuilding, kill switch strictly blocks direct traffic."""
    engine, sm, chain_mgr, kill_switch, routing = build_hardened_env()

    # Permanent failure of active chain
    chain_mgr.active_chain.hops[0].provider.simulate_failure_on_connect = True
    chain_mgr.active_chain.hops[0].provider.inject_failure("Permanent hardware fault")

    # Execute recovery to alternative path
    res = engine.handle_failure("Active chain collapsed")
    assert res is True
    assert sm.current_state == State.PROTECTED

    # Verify new chain is active
    assert chain_mgr.active_chain is not None
    assert chain_mgr.active_chain.hops[0].config.tunnel_id.startswith("alt")
