"""Unit tests for SecureChain State Machine and lifecycle invariants."""

import pytest
from securechain.core.state_machine import State, StateMachine
from securechain.core.exceptions import StateTransitionError


def test_nominal_forward_lifecycle():
    sm = StateMachine()
    assert sm.current_state == State.OFFLINE
    assert not sm.is_traffic_protected()
    assert not sm.is_traffic_blocked()

    sm.transition(State.INITIALIZING, "Starting orchestrator")
    sm.transition(State.BUILDING_CHAIN, "Constructing hop pipeline")
    sm.transition(State.CONNECTING, "Establishing VPN tunnels")
    sm.transition(State.VERIFYING, "Checking routes and DNS")
    sm.transition(State.PROTECTED, "Chain verified successfully")

    assert sm.current_state == State.PROTECTED
    assert sm.is_traffic_protected()
    assert not sm.is_traffic_blocked()
    assert len(sm.history) == 5


def test_failure_and_successful_recovery():
    sm = StateMachine()
    # Advance to PROTECTED
    sm.transition(State.INITIALIZING)
    sm.transition(State.BUILDING_CHAIN)
    sm.transition(State.CONNECTING)
    sm.transition(State.VERIFYING)
    sm.transition(State.PROTECTED)

    # Injected tunnel drop
    sm.transition(State.FAILURE_DETECTED, "Tunnel-02 dropped")
    assert sm.is_traffic_blocked()

    sm.transition(State.TRAFFIC_BLOCKED, "Kill switch engaged")
    assert sm.is_traffic_blocked()
    assert not sm.is_traffic_protected()

    sm.transition(State.RECOVERING, "Reconnecting tunnel")
    sm.transition(State.REBUILDING_ROUTE, "Routes adjusted")
    sm.transition(State.VERIFYING, "Verifying recovered path")
    sm.transition(State.PROTECTED, "Verification passed, traffic released")

    assert sm.is_traffic_protected()
    assert not sm.is_traffic_blocked()


def test_recovery_exhausted_fail_closed():
    sm = StateMachine()
    sm.transition(State.INITIALIZING)
    sm.transition(State.BUILDING_CHAIN)
    sm.transition(State.CONNECTING)
    sm.transition(State.VERIFYING)
    sm.transition(State.PROTECTED)

    sm.transition(State.FAILURE_DETECTED)
    sm.transition(State.TRAFFIC_BLOCKED)
    sm.transition(State.RECOVERING)
    sm.transition(State.RECOVERY_FAILED, "Max recovery retries exceeded")
    sm.transition(State.TRAFFIC_REMAINS_BLOCKED, "Safe lockdown maintained")

    assert sm.current_state == State.TRAFFIC_REMAINS_BLOCKED
    assert sm.is_traffic_blocked()
    assert not sm.is_traffic_protected()


def test_invalid_transitions_rejected():
    sm = StateMachine()

    # Direct jump from OFFLINE to PROTECTED is illegal
    with pytest.raises(StateTransitionError):
        sm.transition(State.PROTECTED)

    # Direct jump from OFFLINE to RECOVERING is illegal
    with pytest.raises(StateTransitionError):
        sm.transition(State.RECOVERING)

    sm.transition(State.INITIALIZING)
    # Direct jump from INITIALIZING to PROTECTED is illegal
    with pytest.raises(StateTransitionError):
        sm.transition(State.PROTECTED)


def test_transition_listeners():
    sm = StateMachine()
    dispatched = []

    def callback(from_state, to_state, reason):
        dispatched.append((from_state, to_state, reason))

    sm.add_listener(callback)
    sm.transition(State.INITIALIZING, "init")
    sm.transition(State.BUILDING_CHAIN, "build")

    assert len(dispatched) == 2
    assert dispatched[0] == (State.OFFLINE, State.INITIALIZING, "init")
    assert dispatched[1] == (State.INITIALIZING, State.BUILDING_CHAIN, "build")
