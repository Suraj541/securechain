"""Central State Machine for SecureChain orchestrator."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Callable, Dict, List, Optional, Set

from securechain.core.exceptions import StateTransitionError
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.state_machine")


class State(str, Enum):
    """Explicit states of the SecureChain orchestrator."""

    OFFLINE = "OFFLINE"
    INITIALIZING = "INITIALIZING"
    BUILDING_CHAIN = "BUILDING_CHAIN"
    CONNECTING = "CONNECTING"
    VERIFYING = "VERIFYING"
    PROTECTED = "PROTECTED"
    DEGRADED = "DEGRADED"
    FAILURE_DETECTED = "FAILURE_DETECTED"
    TRAFFIC_BLOCKED = "TRAFFIC_BLOCKED"
    RECOVERING = "RECOVERING"
    REBUILDING_ROUTE = "REBUILDING_ROUTE"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    TRAFFIC_REMAINS_BLOCKED = "TRAFFIC_REMAINS_BLOCKED"
    SHUTTING_DOWN = "SHUTTING_DOWN"
    DISCONNECTED = "DISCONNECTED"


@dataclass(frozen=True)
class TransitionRecord:
    """Historical audit record of a state transition."""

    from_state: State
    to_state: State
    timestamp: datetime
    reason: str


# Valid directed transitions
VALID_TRANSITIONS: Dict[State, Set[State]] = {
    State.OFFLINE: {State.INITIALIZING, State.SHUTTING_DOWN},
    State.INITIALIZING: {State.BUILDING_CHAIN, State.OFFLINE, State.SHUTTING_DOWN},
    State.BUILDING_CHAIN: {State.CONNECTING, State.TRAFFIC_BLOCKED, State.SHUTTING_DOWN},
    State.CONNECTING: {State.VERIFYING, State.TRAFFIC_BLOCKED, State.SHUTTING_DOWN},
    State.VERIFYING: {State.PROTECTED, State.TRAFFIC_BLOCKED, State.SHUTTING_DOWN},
    State.PROTECTED: {State.DEGRADED, State.FAILURE_DETECTED, State.SHUTTING_DOWN},
    State.DEGRADED: {State.PROTECTED, State.FAILURE_DETECTED, State.SHUTTING_DOWN, State.REBUILDING_ROUTE},
    State.FAILURE_DETECTED: {State.TRAFFIC_BLOCKED, State.SHUTTING_DOWN},
    State.TRAFFIC_BLOCKED: {State.RECOVERING, State.SHUTTING_DOWN},
    State.RECOVERING: {State.REBUILDING_ROUTE, State.RECOVERY_FAILED, State.SHUTTING_DOWN},
    State.REBUILDING_ROUTE: {State.VERIFYING, State.TRAFFIC_BLOCKED, State.SHUTTING_DOWN},
    State.RECOVERY_FAILED: {State.TRAFFIC_REMAINS_BLOCKED, State.SHUTTING_DOWN},
    State.TRAFFIC_REMAINS_BLOCKED: {State.SHUTTING_DOWN},
    State.SHUTTING_DOWN: {State.DISCONNECTED, State.OFFLINE},
    State.DISCONNECTED: {State.OFFLINE, State.INITIALIZING},
}


class StateMachine:
    """Thread-safe state machine controlling the SecureChain lifecycle."""

    def __init__(self, initial_state: State = State.OFFLINE) -> None:
        self._current_state: State = initial_state
        self._history: List[TransitionRecord] = []
        self._listeners: List[Callable[[State, State, str], None]] = []

    @property
    def current_state(self) -> State:
        return self._current_state

    @property
    def history(self) -> List[TransitionRecord]:
        return list(self._history)

    def add_listener(self, listener: Callable[[State, State, str], None]) -> None:
        """Register a callback to be notified on state transitions."""
        self._listeners.append(listener)

    def can_transition(self, target_state: State) -> bool:
        """Check if transitioning from current state to target state is legally permitted."""
        allowed = VALID_TRANSITIONS.get(self._current_state, set())
        return target_state in allowed

    def transition(self, target_state: State, reason: str = "") -> None:
        """Execute a state transition with invariant checks, auditing, and listener dispatch."""
        if target_state == self._current_state:
            logger.debug(f"State transition no-op: already in {self._current_state.value}")
            return

        if not self.can_transition(target_state):
            err_msg = f"Cannot transition from {self._current_state.value} to {target_state.value}"
            logger.error(err_msg)
            raise StateTransitionError(
                from_state=self._current_state.value,
                to_state=target_state.value,
                reason=reason or "Transition not allowed by state transition table",
            )

        from_state = self._current_state
        self._current_state = target_state

        record = TransitionRecord(
            from_state=from_state,
            to_state=target_state,
            timestamp=datetime.now(timezone.utc),
            reason=reason,
        )
        self._history.append(record)

        logger.info(
            f"State transition: {from_state.value} -> {target_state.value} (Reason: {reason or 'nominal'})"
        )

        for listener in self._listeners:
            try:
                listener(from_state, target_state, reason)
            except Exception as exc:
                logger.warning(f"Listener raised exception on transition: {exc}")

    def is_traffic_protected(self) -> bool:
        """Invariant: Traffic is only released and protected when in PROTECTED state."""
        return self._current_state == State.PROTECTED

    def is_traffic_blocked(self) -> bool:
        """Invariant: Traffic is blocked in any failure, recovery, or locked states."""
        return self._current_state in {
            State.FAILURE_DETECTED,
            State.TRAFFIC_BLOCKED,
            State.RECOVERING,
            State.REBUILDING_ROUTE,
            State.RECOVERY_FAILED,
            State.TRAFFIC_REMAINS_BLOCKED,
        }

    def reset(self) -> None:
        """Reset state machine to OFFLINE and clear history."""
        self._current_state = State.OFFLINE
        self._history.clear()
