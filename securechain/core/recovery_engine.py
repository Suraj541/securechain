import threading
import time
from typing import Optional

from securechain.configuration.schema import RecoveryConfig
from securechain.core.chain_manager import MultiHopChainManager
from securechain.core.exceptions import RecoveryExhaustedError, TunnelConnectionError
from securechain.core.path_manager import AdaptivePathManager
from securechain.core.state_machine import State, StateMachine
from securechain.networking.dns.manager import DnsManager
from securechain.networking.firewall.kill_switch import KillSwitch, KillSwitchState
from securechain.networking.ipv6.controller import Ipv6Controller
from securechain.networking.routing.controller import RoutingController
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.core.recovery_engine")


class RecoveryEngine:
    """Coordinates fail-closed containment, bounded retries, and alternative path failover."""

    def __init__(
        self,
        state_machine: StateMachine,
        chain_manager: MultiHopChainManager,
        path_manager: Optional[AdaptivePathManager],
        routing_controller: RoutingController,
        kill_switch: KillSwitch,
        dns_manager: DnsManager,
        ipv6_controller: Ipv6Controller,
        config: Optional[RecoveryConfig] = None,
    ) -> None:
        self.sm = state_machine
        self.chain_mgr = chain_manager
        self.path_mgr = path_manager
        self.routing = routing_controller
        self.kill_switch = kill_switch
        self.dns = dns_manager
        self.ipv6 = ipv6_controller
        self.config = config or RecoveryConfig()
        self._recovery_lock = threading.Lock()

    def handle_failure(self, failure_reason: str = "Tunnel Link Dropped") -> bool:
        """Execute fail-closed containment, bounded retries, and alternative path recovery with race immunity.

        Returns True if system recovered and verified in PROTECTED state;
        Returns False if unrecoverable and locked in TRAFFIC_REMAINS_BLOCKED.
        """
        with self._recovery_lock:
            if self.sm.current_state == State.TRAFFIC_REMAINS_BLOCKED:
                logger.warning("System in terminal TRAFFIC_REMAINS_BLOCKED state; refusing recovery without restart.")
                return False

            logger.warning(f"Failure triggered: {failure_reason}")

            # 1. Immediate Fail-Closed Containment
            if self.sm.can_transition(State.FAILURE_DETECTED):
                self.sm.transition(State.FAILURE_DETECTED, failure_reason)

            # Engage lockdown before anything else
            if hasattr(self.kill_switch, "engage_lockdown"):
                self.kill_switch.engage_lockdown()
            else:
                self.kill_switch.enable()

            if self.sm.can_transition(State.TRAFFIC_BLOCKED):
                self.sm.transition(State.TRAFFIC_BLOCKED, "Kill switch lockdown active")

            # 2. Enter RECOVERING
            self.sm.transition(State.RECOVERING, "Starting bounded recovery")

            # Attempt in-place recovery on active chain (up to max_attempts)
            active_chain = self.chain_mgr.active_chain
            recovered = False

            if active_chain and active_chain.is_active:
                for attempt in range(1, self.config.max_attempts + 1):
                    logger.info(f"Attempting in-place reconnect (attempt {attempt}/{self.config.max_attempts})...")
                    try:
                        # In-place reconnect attempt: check and reconnect disconnected/failed nodes
                        for node in active_chain.hops:
                            st = node.provider.status()
                            if st.state in {st.state.FAILED, st.state.DISCONNECTED}:
                                node.provider.cleanup()
                                node.provider.connect(node.config)

                        # Re-arm exit interface on kill switch for verification
                        if active_chain.exit_interface:
                            self.kill_switch.set_active_exit_interface(active_chain.exit_interface)

                        # Re-verify in place
                        if self.chain_mgr.verify_chain(active_chain):
                            recovered = True
                            logger.info("In-place reconnect succeeded!")
                            break
                        else:
                            # Re-engage lockdown if verification failed
                            self.kill_switch.enable()
                    except Exception as exc:
                        logger.warning(f"In-place recovery attempt {attempt} failed: {exc}")

            # 3. Path Reselection Failover (if in-place failed and reselection enabled)
            if not recovered and self.config.path_reselection and self.path_mgr:
                logger.info("In-place reconnect failed; evaluating alternative candidate paths...")
                alternative = self.path_mgr.evaluate_and_select()

                if alternative and alternative.hop_configs:
                    try:
                        # Dismantle broken chain
                        self.chain_mgr.teardown_chain()
                        # Keep kill switch in lockdown
                        self.kill_switch.enable()

                        # Connect alternative chain
                        new_chain = self.chain_mgr.connect_chain(
                            hop_count=len(alternative.hop_configs),
                            configs=alternative.hop_configs,
                        )

                        # Transition through REBUILDING_ROUTE -> VERIFYING
                        self.sm.transition(State.REBUILDING_ROUTE, f"Switched to path {alternative.path_id}")
                        self.sm.transition(State.VERIFYING, "Verifying alternative chain")

                        # Verify new chain
                        if self.chain_mgr.verify_chain(new_chain):
                            recovered = True
                            logger.info(f"Successfully recovered on alternative path '{alternative.path_id}'!")
                    except Exception as exc:
                        logger.error(f"Alternative path failover failed: {exc}")

            # 4. Final State Resolution
            if recovered:
                if self.sm.current_state == State.RECOVERING:
                    self.sm.transition(State.REBUILDING_ROUTE, "Routes checked")
                    self.sm.transition(State.VERIFYING, "Final verification")
                elif self.sm.current_state == State.REBUILDING_ROUTE:
                    self.sm.transition(State.VERIFYING, "Final verification")
                self.sm.transition(State.PROTECTED, "Chain restored and verified")
                return True
            else:
                logger.critical("All recovery attempts exhausted! Maintaining safe terminal lockdown.")
                self.sm.transition(State.RECOVERY_FAILED, "Max recovery attempts exhausted")
                self.sm.transition(State.TRAFFIC_REMAINS_BLOCKED, "Safe fail-closed terminal state")
                return False
