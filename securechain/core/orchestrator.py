"""Core Orchestrator coordinating all SecureChain subsystems."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import time

from securechain.configuration.loader import load_config
from securechain.configuration.schema import SecureChainConfig
from securechain.core.chain_manager import Chain, MultiHopChainManager
from securechain.core.reality_check import RealityChecker
from securechain.core.exceptions import ConfigurationError, SecureChainError
from securechain.core.path_manager import AdaptivePathManager, CandidatePath
from securechain.core.recovery_engine import RecoveryEngine
from securechain.core.scoring import PathTelemetry
from securechain.core.state_machine import State, StateMachine
from securechain.monitoring.metrics import SystemHealthReport
from securechain.monitoring.monitor import HealthMonitor
from securechain.networking.dns.manager import DnsManager, VirtualDnsManager, WindowsDnsManager
from securechain.networking.firewall.kill_switch import KillSwitch, VirtualKillSwitch, WindowsKillSwitch
from securechain.networking.ipv6.controller import Ipv6Controller, VirtualIpv6Controller, WindowsIpv6Controller
from securechain.networking.routing.controller import RoutingController
from securechain.networking.routing.virtual_routing import VirtualRoutingController
from securechain.networking.routing.windows_routing import WindowsRoutingController, is_windows_admin
from securechain.networking.vps.termination import SimulatedVpsTerminationLayer, VpsConfig
from securechain.security.credentials.dpapi_store import DpapiCredentialStore
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.orchestrator")


class SecureChainOrchestrator:
    """Central orchestrator managing multi-hop VPN chains, security boundaries, and telemetry."""

    def __init__(
        self,
        config: Optional[SecureChainConfig] = None,
        state_file: Optional[Path] = None,
    ) -> None:
        self.config = config or load_config()
        self.state_file = state_file or Path(".securechain_state.json")
        self.is_elevated = is_windows_admin()
        self.active_mode: str = "simulation"

        # State Machine
        self.sm = StateMachine()

        # Routing Controller (elevated Windows or high-fidelity Virtual)
        self.routing: RoutingController = (
            WindowsRoutingController() if self.is_elevated else VirtualRoutingController()
        )

        # Kill Switch
        self.kill_switch: KillSwitch = (
            WindowsKillSwitch() if self.is_elevated else VirtualKillSwitch()
        )

        # DNS Manager
        self.dns: DnsManager = (
            WindowsDnsManager() if self.is_elevated else VirtualDnsManager()
        )

        # IPv6 Controller
        self.ipv6: Ipv6Controller = (
            WindowsIpv6Controller() if self.is_elevated else VirtualIpv6Controller()
        )

        # Credential Store
        self.credentials = DpapiCredentialStore()

        # Multi-Hop Chain Manager
        self.chain_mgr = MultiHopChainManager(
            self.routing,
            self.kill_switch,
            self.dns,
            self.ipv6,
        )

        # Candidate Paths & Path Manager
        self.path_mgr = AdaptivePathManager(config=self.config.path_selection)

        # Setup VPS (if enabled)
        self.vps: Optional[SimulatedVpsTerminationLayer] = None
        if self.config.vps.enabled and self.config.vps.endpoint:
            vps_cfg = VpsConfig(
                endpoint=self.config.vps.endpoint,
                protocol=self.config.vps.protocol or "wireguard",
            )
            self.vps = SimulatedVpsTerminationLayer(vps_cfg, self.routing, self.kill_switch)

        # Health Monitor
        self.monitor = HealthMonitor(
            self.chain_mgr,
            self.routing,
            self.kill_switch,
            self.dns,
            self.ipv6,
            self.vps,
        )

        # Recovery Engine
        self.recovery = RecoveryEngine(
            self.sm,
            self.chain_mgr,
            self.path_mgr,
            self.routing,
            self.kill_switch,
            self.dns,
            self.ipv6,
            config=self.config.recovery,
        )

    def start(self, hop_count: Optional[int] = None, auto: bool = False, mode: str = "real") -> bool:
        """Start multi-hop orchestration and establish protected chain."""
        self.active_mode = mode.lower()

        if self.active_mode == "real":
            checker = RealityChecker(self.config)
            vpn_check = checker.check_vpn_configuration()
            if not vpn_check.is_ready:
                raise ConfigurationError(
                    "Real network infrastructure is NOT CONFIGURED. "
                    "Cannot establish physical multi-hop chain without real VPN endpoints and credentials. "
                    "Run 'securechain doctor' for system readiness, or run with '--mode simulation' to run in the virtual mesh."
                )

        hops = hop_count or self.config.chain.default_hops
        if auto:
            hops = self.config.chain.default_hops

        logger.info(f"Starting SecureChain with {hops} hops (auto={auto}, mode={self.active_mode})...")

        # 1. INITIALIZING
        self.sm.transition(State.INITIALIZING, f"Pre-flight initialization ({self.active_mode})")

        # Populate candidate paths if not present
        if not self.path_mgr.candidate_paths:
            path_a_configs = self.chain_mgr.build_candidate_configs(hops, chain_prefix="hopA")
            path_b_configs = self.chain_mgr.build_candidate_configs(hops, chain_prefix="hopB")
            self.path_mgr.add_candidate_path(CandidatePath("Path-A", path_a_configs, PathTelemetry(40.0, 0.0, 2.0)))
            self.path_mgr.add_candidate_path(CandidatePath("Path-B", path_b_configs, PathTelemetry(60.0, 0.0, 3.0)))

        # 2. BUILDING_CHAIN
        self.sm.transition(State.BUILDING_CHAIN, f"Preparing {hops}-hop chain pipeline")

        # 3. CONNECTING
        self.sm.transition(State.CONNECTING, "Establishing layered tunnels")
        chain = self.chain_mgr.connect_chain(hops)

        # Connect VPS layer if configured
        if self.vps:
            last_hop = chain.hops[-1]
            last_gw = last_hop.interface.gateway_ip if last_hop.interface else "10.8.N.1"
            last_if = last_hop.interface.name if last_hop.interface else "sim-last"
            self.vps.connect(last_gw, last_if)

        # 4. VERIFYING
        self.sm.transition(State.VERIFYING, "Verifying end-to-end chain integrity")
        verified = self.chain_mgr.verify_chain(chain)

        if not verified:
            logger.error("Verification checks failed! Engaging recovery...")
            return self.recovery.handle_failure("Initial chain verification failed")

        # 5. PROTECTED
        self.sm.transition(State.PROTECTED, "Chain verified; outbound traffic protected")
        self._save_state(chain)
        return True

    def stop(self) -> bool:
        """Gracefully stop SecureChain and restore system network state."""
        logger.info("Stopping SecureChain orchestrator...")
        self.sm.transition(State.SHUTTING_DOWN, "Graceful stop requested")

        if self.vps:
            self.vps.cleanup()

        self.chain_mgr.teardown_chain()
        self.sm.transition(State.DISCONNECTED, "Network state cleanly restored")
        self.sm.transition(State.OFFLINE, "System idle")

        if self.state_file.exists():
            try:
                self.state_file.unlink()
            except OSError:
                pass
        return True

    def health(self) -> SystemHealthReport:
        """Retrieve real-time health diagnostic report."""
        return self.monitor.probe()

    def _save_state(self, chain: Chain) -> None:
        try:
            state_data = {
                "state": self.sm.current_state.value,
                "mode": self.active_mode,
                "real_traffic_protected": (self.active_mode == "real" and self.sm.current_state == State.PROTECTED),
                "simulated_mesh_protected": (self.active_mode == "simulation" and self.sm.current_state == State.PROTECTED),
                "chain_id": chain.chain_id,
                "hop_count": chain.hop_count,
                "exit_interface": chain.exit_interface,
                "started_at": chain.created_at.isoformat(),
                "kill_switch": self.kill_switch.get_state().value,
                "candidate_paths": [
                    {
                        "path_id": p.path_id,
                        "latency_ms": p.telemetry.latency_ms,
                        "loss_pct": p.telemetry.packet_loss_pct,
                        "jitter_ms": p.telemetry.jitter_ms,
                        "score": p.score,
                        "is_healthy": p.telemetry.is_healthy,
                    }
                    for p in self.path_mgr.candidate_paths
                ],
            }
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state_data, f, indent=2)
        except Exception as exc:
            logger.warning(f"Failed to persist state: {exc}")

    def load_persisted_state(self) -> Optional[Dict[str, Any]]:
        if not self.state_file.is_file():
            return None
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
