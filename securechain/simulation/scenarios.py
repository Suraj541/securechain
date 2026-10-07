"""Simulation scenarios for SecureChain orchestrator."""

import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from pydantic import SecretStr

from securechain.configuration.schema import PathSelectionConfig, RecoveryConfig
from securechain.core.chain_manager import MultiHopChainManager
from securechain.core.path_manager import AdaptivePathManager, CandidatePath
from securechain.core.recovery_engine import RecoveryEngine
from securechain.core.scoring import PathTelemetry
from securechain.core.state_machine import State, StateMachine
from securechain.monitoring.metrics import ComponentStatus
from securechain.monitoring.monitor import HealthMonitor
from securechain.networking.dns.manager import VirtualDnsManager
from securechain.networking.firewall.kill_switch import KillSwitchState, VirtualKillSwitch
from securechain.networking.ipv6.controller import VirtualIpv6Controller
from securechain.networking.routing.virtual_routing import VirtualRoutingController
from securechain.networking.vps.termination import SimulatedVpsTerminationLayer, VpsConfig
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.simulation")


@dataclass
class SimulationResult:
    """Outcome of a simulated scenario execution."""

    scenario: str
    seed: int
    success: bool
    details: str
    execution_time_ms: float


class SimulationHarness:
    """Executes deterministic multi-hop scenarios exercising core orchestration logic."""

    SUPPORTED_SCENARIOS = [
        "healthy",
        "high-latency",
        "packet-loss",
        "high-jitter",
        "vpn-failure",
        "multiple-vpn-failure",
        "vps-failure",
        "dns-leak",
        "route-failure",
        "flapping",
    ]

    def run_scenario(self, scenario_name: str, seed: int = 42) -> SimulationResult:
        if scenario_name not in self.SUPPORTED_SCENARIOS:
            raise ValueError(f"Unknown scenario '{scenario_name}'. Supported: {self.SUPPORTED_SCENARIOS}")

        rng = random.Random(seed)
        start_time = time.perf_counter()

        routing = VirtualRoutingController()
        kill_switch = VirtualKillSwitch()
        dns = VirtualDnsManager()
        ipv6 = VirtualIpv6Controller()
        sm = StateMachine()

        chain_mgr = MultiHopChainManager(routing, kill_switch, dns, ipv6)
        path_mgr = AdaptivePathManager()
        recovery = RecoveryEngine(
            sm, chain_mgr, path_mgr, routing, kill_switch, dns, ipv6,
            config=RecoveryConfig(max_attempts=2, backoff_seconds=0.5, path_reselection=True),
        )

        try:
            # Lifecycle initialization
            sm.transition(State.INITIALIZING)
            sm.transition(State.BUILDING_CHAIN)
            sm.transition(State.CONNECTING)

            # Build 3-hop chain
            chain = chain_mgr.connect_chain(3)
            sm.transition(State.VERIFYING)
            sm.transition(State.PROTECTED)

            # Setup monitor
            monitor = HealthMonitor(chain_mgr, routing, kill_switch, dns, ipv6)

            success = False
            details = ""

            if scenario_name == "healthy":
                report = monitor.probe()
                success = (report.overall_status == ComponentStatus.HEALTHY)
                details = f"All 3 hops healthy, aggregate latency: {report.aggregate_latency_ms}ms"

            elif scenario_name == "high-latency":
                # Inject 350ms latency into Hop 1
                chain.hops[0].provider.inject_degradation(latency_ms=350.0, loss_pct=0.0, jitter_ms=2.0)
                report = monitor.probe()
                success = (report.overall_status == ComponentStatus.DEGRADED)
                details = f"High latency detected: overall status {report.overall_status.value}"

            elif scenario_name == "packet-loss":
                # Inject 15% packet loss into Hop 2
                chain.hops[1].provider.inject_degradation(latency_ms=25.0, loss_pct=15.0, jitter_ms=2.0)
                report = monitor.probe()
                success = (report.overall_status == ComponentStatus.DEGRADED)
                details = f"Packet loss detected: overall status {report.overall_status.value}"

            elif scenario_name == "high-jitter":
                # Inject 65ms jitter into Hop 3
                chain.hops[2].provider.inject_degradation(latency_ms=40.0, loss_pct=0.0, jitter_ms=65.0)
                report = monitor.probe()
                success = (report.aggregate_jitter_ms >= 65.0)
                details = f"High jitter detected: {report.aggregate_jitter_ms}ms"

            elif scenario_name == "vpn-failure":
                # Injected middle-hop failure -> recovery loop
                chain.hops[1].provider.disconnect()
                recovered = recovery.handle_failure("Middle-hop simulated carrier drop")
                success = recovered and (sm.current_state == State.PROTECTED)
                details = f"VPN failure contained and recovered successfully into {sm.current_state.value}"

            elif scenario_name == "multiple-vpn-failure":
                # Add healthy alternative path B
                alt_configs = chain_mgr.build_candidate_configs(3, chain_prefix="backup")
                path_b = CandidatePath("backup-path", alt_configs, PathTelemetry(28.0, 0.0, 1.5))
                path_mgr.add_candidate_path(path_b)

                # Permanently break active hops
                chain.hops[0].provider.simulate_failure_on_connect = True
                chain.hops[1].provider.simulate_failure_on_connect = True
                recovered = recovery.handle_failure("Multiple hop link loss")
                success = recovered and (sm.current_state == State.PROTECTED)
                details = f"Multiple-hop failure failed over to alternative backup path"

            elif scenario_name == "vps-failure":
                vps_cfg = VpsConfig(endpoint="vps.sim:51820", protocol="wireguard", auth_token=SecretStr("token"))
                vps = SimulatedVpsTerminationLayer(vps_cfg, routing, kill_switch)
                vps.connect(chain.hops[-1].interface.gateway_ip, chain.hops[-1].interface.name)
                vps_monitor = HealthMonitor(chain_mgr, routing, kill_switch, dns, ipv6, vps)

                # Inject VPS drop
                vps.inject_failure("VPS peer crash")
                report = vps_monitor.probe()
                # Must be detected as FAILED and kill switch must be locked
                success = (report.overall_status == ComponentStatus.FAILED) and (kill_switch.get_state() == KillSwitchState.ENGAGED)
                details = "VPS failure detected and traffic immediately contained"
                vps.cleanup()

            elif scenario_name == "dns-leak":
                dns.inject_dns_leak("192.168.1.1")
                report = monitor.probe()
                success = (report.dns_check == "FAIL") and (report.overall_status == ComponentStatus.FAILED)
                details = "Canary DNS leak caught by health monitor"

            elif scenario_name == "route-failure":
                # Inject rogue unauthorized route
                routing.inject_unauthorized_route("10.88.0.0/16", "192.168.1.1", "Ethernet0")
                # Remove active default split route to simulate hijacking
                routing.delete_route("0.0.0.0/1")
                report = monitor.probe()
                success = (report.routing_check == "FAIL")
                details = "Route corruption detected by routing integrity check"

            elif scenario_name == "flapping":
                p_cfg = PathSelectionConfig(minimum_switch_interval_seconds=60.0, improvement_threshold_percent=15.0)
                flapping_mgr = AdaptivePathManager(config=p_cfg)
                pa = CandidatePath("P-A", [], PathTelemetry(89.0, 0.0, 2.0))
                pb = CandidatePath("P-B", [], PathTelemetry(91.0, 0.0, 2.0))
                flapping_mgr.add_candidate_path(pa)
                flapping_mgr.add_candidate_path(pb)
                flapping_mgr.set_active_path("P-A", current_time=0.0)

                switches = 0
                for step in range(1, 13):
                    t = float(step * 5)
                    # Jitter noise between 89ms and 92ms
                    noise_a = 89.0 if step % 2 == 0 else 92.0
                    noise_b = 91.0 if step % 2 == 0 else 90.0
                    flapping_mgr.update_telemetry("P-A", PathTelemetry(noise_a, 0.0, 2.0), current_time=t)
                    flapping_mgr.update_telemetry("P-B", PathTelemetry(noise_b, 0.0, 2.0), current_time=t)
                    res = flapping_mgr.evaluate_and_select(current_time=t)
                    if res is not None and res.path_id != "P-A":
                        switches += 1
                success = (switches == 0)
                details = f"Simulated 60s noise: 0 route flaps (switches={switches})"

            # Safe cleanup
            chain_mgr.teardown_chain()

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return SimulationResult(
                scenario=scenario_name,
                seed=seed,
                success=success,
                details=details,
                execution_time_ms=round(elapsed_ms, 2),
            )

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            chain_mgr.teardown_chain()
            return SimulationResult(
                scenario=scenario_name,
                seed=seed,
                success=False,
                details=f"Exception during simulation: {exc}",
                execution_time_ms=round(elapsed_ms, 2),
            )
