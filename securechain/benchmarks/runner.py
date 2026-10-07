"""Performance Benchmarking Suite for SecureChain."""

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List
import psutil

from securechain.core.chain_manager import MultiHopChainManager
from securechain.core.path_manager import AdaptivePathManager
from securechain.core.recovery_engine import RecoveryEngine
from securechain.core.state_machine import State, StateMachine
from securechain.monitoring.monitor import HealthMonitor
from securechain.networking.dns.manager import VirtualDnsManager
from securechain.networking.firewall.kill_switch import VirtualKillSwitch
from securechain.networking.ipv6.controller import VirtualIpv6Controller
from securechain.networking.routing.virtual_routing import VirtualRoutingController
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.benchmarks")


@dataclass
class HopBenchmarkMetric:
    hop_count: int
    chain_establishment_ms: float
    verification_time_ms: float
    health_check_overhead_ms: float
    path_evaluation_overhead_ms: float
    recovery_time_ms: float
    memory_rss_mb: float
    cpu_percent: float


class BenchmarkRunner:
    """Measures startup, multi-hop establishment, verification, telemetry, and recovery overhead."""

    def run_benchmark(self, hop_counts: List[int] = [2, 3, 5, 10]) -> List[HopBenchmarkMetric]:
        process = psutil.Process(os.getpid())
        results: List[HopBenchmarkMetric] = []

        for hops in hop_counts:
            routing = VirtualRoutingController()
            kill_switch = VirtualKillSwitch()
            dns = VirtualDnsManager()
            ipv6 = VirtualIpv6Controller()
            sm = StateMachine()

            chain_mgr = MultiHopChainManager(routing, kill_switch, dns, ipv6)
            path_mgr = AdaptivePathManager()
            recovery = RecoveryEngine(sm, chain_mgr, path_mgr, routing, kill_switch, dns, ipv6)
            monitor = HealthMonitor(chain_mgr, routing, kill_switch, dns, ipv6)

            # 1. Measure Chain Establishment Time
            t0 = time.perf_counter()
            sm.transition(State.INITIALIZING)
            sm.transition(State.BUILDING_CHAIN)
            sm.transition(State.CONNECTING)
            chain = chain_mgr.connect_chain(hops)
            sm.transition(State.VERIFYING)
            sm.transition(State.PROTECTED)
            est_ms = (time.perf_counter() - t0) * 1000.0

            # 2. Measure Route & Chain Verification Time
            t0 = time.perf_counter()
            verified = chain_mgr.verify_chain(chain)
            ver_ms = (time.perf_counter() - t0) * 1000.0

            # 3. Measure Health Check Overhead
            t0 = time.perf_counter()
            report = monitor.probe()
            health_ms = (time.perf_counter() - t0) * 1000.0

            # 4. Measure Path Evaluation Overhead
            t0 = time.perf_counter()
            alt_configs = chain_mgr.build_candidate_configs(hops, chain_prefix="bench")
            from securechain.core.path_manager import CandidatePath
            from securechain.core.scoring import PathTelemetry
            path_mgr.add_candidate_path(CandidatePath("cand-1", alt_configs, PathTelemetry(40.0, 0.0, 2.0)))
            path_mgr.add_candidate_path(CandidatePath("cand-2", alt_configs, PathTelemetry(55.0, 0.0, 3.0)))
            path_mgr.evaluate_and_select()
            path_eval_ms = (time.perf_counter() - t0) * 1000.0

            # 5. Measure Recovery Time (inject middle hop failure)
            chain.hops[hops // 2].provider.disconnect()
            t0 = time.perf_counter()
            recovered = recovery.handle_failure("Benchmark Injected Link Loss")
            rec_ms = (time.perf_counter() - t0) * 1000.0

            # Measure Resource Utilization
            mem_mb = process.memory_info().rss / (1024 * 1024)
            cpu_pct = process.cpu_percent(interval=None)

            chain_mgr.teardown_chain()

            results.append(
                HopBenchmarkMetric(
                    hop_count=hops,
                    chain_establishment_ms=round(est_ms, 2),
                    verification_time_ms=round(ver_ms, 2),
                    health_check_overhead_ms=round(health_ms, 2),
                    path_evaluation_overhead_ms=round(path_eval_ms, 2),
                    recovery_time_ms=round(rec_ms, 2),
                    memory_rss_mb=round(mem_mb, 2),
                    cpu_percent=round(cpu_pct, 2),
                )
            )

        return results

    def save_and_print_results(self, results: List[HopBenchmarkMetric], output_path: Optional[Path] = None) -> None:
        print("\n" + "=" * 80)
        print("SecureChain Performance Benchmark Results")
        print("=" * 80)
        print(f"{'Hops':<6} {'Establish (ms)':<16} {'Verify (ms)':<14} {'Health (ms)':<14} {'Path Eval (ms)':<16} {'Recovery (ms)':<15} {'RAM (MB)':<10}")
        print("-" * 80)
        for r in results:
            print(f"{r.hop_count:<6} {r.chain_establishment_ms:<16} {r.verification_time_ms:<14} {r.health_check_overhead_ms:<14} {r.path_evaluation_overhead_ms:<16} {r.recovery_time_ms:<15} {r.memory_rss_mb:<10}")
        print("=" * 80 + "\n")

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump([asdict(r) for r in results], f, indent=2)


if __name__ == "__main__":
    runner = BenchmarkRunner()
    metrics = runner.run_benchmark([2, 3, 5, 10])
    runner.save_and_print_results(metrics, Path("artifacts/performance/p15_benchmarks.json"))
