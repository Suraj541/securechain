"""Adaptive Path Manager with hysteresis and flapping dampening for SecureChain."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
import time

from securechain.configuration.schema import PathSelectionConfig, PathWeightsConfig
from securechain.core.scoring import PathTelemetry, calculate_path_score
from securechain.providers.base import TunnelConfig
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.core.path_manager")


@dataclass
class CandidatePath:
    """Represents a candidate multi-hop network path."""

    path_id: str
    hop_configs: List[TunnelConfig]
    telemetry: PathTelemetry
    score: float = 1.0
    healthy_since: float = 0.0  # Unix timestamp when path entered continuous healthy state
    diagnostic_reason: Optional[str] = None

    @property
    def supports_ipv6(self) -> bool:
        """True if every hop in the path explicitly supports IPv6."""
        return all(c.supports_ipv6 for c in self.hop_configs) if self.hop_configs else False

    @property
    def supports_ipv4(self) -> bool:
        """True if every hop in the path supports IPv4."""
        return all(c.supports_ipv4 for c in self.hop_configs) if self.hop_configs else True

    @property
    def min_mtu(self) -> int:
        """Minimum MTU among all hops in the path."""
        return min(c.mtu for c in self.hop_configs) if self.hop_configs else 1420


class AdaptivePathManager:
    """Evaluates candidate paths and selects optimal routes with hysteresis."""

    def __init__(
        self,
        config: Optional[PathSelectionConfig] = None,
        candidate_paths: Optional[List[CandidatePath]] = None,
    ) -> None:
        self.config = config or PathSelectionConfig()
        self._paths: Dict[str, CandidatePath] = {}
        self._active_path_id: Optional[str] = None
        self._last_switch_time: float = 0.0
        self._switch_history: List[str] = []

        if candidate_paths:
            for p in candidate_paths:
                self.add_candidate_path(p)

    @property
    def active_path_id(self) -> Optional[str]:
        return self._active_path_id

    @property
    def candidate_paths(self) -> List[CandidatePath]:
        return list(self._paths.values())

    def add_candidate_path(self, path: CandidatePath) -> None:
        path.score = calculate_path_score(path.telemetry, self.config.weights)
        self._paths[path.path_id] = path

    def set_active_path(self, path_id: str, current_time: Optional[float] = None) -> None:
        if path_id not in self._paths:
            raise ValueError(f"Path '{path_id}' not found in candidate paths")
        now = current_time if current_time is not None else time.time()
        self._active_path_id = path_id
        self._last_switch_time = now
        self._switch_history.append(f"{now}: activated {path_id}")
        logger.info(f"Active path set to '{path_id}'")

    def update_telemetry(self, path_id: str, telemetry: PathTelemetry, current_time: Optional[float] = None) -> None:
        if path_id not in self._paths:
            return
        now = current_time if current_time is not None else time.time()
        p = self._paths[path_id]

        # Track stability window
        if telemetry.is_healthy:
            if not p.telemetry.is_healthy or p.healthy_since == 0.0:
                p.healthy_since = now
        else:
            p.healthy_since = 0.0

        p.telemetry = telemetry
        p.score = calculate_path_score(telemetry, self.config.weights)

    def evaluate_and_select(self, current_time: Optional[float] = None) -> Optional[CandidatePath]:
        """Evaluate candidate paths and decide whether to switch based on hysteresis rules."""
        now = current_time if current_time is not None else time.time()
        if not self._paths:
            return None

        # Filter candidate pool based on policy constraints (e.g., IPv6 requirement)
        pool = list(self._paths.values())
        if self.config.require_ipv6:
            ipv6_pool = [p for p in pool if p.supports_ipv6]
            if not ipv6_pool:
                logger.error(
                    "Path selection failed: require_ipv6 is True, but no candidate path has end-to-end IPv6 support. Failing closed."
                )
                return None
            pool = ipv6_pool

        # If no active path, pick best healthy candidate from pool
        if not self._active_path_id or self._active_path_id not in self._paths:
            healthy = [p for p in pool if p.telemetry.is_healthy]
            if not healthy:
                return None
            best = min(healthy, key=lambda p: p.score)
            self.set_active_path(best.path_id, now)
            return best

        active = self._paths[self._active_path_id]

        # If active path violates policy constraint (e.g. requires IPv6 but active lacks IPv6)
        if self.config.require_ipv6 and not active.supports_ipv6:
            logger.warning(f"Active path '{active.path_id}' lacks IPv6 while require_ipv6=True; triggering switch.")
            healthy_ipv6 = [p for p in pool if p.telemetry.is_healthy and p.path_id != active.path_id]
            if healthy_ipv6:
                best = min(healthy_ipv6, key=lambda p: p.score)
                self.set_active_path(best.path_id, now)
                return best
            return None

        # 1. EMERGENCY SWITCH: If active path is UNHEALTHY, switch immediately to best healthy candidate
        if not active.telemetry.is_healthy:
            healthy_candidates = [p for p in pool if p.path_id != active.path_id and p.telemetry.is_healthy]
            if healthy_candidates:
                best = min(healthy_candidates, key=lambda p: p.score)
                logger.warning(
                    f"EMERGENCY PATH SWITCH: Active path '{active.path_id}' is UNHEALTHY! Switching immediately to '{best.path_id}'"
                )
                self.set_active_path(best.path_id, now)
                return best
            return None

        # 2. HYSTERESIS CHECK: Active path is healthy, check stability and thresholds
        # Rule A: Minimum switch interval must have elapsed
        time_since_last_switch = now - self._last_switch_time
        if time_since_last_switch < self.config.minimum_switch_interval_seconds:
            logger.debug(
                f"Path switch suppressed: minimum switch interval not elapsed ({time_since_last_switch:.1f}s < {self.config.minimum_switch_interval_seconds}s)"
            )
            return None

        # Find best healthy candidate
        eligible_candidates: List[CandidatePath] = []
        for p in pool:
            if p.path_id == active.path_id:
                continue
            if not p.telemetry.is_healthy:
                continue

            # Rule B: Candidate must have been stable for at least stability_window_seconds
            stability_duration = now - p.healthy_since
            if stability_duration < self.config.stability_window_seconds:
                logger.debug(
                    f"Candidate '{p.path_id}' not stable long enough ({stability_duration:.1f}s < {self.config.stability_window_seconds}s)"
                )
                continue

            # Rule C: Candidate score must improve over active score by improvement_threshold_percent
            required_improvement = active.score * (self.config.improvement_threshold_percent / 100.0)
            actual_improvement = active.score - p.score
            if actual_improvement >= required_improvement:
                eligible_candidates.append(p)

        if not eligible_candidates:
            return None

        # Select candidate with lowest score
        best_candidate = min(eligible_candidates, key=lambda p: p.score)
        logger.info(
            f"Switching active path from '{active.path_id}' (score={active.score:.4f}) to '{best_candidate.path_id}' (score={best_candidate.score:.4f})"
        )
        self.set_active_path(best_candidate.path_id, now)
        return best_candidate
