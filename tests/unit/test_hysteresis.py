"""Unit tests for path hysteresis and flapping dampening (P9B)."""

import pytest
from securechain.configuration.schema import PathSelectionConfig
from securechain.core.path_manager import AdaptivePathManager, CandidatePath
from securechain.core.scoring import PathTelemetry


def test_flapping_dampening_sixty_second_simulation():
    """P9B requirement: 60-second simulation with minor latency noise produces 0 route flaps."""
    config = PathSelectionConfig(
        evaluation_interval_seconds=10.0,
        minimum_switch_interval_seconds=60.0,
        improvement_threshold_percent=15.0,
        stability_window_seconds=30.0,
    )

    path_a = CandidatePath(
        path_id="path-A",
        hop_configs=[],
        telemetry=PathTelemetry(89.0, 0.0, 3.0),
        healthy_since=0.0,
    )
    path_b = CandidatePath(
        path_id="path-B",
        hop_configs=[],
        telemetry=PathTelemetry(91.0, 0.0, 3.0),
        healthy_since=0.0,
    )

    mgr = AdaptivePathManager(config=config, candidate_paths=[path_a, path_b])
    mgr.set_active_path("path-A", current_time=0.0)

    # Simulate 60 seconds with minor latency noise (89-92ms vs 90-93ms)
    # Both paths are continuously healthy
    switches_occurred = 0

    for t in range(5, 65, 5):
        # Alternate small latency variations
        lat_a = 89.0 if (t // 5) % 2 == 0 else 92.0
        lat_b = 91.0 if (t // 5) % 2 == 0 else 90.0

        mgr.update_telemetry("path-A", PathTelemetry(lat_a, 0.0, 3.0), current_time=float(t))
        mgr.update_telemetry("path-B", PathTelemetry(lat_b, 0.0, 3.0), current_time=float(t))

        switched = mgr.evaluate_and_select(current_time=float(t))
        if switched is not None and switched.path_id != "path-A":
            switches_occurred += 1

    # Invariant: Minor latency variations must NOT trigger route flaps
    assert switches_occurred == 0
    assert mgr.active_path_id == "path-A"


def test_significant_sustained_improvement_triggers_switch():
    config = PathSelectionConfig(
        evaluation_interval_seconds=10.0,
        minimum_switch_interval_seconds=60.0,
        improvement_threshold_percent=15.0,
        stability_window_seconds=30.0,
    )

    path_a = CandidatePath("path-A", [], PathTelemetry(150.0, 0.0, 5.0), healthy_since=0.0)
    # Path B offers a massive 50ms latency (66% improvement)
    path_b = CandidatePath("path-B", [], PathTelemetry(50.0, 0.0, 2.0), healthy_since=0.0)

    mgr = AdaptivePathManager(config=config, candidate_paths=[path_a, path_b])
    mgr.set_active_path("path-A", current_time=0.0)

    # At t=20s (less than minimum switch interval of 60s and less than 30s stability): no switch
    mgr.update_telemetry("path-B", PathTelemetry(50.0, 0.0, 2.0), current_time=20.0)
    assert mgr.evaluate_and_select(current_time=20.0) is None

    # At t=65s: Path B has been stable for > 30s, and > 60s elapsed since last switch
    mgr.update_telemetry("path-B", PathTelemetry(50.0, 0.0, 2.0), current_time=65.0)
    switched = mgr.evaluate_and_select(current_time=65.0)

    assert switched is not None
    assert switched.path_id == "path-B"
    assert mgr.active_path_id == "path-B"


def test_unhealthy_active_path_triggers_emergency_switch():
    config = PathSelectionConfig(
        minimum_switch_interval_seconds=300.0,  # High switch interval
        stability_window_seconds=60.0,
    )

    path_a = CandidatePath("path-A", [], PathTelemetry(50.0, 0.0, 2.0), healthy_since=0.0)
    path_b = CandidatePath("path-B", [], PathTelemetry(80.0, 0.0, 3.0), healthy_since=0.0)

    mgr = AdaptivePathManager(config=config, candidate_paths=[path_a, path_b])
    mgr.set_active_path("path-A", current_time=0.0)

    # Path A suddenly dies at t=10s (only 10 seconds into 300s window)
    mgr.update_telemetry("path-A", PathTelemetry(999.0, 100.0, 99.0, is_healthy=False), current_time=10.0)

    # Invariant: Emergency switch must bypass min_interval and switch immediately!
    switched = mgr.evaluate_and_select(current_time=10.0)
    assert switched is not None
    assert switched.path_id == "path-B"
    assert mgr.active_path_id == "path-B"
