"""Unit tests for path scoring algorithm across 20 deterministic scenarios (P9)."""

import pytest
from securechain.configuration.schema import PathWeightsConfig
from securechain.core.scoring import PathTelemetry, calculate_path_score


def test_twenty_deterministic_scoring_scenarios():
    """P9 requirement: 20 path-selection scenarios with 20/20 expected decisions."""
    weights = PathWeightsConfig(latency=0.35, loss=0.30, jitter=0.15, failure_rate=0.20)

    scenarios = [
        # 1. Pure latency difference, zero loss/jitter
        (PathTelemetry(50, 0, 2), PathTelemetry(150, 0, 2), "PATH_A_BETTER"),
        # 2. Lower ping vs zero loss (Path A has 60ms but 5% loss and 40ms jitter; Path B has 70ms with 0.1% loss and 4ms jitter) -> Path B must win
        (PathTelemetry(60, 5.0, 40.0), PathTelemetry(70, 0.1, 4.0), "PATH_B_BETTER"),
        # 3. High packet loss vs low packet loss
        (PathTelemetry(40, 10.0, 5), PathTelemetry(40, 0.5, 5), "PATH_B_BETTER"),
        # 4. Severe jitter penalty
        (PathTelemetry(80, 0, 80), PathTelemetry(80, 0, 5), "PATH_B_BETTER"),
        # 5. Recent failure rate penalty
        (PathTelemetry(50, 0, 2, recent_failure_rate=0.4), PathTelemetry(60, 0, 2, recent_failure_rate=0.0), "PATH_B_BETTER"),
        # 6. Dead path vs alive path
        (PathTelemetry(50, 0, 2, is_healthy=False), PathTelemetry(200, 2.0, 15.0, is_healthy=True), "PATH_B_BETTER"),
        # 7. Equal nominal paths
        (PathTelemetry(50, 0, 5), PathTelemetry(50, 0, 5), "EQUAL"),
        # 8. 100ms with 0% loss vs 90ms with 2% loss
        (PathTelemetry(100, 0.0, 2), PathTelemetry(90, 2.0, 2), "PATH_A_BETTER"),
        # 9. 200ms vs 300ms
        (PathTelemetry(200, 0, 10), PathTelemetry(300, 0, 10), "PATH_A_BETTER"),
        # 10. 1% loss vs 0% loss
        (PathTelemetry(45, 1.0, 3), PathTelemetry(45, 0.0, 3), "PATH_B_BETTER"),
        # 11. 30ms latency advantage outweighed by 20% failure history
        (PathTelemetry(70, 0, 2, recent_failure_rate=0.3), PathTelemetry(100, 0, 2, recent_failure_rate=0.0), "PATH_B_BETTER"),
        # 12. Extremely high latency (500ms) capped normalization
        (PathTelemetry(600, 0, 2), PathTelemetry(400, 0, 2), "PATH_B_BETTER"),
        # 13. Jitter 50ms vs 5ms
        (PathTelemetry(30, 0, 50), PathTelemetry(35, 0, 5), "PATH_B_BETTER"),
        # 14. 50ms with 0.5% loss vs 65ms with 0% loss
        (PathTelemetry(50, 0.5, 3), PathTelemetry(65, 0.0, 3), "PATH_A_BETTER"),
        # 15. Near identical paths within 1ms
        (PathTelemetry(41, 0, 1), PathTelemetry(40, 0, 1), "PATH_B_BETTER"),
        # 16. Dead path A and Dead path B
        (PathTelemetry(50, 0, 0, is_healthy=False), PathTelemetry(100, 0, 0, is_healthy=False), "EQUAL"),
        # 17. 15% loss vs 1% loss
        (PathTelemetry(60, 15.0, 10), PathTelemetry(80, 1.0, 10), "PATH_B_BETTER"),
        # 18. Jitter 2ms vs 30ms
        (PathTelemetry(110, 0, 2), PathTelemetry(110, 0, 30), "PATH_A_BETTER"),
        # 19. Both high latency, low jitter vs high jitter
        (PathTelemetry(250, 0, 5), PathTelemetry(250, 0, 45), "PATH_A_BETTER"),
        # 20. Comprehensive mixed telemetry
        (PathTelemetry(120, 0.1, 5, recent_failure_rate=0.05), PathTelemetry(70, 0.2, 6, recent_failure_rate=0.01), "PATH_B_BETTER"),
    ]

    for idx, (tel_a, tel_b, expected_verdict) in enumerate(scenarios, start=1):
        score_a = calculate_path_score(tel_a, weights)
        score_b = calculate_path_score(tel_b, weights)

        if expected_verdict == "PATH_A_BETTER":
            assert score_a < score_b, f"Scenario {idx} failed: Expected Path A better, got score_a={score_a}, score_b={score_b}"
        elif expected_verdict == "PATH_B_BETTER":
            assert score_b < score_a, f"Scenario {idx} failed: Expected Path B better, got score_a={score_a}, score_b={score_b}"
        elif expected_verdict == "EQUAL":
            assert abs(score_a - score_b) < 0.05, f"Scenario {idx} failed: Expected equal, got score_a={score_a}, score_b={score_b}"
