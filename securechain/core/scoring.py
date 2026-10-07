"""Path Quality Scoring algorithm and telemetry normalization for SecureChain."""

from dataclasses import dataclass
from typing import Optional
from securechain.configuration.schema import PathWeightsConfig


@dataclass
class PathTelemetry:
    """Network metrics observed for a candidate path."""

    latency_ms: float
    packet_loss_pct: float
    jitter_ms: float
    recent_failure_rate: float = 0.0  # 0.0 (no recent drops) to 1.0 (continuous failures)
    is_healthy: bool = True


# Normalization baselines:
# Maximum reasonable bounds mapped to 1.0
MAX_LATENCY_NORM_MS = 500.0  # 500ms or higher is normalized to 1.0
MAX_JITTER_NORM_MS = 100.0   # 100ms jitter is normalized to 1.0
MAX_LOSS_NORM_PCT = 20.0     # 20% packet loss is considered fully degraded (1.0)


def calculate_path_score(
    telemetry: PathTelemetry,
    weights: Optional[PathWeightsConfig] = None,
) -> float:
    """Calculate normalized path quality score.

    Score convention: Lower score is a better, higher-quality path.
    A completely dead or unhealthy path returns a score >= 1.0.

    Formula:
      Score = w_lat * norm_lat + w_loss * norm_loss + w_jit * norm_jit + w_fail * fail_rate
    """
    if not telemetry.is_healthy:
        return 1.5 + telemetry.recent_failure_rate

    if weights is None:
        weights = PathWeightsConfig()

    # Normalization into [0.0, 1.0]
    norm_lat = min(1.0, max(0.0, telemetry.latency_ms / MAX_LATENCY_NORM_MS))
    norm_loss = min(1.0, max(0.0, telemetry.packet_loss_pct / MAX_LOSS_NORM_PCT))
    norm_jit = min(1.0, max(0.0, telemetry.jitter_ms / MAX_JITTER_NORM_MS))
    fail_rate = min(1.0, max(0.0, telemetry.recent_failure_rate))

    score = (
        (weights.latency * norm_lat)
        + (weights.loss * norm_loss)
        + (weights.jitter * norm_jit)
        + (weights.failure_rate * fail_rate)
    )

    return round(score, 4)
