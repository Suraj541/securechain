"""Optional Traffic Shaping and Padding Module for SecureChain.

DISCLAIMER:
Traffic shaping, packet padding, and timing jitter reduce observable packet-size
clustering and micro-burst signatures. However, they CANNOT and DO NOT defeat
global passive adversaries executing statistical flow or timing correlation across
entry and exit links.
"""

import math
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from securechain.configuration.schema import TrafficShapingConfig
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.security.traffic_shaping")


class TrafficShapingMode(str, Enum):
    """Preset modes for traffic shaping."""

    DISABLED = "disabled"
    LOW = "low"
    BALANCED = "balanced"
    HIGH = "high"


class PaddingStrategy(str, Enum):
    """Packet size padding strategies."""

    NONE = "none"
    BUCKET = "bucket"
    ADAPTIVE = "adaptive"
    FIXED_MTU = "fixed_mtu"


@dataclass
class TrafficShapingMetrics:
    """Measurable telemetry counters for traffic shaping operations."""

    packets_processed: int = 0
    packets_padded: int = 0
    bytes_added: int = 0
    total_jitter_delay_ms: float = 0.0
    batch_windows_evaluated: int = 0


class TrafficShaper:
    """Implements optional packet-size padding, timing jitter, and batching."""

    # Discrete bucket quantization boundaries (bytes)
    BUCKET_SIZES: List[int] = [128, 256, 512, 1024, 1420]

    def __init__(self, config: Optional[TrafficShapingConfig] = None) -> None:
        self.config = config or TrafficShapingConfig()
        self.metrics = TrafficShapingMetrics()
        self._rng = random.Random()

    @property
    def is_enabled(self) -> bool:
        return self.config.enabled and self.config.mode != "disabled"

    def pad_packet_size(self, original_size: int, target_mtu: int = 1420) -> int:
        """Calculate the padded packet size according to configured strategy.

        Returns the effective padded packet length (bytes).
        """
        self.metrics.packets_processed += 1

        if not self.is_enabled or self.config.padding == "none":
            return original_size

        padded_size = original_size
        strategy = self.config.padding

        if strategy == "fixed_mtu":
            padded_size = min(target_mtu, max(original_size, target_mtu))
        elif strategy == "bucket":
            # Quantize to nearest bucket size that accommodates original_size
            for b in self.BUCKET_SIZES:
                if b >= original_size:
                    padded_size = min(b, target_mtu)
                    break
            else:
                padded_size = min(original_size, target_mtu)
        elif strategy == "adaptive":
            # Round up to nearest power-of-two or bucket
            if original_size <= 256:
                padded_size = 256
            elif original_size <= 512:
                padded_size = 512
            elif original_size <= 1024:
                padded_size = 1024
            else:
                padded_size = min(target_mtu, 1420)

        # Enforce MTU ceiling
        padded_size = min(padded_size, target_mtu)

        delta = max(0, padded_size - original_size)
        if delta > 0:
            self.metrics.packets_padded += 1
            self.metrics.bytes_added += delta

        return padded_size

    def calculate_jitter_delay_ms(self, seed: Optional[int] = None) -> float:
        """Calculate bounded pseudo-random timing delay jitter in milliseconds."""
        if not self.is_enabled or self.config.jitter_ms <= 0.0:
            return 0.0

        if seed is not None:
            rng = random.Random(seed)
        else:
            rng = self._rng

        # Scale jitter based on mode
        scale_factor = 1.0
        if self.config.mode == "low":
            scale_factor = 0.5
        elif self.config.mode == "balanced":
            scale_factor = 1.0
        elif self.config.mode == "high":
            scale_factor = 1.5

        max_jitter = self.config.jitter_ms * scale_factor
        delay = rng.uniform(0.0, max_jitter)
        self.metrics.total_jitter_delay_ms += delay
        return round(delay, 2)

    def get_batching_interval_ms(self) -> float:
        """Get the configured batching window in milliseconds."""
        if not self.is_enabled or self.config.batching_ms <= 0.0:
            return 0.0
        self.metrics.batch_windows_evaluated += 1
        return self.config.batching_ms

    def get_diagnostics(self) -> Dict[str, object]:
        """Return diagnostic metrics and operational configuration."""
        return {
            "enabled": self.is_enabled,
            "mode": self.config.mode,
            "padding_strategy": self.config.padding,
            "configured_jitter_ms": self.config.jitter_ms,
            "configured_batching_ms": self.config.batching_ms,
            "packets_processed": self.metrics.packets_processed,
            "packets_padded": self.metrics.packets_padded,
            "bytes_added": self.metrics.bytes_added,
            "total_jitter_delay_ms": round(self.metrics.total_jitter_delay_ms, 2),
            "disclaimer": "Does not defeat global passive timing correlation",
        }
