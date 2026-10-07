"""Unit tests for Traffic Shaping, Packet Padding, and Jitter Module."""

import pytest
from securechain.configuration.schema import TrafficShapingConfig
from securechain.security.traffic_shaping import (
    PaddingStrategy,
    TrafficShaper,
    TrafficShapingMode,
)


def test_traffic_shaping_disabled_by_default():
    """Verify traffic shaping is disabled by default and passes packets untouched."""
    shaper = TrafficShaper()
    assert shaper.is_enabled is False

    # Packets pass with original length
    assert shaper.pad_packet_size(150) == 150
    assert shaper.pad_packet_size(1000) == 1000
    assert shaper.calculate_jitter_delay_ms() == 0.0
    assert shaper.get_batching_interval_ms() == 0.0

    diag = shaper.get_diagnostics()
    assert diag["enabled"] is False
    assert "Does not defeat global passive timing correlation" in str(diag["disclaimer"])


def test_traffic_shaping_bucket_padding():
    """Verify discrete bucket quantization strategy."""
    cfg = TrafficShapingConfig(
        enabled=True,
        mode="balanced",
        padding="bucket",
        jitter_ms=10.0,
        batching_ms=20.0,
    )
    shaper = TrafficShaper(cfg)
    assert shaper.is_enabled is True

    # BUCKET_SIZES: [128, 256, 512, 1024, 1420]
    assert shaper.pad_packet_size(70) == 128
    assert shaper.pad_packet_size(128) == 128
    assert shaper.pad_packet_size(200) == 256
    assert shaper.pad_packet_size(500) == 512
    assert shaper.pad_packet_size(800) == 1024
    assert shaper.pad_packet_size(1200) == 1420

    # Never exceeds target MTU
    assert shaper.pad_packet_size(1300, target_mtu=1350) == 1350

    diag = shaper.get_diagnostics()
    assert diag["packets_processed"] == 7
    assert diag["packets_padded"] > 0
    assert diag["bytes_added"] > 0


def test_traffic_shaping_fixed_mtu_padding():
    """Verify fixed_mtu strategy pads all packets directly to target MTU."""
    cfg = TrafficShapingConfig(
        enabled=True,
        mode="high",
        padding="fixed_mtu",
    )
    shaper = TrafficShaper(cfg)
    assert shaper.pad_packet_size(100, target_mtu=1400) == 1400
    assert shaper.pad_packet_size(1300, target_mtu=1400) == 1400


def test_traffic_shaping_timing_jitter_bounds():
    """Verify timing jitter produces bounded pseudo-random delays based on mode."""
    cfg = TrafficShapingConfig(
        enabled=True,
        mode="balanced",
        padding="adaptive",
        jitter_ms=15.0,
    )
    shaper = TrafficShaper(cfg)

    # 10 jitter samples must all be within [0.0, 15.0]
    for i in range(10):
        jitter = shaper.calculate_jitter_delay_ms(seed=i)
        assert 0.0 <= jitter <= 15.0

    diag = shaper.get_diagnostics()
    assert diag["total_jitter_delay_ms"] > 0.0


def test_traffic_shaping_modes_scaling():
    """Verify jitter scaling factors across low, balanced, and high modes."""
    shaper_low = TrafficShaper(TrafficShapingConfig(enabled=True, mode="low", jitter_ms=10.0))
    shaper_high = TrafficShaper(TrafficShapingConfig(enabled=True, mode="high", jitter_ms=10.0))

    # Low mode scales jitter by 0.5 (max 5.0)
    for i in range(10):
        assert shaper_low.calculate_jitter_delay_ms(seed=i) <= 5.0

    # High mode scales jitter by 1.5 (max 15.0)
    for i in range(10):
        assert shaper_high.calculate_jitter_delay_ms(seed=i) <= 15.0
