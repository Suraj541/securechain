"""Metrics data models for Health Monitoring."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


class ComponentStatus(str, Enum):
    """Health status for individual system components."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    RECOVERING = "RECOVERING"


@dataclass
class ComponentHealth:
    """Telemetry report for an individual component."""

    name: str
    status: ComponentStatus
    details: str
    latency_ms: Optional[float] = None
    packet_loss_pct: Optional[float] = None
    jitter_ms: Optional[float] = None
    last_checked: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SystemHealthReport:
    """Comprehensive system-wide health evaluation."""

    overall_status: ComponentStatus
    components: List[ComponentHealth]
    routing_check: str   # "PASS" | "FAIL"
    dns_check: str       # "PASS" | "FAIL"
    ipv6_check: str      # "PASS" | "FAIL"
    kill_switch_state: str  # "ENGAGED" | "FILTERED_PASS" | "DISABLED"
    aggregate_latency_ms: float = 0.0
    aggregate_loss_pct: float = 0.0
    aggregate_jitter_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
