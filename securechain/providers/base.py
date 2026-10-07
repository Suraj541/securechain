"""Abstract Base Classes and models for VPN providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, SecretStr


class TunnelState(str, Enum):
    """Lifecycle states of an individual VPN tunnel."""

    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    VERIFYING = "VERIFYING"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


@dataclass
class InterfaceInfo:
    """Network interface details exposed by a tunnel."""

    name: str
    ip_address: str
    gateway_ip: str
    subnet_mask: str = "255.255.255.0"
    dns_servers: List[str] = field(default_factory=list)
    mtu: int = 1420


@dataclass
class HealthMetric:
    """Telemetry sample for an individual tunnel."""

    latency_ms: float
    packet_loss_pct: float
    jitter_ms: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_reachable: bool = True


@dataclass
class TunnelConfig:
    """Configuration required to instantiate a VPN tunnel."""

    tunnel_id: str
    provider_type: str
    endpoint_ip: str
    endpoint_port: int
    public_key: Optional[str] = None
    private_key: Optional[SecretStr] = None
    preshared_key: Optional[SecretStr] = None
    assigned_ip: str = "10.0.0.2"
    gateway_ip: str = "10.0.0.1"
    dns_server: str = "10.0.0.1"
    mtu: int = 1420
    custom_params: Dict[str, str] = field(default_factory=dict)


@dataclass
class TunnelStatus:
    """Current runtime status of a tunnel."""

    tunnel_id: str
    state: TunnelState
    interface: Optional[InterfaceInfo] = None
    uptime_seconds: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    last_error: Optional[str] = None


class VPNProvider(ABC):
    """Abstract interface defining the contract for all VPN providers."""

    @abstractmethod
    def connect(self, config: TunnelConfig) -> TunnelStatus:
        """Connect the VPN tunnel using the provided configuration."""

    @abstractmethod
    def disconnect(self) -> TunnelStatus:
        """Gracefully disconnect the VPN tunnel."""

    @abstractmethod
    def status(self) -> TunnelStatus:
        """Retrieve current tunnel operational status."""

    @abstractmethod
    def health_check(self) -> HealthMetric:
        """Execute telemetry probe measuring latency, jitter, and packet loss."""

    @abstractmethod
    def get_interface(self) -> InterfaceInfo:
        """Retrieve the local virtual interface assigned to this tunnel."""

    @abstractmethod
    def cleanup(self) -> None:
        """Forcefully purge interfaces, temporary configs, and route references."""
