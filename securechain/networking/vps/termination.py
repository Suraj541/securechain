"""VPS Termination Layer for SecureChain."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import SecretStr

from securechain.core.exceptions import TunnelConnectionError, TunnelError
from securechain.networking.firewall.kill_switch import KillSwitch
from securechain.networking.routing.controller import RoutingController
from securechain.providers.base import HealthMetric, InterfaceInfo, TunnelState
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.networking.vps")


class VpsState(str, Enum):
    """Operational states of the VPS termination layer."""

    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


@dataclass
class VpsConfig:
    """Configuration for VPS termination node."""

    endpoint: str  # Host or IP e.g. "vps.securechain.org:51820"
    protocol: str  # "wireguard", "openvpn", "ssh_socks5"
    assigned_ip: str = "10.99.0.2"
    gateway_ip: str = "10.99.0.1"
    dns_server: str = "10.99.0.1"
    auth_token: Optional[SecretStr] = None


@dataclass
class VpsStatus:
    """Runtime status of the VPS termination layer."""

    state: VpsState
    endpoint: str
    protocol: str
    interface: Optional[InterfaceInfo] = None
    uptime_seconds: float = 0.0
    last_error: Optional[str] = None


class VpsTerminationLayer(ABC):
    """Abstract interface defining VPS termination operations."""

    @abstractmethod
    def connect(self, underlying_gateway: str, underlying_interface: str) -> VpsStatus:
        """Connect the VPS layer through the final VPN tunnel hop."""

    @abstractmethod
    def disconnect(self) -> VpsStatus:
        """Gracefully disconnect the VPS layer."""

    @abstractmethod
    def status(self) -> VpsStatus:
        """Retrieve current status of VPS node."""

    @abstractmethod
    def health_check(self) -> HealthMetric:
        """Probe VPS health and telemetry."""

    @abstractmethod
    def cleanup(self) -> None:
        """Clean up all VPS routes and interfaces."""


class SimulatedVpsTerminationLayer(VpsTerminationLayer):
    """High-fidelity simulated VPS termination layer for testing and simulation."""

    def __init__(
        self,
        config: VpsConfig,
        routing_controller: RoutingController,
        kill_switch: KillSwitch,
        base_latency_ms: float = 18.0,
    ) -> None:
        self.config = config
        self.routing = routing_controller
        self.kill_switch = kill_switch
        self.base_latency_ms = base_latency_ms

        self._state: VpsState = VpsState.DISCONNECTED
        self._interface: Optional[InterfaceInfo] = None
        self._last_error: Optional[str] = None
        self._failure_injected: bool = False

    def connect(self, underlying_gateway: str, underlying_interface: str) -> VpsStatus:
        logger.info(f"Connecting VPS layer '{self.config.endpoint}' via underlying gateway {underlying_gateway}...")
        self._state = VpsState.CONNECTING

        if self._failure_injected:
            self._state = VpsState.FAILED
            self._last_error = "Simulated VPS endpoint unreachable"
            logger.error(self._last_error)
            raise TunnelConnectionError(self._last_error)

        # 1. Route VPS endpoint strictly through underlying tunnel interface
        endpoint_host = self.config.endpoint.split(":")[0]
        # Use synthetic IP if hostname
        vps_ip = "198.51.200.50" if not endpoint_host.replace(".", "").isdigit() else endpoint_host
        self.routing.add_route(f"{vps_ip}/32", underlying_gateway, underlying_interface, metric=8)

        # 2. Establish VPS virtual exit interface
        self._interface = InterfaceInfo(
            name="vps-exit-01",
            ip_address=self.config.assigned_ip,
            gateway_ip=self.config.gateway_ip,
            dns_servers=[self.config.dns_server],
            mtu=1380,
        )

        # 3. Override split default routes via VPS
        self.routing.add_route("0.0.0.0/1", self.config.gateway_ip, "vps-exit-01", metric=3)
        self.routing.add_route("128.0.0.0/1", self.config.gateway_ip, "vps-exit-01", metric=3)

        # 4. Authorize VPS interface on Kill Switch
        self.kill_switch.set_active_exit_interface("vps-exit-01")

        self._state = VpsState.CONNECTED
        logger.info(f"VPS termination active on interface 'vps-exit-01' -> {self.config.endpoint}")
        return self.status()

    def disconnect(self) -> VpsStatus:
        if self._state == VpsState.DISCONNECTED:
            return self.status()

        logger.info("Disconnecting VPS termination layer...")
        self._state = VpsState.DISCONNECTED
        self._interface = None
        return self.status()

    def status(self) -> VpsStatus:
        return VpsStatus(
            state=self._state,
            endpoint=self.config.endpoint,
            protocol=self.config.protocol,
            interface=self._interface,
            last_error=self._last_error,
        )

    def health_check(self) -> HealthMetric:
        if self._state != VpsState.CONNECTED or self._failure_injected:
            return HealthMetric(latency_ms=999.0, packet_loss_pct=100.0, jitter_ms=99.0, is_reachable=False)

        return HealthMetric(
            latency_ms=self.base_latency_ms,
            packet_loss_pct=0.0,
            jitter_ms=1.2,
            is_reachable=True,
        )

    def cleanup(self) -> None:
        self.disconnect()
        self._failure_injected = False
        self._last_error = None

    # Test hooks
    def inject_failure(self, error_msg: str = "Simulated VPS peer timeout") -> None:
        """Inject abrupt failure into the VPS connection."""
        self._failure_injected = True
        self._state = VpsState.FAILED
        self._last_error = error_msg
        self.kill_switch.engage_lockdown()
        logger.warning(f"Injected VPS failure: {error_msg}")
