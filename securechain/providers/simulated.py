"""Simulated high-fidelity VPN Provider for testing and un-elevated environments."""

import time
from datetime import datetime, timezone
from typing import Optional
from securechain.core.exceptions import TunnelConnectionError, TunnelError
from securechain.providers.base import (
    HealthMetric,
    InterfaceInfo,
    TunnelConfig,
    TunnelState,
    TunnelStatus,
    VPNProvider,
)
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.providers.simulated")


class SimulatedVPNProvider(VPNProvider):
    """High-fidelity simulated VPN provider supporting deterministic telemetry and failure injection."""

    def __init__(
        self,
        base_latency_ms: float = 25.0,
        base_loss_pct: float = 0.0,
        base_jitter_ms: float = 2.0,
        simulate_failure_on_connect: bool = False,
    ) -> None:
        self.base_latency_ms = base_latency_ms
        self.base_loss_pct = base_loss_pct
        self.base_jitter_ms = base_jitter_ms
        self.simulate_failure_on_connect = simulate_failure_on_connect

        self._config: Optional[TunnelConfig] = None
        self._state: TunnelState = TunnelState.DISCONNECTED
        self._interface: Optional[InterfaceInfo] = None
        self._connected_at: Optional[float] = None
        self._is_cleaned_up: bool = True
        self._last_error: Optional[str] = None

    def connect(self, config: TunnelConfig) -> TunnelStatus:
        logger.info(f"Connecting simulated tunnel '{config.tunnel_id}' to {config.endpoint_ip}:{config.endpoint_port}")
        self._config = config
        self._state = TunnelState.CONNECTING
        self._last_error = None

        if self.simulate_failure_on_connect:
            self._state = TunnelState.FAILED
            self._last_error = "Simulated connection refused by remote endpoint"
            logger.error(f"Failed to connect tunnel '{config.tunnel_id}': {self._last_error}")
            raise TunnelConnectionError(self._last_error)

        # Allocate virtual interface
        if_name = f"sim-{config.tunnel_id}"
        self._interface = InterfaceInfo(
            name=if_name,
            ip_address=config.assigned_ip,
            gateway_ip=config.gateway_ip,
            dns_servers=[config.dns_server],
            mtu=config.mtu,
        )
        self._state = TunnelState.CONNECTED
        self._connected_at = time.time()
        self._is_cleaned_up = False
        logger.info(f"Simulated tunnel '{config.tunnel_id}' connected on interface '{if_name}'")
        return self.status()

    def disconnect(self) -> TunnelStatus:
        if self._state == TunnelState.DISCONNECTED:
            return self.status()

        logger.info(f"Disconnecting simulated tunnel '{self._config.tunnel_id if self._config else 'unknown'}'")
        self._state = TunnelState.DISCONNECTED
        self._interface = None
        self._connected_at = None
        return self.status()

    def status(self) -> TunnelStatus:
        uptime = 0.0
        if self._connected_at and self._state == TunnelState.CONNECTED:
            uptime = max(0.0, time.time() - self._connected_at)

        return TunnelStatus(
            tunnel_id=self._config.tunnel_id if self._config else "uninitialized",
            state=self._state,
            interface=self._interface,
            uptime_seconds=uptime,
            bytes_sent=1024 * int(uptime) if uptime else 0,
            bytes_received=2048 * int(uptime) if uptime else 0,
            last_error=self._last_error,
        )

    def health_check(self) -> HealthMetric:
        if self._state not in {TunnelState.CONNECTED, TunnelState.DEGRADED}:
            return HealthMetric(
                latency_ms=999.0,
                packet_loss_pct=100.0,
                jitter_ms=99.0,
                is_reachable=False,
            )

        return HealthMetric(
            latency_ms=self.base_latency_ms,
            packet_loss_pct=self.base_loss_pct,
            jitter_ms=self.base_jitter_ms,
            is_reachable=True,
        )

    def get_interface(self) -> InterfaceInfo:
        if not self._interface or self._state != TunnelState.CONNECTED:
            raise TunnelError("Interface unavailable: tunnel is not connected")
        return self._interface

    def cleanup(self) -> None:
        logger.info(f"Cleaning up simulated tunnel resources for '{self._config.tunnel_id if self._config else 'uninitialized'}'")
        self._state = TunnelState.DISCONNECTED
        self._interface = None
        self._connected_at = None
        self._config = None
        self._is_cleaned_up = True

    # Simulation control hooks
    def inject_degradation(self, latency_ms: float, loss_pct: float, jitter_ms: float) -> None:
        """Inject artificial degradation for testing telemetry and adaptive switching."""
        self.base_latency_ms = latency_ms
        self.base_loss_pct = loss_pct
        self.base_jitter_ms = jitter_ms
        if loss_pct > 20.0 or latency_ms > 300.0:
            self._state = TunnelState.DEGRADED

    def inject_failure(self, error_message: str = "Injected network link drop") -> None:
        """Inject an abrupt tunnel failure."""
        self._state = TunnelState.FAILED
        self._last_error = error_message
        logger.warning(f"Injected tunnel failure: {error_message}")
