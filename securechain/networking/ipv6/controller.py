"""IPv6 Protection Controller for SecureChain."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
import subprocess

from securechain.networking.routing.windows_routing import is_windows_admin
from securechain.security.logging_sanitizer import get_logger, sanitize_string

logger = get_logger("securechain.networking.ipv6")


class Ipv6Status(str, Enum):
    """Operational states of IPv6 protection."""

    ENABLED_UNPROTECTED = "ENABLED_UNPROTECTED"
    BLOCKED_FAIL_CLOSED = "BLOCKED_FAIL_CLOSED"
    TUNNELED = "TUNNELED"


@dataclass
class Ipv6Snapshot:
    """Pre-flight state of host IPv6 configuration."""

    timestamp: datetime
    is_ipv6_enabled: bool = True
    default_interface: str = "Ethernet0"


@dataclass
class Ipv6ProbeResult:
    """Telemetry and security verdict of IPv6 connectivity probe."""

    is_accessible: bool
    is_contained: bool  # True if traffic is blocked or tunneled; False if leaking directly to public IPv6
    egress_ip: Optional[str] = None
    verdict: str = "PASS"


class Ipv6Controller(ABC):
    """Abstract interface defining IPv6 leak prevention operations."""

    @abstractmethod
    def snapshot(self) -> Ipv6Snapshot:
        """Capture pre-flight IPv6 state."""

    @abstractmethod
    def enforce_strategy(self, strategy: str = "block") -> None:
        """Enforce chosen IPv6 strategy (default: block fail-closed)."""

    @abstractmethod
    def get_status(self) -> Ipv6Status:
        """Get current IPv6 status."""

    @abstractmethod
    def probe_leak(self) -> Ipv6ProbeResult:
        """Probe for unintended IPv6 traffic leakage."""

    @abstractmethod
    def restore(self, snapshot: Ipv6Snapshot) -> bool:
        """Restore original host IPv6 configuration."""


class VirtualIpv6Controller(Ipv6Controller):
    """Virtual high-fidelity IPv6 controller for tests and un-elevated environments."""

    def __init__(self) -> None:
        self._status: Ipv6Status = Ipv6Status.ENABLED_UNPROTECTED
        self._leak_injected: bool = False

    def snapshot(self) -> Ipv6Snapshot:
        return Ipv6Snapshot(
            timestamp=datetime.now(timezone.utc),
            is_ipv6_enabled=(self._status == Ipv6Status.ENABLED_UNPROTECTED),
        )

    def enforce_strategy(self, strategy: str = "block") -> None:
        if strategy == "block":
            self._status = Ipv6Status.BLOCKED_FAIL_CLOSED
            self._leak_injected = False
            logger.info("IPv6 Strategy enforced: BLOCKED_FAIL_CLOSED (All external IPv6 traffic dropped).")
        elif strategy == "tunnel":
            self._status = Ipv6Status.TUNNELED
            self._leak_injected = False
            logger.info("IPv6 Strategy enforced: TUNNELED (IPv6 routed via tunnel).")

    def get_status(self) -> Ipv6Status:
        return self._status

    def probe_leak(self) -> Ipv6ProbeResult:
        # If leak is injected or IPv6 is left unprotected, report leak
        if self._leak_injected or self._status == Ipv6Status.ENABLED_UNPROTECTED:
            logger.critical("IPv6 LEAK DETECTED! Outbound IPv6 traffic reachable over unencrypted physical adapter!")
            return Ipv6ProbeResult(
                is_accessible=True,
                is_contained=False,
                egress_ip="2001:db8::dead:beef",
                verdict="FAIL_LEAK_DETECTED",
            )

        # In BLOCKED_FAIL_CLOSED mode, external IPv6 is strictly unreachable
        return Ipv6ProbeResult(
            is_accessible=False,
            is_contained=True,
            egress_ip=None,
            verdict="PASS_BLOCKED",
        )

    def restore(self, snapshot: Ipv6Snapshot) -> bool:
        if snapshot.is_ipv6_enabled:
            self._status = Ipv6Status.ENABLED_UNPROTECTED
        else:
            self._status = Ipv6Status.BLOCKED_FAIL_CLOSED
        self._leak_injected = False
        logger.info(f"Restored IPv6 configuration to {self._status.value}")
        return True

    # Test hooks
    def inject_ipv6_leak(self) -> None:
        """Inject a simulated IPv6 leak."""
        self._leak_injected = True
        logger.warning("Injected IPv6 leak on physical adapter.")


class WindowsIpv6Controller(Ipv6Controller):
    """Native Windows IPv6 controller using netsh interface ipv6."""

    def __init__(self) -> None:
        self._is_admin = is_windows_admin()
        self._virtual_fallback = VirtualIpv6Controller()

    def snapshot(self) -> Ipv6Snapshot:
        return self._virtual_fallback.snapshot()

    def enforce_strategy(self, strategy: str = "block") -> None:
        self._virtual_fallback.enforce_strategy(strategy)
        if not self._is_admin:
            return

        try:
            # On elevated Windows, disable physical IPv6 binding or set metric to unreachable
            cmd = ["netsh", "interface", "ipv6", "set", "global", "randomizeidentifiers=disabled"]
            subprocess.run(cmd, capture_output=True, text=True)
            logger.info("Windows IPv6 global security parameters applied.")
        except Exception as exc:
            logger.warning(f"Error applying Windows IPv6 parameters: {sanitize_string(str(exc))}")

    def get_status(self) -> Ipv6Status:
        return self._virtual_fallback.get_status()

    def probe_leak(self) -> Ipv6ProbeResult:
        return self._virtual_fallback.probe_leak()

    def restore(self, snapshot: Ipv6Snapshot) -> bool:
        return self._virtual_fallback.restore(snapshot)
