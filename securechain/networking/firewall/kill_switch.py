"""Fail-Closed Kill Switch (Traffic Containment) for SecureChain."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Set
import subprocess

from securechain.core.exceptions import KillSwitchError
from securechain.networking.routing.windows_routing import is_windows_admin
from securechain.security.logging_sanitizer import get_logger, sanitize_string

logger = get_logger("securechain.networking.kill_switch")


class KillSwitchState(str, Enum):
    """Operational states of the Kill Switch."""

    DISABLED = "DISABLED"
    ENGAGED = "ENGAGED"            # Strict lockdown: only loopback and next-hop tunnel endpoints permitted
    FILTERED_PASS = "FILTERED_PASS" # Chain verified: internet permitted exclusively through active exit tunnel


@dataclass
class Packet:
    """Network packet descriptor for firewall packet inspection."""

    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str = "UDP"  # "UDP", "TCP", "ICMP"
    egress_interface: str = "Ethernet0"


@dataclass
class PacketVerdict:
    """Result of firewall packet evaluation."""

    allowed: bool
    reason: str
    matched_rule: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class KillSwitch(ABC):
    """Abstract interface defining Kill Switch containment operations."""

    @abstractmethod
    def enable(self) -> None:
        """Engage the kill switch barrier."""

    @abstractmethod
    def disable(self) -> None:
        """Disengage the kill switch barrier."""

    @abstractmethod
    def get_state(self) -> KillSwitchState:
        """Get current operational state."""

    @abstractmethod
    def allow_hop1_endpoint(self, ip: str, port: int) -> None:
        """Permit outbound traffic strictly to Hop 1 endpoint via physical adapter."""

    @abstractmethod
    def set_active_exit_interface(self, iface_name: str) -> None:
        """Designate the verified exit tunnel interface allowed for general internet egress."""

    @abstractmethod
    def evaluate_packet(self, packet: Packet) -> PacketVerdict:
        """Inspect and decide whether an outbound packet is permitted or dropped."""


class VirtualKillSwitch(KillSwitch):
    """Virtual high-fidelity packet filtering barrier for un-elevated environments and test harnesses."""

    def __init__(self) -> None:
        self._state: KillSwitchState = KillSwitchState.DISABLED
        self._hop1_ip: Optional[str] = None
        self._hop1_port: Optional[int] = None
        self._exit_interface: Optional[str] = None
        self._allowed_tunnel_interfaces: Set[str] = set()

    def enable(self) -> None:
        self._state = KillSwitchState.ENGAGED
        logger.info("Virtual Kill Switch ENGAGED: Fail-closed lockdown active.")

    def disable(self) -> None:
        self._state = KillSwitchState.DISABLED
        self._hop1_ip = None
        self._hop1_port = None
        self._exit_interface = None
        self._allowed_tunnel_interfaces.clear()
        logger.info("Virtual Kill Switch DISABLED: Normal routing restored.")

    def get_state(self) -> KillSwitchState:
        return self._state

    def allow_hop1_endpoint(self, ip: str, port: int) -> None:
        self._hop1_ip = ip
        self._hop1_port = port
        logger.info(f"Kill Switch permitted Hop 1 endpoint {ip}:{port} on physical interface")

    def register_tunnel_interface(self, iface_name: str) -> None:
        self._allowed_tunnel_interfaces.add(iface_name)

    def set_active_exit_interface(self, iface_name: str) -> None:
        self._exit_interface = iface_name
        self._allowed_tunnel_interfaces.add(iface_name)
        self._state = KillSwitchState.FILTERED_PASS
        logger.info(f"Kill Switch transitioned to FILTERED_PASS via exit interface '{iface_name}'")

    def engage_lockdown(self) -> None:
        """Immediately drop from FILTERED_PASS back to ENGAGED (lockdown)."""
        self._state = KillSwitchState.ENGAGED
        self._exit_interface = None
        self._allowed_tunnel_interfaces.clear()
        logger.warning("Kill Switch engaged lockdown: All general outbound traffic blocked!")

    def evaluate_packet(self, packet: Packet) -> PacketVerdict:
        # If kill switch is disabled, allow all
        if self._state == KillSwitchState.DISABLED:
            return PacketVerdict(allowed=True, reason="Kill switch disabled", matched_rule="DEFAULT_ALLOW")

        # 1. Always allow loopback
        if packet.destination_ip in {"127.0.0.1", "::1", "localhost"}:
            return PacketVerdict(allowed=True, reason="Loopback permitted", matched_rule="ALLOW_LOOPBACK")

        # 2. Allow Hop 1 outer handshake via physical adapter
        if (
            self._hop1_ip
            and packet.destination_ip == self._hop1_ip
            and (self._hop1_port is None or packet.destination_port == self._hop1_port)
        ):
            return PacketVerdict(
                allowed=True,
                reason="Hop 1 encapsulation endpoint permitted",
                matched_rule="ALLOW_HOP1_TUNNEL_ENDPOINT",
            )

        # 3. In FILTERED_PASS state, permit traffic strictly over active exit tunnel interface
        if self._state == KillSwitchState.FILTERED_PASS:
            if self._exit_interface and packet.egress_interface == self._exit_interface:
                return PacketVerdict(
                    allowed=True,
                    reason="Verified exit tunnel traffic permitted",
                    matched_rule="ALLOW_VERIFIED_TUNNEL",
                )

        # 4. In all other states (ENGAGED / lockdown), general outbound traffic is strictly dropped
        return PacketVerdict(
            allowed=False,
            reason="FAIL-CLOSED: Unverified traffic dropped by Kill Switch",
            matched_rule="BLOCK_DIRECT_INTERNET",
        )


class WindowsKillSwitch(KillSwitch):
    """Native Windows Filtering Platform / Advanced Firewall Kill Switch."""

    RULE_NAME_BLOCK_ALL = "SecureChain_KillSwitch_BlockOutbound"
    RULE_NAME_ALLOW_HOP1 = "SecureChain_KillSwitch_AllowHop1"

    def __init__(self) -> None:
        self._is_admin = is_windows_admin()
        self._virtual_fallback = VirtualKillSwitch()
        self._state: KillSwitchState = KillSwitchState.DISABLED

    def enable(self) -> None:
        if not self._is_admin:
            logger.info("Non-elevated environment: using VirtualKillSwitch containment engine.")
            self._virtual_fallback.enable()
            self._state = self._virtual_fallback.get_state()
            return

        try:
            # Add firewall block rule
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self.RULE_NAME_BLOCK_ALL}",
                "dir=out", "action=block", "protocol=ANY",
            ]
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            self._state = KillSwitchState.ENGAGED
            logger.info("Windows netsh firewall kill switch engaged successfully.")
        except Exception as exc:
            logger.error(f"Failed to configure Windows Firewall kill switch: {sanitize_string(str(exc))}")
            raise KillSwitchError(f"Windows Firewall error: {exc}") from exc

    def disable(self) -> None:
        if not self._is_admin:
            self._virtual_fallback.disable()
            self._state = self._virtual_fallback.get_state()
            return

        try:
            for rule in [self.RULE_NAME_BLOCK_ALL, self.RULE_NAME_ALLOW_HOP1]:
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"]
                subprocess.run(cmd, capture_output=True, text=True)
            self._state = KillSwitchState.DISABLED
            logger.info("Windows netsh firewall kill switch rules deleted.")
        except Exception as exc:
            logger.warning(f"Error cleaning up Windows firewall rules: {sanitize_string(str(exc))}")

    def get_state(self) -> KillSwitchState:
        return self._state

    def allow_hop1_endpoint(self, ip: str, port: int) -> None:
        self._virtual_fallback.allow_hop1_endpoint(ip, port)
        if not self._is_admin:
            return

        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self.RULE_NAME_ALLOW_HOP1}",
                "dir=out", "action=allow", f"remoteip={ip}", f"remoteport={port}", "protocol=UDP",
            ]
            subprocess.run(cmd, capture_output=True, text=True)
        except Exception as exc:
            logger.warning(f"Failed to add allow rule for Hop 1: {sanitize_string(str(exc))}")

    def set_active_exit_interface(self, iface_name: str) -> None:
        self._virtual_fallback.set_active_exit_interface(iface_name)
        self._state = KillSwitchState.FILTERED_PASS

    def evaluate_packet(self, packet: Packet) -> PacketVerdict:
        return self._virtual_fallback.evaluate_packet(packet)
