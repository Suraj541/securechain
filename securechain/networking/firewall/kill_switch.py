import os
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

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

    def engage_lockdown(self) -> None:
        self._virtual_fallback.engage_lockdown()
        self._state = KillSwitchState.ENGAGED
        if not self._is_admin:
            return
        try:
            self.enable()
        except Exception as exc:
            logger.warning(f"Windows lockdown error: {exc}")

    def get_diagnostics(self) -> Dict[str, Any]:
        return {
            "backend": "Windows netsh advfirewall",
            "platform": sys.platform,
            "is_admin": self._is_admin,
            "native_active": self._is_admin and self._state != KillSwitchState.DISABLED,
            "state": self._state.value,
        }


class LinuxNftablesKillSwitch(KillSwitch):
    """Native Linux nftables packet containment barrier using an isolated table."""

    TABLE_NAME = "inet securechain"

    def __init__(self) -> None:
        self._is_linux = sys.platform.startswith("linux")
        self._nft_path = shutil.which("nft")
        self._is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        self._virtual_fallback = VirtualKillSwitch()
        self._state: KillSwitchState = KillSwitchState.DISABLED
        self._hop1_endpoint: Optional[Tuple[str, int]] = None
        self._exit_iface: Optional[str] = None

    @property
    def is_native_available(self) -> bool:
        return self._is_linux and bool(self._nft_path) and self._is_root

    def enable(self) -> None:
        if not self.is_native_available:
            logger.info("Non-elevated or non-Linux environment: using VirtualKillSwitch containment engine.")
            self._virtual_fallback.enable()
            self._state = self._virtual_fallback.get_state()
            return

        try:
            # Create isolated table and chains (failsafe: does not flush other tables)
            nft_cmds = [
                f"add table {self.TABLE_NAME}",
                f"add chain {self.TABLE_NAME} output {{ type filter hook output priority 0; policy drop; }}",
                f"add chain {self.TABLE_NAME} input {{ type filter hook input priority 0; policy accept; }}",
                f"add rule {self.TABLE_NAME} output oifname \"lo\" accept",
            ]
            for cmd in nft_cmds:
                subprocess.run(["nft", *cmd.split()], capture_output=True, text=True, check=True)
            self._state = KillSwitchState.ENGAGED
            logger.info("Linux nftables kill switch engaged in isolated table 'inet securechain'.")
        except Exception as exc:
            logger.error(f"Failed to engage Linux nftables kill switch: {sanitize_string(str(exc))}")
            self._virtual_fallback.enable()
            self._state = self._virtual_fallback.get_state()
            raise KillSwitchError(f"nftables error: {exc}") from exc

    def disable(self) -> None:
        if not self.is_native_available:
            self._virtual_fallback.disable()
            self._state = self._virtual_fallback.get_state()
            return

        try:
            # Safely delete ONLY our table
            subprocess.run(["nft", "delete", "table", "inet", "securechain"], capture_output=True, text=True)
            self._state = KillSwitchState.DISABLED
            logger.info("Linux nftables isolated table deleted; normal routing restored.")
        except Exception as exc:
            logger.warning(f"Error cleaning up nftables table: {sanitize_string(str(exc))}")
        self._virtual_fallback.disable()
        self._state = KillSwitchState.DISABLED

    def allow_hop1_endpoint(self, ip: str, port: int) -> None:
        self._virtual_fallback.allow_hop1_endpoint(ip, port)
        self._hop1_endpoint = (ip, port)
        if not self.is_native_available:
            return

        try:
            cmd = ["nft", "add", "rule", "inet", "securechain", "output", "udp", "dport", str(port), "ip", "daddr", ip, "accept"]
            subprocess.run(cmd, capture_output=True, text=True)
        except Exception as exc:
            logger.warning(f"Failed to add nftables rule for Hop 1 endpoint: {sanitize_string(str(exc))}")

    def set_active_exit_interface(self, iface_name: str) -> None:
        self._virtual_fallback.set_active_exit_interface(iface_name)
        self._exit_iface = iface_name
        self._state = KillSwitchState.FILTERED_PASS
        if not self.is_native_available:
            return

        try:
            cmd = ["nft", "add", "rule", "inet", "securechain", "output", "oifname", iface_name, "accept"]
            subprocess.run(cmd, capture_output=True, text=True)
        except Exception as exc:
            logger.warning(f"Failed to add nftables rule for exit interface {iface_name}: {sanitize_string(str(exc))}")

    def engage_lockdown(self) -> None:
        self._virtual_fallback.engage_lockdown()
        self._state = KillSwitchState.ENGAGED
        if not self.is_native_available:
            return
        self.enable()
        if self._hop1_endpoint:
            self.allow_hop1_endpoint(*self._hop1_endpoint)

    def get_state(self) -> KillSwitchState:
        return self._state

    def evaluate_packet(self, packet: Packet) -> PacketVerdict:
        return self._virtual_fallback.evaluate_packet(packet)

    def get_diagnostics(self) -> Dict[str, Any]:
        return {
            "backend": "Linux nftables (isolated table inet securechain)",
            "platform": sys.platform,
            "nft_installed": bool(self._nft_path),
            "is_root": self._is_root,
            "native_active": self.is_native_available and self._state != KillSwitchState.DISABLED,
            "state": self._state.value,
        }


class MacOsPfKillSwitch(KillSwitch):
    """Native macOS Packet Filter (pf) containment barrier using an isolated anchor."""

    ANCHOR_NAME = "securechain"

    def __init__(self) -> None:
        self._is_macos = sys.platform == "darwin"
        self._pfctl_path = shutil.which("pfctl")
        self._is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        self._virtual_fallback = VirtualKillSwitch()
        self._state: KillSwitchState = KillSwitchState.DISABLED
        self._hop1_endpoint: Optional[Tuple[str, int]] = None
        self._exit_iface: Optional[str] = None

    @property
    def is_native_available(self) -> bool:
        return self._is_macos and bool(self._pfctl_path) and self._is_root

    def enable(self) -> None:
        if not self.is_native_available:
            logger.info("Non-elevated or non-macOS environment: using VirtualKillSwitch containment engine.")
            self._virtual_fallback.enable()
            self._state = self._virtual_fallback.get_state()
            return

        try:
            rules = "set skip on lo0\nblock out quick all\n"
            subprocess.run(["pfctl", "-e"], capture_output=True, text=True)
            subprocess.run(
                ["pfctl", "-a", self.ANCHOR_NAME, "-f", "-"],
                input=rules,
                capture_output=True,
                text=True,
                check=True,
            )
            self._state = KillSwitchState.ENGAGED
            logger.info("macOS pf kill switch engaged in isolated anchor 'securechain'.")
        except Exception as exc:
            logger.error(f"Failed to engage macOS pf kill switch: {sanitize_string(str(exc))}")
            self._virtual_fallback.enable()
            self._state = self._virtual_fallback.get_state()
            raise KillSwitchError(f"pfctl error: {exc}") from exc

    def disable(self) -> None:
        if not self.is_native_available:
            self._virtual_fallback.disable()
            self._state = self._virtual_fallback.get_state()
            return

        try:
            subprocess.run(["pfctl", "-a", self.ANCHOR_NAME, "-F", "all"], capture_output=True, text=True)
            self._state = KillSwitchState.DISABLED
            logger.info("macOS pf isolated anchor flushed; normal routing restored.")
        except Exception as exc:
            logger.warning(f"Error flushing macOS pf anchor: {sanitize_string(str(exc))}")
        self._virtual_fallback.disable()
        self._state = KillSwitchState.DISABLED

    def allow_hop1_endpoint(self, ip: str, port: int) -> None:
        self._virtual_fallback.allow_hop1_endpoint(ip, port)
        self._hop1_endpoint = (ip, port)
        self._sync_rules()

    def set_active_exit_interface(self, iface_name: str) -> None:
        self._virtual_fallback.set_active_exit_interface(iface_name)
        self._exit_iface = iface_name
        self._state = KillSwitchState.FILTERED_PASS
        self._sync_rules()

    def engage_lockdown(self) -> None:
        self._virtual_fallback.engage_lockdown()
        self._exit_iface = None
        self._state = KillSwitchState.ENGAGED
        self._sync_rules()

    def _sync_rules(self) -> None:
        if not self.is_native_available or self._state == KillSwitchState.DISABLED:
            return
        rules = ["set skip on lo0"]
        if self._hop1_endpoint:
            ip, port = self._hop1_endpoint
            rules.append(f"pass out quick proto udp to {ip} port {port}")
        if self._exit_iface and self._state == KillSwitchState.FILTERED_PASS:
            rules.append(f"pass out quick on {self._exit_iface} all")
        rules.append("block out quick all")
        try:
            subprocess.run(
                ["pfctl", "-a", self.ANCHOR_NAME, "-f", "-"],
                input="\n".join(rules) + "\n",
                capture_output=True,
                text=True,
            )
        except Exception as exc:
            logger.warning(f"Failed to sync pf anchor rules: {sanitize_string(str(exc))}")

    def get_state(self) -> KillSwitchState:
        return self._state

    def evaluate_packet(self, packet: Packet) -> PacketVerdict:
        return self._virtual_fallback.evaluate_packet(packet)

    def get_diagnostics(self) -> Dict[str, Any]:
        return {
            "backend": "macOS pf (isolated anchor securechain)",
            "platform": sys.platform,
            "pfctl_installed": bool(self._pfctl_path),
            "is_root": self._is_root,
            "native_active": self.is_native_available and self._state != KillSwitchState.DISABLED,
            "state": self._state.value,
        }


class CrossPlatformFirewallManager(KillSwitch):
    """Unified platform-independent firewall manager delegating to native backends or virtual mesh."""

    def __init__(self, backend_override: Optional[str] = None) -> None:
        self._override = backend_override
        if backend_override == "windows":
            self._backend: KillSwitch = WindowsKillSwitch()
        elif backend_override == "linux":
            self._backend = LinuxNftablesKillSwitch()
        elif backend_override == "macos":
            self._backend = MacOsPfKillSwitch()
        elif backend_override == "virtual":
            self._backend = VirtualKillSwitch()
        else:
            if sys.platform.startswith("win"):
                self._backend = WindowsKillSwitch()
            elif sys.platform.startswith("linux"):
                self._backend = LinuxNftablesKillSwitch()
            elif sys.platform == "darwin":
                self._backend = MacOsPfKillSwitch()
            else:
                self._backend = VirtualKillSwitch()

    @property
    def active_backend(self) -> KillSwitch:
        return self._backend

    @property
    def backend(self) -> KillSwitch:
        return self._backend

    def enable(self) -> None:
        self._backend.enable()

    def disable(self) -> None:
        self._backend.disable()

    def get_state(self) -> KillSwitchState:
        return self._backend.get_state()

    def allow_hop1_endpoint(self, ip: str, port: int) -> None:
        self._backend.allow_hop1_endpoint(ip, port)

    def set_active_exit_interface(self, iface_name: str) -> None:
        self._backend.set_active_exit_interface(iface_name)

    def engage_lockdown(self) -> None:
        if hasattr(self._backend, "engage_lockdown"):
            self._backend.engage_lockdown()
        else:
            self._backend.enable()

    def evaluate_packet(self, packet: Packet) -> PacketVerdict:
        return self._backend.evaluate_packet(packet)

    def get_diagnostics(self) -> Dict[str, Any]:
        if hasattr(self._backend, "get_diagnostics"):
            return self._backend.get_diagnostics()
        return {
            "backend": type(self._backend).__name__,
            "platform": sys.platform,
            "state": self.get_state().value,
        }

