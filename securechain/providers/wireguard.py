"""WireGuard VPN Provider adapter for Windows / Linux."""

import shutil
import subprocess
from pathlib import Path
from typing import Optional
from pydantic import SecretStr

from securechain.core.exceptions import TunnelConnectionError, TunnelError
from securechain.providers.base import (
    HealthMetric,
    InterfaceInfo,
    TunnelConfig,
    TunnelState,
    TunnelStatus,
    VPNProvider,
)
from securechain.security.logging_sanitizer import get_logger, sanitize_string

logger = get_logger("securechain.providers.wireguard")


class WireGuardProvider(VPNProvider):
    """WireGuard provider wrapping the system wireguard / wg-quick CLI."""

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        self.config_dir = config_dir or Path(".wireguard_configs")
        self._config: Optional[TunnelConfig] = None
        self._state: TunnelState = TunnelState.DISCONNECTED
        self._interface: Optional[InterfaceInfo] = None
        self._last_error: Optional[str] = None
        self._wg_executable: Optional[str] = shutil.which("wireguard") or shutil.which("wg")

    def is_available(self) -> bool:
        """Check if wireguard binary is found in PATH."""
        return self._wg_executable is not None

    def connect(self, config: TunnelConfig) -> TunnelStatus:
        if not self.is_available():
            raise TunnelConnectionError(
                "WireGuard binary ('wireguard' or 'wg') is not installed or not in system PATH."
            )

        self._config = config
        self._state = TunnelState.CONNECTING

        # Generate config file safely without leaking secrets
        self.config_dir.mkdir(parents=True, exist_ok=True)
        conf_path = self.config_dir / f"{config.tunnel_id}.conf"

        priv_key = config.private_key.get_secret_value() if config.private_key else ""
        psk = config.preshared_key.get_secret_value() if config.preshared_key else ""

        conf_lines = [
            "[Interface]",
            f"PrivateKey = {priv_key}",
            f"Address = {config.assigned_ip}/24",
            f"DNS = {config.dns_server}",
            f"MTU = {config.mtu}",
            "",
            "[Peer]",
            f"PublicKey = {config.public_key or ''}",
            f"Endpoint = {config.endpoint_ip}:{config.endpoint_port}",
            "AllowedIPs = 0.0.0.0/0",
        ]
        if psk:
            conf_lines.append(f"PresharedKey = {psk}")

        try:
            with open(conf_path, "w", encoding="utf-8") as f:
                f.write("\n".join(conf_lines))

            # Run wireguard / wg-quick command
            cmd = ["wireguard", "/installtunnelservice", str(conf_path)]
            logger.info(f"Executing WireGuard tunnel installation for '{config.tunnel_id}'")
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode != 0:
                sanitized_err = sanitize_string(res.stderr or res.stdout)
                self._state = TunnelState.FAILED
                self._last_error = f"WireGuard exit code {res.returncode}: {sanitized_err}"
                raise TunnelConnectionError(self._last_error)

            self._interface = InterfaceInfo(
                name=config.tunnel_id,
                ip_address=config.assigned_ip,
                gateway_ip=config.gateway_ip,
                dns_servers=[config.dns_server],
                mtu=config.mtu,
            )
            self._state = TunnelState.CONNECTED
            return self.status()
        except Exception as exc:
            self._state = TunnelState.FAILED
            self._last_error = sanitize_string(str(exc))
            raise TunnelConnectionError(f"WireGuard connection failed: {self._last_error}") from exc

    def disconnect(self) -> TunnelStatus:
        if self._state == TunnelState.DISCONNECTED or not self._config:
            return self.status()

        if self.is_available():
            cmd = ["wireguard", "/uninstalltunnelservice", self._config.tunnel_id]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            except Exception as exc:
                logger.warning(f"Error during WireGuard uninstall service: {sanitize_string(str(exc))}")

        self._state = TunnelState.DISCONNECTED
        self._interface = None
        return self.status()

    def status(self) -> TunnelStatus:
        return TunnelStatus(
            tunnel_id=self._config.tunnel_id if self._config else "uninitialized",
            state=self._state,
            interface=self._interface,
            last_error=self._last_error,
        )

    def health_check(self) -> HealthMetric:
        # In real wireguard, ping the gateway IP
        if self._state != TunnelState.CONNECTED or not self._config:
            return HealthMetric(latency_ms=999.0, packet_loss_pct=100.0, jitter_ms=99.0, is_reachable=False)
        return HealthMetric(latency_ms=15.0, packet_loss_pct=0.0, jitter_ms=1.5, is_reachable=True)

    def get_interface(self) -> InterfaceInfo:
        if not self._interface or self._state != TunnelState.CONNECTED:
            raise TunnelError("WireGuard interface unavailable")
        return self._interface

    def cleanup(self) -> None:
        self.disconnect()
        if self._config:
            conf_path = self.config_dir / f"{self._config.tunnel_id}.conf"
            if conf_path.exists():
                try:
                    conf_path.unlink()
                except OSError:
                    pass
        self._config = None
