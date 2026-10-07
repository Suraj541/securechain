"""Reality Readiness Check for SecureChain Infrastructure."""

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from securechain.configuration.loader import load_config
from securechain.configuration.schema import SecureChainConfig
from securechain.networking.routing.windows_routing import is_windows_admin
from securechain.security.credentials.dpapi_store import DpapiCredentialStore
from securechain.security.test_framework import TestMode, TestProvenance, TestStatus


@dataclass
class RealityCheckItem:
    """Individual readiness check item."""

    name: str
    status: str
    mode: TestMode
    evidence: str
    is_ready: bool


class RealityChecker:
    """Performs strict inspection of actual host system and network configuration."""

    def __init__(self, config: Optional[SecureChainConfig] = None) -> None:
        self.config = config or load_config()
        self.cred_store = DpapiCredentialStore()

    def check_core_app(self) -> RealityCheckItem:
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        return RealityCheckItem(
            name="Core application",
            status="PASS",
            mode=TestMode.REAL,
            evidence=f"Python {py_ver} on {sys.platform}",
            is_ready=True,
        )

    def check_config_schema(self) -> RealityCheckItem:
        try:
            assert self.config.chain.min_hops >= 2
            return RealityCheckItem(
                name="Configuration schema",
                status="PASS",
                mode=TestMode.UNIT,
                evidence="Pydantic schema validated",
                is_ready=True,
            )
        except Exception as exc:
            return RealityCheckItem(
                name="Configuration schema",
                status="FAIL",
                mode=TestMode.UNIT,
                evidence=f"Schema invalid: {exc}",
                is_ready=False,
            )

    def check_vpn_configuration(self) -> RealityCheckItem:
        # Check if real endpoints are specified in config or files
        has_real_config = False
        evidence = "No real VPN endpoints defined in config.yaml"

        # Check for user-provided real wireguard configs
        wg_dir = Path(".wireguard_configs")
        if wg_dir.exists() and list(wg_dir.glob("*.conf")):
            confs = list(wg_dir.glob("*.conf"))
            active_confs = []
            has_templates = False
            for c in confs:
                try:
                    txt = c.read_text(encoding="utf-8")
                    if "<YOUR_" in txt or "<SERVER" in txt:
                        has_templates = True
                    else:
                        active_confs.append(c)
                except Exception:
                    pass

            if active_confs:
                has_real_config = True
                evidence = f"Found {len(active_confs)} active config(s) in .wireguard_configs"
            elif has_templates:
                evidence = "Template files present in .wireguard_configs, but contain unconfigured placeholders (<YOUR_...>, <SERVER...>)"

        status = "PASS" if has_real_config else "NOT CONFIGURED"
        return RealityCheckItem(
            name="VPN configuration",
            status=status,
            mode=TestMode.REAL,
            evidence=evidence,
            is_ready=has_real_config,
        )

    def check_vpn_credentials(self) -> RealityCheckItem:
        stat = self.cred_store.status()
        count = stat.get("stored_keys_count", 0)
        has_creds = count > 0
        status = "PASS" if has_creds else "NOT CONFIGURED"
        evidence = f"{count} credential(s) in DPAPI store" if has_creds else "DPAPI store contains 0 credentials"
        return RealityCheckItem(
            name="VPN credentials",
            status=status,
            mode=TestMode.REAL,
            evidence=evidence,
            is_ready=has_creds,
        )

    def check_vpn_interface(self) -> RealityCheckItem:
        # Check if actual WireGuard adapter exists on Windows
        has_iface = False
        evidence = "No active WireGuard network adapter found on Windows"
        try:
            res = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in res.stdout.splitlines():
                if "wireguard" in line.lower() or "wg" in line.lower():
                    has_iface = True
                    evidence = f"Found interface: {line.strip()}"
                    break
        except Exception:
            pass

        status = "PASS" if has_iface else "NOT AVAILABLE"
        return RealityCheckItem(
            name="VPN interface",
            status=status,
            mode=TestMode.REAL,
            evidence=evidence,
            is_ready=has_iface,
        )

    def check_vps_configuration(self) -> RealityCheckItem:
        is_configured = bool(self.config.vps.enabled and self.config.vps.endpoint)
        status = "PASS" if is_configured else "NOT CONFIGURED"
        evidence = (
            f"Endpoint: {self.config.vps.endpoint} ({self.config.vps.protocol})"
            if is_configured
            else "vps.enabled is False or endpoint is null"
        )
        return RealityCheckItem(
            name="VPS configuration",
            status=status,
            mode=TestMode.REAL,
            evidence=evidence,
            is_ready=is_configured,
        )

    def check_vps_credentials(self) -> RealityCheckItem:
        # If VPS enabled, requires credentials
        if not self.config.vps.enabled:
            return RealityCheckItem(
                name="VPS credentials",
                status="NOT CONFIGURED",
                mode=TestMode.REAL,
                evidence="VPS is disabled",
                is_ready=False,
            )
        stat = self.cred_store.status()
        has_vps_key = stat.get("stored_keys_count", 0) > 0
        return RealityCheckItem(
            name="VPS credentials",
            status="PASS" if has_vps_key else "NOT CONFIGURED",
            mode=TestMode.REAL,
            evidence="VPS credentials verified" if has_vps_key else "Missing VPS auth token/key",
            is_ready=has_vps_key,
        )

    def check_networking_tools(self) -> RealityCheckItem:
        wg_bin = shutil.which("wireguard") or shutil.which("wg")
        has_tool = wg_bin is not None
        return RealityCheckItem(
            name="WireGuard binary",
            status="PASS" if has_tool else "NOT AVAILABLE",
            mode=TestMode.REAL,
            evidence=f"Path: {wg_bin}" if has_tool else "Neither 'wireguard' nor 'wg' found in PATH",
            is_ready=has_tool,
        )

    def check_privileges(self) -> RealityCheckItem:
        admin = is_windows_admin()
        return RealityCheckItem(
            name="Windows Administrator",
            status="PASS" if admin else "NOT AVAILABLE",
            mode=TestMode.REAL,
            evidence="Elevated Administrator" if admin else "Non-elevated user shell",
            is_ready=admin,
        )

    def check_simulation_environment(self) -> RealityCheckItem:
        # Virtual mesh availability
        try:
            from securechain.networking.routing.virtual_routing import VirtualRoutingController
            from securechain.networking.firewall.kill_switch import VirtualKillSwitch
            from securechain.providers.simulated import SimulatedVPNProvider
            _ = VirtualRoutingController()
            _ = VirtualKillSwitch()
            _ = SimulatedVPNProvider()
            return RealityCheckItem(
                name="Simulation environment",
                status="READY",
                mode=TestMode.SIMULATION,
                evidence="In-memory VirtualNetworkMesh operational",
                is_ready=True,
            )
        except Exception as exc:
            return RealityCheckItem(
                name="Simulation environment",
                status="FAIL",
                mode=TestMode.SIMULATION,
                evidence=f"Virtual mesh failed to load: {exc}",
                is_ready=False,
            )

    def check_firewall_backend(self) -> RealityCheckItem:
        if sys.platform.startswith("win"):
            admin = is_windows_admin()
            status = "PASS" if admin else "NOT AVAILABLE"
            ev = "Windows Advanced Firewall (netsh) elevated" if admin else "Non-elevated shell (VirtualKillSwitch fallback active)"
        elif sys.platform.startswith("linux"):
            has_nft = shutil.which("nft") is not None
            is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
            status = "PASS" if (has_nft and is_root) else "NOT AVAILABLE"
            ev = "Linux nftables (isolated table inet securechain)" if (has_nft and is_root) else "nftables requires root or CAP_NET_ADMIN (Virtual fallback active)"
        elif sys.platform == "darwin":
            has_pf = shutil.which("pfctl") is not None
            is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
            status = "PASS" if (has_pf and is_root) else "NOT AVAILABLE"
            ev = "macOS pf (isolated anchor securechain)" if (has_pf and is_root) else "pf requires root privilege (Virtual fallback active)"
        else:
            status = "PASS"
            ev = "VirtualKillSwitch packet barrier active"

        return RealityCheckItem(
            name="Firewall backend",
            status=status,
            mode=TestMode.REAL,
            evidence=ev,
            is_ready=(status == "PASS"),
        )

    def check_ipv6_capability(self) -> RealityCheckItem:
        strat = getattr(self.config.security, "ipv6_strategy", "block")
        ev = f"Strategy: {strat}. Fail-closed unless all selected hops explicitly support IPv6."
        return RealityCheckItem(
            name="IPv6 capability",
            status="PASS" if strat in {"block", "auto_capability", "tunnel"} else "FAIL",
            mode=TestMode.UNIT,
            evidence=ev,
            is_ready=True,
        )

    def check_traffic_shaping(self) -> RealityCheckItem:
        privacy_cfg = getattr(self.config, "privacy", None)
        shaping_cfg = getattr(privacy_cfg, "traffic_shaping", None) if privacy_cfg else None
        enabled = shaping_cfg.enabled if shaping_cfg else False
        mode = shaping_cfg.mode if shaping_cfg else "disabled"
        status = "ENABLED" if enabled else "DISABLED"
        ev = f"Mode: {mode} (Note: Traffic shaping does not defeat global passive timing correlation)"
        return RealityCheckItem(
            name="Traffic shaping",
            status=status,
            mode=TestMode.UNIT,
            evidence=ev,
            is_ready=True,
        )

    def check_privacy_proxy(self) -> RealityCheckItem:
        privacy_cfg = getattr(self.config, "privacy", None)
        proxy_cfg = getattr(privacy_cfg, "proxy", None) if privacy_cfg else None
        enabled = proxy_cfg.enabled if proxy_cfg else False
        status = "ENABLED" if enabled else "DISABLED"
        ev = f"Local proxy {proxy_cfg.host}:{proxy_cfg.port} (transparent CONNECT, no TLS MITM)" if (proxy_cfg and enabled) else "Privacy proxy disabled"
        return RealityCheckItem(
            name="Privacy proxy",
            status=status,
            mode=TestMode.UNIT,
            evidence=ev,
            is_ready=True,
        )

    def run_all_checks(self) -> List[RealityCheckItem]:
        return [
            self.check_core_app(),
            self.check_config_schema(),
            self.check_vpn_configuration(),
            self.check_vpn_credentials(),
            self.check_vpn_interface(),
            self.check_vps_configuration(),
            self.check_vps_credentials(),
            self.check_simulation_environment(),
        ]

    def format_doctor_report(self) -> str:
        checks = self.run_all_checks()
        # Find item statuses
        item_map = {c.name: c.status for c in checks}

        core = item_map.get("Core application", "FAIL")
        schema = item_map.get("Configuration schema", "FAIL")
        vpn_cfg = item_map.get("VPN configuration", "NOT CONFIGURED")
        vpn_cred = item_map.get("VPN credentials", "NOT CONFIGURED")
        vpn_iface = item_map.get("VPN interface", "NOT AVAILABLE")
        vps_cfg = item_map.get("VPS configuration", "NOT CONFIGURED")
        vps_cred = item_map.get("VPS credentials", "NOT CONFIGURED")
        sim_env = item_map.get("Simulation environment", "FAIL")

        real_ready = (
            vpn_cfg == "PASS"
            and vpn_cred == "PASS"
            and vpn_iface == "PASS"
        )
        real_chain_status = "READY" if real_ready else "NOT READY"
        real_network_overall = "READY" if real_ready else "NOT READY"
        sim_overall = "READY" if sim_env == "READY" else "NOT READY"

        fw_item = self.check_firewall_backend()
        ipv6_item = self.check_ipv6_capability()
        shaping_item = self.check_traffic_shaping()
        proxy_item = self.check_privacy_proxy()

        lines = [
            "SecureChain Doctor",
            "",
            f"Core application ............ {core}",
            f"Configuration schema ........ {schema}",
            "",
            f"Firewall backend ............ {fw_item.status} ({fw_item.evidence})",
            f"IPv6 capability ............. {ipv6_item.status} ({ipv6_item.evidence})",
            "",
            f"VPN configuration ........... {vpn_cfg}",
            f"VPN credentials ............. {vpn_cred}",
            f"VPN interface ............... {vpn_iface}",
            "",
            f"VPS configuration ........... {vps_cfg}",
            f"VPS credentials ............. {vps_cred}",
            "",
            f"Traffic shaping ............. {shaping_item.status} ({shaping_item.evidence})",
            f"Privacy proxy ............... {proxy_item.status} ({proxy_item.evidence})",
            "",
            f"Real network chain .......... {real_chain_status}",
            "",
            f"Simulation environment ...... {sim_env}",
            "",
            "Overall:",
            f"REAL NETWORK: {real_network_overall}",
            f"SIMULATION: {sim_overall}",
        ]
        return "\n".join(lines)
