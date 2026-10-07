"""Health and Telemetry Monitoring Engine for SecureChain."""

from typing import List, Optional

from securechain.core.chain_manager import Chain, MultiHopChainManager
from securechain.monitoring.metrics import ComponentHealth, ComponentStatus, SystemHealthReport
from securechain.networking.dns.manager import DnsManager
from securechain.networking.firewall.kill_switch import KillSwitch, KillSwitchState
from securechain.networking.ipv6.controller import Ipv6Controller, Ipv6Status
from securechain.networking.routing.controller import RoutingController
from securechain.networking.vps.termination import VpsTerminationLayer
from securechain.providers.base import TunnelState
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.monitoring.monitor")


class HealthMonitor:
    """Continuously monitors VPN tunnels, VPS, routing integrity, DNS, IPv6, and Kill Switch."""

    def __init__(
        self,
        chain_manager: MultiHopChainManager,
        routing_controller: RoutingController,
        kill_switch: KillSwitch,
        dns_manager: DnsManager,
        ipv6_controller: Ipv6Controller,
        vps_layer: Optional[VpsTerminationLayer] = None,
    ) -> None:
        self.chain_manager = chain_manager
        self.routing = routing_controller
        self.kill_switch = kill_switch
        self.dns = dns_manager
        self.ipv6 = ipv6_controller
        self.vps = vps_layer

    def probe(self) -> SystemHealthReport:
        """Execute a full diagnostic telemetry probe across all components."""
        components: List[ComponentHealth] = []
        overall = ComponentStatus.HEALTHY

        total_lat = 0.0
        max_loss = 0.0
        total_jit = 0.0
        hop_count = 0

        # 1. Probe VPN Tunnels
        active_chain = self.chain_manager.active_chain
        if active_chain and active_chain.is_active:
            for node in active_chain.hops:
                hop_count += 1
                metric = node.provider.health_check()
                status_obj = node.provider.status()

                comp_status = ComponentStatus.HEALTHY
                details = f"State: {status_obj.state.value}"

                if not metric.is_reachable or status_obj.state == TunnelState.FAILED:
                    comp_status = ComponentStatus.FAILED
                    details = status_obj.last_error or "Tunnel unreachable"
                    overall = ComponentStatus.FAILED
                elif status_obj.state == TunnelState.DEGRADED or metric.packet_loss_pct > 10.0 or metric.latency_ms > 200.0:
                    comp_status = ComponentStatus.DEGRADED
                    details = f"Elevated latency/loss (loss: {metric.packet_loss_pct}%)"
                    if overall != ComponentStatus.FAILED:
                        overall = ComponentStatus.DEGRADED

                total_lat += metric.latency_ms if metric.is_reachable else 500.0
                max_loss = max(max_loss, metric.packet_loss_pct)
                total_jit += metric.jitter_ms if metric.is_reachable else 50.0

                components.append(
                    ComponentHealth(
                        name=f"VPN-{node.hop_index:02d} ({node.config.tunnel_id})",
                        status=comp_status,
                        details=details,
                        latency_ms=metric.latency_ms,
                        packet_loss_pct=metric.packet_loss_pct,
                        jitter_ms=metric.jitter_ms,
                    )
                )
        else:
            components.append(
                ComponentHealth(
                    name="VPN Chain",
                    status=ComponentStatus.FAILED,
                    details="No active VPN chain established",
                )
            )
            overall = ComponentStatus.FAILED

        # 2. Probe VPS Layer (if present)
        if self.vps:
            vps_stat = self.vps.status()
            vps_metric = self.vps.health_check()
            vps_status = ComponentStatus.HEALTHY
            vps_details = f"Endpoint: {vps_stat.endpoint}"

            if not vps_metric.is_reachable or vps_stat.state == TunnelState.FAILED:
                vps_status = ComponentStatus.FAILED
                vps_details = vps_stat.last_error or "VPS endpoint unreachable"
                overall = ComponentStatus.FAILED
            elif vps_metric.latency_ms > 250.0 or vps_metric.packet_loss_pct > 10.0:
                vps_status = ComponentStatus.DEGRADED
                vps_details = "Elevated VPS latency"
                if overall != ComponentStatus.FAILED:
                    overall = ComponentStatus.DEGRADED

            total_lat += vps_metric.latency_ms if vps_metric.is_reachable else 500.0
            max_loss = max(max_loss, vps_metric.packet_loss_pct)
            total_jit += vps_metric.jitter_ms if vps_metric.is_reachable else 50.0

            components.append(
                ComponentHealth(
                    name="VPS Exit",
                    status=vps_status,
                    details=vps_details,
                    latency_ms=vps_metric.latency_ms,
                    packet_loss_pct=vps_metric.packet_loss_pct,
                    jitter_ms=vps_metric.jitter_ms,
                )
            )

        # 3. Routing Check
        routing_check = "PASS"
        if active_chain and active_chain.is_active:
            expected_gw = ""
            if self.vps and self.vps.status().state == TunnelState.CONNECTED:
                expected_gw = self.vps.config.gateway_ip
            elif active_chain.hops[-1].interface:
                expected_gw = active_chain.hops[-1].interface.gateway_ip

            if not self.routing.verify_route("0.0.0.0/1", expected_gw):
                routing_check = "FAIL"
                overall = ComponentStatus.FAILED
        else:
            routing_check = "FAIL"

        # 4. DNS Check
        dns_check = "PASS"
        canary = self.dns.test_dns_leak("health.securechain.internal")
        if canary.is_leak:
            dns_check = "FAIL"
            overall = ComponentStatus.FAILED

        # 5. IPv6 Check
        ipv6_check = "PASS"
        probe = self.ipv6.probe_leak()
        if not probe.is_contained:
            ipv6_check = "FAIL"
            overall = ComponentStatus.FAILED

        # 6. Kill Switch
        ks_state = self.kill_switch.get_state().value
        if ks_state == KillSwitchState.DISABLED.value and overall == ComponentStatus.HEALTHY:
            # When active, kill switch should not be completely disabled
            overall = ComponentStatus.DEGRADED

        return SystemHealthReport(
            overall_status=overall,
            components=components,
            routing_check=routing_check,
            dns_check=dns_check,
            ipv6_check=ipv6_check,
            kill_switch_state=ks_state,
            aggregate_latency_ms=round(total_lat, 2),
            aggregate_loss_pct=round(max_loss, 2),
            aggregate_jitter_ms=round(total_jit, 2),
        )
