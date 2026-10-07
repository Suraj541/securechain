"""Multi-Hop Chain Orchestration Engine for SecureChain."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import SecretStr

from securechain.core.exceptions import TunnelConnectionError, TunnelVerificationError
from securechain.networking.dns.manager import DnsManager
from securechain.networking.firewall.kill_switch import KillSwitch, KillSwitchState
from securechain.networking.ipv6.controller import Ipv6Controller
from securechain.networking.routing.controller import RoutingController
from securechain.providers.base import (
    InterfaceInfo,
    TunnelConfig,
    TunnelState,
    TunnelStatus,
    VPNProvider,
)
from securechain.providers.simulated import SimulatedVPNProvider
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.core.chain_manager")


@dataclass
class HopNode:
    """Represents an individual hop in an active multi-hop chain."""

    hop_index: int  # 1-indexed
    config: TunnelConfig
    provider: VPNProvider
    interface: Optional[InterfaceInfo] = None
    status: Optional[TunnelStatus] = None


@dataclass
class Chain:
    """Represents an established or building multi-hop VPN chain."""

    chain_id: str
    hop_count: int
    hops: List[HopNode] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = False
    exit_interface: Optional[str] = None
    ipv6_enabled: bool = False
    ipv6_reason: str = "IPv6 fail-closed: unverified"


class MultiHopChainManager:
    """Orchestrates building, connecting, verifying, and tearing down multi-hop VPN chains."""

    def __init__(
        self,
        routing_controller: RoutingController,
        kill_switch: KillSwitch,
        dns_manager: DnsManager,
        ipv6_controller: Ipv6Controller,
    ) -> None:
        self.routing = routing_controller
        self.kill_switch = kill_switch
        self.dns = dns_manager
        self.ipv6 = ipv6_controller
        self._active_chain: Optional[Chain] = None

    @property
    def active_chain(self) -> Optional[Chain]:
        return self._active_chain

    def build_candidate_configs(
        self,
        hop_count: int,
        chain_prefix: str = "hop",
        supports_ipv6: bool = False,
    ) -> List[TunnelConfig]:
        """Generate validated synthetic tunnel configs for N hops with capability awareness."""
        configs: List[TunnelConfig] = []
        for i in range(1, hop_count + 1):
            cfg = TunnelConfig(
                tunnel_id=f"{chain_prefix}-{i:02d}",
                provider_type="simulated",
                endpoint_ip=f"198.51.{100 + i}.{10 + i}",
                endpoint_port=51820 + i,
                assigned_ip=f"10.8.{i}.2",
                gateway_ip=f"10.8.{i}.1",
                dns_server=f"10.8.{i}.1",
                supports_ipv4=True,
                supports_ipv6=supports_ipv6,
                assigned_ipv6=f"fd00:8:{i}::2" if supports_ipv6 else None,
                gateway_ipv6=f"fd00:8:{i}::1" if supports_ipv6 else None,
                public_key=f"PubKeyHop{i:02d}AbCdEfGhIjKlMnOpQrStUvWxYz01234==",
                private_key=SecretStr(f"PrivKeyHop{i:02d}sUPeRSeCReTKey12345678901234567=="),
                mtu=1420 - (i * 20),  # Encapsulation MTU accounting
            )
            configs.append(cfg)
        return configs

    def connect_chain(self, hop_count: int, configs: Optional[List[TunnelConfig]] = None) -> Chain:
        """Sequentially establish layered multi-hop VPN chain."""
        if not (2 <= hop_count <= 10):
            raise ValueError(f"Hop count must be between 2 and 10 (got {hop_count})")

        if not configs:
            configs = self.build_candidate_configs(hop_count)

        logger.info(f"Initiating multi-hop chain build for {hop_count} hops...")

        # 1. Engage Kill Switch lockdown during connection
        self.kill_switch.enable()

        # Pre-flight snapshots
        route_snap = self.routing.snapshot()
        default_gw = route_snap.default_gateway or "192.168.1.1"
        default_iface = route_snap.default_interface or "Ethernet0"

        chain = Chain(chain_id=f"chain-{hop_count}hop", hop_count=hop_count)
        connected_hops: List[HopNode] = []

        try:
            # 2. Sequential Layer-by-Layer Establishment
            for idx, cfg in enumerate(configs, start=1):
                provider = SimulatedVPNProvider(base_latency_ms=10.0 + (idx * 5.0))
                node = HopNode(hop_index=idx, config=cfg, provider=provider)

                # Configure host routing for this hop's endpoint
                dest_cidr = f"{cfg.endpoint_ip}/32"
                if idx == 1:
                    # Hop 1 endpoint routed via physical default gateway
                    self.routing.add_route(dest_cidr, default_gw, default_iface, metric=10)
                    self.kill_switch.allow_hop1_endpoint(cfg.endpoint_ip, cfg.endpoint_port)
                else:
                    # Hop i endpoint routed via Hop i-1 interface gateway
                    prev_node = connected_hops[-1]
                    prev_gw = prev_node.interface.gateway_ip if prev_node.interface else "10.8.1.1"
                    prev_iface = prev_node.interface.name if prev_node.interface else f"sim-hop-{idx-1:02d}"
                    self.routing.add_route(dest_cidr, prev_gw, prev_iface, metric=10)

                # Connect provider
                status = provider.connect(cfg)
                iface = provider.get_interface()
                node.interface = iface
                node.status = status
                connected_hops.append(node)
                chain.hops.append(node)

                # Verify hop reachability
                metric = provider.health_check()
                if not metric.is_reachable:
                    raise TunnelConnectionError(f"Hop {idx} ({cfg.tunnel_id}) failed reachability probe")

                logger.info(f"Hop {idx}/{hop_count} ({cfg.tunnel_id}) connected on {iface.name} ({iface.ip_address})")

            # 3. Final Hop Routing: Split Default Override (0.0.0.0/1 and 128.0.0.0/1)
            final_node = connected_hops[-1]
            final_gw = final_node.interface.gateway_ip if final_node.interface else "10.8.N.1"
            final_iface = final_node.interface.name if final_node.interface else f"sim-hop-{hop_count:02d}"

            self.routing.add_route("0.0.0.0/1", final_gw, final_iface, metric=5)
            self.routing.add_route("128.0.0.0/1", final_gw, final_iface, metric=5)

            # 4. Capability-Aware IPv6 & DNS Binding
            self.dns.set_tunnel_dns(final_node.config.dns_server, final_iface)

            # Evaluate end-to-end chain IPv6 capability
            all_ipv6 = all(node.config.supports_ipv6 for node in connected_hops)
            if all_ipv6 and len(connected_hops) > 0:
                logger.info("Capability check: All hops support IPv6. Enabling end-to-end IPv6 tunneling.")
                self.ipv6.enforce_strategy("tunnel")
                final_ipv6_gw = final_node.config.gateway_ipv6 or "fd00:8:1::1"
                self.routing.add_route("::/1", final_ipv6_gw, final_iface, metric=5)
                self.routing.add_route("8000::/1", final_ipv6_gw, final_iface, metric=5)
                chain.ipv6_enabled = True
                chain.ipv6_reason = "IPv6 enabled: All hops support IPv6 end-to-end."
            else:
                unsupported = [f"Hop {node.hop_index} ({node.config.tunnel_id})" for node in connected_hops if not node.config.supports_ipv6]
                reason = f"IPv6 disabled: {', '.join(unsupported)} does not support IPv6. External IPv6 blocked to prevent leak."
                logger.info(f"Capability check: {reason} Enforcing BLOCKED_FAIL_CLOSED.")
                self.ipv6.enforce_strategy("block")
                chain.ipv6_enabled = False
                chain.ipv6_reason = reason

            # 5. Set Kill Switch Exit Interface
            chain.exit_interface = final_iface
            chain.is_active = True
            self.kill_switch.set_active_exit_interface(final_iface)

            self._active_chain = chain
            logger.info(f"Successfully established {hop_count}-hop chain '{chain.chain_id}' via exit '{final_iface}' (IPv6: {chain.ipv6_reason})")
            return chain

        except Exception as exc:
            logger.error(f"Failed to connect multi-hop chain at step: {exc}. Rolling back...")
            # Teardown any connected hops and maintain lockdown
            for node in reversed(connected_hops):
                try:
                    node.provider.cleanup()
                except Exception:
                    pass
            self.routing.cleanup_temporary_routes()
            self.kill_switch.enable()  # Maintain fail-closed lockdown
            raise TunnelConnectionError(f"Multi-hop chain connection failed: {exc}") from exc

    def verify_chain(self, chain: Chain) -> bool:
        """Perform end-to-end verification of all chain layers, routing, DNS, and IPv6."""
        if not chain or not chain.is_active:
            return False

        # 1. Verify all hops report connected & healthy
        for node in chain.hops:
            stat = node.provider.status()
            if stat.state != TunnelState.CONNECTED:
                logger.error(f"Chain verification failed: Hop {node.hop_index} is {stat.state.value}")
                return False
            health = node.provider.health_check()
            if not health.is_reachable or health.packet_loss_pct > 50.0:
                logger.error(f"Chain verification failed: Hop {node.hop_index} health degraded")
                return False

        # 2. Verify split default routes exist
        final_node = chain.hops[-1]
        final_gw = final_node.interface.gateway_ip if final_node.interface else ""
        if not self.routing.verify_route("0.0.0.0/1", final_gw):
            logger.error("Chain verification failed: 0.0.0.0/1 route missing or incorrect gateway")
            return False
        if not self.routing.verify_route("128.0.0.0/1", final_gw):
            logger.error("Chain verification failed: 128.0.0.0/1 route missing or incorrect gateway")
            return False

        # 3. Verify DNS
        dns_res = self.dns.test_dns_leak("verify.securechain.internal")
        if dns_res.is_leak:
            logger.error("Chain verification failed: DNS query leaked!")
            return False

        # 4. Verify IPv6
        if chain.ipv6_enabled:
            final_ipv6_gw = chain.hops[-1].config.gateway_ipv6 or "fd00:8:1::1"
            if not self.routing.verify_route("::/1", final_ipv6_gw):
                logger.error("Chain verification failed: IPv6 ::/1 route missing or incorrect gateway")
                return False
        ipv6_probe = self.ipv6.probe_leak()
        if not ipv6_probe.is_contained:
            logger.error("Chain verification failed: IPv6 leak detected!")
            return False

        # 5. Verify Kill Switch state
        if self.kill_switch.get_state() != KillSwitchState.FILTERED_PASS:
            logger.error("Chain verification failed: Kill Switch is not in FILTERED_PASS")
            return False

        logger.info(f"Complete {chain.hop_count}-hop chain '{chain.chain_id}' verified successfully!")
        return True

    def teardown_chain(self, chain: Optional[Chain] = None) -> bool:
        """Gracefully and safely tear down the active multi-hop chain."""
        target = chain or self._active_chain
        if not target:
            return True

        logger.info(f"Tearing down multi-hop chain '{target.chain_id}'...")

        # 1. Engage lockdown to prevent teardown leaks
        self.kill_switch.enable()

        # 2. Cleanup routes
        self.routing.cleanup_temporary_routes()

        # 3. Disconnect providers in reverse order
        for node in reversed(target.hops):
            try:
                node.provider.disconnect()
                node.provider.cleanup()
            except Exception as exc:
                logger.warning(f"Error disconnecting Hop {node.hop_index}: {exc}")

        # 3.5 Re-enforce IPv6 fail-closed block
        self.ipv6.enforce_strategy("block")

        # 4. Disengage Kill Switch once physical network is clean
        self.kill_switch.disable()

        target.is_active = False
        target.exit_interface = None
        if self._active_chain == target:
            self._active_chain = None

        logger.info(f"Multi-hop chain '{target.chain_id}' successfully dismantled.")
        return True
