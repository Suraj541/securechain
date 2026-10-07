"""Integration tests for Health Monitoring engine (P8)."""

import pytest
from pydantic import SecretStr
from securechain.core.chain_manager import MultiHopChainManager
from securechain.monitoring.metrics import ComponentStatus
from securechain.monitoring.monitor import HealthMonitor
from securechain.networking.dns.manager import VirtualDnsManager
from securechain.networking.firewall.kill_switch import VirtualKillSwitch
from securechain.networking.ipv6.controller import VirtualIpv6Controller
from securechain.networking.routing.virtual_routing import VirtualRoutingController
from securechain.networking.vps.termination import SimulatedVpsTerminationLayer, VpsConfig


def setup_test_environment(with_vps: bool = False):
    routing = VirtualRoutingController()
    kill_switch = VirtualKillSwitch()
    dns = VirtualDnsManager()
    ipv6 = VirtualIpv6Controller()
    chain_mgr = MultiHopChainManager(routing, kill_switch, dns, ipv6)

    # Establish 3-hop chain
    chain = chain_mgr.connect_chain(3)

    vps = None
    if with_vps:
        vps_cfg = VpsConfig(
            endpoint="vps.test.internal:51820",
            protocol="wireguard",
            auth_token=SecretStr("vps_token_secret"),
        )
        vps = SimulatedVpsTerminationLayer(vps_cfg, routing, kill_switch)
        vps.connect(chain.hops[-1].interface.gateway_ip, chain.hops[-1].interface.name)

    monitor = HealthMonitor(chain_mgr, routing, kill_switch, dns, ipv6, vps)
    return monitor, chain_mgr, routing, kill_switch, dns, ipv6, vps


def test_nominal_all_healthy():
    monitor, chain_mgr, routing, kill_switch, dns, ipv6, vps = setup_test_environment(with_vps=True)
    report = monitor.probe()

    assert report.overall_status == ComponentStatus.HEALTHY
    assert report.routing_check == "PASS"
    assert report.dns_check == "PASS"
    assert report.ipv6_check == "PASS"
    assert report.kill_switch_state == "FILTERED_PASS"
    assert report.aggregate_latency_ms > 0.0

    chain_mgr.teardown_chain()


def test_vpn_failure_detection():
    monitor, chain_mgr, routing, kill_switch, dns, ipv6, _ = setup_test_environment()

    # INJECT FAILURE into Hop 2
    chain_mgr.active_chain.hops[1].provider.inject_failure("Simulated carrier lost")

    report = monitor.probe()
    assert report.overall_status == ComponentStatus.FAILED
    assert any(c.status == ComponentStatus.FAILED and "hop-02" in c.name for c in report.components)

    chain_mgr.teardown_chain()


def test_vps_failure_detection():
    monitor, chain_mgr, routing, kill_switch, dns, ipv6, vps = setup_test_environment(with_vps=True)

    # INJECT FAILURE into VPS
    vps.inject_failure("VPS peer ping timeout")

    report = monitor.probe()
    assert report.overall_status == ComponentStatus.FAILED
    assert any(c.status == ComponentStatus.FAILED and "VPS" in c.name for c in report.components)

    chain_mgr.teardown_chain()


def test_degraded_telemetry_detection():
    monitor, chain_mgr, routing, kill_switch, dns, ipv6, _ = setup_test_environment()

    # INJECT DEGRADATION: 250ms latency, 15% loss
    chain_mgr.active_chain.hops[0].provider.inject_degradation(latency_ms=250.0, loss_pct=15.0, jitter_ms=25.0)

    report = monitor.probe()
    assert report.overall_status == ComponentStatus.DEGRADED
    assert any(c.status == ComponentStatus.DEGRADED for c in report.components)

    chain_mgr.teardown_chain()


def test_dns_leak_detection_in_monitor():
    monitor, chain_mgr, routing, kill_switch, dns, ipv6, _ = setup_test_environment()

    # INJECT DNS LEAK
    dns.inject_dns_leak("192.168.1.1")

    report = monitor.probe()
    assert report.dns_check == "FAIL"
    assert report.overall_status == ComponentStatus.FAILED

    chain_mgr.teardown_chain()


def test_ipv6_leak_detection_in_monitor():
    monitor, chain_mgr, routing, kill_switch, dns, ipv6, _ = setup_test_environment()

    # INJECT IPv6 LEAK
    ipv6.inject_ipv6_leak()

    report = monitor.probe()
    assert report.ipv6_check == "FAIL"
    assert report.overall_status == ComponentStatus.FAILED

    chain_mgr.teardown_chain()
