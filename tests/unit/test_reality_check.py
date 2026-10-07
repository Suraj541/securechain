"""Unit tests for RealityChecker and TestFramework provenance."""

import pytest
from securechain.core.reality_check import RealityChecker
from securechain.security.test_framework import (
    TestMode,
    TestProvenance,
    TestStatus,
    TestSummary,
)


def test_reality_checker_unconfigured_host():
    checker = RealityChecker()
    checks = checker.run_all_checks()

    check_map = {c.name: c for c in checks}

    # Core app and schema must pass
    assert check_map["Core application"].status == "PASS"
    assert check_map["Configuration schema"].status == "PASS"
    assert check_map["Simulation environment"].status == "READY"

    # Real infrastructure must NOT pass when unconfigured
    assert check_map["VPN configuration"].status == "NOT CONFIGURED"
    assert check_map["VPN credentials"].status == "NOT CONFIGURED"
    assert check_map["VPS configuration"].status == "NOT CONFIGURED"


def test_doctor_report_formatting():
    checker = RealityChecker()
    report = checker.format_doctor_report()

    assert "SecureChain Doctor" in report
    assert "Core application ............ PASS" in report
    assert "Configuration schema ........ PASS" in report
    assert "VPN configuration ........... NOT CONFIGURED" in report
    assert "VPN credentials ............. NOT CONFIGURED" in report
    assert "Real network chain .......... NOT READY" in report
    assert "Simulation environment ...... READY" in report
    assert "REAL NETWORK: NOT READY" in report
    assert "SIMULATION: READY" in report


def test_test_summary_aggregation():
    results = [
        TestProvenance("u1", TestMode.UNIT, TestStatus.PASS, "env"),
        TestProvenance("u2", TestMode.UNIT, TestStatus.PASS, "env"),
        TestProvenance("s1", TestMode.SIMULATION, TestStatus.SIMULATED, "env"),
        TestProvenance("r1", TestMode.REAL, TestStatus.NOT_CONFIGURED, "env"),
        TestProvenance("r2", TestMode.REAL, TestStatus.NOT_AVAILABLE, "env"),
    ]

    summary = TestSummary.from_provenance_list(results)
    assert summary.unit_passed == 2
    assert summary.simulation_passed == 1
    assert summary.real_passed == 0
    assert summary.real_not_configured == 1
    assert summary.real_not_available == 1

    text = summary.format_text()
    assert "SecureChain Test Summary" in text
    assert "REAL" in text
    assert "Passed: 0" in text
    assert "Not Configured: 1" in text
    assert "Core Software: PASS" in text
    assert "Simulation: PASS" in text
    assert "Real Network Validation: NOT CONFIGURED" in text
