"""Pytest suite executing the comprehensive Security Test Suite with 3-mode verification."""

import pytest
from securechain.security.suite_runner import SecuritySuiteRunner
from securechain.security.test_framework import TestMode, TestStatus, TestSummary


def test_full_security_suite_strict_mode_separation():
    runner = SecuritySuiteRunner()
    results = runner.run_all()

    assert len(results) == 17

    unit_results = [r for r in results if r.mode == TestMode.UNIT]
    sim_results = [r for r in results if r.mode == TestMode.SIMULATION]
    real_results = [r for r in results if r.mode == TestMode.REAL]

    assert len(unit_results) == 4
    for r in unit_results:
        assert r.status == TestStatus.PASS, f"Unit test failed: {r.test_name}"

    assert len(sim_results) == 7
    for r in sim_results:
        assert r.status == TestStatus.SIMULATED, f"Simulation test failed: {r.test_name}"

    assert len(real_results) == 6
    for r in real_results:
        assert r.status in (
            TestStatus.NOT_CONFIGURED,
            TestStatus.NOT_AVAILABLE,
            TestStatus.NOT_TESTED,
        ), f"Real test should not pass without configuration: {r.test_name}"

    summary = TestSummary.from_provenance_list(results)
    assert summary.unit_failed == 0
    assert summary.simulation_failed == 0
    assert summary.real_passed == 0  # Zero false positives on unconfigured real hardware!

    all_passed = runner.print_formatted_report(results)
    assert all_passed is True
