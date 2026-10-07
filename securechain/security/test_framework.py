"""Test Framework for Strict Separation of REAL, SIMULATION, and UNIT Modes."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TestMode(str, Enum):
    """Execution mode of a test."""

    __test__ = False
    REAL = "REAL"
    SIMULATION = "SIMULATION"
    UNIT = "UNIT"


class TestStatus(str, Enum):
    """Result status of a test execution."""

    __test__ = False
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_CONFIGURED = "NOT CONFIGURED"
    NOT_AVAILABLE = "NOT AVAILABLE"
    NOT_TESTED = "NOT TESTED"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    SIMULATED = "SIMULATED"


@dataclass
class TestProvenance:
    """Detailed record and evidence provenance for an individual test."""

    __test__ = False
    test_name: str
    mode: TestMode
    status: TestStatus
    environment: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    evidence: Optional[str] = None
    details: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test": self.test_name,
            "mode": self.mode.value,
            "status": self.status.value,
            "environment": self.environment,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
            "details": self.details,
            "duration_ms": self.duration_ms,
        }

    @property
    def display_tag(self) -> str:
        if self.status == TestStatus.PASS:
            if self.mode == TestMode.UNIT:
                return "[UNIT PASS]"
            elif self.mode == TestMode.REAL:
                return "[PASS]"
            else:
                return "[SIMULATED PASS]"
        elif self.status == TestStatus.SIMULATED:
            return "[SIMULATED PASS]"
        elif self.status == TestStatus.NOT_CONFIGURED:
            return "[NOT CONFIGURED]"
        elif self.status == TestStatus.NOT_AVAILABLE:
            return "[NOT AVAILABLE]"
        elif self.status == TestStatus.NOT_TESTED:
            return "[NOT TESTED]"
        elif self.status == TestStatus.SKIPPED:
            return "[SKIPPED]"
        elif self.status == TestStatus.BLOCKED:
            return "[BLOCKED]"
        else:
            return "[FAIL]"


@dataclass
class TestSummary:
    """Aggregated test execution summary broken down by mode."""

    __test__ = False
    real_passed: int = 0
    real_failed: int = 0
    real_not_configured: int = 0
    real_not_available: int = 0
    real_not_tested: int = 0

    unit_passed: int = 0
    unit_failed: int = 0

    simulation_passed: int = 0
    simulation_failed: int = 0

    @classmethod
    def from_provenance_list(cls, results: List[TestProvenance]) -> "TestSummary":
        summary = cls()
        for r in results:
            if r.mode == TestMode.REAL:
                if r.status == TestStatus.PASS:
                    summary.real_passed += 1
                elif r.status == TestStatus.FAIL:
                    summary.real_failed += 1
                elif r.status == TestStatus.NOT_CONFIGURED:
                    summary.real_not_configured += 1
                elif r.status == TestStatus.NOT_AVAILABLE:
                    summary.real_not_available += 1
                elif r.status == TestStatus.NOT_TESTED:
                    summary.real_not_tested += 1
            elif r.mode == TestMode.UNIT:
                if r.status == TestStatus.PASS:
                    summary.unit_passed += 1
                else:
                    summary.unit_failed += 1
            elif r.mode == TestMode.SIMULATION:
                if r.status in (TestStatus.PASS, TestStatus.SIMULATED):
                    summary.simulation_passed += 1
                else:
                    summary.simulation_failed += 1
        return summary

    def format_text(self) -> str:
        lines = [
            "SecureChain Test Summary",
            "",
            "REAL",
            f"Passed: {self.real_passed}",
            f"Failed: {self.real_failed}",
            f"Not Configured: {self.real_not_configured}",
        ]
        if self.real_not_available > 0:
            lines.append(f"Not Available: {self.real_not_available}")
        if self.real_not_tested > 0:
            lines.append(f"Not Tested: {self.real_not_tested}")

        lines.extend([
            "",
            "UNIT",
            f"Passed: {self.unit_passed}",
            f"Failed: {self.unit_failed}",
            "",
            "SIMULATION",
            f"Passed: {self.simulation_passed}",
            f"Failed: {self.simulation_failed}",
            "",
            "Overall:",
            "",
            f"Core Software: {'PASS' if self.unit_failed == 0 and self.unit_passed > 0 else 'FAIL'}",
            f"Simulation: {'PASS' if self.simulation_failed == 0 and self.simulation_passed > 0 else 'FAIL'}",
            f"Real Network Validation: {'PASS' if self.real_failed == 0 and self.real_passed > 0 else 'NOT CONFIGURED'}",
        ])
        return "\n".join(lines)
