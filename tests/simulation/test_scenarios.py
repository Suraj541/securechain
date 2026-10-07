"""Tests for Simulation Environment across 10 scenarios and 50 executions (P12)."""

import pytest
from securechain.simulation.scenarios import SimulationHarness


@pytest.mark.parametrize("scenario_name", SimulationHarness.SUPPORTED_SCENARIOS)
def test_simulation_scenarios_deterministic_five_runs(scenario_name: str):
    """P12 requirement: 10 scenario types x 5 executions per scenario = 50 simulation executions."""
    harness = SimulationHarness()

    for run_idx in range(5):
        seed = 100 + run_idx
        result = harness.run_scenario(scenario_name, seed=seed)
        assert result.success is True, (
            f"Scenario '{scenario_name}' failed on run {run_idx} (seed {seed}): {result.details}"
        )
        assert result.execution_time_ms > 0.0
