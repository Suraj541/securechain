"""Integration tests for SecureChain CLI commands (P14)."""

import pytest
from typer.testing import CliRunner
from securechain.cli.app import app

runner = CliRunner()


def test_cli_version_and_help():
    res_help = runner.invoke(app, ["--help"])
    assert res_help.exit_code == 0
    assert "SecureChain" in res_help.output

    res_ver = runner.invoke(app, ["--version"])
    assert res_ver.exit_code == 0
    assert "1.0.0" in res_ver.output


def test_cli_config_validate():
    res = runner.invoke(app, ["config", "validate"])
    assert res.exit_code == 0
    assert "Configuration is valid" in res.output


def test_cli_credentials_commands():
    res_stat = runner.invoke(app, ["credentials", "status"])
    assert res_stat.exit_code == 0
    assert "Credential Backend" in res_stat.output

    res_val = runner.invoke(app, ["credentials", "validate"])
    assert res_val.exit_code == 0
    assert "securely encrypted" in res_val.output


def test_cli_kill_switch_commands():
    res_stat = runner.invoke(app, ["kill-switch", "status"])
    assert res_stat.exit_code == 0

    res_en = runner.invoke(app, ["kill-switch", "enable"])
    assert res_en.exit_code == 0
    assert "ENGAGED" in res_en.output

    res_dis = runner.invoke(app, ["kill-switch", "disable"])
    assert res_dis.exit_code == 0
    assert "DISABLED" in res_dis.output


def test_cli_doctor_command():
    res = runner.invoke(app, ["doctor"])
    assert res.exit_code == 0
    assert "SecureChain Doctor" in res.output
    assert "VPN configuration ........... NOT CONFIGURED" in res.output
    assert "REAL NETWORK: NOT READY" in res.output
    assert "SIMULATION: READY" in res.output


def test_cli_start_real_mode_fails_when_unconfigured():
    res = runner.invoke(app, ["start", "--hops", "3", "--mode", "real"])
    assert res.exit_code == 1
    assert "Real network infrastructure is NOT CONFIGURED" in res.output


def test_cli_start_status_health_paths_routes_stop_lifecycle():
    # 1. Start with 3 hops in simulation mode
    res_start = runner.invoke(app, ["start", "--hops", "3", "--mode", "simulation"])
    assert res_start.exit_code == 0
    assert "SIMULATION MODE" in res_start.output
    assert "SIMULATED" in res_start.output

    # 2. Status
    res_status = runner.invoke(app, ["status"])
    assert res_status.exit_code == 0
    assert "SIMULATION" in res_status.output
    assert "chain-3hop" in res_status.output
    assert "NO (SIMULATED ONLY)" in res_status.output

    # 3. Health
    res_health = runner.invoke(app, ["health"])
    assert res_health.exit_code == 0
    assert "SecureChain Health" in res_health.output
    assert "SIMULATION" in res_health.output

    # 4. Paths
    res_paths = runner.invoke(app, ["paths"])
    assert res_paths.exit_code == 0
    assert "Candidate Network Paths" in res_paths.output

    # 5. Routes
    res_routes = runner.invoke(app, ["routes"])
    assert res_routes.exit_code == 0
    assert "0.0.0.0/1" in res_routes.output

    # 6. Diagnostics
    res_diag = runner.invoke(app, ["diagnostics"])
    assert res_diag.exit_code == 0

    # 7. Logs
    res_logs = runner.invoke(app, ["logs", "--tail", "10"])
    assert res_logs.exit_code == 0

    # 8. Stop
    res_stop = runner.invoke(app, ["stop"])
    assert res_stop.exit_code == 0
    assert "dismantled" in res_stop.output


def test_cli_test_command():
    res_test = runner.invoke(app, ["test", "security"])
    assert res_test.exit_code == 0
    assert "Core Software: PASS" in res_test.output
    assert "Simulation: PASS" in res_test.output
    assert "Real Network Validation: NOT CONFIGURED" in res_test.output


def test_cli_simulate_command():
    res_sim = runner.invoke(app, ["simulate", "--scenario", "healthy"])
    assert res_sim.exit_code == 0
    assert "PASS" in res_sim.output
