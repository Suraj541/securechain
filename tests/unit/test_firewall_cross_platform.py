"""Unit tests for Cross-Platform Firewall Abstraction (Linux nftables, macOS pf, Windows netsh, Virtual)."""

import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest
from securechain.networking.firewall.kill_switch import (
    CrossPlatformFirewallManager,
    KillSwitchError,
    KillSwitchState,
    LinuxNftablesKillSwitch,
    MacOsPfKillSwitch,
    VirtualKillSwitch,
    WindowsKillSwitch,
)


def test_cross_platform_manager_selection():
    """Verify backend factory selects appropriate engine based on host platform."""
    with patch("sys.platform", "win32"):
        mgr_win = CrossPlatformFirewallManager(backend_override=None)
        assert isinstance(mgr_win.backend, WindowsKillSwitch)

    with patch("sys.platform", "linux"):
        mgr_lin = CrossPlatformFirewallManager(backend_override=None)
        assert isinstance(mgr_lin.backend, LinuxNftablesKillSwitch)

    with patch("sys.platform", "darwin"):
        mgr_mac = CrossPlatformFirewallManager(backend_override=None)
        assert isinstance(mgr_mac.backend, MacOsPfKillSwitch)

    with patch("sys.platform", "unknown_os"):
        mgr_virt = CrossPlatformFirewallManager(backend_override=None)
        assert isinstance(mgr_virt.backend, VirtualKillSwitch)

    # Explicit override to virtual
    mgr_forced = CrossPlatformFirewallManager(backend_override="virtual")
    assert isinstance(mgr_forced.backend, VirtualKillSwitch)


def test_linux_nftables_rules_and_lifecycle():
    """Verify Linux nftables isolated table usage, rules, and safe restoration."""
    executed_commands = []

    def mock_run(cmd, *args, **kwargs):
        executed_commands.append(cmd)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_run), \
         patch("shutil.which", return_value="/usr/sbin/nft"), \
         patch("os.geteuid", return_value=0, create=True), \
         patch("sys.platform", "linux"):

        ks = LinuxNftablesKillSwitch()
        assert ks.is_native_available is True

        diag = ks.get_diagnostics()
        assert "nftables" in diag["backend"]
        assert diag["platform"] == "linux"
        assert diag["nft_installed"] is True
        assert diag["is_root"] is True

        # Enable lockdown
        ks.enable()
        assert ks.get_state() == KillSwitchState.ENGAGED

        # Verify base isolated table and rules were applied
        cmd_strings = [" ".join(c) if isinstance(c, list) else str(c) for c in executed_commands]
        assert any("add table inet securechain" in s for s in cmd_strings)
        assert any("oifname" in s and "lo" in s and "accept" in s for s in cmd_strings)
        assert any("policy drop" in s for s in cmd_strings)

        # Allow Hop 1 endpoint
        executed_commands.clear()
        ks.allow_hop1_endpoint("198.51.100.10", 51820)
        assert ks._hop1_endpoint == ("198.51.100.10", 51820)
        cmd_strings = [" ".join(c) if isinstance(c, list) else str(c) for c in executed_commands]
        assert any("198.51.100.10" in s and "51820" in s for s in cmd_strings)

        # Allow tunnel interface
        executed_commands.clear()
        ks.set_active_exit_interface("wg0")
        assert ks.get_state() == KillSwitchState.FILTERED_PASS
        assert ks._exit_iface == "wg0"
        cmd_strings = [" ".join(c) if isinstance(c, list) else str(c) for c in executed_commands]
        assert any("oifname wg0 accept" in s for s in cmd_strings)

        # Safe disable / teardown
        executed_commands.clear()
        ks.disable()
        assert ks.get_state() == KillSwitchState.DISABLED
        cmd_strings = [" ".join(c) if isinstance(c, list) else str(c) for c in executed_commands]
        assert any("delete table inet securechain" in s for s in cmd_strings)


def test_linux_nftables_command_failure_handling():
    """Verify that command execution errors fail safely into virtual lockdown."""
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, ["nft"], stderr="Permission denied")), \
         patch("shutil.which", return_value="/usr/sbin/nft"), \
         patch("os.geteuid", return_value=0, create=True), \
         patch("sys.platform", "linux"):

        ks = LinuxNftablesKillSwitch()
        # When native nft command fails, raises KillSwitchError and engages virtual fallback
        with pytest.raises(KillSwitchError):
            ks.enable()
        assert ks.get_state() == KillSwitchState.ENGAGED


def test_macos_pf_anchor_and_lifecycle():
    """Verify macOS pf isolated anchor usage, rules, and safe restoration."""
    executed_commands = []

    def mock_run(cmd, *args, **kwargs):
        executed_commands.append(cmd)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=mock_run), \
         patch("shutil.which", return_value="/sbin/pfctl"), \
         patch("os.geteuid", return_value=0, create=True), \
         patch("sys.platform", "darwin"):

        ks = MacOsPfKillSwitch()
        assert ks.is_native_available is True

        diag = ks.get_diagnostics()
        assert "pf" in diag["backend"]
        assert diag["platform"] == "darwin"
        assert diag["pfctl_installed"] is True

        # Enable lockdown
        ks.enable()
        assert ks.get_state() == KillSwitchState.ENGAGED

        # Allow Hop 1 endpoint
        executed_commands.clear()
        ks.allow_hop1_endpoint("203.0.113.5", 51820)
        assert ks._hop1_endpoint == ("203.0.113.5", 51820)

        # Set exit interface
        ks.set_active_exit_interface("utun3")
        assert ks.get_state() == KillSwitchState.FILTERED_PASS

        # Safe disable / flush only anchor
        executed_commands.clear()
        ks.disable()
        assert ks.get_state() == KillSwitchState.DISABLED
        cmd_strings = [" ".join(c) if isinstance(c, list) else str(c) for c in executed_commands]
        assert any("-a securechain -F all" in s for s in cmd_strings)


def test_cross_platform_manager_delegation():
    """Verify CrossPlatformFirewallManager properly wraps and delegates actions."""
    mgr = CrossPlatformFirewallManager(backend_override="virtual")
    assert mgr.get_state() == KillSwitchState.DISABLED

    mgr.enable()
    assert mgr.get_state() == KillSwitchState.ENGAGED

    mgr.allow_hop1_endpoint("198.51.100.1", 51820)
    mgr.set_active_exit_interface("vpn0")
    assert mgr.get_state() == KillSwitchState.FILTERED_PASS

    mgr.engage_lockdown()
    assert mgr.get_state() == KillSwitchState.ENGAGED

    mgr.disable()
    assert mgr.get_state() == KillSwitchState.DISABLED

    diag = mgr.get_diagnostics()
    assert "backend" in diag
