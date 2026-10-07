"""Unit tests for SecureChain configuration validation."""

import pytest
from pathlib import Path
from securechain.configuration.loader import load_config, export_default_config
from securechain.configuration.schema import SecureChainConfig
from securechain.core.exceptions import ConfigurationError


def test_default_config_validity():
    config = load_config()
    assert config.application.name == "SecureChain"
    assert config.chain.min_hops == 2
    assert config.chain.max_hops == 10
    assert config.chain.default_hops == 3
    assert config.security.kill_switch is True
    assert config.security.dns_protection is True
    assert config.security.ipv6_strategy == "block"
    assert config.vps.enabled is False


def test_custom_valid_config(tmp_path: Path):
    yaml_content = """
application:
  name: SecureChain
  version: "1.0.0"
chain:
  min_hops: 3
  max_hops: 7
  default_hops: 5
security:
  kill_switch: true
  dns_protection: true
  ipv6_strategy: block
path_selection:
  evaluation_interval_seconds: 15
  minimum_switch_interval_seconds: 90
  improvement_threshold_percent: 20
  stability_window_seconds: 45
  weights:
    latency: 0.40
    loss: 0.30
    jitter: 0.10
    failure_rate: 0.20
recovery:
  max_attempts: 4
  backoff_seconds: 6.0
  path_reselection: true
vps:
  enabled: true
  endpoint: "vpn.exit.securechain.org:51820"
  protocol: "wireguard"
"""
    cfg_file = tmp_path / "valid_config.yaml"
    cfg_file.write_text(yaml_content, encoding="utf-8")

    cfg = load_config(cfg_file)
    assert cfg.chain.min_hops == 3
    assert cfg.chain.max_hops == 7
    assert cfg.chain.default_hops == 5
    assert cfg.vps.enabled is True
    assert cfg.vps.protocol == "wireguard"


def test_invalid_hop_counts():
    # min_hops < 2
    with pytest.raises(ConfigurationError):
        load_config({"chain": {"min_hops": 1, "max_hops": 5, "default_hops": 3}})

    # max_hops > 10
    with pytest.raises(ConfigurationError):
        load_config({"chain": {"min_hops": 2, "max_hops": 15, "default_hops": 3}})

    # min_hops > max_hops
    with pytest.raises(ConfigurationError):
        load_config({"chain": {"min_hops": 6, "max_hops": 4, "default_hops": 5}})

    # default_hops outside bounds
    with pytest.raises(ConfigurationError):
        load_config({"chain": {"min_hops": 3, "max_hops": 6, "default_hops": 2}})


def test_invalid_path_weights_sum():
    # Sum != 1.0
    with pytest.raises(ConfigurationError):
        load_config({
            "path_selection": {
                "weights": {
                    "latency": 0.50,
                    "loss": 0.50,
                    "jitter": 0.20,
                    "failure_rate": 0.20,
                }
            }
        })


def test_vps_missing_endpoint():
    with pytest.raises(ConfigurationError):
        load_config({"vps": {"enabled": True, "protocol": "wireguard"}})


def test_extra_field_rejected():
    with pytest.raises(ConfigurationError):
        load_config({"unknown_root_key": "malicious"})


def test_nonexistent_file():
    with pytest.raises(ConfigurationError):
        load_config("nonexistent_path_file.yaml")


def test_export_and_reload_default(tmp_path: Path):
    dest = tmp_path / "exported.yaml"
    export_default_config(dest)
    assert dest.exists()
    reloaded = load_config(dest)
    assert reloaded.chain.default_hops == 3
