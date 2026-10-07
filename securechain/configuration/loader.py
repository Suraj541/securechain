"""Configuration loader and validator for SecureChain."""

from pathlib import Path
from typing import Any, Dict, Optional, Union
import yaml
from pydantic import ValidationError

from securechain.configuration.schema import SecureChainConfig
from securechain.core.exceptions import ConfigurationError


def load_config(config_source: Optional[Union[str, Path, Dict[str, Any]]] = None) -> SecureChainConfig:
    """Load and validate SecureChain configuration from file or dict.

    If config_source is None, returns the default configuration.
    """
    if config_source is None:
        return SecureChainConfig()

    data: Dict[str, Any] = {}

    if isinstance(config_source, dict):
        data = config_source
    else:
        path = Path(config_source)
        if not path.is_file():
            raise ConfigurationError(f"Configuration file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                data = loaded if isinstance(loaded, dict) else {}
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Failed to parse YAML configuration: {exc}") from exc
        except Exception as exc:
            raise ConfigurationError(f"Error reading configuration file: {exc}") from exc

    try:
        return SecureChainConfig(**data)
    except ValidationError as exc:
        formatted_errors = []
        for error in exc.errors():
            loc = ".".join(str(p) for p in error.get("loc", []))
            msg = error.get("msg", "invalid")
            formatted_errors.append(f"Field '{loc}': {msg}")
        raise ConfigurationError("Configuration validation failed:\n  - " + "\n  - ".join(formatted_errors)) from exc


def export_default_config(destination_path: Union[str, Path]) -> Path:
    """Generate and write default YAML configuration file."""
    config = SecureChainConfig()
    path = Path(destination_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    config_dict = config.model_dump()
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
    return path
