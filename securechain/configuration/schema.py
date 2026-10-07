"""Configuration schema and validation models for SecureChain."""

from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class ApplicationConfig(BaseModel):
    name: str = "SecureChain"
    version: str = "1.0.0"

    model_config = {"extra": "forbid"}


class ChainConfig(BaseModel):
    min_hops: int = Field(default=2, ge=2, le=10, description="Minimum allowable VPN hops")
    max_hops: int = Field(default=10, ge=2, le=10, description="Maximum allowable VPN hops")
    default_hops: int = Field(default=3, ge=2, le=10, description="Default hops when unspecified")

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def validate_hop_bounds(self) -> "ChainConfig":
        if self.min_hops > self.max_hops:
            raise ValueError(f"min_hops ({self.min_hops}) cannot exceed max_hops ({self.max_hops})")
        if not (self.min_hops <= self.default_hops <= self.max_hops):
            raise ValueError(
                f"default_hops ({self.default_hops}) must be between min_hops ({self.min_hops}) and max_hops ({self.max_hops})"
            )
        return self


class SecurityConfig(BaseModel):
    kill_switch: bool = True
    dns_protection: bool = True
    ipv6_protection: bool = True
    ipv6_strategy: Literal["block", "tunnel", "auto_capability"] = "block"

    model_config = {"extra": "forbid"}


class PathWeightsConfig(BaseModel):
    latency: float = Field(default=0.35, ge=0.0, le=1.0)
    loss: float = Field(default=0.30, ge=0.0, le=1.0)
    jitter: float = Field(default=0.15, ge=0.0, le=1.0)
    failure_rate: float = Field(default=0.20, ge=0.0, le=1.0)

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def validate_weights_sum(self) -> "PathWeightsConfig":
        total = self.latency + self.loss + self.jitter + self.failure_rate
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Path quality weights must sum to 1.0 (current sum: {total:.4f})")
        return self


class PathSelectionConfig(BaseModel):
    evaluation_interval_seconds: float = Field(default=10.0, gt=0.0, le=3600.0)
    minimum_switch_interval_seconds: float = Field(default=60.0, ge=0.0, le=3600.0)
    improvement_threshold_percent: float = Field(default=15.0, ge=0.0, le=100.0)
    stability_window_seconds: float = Field(default=30.0, ge=0.0, le=3600.0)
    require_ipv6: bool = Field(default=False, description="Reject candidate paths containing IPv4-only hops")
    weights: PathWeightsConfig = Field(default_factory=PathWeightsConfig)

    model_config = {"extra": "forbid"}


class RecoveryConfig(BaseModel):
    max_attempts: int = Field(default=3, ge=1, le=10)
    backoff_seconds: float = Field(default=5.0, ge=0.5, le=120.0)
    path_reselection: bool = True

    model_config = {"extra": "forbid"}


class VpsConfig(BaseModel):
    enabled: bool = False
    endpoint: Optional[str] = None
    protocol: Optional[Literal["wireguard", "openvpn", "ssh_socks5"]] = None

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def validate_vps_requirements(self) -> "VpsConfig":
        if self.enabled:
            if not self.endpoint:
                raise ValueError("VPS endpoint must be specified when vps.enabled is True")
            if not self.protocol:
                raise ValueError("VPS protocol must be specified when vps.enabled is True")
        return self


class TrafficShapingConfig(BaseModel):
    """Optional traffic shaping and padding configuration."""

    enabled: bool = False
    mode: Literal["disabled", "low", "balanced", "high"] = "disabled"
    padding: Literal["none", "bucket", "adaptive", "fixed_mtu"] = "adaptive"
    jitter_ms: float = Field(default=10.0, ge=0.0, le=500.0)
    batching_ms: float = Field(default=0.0, ge=0.0, le=100.0)

    model_config = {"extra": "forbid"}


class PrivacyProxyConfig(BaseModel):
    """Optional local application privacy proxy configuration."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8118, ge=1024, le=65535)
    strip_tracking_headers: bool = True
    normalize_user_agent: bool = True

    model_config = {"extra": "forbid"}


class PrivacyConfig(BaseModel):
    """Privacy profile and optional privacy enhancement extensions."""

    profile: Literal["standard", "enhanced", "high"] = "standard"
    traffic_shaping: TrafficShapingConfig = Field(default_factory=TrafficShapingConfig)
    proxy: PrivacyProxyConfig = Field(default_factory=PrivacyProxyConfig)

    model_config = {"extra": "forbid"}


class SecureChainConfig(BaseModel):
    application: ApplicationConfig = Field(default_factory=ApplicationConfig)
    chain: ChainConfig = Field(default_factory=ChainConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    path_selection: PathSelectionConfig = Field(default_factory=PathSelectionConfig)
    recovery: RecoveryConfig = Field(default_factory=RecoveryConfig)
    vps: VpsConfig = Field(default_factory=VpsConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)

    model_config = {"extra": "forbid"}
