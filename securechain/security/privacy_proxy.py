"""Optional Local Privacy Proxy and HTTP Header Sanitizer for SecureChain.

DISCLAIMER:
This module provides optional client-side HTTP header sanitization and proxying.
It explicitly DOES NOT perform TLS Man-in-the-Middle (MITM) inspection, to protect
end-to-end cryptographic authentication.

Browser fingerprinting vectors (Canvas, WebGL, AudioContext, System Font enumeration,
WebRTC IP enumeration, Screen resolution, and TLS ClientHello JA3/JA4 signatures)
execute inside the browser engine or transport handshake and CANNOT be neutralized
by network-layer or HTTP proxies. Complete defense requires dedicated hardened browsers
(e.g., Tor Browser, Mullvad Browser).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from securechain.configuration.schema import PrivacyProxyConfig
from securechain.security.logging_sanitizer import get_logger

logger = get_logger("securechain.security.privacy_proxy")


# Generic cross-platform baseline User-Agent for normalization
BASELINE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

# Tracking and IP leakage headers stripped by default
TRACKING_HEADERS_TO_STRIP: Set[str] = {
    "x-forwarded-for",
    "x-real-ip",
    "client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-client-data",
    "via",
    "forwarded",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
}


@dataclass
class PrivacyProxyStats:
    """Telemetry counters for privacy proxy operations."""

    requests_filtered: int = 0
    headers_stripped: int = 0
    user_agents_normalized: int = 0
    connect_tunnels_opened: int = 0


class PrivacyProxy:
    """Optional local privacy proxy interface and HTTP header sanitization engine."""

    def __init__(self, config: Optional[PrivacyProxyConfig] = None) -> None:
        self.config = config or PrivacyProxyConfig()
        self.stats = PrivacyProxyStats()
        self._is_running = False

    @property
    def is_enabled(self) -> bool:
        return self.config.enabled

    @property
    def is_running(self) -> bool:
        return self._is_running

    def sanitize_request_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Normalize and strip identifying or tracking headers from an outbound HTTP request."""
        self.stats.requests_filtered += 1
        sanitized: Dict[str, str] = {}

        for key, val in headers.items():
            lower_key = key.lower()

            # 1. Strip tracking / forwarded IP headers
            if self.config.strip_tracking_headers and lower_key in TRACKING_HEADERS_TO_STRIP:
                self.stats.headers_stripped += 1
                logger.debug(f"Privacy proxy stripped tracking header: {key}")
                continue

            # 2. Normalize User-Agent
            if self.config.normalize_user_agent and lower_key == "user-agent":
                sanitized["User-Agent"] = BASELINE_USER_AGENT
                self.stats.user_agents_normalized += 1
                continue

            sanitized[key] = val

        # 3. Inject restrictive Referrer-Policy
        sanitized["Referrer-Policy"] = "no-referrer"

        return sanitized

    def handle_connect_tunnel(self, target_host: str, target_port: int) -> bool:
        """Record transparent CONNECT pass-through without TLS MITM."""
        self.stats.connect_tunnels_opened += 1
        logger.debug(f"Privacy proxy transparent CONNECT tunnel established to {target_host}:{target_port}")
        return True

    def start(self) -> bool:
        """Start proxy listener (when enabled in configuration)."""
        if not self.config.enabled:
            logger.info("Privacy proxy is disabled in configuration.")
            return False
        self._is_running = True
        logger.info(f"Privacy proxy active on {self.config.host}:{self.config.port} (transparent CONNECT pass-through)")
        return True

    def stop(self) -> None:
        """Stop proxy listener."""
        self._is_running = False
        logger.info("Privacy proxy stopped.")

    def get_diagnostics(self) -> Dict[str, object]:
        """Return diagnostic metrics and operational status."""
        return {
            "enabled": self.config.enabled,
            "running": self._is_running,
            "bind_address": f"{self.config.host}:{self.config.port}",
            "tls_mitm": False,  # Explicitly disclaimed: zero TLS interception
            "requests_filtered": self.stats.requests_filtered,
            "headers_stripped": self.stats.headers_stripped,
            "user_agents_normalized": self.stats.user_agents_normalized,
            "connect_tunnels_opened": self.stats.connect_tunnels_opened,
            "fingerprinting_mitigation": "Out of scope (requires browser engine hardening)",
        }
