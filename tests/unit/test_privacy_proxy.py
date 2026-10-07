"""Unit tests for Optional Local Privacy Proxy and Header Sanitizer."""

import pytest
from securechain.configuration.schema import PrivacyProxyConfig
from securechain.security.privacy_proxy import (
    BASELINE_USER_AGENT,
    PrivacyProxy,
    TRACKING_HEADERS_TO_STRIP,
)


def test_privacy_proxy_disabled_by_default():
    """Verify privacy proxy is disabled by default."""
    proxy = PrivacyProxy()
    assert proxy.is_enabled is False
    assert proxy.is_running is False
    assert proxy.start() is False

    diag = proxy.get_diagnostics()
    assert diag["enabled"] is False
    assert diag["tls_mitm"] is False
    assert "Out of scope" in str(diag["fingerprinting_mitigation"])


def test_privacy_proxy_strips_tracking_headers():
    """Verify identifying headers are stripped from outbound requests."""
    cfg = PrivacyProxyConfig(enabled=True, strip_tracking_headers=True, normalize_user_agent=False)
    proxy = PrivacyProxy(cfg)

    incoming_headers = {
        "Host": "example.com",
        "Accept": "text/html",
        "X-Forwarded-For": "203.0.113.195",
        "X-Real-IP": "203.0.113.195",
        "Via": "1.1 proxy.internal",
        "CF-Connecting-IP": "203.0.113.195",
        "User-Agent": "CustomApp/1.0",
    }

    sanitized = proxy.sanitize_request_headers(incoming_headers)

    # Tracking headers stripped
    assert "X-Forwarded-For" not in sanitized
    assert "x-forwarded-for" not in sanitized
    assert "X-Real-IP" not in sanitized
    assert "Via" not in sanitized
    assert "CF-Connecting-IP" not in sanitized

    # Allowed headers preserved
    assert sanitized["Host"] == "example.com"
    assert sanitized["Accept"] == "text/html"
    assert sanitized["User-Agent"] == "CustomApp/1.0"
    assert sanitized["Referrer-Policy"] == "no-referrer"

    diag = proxy.get_diagnostics()
    assert diag["headers_stripped"] == 4
    assert diag["requests_filtered"] == 1


def test_privacy_proxy_user_agent_normalization():
    """Verify User-Agent header is normalized to cross-platform baseline."""
    cfg = PrivacyProxyConfig(enabled=True, normalize_user_agent=True)
    proxy = PrivacyProxy(cfg)

    headers = {
        "Host": "api.example.com",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15",
    }

    sanitized = proxy.sanitize_request_headers(headers)
    assert sanitized["User-Agent"] == BASELINE_USER_AGENT

    diag = proxy.get_diagnostics()
    assert diag["user_agents_normalized"] == 1


def test_privacy_proxy_connect_tunnel_no_mitm():
    """Verify CONNECT requests establish transparent tunnel without TLS interception."""
    cfg = PrivacyProxyConfig(enabled=True)
    proxy = PrivacyProxy(cfg)

    assert proxy.handle_connect_tunnel("secure.bank.com", 443) is True
    diag = proxy.get_diagnostics()
    assert diag["connect_tunnels_opened"] == 1
    assert diag["tls_mitm"] is False


def test_privacy_proxy_lifecycle():
    """Verify start and stop lifecycle."""
    cfg = PrivacyProxyConfig(enabled=True)
    proxy = PrivacyProxy(cfg)
    assert proxy.start() is True
    assert proxy.is_running is True

    proxy.stop()
    assert proxy.is_running is False
