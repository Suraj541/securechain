"""Structured exceptions for SecureChain."""


class SecureChainError(Exception):
    """Base exception for all SecureChain errors."""


class ConfigurationError(SecureChainError):
    """Raised when configuration validation fails."""


class StateTransitionError(SecureChainError):
    """Raised when an invalid state transition is attempted."""

    def __init__(self, from_state: str, to_state: str, reason: str = ""):
        message = f"Invalid state transition from {from_state} to {to_state}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.from_state = from_state
        self.to_state = to_state


class TunnelError(SecureChainError):
    """Base exception for tunnel operations."""


class TunnelConnectionError(TunnelError):
    """Raised when a tunnel fails to connect."""


class TunnelVerificationError(TunnelError):
    """Raised when tunnel verification checks fail."""


class RoutingError(SecureChainError):
    """Raised when route manipulation or verification fails."""


class KillSwitchError(SecureChainError):
    """Raised when firewall / kill-switch operations fail."""


class LeakDetectedError(SecureChainError):
    """Raised when a DNS or IPv6 leak is detected."""


class RecoveryExhaustedError(SecureChainError):
    """Raised when automatic recovery attempts are exhausted."""


class CredentialError(SecureChainError):
    """Raised when credential retrieval or validation fails."""
