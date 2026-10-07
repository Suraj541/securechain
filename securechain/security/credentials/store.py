"""Credential Store contract and base classes for SecureChain."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import SecretStr


class CredentialStore(ABC):
    """Abstract interface defining secure OS-level credential management."""

    @abstractmethod
    def store_secret(self, key: str, secret: SecretStr) -> bool:
        """Securely store a secret associated with a unique key."""

    @abstractmethod
    def get_secret(self, key: str) -> Optional[SecretStr]:
        """Retrieve and decrypt a stored secret."""

    @abstractmethod
    def delete_secret(self, key: str) -> bool:
        """Purge a stored secret from the store."""

    @abstractmethod
    def list_keys(self) -> List[str]:
        """List keys of stored secrets (never returns secrets themselves)."""

    @abstractmethod
    def status(self) -> Dict[str, Any]:
        """Report store backend status and key counts."""
