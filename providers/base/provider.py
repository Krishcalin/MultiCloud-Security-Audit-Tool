"""BaseProvider — abstract root class for all cloud provider implementations.

Every cloud provider (AWS, Azure, GCP, …) extends :class:`BaseProvider` and
implements :meth:`fetch` to populate ``self._data`` with the service data dict
consumed by the :class:`~core.engine.ProcessingEngine`.

Data dict contract
------------------
``self._data`` must be a nested plain-Python dict::

    {
        "<service_name>": {
            "<resource_type>": {
                "<resource_id>": { ...config... }
            }
        },
        ...
    }

For scalar/single-item resources (e.g. IAM account summary)::

    {
        "iam": {
            "account_summary": { "AccountMFAEnabled": 0, ... }
        }
    }
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseProvider(ABC):
    """Abstract base class for cloud provider implementations.

    Subclasses must set the :attr:`PROVIDER` class attribute and implement
    :meth:`fetch` and :meth:`get_services`.

    Args
    ----
    credentials:
        Provider-specific credentials object (boto3 Session, Azure credential, …).
        Pass ``None`` for unauthenticated / demo use.
    verbose:
        Print progress messages during data collection.
    """

    #: Short provider identifier, e.g. ``"aws"``, ``"azure"``, ``"gcp"``.
    PROVIDER: str = ""

    def __init__(
        self,
        credentials: Any = None,
        verbose:     bool = False,
        **kwargs:    Any,
    ) -> None:
        self.credentials:  Any              = credentials
        self.verbose:      bool             = verbose
        self._data:        Dict[str, Any]   = {}
        self.account_id:   str              = ""
        self.account_name: str              = ""

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def fetch(self, services: Optional[List[str]] = None) -> None:
        """Populate ``self._data`` by calling the cloud provider's APIs.

        Args
        ----
        services:
            Optional list of service names to fetch (e.g. ``["iam", "s3"]``).
            If ``None``, fetch all services returned by :meth:`get_services`.
        """

    @abstractmethod
    def get_services(self) -> List[str]:
        """Return the list of service names this provider supports."""

    # ------------------------------------------------------------------
    # Common helpers
    # ------------------------------------------------------------------

    def get_data(self) -> Dict[str, Any]:
        """Return the collected data dict (populated by :meth:`fetch`)."""
        return self._data

    def get_report_name(self) -> str:
        """Return a default report filename stem."""
        parts = [self.PROVIDER]
        if self.account_id:
            parts.append(self.account_id)
        return "-".join(parts)

    def _vprint(self, msg: str) -> None:
        """Print *msg* only when verbose mode is enabled."""
        if self.verbose:
            print(f"  [~] {msg}")

    def _warn(self, msg: str) -> None:
        """Print a warning message regardless of verbose setting."""
        print(f"  [!] WARNING: {msg}")

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"provider={self.PROVIDER!r}, "
            f"account={self.account_id!r})"
        )
