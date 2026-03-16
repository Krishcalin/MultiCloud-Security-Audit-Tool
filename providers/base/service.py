"""BaseService — abstract class for a single cloud service within a provider.

Each service (IAM, S3, Compute, KeyVault, …) extends :class:`BaseService`,
implements :meth:`fetch_all`, and exposes its collected data via
:meth:`get_data`.

Usage within a provider::

    class IAMService(BaseService):
        SERVICE_NAME = "iam"

        async def fetch_all(self) -> None:
            users = await self.facade.get_users()
            self._resources["users"] = {u["UserId"]: u for u in users}
            account_summary = await self.facade.get_account_summary()
            self._resources["account_summary"] = account_summary
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseService(ABC):
    """Abstract base class for a cloud service data-collector.

    Args
    ----
    facade:
        The provider's SDK-wrapper facade for this service.
        May be ``None`` in tests or stub implementations.
    verbose:
        Forward verbose flag from the parent provider.
    """

    #: Service identifier used as the top-level key in the provider data dict.
    SERVICE_NAME: str = ""

    def __init__(self, facade: Any = None, verbose: bool = False) -> None:
        self.facade    = facade
        self.verbose   = verbose
        self._resources: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def fetch_all(self) -> None:
        """Fetch all resources for this service into ``self._resources``."""

    # ------------------------------------------------------------------
    # Common helpers
    # ------------------------------------------------------------------

    def get_data(self) -> Dict[str, Any]:
        """Return the collected resource data dict."""
        return self._resources

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(f"    [~] [{self.SERVICE_NAME}] {msg}")

    def _warn(self, msg: str) -> None:
        print(f"    [!] [{self.SERVICE_NAME}] WARNING: {msg}")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(service={self.SERVICE_NAME!r})"
