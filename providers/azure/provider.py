"""AzureProvider — top-level orchestrator for the Azure Phase 3 scanner.

Instantiates the facade, runs each service fetcher, then exposes the
collected data dict to the processing engine.

Usage::

    from providers.azure import AzureProvider

    provider = AzureProvider(
        subscription_id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        tenant_id="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    )
    provider.fetch_sync()
    data = provider.get_data()   # pass to ProcessingEngine.run()
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from providers.base.provider import BaseProvider
from .facade import AzureFacade
from .services.entra      import fetch_entra
from .services.storage    import fetch_storage
from .services.keyvault   import fetch_keyvault
from .services.compute    import fetch_compute
from .services.network    import fetch_network
from .services.sql        import fetch_sql
from .services.monitor    import fetch_monitor
from .services.security   import fetch_security
from .services.appservice import fetch_appservice
from .services.aks               import fetch_aks
from .services.containerregistry import fetch_containerregistry
from .services.cosmosdb          import fetch_cosmosdb

log = logging.getLogger(__name__)

_SERVICE_FETCHERS = {
    "entra":      fetch_entra,
    "storage":    fetch_storage,
    "keyvault":   fetch_keyvault,
    "compute":    fetch_compute,
    "network":    fetch_network,
    "sql":        fetch_sql,
    "monitor":    fetch_monitor,
    "security":   fetch_security,
    "appservice": fetch_appservice,
    "aks":               fetch_aks,
    "containerregistry": fetch_containerregistry,
    "cosmosdb":          fetch_cosmosdb,
}

PROVIDER = "azure"


class AzureProvider(BaseProvider):
    """Live Azure subscription scanner.

    Parameters
    ----------
    subscription_id: Azure subscription UUID.
    tenant_id:       AAD tenant UUID.
    client_id:       Service-principal client ID  (optional).
    client_secret:   Service-principal secret     (optional).
    services:        Whitelist of service keys to scan.  *None* → all.
    verbose:         Print progress to stdout.
    """

    PROVIDER = PROVIDER

    def __init__(
        self,
        subscription_id: str,
        tenant_id:       Optional[str] = None,
        client_id:       Optional[str] = None,
        client_secret:   Optional[str] = None,
        services:        Optional[List[str]] = None,
        verbose:         bool = False,
    ) -> None:
        super().__init__()
        self.subscription_id = subscription_id
        self.tenant_id       = tenant_id
        self.client_id       = client_id
        self.client_secret   = client_secret
        self.verbose         = verbose
        self._services_filter: Optional[List[str]] = (
            [s.lower() for s in services] if services else None
        )
        self._facade: Optional[AzureFacade] = None

    # ------------------------------------------------------------------
    # BaseProvider interface
    # ------------------------------------------------------------------

    def get_services(self) -> List[str]:
        return list(_SERVICE_FETCHERS.keys())

    async def fetch(self, services: Optional[List[str]] = None) -> None:
        """Async stub — delegates to ``fetch_sync()``."""
        self.fetch_sync(services=services)

    # ------------------------------------------------------------------
    # Synchronous fetch (main CLI entry point)
    # ------------------------------------------------------------------

    def fetch_sync(self, services: Optional[List[str]] = None) -> None:
        """Connect to Azure and populate the data dict."""
        self._facade = AzureFacade(
            subscription_id=self.subscription_id,
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

        sub_info         = self._facade.get_subscription_info()
        self.account_id  = sub_info.get("subscription_id", self.subscription_id)
        self.account_name = sub_info.get("display_name", self.account_id)

        filter_ = (
            [s.lower() for s in services]
            if services
            else self._services_filter
        )

        for svc_key, fetch_fn in _SERVICE_FETCHERS.items():
            if filter_ and svc_key not in filter_:
                continue
            self._vprint(f"  [{svc_key.upper():12}] fetching …")
            try:
                svc_data = fetch_fn(self._facade)
                self._data[svc_key] = svc_data
                count = self._count_resources(svc_data)
                self._vprint(f"  [{svc_key.upper():12}] {count} resource(s) collected")
            except Exception as exc:
                log.warning("Service fetch failed [%s]: %s", svc_key, exc)
                self._vprint(f"  [{svc_key.upper():12}] WARN: {exc}")
                self._data[svc_key] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    @staticmethod
    def _count_resources(svc_data: Any) -> int:
        if isinstance(svc_data, dict):
            total = 0
            for v in svc_data.values():
                if isinstance(v, dict):
                    total += len(v)
                elif isinstance(v, list):
                    total += len(v)
                else:
                    total += 1
            return total
        return 0

    def get_data(self) -> Dict[str, Any]:
        return self._data

    def get_report_name(self) -> str:
        return f"azure-{self.account_id}"
