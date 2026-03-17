"""GCPProvider — top-level orchestrator for the GCP Phase 4 scanner.

Usage::

    from providers.gcp import GCPProvider

    provider = GCPProvider(
        project_id="my-project-123",
        service_account_file="/path/to/key.json",  # or omit for ADC
    )
    provider.fetch_sync()
    data = provider.get_data()   # pass to ProcessingEngine.run()
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from providers.base.provider import BaseProvider
from .facade import GCPFacade
from .services.iam      import fetch_iam
from .services.storage  import fetch_storage
from .services.compute  import fetch_compute
from .services.sql      import fetch_sql
from .services.logging  import fetch_logging
from .services.kms      import fetch_kms
from .services.gke        import fetch_gke
from .services.bigquery   import fetch_bigquery
from .services.functions  import fetch_functions

log = logging.getLogger(__name__)

_SERVICE_FETCHERS = {
    "iam":     fetch_iam,
    "storage": fetch_storage,
    "compute": fetch_compute,
    "sql":     fetch_sql,
    "logging": fetch_logging,
    "kms":     fetch_kms,
    "gke":       fetch_gke,
    "bigquery":  fetch_bigquery,
    "functions": fetch_functions,
}

PROVIDER = "gcp"


class GCPProvider(BaseProvider):
    """Live GCP project scanner.

    Parameters
    ----------
    project_id:            GCP project ID to audit.
    service_account_file:  Path to SA key JSON (optional; uses ADC if omitted).
    services:              Whitelist of service keys to scan.  ``None`` → all.
    verbose:               Print progress to stdout.
    """

    PROVIDER = PROVIDER

    def __init__(
        self,
        project_id: str,
        service_account_file: Optional[str] = None,
        services:             Optional[List[str]] = None,
        verbose:              bool = False,
    ) -> None:
        super().__init__()
        self.project_id           = project_id
        self.service_account_file = service_account_file
        self.verbose              = verbose
        self._services_filter: Optional[List[str]] = (
            [s.lower() for s in services] if services else None
        )
        self._facade: Optional[GCPFacade] = None

    # ------------------------------------------------------------------
    # BaseProvider interface
    # ------------------------------------------------------------------

    def get_services(self) -> List[str]:
        return list(_SERVICE_FETCHERS.keys())

    async def fetch(self, services: Optional[List[str]] = None) -> None:
        """Async stub — delegates to :meth:`fetch_sync`."""
        self.fetch_sync(services=services)

    # ------------------------------------------------------------------
    # Synchronous fetch (main CLI entry point)
    # ------------------------------------------------------------------

    def fetch_sync(self, services: Optional[List[str]] = None) -> None:
        """Connect to GCP and populate the data dict."""
        self._facade = GCPFacade(
            project_id=self.project_id,
            service_account_file=self.service_account_file,
        )

        proj_info        = self._facade.get_project_info()
        self.account_id  = proj_info.get("project_id",   self.project_id)
        self.account_name = proj_info.get("display_name", self.project_id)

        filter_ = (
            [s.lower() for s in services]
            if services
            else self._services_filter
        )

        for svc_key, fetch_fn in _SERVICE_FETCHERS.items():
            if filter_ and svc_key not in filter_:
                continue
            self._vprint(f"  [{svc_key.upper():10}] fetching …")
            try:
                svc_data = fetch_fn(self._facade)
                self._data[svc_key] = svc_data
                count = self._count_resources(svc_data)
                self._vprint(f"  [{svc_key.upper():10}] {count} resource(s) collected")
            except Exception as exc:
                log.warning("Service fetch failed [%s]: %s", svc_key, exc)
                self._vprint(f"  [{svc_key.upper():10}] WARN: {exc}")
                self._data[svc_key] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    @staticmethod
    def _count_resources(svc_data: Any) -> int:
        if not isinstance(svc_data, dict):
            return 0
        total = 0
        for v in svc_data.values():
            if isinstance(v, dict):
                total += len(v)
            elif isinstance(v, list):
                total += len(v)
            elif isinstance(v, bool):
                pass  # scalar flag — not a resource
            else:
                total += 1
        return total

    def get_data(self) -> Dict[str, Any]:
        return self._data

    def get_report_name(self) -> str:
        return f"gcp-{self.account_id}"
