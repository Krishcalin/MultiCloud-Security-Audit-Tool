"""Azure Facade — credential factory and Graph API helper for all Azure services.

Provides:
- ``credential``  : an authenticated azure-identity credential object.
- ``subscription_id`` : the target subscription.
- ``graph_get()``     : single-page Microsoft Graph REST call.
- ``graph_paginate()``: full pagination through Graph API collections.
- ``get_subscription_info()`` : display name + tenant ID.

Service modules receive the facade and instantiate their own azure-mgmt-*
clients using ``facade.credential`` and ``facade.subscription_id``.  This
keeps credential management in one place without coupling the facade to every
management-plane SDK.

Authentication priority
-----------------------
1. If *tenant_id* + *client_id* + *client_secret* are all provided →
   ``ClientSecretCredential`` (service-principal auth, ideal for CI/CD).
2. Otherwise → ``DefaultAzureCredential`` (env vars → workload identity →
   managed identity → Azure CLI → Interactive Browser).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)

try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.core.exceptions import HttpResponseError
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False
    DefaultAzureCredential = None   # type: ignore[assignment,misc]
    ClientSecretCredential  = None  # type: ignore[assignment,misc]
    HttpResponseError       = None  # type: ignore[assignment,misc]

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class AzureFacade:
    """Lazy-initialised Azure credential + Graph API client.

    Parameters
    ----------
    subscription_id: Azure subscription UUID to audit.
    tenant_id:       AAD tenant UUID (required for service-principal auth).
    client_id:       Service principal application (client) ID.
    client_secret:   Service principal client secret.
    """

    def __init__(
        self,
        subscription_id: str,
        tenant_id:     Optional[str] = None,
        client_id:     Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> None:
        if not HAS_AZURE:
            raise ImportError(
                "azure-identity is required for live Azure scanning.\n"
                "Install with:\n"
                "  pip install azure-identity azure-mgmt-resource "
                "azure-mgmt-storage azure-mgmt-compute azure-mgmt-network "
                "azure-mgmt-keyvault azure-keyvault-keys azure-keyvault-secrets "
                "azure-mgmt-sql azure-mgmt-monitor azure-mgmt-security "
                "azure-mgmt-web requests"
            )

        self.subscription_id = subscription_id
        self.tenant_id       = tenant_id

        if tenant_id and client_id and client_secret:
            self._credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            self._credential = DefaultAzureCredential()

        self._sub_info: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # Credential access
    # ------------------------------------------------------------------

    @property
    def credential(self) -> Any:
        """Return the azure-identity credential object."""
        return self._credential

    # ------------------------------------------------------------------
    # Subscription info
    # ------------------------------------------------------------------

    def get_subscription_info(self) -> Dict[str, Any]:
        """Return display name and tenant ID for the subscription."""
        if self._sub_info is not None:
            return self._sub_info
        try:
            from azure.mgmt.resource import SubscriptionClient  # type: ignore[import]
            client = SubscriptionClient(self._credential)
            sub    = client.subscriptions.get(self.subscription_id)
            self._sub_info = {
                "subscription_id": sub.subscription_id,
                "display_name":    sub.display_name,
                "tenant_id":       sub.tenant_id,
                "state":           str(sub.state),
            }
        except Exception as exc:
            log.warning("Could not retrieve subscription info: %s", exc)
            self._sub_info = {
                "subscription_id": self.subscription_id,
                "display_name":    "unknown",
                "tenant_id":       self.tenant_id or "unknown",
            }
        return self._sub_info

    def list_resource_groups(self) -> List[str]:
        """Return a list of all resource group names in the subscription."""
        try:
            from azure.mgmt.resource import ResourceManagementClient  # type: ignore[import]
            client = ResourceManagementClient(self._credential, self.subscription_id)
            return [rg.name for rg in client.resource_groups.list()]
        except Exception as exc:
            log.warning("list_resource_groups failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Microsoft Graph REST helpers
    # ------------------------------------------------------------------

    def _graph_token(self) -> str:
        """Acquire a bearer token for Microsoft Graph."""
        token = self._credential.get_token("https://graph.microsoft.com/.default")
        return token.token

    def graph_get(
        self,
        path:   str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Single-page GET call to Microsoft Graph v1.0.

        *path* should start with ``/``, e.g. ``"/users"``.
        Returns the parsed JSON response dict, or ``{}`` on error.
        """
        try:
            import requests  # type: ignore[import]
            headers = {
                "Authorization": f"Bearer {self._graph_token()}",
                "Content-Type":  "application/json",
            }
            url  = f"{_GRAPH_BASE}{path}"
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            log.warning("Graph GET %s: %s", path, exc)
            return {}

    def graph_paginate(
        self,
        path:   str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Follow ``@odata.nextLink`` and return the merged ``value`` list."""
        try:
            import requests  # type: ignore[import]
        except ImportError:
            log.warning("'requests' package not installed — Graph API calls disabled")
            return []

        results: List[Dict[str, Any]] = []
        headers = {
            "Authorization": f"Bearer {self._graph_token()}",
            "Content-Type":  "application/json",
        }
        url: Optional[str] = f"{_GRAPH_BASE}{path}"
        while url:
            try:
                resp = requests.get(url, headers=headers, params=params, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                log.warning("Graph paginate %s: %s", url, exc)
                break
            results.extend(data.get("value", []))
            url    = data.get("@odata.nextLink")
            params = None   # params are embedded in nextLink
        return results
