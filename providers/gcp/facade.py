"""GCPFacade — credential factory and Discovery API builder for GCP Phase 4.

Authentication priority
-----------------------
1. If ``service_account_file`` is provided → ServiceAccountCredentials
2. Otherwise → Application Default Credentials
   (gcloud auth application-default login, Workload Identity, Cloud Shell, etc.)

All service fetchers call :meth:`discovery` to obtain a ``googleapiclient``
service object for the relevant GCP API, then work with plain JSON dicts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class GCPFacade:
    """Thin credential and API client factory for GCP.

    Parameters
    ----------
    project_id:
        GCP project ID to audit (e.g. ``"my-project-123"``).
    service_account_file:
        Optional path to a service-account JSON key file.
        When omitted, Application Default Credentials are used.
    """

    def __init__(
        self,
        project_id: str,
        service_account_file: Optional[str] = None,
    ) -> None:
        self.project_id = project_id
        if service_account_file:
            from google.oauth2 import service_account as _sa
            self._credentials = _sa.Credentials.from_service_account_file(
                service_account_file, scopes=_SCOPES
            )
            log.debug("GCP: using service account credentials from %s", service_account_file)
        else:
            import google.auth
            self._credentials, _ = google.auth.default(scopes=_SCOPES)
            log.debug("GCP: using Application Default Credentials")

    @property
    def credentials(self):
        return self._credentials

    # ------------------------------------------------------------------
    # API client builder
    # ------------------------------------------------------------------

    def discovery(self, api: str, version: str):
        """Return a googleapiclient Discovery service object.

        Parameters
        ----------
        api:     GCP API name (e.g. ``"compute"``, ``"storage"``, ``"iam"``).
        version: API version  (e.g. ``"v1"``, ``"v3"``).
        """
        from googleapiclient import discovery
        return discovery.build(
            api, version,
            credentials=self._credentials,
            cache_discovery=False,
        )

    # ------------------------------------------------------------------
    # Project info
    # ------------------------------------------------------------------

    def get_project_info(self) -> Dict[str, Any]:
        """Return basic project metadata from Resource Manager."""
        try:
            svc = self.discovery("cloudresourcemanager", "v3")
            proj = svc.projects().get(
                name=f"projects/{self.project_id}"
            ).execute()
            return {
                "project_id":     self.project_id,
                "display_name":   proj.get("displayName", self.project_id),
                "project_number": proj.get("projectNumber", ""),
                "state":          proj.get("state", "ACTIVE"),
            }
        except Exception as exc:
            log.warning("GCP: could not fetch project info: %s", exc)
            return {"project_id": self.project_id, "display_name": self.project_id}
