"""AWSProvider — top-level orchestrator for the AWS Phase 2 scanner.

Instantiates the facade, runs each service fetcher, then exposes the
collected data dict to the processing engine.

Usage::

    from providers.aws import AWSProvider

    provider = AWSProvider(region="us-east-1", profile="my-profile")
    provider.fetch()                      # populates internal data dict
    data = provider.get_data()            # pass to ProcessingEngine.run()
    account_id = provider.account_id      # e.g. "123456789012"
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from providers.base.provider import BaseProvider
from .facade import AWSFacade
from .services.iam         import fetch_iam
from .services.s3          import fetch_s3
from .services.ec2         import fetch_ec2
from .services.vpc         import fetch_vpc
from .services.cloudtrail  import fetch_cloudtrail
from .services.kms         import fetch_kms
from .services.rds         import fetch_rds
from .services.guardduty   import fetch_guardduty
from .services.config      import fetch_config
from .services.sns         import fetch_sns
from .services.sqs         import fetch_sqs

log = logging.getLogger(__name__)

# Map of service key → fetch function
# Each fetch(facade) → dict  (the sub-tree for that service)
_SERVICE_FETCHERS = {
    "iam":        fetch_iam,
    "s3":         fetch_s3,
    "ec2":        fetch_ec2,
    "vpc":        fetch_vpc,
    "cloudtrail": fetch_cloudtrail,
    "kms":        fetch_kms,
    "rds":        fetch_rds,
    "guardduty":  fetch_guardduty,
    "config":     fetch_config,
    "sns":        fetch_sns,
    "sqs":        fetch_sqs,
}

PROVIDER = "aws"


class AWSProvider(BaseProvider):
    """Live AWS account scanner.

    Parameters
    ----------
    region:   Primary AWS region (default: ``eu-west-1``).
    profile:  Named AWS credentials profile.
    services: Whitelist of service keys to scan.  *None* → all services.
    verbose:  Print progress messages to stdout.
    """

    PROVIDER = PROVIDER

    def __init__(
        self,
        region:   str = "eu-west-1",
        profile:  Optional[str] = None,
        services: Optional[List[str]] = None,
        verbose:  bool = False,
    ) -> None:
        super().__init__()
        self.region   = region
        self.profile  = profile
        self.verbose  = verbose
        self._services_filter: Optional[List[str]] = (
            [s.lower() for s in services] if services else None
        )
        self._facade: Optional[AWSFacade] = None

    # ------------------------------------------------------------------
    # BaseProvider interface
    # ------------------------------------------------------------------

    def get_services(self) -> List[str]:
        return list(_SERVICE_FETCHERS.keys())

    async def fetch(self, services: Optional[List[str]] = None) -> None:
        """Async stub — delegates to the synchronous ``fetch_sync()``."""
        self.fetch_sync(services=services)

    # ------------------------------------------------------------------
    # Synchronous fetch (main entry point for CLI)
    # ------------------------------------------------------------------

    def fetch_sync(self, services: Optional[List[str]] = None) -> None:
        """Connect to AWS and populate the data dict.

        Parameters
        ----------
        services: Override service whitelist for this run.
        """
        self._facade = AWSFacade(region=self.region, profile=self.profile)
        self.account_id   = self._facade.get_account_id()
        self.account_name = self.account_id

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
        """Best-effort count of top-level resources in a service sub-tree."""
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
        return f"aws-{self.account_id}-{self.region}"
