"""AWS Facade — thin wrapper around boto3 clients with lazy initialisation.

All service modules receive the facade and call its ``client()`` / ``resource()``
helpers rather than creating boto3 clients directly.  This keeps credential
handling in one place and makes unit-testing easy (swap the facade for a mock).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

try:
    import boto3
    import botocore.exceptions as _bex
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False
    boto3 = None           # type: ignore[assignment]
    _bex   = None          # type: ignore[assignment]


class AWSFacade:
    """Lazy-initialised boto3 client factory.

    Parameters
    ----------
    region:  Primary AWS region to use.
    profile: Named AWS profile (``~/.aws/credentials``). *None* → default chain.
    session: Pre-built boto3 Session (useful for testing / cross-account roles).
    """

    def __init__(
        self,
        region:  str = "eu-west-1",
        profile: Optional[str] = None,
        session: Any = None,
    ) -> None:
        if not HAS_BOTO3:
            raise ImportError(
                "boto3 is required for live AWS scanning.\n"
                "Install it with:  pip install boto3"
            )
        if session is not None:
            self._session = session
        else:
            self._session = boto3.Session(
                region_name=region,
                profile_name=profile,
            )
        self.region  = region
        self.profile = profile
        self._clients:   Dict[str, Any] = {}
        self._account_id: Optional[str] = None
        self._all_regions: Optional[list] = None

    # ------------------------------------------------------------------
    # Identity helpers
    # ------------------------------------------------------------------

    def get_account_id(self) -> str:
        """Return the AWS account ID via STS GetCallerIdentity."""
        if self._account_id is None:
            try:
                resp = self.client("sts").get_caller_identity()
                self._account_id = resp["Account"]
            except Exception as exc:
                log.warning("Could not retrieve account ID: %s", exc)
                self._account_id = "unknown"
        return self._account_id

    def get_all_regions(self) -> list:
        """Return all opted-in AWS regions for EC2."""
        if self._all_regions is None:
            try:
                resp = self.client("ec2").describe_regions(
                    Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
                )
                self._all_regions = [r["RegionName"] for r in resp.get("Regions", [])]
            except Exception as exc:
                log.warning("Could not list regions: %s", exc)
                self._all_regions = [self.region]
        return self._all_regions

    # ------------------------------------------------------------------
    # Client factory
    # ------------------------------------------------------------------

    def client(self, service: str, region: Optional[str] = None) -> Any:
        """Return a cached boto3 client for *service* in *region*.

        Uses the facade's default region when *region* is None.
        """
        key = f"{service}:{region or self.region}"
        if key not in self._clients:
            self._clients[key] = self._session.client(
                service, region_name=region or self.region
            )
        return self._clients[key]

    # ------------------------------------------------------------------
    # Paginator helper
    # ------------------------------------------------------------------

    def paginate(
        self,
        service:    str,
        operation:  str,
        key:        str,
        region:     Optional[str] = None,
        **kwargs:   Any,
    ) -> list:
        """Paginate *operation* on *service* and return the merged list under *key*.

        Example::

            users = facade.paginate("iam", "list_users", "Users")
        """
        result: list = []
        try:
            paginator = self.client(service, region).get_paginator(operation)
            for page in paginator.paginate(**kwargs):
                result.extend(page.get(key, []))
        except Exception as exc:  # noqa: BLE001
            log.warning("paginate %s.%s failed: %s", service, operation, exc)
        return result

    def call(
        self,
        service:   str,
        operation: str,
        region:    Optional[str] = None,
        **kwargs:  Any,
    ) -> dict:
        """Call a single (non-paginated) boto3 operation and return the response.

        Returns an empty dict on error so callers don't need individual try/except.
        """
        try:
            method = getattr(self.client(service, region), operation)
            return method(**kwargs)
        except Exception as exc:  # noqa: BLE001
            log.warning("call %s.%s failed: %s", service, operation, exc)
            return {}
