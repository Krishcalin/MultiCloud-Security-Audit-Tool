"""GCP Cloud Functions service fetcher.

Data shape
----------
::

    {
        "functions": {
            "<function-name>": {
                "name":               str,
                "region":             str,
                "status":             str,
                "runtime":            str,
                "isDeprecatedRuntime": bool,
                "isPubliclyInvocable": bool,   # allUsers has roles/cloudfunctions.invoker
                "ingressSettings":    str,      # "ALLOW_ALL" | "ALLOW_INTERNAL_ONLY" | etc.
                "vpcConnector":       str | None,
                "serviceAccountEmail": str,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

log = logging.getLogger(__name__)

# Deprecated GCF runtimes
_DEPRECATED_RUNTIMES = {
    "nodejs6", "nodejs8", "nodejs10",
    "python37",
    "go111", "go113",
    "java11",
    "ruby26", "ruby27",
    "dotnet3",
    "php74",
}


def fetch_functions(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"functions": {}}

    cf = facade.discovery("cloudfunctions", "v1")
    parent = f"projects/{facade.project_id}/locations/-"

    # List all functions across all regions
    try:
        req = cf.projects().locations().functions().list(parent=parent)
        while req is not None:
            resp = req.execute()
            for fn in resp.get("functions", []):
                fn_name = fn.get("name", "")
                short_name = fn_name.rsplit("/", 1)[-1]
                # Region is the second-to-last path segment
                parts  = fn_name.split("/")
                region = parts[-3] if len(parts) >= 4 else ""
                data["functions"][fn_name] = _analyze_function(fn, short_name, region)
            req = cf.projects().locations().functions().list_next(req, resp)
    except Exception as exc:
        log.warning("Cloud Functions: list failed: %s", exc)

    # Check IAM policy for public invocability
    for fn_resource, entry in list(data["functions"].items()):
        try:
            policy = cf.projects().locations().functions().getIamPolicy(
                resource=fn_resource
            ).execute()
            entry["isPubliclyInvocable"] = _is_publicly_invocable(policy)
        except Exception as exc:
            log.debug("Cloud Functions: getIamPolicy %s: %s", fn_resource, exc)

    return data


def _analyze_function(fn: Dict[str, Any], short_name: str, region: str) -> Dict[str, Any]:
    runtime = fn.get("runtime", "")
    ingress = fn.get("ingressSettings", "ALLOW_ALL")

    return {
        "name":                short_name,
        "region":              region,
        "status":              fn.get("status", ""),
        "runtime":             runtime,
        "isDeprecatedRuntime": runtime in _DEPRECATED_RUNTIMES,
        "isPubliclyInvocable": False,  # updated after IAM policy check
        "ingressSettings":     ingress,
        "vpcConnector":        fn.get("vpcConnector"),
        "serviceAccountEmail": fn.get("serviceAccountEmail", ""),
    }


def _is_publicly_invocable(policy: Dict[str, Any]) -> bool:
    for binding in policy.get("bindings", []):
        if binding.get("role") in (
            "roles/cloudfunctions.invoker",
            "roles/run.invoker",
        ):
            members: List[str] = binding.get("members", [])
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                return True
    return False
