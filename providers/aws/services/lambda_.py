"""AWS Lambda service fetcher.

Collected data shape::

    {
        "functions": {
            "<FunctionName>": {
                "FunctionName": str,
                "Runtime": str,
                "FunctionArn": str,
                "FunctionUrlAuthType": str | None,  # "NONE" means unauthenticated
                "hasPublicFunctionUrl": bool,
                "VpcConfig": {"VpcId": str, "SubnetIds": [...], "SecurityGroupIds": [...]},
                "inVpc": bool,
                "KMSKeyArn": str | None,
                "EnvVarsEncrypted": bool,
                "TracingMode": str,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)

# Deprecated runtimes (EOL)
_DEPRECATED_RUNTIMES = {
    "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "python2.7", "python3.6", "python3.7",
    "java8",
    "ruby2.5",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
}


def fetch_lambda(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"functions": {}}

    functions = facade.paginate("lambda", "list_functions", "Functions")
    for fn in functions:
        name = fn["FunctionName"]
        try:
            entry = _build_function(facade, fn)
            data["functions"][name] = entry
        except Exception as exc:
            log.warning("Lambda function %s: %s", name, exc)
            data["functions"][name] = {"FunctionName": name, "error": str(exc)}

    return data


def _build_function(facade: Any, fn: Dict[str, Any]) -> Dict[str, Any]:
    name    = fn["FunctionName"]
    runtime = fn.get("Runtime", "")

    # Check for Function URL configs (public unauthenticated invocation)
    url_auth_type = None
    has_public_url = False
    try:
        resp = facade.call("lambda", "get_function_url_config", FunctionName=name)
        url_auth_type  = resp.get("AuthType")
        has_public_url = url_auth_type == "NONE"
    except Exception:
        pass  # Function URL not configured — that's fine

    vpc_config = fn.get("VpcConfig", {})
    in_vpc     = bool(vpc_config.get("VpcId"))

    return {
        "FunctionName":          name,
        "Runtime":               runtime,
        "FunctionArn":           fn.get("FunctionArn"),
        "FunctionUrlAuthType":   url_auth_type,
        "hasPublicFunctionUrl":  has_public_url,
        "isDeprecatedRuntime":   runtime in _DEPRECATED_RUNTIMES,
        "VpcConfig":             vpc_config,
        "inVpc":                 in_vpc,
        "KMSKeyArn":             fn.get("KMSKeyArn"),
        "EnvVarsEncrypted":      bool(fn.get("KMSKeyArn")),
        "TracingMode":           fn.get("TracingConfig", {}).get("Mode", "PassThrough"),
    }
