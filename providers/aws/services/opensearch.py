"""AWS OpenSearch Service fetcher.

Collected data shape::

    {
        "domains": {
            "<DomainName>": {
                "DomainName": str,
                "ARN": str,
                "EngineVersion": str,
                "inVpc": bool,
                "VpcOptions": dict,
                "EncryptionAtRestEnabled": bool,
                "NodeToNodeEncryptionEnabled": bool,
                "EnforceHTTPS": bool,
                "TLSSecurityPolicy": str,
                "LoggingEnabled": bool,
                "FineGrainedAccessControlEnabled": bool,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_opensearch(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"domains": {}}

    # list domain names first
    try:
        resp = facade.call("opensearch", "list_domain_names")
    except Exception as exc:
        log.warning("OpenSearch: list_domain_names failed: %s", exc)
        return data

    domain_names = [d["DomainName"] for d in resp.get("DomainNames", [])]
    if not domain_names:
        return data

    # Batch describe (up to 5 at a time)
    batch_size = 5
    for i in range(0, len(domain_names), batch_size):
        batch = domain_names[i: i + batch_size]
        try:
            resp = facade.call(
                "opensearch", "describe_domains",
                DomainNames=batch,
            )
            for domain in resp.get("DomainStatusList", []):
                name = domain["DomainName"]
                data["domains"][name] = _build_domain(domain)
        except Exception as exc:
            log.warning("OpenSearch: describe_domains failed: %s", exc)

    return data


def _build_domain(d: Dict[str, Any]) -> Dict[str, Any]:
    vpc_options = d.get("VPCOptions") or d.get("VpcOptions") or {}
    in_vpc = bool(vpc_options.get("VPCId") or vpc_options.get("VpcId"))

    enc_config   = d.get("EncryptionAtRestOptions", {})
    n2n_config   = d.get("NodeToNodeEncryptionOptions", {})
    domain_ep    = d.get("DomainEndpointOptions", {})

    log_options = d.get("LogPublishingOptions", {})
    logging_enabled = any(
        v.get("Enabled", False) for v in log_options.values()
    ) if log_options else False

    fgac = d.get("AdvancedSecurityOptions", {})
    fgac_enabled = fgac.get("Enabled", False)

    return {
        "DomainName":                     d.get("DomainName"),
        "ARN":                            d.get("ARN"),
        "EngineVersion":                  d.get("EngineVersion"),
        "inVpc":                          in_vpc,
        "VpcOptions":                     vpc_options,
        "EncryptionAtRestEnabled":        enc_config.get("Enabled", False),
        "NodeToNodeEncryptionEnabled":    n2n_config.get("Enabled", False),
        "EnforceHTTPS":                   domain_ep.get("EnforceHTTPS", False),
        "TLSSecurityPolicy":              domain_ep.get("TLSSecurityPolicy", ""),
        "LoggingEnabled":                 logging_enabled,
        "FineGrainedAccessControlEnabled": fgac_enabled,
    }
