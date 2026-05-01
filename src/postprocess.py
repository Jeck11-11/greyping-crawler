"""Post-processing: fill 'not_found' into empty fields across API results.

Walks every Pydantic model in the response tree and replaces empty strings
with ``"not_found"`` and empty ``list[str]`` fields with ``["not_found"]``.
This makes the API output self-documenting for consumers (Xano, dashboards)
so they never see silent empty values for data that was looked up but absent.
"""

from __future__ import annotations

from typing import Union, get_args, get_origin

from pydantic import BaseModel

_NF = "not_found"

_SKIP_NAMES = frozenset({
    # Error / metadata fields — never fill
    "error",
    # Evidence / provenance — empty means no evidence
    "issues",
    "evidence",
    "found_on",
    "inferred_from",
    # Contact lists — empty means none discovered
    "emails",
    "phone_numbers",
    "social_profiles",
    # Link lists — empty means none found
    "internal_links",
    "redirect_chain",
    # Security / detection lists — empty means clean
    "detections",
    "findings",
    "secrets",
    "ioc_findings",
    "cookies",
    "sensitive_paths",
    "breaches",
    "cve_findings",
    "email_validations",
    # Subdomain / DNS lists — empty means none resolved
    "live_subdomains",
    "subdomains",
    "a_records",
    "aaaa_records",
    "mx_records",
    "ns_records",
    "txt_records",
    "cname_records",
    "srv_records",
    "caa_records",
    "ptr_records",
    "cname_chain",
    # Passive intel lists
    "issuers",
    "recent_snapshots",
    "name_servers",
    "hosting_providers",
    "countries",
    "hosting_countries",
    "mail_providers",
    "selectors_checked",
    "selectors_found",
    "includes",
    "rua",
    "records",
    # Tech / JS intel lists
    "technologies",
    "categories",
    "script_urls",
    "api_endpoints",
    "internal_hosts",
    "sourcemaps_found",
    "recovered_source_files",
    "notable_endpoints",
    # Nuclei
    "reference",
    "extracted_results",
    "tags",
    # EASM report lists
    "cloud_assets",
    "prioritized_findings",
    "recon_artifacts",
    "unique_routes",
    "notable_pages",
    "external_dependencies",
    "key_positives",
    "key_concerns",
    "cert_sans",
    "san_domains",
    "ct_subdomains",
    "ct_issuers",
    "ip_asn_map",
    "srv_services",
    "mx_hosts",
    "nameservers",
    "notable",
    "high_confidence",
    "data_types",
    "entries",
    "disallow_rules",
    "sitemap_urls",
    "urls",
    "nested_sitemaps",
    "status",
    "pages",
    # Pages summary — empty means no pages crawled
    "routes",
    # Links group — empty means none found
    "internal",
    "external",
    # Port scan — empty means no open ports / no banner
    "open_ports",
    "banner",
    # Screenshots — empty means none taken / no base64 data
    "screenshots",
    "image_base64",
    # SSL cert detail fields — empty means not resolved / not applicable
    "resolved_ip",
    "cert_sha1",
})


def _is_str_list(annotation) -> bool:
    origin = get_origin(annotation)
    if origin is list:
        args = get_args(annotation)
        return bool(args) and args[0] is str
    return False


def _is_optional_str(annotation) -> bool:
    import types as _types
    origin = get_origin(annotation)
    args = get_args(annotation)
    if not args:
        return False
    if origin is Union or (hasattr(_types, "UnionType") and isinstance(annotation, _types.UnionType)):
        return str in args and type(None) in args
    return False


def _walk(obj: BaseModel) -> None:
    for name, field_info in type(obj).model_fields.items():
        if name in _SKIP_NAMES:
            continue

        val = getattr(obj, name)
        annotation = field_info.annotation

        if val is None:
            if _is_optional_str(annotation):
                setattr(obj, name, _NF)
            continue

        if isinstance(val, str) and val.strip() == "":
            setattr(obj, name, _NF)
        elif isinstance(val, list):
            if len(val) == 0 and _is_str_list(annotation):
                setattr(obj, name, [_NF])
            else:
                for item in val:
                    if isinstance(item, BaseModel):
                        _walk(item)
        elif isinstance(val, BaseModel):
            _walk(val)


def fill_not_found(obj: BaseModel) -> None:
    """Fill ``'not_found'`` into empty fields across a result tree."""
    _walk(obj)


__all__ = ["fill_not_found"]
