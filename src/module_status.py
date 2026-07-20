"""Builders for the standard per-module status object.

Central place that decides how a module's raw outcome maps onto the status
taxonomy. The overriding rule: a skipped or failed module must never be
rendered as a successful "no issues" security pass, and an intentionally
excluded module (e.g. active Nuclei testing in the passive EASM profile) must
be clearly labelled out of scope.
"""

from __future__ import annotations

from .models import ModuleStatus

PASSIVE_EASM = "passive_easm"

_NUCLEI_SKIPPED_MESSAGE = (
    "Active Nuclei vulnerability testing was intentionally excluded from the "
    "passive EASM profile."
)


def nuclei_module_status(nuclei_status: str, scan_profile: str = PASSIVE_EASM) -> ModuleStatus:
    """Represent the Nuclei module.

    In the passive EASM profile Nuclei is intentionally not run. That is a
    ``skipped`` module — not a failure and not a clean vulnerability pass. It
    carries ``findings_count=null`` (not 0) and is excluded from the completed
    module denominator by callers.
    """
    status = (nuclei_status or "").lower()
    included = scan_profile not in (PASSIVE_EASM, "")

    if status in ("skipped", "", "not_run") and not included:
        return ModuleStatus(
            module="nuclei",
            status="skipped",
            attempted=False,
            successful=False,
            applicable=True,
            included_in_scan_profile=False,
            intentional=True,
            error=None,
            findings_count=None,
            message=_NUCLEI_SKIPPED_MESSAGE,
        )
    if status in ("error", "failed"):
        return ModuleStatus(
            module="nuclei",
            status="failed",
            attempted=True,
            successful=False,
            included_in_scan_profile=included,
            error="Nuclei scan attempted but did not complete.",
            findings_count=None,
        )
    if status == "pending":
        return ModuleStatus(
            module="nuclei",
            status="not_assessed",
            attempted=True,
            successful=False,
            included_in_scan_profile=included,
            findings_count=None,
            message="Active Nuclei scan is running out-of-band; results delivered via webhook.",
        )
    # completed
    return ModuleStatus(
        module="nuclei",
        status="completed",
        attempted=True,
        successful=True,
        included_in_scan_profile=included,
        findings_count=0,
    )


__all__ = ["nuclei_module_status", "PASSIVE_EASM"]
