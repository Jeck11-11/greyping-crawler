# Financial FAIR ownership and scanner boundary

Decision recorded 2026-11-21 for [build backlog #26](https://github.com/Jeck11-11/greyping-crawler/issues/26).
This document distinguishes inspected scanner behaviour from required platform
behaviour. It is not a new financial model or API contract.

## Authoritative responsibilities

- Scanner: technical observations, findings and provenance.
- Xano: candidate-signal validation, approved scenario inputs, financial FAIR
  calculation and persistence, assessment lifecycle and scheduling.
- Frontend and report consumers: display validated, stored Xano results and their
  assessment identity, currency, model version, timestamps and uncertainty.
- AI: explain validated results only. Never supply missing facts or parameters.

Calculate each loss scenario independently. Never sum unrelated scenario ALE.
Technical grades, posture scores and ransomware susceptibility indicators are
not calibrated probabilities, event rates or monetary losses.

## Confirmed scanner behaviour

Inspected base: `3d68ae15049f71def56476f5698cfccbc751f699`.

- `src/models.py::RiskAssessmentGroup` contains `easm_report` only. The current
  main branch has no `src/fair_signals.py`, `FAIRSignals` or `FAIRFactor` model.
- `src/easm_report.py::_compute_financial_impact` always returns
  `financial_impact_status="insufficient_data"`, regardless of technical evidence.
- `FinancialImpact` retains four integer-zero financial fields for compatibility.
  They mean unavailable under this status, not observed zero loss. Do not use them
  as fallback scenario ALE or silently convert unknown business inputs to zero.
- `src/board_report.py` consumes technical EASM results and the same financial
  placeholder model. It does not provide a canonical Xano financial assessment.
- `src/nuclei_webhook.py` sends incremental technical results and completion
  events. Delivery acknowledgements are not proof of Xano persistence or FAIR
  completion. `src/app.py::_run_async_scan_job` tracks scanning and delivery
  separately; scanner completion alone must not authorise a financial result.

The former 0–100 TEF/V/CS/LM formula, normalisation examples and `fair_signals`
JSON in this document described legacy code. They are removed because they
contradicted the inspected code and Xano's financial authority. No scanner field,
endpoint, type, default, scoring weight or response shape changes in this fix.

## Required canonical platform flow

After successful initial scan ingestion, reuse the existing Xano calculation and
persistence pipeline for the proper tenant, managed customer and customer-domain.
The nightly backend refresh must reuse that pipeline with correctly scoped fresh
evidence and current validated business inputs. Do not create a parallel scanner
scheduler, financial endpoint, function, table or workflow.

The scheduler timezone must be read from authoritative platform configuration.
If no timezone is configured, use **Europe/Dublin**, documenting that fallback.
The scheduler configuration was not accessible during this review, so no claim
is made about its current timezone or whether the nightly task is enabled.

Retries must be idempotent; overlapping runs must not corrupt results; a pending
or failed refresh must not replace the latest valid completed assessment.
Consumers must expose pending, stale and failed states. Dashboard, detail API
and newly generated report must agree on assessment ID and per-scenario values.
Historical reports must retain their original point-in-time snapshot.

Tenant identity must come from authenticated server-side context. Validate all
customer/domain/run ownership chains for reads, writes, callbacks and jobs.
Preserve Secure HttpOnly tokens and evidence provenance.

## Formula and unit verification

Use the existing approved Xano model and calibration. This repository does not
establish baselines, multipliers, probability caps, confidence thresholds,
rounding rules or partial-input policy. Do not invent them to unblock a test.

For each scenario, independently check the approved formula and its dimensions:

| Quantity | Dimension |
| --- | --- |
| Annual TEF | Threat events/year |
| Vulnerability | Conditional probability, dimensionless |
| Annual LEF = annual TEF × vulnerability | Loss events/year |
| Loss magnitude | Recorded currency/loss event |
| ALE = annual LEF × loss magnitude | Recorded currency/year |

If TEF is already annual, do not annualise it a second time. A technical score or
an EPSS probability is not automatically annual TEF or scenario vulnerability.
Preserve unknown/null inputs and incomplete estimates; zero requires support.
Keep min/likely/max values and scenario boundaries distinct.

## Acceptance evidence still required

Execute in the authorised development environment, recording only synthetic IDs,
timestamps and redacted values:

1. Initial successful ingestion → one canonical assessment for the correct owner.
2. Independently checked scenario formula, units, annualisation and ranges.
3. Dashboard/detail/new-report equality on assessment ID and scenario values.
4. Changed evidence and business inputs through the same nightly pipeline.
5. Missing inputs, duplicate events/retries, overlapping runs and partial failure;
   retain the prior valid completed result and expose refresh state.
6. Two distinct synthetic tenants: positive owned access and denied cross-tenant
   reads/writes/jobs/reports. Anonymous 401 tests do not prove tenant isolation.
7. Generate a later report and confirm the older report snapshot is unchanged.

See [the review handover](handovers/2026-11-21-fair-authority.md) for actual tests,
source gaps and the next bounded implementation step.
