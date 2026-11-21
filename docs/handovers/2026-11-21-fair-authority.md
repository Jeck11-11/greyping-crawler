# FAIR authority review — 2026-11-21

## Outcome and scope

Partial progress on build backlog #26, prioritising GP-06/07/08/09/10/11 before
broader backlog work. Reversible documentation corrections only; the end-to-end
financial goal is **not verified or complete**. No merge, publish, deployment,
record mutation, new backend object or API contract change.

## Sources inspected

- Issue #26 and its comments; open scanner PR search returned none.
- Scanner `CLAUDE.md`, README, FAIR documentation, current models, scan worker,
  callback delivery, EASM and board-report consumers, tests and CI workflow.
- Project workspace instructions; project-folder schema register version 2,
  API register version 2, FAIR rules version 2 and handover register version 0.
  These include September observations, not a fresh Xano export.
- Vercel development project metadata and deployment file inventory, plus small
  source files. Large source-file responses were explicitly truncated; incomplete
  base64 fragments are not treated as full source or executable evidence.
- Development app login and Xano workspace login were observed directly.

`GREYPING_SOURCE_INDEX.md` was absent from the inspected scanner checkout and
exact-title searches did not locate it in the available project files. It was
not recreated or overwritten. No synced `sources/` files were modified.
The 20 November checkpoint mentioned in prior context was not recovered.

## Confirmed cause and limits

The documentation conflict is confirmed: the README and prior FAIR document
advertised a scanner financial/factor calculation whose module and model are
absent on inspected main. `_compute_financial_impact` explicitly defers to Xano.
This explains misleading integration guidance; it does **not** establish the
root cause or first failing statement of the deployed Xano/front-end fault.

A local synthetic `DomainResult(target="https://fair-boundary.invalid")` passed
to `_compute_financial_impact` returned a string status `insufficient_data`, four
integer zeros, string methodology and a list of explanation strings. Those zeros
are placeholders, not validated zero losses. No deployed business input values,
FAIR rows or assessment/run IDs were obtained.

## Existing pipeline to inspect and reuse

The dated API/FAIR registers identify:

| Component | Existing reference | Current verification |
| --- | --- | --- |
| Context loader | `fair_get_domain_context` #227 | September register only |
| Calculator | `fair_calculate_domain_results` #228 | September register only |
| Persistence/orchestration | #235; single-domain refresh wrapper | Exact current wrapper/export required |
| Nightly orchestration | #229 | Current task binding/timezone required |
| First-scan orchestration | `process_initial_scan_job` | Current source/ingestion hook required |
| Summary consumer | `get_cio_overview`, `get_summary` | Current source/contract required |

Registers report an explicit calculator Draft dependency in persistence and
eligibility filters added in Draft. Inspect current versions before editing;
do not overwrite that existing work. The dated positive calculation case is
prior evidence, not a test rerun in this review.

The development frontend is a Next.js/Vercel app. A deployment inventory contains
`fair-snapshot.ts`, `risk-data.ts`, `report-data.ts`, `report-model.ts`, financial
formatting helpers and domain FAIR API routes. Complete consumer bodies were
unavailable through bounded source responses; absence of independent financial
calculation has not been proved. No replacement frontend was created and no
Nordcraft work was changed.

## Tests actually executed

Base SHA: `3d68ae15049f71def56476f5698cfccbc751f699`.
Local Python 3.12 runtime; CI specifies Python 3.11, which was not run here.

| Test | Actual result |
| --- | --- |
| Install `requirements-dev.txt` | Succeeded |
| `python -m compileall -q src tests` | Passed |
| `python -m pytest -q` on unchanged base | 936 passed, one FastAPI/Starlette deprecation warning, 4.10s |
| Financial/report boundary modules after documentation edits | 45 passed, 0.26s |
| Local synthetic financial return/type inspection | `insufficient_data`, integer-zero placeholders; no calculated financial values |
| Anonymous development `/api/auth/me` GET | HTTP 401 |
| Anonymous development domain FAIR GET with synthetic UUID | HTTP 401 |
| Anonymous Xano `get_summary` GET | Authentication-required JSON; no authenticated data obtained |
| Browser development login | Email/passcode form; no authenticated session |
| Browser Xano workspace | Redirected to Xano login; no authenticated workspace access |

No Docker executable was available, so production-image build was not run.
No new synthetic database records or assessment IDs exist from this run.

## Exact changes and preserved contracts

- `README.md`: replace obsolete scanner FAIR claims, module entry and example.
- `docs/FAIR.md`: replace legacy technical-score financial guidance with explicit
  Xano ownership, current scanner behaviour, required pipeline and acceptance gates.
- This handover: source review, actual evidence and blockers.

All runtime files, schemas, endpoints, defaults, scores, tenant/auth controls,
Secure HttpOnly handling, evidence and historical reports remain unchanged.
Rollback is a revert of the documentation commit(s).

## Blockers and next step

Required: authenticated development Xano workspace/function execution access;
complete current source/checkpoint and source index; existing scheduler binding,
timezone and configuration; complete editable frontend source with branch
continuity; two authorised synthetic tenant contexts.

Next: inspect the existing first-scan hook, #227/#228/#235 and #229 task binding,
then trace one synthetic domain through ingestion, calculation, persistence,
summary/detail and report. Capture actual runtime types and the first failing
statement before changing code. Verify the full matrix in `docs/FAIR.md` before
resuming unrelated backlog delivery.

Timezone remains unverified. Europe/Dublin is the owner's required fallback
only if authoritative configuration is absent; inability to read it is not proof
that configuration is absent. No scheduler was created or changed.
