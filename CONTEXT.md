# trial-ledger — Context

*Fresh CONTEXT.md created at flagship inception (2026-05-27 marathon Phase A). trial-ledger ships as a cohort-port FROM INCEPTION (R174 5-of-5 strict) — every canonical cohort primitive (R143 / R145.C / R150 / R151 / R166 / R175 + R154 Article-9) is wired from the first commit.*

## One-line purpose

**FDA 21 CFR Part 11 clinical-trial audit-trail forge — appends operator-action audit rows for clinical-trial electronic records and electronic signatures, stamps an L43 Mirror-Mark v1 cold-verifiable receipt on every append (R175 saturator), and ships joint Article-9 health-data + 21 CFR Part 11 advisory shape (R154 4th cohort saturator).**

## Status

**Status (2026-05-27 inception; 2026-06-11 stele-anchor amendment)**: **Phase-1 MVP** — canonical cohort 8-package layout (lore + mirrormark + manifest + honest + firewall + legal + auditledger + fdacfr11) shipped from first commit; the `claude/stele-anchor-2026-06-11` branch adds the 9th package `internal/stele` — opt-in (`TRIAL_LEDGER_STELE_URL`) anchoring of each `append` run's self-checked audit ledger into the Stele verified-trust spine (the anchor complements — it does NOT replace — the Mirror-Mark cold-verifiability; see SECURITY.md §Stele spine anchoring). **Mirror-Mark wire-load-bearing from inception** — `auditledger.NewLedger(nil)` panics with `ErrNilMarker`; there is no code path through `Append()` that produces an unstamped row. **R174 5-of-5 strict** — all 5 canonical cohort R-rules (R143 honest + R145.C firewall + R150 manifest + R151 lore + R166 legal-citation cohort) wired at scaffold birth. **R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION 6th cohort saturator**. **R154 Article-9 cohort 4th saturator** (joins haven + triage-hospital + clinician — clinical-trial records are GDPR Article 9(1) special-category personal data concerning health). Phase-1 in-memory append-only ring; the canonical-shape persistence layer (WAL-SQLite or WAL-Postgres) is Phase-2.

| Field | Value |
|---|---|
| **Phase** | **Phase-1 MVP** (in-memory append-only ring + Mirror-Mark stamp + 5 honest-defaults + 10-entry R150 manifest + 9 cite-able legal citations + canonical 8-pack) |
| **Layer** | flagship — clinical-trials audit-trail (B2B Pharma / Biotech / CRO) |
| **Priority** | **BR6 (overnight-3) rank #3 — $900k Y1** (per overnight-3 business-rank cohort) |
| **Primary language (shipped)** | **Go 1.22** (pure-stdlib; zero `go.mod` requires) |
| **Planned sibling** | **Rust 1.78+** (`trial-ledger-rust` per R169 paired-cross-substrate cohort siblings) |
| **Active branch** | `claude/stele-anchor-2026-06-11` (off `main`; opt-in Stele spine anchoring — third flagship consumer wire after ofgemwatch + bias-audit) |
| **Remote** | `github.com/davly/trial-ledger.git` (Apache 2.0) |
| **Internal packages** | **9** (auditledger / fdacfr11 / firewall / honest / legal / lore / manifest / mirrormark + stele on the 2026-06-11 anchor branch) |
| **Binaries** | **1** (cmd/trial-ledger) |
| **Honest-defaults advisories** | **5** (3 Error + 2 Warn per R143.A severity ladder) |
| **R150 manifest entries** | **10** (6 US FDA + 1 UK GDPR + 2 EU + 1 ICH) |
| **Legal citations** | **9** (4 FDA 21 CFR Part 11 quartet + 21 CFR Part 56 + GDPR Article 9 ×2 + EU CTR + ICH-GCP E6(R2)) |
| **Closed-enum AuditActions** | **7** (ecr.create / ecr.modify / ecr.delete / esig.sign / esig.withdraw / ecr.view / ecr.lock) |
| **Closed-enum SignatureMeanings** | **5** (review / approval / responsibility / authorship / verification) |
| **Closed-enum AuthMethods** | **4** (id-password / mfa-totp / mfa-webauthn / biometric) |
| **R151 KAT-1 digest** | `239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca` |
| **R175 saturator role** | **6th cohort saturator** (joins folio + casino + ledger + canopy + ouroboros) |
| **R154 saturator role** | **4th Article-9 cohort saturator** (joins haven + triage-hospital + clinician) |

## What trial-ledger will be

The §11.10(e) audit-trail primitive of choice for clinical-trial sponsors operating in the US (FDA) + EU (EMA via EU CTR 536/2014) + UK (MHRA via UK Clinical Trials Regulation) + ICH-GCP harmonised. Every clinical-trial electronic record (eCRF page, SAE narrative, SDV verification, DSUR entry, IND amendment) and every electronic signature (investigator approval, sponsor monitor review, IRB / IEC chair sign-off) lands as ONE row in this ledger. The row is monotonic-ID + UTC-timestamp + actor + trial-id + subject-id + record-ref + record-hash + Mirror-Mark.

The Mirror-Mark is the load-bearing property: the FDA / EMA / MHRA inspector who exports the audit-trail JSON can independently re-derive every receipt against the trial's lore-corpus SHA and HMAC key, without trusting trial-ledger source or runtime. The receipt confirms: (a) which lore corpus signed the row, (b) the row was unmodified since signing. Compared to the existing 21 CFR Part 11 EDC vendors (Medidata Rave, Veeva Vault EDC, Oracle InForm, IBM Clinical Development), trial-ledger's differentiator is the COLD-VERIFIABILITY property — a regulator reading the audit-trail JSON does not need trial-ledger source or runtime to confirm record integrity.

## Primary use cases

| Use case | Why it matters |
|---|---|
| eCRF page submission audit | Every clinical-trial subject visit page submitted by an investigator is one `ActionCreate` row + (optionally) one `ActionSign` row when the investigator signs. The §11.10(e) audit trail surfaces who submitted + when + against what record-hash. |
| Source Data Verification (SDV) | Clinical Research Associate (CRA) verifies eCRF data against source documents. Each verification is one `ActionSign` row with `Meaning=verification`. |
| SAE narrative authorship | Serious Adverse Event narratives are author-attributed per §11.50(a)(3). One `ActionSign` row with `Meaning=authorship`. |
| Database lock event | Before regulatory submission the database is locked. One `ActionLock` row scopes the trial. |
| IND / IMPD amendment | Investigational New Drug / Investigational Medicinal Product Dossier amendments are signed by the sponsor's regulatory officer. One `ActionSign` row with `Meaning=approval`. |
| Subject de-enrolment | Subject withdraws consent. One `ActionDelete` row marks the subject's records as withdrawn (records still survive per §11.10(e) append-only invariant). |

## 4-phase roadmap

| Phase | Weeks | Deliverables | Acceptance |
|---|---|---|---|
| **Phase 1 — MVP** | DONE (2026-05-27) | Canonical 8-package cohort layout + Mirror-Mark wire-load-bearing + 5 honest-defaults + 10-entry R150 manifest + 9 cite-able legal citations + closed-enum AuditAction/SignatureMeaning/AuthMethod | R174 5-of-5 strict + R175 saturator + R154 saturator; all tests GREEN |
| **Phase 2 — Persistence + sibling** | 1-4 | WAL-SQLite or WAL-PostgreSQL persistence (canonical-shape port); `trial-ledger-rust` paired sibling (R169 byte-identical wire shape) | First 4/4 quartet candidate (with conformal close — joining casino + ledger + folio + pigeonhole + dreamcatcher) |
| **Phase 3 — Production** | 5-8 | §11.200(a)-compliant IdP wiring; IRB-approval validation upstream; multi-tenant scoping; SOC 2 Type II audit prep | First trial-sponsor pilot |
| **Phase 4 — Reviewer integrations** | 9-12 | FDA submission package generator (.eCTD); EMA EudraCT export; PMDA J-eCTD export | First FDA IND submission with trial-ledger audit-trail |

## Dependencies

- **foundation/pkg/mirrormark** — light. Canonical L43 Mirror-Mark v1 algorithm. trial-ledger ships a local byte-identical implementation today (zero-`go.mod`-requires discipline); a future R145-strict additive sweep can replace `internal/mirrormark` with `import "github.com/davly/foundation/pkg/mirrormark"`.
- **engines/reality (optional Phase 2+)** — moderate. Statistical-rigor primitives for trial-data quality scoring (conformal-prediction confidence intervals on missingness rates).
- **engines/parallax (optional Phase 3+)** — light. Cross-source verification (eCRF vs source documents).
- **sdk/limitless-sdk** — light. App-scaffolding + Trinity integration when the operational surface lands.

## Regulator-facing properties

- **FDA 21 CFR Part 11 §11.10(e)** — computer-generated, time-stamped audit trails: `auditledger.Record.At` is UTC wall-clock at append time (caller-supplied At is ignored); `auditledger.Record.ID` is monotonic.
- **FDA 21 CFR Part 11 §11.50(a)** — signature manifestation: `fdacfr11.ElectronicSignature.SignerID` (a)(1) + `SignedAt` (a)(2) + `Meaning` (a)(3) closed-enum.
- **FDA 21 CFR Part 11 §11.70** — signature/record linking: `ElectronicSignature.RecordHash` is the SHA-256 of the canonical record bytes; `LinksTo(record)` round-trips.
- **FDA 21 CFR Part 11 §11.200(a)** — two-factor electronic signature: `fdacfr11.AuthenticationMethod` closed-enum tags the IdP profile that signed; actual enforcement is upstream (honest-defaults advisory makes this explicit).
- **UK / EU GDPR Article 9(1)** — special-category data concerning health: honest-defaults `TRIAL_LEDGER_ARTICLE_9_HEALTH_DATA` advisory + R154 cohort saturator pin.
- **UK / EU GDPR Article 35** — Data Protection Impact Assessment: R150 manifest entry pinned.

## Cohort impact (at inception)

- **R143** LOUD-ONCE-WARNING-FLAG: 5 advisories (3 Error + 2 Warn per R143.A severity ladder) saturating + 1 mirrormark placeholder warning saturating.
- **R145.C** FIREWALL-TEST-DISCIPLINE: 8-package internal/ + 1-binary cmd/ pin saturating.
- **R150** R-PARALLEL-MAP-R144-REVIEW-METADATA-SIBLING: 10-entry manifest with 4-jurisdiction Class-3 axis saturating.
- **R151** R-KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN: KAT-1 HMAC-SHA256 hex pinned + cohort-substrate count incremented (trial-ledger becomes a new Go saturator).
- **R154** R-ARTICLE-9-DSAR-AUDIT-CLASS-COHORT-EXTENSION: **4th Article-9 cohort saturator** (haven + triage-hospital + clinician + trial-ledger).
- **R166** legal-citation cohort: 9-entry `internal/legal` package with FDA / GDPR / EU CTR / ICH-GCP citations.
- **R174** R-COHORT-PORT-FROM-INCEPTION: 5-of-5 strict (every canonical cohort R-rule wired from scaffold birth).
- **R175** R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION: **6th cohort saturator**. `auditledger.NewLedger(nil)` panics; `Append()` has no non-stamped code path; every Record produced by the Ledger HAS a non-empty MirrorMark by construction.
- **Q40 4/4 quartet candidate** (eventual, post-Phase-2 conformal close).
