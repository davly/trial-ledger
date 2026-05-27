# trial-ledger — Security & Threat Model

**Status**: pure-Go library + offline CLI (Phase-1 MVP, inception 2026-05-27) — FDA 21 CFR Part 11 clinical-trial audit-trail forge in `cmd/trial-ledger` (one CLI binary) + 8 internal packages (`internal/{auditledger,fdacfr11,firewall,honest,legal,lore,manifest,mirrormark}`). **No HTTP listener, no HTTP client, no daemon, no auth surface, no DB.** The CLI reads two env vars (`TRIAL_LEDGER_LORE_CORPUS_SHA_PATH` + `TRIAL_LEDGER_MIRRORMARK_KEY`) at boot for the Mirror-Mark marker, and reads / writes newline-delimited JSON on stdin / stdout. This file documents the trust boundaries that DO exist so future agents can verify what is and is not part of the threat model.

The shipped scaffold is the **append-only audit-trail primitive** with **Mirror-Mark wire-load-bearing from inception (R175 saturator)**. The full 21 CFR Part 11 §11.10(a)-(k) validation programme (system validation, copy-of-records availability, record-retention period, training records, written policies for electronic signatures, change-control) is **operational tenant responsibility** — flagged via the `TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED` honest-defaults advisory (Error). Production deployments MUST wire (a) a Part 11 §11.200(a)-compliant identity provider, (b) IRB-approval validation upstream at the EDC / eCRF tier, (c) WAL-persistence (the in-memory ring is Phase-1 only), (d) tenant-scoping for multi-trial sponsors. **When Phase 2 lands, this file MUST be refreshed.**

## Substrate context

- **Primary language**: Go 1.22; `cmd/trial-ledger` is an offline CLI (`append` reads stdin / writes stdout; `advisories` / `version` / `manifest` / `legal` are pure prints). No HTTP listener, no auth, no daemon mode.
- **Planned sibling (R169)**: Rust 1.78+ via `trial-ledger-rust` — byte-identical wire shape; this file applies to both substrates.
- **Go dependencies**: zero (verified by `cat go.mod` — only `module github.com/davly/trial-ledger` + `go 1.22`; no `require` block, no `go.sum`).
- **Shape**: pure library — `internal/` packages are deterministic pure functions of their inputs; `cmd/trial-ledger` is a one-shot CLI reading `os.Args` + stdin + two env vars only.
- **Domain audience**: clinical-trial sponsors (pharma + biotech + medical-device), CROs (Contract Research Organisations), academic medical centres, IRBs / IECs, FDA / EMA / MHRA / PMDA reviewers.

## 5-boundary surface

| Boundary | Threat | Mitigation |
|---|---|---|
| **B1: Mirror-Mark cold-verifiability** | An audit row is emitted without a Mirror-Mark, defeating the §11.10(e) independent re-derivability property | R175 wire-load-bearing pin: `NewLedger(nil)` panics; `Append()` has no non-stamped code path. Behavioural test `TestAppend_R175EveryAppendStampsMark` asserts 100 sequential appends all carry MirrorMark. |
| **B2: Closed-enum invariants** | Free-form action / meaning / auth-method strings creep in, defeating the §11.10(e) "actions that create, modify, or delete electronic records" pre-declared category requirement | R115 SINGLE-ENUM-REJECTION-OUTCOME pattern: `AuditAction`, `SignatureMeaning`, `AuthenticationMethod` are typed closed-enums. `Append()` + `ElectronicSignature.Validate()` reject any non-enum value with a typed error. |
| **B3: §11.10(e) time-stamp integrity** | Caller-supplied timestamps are accepted, defeating "computer-generated, time-stamped" | `Ledger.Append()` ignores `in.At` (the field doesn't exist on AppendInput); `Record.At = time.Now().UTC()` is set inside the Ledger lock. Test `TestAppend_TimestampIsUTC` pins. |
| **B4: §11.70 signature/record linking** | An ElectronicSignature is forged with arbitrary RecordHash, defeating the §11.70 "shall be linked to their respective electronic records" property | `ElectronicSignature.Validate()` requires non-empty RecordHash; `LinksTo(record)` round-trips SHA-256 of canonical record bytes. Tests `TestElectronicSignature_LinksTo_RoundTrip` + `TestElectronicSignature_LinksTo_TamperDetected` pin. |
| **B5: GDPR Article 9 special-category data** | A sponsor processes clinical-trial subject data without explicit Article 9(2) lawful basis | Honest-defaults `TRIAL_LEDGER_ARTICLE_9_HEALTH_DATA` advisory (Error) fires at every CLI invocation; R150 manifest entries `regulation.gdpr.article_9.special_category_health` + `regulation.gdpr.article_35.dpia` pin the regulatory anchors. trial-ledger is the AUDIT-TRAIL primitive — it does NOT enforce the Article 9(2) lawful-basis; that is the trial sponsor controller responsibility. |

## Out-of-scope (Phase-1 — defended via honest-defaults Error advisories)

1. **FDA 21 CFR Part 11 system validation** — §11.10(a)-(d) requires system-validation, copy-of-records, record-protection, limited-authorised-access controls. trial-ledger ships the AUDIT-TRAIL primitive only; the §11.10(a) validation package is operational tenant responsibility. `TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED` Error advisory.
2. **Electronic-signature controls** — §11.200(a) two-factor enforcement + §11.100(b) certification letter to FDA + §11.300 ID-code / password aging + lockout. trial-ledger's `ElectronicSignature` is a SHAPE PLACEHOLDER. `TRIAL_LEDGER_ELECTRONIC_SIGNATURE_PLACEHOLDER` Error advisory.
3. **IRB / IEC approval validation** — 21 CFR 50 + 56 (US) + EU CTR Article 4 (EU). trial-ledger does NOT validate IRB-approval status of incoming records; upstream EDC / eCRF responsibility. `TRIAL_LEDGER_IRB_APPROVAL_REQUIRED` Warn advisory.
4. **Per-protocol investigator sign-off enforcement** — protocol-specific cardinality / sequencing. trial-ledger records the EVENT, not the rule. `TRIAL_LEDGER_INVESTIGATOR_SIGNOFF_PER_PROTOCOL` Warn advisory.

## Mirror-Mark key management

- The HMAC key (`TRIAL_LEDGER_MIRRORMARK_KEY`) is the load-bearing secret. Loss or compromise of the key destroys the cold-verifiability property of every existing mark.
- Production deployments MUST: (a) use a secret-manager backed key (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager), (b) rotate at the trial-database-lock event boundary (post-lock marks should use a new key; pre-lock marks remain cold-verifiable under the old key for the FDA 21 CFR Part 11 §11.10(c) record-retention period), (c) maintain a key-history log linking trial-id windows to keys.
- The development placeholder key `iik_dev_TRIAL_LEDGER_NOT_FOR_PRODUCTION` is grep-loud-by-name to detect leaked-to-prod use.

## Pre-Phase-2 hardening checklist

- [ ] WAL-SQLite persistence layer (canonical-shape additive; preserves wire bytes byte-for-byte)
- [ ] Multi-tenant scoping (per-trial-sponsor isolation; key-per-tenant)
- [ ] Reader index for `List()` performance (current O(n) trial scan is fine for in-memory ring but breaks at ledger sizes that fit a real trial)
- [ ] Append-rate metrics (Prometheus `trial_ledger_appends_total`)
- [ ] Verification-rate metrics (`trial_ledger_verify_total` + `trial_ledger_verify_failures_total`)
- [ ] Daily cold-verify CI job: re-derive every Mirror-Mark in the ledger snapshot; alert on drift

## Reproducibility (R151 cohort property)

`internal/lore/lore.go` pins the cohort-canonical KAT-1 HMAC-SHA256 digest:

```
HMAC-SHA256(empty-key, 0x01 || 32×0x00) = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

A regulator with OpenSSL (no Limitless toolchain) reproduces this in one command:

```
printf '\x01' > /tmp/kat1.bin
printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
```

The Compute() function in `internal/lore/lore.go` MUST byte-equal this digest; `TestKAT1_DigestPin` is the test-side firewall.
