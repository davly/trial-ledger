# trial-ledger

**FDA 21 CFR Part 11 clinical-trial audit-trail flagship.**

`trial-ledger` is an append-only audit-trail primitive for clinical-trial electronic records and electronic signatures. Every appended row carries an L43 Mirror-Mark v1 receipt — a cold-verifiable HMAC stamp an FDA reviewer can independently re-derive given the corpus SHA and the HMAC key — so the §11.10(e) "computer-generated, time-stamped audit trail" invariant is independently verifiable without trusting the host filesystem.

The flagship is **Phase-1 MVP** (2026-05-27 inception). It ships:

- The 8 canonical cohort packages from inception (`lore`, `mirrormark`, `manifest`, `honest`, `firewall`, `legal`, `auditledger`, `fdacfr11`)
- R174 5-of-5 strict from inception (full canonical cohort layout)
- **Mirror-Mark wire-load-bearing from inception** (R175 saturator: `auditledger.NewLedger(nil)` panics; there is no off-switch)
- R154 Article-9 cohort 4th saturator (joins haven + triage-hospital + clinician — clinical-trial health-data is GDPR Article 9(1) special category)
- R143 LOUD-ONCE-WARNING-FLAG via `internal/honest` (5 advisories — 3 Error + 2 Warn per R143.A severity ladder)
- R150 schematised-knowledge manifest (10 entries: FDA + EU CTR + ICH-GCP + GDPR + internal parity)
- R151 KAT-1 HMAC-SHA256 cross-substrate parity pin
- R145.C firewall test discipline (structural pin against internal/ + cmd/ drift)

## Cohort-port from inception (R174 5-of-5 strict)

`trial-ledger` is the canonical Go primary substrate. A future `trial-ledger-rust` sibling (R169 paired-cross-substrate cohort siblings, the same byte-identity property as `cipher` ↔ `cipher-next`) ports the same wire shape: same Mirror-Mark base64url body, same audit-action discriminator literals, same JSON shape for `Record.CanonicalBytes()`. The FDA inspector who exports a Go-emitted audit-trail JSON and a Rust-emitted audit-trail JSON gets byte-identical canonical bytes (modulo the Go vs Rust json serializer order, which is pinned by struct field declaration order in both substrates).

## Use cases

- Clinical-trial sponsor records every operator entry into the EDC / eCRF (Electronic Data Capture / Electronic Case Report Form) system with a cold-verifiable receipt
- Investigator signs an eCRF page; the signature event lands here with `RecordHash` linking the signature to the signed record per §11.70
- IRB / regulator audits the trial; the audit-trail JSON exports cold-verify against the trial's corpus SHA + HMAC key
- Trial sponsor submits the audit-trail JSON to the FDA as part of a 21 CFR 312 IND (Investigational New Drug) submission; the FDA reviewer independently re-derives the receipts via `openssl dgst`

## Cold-verify recipe

```
# Given a trial-ledger audit-trail JSON line and the original
# (corpusSHA, key):

# 1. Clear the mirrorMark field from the row JSON.
# 2. Re-marshal to byte-stable JSON.
# 3. Compute HMAC-SHA256(0x01 || corpusSHA || canonical_bytes) with key.
# 4. Confirm base64url(corpusSHA[:8] || hmac) matches the mirrorMark
#    suffix (after the "lore@v1:" prefix).

# Equivalent OpenSSL one-liner (KAT-1 canonical baseline):
printf '\x01' > /tmp/kat1.bin
printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
# → 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
# (byte-identical to the cohort foundation anchor; see internal/lore/lore.go)
```

## Roadmap

| Phase | Deliverables |
|---|---|
| **Phase 1 — MVP** (today, 2026-05-27) | In-memory append-only ring + Mirror-Mark stamp + 5 honest-defaults + 10-entry R150 manifest + 9 cite-able legal citations + canonical 5-pack |
| **Phase 2 — Persistence** | WAL-SQLite append log; `trial-ledger-rust` paired sibling (R169 byte-identical wire shape); first 4/4 quartet candidate (conformal close — joining casino + ledger + folio + pigeonhole + dreamcatcher) |
| **Phase 3 — Production** | Part 11 §11.200(a)-compliant IdP wiring; IRB-approval validation upstream; multi-tenant scoping; SOC 2 Type II audit prep |
| **Phase 4 — Reviewer integrations** | FDA submission package generator (.eCTD); EMA EudraCT export; PMDA J-eCTD export |

## Substrate

- **Primary**: Go 1.22 (pure-stdlib; zero `go.mod` requires)
- **Planned sibling**: Rust 1.78+ (`trial-ledger-rust` per R169)

## License

Apache 2.0 — see [LICENSE](./LICENSE).
