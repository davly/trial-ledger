module github.com/davly/trial-ledger

go 1.22

// Additive .evidence-bundle consumer wire-in (2026-05-29). trial-ledger is the
// THIRD flagship consumer of the limitless-evidence-bundle SPEC v1 format
// (Folio was first, bias-audit second). It imports ONLY the public pkg/evidence
// façade, never the evidence repo's internal/* (the regulator-grade firewall).
// The local replace points at the sibling checkout; pkg/evidence lives on that
// repo's main branch, so this require is robust to that tree's branch state.
require github.com/davly/limitless-evidence-bundle v0.0.0

replace github.com/davly/limitless-evidence-bundle => ../../apps/limitless-evidence-bundle
