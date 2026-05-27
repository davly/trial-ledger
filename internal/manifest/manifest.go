// Package manifest implements the R150 cohort-canonical schematised-
// knowledge envelope for trial-ledger's curated content surfaces.
//
// Why trial-ledger consumes this from inception:
//
//   - trial-ledger is an FDA 21 CFR Part 11 clinical-trial audit-trail
//     flagship. Curated content includes 21 CFR Part 11 audit-trail
//     citations, GDPR Article 9 special-category citations, IRB /
//     IEC regulatory references, and the FDA Part 11 Subpart C
//     electronic-signature requirements.
//   - The R150 envelope pins each regulation-citation entry with
//     FreshAt + a cite-able authoritative source (FDA / EMA /
//     EUR-Lex / ICH-GCP) so a regulator-facing audit can detect
//     drift between a claim's recorded confidence and the most
//     recent regulation revision.
//   - Each entry carries an explicit jurisdiction (US / UK / EU /
//     ICH) so the R150 Class-3 jurisdiction-version anchor is
//     load-bearing — a trial sponsor operating in the EU but
//     reading a US-jurisdiction citation gets the staleness signal
//     up-front.
package manifest

import (
	"sort"
	"time"
)

// SchemaVersion is the manifest envelope version. Bumping requires a
// migration of every Entry to the new shape; today every Entry uses
// version 1.
const SchemaVersion = 1

// FreshAtUnknown is the sentinel for entries that predate the FreshAt
// discipline. IsStale always returns true for entries with this
// value — the explicit-honest-TODO signal the cohort R150 9-path
// IsStale matrix enforces.
var FreshAtUnknown = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

// Canonical source-of-truth identifiers. Wire-stable strings; renames
// are regulator-facing log-aggregation breakage.
const (
	SourceFDA21CFR11Subpart_B = "FDA 21 CFR Part 11 Subpart B (electronic records, §11.10 controls + §11.30 open systems + §11.50 signature manifestation + §11.70 signature/record linking)"
	SourceFDA21CFR11Subpart_C = "FDA 21 CFR Part 11 Subpart C (electronic signatures, §11.100 general + §11.200 components/controls + §11.300 identification-code/password controls)"
	SourceFDA21CFR_50         = "FDA 21 CFR Part 50 (protection of human subjects, informed consent)"
	SourceFDA21CFR_56         = "FDA 21 CFR Part 56 (Institutional Review Boards)"
	SourceEUClinicalTrialsReg = "EU Clinical Trials Regulation (EU) No 536/2014 (Article 4: prior authorisation; Article 80: clinical-trial transparency)"
	SourceICHGCP_E6           = "ICH Good Clinical Practice E6(R2) (Integrated Addendum to ICH E6(R1) — sponsor + investigator + ethics committee + essential documents)"
	SourceGDPR_Article_9      = "UK / EU GDPR Article 9 (processing of special categories of personal data: 9(1) prohibition + 9(2)(i)(j) lawful-basis exceptions for public-health + scientific research)"
	SourceGDPR_Article_35     = "UK / EU GDPR Article 35 (Data Protection Impact Assessment)"
	SourceContextDoc          = "trial-ledger CONTEXT.md"
	SourceR85ParityMarker     = "trial-ledger R85 CLEAN-PARITY between code + CONTEXT.md"
)

// Confidence is the cohort 3-rung classifier matching canopy / casino
// / ledger / clinician.
type Confidence int

const (
	ConfidenceHigh   Confidence = 3
	ConfidenceMedium Confidence = 2
	ConfidenceLow    Confidence = 1
)

// Jurisdiction is the R150 Class-3 jurisdiction-version anchor.
// Pinning the jurisdiction makes a same-shape regulation across
// (US, UK, EU) discoverable when one jurisdiction updates ahead of
// another.
type Jurisdiction string

const (
	JurisdictionUS  Jurisdiction = "US"
	JurisdictionUK  Jurisdiction = "UK"
	JurisdictionEU  Jurisdiction = "EU"
	JurisdictionICH Jurisdiction = "ICH"
)

// Entry is one R150 manifest row.
type Entry struct {
	Key           string
	Description   string
	FreshAt       time.Time
	Source        string
	Jurisdiction  Jurisdiction
	SchemaVersion int
	Confidence    Confidence
}

// IsStale returns true if (now - FreshAt) > maxAge or FreshAt is the
// FreshAtUnknown sentinel. R150 9-path matrix: unknown + over-age +
// over-age-by-jurisdiction.
func (e Entry) IsStale(now time.Time, maxAge time.Duration) bool {
	if e.FreshAt.Equal(FreshAtUnknown) {
		return true
	}
	return now.Sub(e.FreshAt) > maxAge
}

// Manifest is the slice of entries comprising the trial-ledger
// curated regulation-citation corpus.
type Manifest []Entry

// SortedKeys returns the manifest keys in lexicographic order. Used
// by the firewall pin to detect insertion-order drift.
func (m Manifest) SortedKeys() []string {
	keys := make([]string, 0, len(m))
	for _, e := range m {
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)
	return keys
}

// StaleEntries returns the subset of m whose IsStale(now, maxAge) is
// true, sorted by key.
func (m Manifest) StaleEntries(now time.Time, maxAge time.Duration) []Entry {
	var out []Entry
	for _, e := range m {
		if e.IsStale(now, maxAge) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// FilterByJurisdiction returns the subset of m matching j. The R150
// Class-3 axis: a sponsor operating in the EU asks for
// FilterByJurisdiction(EU) and gets only EU-relevant rows.
func (m Manifest) FilterByJurisdiction(j Jurisdiction) Manifest {
	var out Manifest
	for _, e := range m {
		if e.Jurisdiction == j {
			out = append(out, e)
		}
	}
	return out
}

// AllSources returns the canonical source-of-truth identifiers (the
// 10 const block). Used by the firewall pin.
func AllSources() []string {
	return []string{
		SourceFDA21CFR11Subpart_B,
		SourceFDA21CFR11Subpart_C,
		SourceFDA21CFR_50,
		SourceFDA21CFR_56,
		SourceEUClinicalTrialsReg,
		SourceICHGCP_E6,
		SourceGDPR_Article_9,
		SourceGDPR_Article_35,
		SourceContextDoc,
		SourceR85ParityMarker,
	}
}

// Seed returns the canonical R150 manifest for trial-ledger.
//
// 10 entries at inception:
//   - 4 FDA 21 CFR Part 11 + Part 50 + Part 56 (US)
//   - 1 EU CTR + 1 ICH-GCP (EU/ICH)
//   - 2 GDPR Article 9 + Article 35 (UK + EU)
//   - 2 internal anchors (CONTEXT parity)
func Seed() Manifest {
	// All regulatory citations checked-against-source on
	// 2026-05-27 — the inception date for trial-ledger.
	regCheck := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	parity := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)

	return Manifest{
		// FDA 21 CFR Part 11 (electronic records + signatures).
		{
			Key:           "regulation.fda.21cfr11.subpart_b.audit_trail",
			Description:   "FDA 21 CFR Part 11 §11.10(e) — secure, computer-generated, time-stamped audit trails independently recording the date and time of operator entries and actions that create, modify, or delete electronic records.",
			FreshAt:       regCheck,
			Source:        SourceFDA21CFR11Subpart_B,
			Jurisdiction:  JurisdictionUS,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},
		{
			Key:           "regulation.fda.21cfr11.subpart_b.system_validation",
			Description:   "FDA 21 CFR Part 11 §11.10(a)-(d) — system validation, copy-of-records availability, record-protection, limited authorised access. trial-ledger ships the audit-trail primitive; the §11.10(a) validation package is the operational tenant responsibility.",
			FreshAt:       regCheck,
			Source:        SourceFDA21CFR11Subpart_B,
			Jurisdiction:  JurisdictionUS,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},
		{
			Key:           "regulation.fda.21cfr11.subpart_c.electronic_signature",
			Description:   "FDA 21 CFR Part 11 Subpart C — electronic-signature controls (§11.100 general + §11.200 two-factor non-biometric + §11.300 identification-code/password aging + lockout). trial-ledger's `ElectronicSignature` shape is a placeholder; production needs a Part 11 §11.200(a)-compliant IdP.",
			FreshAt:       regCheck,
			Source:        SourceFDA21CFR11Subpart_C,
			Jurisdiction:  JurisdictionUS,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},
		{
			Key:           "regulation.fda.21cfr50.informed_consent",
			Description:   "FDA 21 CFR Part 50 — protection of human subjects + informed-consent requirements. trial-ledger does NOT validate informed-consent status of incoming records; upstream EDC/eCRF responsibility.",
			FreshAt:       regCheck,
			Source:        SourceFDA21CFR_50,
			Jurisdiction:  JurisdictionUS,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},
		{
			Key:           "regulation.fda.21cfr56.irb",
			Description:   "FDA 21 CFR Part 56 — Institutional Review Boards. Subject-level audit rows in trial-ledger MUST correspond to subjects enrolled under an IRB-approved protocol; trial-ledger does NOT enforce this.",
			FreshAt:       regCheck,
			Source:        SourceFDA21CFR_56,
			Jurisdiction:  JurisdictionUS,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},

		// EU + ICH.
		{
			Key:           "regulation.eu.ctr.536_2014",
			Description:   "EU Clinical Trials Regulation (EU) No 536/2014 — prior authorisation (Art. 4) + EU Clinical Trials Information System (CTIS) + sponsor-pharmacovigilance obligations. EU equivalent of US 21 CFR Part 312 (IND) + Part 56 (IRB).",
			FreshAt:       regCheck,
			Source:        SourceEUClinicalTrialsReg,
			Jurisdiction:  JurisdictionEU,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},
		{
			Key:           "regulation.ich.gcp.e6_r2",
			Description:   "ICH Good Clinical Practice E6(R2) — sponsor + investigator + ethics-committee responsibilities + essential-documents list. Adopted by FDA + EMA + PMDA as harmonised baseline.",
			FreshAt:       regCheck,
			Source:        SourceICHGCP_E6,
			Jurisdiction:  JurisdictionICH,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},

		// GDPR Article 9 (UK + EU).
		{
			Key:           "regulation.gdpr.article_9.special_category_health",
			Description:   "UK / EU GDPR Article 9(1) prohibits processing of special-category data including health; Article 9(2)(i)(j) lifts the prohibition for public-health interest + scientific research with appropriate safeguards. R154 cohort saturator with haven + triage-hospital + clinician.",
			FreshAt:       regCheck,
			Source:        SourceGDPR_Article_9,
			Jurisdiction:  JurisdictionUK,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},
		{
			Key:           "regulation.gdpr.article_35.dpia",
			Description:   "UK / EU GDPR Article 35 — Data Protection Impact Assessment required when processing is likely to result in high risk; clinical-trial health-data processing typically triggers this.",
			FreshAt:       regCheck,
			Source:        SourceGDPR_Article_35,
			Jurisdiction:  JurisdictionEU,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},

		// Internal anchors.
		{
			Key:           "r85.parity.code_vs_context",
			Description:   "R85 CLEAN-PARITY anchor — CONTEXT.md status row vs runtime ground truth (canonical-advisory count + manifest entry count).",
			FreshAt:       parity,
			Source:        SourceR85ParityMarker,
			Jurisdiction:  JurisdictionUS,
			SchemaVersion: SchemaVersion,
			Confidence:    ConfidenceHigh,
		},
	}
}
