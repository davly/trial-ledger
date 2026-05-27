// Package honest implements the cohort R143 LOUD-ONCE-WARNING-FLAG
// discipline for trial-ledger, with R157 substrate-native idiom (Go's
// `sync.Once`) and R154 R-ARTICLE-9-DSAR-AUDIT-CLASS-COHORT-EXTENSION
// + R153 R-DOMAIN-ESCAPE-INVARIANT explicit advisories.
//
// trial-ledger operates in two simultaneously-regulated domains:
//
//  1. **FDA 21 CFR Part 11** — clinical-trial electronic records +
//     signatures + audit trail. The §11.10(e) audit-trail invariant
//     ("computer-generated, time-stamped audit trails to
//     independently record the date and time of operator entries and
//     actions") is the namesake load-bearing property. Without
//     independent re-derivability (Mirror-Mark cold-verify), a 21
//     CFR Part 11 submission is unverifiable.
//
//  2. **UK / EU GDPR Article 9** — clinical-trial records contain
//     personal data concerning health (Article 9(1) "special
//     category"). Processing requires an Article 9(2) lawful basis
//     (typically (i) public-health interest or (j) scientific
//     research with appropriate safeguards). R154 saturator cohort:
//     trial-ledger joins haven + triage-hospital + clinician as 4th
//     Article-9 health-data flagship.
//
// trial-ledger's 5 honest-defaults surfaces (the canonical
// scaffold-inception advisory set):
//
//  1. TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED (Error)
//  2. TRIAL_LEDGER_ARTICLE_9_HEALTH_DATA (Error — R154 saturator)
//  3. TRIAL_LEDGER_ELECTRONIC_SIGNATURE_PLACEHOLDER (Error)
//  4. TRIAL_LEDGER_INVESTIGATOR_SIGNOFF_PER_PROTOCOL (Warn)
//  5. TRIAL_LEDGER_IRB_APPROVAL_REQUIRED (Warn)
package honest

import (
	"fmt"
	"io"
	"sync"
)

// LoudOncePrefix is the grep-target prefix every advisory emits at
// first-fire. Byte-identical to canopy / casino / ledger / clinician
// for ecosystem-wide log-aggregation.
const LoudOncePrefix = "[LOUD-ONCE-WARNING]"

// Severity is the R143.A SEVERITY-LADDER-CONVENTION 3-rung enum.
// INFO < WARN < ERROR; Error advisories MUST block production
// promotion.
type Severity string

const (
	SeverityInfo  Severity = "INFO"
	SeverityWarn  Severity = "WARN"
	SeverityError Severity = "ERROR"
)

// Advisory is one honest-defaults entry. Code is the grep-stable
// SCREAMING_SNAKE identifier; Severity is the R143.A 3-rung rung;
// Message is the human-readable text emitted at first-fire; DocLink
// is the relative path to the load-bearing source (e.g.
// "SECURITY.md").
type Advisory struct {
	Code     string
	Severity Severity
	Message  string
	DocLink  string
}

var canonicalAdvisories = []Advisory{
	{
		Code:     "TRIAL_LEDGER_FDA_21_CFR_PART_11_AUDIT_TRAIL_NOT_REVIEWED",
		Severity: SeverityError,
		Message:  "FDA 21 CFR Part 11 §11.10(e) requires \"secure, computer-generated, time-stamped audit trails to independently record the date and time of operator entries and actions that create, modify, or delete electronic records\". trial-ledger ships the audit-trail PRIMITIVE (Mirror-Mark stamped, monotonic ID, UTC timestamp, append-only ring) but the full 21 CFR Part 11 §11.10(a)-(k) validation programme (system validation, copy-of-records availability, record-retention period, training records, written policies for electronic signatures, change-control) is OPERATIONAL TENANT RESPONSIBILITY. NO trial-ledger deployment may be cited in an FDA submission until a qualified Part 11 SME has reviewed the validation package.",
		DocLink:  "SECURITY.md",
	},
	{
		Code:     "TRIAL_LEDGER_ARTICLE_9_HEALTH_DATA",
		Severity: SeverityError,
		Message:  "R154 R-ARTICLE-9-DSAR-AUDIT-CLASS-COHORT-EXTENSION: clinical-trial records contain UK / EU GDPR Article 9(1) special-category personal data concerning health. Processing requires an Article 9(2) lawful basis (typically (i) public-health interest in the area of public health or (j) scientific research) AND, for UK processors, a Data Protection Impact Assessment under Article 35 AND, for EU processors, Article 30 record-of-processing-activities. trial-ledger is the AUDIT-TRAIL primitive; it does NOT enforce or document the Article 9(2) lawful basis — that is the trial sponsor's controller responsibility. Cohort R154 saturator (haven / triage-hospital / clinician / trial-ledger).",
		DocLink:  "SECURITY.md",
	},
	{
		Code:     "TRIAL_LEDGER_ELECTRONIC_SIGNATURE_PLACEHOLDER",
		Severity: SeverityError,
		Message:  "FDA 21 CFR Part 11 Subpart C (§11.100-§11.300) requires electronic signatures be: (a) unique to one individual, (b) verified prior to first use by the issuing organisation, (c) certified to the FDA in writing as legally equivalent to handwritten signatures, (d) comprise two distinct identification components (e.g. ID + password) for non-biometric signatures, (e) executed with controls preventing falsification. trial-ledger's `internal/fdacfr11.ElectronicSignature` is a SHAPE PLACEHOLDER — it captures the canonical fields (signer, intent, timestamp, signature-binding to record-hash) for shape stability, but the actual Part 11 §11.200(a) controls (two-factor enforcement, certification letter to FDA, signature-manifestation linkage) are NOT enforced by this scaffold. Production deployments MUST wire a Part 11 §11.200(a)-compliant identity provider before accepting any signature row as cite-able.",
		DocLink:  "SECURITY.md",
	},
	{
		Code:     "TRIAL_LEDGER_INVESTIGATOR_SIGNOFF_PER_PROTOCOL",
		Severity: SeverityWarn,
		Message:  "Per-protocol investigator sign-off requirements vary by trial phase (Phase 1 / 2 / 3 / 4) and by clinical-protocol document (eCRF / SDV / SAE narrative / DSUR). trial-ledger records the EVENT (who signed, when, on what record) but does NOT enforce per-protocol sign-off cardinality or sequencing — that is the protocol-specific controller responsibility. Treat investigator-signoff audit rows as INDICATIVE; the load-bearing per-protocol enforcement lives upstream in the eCRF / EDC system.",
		DocLink:  "CONTEXT.md",
	},
	{
		Code:     "TRIAL_LEDGER_IRB_APPROVAL_REQUIRED",
		Severity: SeverityWarn,
		Message:  "Institutional Review Board (IRB) / Independent Ethics Committee (IEC) approval is a REGULATORY PRECONDITION for clinical-trial data collection — 21 CFR 50 + 21 CFR 56 (US) and EU Clinical Trials Regulation 536/2014 Article 4 (EU). trial-ledger does NOT validate IRB-approval status of an incoming audit-record; an audit row for a subject NOT covered by an approved protocol is a regulator-visible compliance violation. Production deployments MUST integrate IRB-approval-status validation at the EDC / eCRF tier BEFORE records reach trial-ledger.",
		DocLink:  "SECURITY.md",
	},
}

var (
	registryMu sync.RWMutex
	registry   = map[string]*sync.Once{}
)

// LoudOnce fires the advisory's WARN line exactly once per process
// per Code, regardless of how many times LoudOnce is called. R143
// LOUD-ONCE-WARNING-FLAG primitive; R157 substrate-native idiom
// (sync.Once).
func LoudOnce(adv Advisory, w io.Writer) {
	registryMu.RLock()
	once, ok := registry[adv.Code]
	registryMu.RUnlock()
	if !ok {
		registryMu.Lock()
		once, ok = registry[adv.Code]
		if !ok {
			once = &sync.Once{}
			registry[adv.Code] = once
		}
		registryMu.Unlock()
	}
	once.Do(func() {
		_, _ = fmt.Fprintf(w, "%s %s %s: %s (see %s)\n",
			LoudOncePrefix, adv.Severity, adv.Code, adv.Message, adv.DocLink)
	})
}

// Reset clears the once-registry. Tests MUST call this between cases
// that exercise the same Code; production callers NEVER call this.
func Reset() {
	registryMu.Lock()
	registry = map[string]*sync.Once{}
	registryMu.Unlock()
}

// CanonicalAdvisories returns a copy of the 5-entry canonical
// advisory list. The copy semantics matter: a caller cannot mutate
// the package state through the returned slice.
func CanonicalAdvisories() []Advisory {
	out := make([]Advisory, len(canonicalAdvisories))
	copy(out, canonicalAdvisories)
	return out
}

// FindAdvisory returns the advisory with the given code; ok=false if
// no such code is registered. Useful in tests that pin individual
// advisory shapes.
func FindAdvisory(code string) (Advisory, bool) {
	for _, a := range canonicalAdvisories {
		if a.Code == code {
			return a, true
		}
	}
	return Advisory{}, false
}
