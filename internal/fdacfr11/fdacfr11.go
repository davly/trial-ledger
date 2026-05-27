// Package fdacfr11 implements the FDA 21 CFR Part 11 electronic-
// records + electronic-signatures primitive for trial-ledger.
//
// What this package is:
//
//	The shape primitive for 21 CFR Part 11 §11.10 (electronic
//	records) and §11.50-§11.70 (signature manifestation + linking)
//	and §11.200 (electronic-signature two-factor controls). Callers
//	construct ElectronicRecord + ElectronicSignature values; the
//	package canonicalises them (Go json.Marshal-stable shape) so
//	an audit-ledger row can stamp a Mirror-Mark over the canonical
//	bytes and an FDA reviewer can cold-verify the receipt.
//
// What this package is NOT:
//
//	A turn-key 21 CFR Part 11 compliance solution. The
//	`TRIAL_LEDGER_ELECTRONIC_SIGNATURE_PLACEHOLDER` honest-defaults
//	advisory makes this explicit: the actual Part 11 §11.200(a)
//	controls (two-factor enforcement, certification letter to FDA,
//	signature-manifestation linkage) require an upstream Part 11-
//	compliant identity provider. This package captures the canonical
//	field shape so the audit-trail Mirror-Mark is byte-stable across
//	signature implementations.
//
// Wire shape (load-bearing for Mirror-Mark cold-verify):
//
//	ElectronicRecord:
//	  RecordType   string  // e.g. "ecrf.subject_visit", "sae.narrative"
//	  RecordID     string  // tenant-namespaced unique ID
//	  RecordHash   string  // SHA-256 hex of the canonical record body
//	  CreatedAt    time.Time
//	  CreatorID    string
//	  TrialID      string  // protocol identifier
//	  SubjectID    string  // anonymised subject identifier
//	  ContentType  string  // MIME (typically application/json)
//
//	ElectronicSignature:
//	  SignerID         string // §11.50(a)(1) printed name / unique ID
//	  SignedAt         time.Time // §11.50(a)(2) date/time
//	  Meaning          SignatureMeaning // §11.50(a)(3) review / approval / etc.
//	  RecordHash       string // §11.70 linking — SHA-256 of signed record
//	  Method           AuthenticationMethod // §11.200(a) two-factor descriptor
//	  CertificationRef string // ID of the §11.100(b) certification letter to FDA
package fdacfr11

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// SignatureMeaning is the closed-enum 21 CFR §11.50(a)(3) meaning
// classifier. R115 SINGLE-ENUM-REJECTION-OUTCOME-style discipline:
// free-form meaning strings would defeat the §11.50(a)(3) requirement
// that the meaning be explicitly recorded.
type SignatureMeaning string

const (
	// MeaningReview — the signer attests they have reviewed the record.
	MeaningReview SignatureMeaning = "review"
	// MeaningApproval — the signer attests they approve the record.
	MeaningApproval SignatureMeaning = "approval"
	// MeaningResponsibility — the signer attests responsibility for the record.
	MeaningResponsibility SignatureMeaning = "responsibility"
	// MeaningAuthorship — the signer attests they authored the record.
	MeaningAuthorship SignatureMeaning = "authorship"
	// MeaningVerification — investigator verification of source data.
	MeaningVerification SignatureMeaning = "verification"
)

// AllSignatureMeanings returns the closed-enum 5-tuple. R143 firewall
// test pins this list.
func AllSignatureMeanings() []SignatureMeaning {
	return []SignatureMeaning{
		MeaningReview,
		MeaningApproval,
		MeaningResponsibility,
		MeaningAuthorship,
		MeaningVerification,
	}
}

// AuthenticationMethod is the closed-enum descriptor for §11.200(a)
// two-factor authentication. Names match common IdP profiles; the
// actual enforcement happens upstream at the IdP — this is a
// declarative TAG so the audit-ledger row records WHICH IdP profile
// signed.
type AuthenticationMethod string

const (
	// MethodIDPassword — §11.200(a)(1) baseline two-factor (ID code + password).
	MethodIDPassword AuthenticationMethod = "id-password"
	// MethodMFA_TOTP — TOTP-based MFA (e.g. Google Authenticator).
	MethodMFA_TOTP AuthenticationMethod = "mfa-totp"
	// MethodMFA_WebAuthn — WebAuthn / FIDO2 hardware-key based MFA.
	MethodMFA_WebAuthn AuthenticationMethod = "mfa-webauthn"
	// MethodBiometric — §11.200(b) biometric signature method.
	MethodBiometric AuthenticationMethod = "biometric"
)

// AllAuthenticationMethods returns the closed-enum 4-tuple.
func AllAuthenticationMethods() []AuthenticationMethod {
	return []AuthenticationMethod{
		MethodIDPassword,
		MethodMFA_TOTP,
		MethodMFA_WebAuthn,
		MethodBiometric,
	}
}

// ElectronicRecord is the §11.10 electronic-record shape. Field order
// is load-bearing for the canonical-bytes derivation (encoding/json
// marshals struct fields in declaration order).
type ElectronicRecord struct {
	RecordType  string    `json:"recordType"`
	RecordID    string    `json:"recordId"`
	RecordHash  string    `json:"recordHash"`
	CreatedAt   time.Time `json:"createdAt"`
	CreatorID   string    `json:"creatorId"`
	TrialID     string    `json:"trialId"`
	SubjectID   string    `json:"subjectId,omitempty"`
	ContentType string    `json:"contentType"`
}

// Validate returns a non-nil error if the record is missing
// required fields. Required: RecordType / RecordID / RecordHash /
// CreatorID / TrialID / ContentType. CreatedAt zero-value is
// rejected.
func (r ElectronicRecord) Validate() error {
	if strings.TrimSpace(r.RecordType) == "" {
		return errors.New("fdacfr11: ElectronicRecord.RecordType required")
	}
	if strings.TrimSpace(r.RecordID) == "" {
		return errors.New("fdacfr11: ElectronicRecord.RecordID required")
	}
	if strings.TrimSpace(r.RecordHash) == "" {
		return errors.New("fdacfr11: ElectronicRecord.RecordHash required")
	}
	if strings.TrimSpace(r.CreatorID) == "" {
		return errors.New("fdacfr11: ElectronicRecord.CreatorID required")
	}
	if strings.TrimSpace(r.TrialID) == "" {
		return errors.New("fdacfr11: ElectronicRecord.TrialID required")
	}
	if strings.TrimSpace(r.ContentType) == "" {
		return errors.New("fdacfr11: ElectronicRecord.ContentType required")
	}
	if r.CreatedAt.IsZero() {
		return errors.New("fdacfr11: ElectronicRecord.CreatedAt required (§11.10(e) time-stamp invariant)")
	}
	return nil
}

// CanonicalBytes returns the JSON encoding of the record for hashing
// + Mirror-Mark stamping. UTC-normalised CreatedAt — a regulator
// re-deriving in a different timezone reproduces the same canonical.
func (r ElectronicRecord) CanonicalBytes() ([]byte, error) {
	c := r
	c.CreatedAt = c.CreatedAt.UTC()
	return json.Marshal(c)
}

// HashRecordBody returns the SHA-256 hex digest of the supplied
// record body bytes. Callers populate ElectronicRecord.RecordHash
// with this value so §11.70 linking is byte-stable.
func HashRecordBody(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// ElectronicSignature is the §11.50 + §11.70 + §11.200 signature
// shape. Field order is load-bearing for canonical-bytes derivation.
type ElectronicSignature struct {
	SignerID         string               `json:"signerId"`
	SignedAt         time.Time            `json:"signedAt"`
	Meaning          SignatureMeaning     `json:"meaning"`
	RecordHash       string               `json:"recordHash"`
	Method           AuthenticationMethod `json:"method"`
	CertificationRef string               `json:"certificationRef,omitempty"`
}

// Validate returns a non-nil error if the signature is missing
// required fields. Required: SignerID / SignedAt / Meaning (in
// allowed enum) / RecordHash / Method (in allowed enum).
func (s ElectronicSignature) Validate() error {
	if strings.TrimSpace(s.SignerID) == "" {
		return errors.New("fdacfr11: ElectronicSignature.SignerID required (§11.50(a)(1) printed name)")
	}
	if s.SignedAt.IsZero() {
		return errors.New("fdacfr11: ElectronicSignature.SignedAt required (§11.50(a)(2) date/time)")
	}
	if !isValidMeaning(s.Meaning) {
		return errors.New("fdacfr11: ElectronicSignature.Meaning must be one of the closed-enum values (review / approval / responsibility / authorship / verification)")
	}
	if strings.TrimSpace(s.RecordHash) == "" {
		return errors.New("fdacfr11: ElectronicSignature.RecordHash required (§11.70 signature/record linking)")
	}
	if !isValidMethod(s.Method) {
		return errors.New("fdacfr11: ElectronicSignature.Method must be one of the closed-enum values (id-password / mfa-totp / mfa-webauthn / biometric)")
	}
	return nil
}

// CanonicalBytes returns the JSON encoding of the signature for
// hashing + Mirror-Mark stamping. UTC-normalised SignedAt.
func (s ElectronicSignature) CanonicalBytes() ([]byte, error) {
	c := s
	c.SignedAt = c.SignedAt.UTC()
	return json.Marshal(c)
}

// LinksTo confirms the signature is §11.70-linked to the supplied
// record (SHA-256(record.CanonicalBytes()) matches signature.RecordHash).
// Returns the link-validity bool + a typed error on canonicalisation
// failure.
func (s ElectronicSignature) LinksTo(r ElectronicRecord) (bool, error) {
	rb, err := r.CanonicalBytes()
	if err != nil {
		return false, err
	}
	wantHex := HashRecordBody(rb)
	return wantHex == s.RecordHash, nil
}

// SortedMeanings returns AllSignatureMeanings as a sorted-strings
// slice; used by the firewall pin.
func SortedMeanings() []string {
	all := AllSignatureMeanings()
	out := make([]string, 0, len(all))
	for _, m := range all {
		out = append(out, string(m))
	}
	sort.Strings(out)
	return out
}

func isValidMeaning(m SignatureMeaning) bool {
	for _, allowed := range AllSignatureMeanings() {
		if m == allowed {
			return true
		}
	}
	return false
}

func isValidMethod(m AuthenticationMethod) bool {
	for _, allowed := range AllAuthenticationMethods() {
		if m == allowed {
			return true
		}
	}
	return false
}
