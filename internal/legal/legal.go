// Package legal pins the regulator-cite-able legal anchors for
// trial-ledger as load-bearing Go constants — not free-form prose
// embedded in doc comments.
//
// Why a dedicated package:
//
//   - Per the cohort feedback_knowledge_bedrock_must_be_db_for_domain_rules
//     discipline, regulatory citations that vary by tenant /
//     jurisdiction / phase are NOT hard-coded; they live in a
//     curated DB. But the cohort-canonical FDA / GDPR / ICH
//     citations are UNIVERSAL FACTS (the regulation IS the
//     regulation; the citation does not vary per-tenant) — those
//     belong in code so the firewall test can pin them.
//   - Co-locating the citation strings in a `legal` package (vs
//     scattering them across docstrings) gives the R150 manifest a
//     single canonical re-import point and the R145.C firewall a
//     single grep target.
//
// All citation strings in this file are PUBLIC AUTHORITATIVE TEXT —
// FDA 21 CFR § text + EUR-Lex GDPR Article text + ICH-GCP E6(R2)
// adopted-text. Reproducing them verbatim in a citation pin does not
// invoke any copyright concern; they are statute / regulation /
// harmonised guideline.
package legal

// Citation is the canonical regulator-cite-able pin. RegulatorURL is
// the authoritative-source URL that the FDA / EMA / NHS / IRB
// reviewer would look up; CitationText is the verbatim quoted text
// (kept short — full text lives at the URL).
type Citation struct {
	ID           string // grep-stable identifier
	Jurisdiction string // US / UK / EU / ICH
	CitationText string // verbatim quote, ≤ 240 chars
	RegulatorURL string // authoritative source URL
}

// FDA21CFRPart11_10e is the §11.10(e) audit-trail invariant — the
// load-bearing regulation that justifies trial-ledger's existence.
var FDA21CFRPart11_10e = Citation{
	ID:           "FDA_21_CFR_11_10_e",
	Jurisdiction: "US",
	CitationText: "Use of secure, computer-generated, time-stamped audit trails to independently record the date and time of operator entries and actions that create, modify, or delete electronic records.",
	RegulatorURL: "https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11/subpart-B/section-11.10",
}

// FDA21CFRPart11_50 is the signature-manifestation requirement.
// §11.50(a)(1)-(3) require the printed name + date/time + meaning of
// the signature (e.g., "review", "approval", "responsibility").
var FDA21CFRPart11_50 = Citation{
	ID:           "FDA_21_CFR_11_50",
	Jurisdiction: "US",
	CitationText: "Signed electronic records shall contain information associated with the signing that clearly indicates all of the following: (1) the printed name of the signer; (2) the date and time when the signature was executed; and (3) the meaning (such as review, approval, responsibility, or authorship) associated with the signature.",
	RegulatorURL: "https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11/subpart-B/section-11.50",
}

// FDA21CFRPart11_70 is the signature/record-linking requirement.
// §11.70 requires electronic signatures be linked to their electronic
// records to ensure the signatures cannot be excised, copied, or
// otherwise transferred.
var FDA21CFRPart11_70 = Citation{
	ID:           "FDA_21_CFR_11_70",
	Jurisdiction: "US",
	CitationText: "Electronic signatures and handwritten signatures executed to electronic records shall be linked to their respective electronic records to ensure that the signatures cannot be excised, copied, or otherwise transferred to falsify an electronic record by ordinary means.",
	RegulatorURL: "https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11/subpart-B/section-11.70",
}

// FDA21CFRPart11_200 is the two-factor electronic-signature
// requirement. §11.200(a)(1)(i)-(ii) require two distinct
// identification components for non-biometric signatures.
var FDA21CFRPart11_200 = Citation{
	ID:           "FDA_21_CFR_11_200",
	Jurisdiction: "US",
	CitationText: "Electronic signatures that are not based upon biometrics shall: (1) Employ at least two distinct identification components such as an identification code and password.",
	RegulatorURL: "https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11/subpart-C/section-11.200",
}

// FDA21CFRPart56 is the IRB regulation citation.
var FDA21CFRPart56 = Citation{
	ID:           "FDA_21_CFR_56",
	Jurisdiction: "US",
	CitationText: "An IRB shall review and have authority to approve, require modifications in (to secure approval), or disapprove all research activities covered by these regulations.",
	RegulatorURL: "https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-56",
}

// GDPRArticle9_1 is the special-category-data prohibition.
var GDPRArticle9_1 = Citation{
	ID:           "GDPR_Article_9_1",
	Jurisdiction: "UK", // applies UK + EU; UK chosen as default
	CitationText: "Processing of personal data revealing racial or ethnic origin, political opinions, religious or philosophical beliefs, or trade union membership, and the processing of genetic data, biometric data for the purpose of uniquely identifying a natural person, data concerning health or data concerning a natural person's sex life or sexual orientation shall be prohibited.",
	RegulatorURL: "https://gdpr-info.eu/art-9-gdpr/",
}

// GDPRArticle9_2j is the scientific-research lawful-basis exception.
var GDPRArticle9_2j = Citation{
	ID:           "GDPR_Article_9_2_j",
	Jurisdiction: "UK",
	CitationText: "Paragraph 1 shall not apply if one of the following applies: (j) processing is necessary for archiving purposes in the public interest, scientific or historical research purposes or statistical purposes in accordance with Article 89(1) based on Union or Member State law which shall be proportionate to the aim pursued, respect the essence of the right to data protection and provide for suitable and specific measures to safeguard the fundamental rights and the interests of the data subject.",
	RegulatorURL: "https://gdpr-info.eu/art-9-gdpr/",
}

// EUCTR_Article_4 is the EU Clinical Trials Regulation prior-
// authorisation requirement.
var EUCTR_Article_4 = Citation{
	ID:           "EU_CTR_536_2014_Article_4",
	Jurisdiction: "EU",
	CitationText: "A clinical trial shall be subject to scientific and ethical review and shall be authorised in accordance with this Regulation.",
	RegulatorURL: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32014R0536",
}

// ICHGCP_E6_R2 is the ICH Good Clinical Practice E6(R2) primary
// reference.
var ICHGCP_E6_R2 = Citation{
	ID:           "ICH_GCP_E6_R2",
	Jurisdiction: "ICH",
	CitationText: "Good Clinical Practice (GCP) is an international ethical and scientific quality standard for designing, conducting, recording and reporting trials that involve the participation of human subjects.",
	RegulatorURL: "https://database.ich.org/sites/default/files/E6_R2_Addendum.pdf",
}

// AllCitations returns every Citation in the legal package, in
// canonical insertion order. Used by the firewall pin to detect
// adds / removes.
func AllCitations() []Citation {
	return []Citation{
		FDA21CFRPart11_10e,
		FDA21CFRPart11_50,
		FDA21CFRPart11_70,
		FDA21CFRPart11_200,
		FDA21CFRPart56,
		GDPRArticle9_1,
		GDPRArticle9_2j,
		EUCTR_Article_4,
		ICHGCP_E6_R2,
	}
}
