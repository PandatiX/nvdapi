package nvdapi

import (
	"github.com/pandatix/nvdapi/common"
)

type GetCVEsParams struct {
	CPEName        *string `nvd:"cpeName,omitempty,"`
	CVEID          *string `nvd:"cveId,omitempty,"`
	CVSSV2Metrics  *string `nvd:"cvssV2Metrics,omitempty,"`
	CVSSV2Severity *string `nvd:"cvssV2Severity,omitempty,"`
	CVSSV3Metrics  *string `nvd:"cvssV3Metrics,omitempty,"`
	CVSSV3Severity *string `nvd:"cvssV3Severity,omitempty,"`
	CWEID          *string `nvd:"cweId,omitempty,"`
	// DEPRECATED as of official technical NIST NVD email (15 nov. 2024)
	HasCertAlerts *bool `nvd:"hasCertAlerts,omitempty,noValue"`
	// DEPRECATED as of official technical NIST NVD email (15 nov. 2024)
	HasCertNotes *bool `nvd:"hasCertNotes,omitempty,noValue"`
	HasKEV       *bool `nvd:"hasKev,omitempty,noValue"`
	// DEPRECATED as of official technical NIST NVD email (15 nov. 2024)
	HasOVAL            *bool   `nvd:"hasOval,omitempty,noValue"`
	IsVulnerable       *bool   `nvd:"isVulnerable,omitempty,noValue"`
	KeywordExactMatch  *bool   `nvd:"keywordExactMatch,omitempty,noValue"`
	KeywordSearch      *string `nvd:"keywordSearch,omitempty,"`
	LastModStartDate   *string `nvd:"lastModStartDate,omitempty,"`
	LastModEndDate     *string `nvd:"lastModEndDate,omitempty,"`
	NoRejected         *bool   `nvd:"noRejected,omitempty,noValue"`
	PubStartDate       *string `nvd:"pubStartDate,omitempty,"`
	PubEndDate         *string `nvd:"pubEndDate,omitempty,"`
	ResultsPerPage     *int    `nvd:"resultsPerPage,omitempty,"`
	StartIndex         *int    `nvd:"startIndex,omitempty,"`
	SourceIdentifier   *string `nvd:"sourceIdentifier,omitempty,"`
	VersionStart       *string `nvd:"versionStart,omitempty,"`
	VersionStartType   *string `nvd:"versionStartType,omitempty,"`
	VersionEnd         *string `nvd:"versionEnd,omitempty,"`
	VersionEndType     *string `nvd:"versionEndType,omitempty,"`
	VirtualMatchString *string `nvd:"virtualMatchString,omitempty,"`
}

func GetCVEs(client common.HTTPClient, params GetCVEsParams, opts ...common.Option) (*CVEResponse, error) {
	resp := &CVEResponse{}
	if err := getEndp(client, "cves/2.0", params, resp, opts...); err != nil {
		return nil, err
	}
	return resp, nil
}

type (
	CVEResponse struct {
		ResultsPerPage  int       `json:"resultsPerPage"`
		StartIndex      int       `json:"startIndex"`
		TotalResults    int       `json:"totalResults"`
		Format          string    `json:"format"`
		Version         string    `json:"version"`
		Timestamp       string    `json:"timestamp"`
		Vulnerabilities []CVEItem `json:"vulnerabilities"`
	}

	CVEItem struct {
		CVE CVE `json:"cve"`
	}

	CVE struct {
		ID                    *string         `json:"id,omitempty"`
		SourceIdentifier      *string         `json:"sourceIdentifier,omitempty"`
		VulnStatus            *string         `json:"vulnStatus,omitempty"`
		Published             *string         `json:"published,omitempty"`
		LastModified          *string         `json:"lastModified,omitempty"`
		EvaluatorComment      *string         `json:"evaluatorComment,omitempty"`
		EvaluatorSolution     *string         `json:"evaluatorSolution,omitempty"`
		EvaluatorImpact       *string         `json:"evaluatorImpact,omitempty"`
		CISAExploitAdd        *string         `json:"cisaExploitAdd,omitempty"`
		CISAActionDue         *string         `json:"cisaActionDue,omitempty"`
		CISARequiredAction    *string         `json:"cisaRequiredAction,omitempty"`
		CISAVulnerabilityName *string         `json:"cisaVulnerabilityName,omitempty"`
		Descriptions          []LangString    `json:"descriptions"` // min = 1
		References            []CVEReference  `json:"references"`   // min = 0 ; max = 500
		Metrics               *Metrics        `json:"metrics,omitempty"`
		Weaknesses            []Weakness      `json:"weaknesses,omitempty"`
		Configurations        []Config        `json:"configurations,omitempty"`
		VendorComments        []VendorComment `json:"vendorComments,omitempty"`
		CVETags               []string        `json:"cveTags,omitempty"`
	}

	LangString struct {
		Lang  string `json:"lang"`
		Value string `json:"value"` // max = 4096 chars
	}

	CVEReference struct {
		URL    string   `json:"url"` // max = 500
		Source *string  `json:"source,omitempty"`
		Tags   []string `json:"tags,omitempty"`
	}

	Metrics struct {
		CVSSMetricV40 []CVSSMetricV40 `json:"cvssMetricV40,omitempty"`
		CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31,omitempty"`
		CVSSMetricV30 []CVSSMetricV30 `json:"cvssMetricV30,omitempty"`
		CVSSMetricV2  []CVSSMetricV2  `json:"cvssMetricV2,omitempty"`
	}

	CVSSMetricV2 struct {
		Source                  string    `json:"source"`
		Type                    TypeEnum  `json:"type"`
		CVSSData                CVSSV20   `json:"cvssData"`
		BaseSeverity            *string   `json:"baseSeverity,omitempty"`
		ExploitabilityScore     *Subscore `json:"exploitabilityScore,omitempty"`
		ImpactScore             *Subscore `json:"impactScore,omitempty"`
		ACInsufInfo             *bool     `json:"acInsufInfo,omitempty"`
		ObtainAllPrivilege      *bool     `json:"obtainAllPrivilege,omitempty"`
		ObtainUserPrivilege     *bool     `json:"obtainUserPrivilege,omitempty"`
		ObtainOtherPrivilege    *bool     `json:"obtainOtherPrivilege,omitempty"`
		UserInteractionRequired *bool     `json:"userInteractionRequired,omitempty"`
	}

	CVSSMetricV30 struct {
		Source              string    `json:"source"`
		Type                TypeEnum  `json:"type"`
		CVSSData            CVSSV30   `json:"cvssData"`
		ExploitabilityScore *Subscore `json:"exploitabilityScore,omitempty"`
		ImpactScore         *Subscore `json:"impactScore,omitempty"`
	}

	CVSSMetricV31 struct {
		Source              string    `json:"source"`
		Type                TypeEnum  `json:"type"`
		CVSSData            CVSSV31   `json:"cvssData"`
		ExploitabilityScore *Subscore `json:"exploitabilityScore,omitempty"`
		ImpactScore         *Subscore `json:"impactScore,omitempty"`
	}

	CVSSMetricV40 struct {
		Source   string   `json:"source"`
		Type     TypeEnum `json:"type"`
		CVSSData CVSSV40  `json:"cvssData"`
	}

	Weakness struct {
		Source      string       `json:"source"`
		Type        string       `json:"type"`
		Description []LangString `json:"description"` // min = 0
	}

	Config struct {
		Operator *OperatorEnum `json:"operator,omitempty"`
		Negate   *bool         `json:"negate,omitempty"`
		Nodes    []Node        `json:"nodes"`
	}

	Node struct {
		Operator OperatorEnum  `json:"operator"`
		Negate   *bool         `json:"negate,omitempty"`
		CPEMatch []CVECPEMatch `json:"cpeMatch"`
	}

	CVECPEMatch struct {
		Vulnerable            bool    `json:"vulnerable"`
		Criteria              string  `json:"criteria"`
		MatchCriteriaID       string  `json:"matchCriteriaId"` // uuid
		VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
		VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
		VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
		VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
	}

	VendorComment struct {
		Organization string `json:"organization"`
		Comment      string `json:"comment"`
		LastModified string `json:"lastModified"`
	}

	CVSSV20 struct {
		Version                    string   `json:"version"`
		VectorString               string   `json:"vectorString"`
		AccessVector               *string  `json:"accessVector,omitempty"`
		AccessComplexity           *string  `json:"accessComplexity,omitempty"`
		Authentication             *string  `json:"authentication,omitempty"`
		ConfidentialityImpact      *string  `json:"confidentialityImpact,omitempty"`
		IntegrityImpact            *string  `json:"integrityImpact,omitempty"`
		AvailabilityImpact         *string  `json:"availabilityImpact,omitempty"`
		BaseScore                  float64  `json:"baseScore"`
		BaseSeverity               *string  `json:"baseSeverity,omitempty"`
		Exploitability             *string  `json:"exploitability,omitempty"`
		RemediationLevel           *string  `json:"remediationLevel,omitempty"`
		ReportConfidence           *string  `json:"reportConfidence,omitempty"`
		TemporalScore              *float64 `json:"temporalScore,omitempty"`
		CollateralDamagePotential  *string  `json:"collateralDamagePotential,omitempty"`
		TargetDistribution         *string  `json:"targetDistribution,omitempty"`
		ConfidentialityRequirement *string  `json:"confidentialityRequirement,omitempty"`
		IntegrityRequirement       *string  `json:"integrityRequirement,omitempty"`
		AvailabilityRequirement    *string  `json:"availabilityRequirement,omitempty"`
		EnvironmentalScore         *float64 `json:"environmentalScore,omitempty"`
	}

	CVSSV30 struct {
		Version                       string   `json:"version"`
		VectorString                  string   `json:"vectorString"`
		AttackVector                  *string  `json:"attackVector,omitempty"`
		AttackComplexity              *string  `json:"attackComplexity,omitempty"`
		PrivilegesRequired            *string  `json:"privilegesRequired,omitempty"`
		UserInteraction               *string  `json:"userInteraction,omitempty"`
		Scope                         *string  `json:"scope,omitempty"`
		ConfidentialityImpact         *string  `json:"confidentialityImpact,omitempty"`
		IntegrityImpact               *string  `json:"integrityImpact,omitempty"`
		AvailabilityImpact            *string  `json:"availabilityImpact,omitempty"`
		BaseScore                     float64  `json:"baseScore"`
		BaseSeverity                  string   `json:"baseSeverity"`
		ExploitCodeMaturity           *string  `json:"exploitCodeMaturity,omitempty"`
		RemediationLevel              *string  `json:"remediationLevel,omitempty"`
		ReportConfidence              *string  `json:"reportConfidence,omitempty"`
		TemporalScore                 *float64 `json:"temporalScore,omitempty"`
		TemporalSeverity              *string  `json:"temporalSeverity,omitempty"`
		ConfidentialityRequirement    *string  `json:"confidentialityRequirement,omitempty"`
		IntegrityRequirement          *string  `json:"integrityRequirement,omitempty"`
		AvailabilityRequirement       *string  `json:"availabilityRequirement,omitempty"`
		ModifiedAttackVector          *string  `json:"modifiedAttackVector,omitempty"`
		ModifiedAttackComplexity      *string  `json:"modifiedAttackComplexity,omitempty"`
		ModifiedPrivilegesRequired    *string  `json:"modifiedPrivilegesRequired,omitempty"`
		ModifiedUserInteraction       *string  `json:"modifiedUserInteraction,omitempty"`
		ModifiedScope                 *string  `json:"modifiedScope,omitempty"`
		ModifiedConfidentialityImpact *string  `json:"modifiedConfidentialityImpact,omitempty"`
		ModifiedIntegrityImpact       *string  `json:"modifiedIntegrityImpact,omitempty"`
		ModifiedAvailabilityImpact    *string  `json:"modifiedAvailabilityImpact,omitempty"`
		EnvironmentalScore            *float64 `json:"environmentalScore,omitempty"`
		EnvironmentalSeverity         *string  `json:"environmentalSeverity,omitempty"`
	}

	CVSSV31 struct {
		Version                       string   `json:"version"`
		VectorString                  string   `json:"vectorString"`
		AttackVector                  *string  `json:"attackVector,omitempty"`
		AttackComplexity              *string  `json:"attackComplexity,omitempty"`
		PrivilegesRequired            *string  `json:"privilegesRequired,omitempty"`
		UserInteraction               *string  `json:"userInteraction,omitempty"`
		Scope                         *string  `json:"scope,omitempty"`
		ConfidentialityImpact         *string  `json:"confidentialityImpact,omitempty"`
		IntegrityImpact               *string  `json:"integrityImpact,omitempty"`
		AvailabilityImpact            *string  `json:"availabilityImpact,omitempty"`
		BaseScore                     float64  `json:"baseScore"`
		BaseSeverity                  string   `json:"baseSeverity"`
		ExploitCodeMaturity           *string  `json:"exploitCodeMaturity,omitempty"`
		RemediationLevel              *string  `json:"remediationLevel,omitempty"`
		ReportConfidence              *string  `json:"reportConfidence,omitempty"`
		TemporalScore                 *float64 `json:"temporalScore,omitempty"`
		TemporalSeverity              *string  `json:"temporalSeverity,omitempty"`
		ConfidentialityRequirement    *string  `json:"confidentialityRequirement,omitempty"`
		IntegrityRequirement          *string  `json:"integrityRequirement,omitempty"`
		AvailabilityRequirement       *string  `json:"availabilityRequirement,omitempty"`
		ModifiedAttackVector          *string  `json:"modifiedAttackVector,omitempty"`
		ModifiedAttackComplexity      *string  `json:"modifiedAttackComplexity,omitempty"`
		ModifiedPrivilegesRequired    *string  `json:"modifiedPrivilegesRequired,omitempty"`
		ModifiedUserInteraction       *string  `json:"modifiedUserInteraction,omitempty"`
		ModifiedScope                 *string  `json:"modifiedScope,omitempty"`
		ModifiedConfidentialityImpact *string  `json:"modifiedConfidentialityImpact,omitempty"`
		ModifiedIntegrityImpact       *string  `json:"modifiedIntegrityImpact,omitempty"`
		ModifiedAvailabilityImpact    *string  `json:"modifiedAvailabilityImpact,omitempty"`
		EnvironmentalScore            *float64 `json:"environmentalScore,omitempty"`
		EnvironmentalSeverity         *string  `json:"environmentalSeverity,omitempty"`
	}

	CVSSV40 struct {
		Version                           string   `json:"version"`
		VectorString                      string   `json:"vectorString"`
		AttackVector                      *string  `json:"attackVector,omitempty"`
		AttackComplexity                  *string  `json:"attackComplexity,omitempty"`
		AttackRequirements                *string  `json:"attackRequirements,omitempty"`
		PrivilegesRequired                *string  `json:"privilegesRequired,omitempty"`
		UserInteraction                   *string  `json:"userInteraction,omitempty"`
		VulnConfidentialityImpact         *string  `json:"vulnConfidentialityImpact,omitempty"`
		VulnIntegrityImpact               *string  `json:"vulnIntegrityImpact,omitempty"`
		VulnAvailabilityImpact            *string  `json:"vulnAvailabilityImpact,omitempty"`
		SubConfidentialityImpact          *string  `json:"subConfidentialityImpact,omitempty"`
		SubIntegrityImpact                *string  `json:"subIntegrityImpact,omitempty"`
		SubAvailabilityImpact             *string  `json:"subAvailabilityImpact,omitempty"`
		ExploitMaturity                   *string  `json:"exploitMaturity,omitempty"`
		ConfidentialityRequirement        *string  `json:"confidentialityRequirement,omitempty"`
		IntegrityRequirement              *string  `json:"integrityRequirement,omitempty"`
		AvailabilityRequirement           *string  `json:"availabilityRequirement,omitempty"`
		ModifiedAttackVector              *string  `json:"modifiedAttackVector,omitempty"`
		ModifiedAttackComplexity          *string  `json:"modifiedAttackComplexity,omitempty"`
		ModifiedAttackRequirements        *string  `json:"modifiedAttackRequirements,omitempty"`
		ModifiedPrivilegesRequired        *string  `json:"modifiedPrivilegesRequired,omitempty"`
		ModifiedUserInteraction           *string  `json:"modifiedUserInteraction,omitempty"`
		ModifiedVulnConfidentialityImpact *string  `json:"modifiedVulnConfidentialityImpact,omitempty"`
		ModifiedVulnIntegrityImpact       *string  `json:"modifiedVulnIntegrityImpact,omitempty"`
		ModifiedVulnAvailabilityImpact    *string  `json:"modifiedVulnAvailabilityImpact,omitempty"`
		ModifiedSubConfidentialityImpact  *string  `json:"modifiedSubConfidentialityImpact,omitempty"`
		ModifiedSubIntegrityImpact        *string  `json:"modifiedSubIntegrityImpact,omitempty"`
		ModifiedSubAvailabilityImpact     *string  `json:"modifiedSubAvailabilityImpact,omitempty"`
		Safety                            *string  `json:"Safety,omitempty"`
		Automatable                       *string  `json:"Automatable,omitempty"`
		Recovery                          *string  `json:"Recovery,omitempty"`
		ValueDensity                      *string  `json:"valueDensity,omitempty"`
		VulnerabilityResponseEffort       *string  `json:"vulnerabilityResponseEffort,omitempty"`
		ProviderUrgency                   *string  `json:"providerUrgency,omitempty"`
		BaseScore                         float64  `json:"baseScore"`
		BaseSeverity                      string   `json:"baseSeverity"`
		ThreatScore                       *float64 `json:"threatScore,omitempty"`
		ThreatSeverity                    *string  `json:"threatSeverity,omitempty"`
		EnvironmentalScore                *float64 `json:"environmentalScore,omitempty"`
		EnvironmentalSeverity             *string  `json:"environmentalSeverity,omitempty"`
	}

	TypeEnum     string
	Subscore     float64 // min = 0 ; max = 10
	OperatorEnum string
)

var (
	TypePrimary   TypeEnum = "Primary"
	TypeSecondary TypeEnum = "Secondary"

	OperatorAnd OperatorEnum = "AND"
	OperatorOr  OperatorEnum = "OR"
)
