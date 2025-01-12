package nvdapi

import "github.com/pandatix/nvdapi/common"

type GetCVEHistoryParams struct {
	ChangeStartDate *string    `nvd:"changeStartDate,omitempty,"`
	ChangeEndDate   *string    `nvd:"changeEndDate,omitempty,"`
	CVEID           *string    `nvd:"cveId,omitempty,"`
	EventName       *EventName `nvd:"eventName,omitempty,"`
	ResultsPerPage  *int       `nvd:"resultsPerPage,omitempty,"`
	StartIndex      *int       `nvd:"startIndex,omitempty,"`
}

type EventName string

var (
	EventNewCVEReceived      EventName = "New CVE Received"
	EventInitialAnalysis     EventName = "Initial Analysis"
	EventReanalysis          EventName = "Reanalysis"
	EventCVEModified         EventName = "CVE Modified"
	EventModifiedAnalysis    EventName = "Modified Analysis"
	EventCVETranslated       EventName = "CVE Translated"
	EventVendorComment       EventName = "Vendor Comment"
	EventCVESourceUpdate     EventName = "CVE Source Update"
	EventCPEDeprecationRemap EventName = "CPE Deprecation Remap"
	EventCWERemap            EventName = "CWE Remap"
	EventCVERejected         EventName = "CVE Rejected"
	EventCVEUnrejected       EventName = "CVE Unrejected"
	EventCVECISAKEVUpdate    EventName = "CVE CISA KEV Update"
)

func GetCVEHistory(client common.HTTPClient, params GetCVEHistoryParams, opts ...common.Option) (*CVEHistoryResponse, error) {
	resp := &CVEHistoryResponse{}
	if err := getEndp(client, "cvehistory/2.0", params, &resp, opts...); err != nil {
		return nil, err
	}
	return resp, nil
}

type (
	CVEHistoryResponse struct {
		ResultsPerPage int      `json:"resultsPerPage"`
		StartIndex     int      `json:"startIndex"`
		TotalResults   int      `json:"totalResults"`
		Format         string   `json:"format"`
		Version        string   `json:"version"`
		Timestamp      string   `json:"timestamp"`
		CVEChanges     []Change `json:"cveChanges,omitempty"`
	}

	Change struct {
		Change ChangeItem `json:"change"`
	}

	ChangeItem struct {
		CVEID            string  `json:"cveId"`
		EventName        string  `json:"eventName"`
		CVEChangeID      string  `json:"cveChangeId"`
		SourceIdentifier string  `json:"sourceIdentifier"`
		Created          *string `json:"created,omitempty"`
		// Details should be omitempty according to the schema, but is not experimentally
		Details []Detail `json:"details"`
	}

	Detail struct {
		Action   *string `json:"action,omitempty"`
		Type     string  `json:"type"`
		OldValue *string `json:"oldValue,omitempty"`
		NewValue *string `json:"newValue,omitempty"`
	}
)
