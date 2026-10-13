package azuread

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	securitymodels "github.com/microsoftgraph/msgraph-sdk-go/models/security"
)

// The columns push status/severity/service_source/classification through as Graph's wire enum
// strings, so the SDK's String() output must match those wire strings exactly.
func TestAlertEnumStringsAreGraphWireValues(t *testing.T) {
	if got := securitymodels.HIGH_ALERTSEVERITY.String(); got != "high" {
		t.Errorf("high severity wire string = %q, want high", got)
	}
	if got := securitymodels.INFORMATIONAL_ALERTSEVERITY.String(); got != "informational" {
		t.Errorf("informational severity wire string = %q, want informational", got)
	}
	if got := securitymodels.UNKNOWN_ALERTSEVERITY.String(); got != "unknown" {
		t.Errorf("unknown severity wire string = %q, want unknown", got)
	}
	if got := securitymodels.INPROGRESS_ALERTSTATUS.String(); got != "inProgress" {
		t.Errorf("inProgress status wire string = %q, want inProgress", got)
	}
	if got := securitymodels.NEW_ALERTSTATUS.String(); got != "new" {
		t.Errorf("new status wire string = %q, want new", got)
	}
	if got := securitymodels.RESOLVED_ALERTSTATUS.String(); got != "resolved" {
		t.Errorf("resolved status wire string = %q, want resolved", got)
	}
	if got := securitymodels.TRUEPOSITIVE_ALERTCLASSIFICATION.String(); got != "truePositive" {
		t.Errorf("truePositive classification wire string = %q, want truePositive", got)
	}
	if got := securitymodels.FALSEPOSITIVE_ALERTCLASSIFICATION.String(); got != "falsePositive" {
		t.Errorf("falsePositive classification wire string = %q, want falsePositive", got)
	}
	if got := securitymodels.MICROSOFTDEFENDERFOROFFICE365_SERVICESOURCE.String(); got != "microsoftDefenderForOffice365" {
		t.Errorf("service source wire string = %q, want microsoftDefenderForOffice365", got)
	}
}

func TestSecurityAlertTransformsEnumsAndNulls(t *testing.T) {
	alert := securitymodels.NewAlert()
	severity := securitymodels.HIGH_ALERTSEVERITY
	alert.SetSeverity(&severity)
	status := securitymodels.INPROGRESS_ALERTSTATUS
	alert.SetStatus(&status)
	source := securitymodels.MICROSOFTDEFENDERFOROFFICE365_SERVICESOURCE
	alert.SetServiceSource(&source)

	info := &ADSecurityAlertInfo{alert}

	if got := info.Severity(); got == nil || *got != "high" {
		t.Errorf("Severity() = %v, want high", got)
	}
	if got := info.Status(); got == nil || *got != "inProgress" {
		t.Errorf("Status() = %v, want inProgress", got)
	}
	if got := info.ServiceSource(); got == nil || *got != "microsoftDefenderForOffice365" {
		t.Errorf("ServiceSource() = %v, want microsoftDefenderForOffice365", got)
	}
	// classification and determination were never set, so they must stay null rather than
	// collapsing to the zero-value "unknown".
	if got := info.Classification(); got != nil {
		t.Errorf("Classification() = %v, want nil", got)
	}
	if got := info.Determination(); got != nil {
		t.Errorf("Determination() = %v, want nil", got)
	}
}

func TestSecurityAlertComments(t *testing.T) {
	alert := securitymodels.NewAlert()
	comment := securitymodels.NewAlertComment()
	body := "triaged as benign"
	comment.SetComment(&body)
	author := "analyst@acme.com"
	comment.SetCreatedByDisplayName(&author)
	alert.SetComments([]securitymodels.AlertCommentable{comment})

	comments := (&ADSecurityAlertInfo{alert}).Comments()
	if len(comments) != 1 {
		t.Fatalf("got %d comments, want 1", len(comments))
	}
	if comments[0]["comment"] != "triaged as benign" {
		t.Errorf("comment body did not flatten: %+v", comments[0])
	}
	if comments[0]["createdByDisplayName"] != "analyst@acme.com" {
		t.Errorf("comment author did not flatten: %+v", comments[0])
	}
}

func TestSecurityAlertEvidencePassesThroughAdditionalData(t *testing.T) {
	alert := securitymodels.NewAlert()
	evidence := securitymodels.NewAlertEvidence()
	verdict := securitymodels.SUSPICIOUS_EVIDENCEVERDICT
	evidence.SetVerdict(&verdict)
	evidence.SetAdditionalData(map[string]any{"@odata.type": "#microsoft.graph.security.mailboxEvidence", "primaryAddress": "victim@acme.com"})
	alert.SetEvidence([]securitymodels.AlertEvidenceable{evidence})

	items := (&ADSecurityAlertInfo{alert}).Evidence()
	if len(items) != 1 {
		t.Fatalf("got %d evidence items, want 1", len(items))
	}
	if items[0]["verdict"] != "suspicious" {
		t.Errorf("verdict did not flatten to its wire string: %+v", items[0])
	}
	if items[0]["primaryAddress"] != "victim@acme.com" {
		t.Errorf("evidence additionalData was dropped: %+v", items[0])
	}
}

func TestSecurityAlertEvidenceAndCommentsNilWhenAbsent(t *testing.T) {
	info := &ADSecurityAlertInfo{securitymodels.NewAlert()}
	if info.Evidence() != nil {
		t.Error("Evidence() should be nil when the alert has none")
	}
	if info.Comments() != nil {
		t.Error("Comments() should be nil when the alert has none")
	}
}

func TestSecureScoreControlScoreAdditionalDataSources(t *testing.T) {
	control := models.NewControlScore()
	synced := "2026-09-20T04:00:00Z"
	control.SetAdditionalData(map[string]any{
		"implementationStatus": "This control is fully implemented.",
		"lastSynced":           synced,
	})
	max := 10.0
	info := &ADSecureScoreControlScoreInfo{ControlScoreable: control, MaxScore: &max}

	if got := info.ImplementationStatus(); got == nil || *got != "This control is fully implemented." {
		t.Errorf("ImplementationStatus() = %v, want the additionalData string", got)
	}
	if got := info.LastSyncedDateTime(); got == nil || !got.Equal(time.Date(2026, 9, 20, 4, 0, 0, 0, time.UTC)) {
		t.Errorf("LastSyncedDateTime() = %v, want 2026-09-20T04:00:00Z", got)
	}
	if info.MaxScore == nil || *info.MaxScore != 10.0 {
		t.Errorf("MaxScore = %v, want 10", info.MaxScore)
	}
}

func TestSecureScoreControlScoreNullsWhenGraphSilent(t *testing.T) {
	info := &ADSecureScoreControlScoreInfo{ControlScoreable: models.NewControlScore()}
	if info.ImplementationStatus() != nil {
		t.Error("ImplementationStatus() should be nil when Graph provides no value")
	}
	if info.LastSyncedDateTime() != nil {
		t.Error("LastSyncedDateTime() should be nil when Graph provides no value")
	}
	if info.MaxScore != nil {
		t.Error("MaxScore should be nil when no profile exposed it")
	}
}

func TestSubscribedSkuTransforms(t *testing.T) {
	sku := models.NewSubscribedSku()
	skuID := uuid.MustParse("c42b9cae-ea4f-4ab7-9717-81576235ccac")
	sku.SetSkuId(&skuID)
	part := "ENTERPRISEPREMIUM"
	sku.SetSkuPartNumber(&part)

	plan := models.NewServicePlanInfo()
	planID := uuid.MustParse("8e0c0a52-6a6c-4d40-8370-dd62790dcd70")
	plan.SetServicePlanId(&planID)
	planName := "THREAT_INTELLIGENCE"
	plan.SetServicePlanName(&planName)
	provisioning := "Success"
	plan.SetProvisioningStatus(&provisioning)
	sku.SetServicePlans([]models.ServicePlanInfoable{plan})

	info := &ADSubscribedSkuInfo{sku}
	if got := info.SkuId(); got == nil || *got != "c42b9cae-ea4f-4ab7-9717-81576235ccac" {
		t.Errorf("SkuId() = %v, want the GUID string", got)
	}

	plans := info.ServicePlans()
	if len(plans) != 1 {
		t.Fatalf("got %d service plans, want 1", len(plans))
	}
	if plans[0]["servicePlanName"] != "THREAT_INTELLIGENCE" {
		t.Errorf("service plan name did not flatten: %+v", plans[0])
	}
	if plans[0]["servicePlanId"] != "8e0c0a52-6a6c-4d40-8370-dd62790dcd70" {
		t.Errorf("service plan id did not flatten to its GUID string: %+v", plans[0])
	}
}

func TestAdditionalDataStringHandlesPointerAndValue(t *testing.T) {
	direct := "value"
	data := map[string]any{"ptr": &direct, "val": "plain", "wrong": 42}
	if got := additionalDataString(data, "ptr"); got == nil || *got != "value" {
		t.Errorf("pointer string not read: %v", got)
	}
	if got := additionalDataString(data, "val"); got == nil || *got != "plain" {
		t.Errorf("plain string not read: %v", got)
	}
	if additionalDataString(data, "wrong") != nil {
		t.Error("non-string value should yield nil")
	}
	if additionalDataString(nil, "any") != nil {
		t.Error("nil map should yield nil")
	}
}
