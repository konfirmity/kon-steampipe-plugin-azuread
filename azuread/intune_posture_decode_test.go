package azuread

import (
	"context"
	"reflect"
	"testing"
	"time"

	jsonserialization "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

func TestIntuneManagedDevicePostureColumnsDecode(t *testing.T) {
	info := decodeManagedDevice(t, `{
		"id": "0a1b2c3d-0000-0000-0000-000000000001",
		"isSupervised": true,
		"azureADRegistered": false,
		"partnerReportedThreatState": "highSeverity",
		"deviceHealthAttestationState": {
			"@odata.type": "microsoft.graph.deviceHealthAttestationState",
			"bitLockerStatus": "enabled",
			"secureBoot": "enabled",
			"codeIntegrity": "enabled",
			"resetCount": 3
		}
	}`)

	if got := info.GetIsSupervised(); got == nil || !*got {
		t.Errorf("GetIsSupervised() = %v, want true", got)
	}
	if got := info.GetAzureADRegistered(); got == nil || *got {
		t.Errorf("GetAzureADRegistered() = %v, want false", got)
	}
	if got := info.PartnerReportedThreatState(); got == nil || *got != "highSeverity" {
		t.Errorf("PartnerReportedThreatState() = %v, want highSeverity", got)
	}
	state, ok := info.DeviceHealthAttestationState().(map[string]interface{})
	if !ok {
		t.Fatalf("DeviceHealthAttestationState() = %#v, want a map", info.DeviceHealthAttestationState())
	}
	if state["bitLockerStatus"] != "enabled" || state["secureBoot"] != "enabled" || state["codeIntegrity"] != "enabled" {
		t.Errorf("attestation state lost Graph's camelCase keys: %v", state)
	}
	if state["resetCount"] != float64(3) {
		t.Errorf("resetCount = %v, want 3", state["resetCount"])
	}
}

func TestIntuneManagedDevicePostureColumnsNullWhenAbsent(t *testing.T) {
	info := decodeManagedDevice(t, `{"id": "0a1b2c3d-0000-0000-0000-000000000003"}`)

	if got := info.PartnerReportedThreatState(); got != nil {
		t.Errorf("PartnerReportedThreatState() = %v, want nil", *got)
	}
	if got := info.DeviceHealthAttestationState(); got != nil {
		t.Errorf("DeviceHealthAttestationState() = %#v, want nil", got)
	}
}

// Shaped like Microsoft Learn's "Get windowsProtectionState" response, with the flag enums carrying two flags each.
const windowsProtectionStatePayload = `{
	"@odata.type": "#microsoft.graph.windowsProtectionState",
	"id": "a1b2c3d4-0000-0000-0000-00000000000a",
	"malwareProtectionEnabled": true,
	"deviceState": "fullScanPending,rebootPending",
	"realTimeProtectionEnabled": false,
	"networkInspectionSystemEnabled": true,
	"quickScanOverdue": true,
	"fullScanOverdue": false,
	"signatureUpdateOverdue": true,
	"rebootRequired": true,
	"fullScanRequired": false,
	"engineVersion": "1.1.24090.11",
	"signatureVersion": "1.419.311.0",
	"antiMalwareVersion": "4.18.24090.11",
	"lastQuickScanDateTime": "2026-11-01T09:10:11Z",
	"lastFullScanDateTime": "0001-01-01T00:00:00Z",
	"lastQuickScanSignatureVersion": "1.419.300.0",
	"lastFullScanSignatureVersion": null,
	"lastReportedDateTime": "2026-11-07T22:00:00Z",
	"productStatus": "serviceNotRunning,avSignaturesOutOfDate",
	"isVirtualMachine": false,
	"tamperProtectionEnabled": true
}`

func decodeWindowsProtectionState(t *testing.T, payload string) *ADIntuneWindowsProtectionStateInfo {
	t.Helper()
	node, err := jsonserialization.NewJsonParseNode([]byte(payload))
	if err != nil {
		t.Fatalf("parse node: %v", err)
	}
	parsed, err := node.GetObjectValue(models.CreateWindowsProtectionStateFromDiscriminatorValue)
	if err != nil {
		t.Fatalf("decode windowsProtectionState: %v", err)
	}
	return &ADIntuneWindowsProtectionStateInfo{parsed.(models.WindowsProtectionStateable), "device-1"}
}

func TestIntuneWindowsProtectionStateDecodesGraphPayload(t *testing.T) {
	info := decodeWindowsProtectionState(t, windowsProtectionStatePayload)

	if got := info.ManagedDeviceID(); *got != "device-1" {
		t.Errorf("ManagedDeviceID() = %v", *got)
	}
	if got := info.ProductStatus(); got == nil || *got != "serviceNotRunning,avSignaturesOutOfDate" {
		t.Errorf("ProductStatus() = %v", got)
	}
	if got := info.DeviceState(); got == nil || *got != "fullScanPending,rebootPending" {
		t.Errorf("DeviceState() = %v", got)
	}
	if got := info.GetRealTimeProtectionEnabled(); got == nil || *got {
		t.Errorf("GetRealTimeProtectionEnabled() = %v, want false", got)
	}
	if got := info.GetTamperProtectionEnabled(); got == nil || !*got {
		t.Errorf("GetTamperProtectionEnabled() = %v, want true", got)
	}
	if got := info.GetSignatureUpdateOverdue(); got == nil || !*got {
		t.Errorf("GetSignatureUpdateOverdue() = %v, want true", got)
	}
	want := time.Date(2026, 11, 7, 22, 0, 0, 0, time.UTC)
	if got := info.LastReportedDateTime(); got == nil || !got.Equal(want) {
		t.Errorf("LastReportedDateTime() = %v, want %v", got, want)
	}
	if got := info.LastFullScanDateTime(); got != nil {
		t.Errorf("LastFullScanDateTime() = %v, want nil for Graph's never placeholder", *got)
	}
}

func TestIntuneWindowsProtectionStateEnumsNilWhenAbsent(t *testing.T) {
	info := decodeWindowsProtectionState(t, `{"malwareProtectionEnabled": true}`)
	if got := info.ProductStatus(); got != nil {
		t.Errorf("ProductStatus() = %v, want nil", *got)
	}
	if got := info.DeviceState(); got != nil {
		t.Errorf("DeviceState() = %v, want nil", *got)
	}
}

// A non-Windows device has no protection state; a denial must still fail the query so the app can report the missing grant.
func TestIntuneWindowsProtectionStateIgnoresOnlyNotFound(t *testing.T) {
	shouldIgnore := tableAzureAdIntuneWindowsProtectionState(context.Background()).List.IgnoreConfig.ShouldIgnoreErrorFunc
	ctx := context.Background()

	if !shouldIgnore(ctx, nil, nil, &RequestError{Code: "ResourceNotFound", Message: "Resource not found"}) {
		t.Error("ResourceNotFound was not ignored")
	}
	if shouldIgnore(ctx, nil, nil, &RequestError{Code: "Forbidden", Message: "Application is not authorized to perform this operation."}) {
		t.Error("Forbidden was ignored")
	}
}

func decodeComplianceSettingState(t *testing.T, summaryPayload, statePayload string) *ADIntuneDeviceComplianceSettingStateInfo {
	t.Helper()
	summaryNode, err := jsonserialization.NewJsonParseNode([]byte(summaryPayload))
	if err != nil {
		t.Fatalf("parse summary: %v", err)
	}
	summary, err := summaryNode.GetObjectValue(models.CreateDeviceCompliancePolicySettingStateSummaryFromDiscriminatorValue)
	if err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	stateNode, err := jsonserialization.NewJsonParseNode([]byte(statePayload))
	if err != nil {
		t.Fatalf("parse state: %v", err)
	}
	state, err := stateNode.GetObjectValue(models.CreateDeviceComplianceSettingStateFromDiscriminatorValue)
	if err != nil {
		t.Fatalf("decode state: %v", err)
	}
	return &ADIntuneDeviceComplianceSettingStateInfo{state.(models.DeviceComplianceSettingStateable), summary.(models.DeviceCompliancePolicySettingStateSummaryable)}
}

func TestIntuneDeviceComplianceSettingStateDecodesGraphPayload(t *testing.T) {
	info := decodeComplianceSettingState(t, `{
		"id": "summary-1",
		"setting": "Windows10CompliancePolicy.BitLockerEnabled",
		"settingName": "Require BitLocker",
		"platformType": "windows10AndLater",
		"nonCompliantDeviceCount": 1
	}`, `{
		"id": "state-1",
		"setting": "Windows10CompliancePolicy.BitLockerEnabled",
		"settingName": "Require BitLocker",
		"deviceId": "0a1b2c3d-0000-0000-0000-000000000001",
		"deviceName": "LAPTOP-01",
		"userPrincipalName": "jane@contoso.com",
		"state": "nonCompliant",
		"complianceGracePeriodExpirationDateTime": "9999-12-31T23:59:59Z"
	}`)

	if got := info.SettingSummaryID(); got == nil || *got != "summary-1" {
		t.Errorf("SettingSummaryID() = %v", got)
	}
	if got := info.PlatformType(); got == nil || *got != "windows10AndLater" {
		t.Errorf("PlatformType() = %v, want windows10AndLater", got)
	}
	if got := info.State(); got == nil || *got != "nonCompliant" {
		t.Errorf("State() = %v, want nonCompliant", got)
	}
	if got := info.GetDeviceId(); got == nil || *got != "0a1b2c3d-0000-0000-0000-000000000001" {
		t.Errorf("GetDeviceId() = %v", got)
	}
	if got := info.Setting(); got == nil || *got != "Windows10CompliancePolicy.BitLockerEnabled" {
		t.Errorf("Setting() = %v", got)
	}
}

// A setting state that omits its own setting fields takes the summary's.
func TestIntuneDeviceComplianceSettingStateFallsBackToSummarySetting(t *testing.T) {
	info := decodeComplianceSettingState(t,
		`{"id": "summary-2", "setting": "Windows10CompliancePolicy.DefenderEnabled", "settingName": "Microsoft Defender Antimalware"}`,
		`{"id": "state-2", "deviceId": "device-2", "state": "compliant"}`)

	if got := info.Setting(); got == nil || *got != "Windows10CompliancePolicy.DefenderEnabled" {
		t.Errorf("Setting() = %v", got)
	}
	if got := info.SettingName(); got == nil || *got != "Microsoft Defender Antimalware" {
		t.Errorf("SettingName() = %v", got)
	}
	if got := info.PlatformType(); got != nil {
		t.Errorf("PlatformType() = %v, want nil", *got)
	}
}

func TestIntuneComplianceSettingStateWireStrings(t *testing.T) {
	for _, wire := range []string{"unknown", "notApplicable", "compliant", "remediated", "nonCompliant", "error", "conflict", "notAssigned"} {
		info := decodeComplianceSettingState(t, `{"id": "s"}`, `{"state": "`+wire+`"}`)
		if got := info.State(); got == nil || *got != wire {
			t.Errorf("state %q decoded to %v", wire, got)
		}
	}
}

// FromMethod and FromField resolve by reflection at query time, so a misspelt name only fails on a live read.
func TestPostureTableColumnTransformsResolve(t *testing.T) {
	assertColumnTransformsResolve(t, tableAzureAdIntuneManagedDevice(context.Background()), &ADIntuneManagedDeviceInfo{})
	assertColumnTransformsResolve(t, tableAzureAdIntuneWindowsProtectionState(context.Background()), &ADIntuneWindowsProtectionStateInfo{})
	assertColumnTransformsResolve(t, tableAzureAdIntuneDeviceComplianceSettingState(context.Background()), &ADIntuneDeviceComplianceSettingStateInfo{})
}

func assertColumnTransformsResolve(t *testing.T, table *plugin.Table, item interface{}) {
	t.Helper()
	itemType := reflect.TypeOf(item)
	for _, column := range table.Columns {
		if column.Transform == nil {
			continue
		}
		for _, call := range column.Transform.Transforms {
			name, ok := call.Param.(string)
			if !ok {
				continue
			}
			_, isMethod := itemType.MethodByName(name)
			_, isField := itemType.Elem().FieldByName(name)
			if !isMethod && !isField {
				t.Errorf("%s.%s reads %s, which %s lacks", table.Name, column.Name, name, itemType)
			}
		}
	}
}
