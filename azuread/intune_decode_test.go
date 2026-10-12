package azuread

import (
	"strings"
	"testing"
	"time"

	jsonserialization "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

func decodeManagedDevice(t *testing.T, payload string) *ADIntuneManagedDeviceInfo {
	t.Helper()
	node, err := jsonserialization.NewJsonParseNode([]byte(payload))
	if err != nil {
		t.Fatalf("parse node: %v", err)
	}
	parsed, err := node.GetObjectValue(models.CreateManagedDeviceFromDiscriminatorValue)
	if err != nil {
		t.Fatalf("decode managedDevice: %v", err)
	}
	device, ok := parsed.(models.ManagedDeviceable)
	if !ok {
		t.Fatalf("decoded %T, want ManagedDeviceable", parsed)
	}
	return &ADIntuneManagedDeviceInfo{device}
}

func TestIntuneManagedDeviceDecodesGraphPayload(t *testing.T) {
	info := decodeManagedDevice(t, `{
		"id": "0a1b2c3d-0000-0000-0000-000000000001",
		"deviceName": "LAPTOP-01",
		"serialNumber": "PF3ABC12",
		"azureADDeviceId": "9f8e7d6c-0000-0000-0000-000000000002",
		"userPrincipalName": "jane@contoso.com",
		"emailAddress": "Jane@Contoso.com",
		"operatingSystem": "Windows",
		"osVersion": "10.0.22631.4317",
		"complianceState": "inGracePeriod",
		"isEncrypted": true,
		"managementAgent": "configurationManagerClientMdm",
		"managedDeviceOwnerType": "company",
		"enrolledDateTime": "2025-02-03T04:05:06Z",
		"lastSyncDateTime": "2026-10-12T23:59:01Z",
		"manufacturer": "LENOVO",
		"model": "ThinkPad T14"
	}`)

	if got := info.ComplianceState(); got == nil || *got != "inGracePeriod" {
		t.Errorf("ComplianceState() = %v, want inGracePeriod", got)
	}
	if got := info.ManagementAgent(); got == nil || *got != "configurationManagerClientMdm" {
		t.Errorf("ManagementAgent() = %v, want configurationManagerClientMdm", got)
	}
	if got := info.ManagedDeviceOwnerType(); got == nil || *got != "company" {
		t.Errorf("ManagedDeviceOwnerType() = %v, want company", got)
	}
	if got := info.GetIsEncrypted(); got == nil || !*got {
		t.Errorf("GetIsEncrypted() = %v, want true", got)
	}
	if got := info.GetSerialNumber(); got == nil || *got != "PF3ABC12" {
		t.Errorf("GetSerialNumber() = %v, want PF3ABC12", got)
	}
	if got := info.GetAzureADDeviceId(); got == nil || *got != "9f8e7d6c-0000-0000-0000-000000000002" {
		t.Errorf("GetAzureADDeviceId() = %v", got)
	}
	wantSync := time.Date(2026, 10, 12, 23, 59, 1, 0, time.UTC)
	if got := info.GetLastSyncDateTime(); got == nil || !got.Equal(wantSync) {
		t.Errorf("GetLastSyncDateTime() = %v, want %v", got, wantSync)
	}
	wantEnrolled := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	if got := info.GetEnrolledDateTime(); got == nil || !got.Equal(wantEnrolled) {
		t.Errorf("GetEnrolledDateTime() = %v, want %v", got, wantEnrolled)
	}
}

// The app maps compliance_state words to its own verdicts, so every Graph value must round-trip
// to its exact wire string rather than an SDK constant name.
func TestIntuneComplianceStateWireStrings(t *testing.T) {
	for _, wire := range []string{"unknown", "compliant", "noncompliant", "conflict", "error", "inGracePeriod", "configManager"} {
		info := decodeManagedDevice(t, `{"complianceState": "`+wire+`"}`)
		if got := info.ComplianceState(); got == nil || *got != wire {
			t.Errorf("complianceState %q decoded to %v", wire, got)
		}
	}
}

// An unset enum must stay null: the SDK's zero value is "unknown", which the app would read as a
// real Intune answer.
func TestIntuneManagedDeviceEnumsNilWhenAbsent(t *testing.T) {
	info := decodeManagedDevice(t, `{"id": "0a1b2c3d-0000-0000-0000-000000000003"}`)

	if got := info.ComplianceState(); got != nil {
		t.Errorf("ComplianceState() = %v, want nil", *got)
	}
	if got := info.ManagementAgent(); got != nil {
		t.Errorf("ManagementAgent() = %v, want nil", *got)
	}
	if got := info.ManagedDeviceOwnerType(); got != nil {
		t.Errorf("ManagedDeviceOwnerType() = %v, want nil", *got)
	}
	if got := info.GetIsEncrypted(); got != nil {
		t.Errorf("GetIsEncrypted() = %v, want nil", *got)
	}
	if got := info.GetLastSyncDateTime(); got != nil {
		t.Errorf("GetLastSyncDateTime() = %v, want nil", *got)
	}
}

// The app classifies a missing permission or licence as "not assessed" by the Graph error code in
// the query error text, so that code must survive into the error string.
func TestIntuneForbiddenErrorKeepsGraphCode(t *testing.T) {
	mainErr := odataerrors.NewMainError()
	code := "Forbidden"
	message := "Application is not authorized to perform this operation. Application must have one of the following scopes: DeviceManagementManagedDevices.Read.All"
	mainErr.SetCode(&code)
	mainErr.SetMessage(&message)
	odataErr := odataerrors.NewODataError()
	odataErr.SetErrorEscaped(mainErr)

	got := getErrorObject(odataErr).Error()
	if !strings.Contains(got, `"Code":"Forbidden"`) {
		t.Errorf("error string %q does not carry the Graph code", got)
	}
	if !strings.Contains(got, "DeviceManagementManagedDevices.Read.All") {
		t.Errorf("error string %q does not carry the Graph message", got)
	}
}
