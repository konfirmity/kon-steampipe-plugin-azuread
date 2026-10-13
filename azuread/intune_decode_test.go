package azuread

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	jsonserialization "github.com/microsoft/kiota-serialization-json-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	betaodataerrors "github.com/microsoftgraph/msgraph-beta-sdk-go/models/odataerrors"
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
	if got := info.LastSyncDateTime(); got == nil || !got.Equal(wantSync) {
		t.Errorf("LastSyncDateTime() = %v, want %v", got, wantSync)
	}
	wantEnrolled := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	if got := info.EnrolledDateTime(); got == nil || !got.Equal(wantEnrolled) {
		t.Errorf("EnrolledDateTime() = %v, want %v", got, wantEnrolled)
	}
}

// Graph sends 0001-01-01T00:00:00Z for a device that never enrolled, synced or entered a grace
// period; passed through, the app would store it as a real date.
func TestIntuneManagedDevicePlaceholderDatesAreNull(t *testing.T) {
	info := decodeManagedDevice(t, `{
		"enrolledDateTime": "0001-01-01T00:00:00Z",
		"lastSyncDateTime": "0001-01-01T00:00:00Z",
		"complianceGracePeriodExpirationDateTime": "0001-01-01T00:00:00Z"
	}`)

	if got := info.EnrolledDateTime(); got != nil {
		t.Errorf("EnrolledDateTime() = %v, want nil", *got)
	}
	if got := info.LastSyncDateTime(); got != nil {
		t.Errorf("LastSyncDateTime() = %v, want nil", *got)
	}
	if got := info.ComplianceGracePeriodExpirationDateTime(); got != nil {
		t.Errorf("ComplianceGracePeriodExpirationDateTime() = %v, want nil", *got)
	}
}

// FromMethod resolves by reflection at query time, so a misspelt method only fails on a live read.
func TestIntuneManagedDeviceColumnMethodsExist(t *testing.T) {
	infoType := reflect.TypeOf(&ADIntuneManagedDeviceInfo{})
	for _, column := range tableAzureAdIntuneManagedDevice(context.Background()).Columns {
		if column.Transform == nil {
			continue
		}
		for _, call := range column.Transform.Transforms {
			name, ok := call.Param.(string)
			if !ok {
				continue
			}
			if _, found := infoType.MethodByName(name); !found {
				t.Errorf("column %s reads method %s, which ADIntuneManagedDeviceInfo lacks", column.Name, name)
			}
		}
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

func decodeDetectedApp(t *testing.T, managedDeviceID, payload string) *ADIntuneDetectedAppInfo {
	t.Helper()
	node, err := jsonserialization.NewJsonParseNode([]byte(payload))
	if err != nil {
		t.Fatalf("parse node: %v", err)
	}
	parsed, err := node.GetObjectValue(betamodels.CreateDetectedAppFromDiscriminatorValue)
	if err != nil {
		t.Fatalf("decode detectedApp: %v", err)
	}
	app, ok := parsed.(betamodels.DetectedAppable)
	if !ok {
		t.Fatalf("decoded %T, want DetectedAppable", parsed)
	}
	return &ADIntuneDetectedAppInfo{app, managedDeviceID}
}

func TestIntuneDetectedAppDecodesGraphPayload(t *testing.T) {
	info := decodeDetectedApp(t, "0a1b2c3d-0000-0000-0000-000000000001", `{
		"id": "00002f5d5d8d1d0d4c0a7e0c2c3d0f6b1a2b0000ffff",
		"displayName": "Google Chrome",
		"version": "129.0.6668.90",
		"sizeInByte": 5368709120,
		"deviceCount": 42,
		"publisher": "Google LLC",
		"platform": "macOS"
	}`)

	if got := info.ManagedDeviceID(); got == nil || *got != "0a1b2c3d-0000-0000-0000-000000000001" {
		t.Errorf("ManagedDeviceID() = %v", got)
	}
	if got := info.GetId(); got == nil || *got != "00002f5d5d8d1d0d4c0a7e0c2c3d0f6b1a2b0000ffff" {
		t.Errorf("GetId() = %v", got)
	}
	if got := info.GetDisplayName(); got == nil || *got != "Google Chrome" {
		t.Errorf("GetDisplayName() = %v, want Google Chrome", got)
	}
	if got := info.GetVersion(); got == nil || *got != "129.0.6668.90" {
		t.Errorf("GetVersion() = %v, want 129.0.6668.90", got)
	}
	if got := info.GetPublisher(); got == nil || *got != "Google LLC" {
		t.Errorf("GetPublisher() = %v, want Google LLC", got)
	}
	if got := info.Platform(); got == nil || *got != "macOS" {
		t.Errorf("Platform() = %v, want macOS", got)
	}
	if got := info.GetSizeInByte(); got == nil || *got != 5368709120 {
		t.Errorf("GetSizeInByte() = %v, want 5368709120", got)
	}
	if got := info.GetDeviceCount(); got == nil || *got != 42 {
		t.Errorf("GetDeviceCount() = %v, want 42", got)
	}
}

// The app maps platform words to package ecosystems, so every Graph value must round-trip to its
// exact wire string rather than an SDK constant name.
func TestIntuneDetectedAppPlatformWireStrings(t *testing.T) {
	for _, wire := range []string{"unknown", "windows", "windowsMobile", "windowsHolographic", "ios", "macOS", "chromeOS", "androidOSP", "androidDeviceAdministrator", "androidWorkProfile", "androidDedicatedAndFullyManaged"} {
		info := decodeDetectedApp(t, "device", `{"platform": "`+wire+`"}`)
		if got := info.Platform(); got == nil || *got != wire {
			t.Errorf("platform %q decoded to %v", wire, got)
		}
	}
}

func TestIntuneDetectedAppAbsentFieldsAreNull(t *testing.T) {
	info := decodeDetectedApp(t, "device", `{"id": "app-1", "displayName": "Notepad++"}`)

	if got := info.Platform(); got != nil {
		t.Errorf("Platform() = %v, want nil", *got)
	}
	if got := info.GetVersion(); got != nil {
		t.Errorf("GetVersion() = %v, want nil", *got)
	}
	if got := info.GetSizeInByte(); got != nil {
		t.Errorf("GetSizeInByte() = %v, want nil", *got)
	}
}

func TestIntuneDetectedAppColumnMethodsExist(t *testing.T) {
	infoType := reflect.TypeOf(&ADIntuneDetectedAppInfo{})
	for _, column := range tableAzureAdIntuneDetectedApp(context.Background()).Columns {
		if column.Transform == nil {
			continue
		}
		for _, call := range column.Transform.Transforms {
			name, ok := call.Param.(string)
			if !ok {
				continue
			}
			if _, found := infoType.MethodByName(name); !found {
				t.Errorf("column %s reads method %s, which ADIntuneDetectedAppInfo lacks", column.Name, name)
			}
		}
	}
}

func betaODataError(code, message string) error {
	mainErr := betaodataerrors.NewMainError()
	mainErr.SetCode(&code)
	mainErr.SetMessage(&message)
	odataErr := betaodataerrors.NewODataError()
	odataErr.SetErrorEscaped(mainErr)
	return odataErr
}

// detectedApps is read through the beta SDK, whose own ODataError.Error() drops the code the app
// classifies denial by.
func TestIntuneDetectedAppBetaForbiddenErrorKeepsGraphCode(t *testing.T) {
	err := betaODataError("Forbidden", "Application is not authorized to perform this operation. Application must have one of the following scopes: DeviceManagementManagedDevices.Read.All")

	got := getErrorObject(err).Error()
	if !strings.Contains(got, `"Code":"Forbidden"`) {
		t.Errorf("error string %q does not carry the Graph code", got)
	}
	if !strings.Contains(got, "DeviceManagementManagedDevices.Read.All") {
		t.Errorf("error string %q does not carry the Graph message", got)
	}
}

// A device deleted between the device read and the app read yields no rows, but a denial must still
// fail the query so the app can report the missing grant.
func TestIntuneDetectedAppIgnoresOnlyNotFound(t *testing.T) {
	shouldIgnore := tableAzureAdIntuneDetectedApp(context.Background()).List.IgnoreConfig.ShouldIgnoreErrorFunc
	ctx := context.Background()

	if !shouldIgnore(ctx, nil, nil, getErrorObject(betaODataError("ResourceNotFound", "Resource not found"))) {
		t.Error("ResourceNotFound was not ignored")
	}
	if shouldIgnore(ctx, nil, nil, getErrorObject(betaODataError("Forbidden", "Application is not authorized to perform this operation."))) {
		t.Error("Forbidden was ignored")
	}
	if shouldIgnore(ctx, nil, nil, getErrorObject(betaODataError("BadRequest", "Resource not found for the segment 'detectedApps'."))) {
		t.Error("a malformed request was ignored")
	}
}
