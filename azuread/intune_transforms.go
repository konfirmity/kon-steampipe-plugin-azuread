package azuread

import (
	"encoding/json"
	"time"

	"github.com/microsoft/kiota-abstractions-go/serialization"
	jsonserialization "github.com/microsoft/kiota-serialization-json-go"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

type ADIntuneDetectedAppInfo struct {
	betamodels.DetectedAppable
	managedDeviceID string
}

func (a *ADIntuneDetectedAppInfo) ManagedDeviceID() *string {
	return &a.managedDeviceID
}

func (a *ADIntuneDetectedAppInfo) Platform() *string {
	if a.GetPlatform() == nil {
		return nil
	}
	return stringPtr(a.GetPlatform().String())
}

type ADIntuneManagedDeviceInfo struct {
	models.ManagedDeviceable
}

func (m *ADIntuneManagedDeviceInfo) ComplianceState() *string {
	if m.GetComplianceState() == nil {
		return nil
	}
	return stringPtr(m.GetComplianceState().String())
}

func (m *ADIntuneManagedDeviceInfo) ManagementAgent() *string {
	if m.GetManagementAgent() == nil {
		return nil
	}
	return stringPtr(m.GetManagementAgent().String())
}

func (m *ADIntuneManagedDeviceInfo) ManagedDeviceOwnerType() *string {
	if m.GetManagedDeviceOwnerType() == nil {
		return nil
	}
	return stringPtr(m.GetManagedDeviceOwnerType().String())
}

func (m *ADIntuneManagedDeviceInfo) PartnerReportedThreatState() *string {
	if m.GetPartnerReportedThreatState() == nil {
		return nil
	}
	return stringPtr(m.GetPartnerReportedThreatState().String())
}

// DeviceHealthAttestationState returns nil, not an error, for a report that will not serialise: FromMethod drops a second return value.
func (m *ADIntuneManagedDeviceInfo) DeviceHealthAttestationState() interface{} {
	state := m.GetDeviceHealthAttestationState()
	if state == nil {
		return nil
	}
	out, err := graphObjectToMap(state)
	if err != nil || len(out) == 0 {
		return nil
	}
	return out
}

// graphObjectToMap renders a Graph model as its wire JSON, keeping Graph's camelCase property names.
func graphObjectToMap(value serialization.Parsable) (map[string]interface{}, error) {
	writer := jsonserialization.NewJsonSerializationWriter()
	defer func() { _ = writer.Close() }()
	if err := writer.WriteObjectValue("", value); err != nil {
		return nil, err
	}
	content, err := writer.GetSerializedContent()
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{}
	if err := json.Unmarshal(content, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// graphDate drops Graph's 0001-01-01T00:00:00Z, which managedDevice uses for "never".
func graphDate(t *time.Time) *time.Time {
	if t == nil || t.Year() <= 1 {
		return nil
	}
	return t
}

func (m *ADIntuneManagedDeviceInfo) EnrolledDateTime() *time.Time {
	return graphDate(m.GetEnrolledDateTime())
}

func (m *ADIntuneManagedDeviceInfo) LastSyncDateTime() *time.Time {
	return graphDate(m.GetLastSyncDateTime())
}

func (m *ADIntuneManagedDeviceInfo) ComplianceGracePeriodExpirationDateTime() *time.Time {
	return graphDate(m.GetComplianceGracePeriodExpirationDateTime())
}

type ADIntuneWindowsProtectionStateInfo struct {
	models.WindowsProtectionStateable
	managedDeviceID string
}

func (w *ADIntuneWindowsProtectionStateInfo) ManagedDeviceID() *string {
	return &w.managedDeviceID
}

func (w *ADIntuneWindowsProtectionStateInfo) ProductStatus() *string {
	if w.GetProductStatus() == nil {
		return nil
	}
	return stringPtr(w.GetProductStatus().String())
}

func (w *ADIntuneWindowsProtectionStateInfo) DeviceState() *string {
	if w.GetDeviceState() == nil {
		return nil
	}
	return stringPtr(w.GetDeviceState().String())
}

func (w *ADIntuneWindowsProtectionStateInfo) LastReportedDateTime() *time.Time {
	return graphDate(w.GetLastReportedDateTime())
}

func (w *ADIntuneWindowsProtectionStateInfo) LastQuickScanDateTime() *time.Time {
	return graphDate(w.GetLastQuickScanDateTime())
}

func (w *ADIntuneWindowsProtectionStateInfo) LastFullScanDateTime() *time.Time {
	return graphDate(w.GetLastFullScanDateTime())
}

type ADIntuneDeviceComplianceSettingStateInfo struct {
	models.DeviceComplianceSettingStateable
	summary models.DeviceCompliancePolicySettingStateSummaryable
}

func (s *ADIntuneDeviceComplianceSettingStateInfo) SettingSummaryID() *string {
	return s.summary.GetId()
}

func (s *ADIntuneDeviceComplianceSettingStateInfo) Setting() *string {
	if s.GetSetting() != nil {
		return s.GetSetting()
	}
	return s.summary.GetSetting()
}

func (s *ADIntuneDeviceComplianceSettingStateInfo) SettingName() *string {
	if s.GetSettingName() != nil {
		return s.GetSettingName()
	}
	return s.summary.GetSettingName()
}

func (s *ADIntuneDeviceComplianceSettingStateInfo) PlatformType() *string {
	if s.summary.GetPlatformType() == nil {
		return nil
	}
	return stringPtr(s.summary.GetPlatformType().String())
}

func (s *ADIntuneDeviceComplianceSettingStateInfo) State() *string {
	if s.GetState() == nil {
		return nil
	}
	return stringPtr(s.GetState().String())
}

func (s *ADIntuneDeviceComplianceSettingStateInfo) ComplianceGracePeriodExpirationDateTime() *time.Time {
	return graphDate(s.GetComplianceGracePeriodExpirationDateTime())
}
