package azuread

import (
	"time"

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
