package azuread

import (
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

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
