package azuread

import (
	"context"

	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/microsoftgraph/msgraph-sdk-go/models"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureAdIntuneDeviceComplianceSettingState(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azuread_intune_device_compliance_setting_state",
		Description: "Represents the state of each Intune compliance policy setting on each managed device.",
		List: &plugin.ListConfig{
			Hydrate: listAdIntuneDeviceComplianceSettingStates,
		},

		Columns: commonColumns([]*plugin.Column{
			{Name: "id", Type: proto.ColumnType_STRING, Description: "The unique identifier of the setting state.", Transform: transform.FromMethod("GetId")},
			{Name: "setting_summary_id", Type: proto.ColumnType_STRING, Description: "The unique identifier of the compliance policy setting summary the state belongs to.", Transform: transform.FromMethod("SettingSummaryID")},
			{Name: "setting", Type: proto.ColumnType_STRING, Description: "The setting class name and property name, for example Windows10CompliancePolicy.BitLockerEnabled.", Transform: transform.FromMethod("Setting")},
			{Name: "setting_name", Type: proto.ColumnType_STRING, Description: "The display name of the setting.", Transform: transform.FromMethod("SettingName")},
			{Name: "platform_type", Type: proto.ColumnType_STRING, Description: "The platform the setting applies to, for example windows10AndLater, macOS, iOS, android.", Transform: transform.FromMethod("PlatformType")},
			{Name: "device_id", Type: proto.ColumnType_STRING, Description: "The Intune managed device identifier.", Transform: transform.FromMethod("GetDeviceId")},
			{Name: "device_name", Type: proto.ColumnType_STRING, Description: "The device name.", Transform: transform.FromMethod("GetDeviceName")},
			{Name: "device_model", Type: proto.ColumnType_STRING, Description: "The device model.", Transform: transform.FromMethod("GetDeviceModel")},
			{Name: "user_id", Type: proto.ColumnType_STRING, Description: "The identifier of the user on the device.", Transform: transform.FromMethod("GetUserId")},
			{Name: "user_principal_name", Type: proto.ColumnType_STRING, Description: "The user principal name of the user on the device.", Transform: transform.FromMethod("GetUserPrincipalName")},
			{Name: "state", Type: proto.ColumnType_STRING, Description: "The compliance state of the setting on the device. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict, notAssigned.", Transform: transform.FromMethod("State")},
			{Name: "compliance_grace_period_expiration_date_time", Type: proto.ColumnType_TIMESTAMP, Description: "When the device's compliance grace period expires.", Transform: transform.FromMethod("ComplianceGracePeriodExpirationDateTime")},

			// Standard columns
			{Name: "title", Type: proto.ColumnType_STRING, Description: ColumnDescriptionTitle, Transform: transform.FromMethod("SettingName")},
		}),
	}
}

//// LIST FUNCTION

// listAdIntuneDeviceComplianceSettingStates walks every setting summary, then each summary's per-device states.
func listAdIntuneDeviceComplianceSettingStates(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	client, adapter, err := GetGraphClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azuread_intune_device_compliance_setting_state.listAdIntuneDeviceComplianceSettingStates", "connection_error", err)
		return nil, err
	}

	result, err := client.DeviceManagement().DeviceCompliancePolicySettingStateSummaries().Get(ctx, nil)
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("azuread_intune_device_compliance_setting_state.listAdIntuneDeviceComplianceSettingStates", "list_setting_summary_error", errObj)
		return nil, errObj
	}

	var summaries []models.DeviceCompliancePolicySettingStateSummaryable
	summaryIterator, err := msgraphcore.NewPageIterator[interface{}](result, adapter, models.CreateDeviceCompliancePolicySettingStateSummaryCollectionResponseFromDiscriminatorValue)
	if err != nil {
		plugin.Logger(ctx).Error("azuread_intune_device_compliance_setting_state.listAdIntuneDeviceComplianceSettingStates", "create_iterator_instance_error", err)
		return nil, err
	}
	err = summaryIterator.Iterate(ctx, func(pageItem interface{}) bool {
		if summary, ok := pageItem.(models.DeviceCompliancePolicySettingStateSummaryable); ok {
			summaries = append(summaries, summary)
		}
		return true
	})
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("azuread_intune_device_compliance_setting_state.listAdIntuneDeviceComplianceSettingStates", "paging_error", errObj)
		return nil, errObj
	}

	for _, summary := range summaries {
		if summary.GetId() == nil {
			continue
		}
		states, err := client.DeviceManagement().DeviceCompliancePolicySettingStateSummaries().ByDeviceCompliancePolicySettingStateSummaryId(*summary.GetId()).DeviceComplianceSettingStates().Get(ctx, nil)
		if err != nil {
			errObj := getErrorObject(err)
			// A summary removed between the two reads has no states left to report.
			if isNotFoundError(errObj) {
				continue
			}
			plugin.Logger(ctx).Error("azuread_intune_device_compliance_setting_state.listAdIntuneDeviceComplianceSettingStates", "list_setting_state_error", errObj)
			return nil, errObj
		}

		stateIterator, err := msgraphcore.NewPageIterator[interface{}](states, adapter, models.CreateDeviceComplianceSettingStateCollectionResponseFromDiscriminatorValue)
		if err != nil {
			plugin.Logger(ctx).Error("azuread_intune_device_compliance_setting_state.listAdIntuneDeviceComplianceSettingStates", "create_iterator_instance_error", err)
			return nil, err
		}
		err = stateIterator.Iterate(ctx, func(pageItem interface{}) bool {
			if state, ok := pageItem.(models.DeviceComplianceSettingStateable); ok {
				d.StreamListItem(ctx, &ADIntuneDeviceComplianceSettingStateInfo{state, summary})
			}
			return d.RowsRemaining(ctx) != 0
		})
		if err != nil {
			errObj := getErrorObject(err)
			plugin.Logger(ctx).Error("azuread_intune_device_compliance_setting_state.listAdIntuneDeviceComplianceSettingStates", "paging_error", errObj)
			return nil, errObj
		}
		if d.RowsRemaining(ctx) == 0 {
			break
		}
	}

	return nil, nil
}
