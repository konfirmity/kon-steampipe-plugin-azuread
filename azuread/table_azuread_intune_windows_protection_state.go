package azuread

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureAdIntuneWindowsProtectionState(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azuread_intune_windows_protection_state",
		Description: "Represents the Microsoft Defender Antivirus protection state Intune reports for a Windows managed device.",
		List: &plugin.ListConfig{
			Hydrate: listAdIntuneWindowsProtectionStates,
			// A non-Windows device, or one removed from Intune between reads, has no protection state; a denial must still fail.
			IgnoreConfig: &plugin.IgnoreConfig{
				ShouldIgnoreErrorFunc: isIgnorableErrorPredicate([]string{"Request_ResourceNotFound", "ResourceNotFound", "NotFound"}),
			},
			KeyColumns: plugin.SingleColumn("managed_device_id"),
		},

		Columns: commonColumns([]*plugin.Column{
			{Name: "managed_device_id", Type: proto.ColumnType_STRING, Description: "The unique identifier of the managed device.", Transform: transform.FromMethod("ManagedDeviceID")},
			{Name: "malware_protection_enabled", Type: proto.ColumnType_BOOL, Description: "Whether anti-malware is enabled.", Transform: transform.FromMethod("GetMalwareProtectionEnabled")},
			{Name: "real_time_protection_enabled", Type: proto.ColumnType_BOOL, Description: "Whether real-time protection is enabled.", Transform: transform.FromMethod("GetRealTimeProtectionEnabled")},
			{Name: "network_inspection_system_enabled", Type: proto.ColumnType_BOOL, Description: "Whether the network inspection system is enabled.", Transform: transform.FromMethod("GetNetworkInspectionSystemEnabled")},
			{Name: "tamper_protection_enabled", Type: proto.ColumnType_BOOL, Description: "Whether tamper protection is enabled.", Transform: transform.FromMethod("GetTamperProtectionEnabled")},
			{Name: "signature_update_overdue", Type: proto.ColumnType_BOOL, Description: "Whether the antivirus signature update is overdue.", Transform: transform.FromMethod("GetSignatureUpdateOverdue")},
			{Name: "quick_scan_overdue", Type: proto.ColumnType_BOOL, Description: "Whether a quick scan is overdue.", Transform: transform.FromMethod("GetQuickScanOverdue")},
			{Name: "full_scan_overdue", Type: proto.ColumnType_BOOL, Description: "Whether a full scan is overdue.", Transform: transform.FromMethod("GetFullScanOverdue")},
			{Name: "reboot_required", Type: proto.ColumnType_BOOL, Description: "Whether the device needs a reboot.", Transform: transform.FromMethod("GetRebootRequired")},
			{Name: "full_scan_required", Type: proto.ColumnType_BOOL, Description: "Whether the device needs a full scan.", Transform: transform.FromMethod("GetFullScanRequired")},
			{Name: "is_virtual_machine", Type: proto.ColumnType_BOOL, Description: "Whether the device is a virtual machine.", Transform: transform.FromMethod("GetIsVirtualMachine")},
			{Name: "product_status", Type: proto.ColumnType_STRING, Description: "The Defender product status flags, comma separated, for example noStatus, serviceNotRunning, avSignaturesOutOfDate, productExpired.", Transform: transform.FromMethod("ProductStatus")},
			{Name: "device_state", Type: proto.ColumnType_STRING, Description: "The device health state flags, comma separated: clean, fullScanPending, rebootPending, manualStepsPending, offlineScanPending, critical.", Transform: transform.FromMethod("DeviceState")},
			{Name: "engine_version", Type: proto.ColumnType_STRING, Description: "The anti-malware engine version.", Transform: transform.FromMethod("GetEngineVersion")},
			{Name: "signature_version", Type: proto.ColumnType_STRING, Description: "The antivirus signature version.", Transform: transform.FromMethod("GetSignatureVersion")},
			{Name: "anti_malware_version", Type: proto.ColumnType_STRING, Description: "The anti-malware client version.", Transform: transform.FromMethod("GetAntiMalwareVersion")},
			{Name: "last_reported_date_time", Type: proto.ColumnType_TIMESTAMP, Description: "When the device last reported its protection state.", Transform: transform.FromMethod("LastReportedDateTime")},
			{Name: "last_quick_scan_date_time", Type: proto.ColumnType_TIMESTAMP, Description: "When the last quick scan ran.", Transform: transform.FromMethod("LastQuickScanDateTime")},
			{Name: "last_full_scan_date_time", Type: proto.ColumnType_TIMESTAMP, Description: "When the last full scan ran.", Transform: transform.FromMethod("LastFullScanDateTime")},
		}),
	}
}

//// LIST FUNCTION

// listAdIntuneWindowsProtectionStates reads one device's protection state; the SDK calls it once per value of an IN list.
func listAdIntuneWindowsProtectionStates(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	deviceID := d.EqualsQuals["managed_device_id"].GetStringValue()
	if deviceID == "" {
		return nil, nil
	}

	client, _, err := GetGraphClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azuread_intune_windows_protection_state.listAdIntuneWindowsProtectionStates", "connection_error", err)
		return nil, err
	}

	state, err := client.DeviceManagement().ManagedDevices().ByManagedDeviceId(deviceID).WindowsProtectionState().Get(ctx, nil)
	if err != nil {
		errObj := getErrorObject(err)
		plugin.Logger(ctx).Error("azuread_intune_windows_protection_state.listAdIntuneWindowsProtectionStates", "get_windows_protection_state_error", errObj)
		return nil, errObj
	}
	if state == nil {
		return nil, nil
	}

	d.StreamListItem(ctx, &ADIntuneWindowsProtectionStateInfo{state, deviceID})
	return nil, nil
}
