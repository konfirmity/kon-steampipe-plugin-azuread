package azuread

import (
	"context"
	"net/url"
	"strconv"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableAzureAdDefenderMachine(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "azuread_defender_machine",
		Description: "Represents the devices Microsoft Defender for Endpoint has seen in the tenant.",
		List: &plugin.ListConfig{
			Hydrate: listAdDefenderMachines,
		},

		Columns: commonColumns([]*plugin.Column{
			{Name: "id", Type: proto.ColumnType_STRING, Description: "The Defender for Endpoint machine identifier.", Transform: transform.FromField("ID")},
			{Name: "computer_dns_name", Type: proto.ColumnType_STRING, Description: "The fully qualified name of the machine.", Transform: transform.FromField("ComputerDNSName")},
			{Name: "aad_device_id", Type: proto.ColumnType_STRING, Description: "The Microsoft Entra device identifier, when the machine is Entra joined. Matches azuread_intune_managed_device.azure_ad_device_id.", Transform: transform.FromField("AadDeviceID")},
			{Name: "os_platform", Type: proto.ColumnType_STRING, Description: "The operating system platform, for example Windows11.", Transform: transform.FromField("OsPlatform")},
			{Name: "os_version", Type: proto.ColumnType_STRING, Description: "The operating system version, from Defender's version property, for example 22H2.", Transform: transform.FromField("Version")},
			{Name: "health_status", Type: proto.ColumnType_STRING, Description: "The sensor health status. Possible values are: Active, Inactive, ImpairedCommunication, NoSensorData, NoSensorDataImpairedCommunication, Unknown.", Transform: transform.FromField("HealthStatus")},
			{Name: "onboarding_status", Type: proto.ColumnType_STRING, Description: "The onboarding status. Possible values are: onboarded, CanBeOnboarded, Unsupported, InsufficientInfo.", Transform: transform.FromField("OnboardingStatus")},
			{Name: "exposure_level", Type: proto.ColumnType_STRING, Description: "The exposure level Defender evaluates. Possible values are: None, Low, Medium, High.", Transform: transform.FromField("ExposureLevel")},
			{Name: "risk_score", Type: proto.ColumnType_STRING, Description: "The risk score Defender evaluates. Possible values are: None, Informational, Low, Medium, High.", Transform: transform.FromField("RiskScore")},
			{Name: "last_seen", Type: proto.ColumnType_TIMESTAMP, Description: "When the machine last sent a full device report.", Transform: transform.FromMethod("LastSeen")},
			{Name: "first_seen", Type: proto.ColumnType_TIMESTAMP, Description: "When Defender first observed the machine.", Transform: transform.FromMethod("FirstSeen")},

			// Standard columns
			{Name: "title", Type: proto.ColumnType_STRING, Description: ColumnDescriptionTitle, Transform: transform.FromField("ComputerDNSName")},
		}),
	}
}

//// LIST FUNCTION

func listAdDefenderMachines(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	client, err := newDefenderClient(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("azuread_defender_machine.listAdDefenderMachines", "connection_error", err)
		return nil, err
	}

	query := url.Values{}
	if limit := d.QueryContext.Limit; limit != nil && *limit > 0 && *limit < 10000 {
		query.Set("$top", strconv.FormatInt(*limit, 10))
	}

	err = listDefender(ctx, client, "/api/machines", query, defenderMachinePermission, func(machine *defenderMachine) bool {
		d.StreamListItem(ctx, machine)
		return d.RowsRemaining(ctx) != 0
	})
	if err != nil {
		// Defender answers 404 when it has no recent machines.
		if requestErr, ok := err.(*RequestError); ok && isNotFoundError(requestErr) {
			return nil, nil
		}
		plugin.Logger(ctx).Error("azuread_defender_machine.listAdDefenderMachines", "list_machine_error", err)
		return nil, err
	}

	return nil, nil
}
