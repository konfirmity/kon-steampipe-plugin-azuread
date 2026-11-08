package azuread

import (
	"strings"
	"time"
)

type defenderMachine struct {
	ID               string  `json:"id"`
	ComputerDNSName  *string `json:"computerDnsName"`
	AadDeviceID      *string `json:"aadDeviceId"`
	OsPlatform       *string `json:"osPlatform"`
	Version          *string `json:"version"`
	HealthStatus     *string `json:"healthStatus"`
	OnboardingStatus *string `json:"onboardingStatus"`
	ExposureLevel    *string `json:"exposureLevel"`
	RiskScore        *string `json:"riskScore"`
	LastSeenRaw      *string `json:"lastSeen"`
	FirstSeenRaw     *string `json:"firstSeen"`
}

func (m *defenderMachine) LastSeen() *time.Time {
	return parseDefenderTime(m.LastSeenRaw)
}

func (m *defenderMachine) FirstSeen() *time.Time {
	return parseDefenderTime(m.FirstSeenRaw)
}

type defenderSoftwareVulnerability struct {
	ID                          string   `json:"id"`
	DeviceID                    *string  `json:"deviceId"`
	DeviceName                  *string  `json:"deviceName"`
	OsPlatform                  *string  `json:"osPlatform"`
	OsVersion                   *string  `json:"osVersion"`
	SoftwareVendor              *string  `json:"softwareVendor"`
	SoftwareName                *string  `json:"softwareName"`
	SoftwareVersion             *string  `json:"softwareVersion"`
	CveID                       *string  `json:"cveId"`
	CvssScore                   *float64 `json:"cvssScore"`
	VulnerabilitySeverityLevel  *string  `json:"vulnerabilitySeverityLevel"`
	RecommendedSecurityUpdate   *string  `json:"recommendedSecurityUpdate"`
	RecommendedSecurityUpdateID *string  `json:"recommendedSecurityUpdateId"`
	SecurityUpdateAvailable     *bool    `json:"securityUpdateAvailable"`
	ExploitabilityLevel         *string  `json:"exploitabilityLevel"`
	FirstSeenRaw                *string  `json:"firstSeenTimestamp"`
	LastSeenRaw                 *string  `json:"lastSeenTimestamp"`
	DiskPaths                   []string `json:"diskPaths"`
}

func (v *defenderSoftwareVulnerability) FirstSeenTimestamp() *time.Time {
	return parseDefenderTime(v.FirstSeenRaw)
}

func (v *defenderSoftwareVulnerability) LastSeenTimestamp() *time.Time {
	return parseDefenderTime(v.LastSeenRaw)
}

// parseDefenderTime reads both Defender timestamp shapes: ISO 8601 on machines, and "2020-12-30 14:17:26.8476880" (UTC, no zone) on the vulnerability export.
func parseDefenderTime(raw *string) *time.Time {
	if raw == nil {
		return nil
	}
	value := strings.TrimSpace(*raw)
	if value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			if t.Year() <= 1 {
				return nil
			}
			return &t
		}
	}
	return nil
}
