package azuread

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Microsoft Learn's "List machines API" response example; the docs print osPlatform as two strings, which is not valid JSON.
const defenderMachinesPage = `{
	"@odata.context": "https://api.security.microsoft.com/api/$metadata#Machines",
	"value": [
		{
			"id": "1e5bc9d7e413ddd7902c2932e418702b84d0cc07",
			"computerDnsName": "mymachine1.contoso.com",
			"firstSeen": "2018-08-02T14:55:03.7791856Z",
			"lastSeen": "2018-08-02T14:55:03.7791856Z",
			"osPlatform": "Windows11",
			"version": "1709",
			"osProcessor": "x64",
			"lastIpAddress": "172.17.230.209",
			"lastExternalIpAddress": "167.220.196.71",
			"osBuild": 18209,
			"healthStatus": "Active",
			"onboardingStatus": "Onboarded",
			"rbacGroupId": 140,
			"rbacGroupName": "The-A-Team",
			"riskScore": "Low",
			"exposureLevel": "Medium",
			"isAadJoined": true,
			"aadDeviceId": "80fe8ff8-2624-418e-9591-41f0491218f9",
			"machineTags": [ "test tag 1", "test tag 2" ]
		}
	]
}`

// Records from Microsoft Learn's SoftwareVulnerabilitiesByMachine examples: one software row without a CVE, one with.
const defenderVulnerabilityRecords = `
	{
		"id": "00044f612345baf759462dbe6db733b6a9c59ab4_edge_10.0.17763.1637__",
		"deviceId": "00044f612345daf756462bde6bd733b9a9c59ab4",
		"rbacGroupName": "hhh",
		"deviceName": "computerpii.corp.contoso.com",
		"osPlatform": "Windows10",
		"osVersion": "10.0.17763.1637",
		"osArchitecture": "x64",
		"softwareVendor": "microsoft",
		"softwareName": "edge",
		"softwareVersion": "10.0.17763.1637",
		"cveId": null,
		"vulnerabilitySeverityLevel": null,
		"recommendedSecurityUpdate": null,
		"recommendedSecurityUpdateId": null,
		"recommendedSecurityUpdateUrl": null,
		"diskPaths": [],
		"registryPaths": [],
		"lastSeenTimestamp": "2020-12-30 14:17:26",
		"firstSeenTimestamp": "2020-12-30 11:07:15",
		"exploitabilityLevel": "NoExploit",
		"recommendationReference": "va-_-microsoft-_-edge",
		"securityUpdateAvailable": true
	},
	{
		"id": "01aa8c73095bb12345918663f3f94ce322107d24_firefox_83.0.0.0_CVE-2020-26971_",
		"deviceId": "01aa8c73065bb12345918693f3f94ce322107d24",
		"rbacGroupName": "hhh",
		"deviceName": "computerpii2.corp.contoso.com",
		"osPlatform": "Windows10",
		"osVersion": "10.0.19042.685",
		"osArchitecture": "x64",
		"softwareVendor": "mozilla",
		"softwareName": "firefox",
		"softwareVersion": "83.0.0.0",
		"cveId": "CVE-2020-26971",
		"cvssScore": 8.8,
		"vulnerabilitySeverityLevel": "High",
		"recommendedSecurityUpdate": "193220",
		"recommendedSecurityUpdateId": "4550961",
		"recommendedSecurityUpdateUrl": null,
		"diskPaths": ["C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe"],
		"registryPaths": ["HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mozilla Firefox 83.0 (x86 en-US)"],
		"lastSeenTimestamp": "2021-01-05 17:04:30.8476880",
		"firstSeenTimestamp": "2020-05-06 12:42:19",
		"exploitabilityLevel": "ExploitIsPublic",
		"recommendationReference": "va-_-mozilla-_-firefox",
		"securityUpdateAvailable": false
	}`

func testDefenderClient(server *httptest.Server) *defenderClient {
	return &defenderClient{
		baseURL:    server.URL,
		httpClient: server.Client(),
		token:      func(context.Context) (string, error) { return "test-token", nil },
		sleep:      func(context.Context, time.Duration) error { return nil },
	}
}

func TestDefenderMachineMapsListResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/machines" {
			t.Errorf("path = %s, want /api/machines", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		_, _ = fmt.Fprint(w, defenderMachinesPage)
	}))
	defer server.Close()

	var machines []*defenderMachine
	err := listDefender(context.Background(), testDefenderClient(server), "/api/machines", nil, defenderMachinePermission, func(m *defenderMachine) bool {
		machines = append(machines, m)
		return true
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(machines) != 1 {
		t.Fatalf("got %d machines, want 1", len(machines))
	}
	m := machines[0]
	if m.ID != "1e5bc9d7e413ddd7902c2932e418702b84d0cc07" {
		t.Errorf("ID = %q", m.ID)
	}
	if m.AadDeviceID == nil || *m.AadDeviceID != "80fe8ff8-2624-418e-9591-41f0491218f9" {
		t.Errorf("AadDeviceID = %v", m.AadDeviceID)
	}
	if m.ComputerDNSName == nil || *m.ComputerDNSName != "mymachine1.contoso.com" {
		t.Errorf("ComputerDNSName = %v", m.ComputerDNSName)
	}
	if m.Version == nil || *m.Version != "1709" {
		t.Errorf("Version = %v", m.Version)
	}
	if m.HealthStatus == nil || *m.HealthStatus != "Active" || m.OnboardingStatus == nil || *m.OnboardingStatus != "Onboarded" {
		t.Errorf("HealthStatus = %v, OnboardingStatus = %v", m.HealthStatus, m.OnboardingStatus)
	}
	if m.RiskScore == nil || *m.RiskScore != "Low" || m.ExposureLevel == nil || *m.ExposureLevel != "Medium" {
		t.Errorf("RiskScore = %v, ExposureLevel = %v", m.RiskScore, m.ExposureLevel)
	}
	want := time.Date(2018, 8, 2, 14, 55, 3, 779185600, time.UTC)
	if got := m.LastSeen(); got == nil || !got.Equal(want) {
		t.Errorf("LastSeen() = %v, want %v", got, want)
	}
	if got := m.FirstSeen(); got == nil || !got.Equal(want) {
		t.Errorf("FirstSeen() = %v, want %v", got, want)
	}
}

func TestDefenderVulnerabilityMapsExportRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"value":[%s]}`, defenderVulnerabilityRecords)
	}))
	defer server.Close()

	var rows []*defenderSoftwareVulnerability
	err := listDefender(context.Background(), testDefenderClient(server), "/api/machines/SoftwareVulnerabilitiesByMachine", nil, defenderVulnerabilityPermission, func(v *defenderSoftwareVulnerability) bool {
		rows = append(rows, v)
		return true
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}

	noCve := rows[0]
	if noCve.CveID != nil || noCve.CvssScore != nil {
		t.Errorf("software row without a CVE got CveID = %v, CvssScore = %v", noCve.CveID, noCve.CvssScore)
	}
	if noCve.SecurityUpdateAvailable == nil || !*noCve.SecurityUpdateAvailable {
		t.Errorf("SecurityUpdateAvailable = %v, want true", noCve.SecurityUpdateAvailable)
	}

	v := rows[1]
	if v.DeviceID == nil || *v.DeviceID != "01aa8c73065bb12345918693f3f94ce322107d24" {
		t.Errorf("DeviceID = %v", v.DeviceID)
	}
	if v.CveID == nil || *v.CveID != "CVE-2020-26971" {
		t.Errorf("CveID = %v", v.CveID)
	}
	if v.CvssScore == nil || *v.CvssScore != 8.8 {
		t.Errorf("CvssScore = %v, want 8.8", v.CvssScore)
	}
	if v.SoftwareVendor == nil || *v.SoftwareVendor != "mozilla" || v.SoftwareName == nil || *v.SoftwareName != "firefox" || v.SoftwareVersion == nil || *v.SoftwareVersion != "83.0.0.0" {
		t.Errorf("software = %v %v %v", v.SoftwareVendor, v.SoftwareName, v.SoftwareVersion)
	}
	if v.VulnerabilitySeverityLevel == nil || *v.VulnerabilitySeverityLevel != "High" || v.ExploitabilityLevel == nil || *v.ExploitabilityLevel != "ExploitIsPublic" {
		t.Errorf("severity = %v, exploitability = %v", v.VulnerabilitySeverityLevel, v.ExploitabilityLevel)
	}
	if v.RecommendedSecurityUpdateID == nil || *v.RecommendedSecurityUpdateID != "4550961" {
		t.Errorf("RecommendedSecurityUpdateID = %v", v.RecommendedSecurityUpdateID)
	}
	if len(v.DiskPaths) != 1 || v.DiskPaths[0] != `C:\Program Files (x86)\Mozilla Firefox\firefox.exe` {
		t.Errorf("DiskPaths = %v", v.DiskPaths)
	}
	wantLast := time.Date(2021, 1, 5, 17, 4, 30, 847688000, time.UTC)
	if got := v.LastSeenTimestamp(); got == nil || !got.Equal(wantLast) {
		t.Errorf("LastSeenTimestamp() = %v, want %v", got, wantLast)
	}
	wantFirst := time.Date(2020, 5, 6, 12, 42, 19, 0, time.UTC)
	if got := v.FirstSeenTimestamp(); got == nil || !got.Equal(wantFirst) {
		t.Errorf("FirstSeenTimestamp() = %v, want %v", got, wantFirst)
	}
}

func TestDefenderListFollowsNextLink(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("$skiptoken") {
		case "":
			if got := r.URL.Query().Get("pageSize"); got != "2" {
				t.Errorf("pageSize = %q, want 2", got)
			}
			_, _ = fmt.Fprintf(w, `{"value":[{"id":"a"},{"id":"b"}],"@odata.nextLink":"%s/api/machines/SoftwareVulnerabilitiesByMachine?pagesize=2&$skiptoken=p2"}`, server.URL)
		case "p2":
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Errorf("page 2 Authorization = %q", got)
			}
			_, _ = fmt.Fprintf(w, `{"value":[{"id":"c"}],"@odata.nextLink":"%s/api/machines/SoftwareVulnerabilitiesByMachine?pagesize=2&$skiptoken=p3"}`, server.URL)
		case "p3":
			_, _ = fmt.Fprint(w, `{"value":[{"id":"d"}]}`)
		default:
			t.Errorf("unexpected skiptoken %q", r.URL.Query().Get("$skiptoken"))
		}
	}))
	defer server.Close()

	var ids []string
	err := listDefender(context.Background(), testDefenderClient(server), "/api/machines/SoftwareVulnerabilitiesByMachine", url.Values{"pageSize": {"2"}}, defenderVulnerabilityPermission, func(v *defenderSoftwareVulnerability) bool {
		ids = append(ids, v.ID)
		return true
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := strings.Join(ids, ","); got != "a,b,c,d" {
		t.Errorf("ids = %s, want a,b,c,d", got)
	}
}

func TestDefenderListStopsWhenCallerHasEnough(t *testing.T) {
	var calls int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"a"},{"id":"b"}],"@odata.nextLink":"%s/api/machines?$skiptoken=more"}`, server.URL)
	}))
	defer server.Close()

	var seen int
	err := listDefender(context.Background(), testDefenderClient(server), "/api/machines", nil, defenderMachinePermission, func(*defenderMachine) bool {
		seen++
		return seen < 1
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if calls != 1 || seen != 1 {
		t.Errorf("calls = %d, seen = %d; want 1 and 1", calls, seen)
	}
}

func TestDefenderListRefusesForeignNextLink(t *testing.T) {
	var foreignHits int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&foreignHits, 1)
	}))
	defer foreign.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"a"}],"@odata.nextLink":"%s/steal"}`, foreign.URL)
	}))
	defer server.Close()

	err := listDefender(context.Background(), testDefenderClient(server), "/api/machines", nil, defenderMachinePermission, func(*defenderMachine) bool { return true })
	if err == nil {
		t.Fatal("expected an error for a nextLink on another host")
	}
	if foreignHits != 0 {
		t.Errorf("the bearer token was sent to a foreign host")
	}
}

func TestDefenderTrustsRegionalHosts(t *testing.T) {
	c := &defenderClient{baseURL: "https://api.securitycenter.microsoft.com"}
	for link, want := range map[string]bool{
		"https://api.security.microsoft.com/api/machines?$skiptoken=x":          true,
		"https://api-eu.securitycenter.microsoft.com/api/machines?$skiptoken=x": true,
		"http://api-eu.securitycenter.microsoft.com/api/machines":               false,
		"https://securitycenter.microsoft.com.attacker.example/api":             false,
	} {
		if got := c.trustedLink(link); got != want {
			t.Errorf("trustedLink(%s) = %v, want %v", link, got, want)
		}
	}
}

func TestDefenderRetriesTooManyRequestsAfterRetryAfter(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprint(w, `{"error":{"code":"TooManyRequests","message":"Rate limit is exceeded. Try again in 7 seconds.","target":"t"}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"value":[{"id":"a"}]}`)
	}))
	defer server.Close()

	var waits []time.Duration
	client := testDefenderClient(server)
	client.sleep = func(_ context.Context, wait time.Duration) error {
		waits = append(waits, wait)
		return nil
	}

	var rows int
	err := listDefender(context.Background(), client, "/api/machines", nil, defenderMachinePermission, func(*defenderMachine) bool {
		rows++
		return true
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if rows != 1 || len(waits) != 1 || waits[0] != 7*time.Second {
		t.Errorf("rows = %d, waits = %v; want 1 row after one 7s wait", rows, waits)
	}
}

// The app's classifier reads these phrases (backend/src/services/cloud-assets/steampipe-client.ts); a mismatch turns a missing grant into an outage.
var (
	appDenialRe      = regexp.MustCompile(`(?i)access ?denied|not authorized|unauthorized|forbidden|\b403\b|(?:returned|:|status) 401\b`)
	appRateLimitRe   = regexp.MustCompile(`(?i)(?:Error|status|returned|:) 429\b|rate[ _]?limit[ _]?exceeded|quota exceeded|too many requests`)
	defenderOffRe    = regexp.MustCompile(regexp.QuoteMeta(defenderNotEnabledPrefix))
	forbiddenPayload = `{"error":{"code":"Forbidden","message":"The application does not have any of the required application permissions (Vulnerability.ReadWrite.All, Vulnerability.Read.All) to access the resource.","target":"43f4cb08-8fac-4b65-9db1-745c2ae65f3a"}}`
)

func defenderErrorFrom(t *testing.T, status int, body string, header http.Header) error {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
	defer server.Close()
	err := listDefender(context.Background(), testDefenderClient(server), "/api/machines/SoftwareVulnerabilitiesByMachine", nil, defenderVulnerabilityPermission, func(*defenderSoftwareVulnerability) bool { return true })
	if err == nil {
		t.Fatalf("status %d returned no error", status)
	}
	return err
}

func TestDefenderForbiddenCarriesCodeAndPermission(t *testing.T) {
	got := defenderErrorFrom(t, http.StatusForbidden, forbiddenPayload, nil).Error()

	if !strings.Contains(got, `"Code":"Forbidden"`) {
		t.Errorf("error %q lost the Microsoft code", got)
	}
	if !strings.Contains(got, "required application permissions") || !strings.Contains(got, "WindowsDefenderATP application permission Vulnerability.Read.All") {
		t.Errorf("error %q does not carry Microsoft's message and the permission", got)
	}
	if !appDenialRe.MatchString(got) || defenderOffRe.MatchString(got) {
		t.Errorf("error %q would not classify as denied", got)
	}
}

func TestDefenderUnauthorizedReadsAsDenied(t *testing.T) {
	got := defenderErrorFrom(t, http.StatusUnauthorized, `{"error":{"code":"Unauthorized","message":"Unauthorized","target":"t"}}`, nil).Error()

	if !strings.Contains(got, `"Code":"Unauthorized"`) || !strings.Contains(got, "status 401") || !strings.Contains(got, "Vulnerability.Read.All") {
		t.Errorf("error %q lacks the code, status or permission", got)
	}
	if !appDenialRe.MatchString(got) {
		t.Errorf("error %q would not classify as denied", got)
	}
}

func TestDefenderDisabledFeatureReadsAsNotEnabledNotDenied(t *testing.T) {
	got := defenderErrorFrom(t, http.StatusForbidden, `{"error":{"code":"DisabledFeature","message":"Tenant feature is not enabled.","target":"t"}}`, nil).Error()

	if !strings.Contains(got, `"Code":"DisabledFeature"`) || !defenderOffRe.MatchString(got) {
		t.Errorf("error %q is not marked as Defender not enabled", got)
	}
	if appDenialRe.MatchString(got) {
		t.Errorf("error %q would classify as a missing permission", got)
	}
}

func TestDefenderTokenForMissingResourceReadsAsNotEnabled(t *testing.T) {
	raw := errors.New("ClientSecretCredential authentication failed\nPOST https://login.microsoftonline.com/tenant/oauth2/v2.0/token\n--------------------------------------------------------------------------------\nRESPONSE 400 Bad Request\n--------------------------------------------------------------------------------\n{\"error\":\"invalid_resource\",\"error_description\":\"AADSTS500011: The resource principal named https://api.securitycenter.microsoft.com was not found in the tenant named Contoso. This can happen if the application has not been installed by the administrator of the tenant or consented to by any user in the tenant.\"}")
	got := defenderTokenError(raw).Error()

	if !strings.Contains(got, `"Code":"AADSTS500011"`) || !defenderOffRe.MatchString(got) {
		t.Errorf("error %q is not marked as Defender not enabled", got)
	}
	if appDenialRe.MatchString(got) {
		t.Errorf("error %q would classify as a missing permission", got)
	}

	other := errors.New("AADSTS7000222: The provided client secret keys are expired.")
	if defenderTokenError(other) != other {
		t.Error("an unrelated credential error was rewritten")
	}
}

func TestDefenderRateLimitAfterRetriesReadsAsRateLimited(t *testing.T) {
	got := defenderErrorFrom(t, http.StatusTooManyRequests, `{"error":{"code":"TooManyRequests","message":"Rate limit is exceeded.","target":"t"}}`, http.Header{"Retry-After": {"1"}}).Error()

	if !appRateLimitRe.MatchString(got) {
		t.Errorf("error %q would not classify as rate limited", got)
	}
	if appDenialRe.MatchString(got) {
		t.Errorf("error %q would classify as denied", got)
	}
}

func TestDefenderNotFoundIsNotFound(t *testing.T) {
	err := defenderErrorFrom(t, http.StatusNotFound, `{"error":{"code":"NotFound","message":"No machines found","target":"t"}}`, nil)
	requestErr, ok := err.(*RequestError)
	if !ok || !isNotFoundError(requestErr) {
		t.Errorf("404 = %v, want a not-found RequestError", err)
	}

	err = defenderErrorFrom(t, http.StatusNotFound, ``, nil)
	if requestErr, ok := err.(*RequestError); !ok || !isNotFoundError(requestErr) {
		t.Errorf("bodiless 404 = %v, want a not-found RequestError", err)
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		header  string
		attempt int
		want    time.Duration
	}{
		{"12", 0, 12 * time.Second},
		{"", 0, time.Second},
		{"", 3, 8 * time.Second},
		{"3600", 0, defenderMaxRetryWait},
		{"Sun, 08 Nov 2026 10:00:30 GMT", 0, 30 * time.Second},
		{"Sun, 08 Nov 2026 09:00:00 GMT", 0, 0},
	}
	for _, c := range cases {
		if got := retryAfter(c.header, c.attempt, now); got != c.want {
			t.Errorf("retryAfter(%q, %d) = %v, want %v", c.header, c.attempt, got, c.want)
		}
	}
}

func TestParseDefenderTimeRejectsPlaceholders(t *testing.T) {
	for _, raw := range []string{"", "0001-01-01T00:00:00Z", "not a date"} {
		value := raw
		if got := parseDefenderTime(&value); got != nil {
			t.Errorf("parseDefenderTime(%q) = %v, want nil", raw, got)
		}
	}
}

func TestDefenderTableColumnTransformsResolve(t *testing.T) {
	assertColumnTransformsResolve(t, tableAzureAdDefenderMachine(context.Background()), &defenderMachine{})
	assertColumnTransformsResolve(t, tableAzureAdDefenderSoftwareVulnerability(context.Background()), &defenderSoftwareVulnerability{})
}
