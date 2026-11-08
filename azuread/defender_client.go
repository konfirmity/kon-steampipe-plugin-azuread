package azuread

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

const (
	defenderMachinePermission       = "Machine.Read.All"
	defenderVulnerabilityPermission = "Vulnerability.Read.All"

	defenderMaxRetries   = 5
	defenderMaxRetryWait = 60 * time.Second

	// defenderNotEnabledPrefix starts every error meaning the tenant has no Defender for Endpoint to read, so callers can tell it from a missing grant.
	defenderNotEnabledPrefix = "Microsoft Defender for Endpoint is not enabled for this tenant"
)

// defenderClient calls the Microsoft Defender for Endpoint REST API, which has no Graph SDK.
type defenderClient struct {
	baseURL    string
	httpClient *http.Client
	token      func(ctx context.Context) (string, error)
	sleep      func(ctx context.Context, wait time.Duration) error
}

type defenderPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

type defenderErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func defenderEndpoint(environment string) (string, error) {
	switch environment {
	case environmentAzureUSGovernmentCloud:
		return "https://api-gov.securitycenter.microsoft.us", nil
	case environmentAzureChinaCloud:
		return "", errors.New("the Microsoft Defender for Endpoint API is not available in Azure China")
	default:
		return "https://api.securitycenter.microsoft.com", nil
	}
}

func newDefenderClient(ctx context.Context, d *plugin.QueryData) (*defenderClient, error) {
	cred, environment, err := newAzureCredential(ctx, d, "newDefenderClient")
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, errors.New("no Azure credential is configured for this connection")
	}
	baseURL, err := defenderEndpoint(environment)
	if err != nil {
		return nil, err
	}
	scope := baseURL + "/.default"

	return &defenderClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Minute},
		token: func(ctx context.Context) (string, error) {
			token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
			if err != nil {
				return "", defenderTokenError(err)
			}
			return token.Token, nil
		},
		sleep: sleepContext,
	}, nil
}

func sleepContext(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// listDefender pages a collection through @odata.nextLink until each returns false or the pages run out.
func listDefender[T any](ctx context.Context, c *defenderClient, path string, query url.Values, permission string, each func(*T) bool) error {
	next := c.baseURL + path
	if len(query) > 0 {
		next += "?" + query.Encode()
	}
	for next != "" {
		var page defenderPage[T]
		if err := c.get(ctx, next, permission, &page); err != nil {
			return err
		}
		for i := range page.Value {
			if !each(&page.Value[i]) {
				return nil
			}
		}
		if page.NextLink != "" && !c.trustedLink(page.NextLink) {
			return fmt.Errorf("refusing to follow Defender nextLink outside the Defender API: %s", page.NextLink)
		}
		next = page.NextLink
	}
	return nil
}

// trustedLink keeps the bearer token on Defender's own hosts; Microsoft may page across its regional API hosts.
func (c *defenderClient) trustedLink(link string) bool {
	target, err := url.Parse(link)
	if err != nil {
		return false
	}
	base, err := url.Parse(c.baseURL)
	if err == nil && target.Scheme == base.Scheme && target.Host == base.Host {
		return true
	}
	if target.Scheme != "https" {
		return false
	}
	host := target.Hostname()
	for _, suffix := range []string{".securitycenter.microsoft.com", ".security.microsoft.com", ".securitycenter.microsoft.us", ".security.microsoft.us"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func (c *defenderClient) get(ctx context.Context, link, permission string, out interface{}) error {
	for attempt := 0; ; attempt++ {
		token, err := c.token(ctx)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("decoding Defender response from %s: %w", req.URL.Path, err)
			}
			return nil
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) && attempt < defenderMaxRetries {
			if err := c.sleep(ctx, retryAfter(resp.Header.Get("Retry-After"), attempt, time.Now())); err != nil {
				return err
			}
			continue
		}
		return defenderResponseError(resp.StatusCode, body, permission)
	}
}

// retryAfter honours a Retry-After of seconds or an HTTP date, else backs off exponentially, never past defenderMaxRetryWait.
func retryAfter(header string, attempt int, now time.Time) time.Duration {
	wait := time.Duration(1<<attempt) * time.Second
	if header != "" {
		if seconds, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && seconds >= 0 {
			wait = time.Duration(seconds) * time.Second
		} else if at, err := http.ParseTime(header); err == nil {
			wait = at.Sub(now)
		}
	}
	if wait < 0 {
		wait = 0
	}
	if wait > defenderMaxRetryWait {
		wait = defenderMaxRetryWait
	}
	return wait
}

// defenderResponseError keeps Microsoft's code and message, and names the WindowsDefenderATP permission on a denial.
func defenderResponseError(status int, body []byte, permission string) *RequestError {
	var parsed defenderErrorBody
	_ = json.Unmarshal(body, &parsed)
	code := parsed.Error.Code
	message := parsed.Error.Message
	if code == "" {
		code = strings.ReplaceAll(http.StatusText(status), " ", "")
	}
	if message == "" {
		message = strings.TrimSpace(string(body))
	}

	switch {
	case status == http.StatusForbidden && code == "DisabledFeature":
		return &RequestError{Code: code, Message: fmt.Sprintf("%s: %s", defenderNotEnabledPrefix, message)}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &RequestError{Code: code, Message: fmt.Sprintf("status %d: %s (requires the WindowsDefenderATP application permission %s with admin consent)", status, message, permission)}
	default:
		return &RequestError{Code: code, Message: fmt.Sprintf("status %d: %s", status, message)}
	}
}

// defenderTokenError reads AADSTS500011 as no Defender in the tenant: the WindowsDefenderATP service principal only exists once Defender is provisioned.
func defenderTokenError(err error) error {
	if strings.Contains(err.Error(), "AADSTS500011") {
		return &RequestError{Code: "AADSTS500011", Message: defenderNotEnabledPrefix + ": the WindowsDefenderATP resource was not found in the tenant"}
	}
	return err
}
