package azuread

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/quals"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func timeQual(op string, at time.Time) *quals.Qual {
	return &quals.Qual{Column: "created_date_time", Operator: op, Value: &proto.QualValue{Value: &proto.QualValue_TimestampValue{TimestampValue: timestamppb.New(at)}}}
}

func listQual(column, op string) *quals.Qual {
	return &quals.Qual{Column: column, Operator: op, Value: &proto.QualValue{Value: &proto.QualValue_ListValue{ListValue: &proto.QualValueList{}}}}
}

func stringQual(column, op, value string) *quals.Qual {
	return &quals.Qual{Column: column, Operator: op, Value: &proto.QualValue{Value: &proto.QualValue_StringValue{StringValue: value}}}
}

func qualMap(qs ...*quals.Qual) plugin.KeyColumnQualMap {
	m := plugin.KeyColumnQualMap{}
	for _, q := range qs {
		if m[q.Column] == nil {
			m[q.Column] = &plugin.KeyColumnQuals{Name: q.Column}
		}
		m[q.Column].Quals = append(m[q.Column].Quals, q)
	}
	return m
}

func TestBuildSignInReportQueryFilter(t *testing.T) {
	whole := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	fractional := time.Date(2026, 9, 20, 10, 0, 0, 500_000_000, time.UTC)
	offset := time.Date(2026, 9, 20, 15, 30, 0, 0, time.FixedZone("IST", 5*3600+1800))

	cases := []struct {
		name  string
		quals plugin.KeyColumnQualMap
		want  []string
	}{
		{"no quals", qualMap(), []string{}},
		{">= whole second", qualMap(timeQual(">=", whole)), []string{"createdDateTime ge 2026-09-20T10:00:00Z"}},
		{"> widens to ge", qualMap(timeQual(">", whole)), []string{"createdDateTime ge 2026-09-20T10:00:00Z"}},
		{">= fraction floors", qualMap(timeQual(">=", fractional)), []string{"createdDateTime ge 2026-09-20T10:00:00Z"}},
		{"<= whole second still covers its sub-second sign-ins", qualMap(timeQual("<=", whole)), []string{"createdDateTime le 2026-09-20T10:00:01Z"}},
		{"<= fraction ceils", qualMap(timeQual("<=", fractional)), []string{"createdDateTime le 2026-09-20T10:00:01Z"}},
		{"< widens to le", qualMap(timeQual("<", whole)), []string{"createdDateTime le 2026-09-20T10:00:01Z"}},
		{"= becomes a one-second range", qualMap(timeQual("=", whole)), []string{"createdDateTime ge 2026-09-20T10:00:00Z", "createdDateTime le 2026-09-20T10:00:01Z"}},
		{"offset renders as UTC", qualMap(timeQual(">=", offset)), []string{"createdDateTime ge 2026-09-20T10:00:00Z"}},
		{"client app", qualMap(stringQual("client_app_used", "=", "Authenticated SMTP")), []string{"clientAppUsed eq 'Authenticated SMTP'"}},
		{"client app quote escaped", qualMap(stringQual("client_app_used", "=", "O'Brien")), []string{"clientAppUsed eq 'O''Brien'"}},
		{
			"unsplit IN lists are left to Postgres, never read as the epoch",
			qualMap(listQual("created_date_time", "="), listQual("client_app_used", "="), timeQual(">=", whole)),
			[]string{"createdDateTime ge 2026-09-20T10:00:00Z"},
		},
		{
			"window and client app together",
			qualMap(timeQual(">=", whole), stringQual("client_app_used", "=", "IMAP4")),
			[]string{"createdDateTime ge 2026-09-20T10:00:00Z", "clientAppUsed eq 'IMAP4'"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSignInReportQueryFilter(tc.quals)
			if !slices.Equal(got, tc.want) {
				t.Errorf("filter = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSignInReportListDeclaresFilterKeyColumns(t *testing.T) {
	keyColumns := tableAzureAdSignInReport(context.Background()).List.KeyColumns

	created := keyColumns.Find("created_date_time")
	if created == nil || created.Require != plugin.Optional {
		t.Fatalf("created_date_time must be an optional key column, got %+v", created)
	}
	if !slices.Equal(created.Operators, []string{">", ">=", "=", "<", "<="}) {
		t.Errorf("created_date_time operators = %v", created.Operators)
	}

	clientApp := keyColumns.Find("client_app_used")
	if clientApp == nil || clientApp.Require != plugin.Optional {
		t.Fatalf("client_app_used must be an optional key column, got %+v", clientApp)
	}
}

func TestSignInReportListLimiterTargetsOnlySignInLists(t *testing.T) {
	limiter := signInReportListLimiter
	if err := limiter.Initialise(); err != nil {
		t.Fatalf("limiter where clause does not parse: %v", err)
	}
	if errs := limiter.Validate(); len(errs) > 0 {
		t.Fatalf("limiter invalid: %v", errs)
	}

	tags := tableAzureAdSignInReport(context.Background()).List.Tags
	if !limiter.SatisfiesFilters(tags) {
		t.Errorf("limiter does not match the sign-in list call's tags %v", tags)
	}
	if limiter.SatisfiesFilters(map[string]string{"service": "auditLogs", "action": "directoryAudits.list"}) {
		t.Error("limiter must not throttle other audit-log tables")
	}
	if !slices.Contains(Plugin(context.Background()).RateLimiters, limiter) {
		t.Error("plugin does not register the sign-in list limiter")
	}
}
