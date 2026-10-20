package azuread

import (
	"context"
	"fmt"
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
		{"<= fraction ceils", qualMap(timeQual("<=", fractional)), []string{"createdDateTime le 2026-09-20T10:00:01Z"}},
		{"< widens to le", qualMap(timeQual("<", whole)), []string{"createdDateTime le 2026-09-20T10:00:00Z"}},
		{"= becomes a one-second range", qualMap(timeQual("=", fractional)), []string{"createdDateTime ge 2026-09-20T10:00:00Z", "createdDateTime le 2026-09-20T10:00:01Z"}},
		{"offset renders as UTC", qualMap(timeQual(">=", offset)), []string{"createdDateTime ge 2026-09-20T10:00:00Z"}},
		{"client app", qualMap(stringQual("client_app_used", "=", "Authenticated SMTP")), []string{"clientAppUsed eq 'Authenticated SMTP'"}},
		{"client app quote escaped", qualMap(stringQual("client_app_used", "=", "O'Brien")), []string{"clientAppUsed eq 'O''Brien'"}},
		{"client app non-equals ignored", qualMap(stringQual("client_app_used", "<>", "Browser")), []string{}},
		{
			"window and client app together",
			qualMap(timeQual(">=", whole), stringQual("client_app_used", "=", "IMAP4")),
			[]string{"createdDateTime ge 2026-09-20T10:00:00Z", "clientAppUsed eq 'IMAP4'"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSignInReportQueryFilter(tc.quals)
			if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", tc.want) {
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
	if fmt.Sprint(created.Operators) != fmt.Sprint([]string{">", ">=", "=", "<", "<="}) {
		t.Errorf("created_date_time operators = %v", created.Operators)
	}

	clientApp := keyColumns.Find("client_app_used")
	if clientApp == nil || clientApp.Require != plugin.Optional {
		t.Fatalf("client_app_used must be an optional key column, got %+v", clientApp)
	}
}
