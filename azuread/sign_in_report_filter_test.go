package azuread

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
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
	if !slices.Contains(Plugin(context.Background()).RateLimiters, limiter) {
		t.Error("plugin does not register the sign-in list limiter")
	}
}

func TestMatchesCreatedDateTimeQualsDropsOnlyWideningRows(t *testing.T) {
	bound := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := bound.Add(d); return &v }

	cases := []struct {
		name    string
		quals   plugin.KeyColumnQualMap
		created *time.Time
		want    bool
	}{
		{"no time quals keeps everything", qualMap(stringQual("client_app_used", "=", "IMAP4")), nil, true},
		{"< drops the extra second Graph returned", qualMap(timeQual("<", bound)), at(400 * time.Millisecond), false},
		{"< keeps an earlier row", qualMap(timeQual("<", bound)), at(-time.Microsecond), true},
		{"<= keeps a row Postgres rounds onto the bound", qualMap(timeQual("<=", bound)), at(400 * time.Nanosecond), true},
		{"<= drops a row past the bound", qualMap(timeQual("<=", bound)), at(2 * time.Microsecond), false},
		{"= keeps a row Postgres rounds onto the bound", qualMap(timeQual("=", bound)), at(-400 * time.Nanosecond), true},
		{">= drops the extra second Graph returned", qualMap(timeQual(">=", bound.Add(500*time.Millisecond))), at(100 * time.Millisecond), false},
		{"range keeps a row inside it", qualMap(timeQual(">=", bound), timeQual("<", bound.Add(time.Hour))), at(time.Minute), true},
		{"a time qual drops a row without a time", qualMap(timeQual(">=", bound)), nil, false},
		{"an unsplit list qual is left to Postgres", qualMap(listQual("created_date_time", "=")), at(time.Hour), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesCreatedDateTimeQuals(tc.created, tc.quals); got != tc.want {
				t.Errorf("matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func signInPage(nextLink string, ids ...string) models.SignInCollectionResponseable {
	page := models.NewSignInCollectionResponse()
	var value []models.SignInable
	for _, id := range ids {
		signIn := models.NewSignIn()
		signIn.SetId(&id)
		value = append(value, signIn)
	}
	page.SetValue(value)
	if nextLink != "" {
		page.SetOdataNextLink(&nextLink)
	}
	return page
}

func TestIterateSignInPagesFetchesEachNextLinkThroughNextPage(t *testing.T) {
	pages := map[string]models.SignInCollectionResponseable{
		"page2": signInPage("page3", "b", "c"),
		"page3": signInPage("", "d"),
	}
	var fetched, ids []string
	nextPage := func(_ context.Context, link string) (models.SignInCollectionResponseable, error) {
		fetched = append(fetched, link)
		return pages[link], nil
	}

	err := iterateSignInPages(context.Background(), signInPage("page2", "a"), nextPage, func(s models.SignInable) bool {
		ids = append(ids, *s.GetId())
		return true
	})
	if err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if !slices.Equal(ids, []string{"a", "b", "c", "d"}) {
		t.Errorf("ids = %v", ids)
	}
	if !slices.Equal(fetched, []string{"page2", "page3"}) {
		t.Errorf("fetched = %v", fetched)
	}
}

func TestIterateSignInPagesStopsWhenEmitStopsOrAPageFails(t *testing.T) {
	fetches := 0
	nextPage := func(context.Context, string) (models.SignInCollectionResponseable, error) {
		fetches++
		return nil, errors.New("throttled")
	}

	err := iterateSignInPages(context.Background(), signInPage("page2", "a", "b"), nextPage, func(models.SignInable) bool { return false })
	if err != nil || fetches != 0 {
		t.Errorf("a stopped emit must not fetch: err=%v fetches=%d", err, fetches)
	}

	err = iterateSignInPages(context.Background(), signInPage("page2", "a"), nextPage, func(models.SignInable) bool { return true })
	if err == nil || err.Error() != "throttled" {
		t.Errorf("err = %v, want the page error", err)
	}
}
