package azuread

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	jsonserialization "github.com/microsoft/kiota-serialization-json-go"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/auditlogs"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

// fakeSignInGraph serves two sign-in pages: the first ("a", "b") links to the second ("c").
// onPage2, when set, runs before the second page is written.
type fakeSignInGraph struct {
	server   *httptest.Server
	requests atomic.Int32
	onPage2  func(*http.Request)
}

func newFakeSignInGraph(t *testing.T) *fakeSignInGraph {
	t.Helper()
	g := &fakeSignInGraph{}
	g.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("$skiptoken") == "" {
			_, _ = fmt.Fprintf(w, `{"@odata.nextLink":"%s/v1.0/auditLogs/signIns?$skiptoken=p2","value":[{"id":"a"},{"id":"b"}]}`, g.server.URL)
			return
		}
		if g.onPage2 != nil {
			g.onPage2(r)
		}
		_, _ = fmt.Fprint(w, `{"value":[{"id":"c"}]}`)
	}))
	t.Cleanup(g.server.Close)
	return g
}

func (g *fakeSignInGraph) signIns(t *testing.T) *auditlogs.SignInsRequestBuilder {
	t.Helper()
	adapter, err := msgraphsdkgo.NewGraphRequestAdapterWithParseNodeFactoryAndSerializationWriterFactoryAndHttpClient(
		&authentication.AnonymousAuthenticationProvider{},
		jsonserialization.NewJsonParseNodeFactory(),
		jsonserialization.NewJsonSerializationWriterFactory(),
		g.server.Client(),
	)
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	adapter.SetBaseUrl(g.server.URL + "/v1.0")
	return msgraphsdkgo.NewGraphServiceClient(adapter).AuditLogs().SignIns()
}

// collect lists sign-ins the way the table does and returns the ids it emitted with the error.
func collect(ctx context.Context, t *testing.T, g *fakeSignInGraph, wait func(context.Context)) ([]string, error) {
	t.Helper()
	var ids []string
	err := listSignIns(ctx, g.signIns(t), &auditlogs.SignInsRequestBuilderGetQueryParameters{Top: Int32(999)}, wait, func(s models.SignInable) bool {
		ids = append(ids, *s.GetId())
		return ctx.Err() == nil
	})
	return ids, err
}

func TestListSignInsReturnsEveryPage(t *testing.T) {
	g := newFakeSignInGraph(t)
	waits := 0
	ids, err := collect(context.Background(), t, g, func(context.Context) { waits++ })
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !slices.Equal(ids, []string{"a", "b", "c"}) || waits != 1 {
		t.Errorf("ids = %v, waits = %d; want a, b, c after one wait", ids, waits)
	}
}

// Each case cuts the query short at a different point; every one must fail, never end as a
// shorter (or empty) list.
func TestListSignInsCutShortIsAnError(t *testing.T) {
	t.Run("cancelled before the first request", func(t *testing.T) {
		g := newFakeSignInGraph(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ids, err := collect(ctx, t, g, func(context.Context) {})
		if !errors.Is(err, context.Canceled) || len(ids) != 0 || g.requests.Load() != 0 {
			t.Errorf("err = %v, ids = %v, requests = %d; want context.Canceled before any request", err, ids, g.requests.Load())
		}
	})

	t.Run("cancelled during the limiter wait", func(t *testing.T) {
		g := newFakeSignInGraph(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// The SDK limiter's Wait returns, without an error, as soon as the context is done.
		wait := func(ctx context.Context) {
			cancel()
			<-ctx.Done()
		}
		ids, err := collect(ctx, t, g, wait)
		if !errors.Is(err, context.Canceled) || g.requests.Load() != 1 {
			t.Errorf("err = %v, requests = %d; want context.Canceled and no second page", err, g.requests.Load())
		}
		if !slices.Equal(ids, []string{"a", "b"}) {
			t.Errorf("ids = %v, want only the first page", ids)
		}
	})

	t.Run("cancelled while fetching the next page", func(t *testing.T) {
		g := newFakeSignInGraph(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g.onPage2 = func(r *http.Request) {
			cancel()
			<-r.Context().Done()
		}
		_, err := collect(ctx, t, g, func(context.Context) {})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("cancelled while streaming rows", func(t *testing.T) {
		g := newFakeSignInGraph(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// RowsRemaining returns 0 once the context is cancelled, which stops emit like a met LIMIT.
		err := listSignIns(ctx, g.signIns(t), nil, func(context.Context) {}, func(models.SignInable) bool {
			cancel()
			return false
		})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("statement timeout during the limiter wait", func(t *testing.T) {
		g := newFakeSignInGraph(t)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := collect(ctx, t, g, func(ctx context.Context) { <-ctx.Done() })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want context.DeadlineExceeded", err)
		}
	})
}

func TestListSignInsStopsQuietlyAtLimit(t *testing.T) {
	g := newFakeSignInGraph(t)
	var ids []string
	err := listSignIns(context.Background(), g.signIns(t), nil, func(context.Context) {}, func(s models.SignInable) bool {
		ids = append(ids, *s.GetId())
		return false
	})
	if err != nil || !slices.Equal(ids, []string{"a"}) || g.requests.Load() != 1 {
		t.Errorf("err = %v, ids = %v, requests = %d; want one row and no error", err, ids, g.requests.Load())
	}
}

func TestListSignInsReturnsGraphError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`)
	}))
	defer server.Close()
	g := &fakeSignInGraph{server: server}

	ids, err := collect(context.Background(), t, g, func(context.Context) {})
	var reqErr *RequestError
	if !errors.As(err, &reqErr) || reqErr.Code != "Authorization_RequestDenied" || len(ids) != 0 {
		t.Errorf("err = %v, ids = %v; want the Graph error", err, ids)
	}
}
