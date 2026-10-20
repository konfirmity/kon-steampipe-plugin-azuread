package azuread

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	betaodataerrors "github.com/microsoftgraph/msgraph-beta-sdk-go/models/odataerrors"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

type RequestError struct {
	Code    string
	Message string
}

func (m *RequestError) Error() string {
	errStr, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(errStr)
}

func getErrorObject(err error) *RequestError {
	if oDataError, ok := err.(*odataerrors.ODataError); ok {
		terr := oDataError.GetErrorEscaped()
		if terr != nil {
			return &RequestError{
				Code:    *terr.GetCode(),
				Message: *terr.GetMessage(),
			}
		}
	}

	// The beta SDK's ODataError is a distinct type whose Error() drops the Graph code.
	if oDataError, ok := err.(*betaodataerrors.ODataError); ok {
		if terr := oDataError.GetErrorEscaped(); terr != nil {
			return &RequestError{
				Code:    derefString(terr.GetCode()),
				Message: derefString(terr.GetMessage()),
			}
		}
	}

	return &RequestError{Message: err.Error()}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func isIgnorableErrorPredicate(ignoreErrorCodes []string) plugin.ErrorPredicateWithContext {
	return func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData, err error) bool {
		if err != nil {
			if terr, ok := err.(*RequestError); ok {
				for _, item := range ignoreErrorCodes {
					if terr != nil && (terr.Code == item || strings.Contains(terr.Message, item)) {
						return true
					}
				}
			}
		}
		return false
	}
}

// listCutShort is the error for a list hydrate that stopped because its query was cancelled or
// timed out, and nil while the context is live (a list that stopped at LIMIT). A list that stops
// early and returns nil reads as a complete result, so a check sees "no rows" where it should see
// a failure.
func listCutShort(ctx context.Context, table string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: list stopped before it was complete: %w", table, err)
	}
	return nil
}
