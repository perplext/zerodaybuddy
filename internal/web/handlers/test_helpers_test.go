package handlers

import (
	"context"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
)

// contextWithUserForTest is a re-export of middleware.ContextWithUser used by
// handler test files. Centralising it here keeps the per-handler test files
// from each importing the middleware package directly.
func contextWithUserForTest(ctx context.Context, u *auth.User) context.Context {
	return middleware.ContextWithUser(ctx, u)
}
