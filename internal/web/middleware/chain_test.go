package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// tagger returns a middleware that appends its tag to a header on the way in
// and again on the way out, so tests can observe both ordering directions.
func tagger(tag string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("X-Order", tag+"-in")
			next.ServeHTTP(w, r)
			w.Header().Add("X-Order", tag+"-out")
		})
	}
}

// shortCircuit returns a middleware that writes 418 and never calls next.
func shortCircuit() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})
	}
}

// contextKey for the context-mutation test
type ctxKey string

const ctxTagKey ctxKey = "tag"

// stamp returns a middleware that puts a tag into request context.
func stamp(tag string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ctxTagKey, tag)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func TestChain_NoMiddlewares(t *testing.T) {
	called := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Chain(h)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	assert.True(t, called, "handler must be invoked when no middlewares")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestChain_SingleMiddleware(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Chain(h, tagger("a"))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	order := w.Header().Values("X-Order")
	assert.Equal(t, []string{"a-in", "a-out"}, order)
}

func TestChain_MultipleMiddlewaresInSourceOrder(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Source order: a, b, c. Request flow: a-in -> b-in -> c-in -> handler -> c-out -> b-out -> a-out.
	wrapped := Chain(h, tagger("a"), tagger("b"), tagger("c"))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	order := w.Header().Values("X-Order")
	assert.Equal(t, []string{"a-in", "b-in", "c-in", "c-out", "b-out", "a-out"}, order,
		"first listed middleware must be outermost (request flows in source order)")
}

func TestChain_ShortCircuitMiddlewarePreventsHandler(t *testing.T) {
	handlerCalled := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	// Chain: tagger("a") -> shortCircuit -> tagger("b") -> handler.
	// shortCircuit never calls next, so b and the handler should never run.
	wrapped := Chain(h, tagger("a"), shortCircuit(), tagger("b"))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	assert.False(t, handlerCalled, "handler must not run when middleware short-circuits")
	assert.Equal(t, http.StatusTeapot, w.Code, "short-circuit response code must propagate out")

	// Only a's "in" tag should appear (a-out runs because a still wraps the short-circuit).
	order := w.Header().Values("X-Order")
	assert.Contains(t, order, "a-in")
	assert.NotContains(t, order, "b-in")
	assert.NotContains(t, order, "b-out")
}

func TestChain_ContextMutationsPropagate(t *testing.T) {
	var receivedTag string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(ctxTagKey).(string); ok {
			receivedTag = v
		}
		w.WriteHeader(http.StatusOK)
	})

	// stamp("inner") runs LAST in request flow because it's listed last, so it overwrites stamp("outer")'s value.
	wrapped := Chain(h, stamp("outer"), stamp("inner"))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	assert.Equal(t, "inner", receivedTag, "innermost middleware's context value reaches the handler")
}

func TestChain_PreservesOriginalHandlerWhenSliceEmpty(t *testing.T) {
	// Variant of TestChain_NoMiddlewares using a variadic-spread with an empty slice.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Reached", "yes")
		w.WriteHeader(http.StatusOK)
	})

	var none []func(http.Handler) http.Handler
	wrapped := Chain(h, none...)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	assert.Equal(t, "yes", w.Header().Get("X-Reached"))
	body := strings.TrimSpace(w.Body.String())
	assert.Empty(t, body)
}
