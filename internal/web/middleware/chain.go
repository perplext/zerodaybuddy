package middleware

import "net/http"

// Chain composes a sequence of middlewares onto a handler in source-order.
//
// The middleware listed first runs first. Given Chain(h, mw1, mw2, mw3):
// the request flows mw1 -> mw2 -> mw3 -> h, and the response unwinds in
// reverse. This matches reading order, which is the most common bug source
// in middleware composition — listing middlewares in the order they appear
// in the request flow makes it harder to invert security-critical order
// (e.g., recover-panic must wrap rate-limit, not the other way around).
//
// Calling Chain with no middlewares returns the handler unchanged.
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	// Apply in reverse so the first listed middleware ends up outermost.
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
