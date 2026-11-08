// Package connect is the hand-off between a relay's CONNECT front (the Naive
// proxy in server/naive) and handlers before it: a dial put on the request
// context owns that one CONNECT's destination.
package connect

// ContextKeyDial carries a func(context.Context) (net.Conn, error) on a
// CONNECT request's context. The proxy dials it instead of the destination,
// skipping its ACL and resolver, behind the same auth and padding. Hikkari
// serves its UDP-over-TCP fallback this way.
type ContextKeyDial struct{}
