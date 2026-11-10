package observe

import (
	"context"
	"strings"
)

// Paths a relay tells its users' traffic by: straight from the client, or
// carried by the cascade's trunk from our entry (it reaches the relay on
// loopback, so its own TCP and QUIC numbers measure only the box).
const (
	PathDirect = "direct"
	PathEntry  = "entry"
)

// RelayGroup is a relay's group for key on path: "<path>/<key>".
func RelayGroup(path, key string) string { return path + "/" + key }

// SplitGroup undoes RelayGroup; a group without a path reads as direct.
func SplitGroup(group string) (path, key string) {
	if path, key, ok := strings.Cut(group, "/"); ok {
		return path, key
	}
	return PathDirect, group
}

type groupKey struct{}

// WithGroup names the group what is served under ctx counts in.
func WithGroup(ctx context.Context, group string) context.Context {
	return context.WithValue(ctx, groupKey{}, group)
}

// GroupFrom is ctx's group, or fallback when it names none.
func GroupFrom(ctx context.Context, fallback string) string {
	if g, ok := ctx.Value(groupKey{}).(string); ok {
		return g
	}
	return fallback
}
