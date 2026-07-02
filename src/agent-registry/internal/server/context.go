package server

import (
	"context"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

func contextWithOwner(ctx context.Context, o *store.Owner) context.Context {
	return context.WithValue(ctx, ctxKeyAuthUser, o)
}

// ownerFromContext returns the authenticated owner, or nil for the anonymous
// trusted-proxy read path.
func ownerFromContext(ctx context.Context) *store.Owner {
	if v, ok := ctx.Value(ctxKeyAuthUser).(*store.Owner); ok {
		return v
	}
	return nil
}

// contextWithBearer marks the request as authenticated via a registry-minted
// bearer token; denials then re-challenge (401 + scope) instead of 403.
func contextWithBearer(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyAuthBearer, true)
}

func isBearerAuth(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyAuthBearer).(bool)
	return v
}
