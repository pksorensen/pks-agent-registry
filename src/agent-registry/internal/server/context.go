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
