package server

import "context"

func contextWithUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, ctxKeyAuthUser, user)
}

func userFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyAuthUser).(string); ok {
		return v
	}
	return ""
}
