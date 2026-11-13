package auth

import "context"

type ctxKey int

const identityKey ctxKey = 1

func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func From(ctx context.Context) Identity {
	if id, ok := ctx.Value(identityKey).(Identity); ok {
		return id
	}
	return Identity{}
}