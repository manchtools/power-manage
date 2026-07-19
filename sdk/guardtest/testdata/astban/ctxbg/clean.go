package ctxbg

import "context"

// Clean: the request context flows in as a parameter.
func handleClean(ctx context.Context) error {
	_ = ctx
	return nil
}
