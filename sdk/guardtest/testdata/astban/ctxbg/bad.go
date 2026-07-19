package ctxbg

import "context"

// Planted violation: context.Background() in a request-shaped path.
func handle() error {
	ctx := context.Background()
	_ = ctx
	return nil
}
