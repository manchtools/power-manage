package control

import (
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

// ErrServiceNotWired classifies missing ControlService handler wiring.
var ErrServiceNotWired = errors.New("control: service is not wired")

// NewHTTPHandler exposes ControlService only behind the ordered authentication
// interceptor chain.
func NewHTTPHandler(
	service powermanagev1connect.ControlServiceHandler,
	chain *auth.InterceptorChain,
) (string, http.Handler, error) {
	if interfaceNil(service) {
		return "", nil, ErrServiceNotWired
	}
	if err := chain.ValidateWiring(); err != nil {
		return "", nil, fmt.Errorf("control: interceptor chain: %w", err)
	}
	path, handler := powermanagev1connect.NewControlServiceHandler(
		service,
		connect.WithInterceptors(chain),
	)
	return path, handler, nil
}
