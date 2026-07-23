package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/manchtools/power-manage/sdk/nilcheck"
	"github.com/manchtools/power-manage/server/internal/auth"
)

const (
	bootstrapAdminSessionPath = "/bootstrap-admin/session"
	maxBootstrapRequestBytes  = 8 << 10
)

type bootstrapAdminConsumer interface {
	Consume(context.Context, string) (auth.SessionTokens, error)
}

type bootstrapAdminRequest struct {
	Token string `json:"token"`
}

type bootstrapAdminResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type bootstrapAdminError struct {
	Error string `json:"error"`
}

// NewBootstrapAdminHTTPHandler returns the cookie-free, non-RPC break-glass
// consume surface used by the web UI after it reads the login URL fragment.
func NewBootstrapAdminHTTPHandler(
	consumer bootstrapAdminConsumer,
) (string, http.Handler, error) {
	if nilcheck.Interface(consumer) {
		return "", nil, errors.New("control: bootstrap admin consumer is not wired")
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		setBootstrapResponseHeaders(response.Header())
		if request == nil || request.Method != http.MethodPost {
			response.Header().Set("Allow", http.MethodPost)
			writeBootstrapError(response, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeBootstrapError(response, http.StatusUnsupportedMediaType, "unsupported media type")
			return
		}
		request.Body = http.MaxBytesReader(response, request.Body, maxBootstrapRequestBytes)
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		var body bootstrapAdminRequest
		if err := decoder.Decode(&body); err != nil ||
			body.Token == "" ||
			decodeHasTrailingValue(decoder) {
			writeBootstrapError(response, http.StatusBadRequest, "invalid bootstrap request")
			return
		}
		tokens, err := consumer.Consume(request.Context(), body.Token)
		switch {
		case err == nil:
			response.WriteHeader(http.StatusOK)
			writeBootstrapJSON(response, bootstrapAdminResponse{
				AccessToken:  tokens.AccessToken,
				RefreshToken: tokens.RefreshToken,
			})
		case errors.Is(err, auth.ErrBootstrapRejected):
			writeBootstrapError(response, http.StatusUnauthorized, auth.ErrBootstrapRejected.Error())
		default:
			slog.Error("bootstrap admin consume failed", "error", err)
			writeBootstrapError(response, http.StatusServiceUnavailable, auth.ErrBootstrapUnavailable.Error())
		}
	})
	return bootstrapAdminSessionPath, handler, nil
}

func decodeHasTrailingValue(decoder *json.Decoder) bool {
	var trailing any
	return !errors.Is(decoder.Decode(&trailing), io.EOF)
}

func setBootstrapResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", "application/json")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
}

func writeBootstrapError(response http.ResponseWriter, status int, message string) {
	response.WriteHeader(status)
	writeBootstrapJSON(response, bootstrapAdminError{Error: message})
}

func writeBootstrapJSON(response http.ResponseWriter, value any) {
	if err := json.NewEncoder(response).Encode(value); err != nil {
		slog.Error("bootstrap response write failed", "error", err)
	}
}
