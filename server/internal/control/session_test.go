package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

func TestRefreshHandler_UsesRealBoundaryAndFailureOnlyLimits(t *testing.T) {
	refresh, _, verifier, clock, _, _ := newTestRefreshServiceWithUser(t)
	session, err := NewSessionService(
		refresh,
		[]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		clock.Now,
	)
	if err != nil {
		t.Fatalf("create session service: %v", err)
	}
	nonMatchingLadder, err := auth.NewFailureLadder(map[string]auth.RateLimitPolicy{
		"/test.NonMatching/Procedure": refreshRateLimitPolicy(),
	})
	if err != nil {
		t.Fatalf("create non-matching success-path ladder: %v", err)
	}
	session.failureLadder = nonMatchingLadder

	var stagesMu sync.Mutex
	var stages []string
	stage := func(name string) connect.Interceptor {
		return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
				stagesMu.Lock()
				stages = append(stages, name)
				stagesMu.Unlock()
				return next(ctx, request)
			}
		})
	}
	chain, err := auth.NewInterceptorChain(
		stage("validate"),
		stage("authenticate"),
		stage("rate-limit"),
		testAuthorizationGate(t),
	)
	if err != nil {
		t.Fatalf("create control interceptor chain: %v", err)
	}
	path, handler, err := NewHTTPHandler(session, chain)
	if err != nil {
		t.Fatalf("create control HTTP handler: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := powermanagev1connect.NewControlServiceClient(server.Client(), server.URL)

	current, err := refresh.StartSession(t.Context(), refreshTestSubject)
	if err != nil {
		t.Fatalf("start handler session fixture: %v", err)
	}
	for range 6 {
		response, err := client.RefreshSession(
			t.Context(),
			connect.NewRequest(&powermanagev1.RefreshSessionRequest{
				RefreshToken: current.RefreshToken,
			}),
		)
		if err != nil {
			t.Fatalf("successful refresh through HTTP boundary: %v", err)
		}
		current = auth.SessionTokens{
			AccessToken:  response.Msg.GetAccessToken(),
			RefreshToken: response.Msg.GetRefreshToken(),
		}
		assertSessionTokens(t, verifier, current)
	}
	stagesMu.Lock()
	gotStages := slices.Clone(stages)
	stagesMu.Unlock()
	wantStages := []string{
		"validate", "authenticate", "rate-limit",
		"validate", "authenticate", "rate-limit",
		"validate", "authenticate", "rate-limit",
		"validate", "authenticate", "rate-limit",
		"validate", "authenticate", "rate-limit",
		"validate", "authenticate", "rate-limit",
	}
	if !slices.Equal(gotStages, wantStages) {
		t.Fatalf("control interceptor stages = %v; want ordered chain %v", gotStages, wantStages)
	}
	session.failureLadder, err = auth.NewFailureLadder(map[string]auth.RateLimitPolicy{
		powermanagev1connect.ControlServiceRefreshSessionProcedure: refreshRateLimitPolicy(),
	})
	if err != nil {
		t.Fatalf("restore refresh failure ladder: %v", err)
	}

	for attempt := 1; attempt <= 6; attempt++ {
		_, err := client.RefreshSession(
			t.Context(),
			connect.NewRequest(&powermanagev1.RefreshSessionRequest{
				RefreshToken: "distinct-invalid-token-" + string(rune('a'+attempt)),
			}),
		)
		wantCode := connect.CodeUnauthenticated
		if attempt == 6 {
			wantCode = connect.CodeResourceExhausted
		}
		if connect.CodeOf(err) != wantCode {
			t.Fatalf("per-IP failure %d code = %v (%v); want %v", attempt, connect.CodeOf(err), err, wantCode)
		}
	}

	accountSession, err := NewSessionService(
		refresh,
		[]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		clock.Now,
	)
	if err != nil {
		t.Fatalf("create account-limit session service: %v", err)
	}
	accountPath, accountHandler, err := NewHTTPHandler(accountSession, chain)
	if err != nil {
		t.Fatalf("create account-limit HTTP handler: %v", err)
	}
	accountMux := http.NewServeMux()
	accountMux.Handle(accountPath, accountHandler)
	accountServer := httptest.NewServer(accountMux)
	t.Cleanup(accountServer.Close)
	accountClient := powermanagev1connect.NewControlServiceClient(accountServer.Client(), accountServer.URL)
	for attempt := 1; attempt <= 6; attempt++ {
		request := connect.NewRequest(&powermanagev1.RefreshSessionRequest{
			RefreshToken: "same-invalid-token",
		})
		request.Header().Set("X-Forwarded-For", "198.51.100."+string(rune('0'+attempt)))
		_, err := accountClient.RefreshSession(t.Context(), request)
		wantCode := connect.CodeUnauthenticated
		if attempt == 6 {
			wantCode = connect.CodeResourceExhausted
		}
		if connect.CodeOf(err) != wantCode {
			t.Fatalf("per-account failure %d code = %v (%v); want %v", attempt, connect.CodeOf(err), err, wantCode)
		}
	}
}

func TestNewSessionService_RejectsMissingDependencies(t *testing.T) {
	refresh, _, _, clock, _, _ := newTestRefreshService(t)
	tests := []struct {
		name    string
		refresh *auth.RefreshService
		trusted []netip.Prefix
		now     func() time.Time
		want    string
	}{
		{name: "nil refresh", now: clock.Now, want: "control: refresh service is not wired"},
		{name: "nil clock", refresh: refresh, want: "control: session clock is not wired"},
		{
			name:    "invalid trusted proxy",
			refresh: refresh,
			trusted: []netip.Prefix{{}},
			now:     clock.Now,
			want:    "control: create client IP resolver: trusted proxy prefix is invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewSessionService(test.refresh, test.trusted, test.now)
			if err == nil || err.Error() != test.want {
				t.Fatalf("NewSessionService error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestRefreshHandler_RejectsMalformedBoundaryInputs(t *testing.T) {
	refresh, _, _, clock, _, _ := newTestRefreshService(t)
	session, err := NewSessionService(refresh, nil, clock.Now)
	if err != nil {
		t.Fatalf("create session service: %v", err)
	}
	if _, err := session.RefreshSession(t.Context(), nil); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("nil refresh request code = %v; want invalid_argument", connect.CodeOf(err))
	}
	request := connect.NewRequest(&powermanagev1.RefreshSessionRequest{})
	if _, err := session.RefreshSession(t.Context(), request); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("empty refresh token code = %v; want invalid_argument", connect.CodeOf(err))
	}
	var nilSession *SessionService
	if _, err := nilSession.RefreshSession(t.Context(), request); !errors.Is(err, errSessionUnavailable) {
		t.Fatalf("nil session service error = %v; want unavailable category", err)
	}
}
