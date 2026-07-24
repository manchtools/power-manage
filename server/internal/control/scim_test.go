package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestSCIMAuthentication_IdenticalFailuresBurnOneRealOrDummyBcrypt(t *testing.T) {
	var wantBody string
	for _, test := range []struct {
		name          string
		provider      string
		authorization string
		disable       bool
	}{
		{name: "wrong bearer", provider: "corporate", authorization: "Bearer wrong"},
		{name: "nonexistent provider", provider: "missing", authorization: "Bearer wrong"},
		{name: "disabled provider", provider: "corporate", disable: true},
		{name: "malformed bearer", provider: "corporate", authorization: "Basic wrong"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSCIMFixture(t, auth.SCIMFailureLimits{
				PerProvider:   auth.FailureLimit{Attempts: 10, Window: time.Minute},
				PerProviderIP: auth.FailureLimit{Attempts: 10, Window: time.Minute},
			})
			if test.authorization == "" {
				test.authorization = "Bearer " + fixture.token
			}
			if test.disable {
				if err := fixture.manager.Disable(t.Context(), "corporate"); err != nil {
					t.Fatalf("disable SCIM provider: %v", err)
				}
			}
			before := fixture.comparator.Calls()
			response := fixture.request(
				t,
				http.MethodGet,
				"/scim/v2/"+test.provider+"/ServiceProviderConfig",
				test.authorization,
				nil,
				"192.0.2.10:1234",
			)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("SCIM rejection status = %d; want 401", response.Code)
			}
			if got := fixture.comparator.Calls() - before; got != 1 {
				t.Fatalf("SCIM rejection bcrypt calls = %d; want one", got)
			}
			if wantBody == "" {
				wantBody = response.Body.String()
			}
			if response.Body.String() != wantBody {
				t.Fatalf(
					"SCIM rejection body = %q; want byte-identical %q",
					response.Body.String(),
					wantBody,
				)
			}
		})
	}
}

func TestSCIMAuthentication_FailureCausesHaveTimingParity(t *testing.T) {
	profile := auth.EnumerationParityProfiles()[auth.SecretVerifierSCIM]
	fixtures := map[auth.EnumerationFailureCause]func(*testing.T, *scimFixture) (string, string){
		auth.EnumerationMalformed: func(_ *testing.T, _ *scimFixture) (string, string) {
			return "corporate", "Basic wrong"
		},
		auth.EnumerationNonexistent: func(_ *testing.T, fixture *scimFixture) (string, string) {
			return "missing", "Bearer " + fixture.token
		},
		auth.EnumerationDisabled: func(t *testing.T, fixture *scimFixture) (string, string) {
			t.Helper()
			if err := fixture.manager.Disable(t.Context(), "corporate"); err != nil {
				t.Fatalf("disable SCIM timing fixture: %v", err)
			}
			return "corporate", "Bearer " + fixture.token
		},
		auth.EnumerationWrongSecret: func(_ *testing.T, _ *scimFixture) (string, string) {
			return "corporate", "Bearer wrong"
		},
	}
	if len(fixtures) != len(profile.FailureCauses) {
		t.Fatalf(
			"SCIM timing fixtures = %d; registered causes = %d",
			len(fixtures),
			len(profile.FailureCauses),
		)
	}
	const samplesPerCause = 3
	medians := make(map[auth.EnumerationFailureCause]time.Duration, len(fixtures))
	var wantBody string
	for _, cause := range profile.FailureCauses {
		fixtureFn, exists := fixtures[cause]
		if !exists {
			t.Fatalf("registered SCIM parity cause %q has no fixture", cause)
		}
		t.Run(string(cause), func(t *testing.T) {
			fixture := newSCIMFixture(t, auth.SCIMFailureLimits{
				PerProvider:   auth.FailureLimit{Attempts: 10, Window: time.Minute},
				PerProviderIP: auth.FailureLimit{Attempts: 10, Window: time.Minute},
			})
			provider, authorization := fixtureFn(t, fixture)
			samples := make([]time.Duration, 0, samplesPerCause)
			for range samplesPerCause {
				started := time.Now()
				response := fixture.request(
					t,
					http.MethodGet,
					"/scim/v2/"+provider+"/ServiceProviderConfig",
					authorization,
					nil,
					"192.0.2.10:1234",
				)
				samples = append(samples, time.Since(started))
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("%s SCIM status = %d; want 401", cause, response.Code)
				}
				if wantBody == "" {
					wantBody = response.Body.String()
				} else if response.Body.String() != wantBody {
					t.Fatalf("%s SCIM body differs from parity baseline", cause)
				}
			}
			slices.Sort(samples)
			median := samples[len(samples)/2]
			if median < profile.MinimumRejectionLatency {
				t.Fatalf(
					"%s median SCIM rejection took %s; want at least %s",
					cause,
					median,
					profile.MinimumRejectionLatency,
				)
			}
			medians[cause] = median
		})
	}
	var fastest, slowest time.Duration
	for _, median := range medians {
		if fastest == 0 || median < fastest {
			fastest = median
		}
		if median > slowest {
			slowest = median
		}
	}
	if spread := slowest - fastest; spread > 100*time.Millisecond {
		t.Fatalf("SCIM rejection median spread = %s; want no more than 100ms (%v)", spread, medians)
	}
}

func TestSCIMAuthentication_LimitsBeforeBcrypt(t *testing.T) {
	for _, test := range []struct {
		name       string
		limits     auth.SCIMFailureLimits
		secondPeer string
	}{
		{
			name: "provider",
			limits: auth.SCIMFailureLimits{
				PerProvider:   auth.FailureLimit{Attempts: 1, Window: time.Minute},
				PerProviderIP: auth.FailureLimit{Attempts: 10, Window: time.Minute},
			},
			secondPeer: "198.51.100.10:1234",
		},
		{
			name: "provider plus IP",
			limits: auth.SCIMFailureLimits{
				PerProvider:   auth.FailureLimit{Attempts: 10, Window: time.Minute},
				PerProviderIP: auth.FailureLimit{Attempts: 1, Window: time.Minute},
			},
			secondPeer: "192.0.2.10:5678",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSCIMFixture(t, test.limits)
			first := fixture.request(
				t,
				http.MethodGet,
				"/scim/v2/corporate/ServiceProviderConfig",
				"Bearer wrong",
				nil,
				"192.0.2.10:1234",
			)
			if first.Code != http.StatusUnauthorized || fixture.comparator.Calls() != 1 {
				t.Fatalf(
					"first SCIM failure = (status %d, bcrypt %d); want (401, 1)",
					first.Code,
					fixture.comparator.Calls(),
				)
			}
			second := fixture.request(
				t,
				http.MethodGet,
				"/scim/v2/corporate/ServiceProviderConfig",
				"Bearer wrong",
				nil,
				test.secondPeer,
			)
			if second.Code != http.StatusTooManyRequests {
				t.Fatalf("limited SCIM status = %d; want 429", second.Code)
			}
			if fixture.comparator.Calls() != 1 {
				t.Fatalf(
					"limited SCIM request reached bcrypt: calls = %d; want one total",
					fixture.comparator.Calls(),
				)
			}
		})
	}
}

func TestSCIMHTTP_UserGroupAndDiscoveryRoundTrip(t *testing.T) {
	fixture := newSCIMFixture(t, auth.SCIMFailureLimits{
		PerProvider:   auth.FailureLimit{Attempts: 20, Window: time.Minute},
		PerProviderIP: auth.FailureLimit{Attempts: 20, Window: time.Minute},
	})
	authorization := "Bearer " + fixture.token

	for _, resource := range []string{"ServiceProviderConfig", "Schemas", "ResourceTypes"} {
		discovery := fixture.request(
			t,
			http.MethodGet,
			"/scim/v2/corporate/"+resource,
			authorization,
			nil,
			"192.0.2.10:1234",
		)
		if discovery.Code != http.StatusOK ||
			discovery.Header().Get("Content-Type") != "application/scim+json" ||
			discovery.Header().Get("Set-Cookie") != "" {
			t.Fatalf(
				"SCIM %s discovery = (status %d, headers %v); want SCIM JSON without cookies",
				resource,
				discovery.Code,
				discovery.Header(),
			)
		}
	}

	existingID := "01K0QJ3E5E8R4M0D8EV3Y4N6N0"
	created, err := store.UserCreatedEvent(existingID, "linked@example.test")
	if err != nil {
		t.Fatalf("create existing user: %v", err)
	}
	oidcLinked, err := store.OIDCIdentityLinkedEvent(
		existingID,
		"workforce",
		"https://identity.example.test",
		"linked-oidc-subject",
		"linked@example.test",
	)
	if err != nil {
		t.Fatalf("create existing OIDC link: %v", err)
	}
	if err := fixture.eventStore.AppendEvents(
		t.Context(),
		[]store.Event{created, oidcLinked},
	); err != nil {
		t.Fatalf("append existing OIDC user: %v", err)
	}
	linkedUser := fixture.createUser(
		t,
		authorization,
		"linked-scim-subject",
		"linked@example.test",
	)
	if linkedUser.ID != existingID {
		t.Fatalf("SCIM existing-email link user ID = %q; want %q", linkedUser.ID, existingID)
	}
	deleteLinked := fixture.request(
		t,
		http.MethodDelete,
		"/scim/v2/corporate/Users/"+existingID,
		authorization,
		nil,
		"192.0.2.10:1234",
	)
	if deleteLinked.Code != http.StatusNoContent {
		t.Fatalf("two-link SCIM delete status = %d; want 204", deleteLinked.Code)
	}
	if _, err := fixture.eventStore.UserByID(t.Context(), existingID); err != nil {
		t.Fatalf("two-link SCIM delete removed user: %v", err)
	}

	lastUser := fixture.createUser(
		t,
		authorization,
		"last-scim-subject",
		"last@example.test",
	)
	getUser := fixture.request(
		t,
		http.MethodGet,
		"/scim/v2/corporate/Users/"+lastUser.ID,
		authorization,
		nil,
		"192.0.2.10:1234",
	)
	if getUser.Code != http.StatusOK {
		t.Fatalf("get SCIM user status = %d, body %q", getUser.Code, getUser.Body.String())
	}
	listUsers := fixture.request(
		t,
		http.MethodGet,
		`/scim/v2/corporate/Users?filter=userName%20eq%20%22last%40example.test%22`,
		authorization,
		nil,
		"192.0.2.10:1234",
	)
	if listUsers.Code != http.StatusOK ||
		!strings.Contains(listUsers.Body.String(), lastUser.ID) {
		t.Fatalf(
			"filtered SCIM users = (status %d, body %q); want last user",
			listUsers.Code,
			listUsers.Body.String(),
		)
	}

	groupBody := []byte(`{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"externalId":"platform-operators",
		"displayName":"Platform Operators",
		"members":[{"value":"` + lastUser.ID + `"}]
	}`)
	groupResponse := fixture.request(
		t,
		http.MethodPost,
		"/scim/v2/corporate/Groups",
		authorization,
		groupBody,
		"192.0.2.10:1234",
	)
	if groupResponse.Code != http.StatusCreated {
		t.Fatalf(
			"create SCIM group status = %d, body %q; want 201",
			groupResponse.Code,
			groupResponse.Body.String(),
		)
	}
	var group scimGroupResource
	if err := json.Unmarshal(groupResponse.Body.Bytes(), &group); err != nil {
		t.Fatalf("decode SCIM group: %v", err)
	}
	if group.ID == "" || len(group.Members) != 1 || group.Members[0].Value != lastUser.ID {
		t.Fatalf("created SCIM group = %+v; want one member", group)
	}
	groupBody = []byte(`{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"externalId":"platform-operators",
		"displayName":"Renamed Operators",
		"members":[]
	}`)
	replacedGroup := fixture.request(
		t,
		http.MethodPut,
		"/scim/v2/corporate/Groups/"+group.ID,
		authorization,
		groupBody,
		"192.0.2.10:1234",
	)
	if replacedGroup.Code != http.StatusOK ||
		!strings.Contains(replacedGroup.Body.String(), "Renamed Operators") {
		t.Fatalf(
			"replace SCIM group = (status %d, body %q); want renamed group",
			replacedGroup.Code,
			replacedGroup.Body.String(),
		)
	}
	deletedGroup := fixture.request(
		t,
		http.MethodDelete,
		"/scim/v2/corporate/Groups/"+group.ID,
		authorization,
		nil,
		"192.0.2.10:1234",
	)
	if deletedGroup.Code != http.StatusNoContent {
		t.Fatalf("delete SCIM group status = %d; want 204", deletedGroup.Code)
	}

	deleteLast := fixture.request(
		t,
		http.MethodDelete,
		"/scim/v2/corporate/Users/"+lastUser.ID,
		authorization,
		nil,
		"192.0.2.10:1234",
	)
	if deleteLast.Code != http.StatusNoContent {
		t.Fatalf("last-link SCIM delete status = %d; want 204", deleteLast.Code)
	}
	if _, err := fixture.eventStore.UserByID(t.Context(), lastUser.ID); !store.IsNotFound(err) {
		t.Fatalf("last-link SCIM delete user error = %v; want not found", err)
	}
}

func TestSCIMHTTP_NormalizesProviderBeforeAuthenticationAndDispatch(t *testing.T) {
	fixture := newSCIMFixture(t, auth.SCIMFailureLimits{
		PerProvider:   auth.FailureLimit{Attempts: 10, Window: time.Minute},
		PerProviderIP: auth.FailureLimit{Attempts: 10, Window: time.Minute},
	})
	response := fixture.request(
		t,
		http.MethodGet,
		"/scim/v2/%20corporate%20/Users",
		"Bearer "+fixture.token,
		nil,
		"192.0.2.10:1234",
	)
	if response.Code != http.StatusOK {
		t.Fatalf(
			"normalized SCIM provider status = %d, body %q; want 200",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestSCIMHTTP_UserReplacementRequiresExplicitActiveBeforeDeprovision(t *testing.T) {
	fixture := newSCIMFixture(t, auth.SCIMFailureLimits{
		PerProvider:   auth.FailureLimit{Attempts: 10, Window: time.Minute},
		PerProviderIP: auth.FailureLimit{Attempts: 10, Window: time.Minute},
	})
	user := fixture.createUser(
		t,
		"Bearer "+fixture.token,
		"explicit-active",
		"explicit-active@example.test",
	)
	body := []byte(`{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"id":"` + user.ID + `",
		"externalId":"explicit-active",
		"userName":"explicit-active@example.test"
	}`)
	response := fixture.request(
		t,
		http.MethodPut,
		"/scim/v2/corporate/Users/"+user.ID,
		"Bearer "+fixture.token,
		body,
		"192.0.2.10:1234",
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"SCIM replacement without active status = %d, body %q; want 400",
			response.Code,
			response.Body.String(),
		)
	}
	var rejection scimErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &rejection); err != nil {
		t.Fatalf("decode SCIM replacement rejection: %v", err)
	}
	if rejection.Detail != "invalid user" {
		t.Fatalf(
			"SCIM replacement rejection detail = %q; want static invalid user",
			rejection.Detail,
		)
	}
	if _, err := fixture.eventStore.SCIMUser(t.Context(), "corporate", user.ID); err != nil {
		t.Fatalf("SCIM replacement without active deprovisioned user: %v", err)
	}
}

func TestSCIMHTTP_RejectsUnknownAndOversizedJSONWithoutMutation(t *testing.T) {
	fixture := newSCIMFixture(t, auth.SCIMFailureLimits{
		PerProvider:   auth.FailureLimit{Attempts: 10, Window: time.Minute},
		PerProviderIP: auth.FailureLimit{Attempts: 10, Window: time.Minute},
	})
	for _, test := range []struct {
		name string
		body []byte
	}{
		{
			name: "unknown field",
			body: []byte(`{"externalId":"subject","userName":"user@example.test","unknown":true}`),
		},
		{
			name: "oversized body",
			body: []byte(`{"externalId":"subject","userName":"` + strings.Repeat("x", 70<<10) + `"}`),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := fixture.request(
				t,
				http.MethodPost,
				"/scim/v2/corporate/Users",
				"Bearer "+fixture.token,
				test.body,
				"192.0.2.10:1234",
			)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid SCIM JSON status = %d; want 400", response.Code)
			}
			var rejection scimErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &rejection); err != nil {
				t.Fatalf("decode invalid SCIM JSON rejection: %v", err)
			}
			if rejection.Detail != "invalid user" {
				t.Fatalf(
					"invalid SCIM JSON detail = %q; want static invalid user",
					rejection.Detail,
				)
			}
		})
	}
	users, err := fixture.eventStore.SCIMUsers(t.Context(), "corporate", "", 100)
	if err != nil {
		t.Fatalf("list SCIM users after invalid bodies: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("invalid SCIM bodies created users: %+v", users)
	}
}

type scimComparatorSpy struct {
	mu    sync.Mutex
	calls int
}

func (s *scimComparatorSpy) Compare(hash, password []byte) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return bcrypt.CompareHashAndPassword(hash, password)
}

func (s *scimComparatorSpy) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type scimFixture struct {
	eventStore  *store.Store
	manager     *auth.SCIMProviderManager
	handler     http.Handler
	token       string
	comparator  *scimComparatorSpy
	clock       *refreshTestClock
	requestPath string
}

func newSCIMFixture(t *testing.T, limits auth.SCIMFailureLimits) *scimFixture {
	t.Helper()
	_, _, _, clock, eventStore, _ := newTestRefreshService(t)
	manager, err := auth.NewSCIMProviderManager(
		eventStore,
		bytes.NewReader(bootstrapTestEntropy()),
		clock.Now,
		func(secret []byte) ([]byte, error) {
			return bcrypt.GenerateFromPassword(secret, bcrypt.MinCost)
		},
	)
	if err != nil {
		t.Fatalf("create SCIM provider manager: %v", err)
	}
	token, err := manager.Create(t.Context(), "corporate")
	if err != nil {
		t.Fatalf("create SCIM provider: %v", err)
	}
	dummyHash, err := bcrypt.GenerateFromPassword([]byte("dummy-scim-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash dummy SCIM secret: %v", err)
	}
	limiter, err := auth.NewSCIMFailureLimiter(limits)
	if err != nil {
		t.Fatalf("create SCIM failure limiter: %v", err)
	}
	resolver, err := auth.NewClientIPResolver(nil)
	if err != nil {
		t.Fatalf("create SCIM client-IP resolver: %v", err)
	}
	comparator := &scimComparatorSpy{}
	authenticator, err := auth.NewSCIMAuthenticator(
		eventStore,
		limiter,
		resolver,
		comparator.Compare,
		dummyHash,
		clock.Now,
	)
	if err != nil {
		t.Fatalf("create SCIM authenticator: %v", err)
	}
	service, err := NewSCIMService(
		eventStore,
		authenticator,
		bytes.NewReader(bootstrapTestEntropy()[1024:]),
		clock.Now,
	)
	if err != nil {
		t.Fatalf("create SCIM service: %v", err)
	}
	path, handler, err := NewSCIMHTTPHandler(service)
	if err != nil {
		t.Fatalf("create SCIM HTTP handler: %v", err)
	}
	if path != "/scim/v2/" {
		t.Fatalf("SCIM handler path = %q; want /scim/v2/", path)
	}
	return &scimFixture{
		eventStore:  eventStore,
		manager:     manager,
		handler:     handler,
		token:       token,
		comparator:  comparator,
		clock:       clock,
		requestPath: path,
	}
}

func (f *scimFixture) request(
	t *testing.T,
	method string,
	path string,
	authorization string,
	body []byte,
	remoteAddress string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.RemoteAddr = remoteAddress
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/scim+json")
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func (f *scimFixture) createUser(
	t *testing.T,
	authorization string,
	externalID string,
	email string,
) scimUserResource {
	t.Helper()
	body, err := json.Marshal(scimUserResource{
		Schemas:    []string{scimUserSchema},
		ExternalID: externalID,
		UserName:   email,
		Active:     true,
	})
	if err != nil {
		t.Fatalf("encode SCIM user: %v", err)
	}
	response := f.request(
		t,
		http.MethodPost,
		"/scim/v2/corporate/Users",
		authorization,
		body,
		"192.0.2.10:1234",
	)
	if response.Code != http.StatusCreated {
		t.Fatalf(
			"create SCIM user status = %d, body %q; want 201",
			response.Code,
			response.Body.String(),
		)
	}
	var user scimUserResource
	if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
		t.Fatalf("decode SCIM user: %v", err)
	}
	if user.ID == "" || user.ExternalID != externalID || user.UserName != email || !user.Active {
		t.Fatalf("created SCIM user = %+v; want active round trip", user)
	}
	return user
}

func TestSCIMProviderManager_RotatesAndDisablesBearer(t *testing.T) {
	fixture := newSCIMFixture(t, auth.SCIMFailureLimits{
		PerProvider:   auth.FailureLimit{Attempts: 10, Window: time.Minute},
		PerProviderIP: auth.FailureLimit{Attempts: 10, Window: time.Minute},
	})
	rotated, err := fixture.manager.Rotate(t.Context(), "corporate")
	if err != nil {
		t.Fatalf("rotate SCIM provider bearer: %v", err)
	}
	if rotated == "" || rotated == fixture.token {
		t.Fatal("SCIM provider rotation did not return one fresh bearer")
	}
	oldResponse := fixture.request(
		t,
		http.MethodGet,
		"/scim/v2/corporate/ServiceProviderConfig",
		"Bearer "+fixture.token,
		nil,
		"192.0.2.10:1234",
	)
	newResponse := fixture.request(
		t,
		http.MethodGet,
		"/scim/v2/corporate/ServiceProviderConfig",
		"Bearer "+rotated,
		nil,
		"192.0.2.10:1234",
	)
	if oldResponse.Code != http.StatusUnauthorized || newResponse.Code != http.StatusOK {
		t.Fatalf(
			"SCIM rotation statuses = (old %d, new %d); want (401, 200)",
			oldResponse.Code,
			newResponse.Code,
		)
	}
	if err := fixture.manager.Disable(t.Context(), "corporate"); err != nil {
		t.Fatalf("disable SCIM provider: %v", err)
	}
	disabled := fixture.request(
		t,
		http.MethodGet,
		"/scim/v2/corporate/ServiceProviderConfig",
		"Bearer "+rotated,
		nil,
		"192.0.2.10:1234",
	)
	if disabled.Code != http.StatusUnauthorized {
		t.Fatalf("disabled SCIM provider status = %d; want 401", disabled.Code)
	}
}

func TestSCIMHTTP_GroupReplacementRejectsMissingMemberAtomically(t *testing.T) {
	fixture := newSCIMFixture(t, auth.SCIMFailureLimits{
		PerProvider:   auth.FailureLimit{Attempts: 10, Window: time.Minute},
		PerProviderIP: auth.FailureLimit{Attempts: 10, Window: time.Minute},
	})
	user := fixture.createUser(t, "Bearer "+fixture.token, "member", "member@example.test")
	createBody := []byte(`{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"externalId":"atomic-group",
		"displayName":"Atomic Group",
		"members":[{"value":"` + user.ID + `"}]
	}`)
	created := fixture.request(
		t,
		http.MethodPost,
		"/scim/v2/corporate/Groups",
		"Bearer "+fixture.token,
		createBody,
		"192.0.2.10:1234",
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("create atomic SCIM group status = %d", created.Code)
	}
	var group scimGroupResource
	if err := json.Unmarshal(created.Body.Bytes(), &group); err != nil {
		t.Fatalf("decode atomic SCIM group: %v", err)
	}
	replaceBody := []byte(`{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"externalId":"atomic-group",
		"displayName":"Must Roll Back",
		"members":[{"value":"01K0QJ3E5E8R4M0D8EV3Y4N6N9"}]
	}`)
	replaced := fixture.request(
		t,
		http.MethodPut,
		"/scim/v2/corporate/Groups/"+group.ID,
		"Bearer "+fixture.token,
		replaceBody,
		"192.0.2.10:1234",
	)
	if replaced.Code != http.StatusBadRequest {
		t.Fatalf("invalid SCIM group replacement status = %d; want 400", replaced.Code)
	}
	var rejection scimErrorResponse
	if err := json.Unmarshal(replaced.Body.Bytes(), &rejection); err != nil {
		t.Fatalf("decode invalid SCIM group rejection: %v", err)
	}
	if rejection.Detail != "invalid request" {
		t.Fatalf(
			"invalid SCIM group rejection detail = %q; want static invalid request",
			rejection.Detail,
		)
	}
	stored, err := fixture.eventStore.SCIMGroup(t.Context(), "corporate", group.ID)
	if err != nil {
		t.Fatalf("read group after invalid replacement: %v", err)
	}
	if stored.DisplayName != "Atomic Group" ||
		!slices.Equal(stored.Members, []string{user.ID}) ||
		stored.ProjectionVersion != 2 {
		t.Fatalf("invalid SCIM group replacement changed state: %+v", stored)
	}
}

func TestSCIMAuthenticator_RejectsNilWiring(t *testing.T) {
	if _, err := auth.NewSCIMAuthenticator(
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	); !errors.Is(err, auth.ErrSCIMAuthenticatorNotWired) {
		t.Fatalf(
			"nil SCIM authenticator wiring error = %v; want %v",
			err,
			auth.ErrSCIMAuthenticatorNotWired,
		)
	}
	var service *SCIMService
	if _, _, err := NewSCIMHTTPHandler(service); !errors.Is(err, ErrSCIMServiceNotWired) {
		t.Fatalf("nil SCIM handler error = %v; want %v", err, ErrSCIMServiceNotWired)
	}
}
