package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/manchtools/power-manage/sdk/ulidx"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	scimPathPrefix          = "/scim/v2/"
	scimMediaType           = "application/scim+json"
	scimUserSchema          = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema         = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListResponseSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema         = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimRejectedDetail      = "SCIM bearer rejected"
	scimRateLimitedDetail   = "SCIM request rate limited"
	scimUnavailableDetail   = "SCIM service unavailable"
	maxSCIMRequestBytes     = 64 << 10
	defaultSCIMPageSize     = 100
	maxSCIMResourceSegments = 3
)

// ErrSCIMServiceNotWired classifies missing SCIM HTTP service dependencies.
var ErrSCIMServiceNotWired = errors.New("control: SCIM service is not wired")

type scimUserResource struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId"`
	UserName   string   `json:"userName"`
	Active     bool     `json:"active"`
}

type scimUserWriteRequest struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId"`
	UserName   string   `json:"userName"`
	Active     *bool    `json:"active"`
}

type scimGroupMember struct {
	Value string `json:"value"`
}

type scimGroupResource struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id,omitempty"`
	ExternalID  string            `json:"externalId"`
	DisplayName string            `json:"displayName"`
	Members     []scimGroupMember `json:"members"`
}

type scimListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    any      `json:"Resources"`
}

type scimErrorResponse struct {
	Schemas []string `json:"schemas"`
	Status  string   `json:"status"`
	Detail  string   `json:"detail"`
}

// SCIMService owns the pure-HTTP provider provisioning boundary.
type SCIMService struct {
	eventStore    *store.Store
	authenticator *auth.SCIMAuthenticator
	random        io.Reader
	randomMu      sync.Mutex
	now           func() time.Time
}

// NewSCIMService validates durable store, authentication, entropy, and clock
// wiring.
func NewSCIMService(
	eventStore *store.Store,
	authenticator *auth.SCIMAuthenticator,
	random io.Reader,
	now func() time.Time,
) (*SCIMService, error) {
	if eventStore == nil || authenticator == nil || random == nil || now == nil {
		return nil, ErrSCIMServiceNotWired
	}
	return &SCIMService{
		eventStore:    eventStore,
		authenticator: authenticator,
		random:        random,
		now:           now,
	}, nil
}

// NewSCIMHTTPHandler exposes SCIM v2 as application/scim+json, never protobuf.
func NewSCIMHTTPHandler(service *SCIMService) (string, http.Handler, error) {
	if service == nil ||
		service.eventStore == nil ||
		service.authenticator == nil ||
		service.random == nil ||
		service.now == nil {
		return "", nil, ErrSCIMServiceNotWired
	}
	return scimPathPrefix, http.HandlerFunc(service.serveHTTP), nil
}

func (s *SCIMService) serveHTTP(response http.ResponseWriter, request *http.Request) {
	setSCIMResponseHeaders(response.Header())
	if request == nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid request")
		return
	}
	segments, ok := scimPathSegments(request.URL.Path)
	if !ok {
		writeSCIMError(response, http.StatusNotFound, "resource not found")
		return
	}
	providerSlug := strings.TrimSpace(segments[0])
	err := s.authenticator.Authenticate(
		request.Context(),
		providerSlug,
		request.Header.Get("Authorization"),
		request.RemoteAddr,
		request.Header.Get("X-Forwarded-For"),
	)
	switch {
	case errors.Is(err, auth.ErrSCIMRejected):
		writeSCIMError(response, http.StatusUnauthorized, scimRejectedDetail)
		return
	case errors.Is(err, auth.ErrSCIMRateLimited):
		writeSCIMError(response, http.StatusTooManyRequests, scimRateLimitedDetail)
		return
	case err != nil:
		slog.Error("SCIM authentication failed", "error", err)
		writeSCIMError(response, http.StatusServiceUnavailable, scimUnavailableDetail)
		return
	}

	resource := segments[1]
	resourceID := ""
	if len(segments) == maxSCIMResourceSegments {
		resourceID = segments[2]
	}
	switch resource {
	case "ServiceProviderConfig", "Schemas", "ResourceTypes":
		s.serveSCIMDiscovery(response, request, resource, resourceID)
	case "Users":
		s.serveSCIMUsers(response, request, providerSlug, resourceID)
	case "Groups":
		s.serveSCIMGroups(response, request, providerSlug, resourceID)
	default:
		writeSCIMError(response, http.StatusNotFound, "resource not found")
	}
}

func scimPathSegments(path string) ([]string, bool) {
	if !strings.HasPrefix(path, scimPathPrefix) {
		return nil, false
	}
	remainder := strings.TrimPrefix(path, scimPathPrefix)
	if remainder == "" || strings.HasSuffix(remainder, "/") {
		return nil, false
	}
	segments := strings.Split(remainder, "/")
	if len(segments) < 2 || len(segments) > maxSCIMResourceSegments {
		return nil, false
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return nil, false
		}
	}
	return segments, true
}

func (s *SCIMService) serveSCIMDiscovery(
	response http.ResponseWriter,
	request *http.Request,
	resource string,
	resourceID string,
) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeSCIMError(response, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if resourceID != "" {
		writeSCIMError(response, http.StatusNotFound, "resource not found")
		return
	}
	switch resource {
	case "ServiceProviderConfig":
		writeSCIMJSON(response, http.StatusOK, map[string]any{
			"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
			"patch":          map[string]bool{"supported": false},
			"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter":         map[string]any{"supported": true, "maxResults": defaultSCIMPageSize},
			"changePassword": map[string]bool{"supported": false},
			"sort":           map[string]bool{"supported": false},
			"etag":           map[string]bool{"supported": false},
		})
	case "Schemas":
		writeSCIMJSON(response, http.StatusOK, scimListResponse{
			Schemas:      []string{scimListResponseSchema},
			TotalResults: 2,
			StartIndex:   1,
			ItemsPerPage: 2,
			Resources: []map[string]any{
				{"id": scimUserSchema, "name": "User"},
				{"id": scimGroupSchema, "name": "Group"},
			},
		})
	case "ResourceTypes":
		writeSCIMJSON(response, http.StatusOK, scimListResponse{
			Schemas:      []string{scimListResponseSchema},
			TotalResults: 2,
			StartIndex:   1,
			ItemsPerPage: 2,
			Resources: []map[string]any{
				{"id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema},
				{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema},
			},
		})
	}
}

func (s *SCIMService) serveSCIMUsers(
	response http.ResponseWriter,
	request *http.Request,
	providerSlug string,
	userID string,
) {
	switch request.Method {
	case http.MethodGet:
		if userID == "" {
			s.listSCIMUsers(response, request, providerSlug)
			return
		}
		user, err := s.eventStore.SCIMUser(request.Context(), providerSlug, userID)
		if err != nil {
			s.writeSCIMStoreError(response, err)
			return
		}
		writeSCIMJSON(response, http.StatusOK, scimUserFromStore(user))
	case http.MethodPost:
		if userID != "" {
			writeSCIMError(response, http.StatusNotFound, "resource not found")
			return
		}
		s.createSCIMUser(response, request, providerSlug)
	case http.MethodPut:
		if userID == "" {
			writeSCIMError(response, http.StatusNotFound, "resource not found")
			return
		}
		s.replaceSCIMUser(response, request, providerSlug, userID)
	case http.MethodDelete:
		if userID == "" {
			writeSCIMError(response, http.StatusNotFound, "resource not found")
			return
		}
		s.deleteSCIMUser(response, request.Context(), providerSlug, userID)
	default:
		response.Header().Set("Allow", "GET, POST, PUT, DELETE")
		writeSCIMError(response, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *SCIMService) listSCIMUsers(
	response http.ResponseWriter,
	request *http.Request,
	providerSlug string,
) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid filter")
		return
	}
	if values := query["filter"]; len(values) > 1 {
		writeSCIMError(response, http.StatusBadRequest, "invalid filter")
		return
	}
	filter, err := scimUserNameFilter(query.Get("filter"))
	if err != nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid filter")
		return
	}
	users, err := s.eventStore.SCIMUsers(
		request.Context(),
		providerSlug,
		filter,
		defaultSCIMPageSize,
	)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	resources := make([]scimUserResource, 0, len(users))
	for _, user := range users {
		resources = append(resources, scimUserFromStore(user))
	}
	writeSCIMJSON(response, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: len(resources),
		StartIndex:   1,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func scimUserNameFilter(filter string) (string, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return "", nil
	}
	const prefix = `userName eq "`
	if !strings.HasPrefix(filter, prefix) || !strings.HasSuffix(filter, `"`) {
		return "", errors.New("control: unsupported SCIM filter")
	}
	value := strings.TrimSuffix(strings.TrimPrefix(filter, prefix), `"`)
	if strings.ContainsAny(value, `"\\`) {
		return "", errors.New("control: invalid SCIM filter value")
	}
	return store.CanonicalUserEmail(value)
}

func (s *SCIMService) createSCIMUser(
	response http.ResponseWriter,
	request *http.Request,
	providerSlug string,
) {
	var body scimUserWriteRequest
	if err := decodeSCIMBody(response, request, &body); err != nil ||
		!validSCIMSchemas(body.Schemas, scimUserSchema) ||
		body.ID != "" || body.Active == nil || !*body.Active ||
		!validSCIMExternalID(body.ExternalID) {
		writeSCIMError(response, http.StatusBadRequest, "invalid user")
		return
	}
	email, err := store.CanonicalUserEmail(body.UserName)
	if err != nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid user")
		return
	}
	user, err := s.eventStore.UserByEmail(request.Context(), email)
	switch {
	case err == nil:
		link, linkErr := store.SCIMIdentityLinkedEvent(
			user.UserID,
			providerSlug,
			body.ExternalID,
			email,
		)
		if linkErr != nil {
			writeSCIMError(response, http.StatusBadRequest, "invalid user")
			return
		}
		err = s.eventStore.AppendEventWithVersion(
			request.Context(),
			link,
			user.ProjectionVersion,
		)
	case store.IsNotFound(err):
		userID, idErr := s.newID()
		if idErr != nil {
			s.writeSCIMStoreError(response, idErr)
			return
		}
		created, createErr := store.UserCreatedEvent(userID, email)
		if createErr != nil {
			writeSCIMError(response, http.StatusBadRequest, "invalid user")
			return
		}
		link, linkErr := store.SCIMIdentityLinkedEvent(
			userID,
			providerSlug,
			body.ExternalID,
			email,
		)
		if linkErr != nil {
			writeSCIMError(response, http.StatusBadRequest, "invalid user")
			return
		}
		err = s.eventStore.AppendEvents(
			request.Context(),
			[]store.Event{created, link},
		)
		user = store.User{
			UserID:            userID,
			Email:             email,
			SessionVersion:    1,
			ProjectionVersion: 2,
		}
	default:
		s.writeSCIMStoreError(response, err)
		return
	}
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	writeSCIMJSON(response, http.StatusCreated, scimUserResource{
		Schemas:    []string{scimUserSchema},
		ID:         user.UserID,
		ExternalID: body.ExternalID,
		UserName:   email,
		Active:     true,
	})
}

func (s *SCIMService) replaceSCIMUser(
	response http.ResponseWriter,
	request *http.Request,
	providerSlug string,
	userID string,
) {
	var body scimUserWriteRequest
	if err := decodeSCIMBody(response, request, &body); err != nil ||
		!validSCIMSchemas(body.Schemas, scimUserSchema) ||
		(body.ID != "" && body.ID != userID) ||
		body.Active == nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid user")
		return
	}
	if !*body.Active {
		s.deleteSCIMUser(response, request.Context(), providerSlug, userID)
		return
	}
	current, err := s.eventStore.SCIMUser(request.Context(), providerSlug, userID)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	email, err := store.CanonicalUserEmail(body.UserName)
	if err != nil || email != current.Email || body.ExternalID != current.ExternalID {
		writeSCIMError(response, http.StatusBadRequest, "immutable user attributes differ")
		return
	}
	writeSCIMJSON(response, http.StatusOK, scimUserFromStore(current))
}

func (s *SCIMService) deleteSCIMUser(
	response http.ResponseWriter,
	ctx context.Context,
	providerSlug string,
	userID string,
) {
	user, err := s.eventStore.SCIMUser(ctx, providerSlug, userID)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	links, err := s.eventStore.UserIdentityLinkCount(ctx, user.UserID)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	if links <= 0 {
		s.writeSCIMStoreError(response, errors.New("control: SCIM user has no identity links"))
		return
	}
	unlink, err := store.SCIMIdentityUnlinkedEvent(
		user.UserID,
		providerSlug,
		user.ExternalID,
	)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	if links > 1 {
		err = s.eventStore.AppendEventWithVersion(
			ctx,
			unlink,
			user.ProjectionVersion,
		)
	} else {
		deprovisioned, eventErr := store.SCIMUserDeprovisionedEvent(user.UserID)
		if eventErr != nil {
			s.writeSCIMStoreError(response, eventErr)
			return
		}
		err = s.eventStore.AppendEvents(ctx, []store.Event{unlink, deprovisioned})
	}
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *SCIMService) serveSCIMGroups(
	response http.ResponseWriter,
	request *http.Request,
	providerSlug string,
	groupID string,
) {
	switch request.Method {
	case http.MethodGet:
		if groupID == "" {
			s.listSCIMGroups(response, request.Context(), providerSlug)
			return
		}
		group, err := s.eventStore.SCIMGroup(request.Context(), providerSlug, groupID)
		if err != nil {
			s.writeSCIMStoreError(response, err)
			return
		}
		writeSCIMJSON(response, http.StatusOK, scimGroupFromStore(group))
	case http.MethodPost:
		if groupID != "" {
			writeSCIMError(response, http.StatusNotFound, "resource not found")
			return
		}
		s.createSCIMGroup(response, request, providerSlug)
	case http.MethodPut:
		if groupID == "" {
			writeSCIMError(response, http.StatusNotFound, "resource not found")
			return
		}
		s.replaceSCIMGroup(response, request, providerSlug, groupID)
	case http.MethodDelete:
		if groupID == "" {
			writeSCIMError(response, http.StatusNotFound, "resource not found")
			return
		}
		s.deleteSCIMGroup(response, request.Context(), providerSlug, groupID)
	default:
		response.Header().Set("Allow", "GET, POST, PUT, DELETE")
		writeSCIMError(response, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *SCIMService) listSCIMGroups(
	response http.ResponseWriter,
	ctx context.Context,
	providerSlug string,
) {
	groups, err := s.eventStore.SCIMGroups(ctx, providerSlug, defaultSCIMPageSize)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	resources := make([]scimGroupResource, 0, len(groups))
	for _, group := range groups {
		resources = append(resources, scimGroupFromStore(group))
	}
	writeSCIMJSON(response, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: len(resources),
		StartIndex:   1,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (s *SCIMService) createSCIMGroup(
	response http.ResponseWriter,
	request *http.Request,
	providerSlug string,
) {
	var body scimGroupResource
	if err := decodeSCIMBody(response, request, &body); err != nil ||
		!validSCIMSchemas(body.Schemas, scimGroupSchema) ||
		body.ID != "" ||
		!validSCIMExternalID(body.ExternalID) ||
		!validSCIMDisplayName(body.DisplayName) {
		writeSCIMError(response, http.StatusBadRequest, "invalid group")
		return
	}
	groupID, err := s.newID()
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	memberIDs, err := scimMemberIDs(body.Members)
	if err != nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid group")
		return
	}
	created, err := store.SCIMGroupCreatedEvent(
		groupID,
		providerSlug,
		body.ExternalID,
		body.DisplayName,
	)
	if err != nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid group")
		return
	}
	members, err := store.SCIMGroupMembershipsReplacedEvent(groupID, memberIDs)
	if err != nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid group")
		return
	}
	if err := s.eventStore.AppendEvents(
		request.Context(),
		[]store.Event{created, members},
	); err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	group, err := s.eventStore.SCIMGroup(request.Context(), providerSlug, groupID)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	writeSCIMJSON(response, http.StatusCreated, scimGroupFromStore(group))
}

func (s *SCIMService) replaceSCIMGroup(
	response http.ResponseWriter,
	request *http.Request,
	providerSlug string,
	groupID string,
) {
	var body scimGroupResource
	if err := decodeSCIMBody(response, request, &body); err != nil ||
		!validSCIMSchemas(body.Schemas, scimGroupSchema) ||
		(body.ID != "" && body.ID != groupID) ||
		!validSCIMExternalID(body.ExternalID) ||
		!validSCIMDisplayName(body.DisplayName) {
		writeSCIMError(response, http.StatusBadRequest, "invalid group")
		return
	}
	current, err := s.eventStore.SCIMGroup(request.Context(), providerSlug, groupID)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	memberIDs, err := scimMemberIDs(body.Members)
	if err != nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid group")
		return
	}
	updated, err := store.SCIMGroupUpdatedEvent(
		groupID,
		providerSlug,
		body.ExternalID,
		body.DisplayName,
	)
	if err != nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid group")
		return
	}
	members, err := store.SCIMGroupMembershipsReplacedEvent(groupID, memberIDs)
	if err != nil {
		writeSCIMError(response, http.StatusBadRequest, "invalid group")
		return
	}
	if current.ProjectionVersion <= 0 {
		s.writeSCIMStoreError(response, errors.New("control: invalid SCIM group version"))
		return
	}
	if err := s.eventStore.AppendEventsWithVersion(
		request.Context(),
		[]store.Event{updated, members},
		current.ProjectionVersion,
	); err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	group, err := s.eventStore.SCIMGroup(request.Context(), providerSlug, groupID)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	writeSCIMJSON(response, http.StatusOK, scimGroupFromStore(group))
}

func (s *SCIMService) deleteSCIMGroup(
	response http.ResponseWriter,
	ctx context.Context,
	providerSlug string,
	groupID string,
) {
	group, err := s.eventStore.SCIMGroup(ctx, providerSlug, groupID)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	event, err := store.SCIMGroupDeletedEvent(groupID, providerSlug)
	if err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	if err := s.eventStore.AppendEventWithVersion(
		ctx,
		event,
		group.ProjectionVersion,
	); err != nil {
		s.writeSCIMStoreError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *SCIMService) newID() (string, error) {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	now := s.now()
	if now.IsZero() {
		return "", errors.New("control: SCIM clock is invalid")
	}
	return ulidx.NewWithReader(now, s.random)
}

func (s *SCIMService) writeSCIMStoreError(response http.ResponseWriter, err error) {
	if store.IsNotFound(err) {
		writeSCIMError(response, http.StatusNotFound, "resource not found")
		return
	}
	if store.IsSCIMInvalid(err) {
		writeSCIMError(response, http.StatusBadRequest, "invalid request")
		return
	}
	slog.Error("SCIM operation failed", "error", err)
	writeSCIMError(response, http.StatusServiceUnavailable, scimUnavailableDetail)
}

func scimUserFromStore(user store.SCIMUser) scimUserResource {
	return scimUserResource{
		Schemas:    []string{scimUserSchema},
		ID:         user.UserID,
		ExternalID: user.ExternalID,
		UserName:   user.Email,
		Active:     true,
	}
}

func scimGroupFromStore(group store.SCIMGroup) scimGroupResource {
	members := make([]scimGroupMember, 0, len(group.Members))
	for _, userID := range group.Members {
		members = append(members, scimGroupMember{Value: userID})
	}
	return scimGroupResource{
		Schemas:     []string{scimGroupSchema},
		ID:          group.GroupID,
		ExternalID:  group.ExternalID,
		DisplayName: group.DisplayName,
		Members:     members,
	}
}

func decodeSCIMBody(
	response http.ResponseWriter,
	request *http.Request,
	target any,
) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != scimMediaType {
		return errors.New("control: invalid SCIM media type")
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxSCIMRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("control: invalid SCIM JSON")
	}
	if decodeHasTrailingValue(decoder) {
		return errors.New("control: trailing SCIM JSON")
	}
	return nil
}

func validSCIMSchemas(schemas []string, required string) bool {
	return len(schemas) == 1 && schemas[0] == required
}

func validSCIMExternalID(value string) bool {
	return value == strings.TrimSpace(value) &&
		value != "" &&
		len(value) <= 1024 &&
		!strings.ContainsRune(value, '\x00')
}

func validSCIMDisplayName(value string) bool {
	return value == strings.TrimSpace(value) &&
		value != "" &&
		len(value) <= 512 &&
		!strings.ContainsRune(value, '\x00')
}

func scimMemberIDs(members []scimGroupMember) ([]string, error) {
	if len(members) > 1000 {
		return nil, errors.New("control: SCIM group membership is too large")
	}
	userIDs := make([]string, 0, len(members))
	for _, member := range members {
		if strings.TrimSpace(member.Value) == "" {
			return nil, errors.New("control: SCIM group member is invalid")
		}
		userIDs = append(userIDs, member.Value)
	}
	slices.Sort(userIDs)
	if len(slices.Compact(slices.Clone(userIDs))) != len(userIDs) {
		return nil, errors.New("control: SCIM group members contain duplicates")
	}
	return userIDs, nil
}

func setSCIMResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", scimMediaType)
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
}

func writeSCIMError(response http.ResponseWriter, status int, detail string) {
	writeSCIMJSON(response, status, scimErrorResponse{
		Schemas: []string{scimErrorSchema},
		Status:  fmt.Sprintf("%d", status),
		Detail:  detail,
	})
}

func writeSCIMJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		slog.Error("SCIM response write failed", "error", err)
	}
}
