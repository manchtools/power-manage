package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	compliancePolicyStreamType     = "compliance-policy"
	compliancePolicyCreatedType    = "CompliancePolicyCreated"
	compliancePolicyUpdatedType    = "CompliancePolicyUpdated"
	compliancePolicyDeletedType    = "CompliancePolicyDeleted"
	compliancePolicyPayloadVersion = 1
	maxCompliancePolicyRules       = 256
	maxComplianceGraceHours        = 8760

	// CompliancePolicyRebuildTarget is the CLI-only policy recovery target.
	CompliancePolicyRebuildTarget = "compliance-policies"
)

var errCompliancePolicyExists = errors.New("store: compliance policy already exists")

// CompliancePolicy bundles ordered compliance action rules and grace time.
type CompliancePolicy struct {
	ID                string
	Name              string
	RuleActionIDs     []string
	GraceHours        int32
	ProjectionVersion int64
}

type compliancePolicyPayload struct {
	Name          string   `json:"name"`
	RuleActionIDs []string `json:"rule_action_ids"`
	GraceHours    int32    `json:"grace_hours"`
}

type compliancePolicyDeletedPayload struct{}

// CompliancePolicyCreatedEvent records one policy.
func CompliancePolicyCreatedEvent(policy CompliancePolicy) (Event, error) {
	return newCompliancePolicyEvent(policy, compliancePolicyCreatedType)
}

// CompliancePolicyUpdatedEvent fully replaces one policy.
func CompliancePolicyUpdatedEvent(policy CompliancePolicy) (Event, error) {
	return newCompliancePolicyEvent(policy, compliancePolicyUpdatedType)
}

// CompliancePolicyDeletedEvent removes one policy projection.
func CompliancePolicyDeletedEvent(id string) (Event, error) {
	id, err := canonicalCompliancePolicyID(id)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(compliancePolicyDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode compliance-policy deletion: %w", err)
	}
	return compliancePolicyEvent(id, compliancePolicyDeletedType, payload), nil
}

func newCompliancePolicyEvent(policy CompliancePolicy, eventType string) (Event, error) {
	policy, err := normalizeCompliancePolicy(policy, 1)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(compliancePolicyPayload{
		Name:          policy.Name,
		RuleActionIDs: policy.RuleActionIDs,
		GraceHours:    policy.GraceHours,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode compliance policy: %w", err)
	}
	return compliancePolicyEvent(policy.ID, eventType, payload), nil
}

func compliancePolicyEvent(id, eventType string, payload []byte) Event {
	return Event{
		StreamType:     compliancePolicyStreamType,
		StreamID:       id,
		EventType:      eventType,
		PayloadVersion: compliancePolicyPayloadVersion,
		Payload:        payload,
	}
}

// CompliancePolicyByID reads one globally reachable policy.
func (s *Store) CompliancePolicyByID(
	ctx context.Context,
	id string,
	global bool,
) (CompliancePolicy, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return CompliancePolicy{}, errors.New("store: invalid compliance-policy lookup")
	}
	id, err := canonicalCompliancePolicyID(id)
	if err != nil {
		return CompliancePolicy{}, err
	}
	row, err := generated.New(s.pool).GetCompliancePolicy(
		ctx,
		generated.GetCompliancePolicyParams{PolicyID: id, GlobalScope: global},
	)
	if err != nil {
		return CompliancePolicy{}, fmt.Errorf("store: read compliance policy: %w", err)
	}
	return normalizeCompliancePolicy(CompliancePolicy{
		ID: row.PolicyID, Name: row.Name, RuleActionIDs: row.RuleActionIds,
		GraceHours: row.GraceHours,
	}, row.ProjectionVersion)
}

// ListCompliancePolicies returns one globally reachable policy page.
func (s *Store) ListCompliancePolicies(
	ctx context.Context,
	global bool,
	limit int32,
) ([]CompliancePolicy, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid compliance-policy list")
	}
	rows, err := generated.New(s.pool).ListCompliancePolicies(
		ctx,
		generated.ListCompliancePoliciesParams{
			GlobalScope: global,
			PageLimit:   limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list compliance policies: %w", err)
	}
	policies := make([]CompliancePolicy, len(rows))
	for index, row := range rows {
		policies[index], err = normalizeCompliancePolicy(CompliancePolicy{
			ID: row.PolicyID, Name: row.Name, RuleActionIDs: row.RuleActionIds,
			GraceHours: row.GraceHours,
		}, row.ProjectionVersion)
		if err != nil {
			return nil, err
		}
	}
	return policies, nil
}

// CompliancePolicyEventTypes returns the exact policy mutation set.
func CompliancePolicyEventTypes() []string {
	return []string{
		compliancePolicyCreatedType,
		compliancePolicyUpdatedType,
		compliancePolicyDeletedType,
	}
}

// IsCompliancePolicyExists recognizes duplicate policy creation.
func IsCompliancePolicyExists(err error) bool {
	return errors.Is(err, errCompliancePolicyExists)
}

func canonicalCompliancePolicyID(id string) (string, error) {
	if err := validate.ULIDPathID(id); err != nil {
		return "", fmt.Errorf("store: invalid compliance-policy ID: %w", err)
	}
	return strings.ToUpper(id), nil
}

func normalizeCompliancePolicy(
	policy CompliancePolicy,
	version int64,
) (CompliancePolicy, error) {
	id, err := canonicalCompliancePolicyID(policy.ID)
	if err != nil {
		return CompliancePolicy{}, err
	}
	if len(policy.Name) < 1 || len(policy.Name) > 200 ||
		!utf8.ValidString(policy.Name) || strings.ContainsRune(policy.Name, '\x00') ||
		len(policy.RuleActionIDs) < 1 ||
		len(policy.RuleActionIDs) > maxCompliancePolicyRules ||
		policy.GraceHours < 0 ||
		policy.GraceHours > maxComplianceGraceHours ||
		version < 1 {
		return CompliancePolicy{}, errors.New("store: compliance policy is invalid")
	}
	rules := slices.Clone(policy.RuleActionIDs)
	seen := make(map[string]struct{}, len(rules))
	for index, rule := range rules {
		rules[index], err = canonicalActionID(rule)
		if err != nil {
			return CompliancePolicy{}, errors.New("store: compliance rule ID is invalid")
		}
		if _, duplicate := seen[rules[index]]; duplicate {
			return CompliancePolicy{}, errors.New("store: compliance rule IDs contain duplicates")
		}
		seen[rules[index]] = struct{}{}
	}
	policy.ID = id
	policy.RuleActionIDs = rules
	policy.ProjectionVersion = version
	return policy, nil
}

func compliancePolicyEventDefinitions() map[string]eventDefinition {
	golden := compliancePolicyPayload{
		Name:          "shell-baseline",
		RuleActionIDs: []string{"01J00000000000000000000001"},
		GraceHours:    24,
	}
	return map[string]eventDefinition{
		compliancePolicyCreatedType: {
			PayloadVersion: compliancePolicyPayloadVersion,
			PayloadType:    compliancePolicyPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(golden)
			},
			Projector: projectCompliancePolicyCreate,
		},
		compliancePolicyUpdatedType: {
			PayloadVersion: compliancePolicyPayloadVersion,
			PayloadType:    compliancePolicyPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(golden)
			},
			Projector: projectCompliancePolicyUpdate,
		},
		compliancePolicyDeletedType: {
			PayloadVersion: compliancePolicyPayloadVersion,
			PayloadType:    compliancePolicyDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(compliancePolicyDeletedPayload{})
			},
			Projector: projectCompliancePolicyDelete,
		},
	}
}

func compliancePolicyGoldenCorpus() map[string]goldenEvent {
	payload := []byte(
		`{"name":"shell-baseline","rule_action_ids":["01J00000000000000000000001"],"grace_hours":24}`,
	)
	return map[string]goldenEvent{
		compliancePolicyCreatedType: {
			PayloadVersion: compliancePolicyPayloadVersion,
			Payload:        payload,
		},
		compliancePolicyUpdatedType: {
			PayloadVersion: compliancePolicyPayloadVersion,
			Payload:        payload,
		},
		compliancePolicyDeletedType: {
			PayloadVersion: compliancePolicyPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectCompliancePolicyCreate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errCompliancePolicyExists
	}
	policy, err := compliancePolicyFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertCompliancePolicy(
		ctx,
		generated.InsertCompliancePolicyParams{
			PolicyID:          policy.ID,
			Name:              policy.Name,
			RuleActionIds:     policy.RuleActionIDs,
			GraceHours:        policy.GraceHours,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project compliance-policy creation: %w", err)
	}
	if affected != 1 {
		return errCompliancePolicyExists
	}
	return nil
}

func projectCompliancePolicyUpdate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: compliance-policy update requires creation")
	}
	policy, err := compliancePolicyFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).ReplaceCompliancePolicy(
		ctx,
		generated.ReplaceCompliancePolicyParams{
			Name:                      policy.Name,
			RuleActionIds:             policy.RuleActionIDs,
			GraceHours:                policy.GraceHours,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			PolicyID:                  policy.ID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project compliance-policy update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: compliance-policy update conflicts with projection")
	}
	return nil
}

func projectCompliancePolicyDelete(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: compliance-policy deletion requires creation")
	}
	if _, err := decodeEventPayload[compliancePolicyDeletedPayload](
		event,
		compliancePolicyPayloadVersion,
	); err != nil {
		return err
	}
	id, err := canonicalCompliancePolicyID(event.StreamID)
	if err != nil || id != event.StreamID {
		return errors.New("store: compliance-policy deletion ID is invalid")
	}
	affected, err := generated.New(tx).DeleteCompliancePolicy(
		ctx,
		generated.DeleteCompliancePolicyParams{
			PolicyID:                  id,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project compliance-policy deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: compliance-policy deletion conflicts with projection")
	}
	return nil
}

func compliancePolicyFromEvent(event PersistedEvent) (CompliancePolicy, error) {
	payload, err := decodeEventPayload[compliancePolicyPayload](
		event,
		compliancePolicyPayloadVersion,
	)
	if err != nil {
		return CompliancePolicy{}, err
	}
	return normalizeCompliancePolicy(CompliancePolicy{
		ID: event.StreamID, Name: payload.Name, RuleActionIDs: payload.RuleActionIDs,
		GraceHours: payload.GraceHours,
	}, event.StreamVersion)
}

func resetCompliancePolicies(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetCompliancePolicies(ctx); err != nil {
		return fmt.Errorf("store: reset compliance policies: %w", err)
	}
	return nil
}
