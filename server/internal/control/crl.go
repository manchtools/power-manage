package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/manchtools/power-manage/server/internal/store"
)

// CRLStateSource returns the latest durable signed CRL for a certificate class.
type CRLStateSource interface {
	LatestCRL(context.Context, store.CertificateClass) (store.SignedCRL, error)
}

type issuerScopedCRLStateSource interface {
	CurrentCRLs(context.Context, store.CertificateClass) ([]store.SignedCRL, error)
	LatestCRL(context.Context, store.CertificateClass, ...[sha256.Size]byte) (store.SignedCRL, error)
}

type crlStateKey struct {
	class  store.CertificateClass
	issuer [sha256.Size]byte
}

type crlSubscription struct {
	mu      sync.Mutex
	pending map[crlStateKey]store.SignedCRL
	wake    chan struct{}
	flush   chan chan struct{}
	done    <-chan struct{}
	updates chan store.SignedCRL
}

// CRLDistributor provides the current-on-connect and change-push seam used by
// InternalService. Slow subscribers retain only the newest cumulative CRL.
type CRLDistributor struct {
	source any

	mu          sync.Mutex
	nextID      uint64
	latest      map[crlStateKey]store.SignedCRL
	subscribers map[store.CertificateClass]map[uint64]*crlSubscription
}

// NewCRLDistributor requires durable current-state wiring.
func NewCRLDistributor(source any) (*CRLDistributor, error) {
	if interfaceNil(source) {
		return nil, errors.New("control: CRL state source is not wired")
	}
	if _, legacy := source.(CRLStateSource); !legacy {
		if _, scoped := source.(issuerScopedCRLStateSource); !scoped {
			return nil, errors.New("control: CRL state source is not wired")
		}
	}
	return &CRLDistributor{
		source:      source,
		latest:      make(map[crlStateKey]store.SignedCRL),
		subscribers: make(map[store.CertificateClass]map[uint64]*crlSubscription),
	}, nil
}

// Subscribe returns a bounded update stream seeded from durable current state.
func (d *CRLDistributor) Subscribe(ctx context.Context, class store.CertificateClass) (<-chan store.SignedCRL, error) {
	if d == nil || interfaceNil(d.source) {
		return nil, errors.New("control: CRL distributor is not wired")
	}
	if ctx == nil {
		return nil, errors.New("control: nil CRL subscription context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("control: CRL subscription context: %w", err)
	}
	current, err := d.currentCRLs(ctx, class)
	if err != nil {
		return nil, fmt.Errorf("control: read current CRL: %w", err)
	}
	for index := range current {
		current[index], err = validateSignedCRL(current[index])
		if err != nil {
			return nil, err
		}
	}

	d.mu.Lock()
	for index, state := range current {
		key := signedCRLKey(state)
		if held, ok := d.latest[key]; ok {
			switch {
			case held.Sequence > state.Sequence:
				current[index] = held
			case held.Sequence == state.Sequence:
				if !sameSignedCRL(held, state) {
					d.mu.Unlock()
					if state.IssuerFingerprint == ([sha256.Size]byte{}) {
						return nil, errors.New("control: durable CRL changed without advancing its sequence")
					}
					return nil, errors.New("control: durable issuer CRL forked without advancing its sequence")
				}
				current[index] = held
			default:
				d.latest[key] = state
			}
		} else {
			d.latest[key] = state
		}
	}
	current = d.currentClassStateLocked(class)
	d.nextID++
	id := d.nextID
	subscription := &crlSubscription{
		pending: make(map[crlStateKey]store.SignedCRL),
		wake:    make(chan struct{}, 1),
		flush:   make(chan chan struct{}),
		done:    ctx.Done(),
		updates: make(chan store.SignedCRL, 1),
	}
	for _, state := range current {
		subscription.enqueue(state)
	}
	if d.subscribers[class] == nil {
		d.subscribers[class] = make(map[uint64]*crlSubscription)
	}
	d.subscribers[class][id] = subscription
	d.mu.Unlock()

	go d.runSubscription(ctx, class, id, subscription)
	return subscription.updates, nil
}

// Publish validates and fans out a strictly newer durable CRL.
func (d *CRLDistributor) Publish(ctx context.Context, state store.SignedCRL) error {
	if d == nil || interfaceNil(d.source) {
		return errors.New("control: CRL distributor is not wired")
	}
	if ctx == nil {
		return errors.New("control: nil CRL publication context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("control: CRL publication context: %w", err)
	}
	issuerFingerprint := state.IssuerFingerprint
	state, err := validateSignedCRL(state)
	if err != nil {
		if issuerFingerprint != ([sha256.Size]byte{}) {
			return fmt.Errorf("control: invalid issuer-scoped CRL: %w", err)
		}
		return err
	}
	durable, err := d.latestCRL(ctx, state.Class, state.IssuerFingerprint)
	if err != nil {
		return fmt.Errorf("control: read durable CRL before publication: %w", err)
	}
	if durable.Sequence == 0 {
		if state.IssuerFingerprint == ([sha256.Size]byte{}) {
			return errors.New("control: class has no durable CRL publication")
		}
		return errors.New("control: class or issuer has no durable CRL publication")
	}
	durable, err = validateSignedCRL(durable)
	if err != nil {
		return err
	}
	if !sameSignedCRL(durable, state) {
		if state.IssuerFingerprint == ([sha256.Size]byte{}) {
			return errors.New("control: CRL publication differs from durable state")
		}
		switch {
		case state.Sequence < durable.Sequence:
			return errors.New("control: stale issuer CRL publication")
		case state.Sequence == durable.Sequence:
			return errors.New("control: issuer CRL publication fork differs from durable state")
		default:
			return errors.New("control: issuer CRL publication is not durable")
		}
	}
	d.mu.Lock()
	key := signedCRLKey(state)
	if current, ok := d.latest[key]; ok {
		if sameSignedCRL(state, current) {
			d.mu.Unlock()
			return nil
		}
		if state.Sequence <= current.Sequence {
			d.mu.Unlock()
			if state.IssuerFingerprint == ([sha256.Size]byte{}) {
				return fmt.Errorf("control: CRL sequence %d is not newer than %d", state.Sequence, current.Sequence)
			}
			return fmt.Errorf("control: stale issuer CRL sequence %d is not newer than %d", state.Sequence, current.Sequence)
		}
	}
	d.latest[key] = state
	subscriptions := make([]*crlSubscription, 0, len(d.subscribers[state.Class]))
	for _, subscription := range d.subscribers[state.Class] {
		subscriptions = append(subscriptions, subscription)
	}
	d.mu.Unlock()
	for _, subscription := range subscriptions {
		subscription.enqueueAndSync(ctx, state)
	}
	return nil
}

func (d *CRLDistributor) currentCRLs(ctx context.Context, class store.CertificateClass) ([]store.SignedCRL, error) {
	if source, ok := d.source.(issuerScopedCRLStateSource); ok {
		return source.CurrentCRLs(ctx, class)
	}
	state, err := d.source.(CRLStateSource).LatestCRL(ctx, class)
	if err != nil {
		return nil, err
	}
	return []store.SignedCRL{state}, nil
}

func (d *CRLDistributor) latestCRL(ctx context.Context, class store.CertificateClass, issuer [sha256.Size]byte) (store.SignedCRL, error) {
	if source, ok := d.source.(issuerScopedCRLStateSource); ok {
		return source.LatestCRL(ctx, class, issuer)
	}
	if issuer != ([sha256.Size]byte{}) {
		return store.SignedCRL{}, errors.New("control: legacy CRL source cannot resolve an issuer-scoped publication")
	}
	return d.source.(CRLStateSource).LatestCRL(ctx, class)
}

func (d *CRLDistributor) currentClassStateLocked(class store.CertificateClass) []store.SignedCRL {
	result := make([]store.SignedCRL, 0, 2)
	for key, state := range d.latest {
		if key.class == class {
			result = append(result, cloneSignedCRL(state))
		}
	}
	slices.SortFunc(result, func(first, second store.SignedCRL) int {
		return slices.Compare(first.IssuerFingerprint[:], second.IssuerFingerprint[:])
	})
	return result
}

func (d *CRLDistributor) runSubscription(
	ctx context.Context,
	class store.CertificateClass,
	id uint64,
	subscription *crlSubscription,
) {
	defer func() {
		d.mu.Lock()
		if subscribers := d.subscribers[class]; subscribers != nil {
			delete(subscribers, id)
			if len(subscribers) == 0 {
				delete(d.subscribers, class)
			}
		}
		d.mu.Unlock()
		close(subscription.updates)
	}()

	for {
		state, ok := subscription.take()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case acknowledged := <-subscription.flush:
				subscription.reclaimBuffered()
				close(acknowledged)
			case <-subscription.wake:
				subscription.reclaimBuffered()
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case subscription.updates <- state:
		case acknowledged := <-subscription.flush:
			subscription.requeue(state)
			subscription.reclaimBuffered()
			close(acknowledged)
		case <-subscription.wake:
			subscription.requeue(state)
			subscription.reclaimBuffered()
		}
	}
}

func (s *crlSubscription) enqueue(state store.SignedCRL) {
	s.mu.Lock()
	s.mergeLocked(state)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *crlSubscription) enqueueAndSync(ctx context.Context, state store.SignedCRL) {
	s.enqueue(state)
	acknowledged := make(chan struct{})
	select {
	case <-ctx.Done():
		return
	case <-s.done:
		return
	case s.flush <- acknowledged:
	}
	select {
	case <-ctx.Done():
	case <-s.done:
	case <-acknowledged:
	}
}

func (s *crlSubscription) requeue(state store.SignedCRL) {
	s.mu.Lock()
	s.mergeLocked(state)
	s.mu.Unlock()
}

func (s *crlSubscription) reclaimBuffered() {
	select {
	case state := <-s.updates:
		s.requeue(state)
	default:
	}
}

func (s *crlSubscription) mergeLocked(state store.SignedCRL) {
	key := signedCRLKey(state)
	current, ok := s.pending[key]
	if !ok || state.Sequence > current.Sequence {
		s.pending[key] = cloneSignedCRL(state)
	}
}

func (s *crlSubscription) take() (store.SignedCRL, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 {
		return store.SignedCRL{}, false
	}
	states := make([]store.SignedCRL, 0, len(s.pending))
	for _, state := range s.pending {
		states = append(states, state)
	}
	slices.SortFunc(states, func(first, second store.SignedCRL) int {
		return slices.Compare(first.IssuerFingerprint[:], second.IssuerFingerprint[:])
	})
	state := states[0]
	delete(s.pending, signedCRLKey(state))
	select {
	case <-s.wake:
	default:
	}
	return cloneSignedCRL(state), true
}

func signedCRLKey(state store.SignedCRL) crlStateKey {
	return crlStateKey{class: state.Class, issuer: state.IssuerFingerprint}
}

func validateSignedCRL(state store.SignedCRL) (store.SignedCRL, error) {
	if state.Class != store.CertificateClassAgent && state.Class != store.CertificateClassGateway {
		return store.SignedCRL{}, errors.New("control: signed CRL has an invalid certificate class")
	}
	if state.Sequence <= 0 || len(state.DER) == 0 || state.IssuedAt.IsZero() {
		return store.SignedCRL{}, errors.New("control: signed CRL state is incomplete")
	}
	if state.Source != (store.CRLSource{}) &&
		(state.Source.StreamType == "" || state.Source.StreamID == "" || state.Source.StreamVersion <= 0) {
		return store.SignedCRL{}, errors.New("control: signed CRL source event is invalid")
	}
	list, err := x509.ParseRevocationList(state.DER)
	if err != nil || !bytes.Equal(list.Raw, state.DER) {
		return store.SignedCRL{}, errors.New("control: signed CRL DER is invalid")
	}
	if list.Number == nil || !list.Number.IsInt64() || list.Number.Int64() != state.Sequence {
		return store.SignedCRL{}, errors.New("control: signed CRL number does not match durable sequence")
	}
	if !list.ThisUpdate.Equal(state.IssuedAt) {
		return store.SignedCRL{}, errors.New("control: signed CRL issued-at does not match durable state")
	}
	state.DER = slices.Clone(state.DER)
	return state, nil
}

func cloneSignedCRL(state store.SignedCRL) store.SignedCRL {
	state.DER = slices.Clone(state.DER)
	return state
}

func sameSignedCRL(first, second store.SignedCRL) bool {
	return first.Class == second.Class && first.IssuerFingerprint == second.IssuerFingerprint && first.Sequence == second.Sequence &&
		first.Source == second.Source && first.IssuedAt.Equal(second.IssuedAt) &&
		bytes.Equal(first.DER, second.DER)
}
