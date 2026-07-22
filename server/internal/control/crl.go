package control

import (
	"bytes"
	"context"
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

// CRLDistributor provides the current-on-connect and change-push seam used by
// InternalService. Slow subscribers retain only the newest cumulative CRL.
type CRLDistributor struct {
	source CRLStateSource

	mu          sync.Mutex
	nextID      uint64
	latest      map[store.CertificateClass]store.SignedCRL
	subscribers map[store.CertificateClass]map[uint64]chan store.SignedCRL
}

// NewCRLDistributor requires durable current-state wiring.
func NewCRLDistributor(source CRLStateSource) (*CRLDistributor, error) {
	if interfaceNil(source) {
		return nil, errors.New("control: CRL state source is not wired")
	}
	return &CRLDistributor{
		source:      source,
		latest:      make(map[store.CertificateClass]store.SignedCRL),
		subscribers: make(map[store.CertificateClass]map[uint64]chan store.SignedCRL),
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
	current, err := d.source.LatestCRL(ctx, class)
	if err != nil {
		return nil, fmt.Errorf("control: read current CRL: %w", err)
	}
	current, err = validateSignedCRL(current)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	if held, ok := d.latest[class]; ok {
		switch {
		case held.Sequence > current.Sequence:
			current = held
		case held.Sequence == current.Sequence:
			if !sameSignedCRL(held, current) {
				d.mu.Unlock()
				return nil, errors.New("control: durable CRL changed without advancing its sequence")
			}
			current = held
		default:
			d.latest[class] = current
		}
	} else {
		d.latest[class] = current
	}
	d.nextID++
	id := d.nextID
	updates := make(chan store.SignedCRL, 1)
	updates <- cloneSignedCRL(current)
	if d.subscribers[class] == nil {
		d.subscribers[class] = make(map[uint64]chan store.SignedCRL)
	}
	d.subscribers[class][id] = updates
	d.mu.Unlock()

	go func() {
		<-ctx.Done()
		d.mu.Lock()
		if subscribers := d.subscribers[class]; subscribers != nil {
			if subscription, ok := subscribers[id]; ok {
				delete(subscribers, id)
				close(subscription)
			}
			if len(subscribers) == 0 {
				delete(d.subscribers, class)
			}
		}
		d.mu.Unlock()
	}()
	return updates, nil
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
	state, err := validateSignedCRL(state)
	if err != nil {
		return err
	}
	durable, err := d.source.LatestCRL(ctx, state.Class)
	if err != nil {
		return fmt.Errorf("control: read durable CRL before publication: %w", err)
	}
	durable, err = validateSignedCRL(durable)
	if err != nil {
		return err
	}
	if !sameSignedCRL(durable, state) {
		return errors.New("control: CRL publication differs from durable state")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if current, ok := d.latest[state.Class]; ok {
		if sameSignedCRL(state, current) {
			return nil
		}
		if state.Sequence <= current.Sequence {
			return fmt.Errorf("control: CRL sequence %d is not newer than %d", state.Sequence, current.Sequence)
		}
	}
	d.latest[state.Class] = state
	for _, updates := range d.subscribers[state.Class] {
		update := cloneSignedCRL(state)
		select {
		case updates <- update:
		default:
			select {
			case <-updates:
			default:
			}
			updates <- update
		}
	}
	return nil
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
	return first.Class == second.Class && first.Sequence == second.Sequence &&
		first.Source == second.Source && first.IssuedAt.Equal(second.IssuedAt) &&
		bytes.Equal(first.DER, second.DER)
}
