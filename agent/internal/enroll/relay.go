package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
)

const (
	DefaultSocketPath       = "/run/pm-agent/enroll.sock"
	localAttemptsPerMinute  = 5
	localEnrollmentTimeout  = 30 * time.Second
	maxLocalEnrollmentBytes = 4096
	staleSocketProbeTimeout = 250 * time.Millisecond
)

var (
	ErrLocalRateLimited   = errors.New("enroll: local enrollment rate limited")
	ErrEnrollmentRejected = errors.New("enroll: enrollment rejected")
	errLocalTrailingData  = errors.New("enroll: local response contains trailing data")
	relayParentSafe       = validateRelayParent
)

// Enroller is the narrow local relay target implemented by Client.
type Enroller interface {
	Enroll(context.Context, string, string) (string, error)
}

// Relay owns the deliberately world-connectable, token-authorized local
// enrollment socket.
type Relay struct {
	enroller Enroller
	limiter  *localRateLimiter
	now      func() time.Time
}

// NewRelay validates the remote enrollment dependency.
func NewRelay(enroller Enroller) (*Relay, error) {
	if isNilEnrollmentDependency(enroller) {
		return nil, errors.New("enroll: nil relay enroller")
	}
	return &Relay{enroller: enroller, limiter: &localRateLimiter{}, now: time.Now}, nil
}

// Serve binds path at exact mode 0666 and relays at most five attempts in a
// sliding minute. The mode is deliberately not an authorization gate.
func (r *Relay) Serve(ctx context.Context, path string) (retErr error) {
	if r == nil || isNilEnrollmentDependency(r.enroller) || r.limiter == nil || r.now == nil {
		return errors.New("enroll: relay is not wired")
	}
	if ctx == nil {
		return errors.New("enroll: nil relay context")
	}
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("enroll: relay socket path must be absolute")
	}
	path = filepath.Clean(path)
	if err := relayParentSafe(filepath.Dir(path)); err != nil {
		return err
	}
	if err := removeStaleSocket(path); err != nil {
		return err
	}
	address, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return fmt.Errorf("enroll: resolve relay socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return fmt.Errorf("enroll: listen on relay socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	defer func() { _ = listener.Close() }()
	original, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("enroll: lstat bound relay socket: %w", err)
	}
	defer func() {
		if err := removeSocketIfSame(path, original); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	if err := os.Chmod(path, 0o666); err != nil {
		return fmt.Errorf("enroll: chmod relay socket: %w", err)
	}
	mode, err := os.Lstat(path)
	if err != nil || !os.SameFile(original, mode) || mode.Mode().Type() != os.ModeSocket || mode.Mode().Perm() != 0o666 {
		return errors.New("enroll: relay socket did not retain exact mode 0666")
	}

	serveDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-serveDone:
		}
	}()
	var handlers sync.WaitGroup
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			close(serveDone)
			handlers.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("enroll: accept relay connection: %w", err)
		}
		allowed := r.limiter.Allow(r.now())
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			r.handleConnection(ctx, connection, allowed)
		}()
	}
}

func (r *Relay) handleConnection(ctx context.Context, connection *net.UnixConn, allowed bool) {
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(r.now().Add(localEnrollmentTimeout))
	if !allowed {
		// Submit half-closes its write side after one bounded request. Drain that
		// request before replying so closing the socket cannot turn the valid
		// rate-limit response into a trailing connection-reset error.
		_, _ = io.Copy(io.Discard, io.LimitReader(connection, maxLocalEnrollmentBytes+1))
		_ = json.NewEncoder(connection).Encode(localEnrollmentResponse{Error: "rate_limited"})
		return
	}
	request, err := decodeLocalEnrollmentRequest(connection)
	if err != nil {
		_ = json.NewEncoder(connection).Encode(localEnrollmentResponse{Error: "rejected"})
		return
	}
	requestContext, cancel := context.WithTimeout(ctx, localEnrollmentTimeout)
	defer cancel()
	deviceID, err := r.enroller.Enroll(requestContext, request.Token, request.CAFingerprint)
	if err != nil || !identity.IsCanonicalULID(deviceID) {
		_ = json.NewEncoder(connection).Encode(localEnrollmentResponse{Error: "rejected"})
		return
	}
	_ = json.NewEncoder(connection).Encode(localEnrollmentResponse{DeviceID: deviceID})
}

// Submit sends one token-bearing request to the local relay. The token is
// carried only in the socket payload, never in argv or a URL.
func Submit(ctx context.Context, path, token, caFingerprint string) (string, error) {
	if ctx == nil {
		return "", errors.New("enroll: nil local-client context")
	}
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("enroll: local socket path must be absolute")
	}
	if token == "" || len(token) > maxRegistrationTokenBytes {
		return "", errors.New("enroll: registration token is invalid")
	}
	if _, err := parseCAFingerprint(caFingerprint); err != nil {
		return "", err
	}
	requestContext, cancel := context.WithTimeout(ctx, localEnrollmentTimeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(requestContext, "unix", filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("enroll: connect to local relay: %w", err)
	}
	defer func() { _ = connection.Close() }()
	connectionDone := make(chan struct{})
	go func() {
		select {
		case <-requestContext.Done():
			_ = connection.Close()
		case <-connectionDone:
		}
	}()
	defer close(connectionDone)
	if err := json.NewEncoder(connection).Encode(localEnrollmentRequest{Token: token, CAFingerprint: caFingerprint}); err != nil {
		return "", fmt.Errorf("enroll: send local enrollment request: %w", err)
	}
	if unix, ok := connection.(*net.UnixConn); ok {
		if err := unix.CloseWrite(); err != nil {
			return "", fmt.Errorf("enroll: finish local enrollment request: %w", err)
		}
	}
	response, err := decodeLocalEnrollmentResponse(connection)
	if err != nil {
		if requestContext.Err() != nil {
			return "", requestContext.Err()
		}
		return "", fmt.Errorf("enroll: read local enrollment response: %w", err)
	}
	switch response.Error {
	case "":
		if !identity.IsCanonicalULID(response.DeviceID) {
			return "", ErrEnrollmentRejected
		}
		return response.DeviceID, nil
	case "rate_limited":
		return "", ErrLocalRateLimited
	default:
		return "", ErrEnrollmentRejected
	}
}

type localEnrollmentRequest struct {
	Token         string `json:"token"`
	CAFingerprint string `json:"ca_fingerprint"`
}

type localEnrollmentResponse struct {
	DeviceID string `json:"device_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

func decodeLocalEnrollmentRequest(reader io.Reader) (localEnrollmentRequest, error) {
	limited := &io.LimitedReader{R: reader, N: maxLocalEnrollmentBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var request localEnrollmentRequest
	if err := decoder.Decode(&request); err != nil {
		return localEnrollmentRequest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return localEnrollmentRequest{}, errors.New("enroll: local request contains trailing data")
	}
	if limited.N == 0 || request.Token == "" || len(request.Token) > maxRegistrationTokenBytes {
		return localEnrollmentRequest{}, errors.New("enroll: local request token is invalid")
	}
	if _, err := parseCAFingerprint(request.CAFingerprint); err != nil {
		return localEnrollmentRequest{}, err
	}
	return request, nil
}

func decodeLocalEnrollmentResponse(reader io.Reader) (localEnrollmentResponse, error) {
	limited := &io.LimitedReader{R: reader, N: maxLocalEnrollmentBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var response localEnrollmentResponse
	if err := decoder.Decode(&response); err != nil {
		return localEnrollmentResponse{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return localEnrollmentResponse{}, errLocalTrailingData
	}
	if limited.N == 0 {
		return localEnrollmentResponse{}, errors.New("enroll: local response is too large")
	}
	if response.Error != "" && response.DeviceID != "" {
		return localEnrollmentResponse{}, errors.New("enroll: local response is ambiguous")
	}
	return response, nil
}

type localRateLimiter struct {
	mu       sync.Mutex
	attempts []time.Time
}

func (l *localRateLimiter) Allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-time.Minute)
	firstLive := 0
	for firstLive < len(l.attempts) && !l.attempts[firstLive].After(cutoff) {
		firstLive++
	}
	if firstLive > 0 {
		l.attempts = append(l.attempts[:0], l.attempts[firstLive:]...)
	}
	if len(l.attempts) >= localAttemptsPerMinute {
		return false
	}
	l.attempts = append(l.attempts, now)
	return true
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("enroll: inspect relay socket: %w", err)
	case info.Mode().Type() != os.ModeSocket:
		return errors.New("enroll: relay socket path exists and is not a socket")
	default:
		connection, dialErr := net.DialTimeout("unix", path, staleSocketProbeTimeout)
		if dialErr == nil {
			_ = connection.Close()
			return errors.New("enroll: relay socket is active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return fmt.Errorf("enroll: probe relay socket: %w", dialErr)
		}
		current, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("enroll: re-inspect stale relay socket: %w", err)
		}
		if !os.SameFile(info, current) {
			return errors.New("enroll: relay socket changed during stale probe")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("enroll: remove stale relay socket: %w", err)
		}
		return nil
	}
}

func validateRelayParent(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("enroll: resolve relay socket parent: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("enroll: inspect relay socket parent: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return errors.New("enroll: relay socket parent ownership is unavailable")
	}
	if stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("enroll: relay socket parent is unsafe: %s", resolved)
	}
	return nil
}

func removeSocketIfSame(path string, original os.FileInfo) error {
	current, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("enroll: inspect relay socket during cleanup: %w", err)
	case !os.SameFile(original, current):
		return errors.New("enroll: relay socket changed before cleanup")
	default:
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("enroll: remove relay socket: %w", err)
		}
		return nil
	}
}
