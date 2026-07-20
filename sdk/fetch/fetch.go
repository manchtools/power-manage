// Package fetch downloads remote artifacts over HTTPS with an IP-level SSRF
// guard on every dial, a mandatory size bound, an optional SHA-256 pin, and
// a redirect-hop ceiling ([SDK-9]; artifact rules AG-13a, SPEC-013).
package fetch

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
)

// Sentinels, errors.Is-matchable so callers can fail closed per cause.
var (
	ErrDisallowedAddress = errors.New("fetch: address refused by SSRF guard")
	ErrInsecureScheme    = errors.New("fetch: https is required")
	ErrTooManyRedirects  = errors.New("fetch: too many redirects")
	ErrSizeExceeded      = errors.New("fetch: response larger than MaxBytes")
	ErrChecksumMismatch  = errors.New("fetch: SHA-256 mismatch")
)

// maxRedirectHops is the AG-13a redirect ceiling.
const maxRedirectHops = 10

// Options parameterises Fetch.
type Options struct {
	// MaxBytes bounds the response body. Mandatory — a zero or negative bound
	// refuses the fetch. Exceeding it is an error, never a truncation.
	MaxBytes int64
	// PinnedSHA256 is the hex SHA-256 the full body must match. Optional, but
	// cross-origin redirects are followed only when it is set.
	PinnedSHA256 string
}

// checkAddr refuses dial targets that reach the host itself or the
// link-local/metadata ranges: loopback, link-local unicast and multicast
// (169.254.0.0/16 including 169.254.169.254, fe80::/10), and unspecified —
// in every spelling, since net.IP's class predicates test the embedded v4 of
// a v4-mapped v6 address too. Anything that does not parse as
// literal-IP:port is refused: the dialer only ever sees resolved literal
// IPs, so a non-IP here is malformed (fail closed).
func checkAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrDisallowedAddress, addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %q is not a literal IP", ErrDisallowedAddress, host)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%w: %s", ErrDisallowedAddress, ip)
	}
	return nil
}

// guardAddr is the dial-control seam: every connection — the initial request
// and every redirect landing — passes its resolved address through it before
// the socket connects. Package var so tests can admit loopback for a local
// TLS server; production never overrides it.
var guardAddr = checkAddr

// rootCAs overrides the TLS trust store (nil = system roots). Test seam.
var rootCAs *x509.CertPool

// Fetch downloads rawURL into dst under the [SDK-9]/AG-13a rules: HTTPS-only
// on every hop, the SSRF dial guard on every connection, at most
// maxRedirectHops redirects, cross-origin redirects only when pinned, and a
// mandatory size bound. When a pin is set the full body's SHA-256 must match
// — the caller must treat dst as unverified until Fetch returns nil.
func Fetch(ctx context.Context, rawURL string, dst io.Writer, opts Options) error {
	if opts.MaxBytes <= 0 {
		return fmt.Errorf("fetch %s: MaxBytes is required — an unbounded download is refused", rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("fetch: parse URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q", ErrInsecureScheme, u.Scheme)
	}
	origin := u.Host

	dialer := &net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error {
			return guardAddr(address)
		},
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:     dialer.DialContext,
			TLSClientConfig: &tls.Config{RootCAs: rootCAs},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirectHops {
				return ErrTooManyRedirects
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("%w: redirect to scheme %q", ErrInsecureScheme, req.URL.Scheme)
			}
			if req.URL.Host != origin && opts.PinnedSHA256 == "" {
				return fmt.Errorf("fetch: cross-origin redirect to %s refused without a checksum pin", req.URL.Host)
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("fetch: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }() // GET body close cannot lose data
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: unexpected status %s", rawURL, resp.Status)
	}

	hasher := sha256.New()
	out := dst
	if opts.PinnedSHA256 != "" {
		out = io.MultiWriter(dst, hasher)
	}
	// Reading one byte past the bound distinguishes exactly-at-limit from
	// over-limit without ever buffering the body.
	n, err := io.Copy(out, io.LimitReader(resp.Body, opts.MaxBytes+1))
	if err != nil {
		return fmt.Errorf("fetch %s: read body: %w", rawURL, err)
	}
	if n > opts.MaxBytes {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrSizeExceeded, opts.MaxBytes)
	}
	if opts.PinnedSHA256 != "" {
		got := hex.EncodeToString(hasher.Sum(nil))
		if got != strings.ToLower(opts.PinnedSHA256) {
			return fmt.Errorf("%w: got %s", ErrChecksumMismatch, got)
		}
	}
	return nil
}
