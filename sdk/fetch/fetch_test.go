package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// AC-13 / AG-13a: HTTPS-only remote fetch with an IP-level SSRF guard on
// every dial (initial AND redirect landings), bounded size, optional SHA-256
// pinning, and a redirect-hop ceiling. The guard rows are TEST-OWNED attack
// spellings — never derived from the implementation's own list.

func TestCheckAddr_AttackRows(t *testing.T) {
	refused := []string{
		"127.0.0.1:443",
		"127.8.9.1:443", // whole 127/8, not just .1
		"[::1]:443",
		"169.254.169.254:80", // cloud metadata
		"[fe80::1]:443",
		"[::]:443",
		"0.0.0.0:80",
		"[::ffff:127.0.0.1]:443", // v4-mapped spelling of loopback
		"[::ffff:169.254.169.254]:80",
	}
	for _, addr := range refused {
		if err := checkAddr(addr); !errors.Is(err, ErrDisallowedAddress) {
			t.Errorf("checkAddr(%q) = %v, want ErrDisallowedAddress", addr, err)
		}
	}

	if err := checkAddr("93.184.216.34:443"); err != nil {
		t.Errorf("checkAddr(public) = %v, want nil", err)
	}

	// Malformed input fails CLOSED: no parse, no dial.
	for _, addr := range []string{"", "nonsense", "127.0.0.1", "[::1", "host.name:443"} {
		if err := checkAddr(addr); err == nil {
			t.Errorf("checkAddr(%q) = nil, want fail-closed refusal", addr)
		}
	}
}

// allowLoopback swaps the dial guard for one that admits loopback (so
// httptest servers are reachable) but delegates everything else to the real
// guard — link-local and friends stay refused.
func allowLoopback(t *testing.T) {
	t.Helper()
	saved := guardAddr
	guardAddr = func(addr string) error {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				return nil
			}
		}
		return saved(addr)
	}
	t.Cleanup(func() { guardAddr = saved })
}

func trustServers(t *testing.T, servers ...*httptest.Server) {
	t.Helper()
	saved := rootCAs
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	rootCAs = pool
	t.Cleanup(func() { rootCAs = saved })
}

var body = []byte("fetch payload\n")

func bodyPin() string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func newServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/body", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/hop/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
		if err != nil || n <= 0 {
			_, _ = w.Write(body)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/hop/%d", n-1), http.StatusFound)
	})
	mux.HandleFunc("/to-http", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "http://127.0.0.1:9/body", http.StatusFound)
	})
	mux.HandleFunc("/to-metadata", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestFetch_RefusesNonHTTPSWithoutDialing(t *testing.T) {
	var dst bytes.Buffer
	for _, url := range []string{
		"http://203.0.113.7/artifact", // plaintext — refused on scheme, before DNS or dial
		"ftp://203.0.113.7/artifact",
		"://not-a-url",
	} {
		err := Fetch(context.Background(), url, &dst, Options{MaxBytes: 1 << 20})
		if err == nil {
			t.Errorf("Fetch(%q) = nil, want refusal", url)
		}
	}
	if err := Fetch(context.Background(), "http://203.0.113.7/artifact", &dst, Options{MaxBytes: 1 << 20}); !errors.Is(err, ErrInsecureScheme) {
		t.Errorf("http scheme: err = %v, want ErrInsecureScheme", err)
	}
}

// A fetch URL can carry a presigned signature or userinfo credential in its
// query/userinfo — those must never appear in a returned error (which a
// caller may log). The MaxBytes=0 path errors before any request and is the
// earliest URL-bearing error site.
func TestFetch_URLCredentialsNotInError(t *testing.T) {
	const secret = "X-Amz-Signature=DEADBEEFSIGNATURE"
	rawURL := "https://artifacts.example.com/app.tar.gz?token=SUPERSECRET&" + secret
	err := Fetch(context.Background(), rawURL, &bytes.Buffer{}, Options{MaxBytes: 0})
	if err == nil {
		t.Fatal("zero MaxBytes accepted")
	}
	if strings.Contains(err.Error(), "SUPERSECRET") || strings.Contains(err.Error(), "DEADBEEFSIGNATURE") {
		t.Errorf("credential leaked in error: %v", err)
	}
}

// MaxBytes is mandatory: an unbounded fetch is refused before any request.
func TestFetch_RequiresMaxBytes(t *testing.T) {
	allowLoopback(t)
	srv, hits := newServer(t)
	trustServers(t, srv)
	var dst bytes.Buffer
	if err := Fetch(context.Background(), srv.URL+"/body", &dst, Options{}); err == nil {
		t.Fatal("Fetch with zero MaxBytes succeeded, want refusal")
	}
	if hits.Load() != 0 {
		t.Error("request was sent despite the missing bound")
	}
}

func TestFetch_DownloadsWithinLimit(t *testing.T) {
	allowLoopback(t)
	srv, _ := newServer(t)
	trustServers(t, srv)
	var dst bytes.Buffer
	// The limit is inclusive: a body of exactly MaxBytes succeeds.
	if err := Fetch(context.Background(), srv.URL+"/body", &dst, Options{MaxBytes: int64(len(body))}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(dst.Bytes(), body) {
		t.Errorf("dst = %q, want %q", dst.Bytes(), body)
	}
}

// Over-limit is an ERROR, never a silent truncation.
func TestFetch_SizeExceeded(t *testing.T) {
	allowLoopback(t)
	srv, _ := newServer(t)
	trustServers(t, srv)
	var dst bytes.Buffer
	err := Fetch(context.Background(), srv.URL+"/body", &dst, Options{MaxBytes: int64(len(body)) - 1})
	if !errors.Is(err, ErrSizeExceeded) {
		t.Fatalf("err = %v, want ErrSizeExceeded", err)
	}
}

func TestFetch_ChecksumPin(t *testing.T) {
	allowLoopback(t)
	srv, _ := newServer(t)
	trustServers(t, srv)

	var dst bytes.Buffer
	if err := Fetch(context.Background(), srv.URL+"/body", &dst, Options{MaxBytes: 1 << 20, PinnedSHA256: bodyPin()}); err != nil {
		t.Fatalf("matching pin refused: %v", err)
	}
	if !bytes.Equal(dst.Bytes(), body) {
		t.Errorf("dst = %q", dst.Bytes())
	}

	wrong := strings.Repeat("ab", 32)
	err := Fetch(context.Background(), srv.URL+"/body", &bytes.Buffer{}, Options{MaxBytes: 1 << 20, PinnedSHA256: wrong})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("mismatched pin: err = %v, want ErrChecksumMismatch", err)
	}
}

// A redirect landing on http:// is refused — HTTPS-only holds on EVERY hop.
func TestFetch_RedirectToHTTPRefused(t *testing.T) {
	allowLoopback(t)
	srv, _ := newServer(t)
	trustServers(t, srv)
	err := Fetch(context.Background(), srv.URL+"/to-http", &bytes.Buffer{}, Options{MaxBytes: 1 << 20})
	if !errors.Is(err, ErrInsecureScheme) {
		t.Fatalf("err = %v, want ErrInsecureScheme", err)
	}
}

// A redirect landing on the metadata IP is refused AT DIAL by the same guard
// as the initial request — the guard override admits loopback only, so this
// proves redirect landings re-enter the guard. The pin is set deliberately:
// it satisfies the cross-origin redirect POLICY layer, so the refusal below
// can only come from the dial guard itself (defense in depth, not policy).
func TestFetch_RedirectToLinkLocalRefusedAtDial(t *testing.T) {
	allowLoopback(t)
	srv, _ := newServer(t)
	trustServers(t, srv)
	err := Fetch(context.Background(), srv.URL+"/to-metadata", &bytes.Buffer{}, Options{MaxBytes: 1 << 20, PinnedSHA256: bodyPin()})
	if !errors.Is(err, ErrDisallowedAddress) {
		t.Fatalf("err = %v, want ErrDisallowedAddress", err)
	}
}

func TestFetch_RedirectHopCeiling(t *testing.T) {
	allowLoopback(t)
	srv, _ := newServer(t)
	trustServers(t, srv)

	var dst bytes.Buffer
	if err := Fetch(context.Background(), srv.URL+"/hop/10", &dst, Options{MaxBytes: 1 << 20}); err != nil {
		t.Fatalf("10 hops (the AG-13a ceiling) refused: %v", err)
	}
	if !bytes.Equal(dst.Bytes(), body) {
		t.Errorf("dst = %q", dst.Bytes())
	}

	err := Fetch(context.Background(), srv.URL+"/hop/11", &bytes.Buffer{}, Options{MaxBytes: 1 << 20})
	if !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("11 hops: err = %v, want ErrTooManyRedirects", err)
	}
}

// Cross-origin redirects (different host:port) are followed ONLY when the
// content is checksum-pinned — an unpinned fetch must stay on its origin.
func TestFetch_CrossOriginRedirect(t *testing.T) {
	allowLoopback(t)
	target, _ := newServer(t)
	var hits atomic.Int64
	hopMux := http.NewServeMux()
	hopMux.HandleFunc("/jump", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, target.URL+"/body", http.StatusFound)
	})
	origin := httptest.NewTLSServer(hopMux)
	t.Cleanup(origin.Close)
	trustServers(t, origin, target)

	if err := Fetch(context.Background(), origin.URL+"/jump", &bytes.Buffer{}, Options{MaxBytes: 1 << 20}); err == nil {
		t.Fatal("unpinned cross-origin redirect followed, want refusal")
	}

	var dst bytes.Buffer
	if err := Fetch(context.Background(), origin.URL+"/jump", &dst, Options{MaxBytes: 1 << 20, PinnedSHA256: bodyPin()}); err != nil {
		t.Fatalf("pinned cross-origin redirect refused: %v", err)
	}
	if !bytes.Equal(dst.Bytes(), body) {
		t.Errorf("dst = %q", dst.Bytes())
	}
}
