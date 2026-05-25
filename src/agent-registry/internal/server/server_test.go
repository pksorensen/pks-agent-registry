package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

func newTestServer(t *testing.T, trustedCIDRs []string) *Server {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	var nets []*net.IPNet
	for _, c := range trustedCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ParseCIDR %q: %v", c, err)
		}
		nets = append(nets, n)
	}
	return New(Config{
		Addr:              ":0",
		Store:             st,
		TrustedProxyCIDRs: nets,
	})
}

func TestTrustedProxyBypassAllowsReads(t *testing.T) {
	s := newTestServer(t, []string{"10.0.0.0/8"})
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.RemoteAddr = "10.0.8.2:54321"
	// XFF tail must be in the trusted CIDR — internal pull's last hop is on the same bridge.
	req.Header.Set("X-Forwarded-For", "10.0.8.1")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from trusted-proxy /v2/, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTrustedProxyBypassRejectsWrites(t *testing.T) {
	s := newTestServer(t, []string{"10.0.0.0/8"})
	req := httptest.NewRequest(http.MethodPost, "/v2/aspire/api/blobs/uploads/", nil)
	req.RemoteAddr = "10.0.8.2:54321"
	req.Header.Set("X-Forwarded-For", "10.0.8.1")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on write from trusted-proxy IP, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUntrustedSourceStillRequiresAuth(t *testing.T) {
	s := newTestServer(t, []string{"10.0.0.0/8"})
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 from untrusted source, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExternalClientViaProxyStillRequiresAuth(t *testing.T) {
	// Reproduces the pentest finding: TCP source is the proxy (trusted) but the original
	// client behind it is a public IP. The bypass MUST NOT trigger.
	s := newTestServer(t, []string{"10.0.0.0/8"})
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.RemoteAddr = "10.0.8.2:54321"             // proxy → registry hop
	req.Header.Set("X-Forwarded-For", "203.0.113.7") // public-internet client
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("external client routed via trusted proxy must 401, got %d body=%s",
			rec.Code, rec.Body.String())
	}
}

func TestMissingXFFRejectsEvenFromTrustedProxy(t *testing.T) {
	// Belt-and-suspenders: a direct request to the registry from an IP in the trusted CIDR
	// but without any XFF (no proxy traversal) is rejected. Operators who legitimately want
	// no-proxy bypass should clear TrustedProxyCIDRs entirely.
	s := newTestServer(t, []string{"10.0.0.0/8"})
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.RemoteAddr = "10.0.8.99:54321"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing XFF must 401, got %d", rec.Code)
	}
}

func TestSpoofedXFFFromExternalIsRejected(t *testing.T) {
	// External client crafts a fake XFF with a private IP. Their TCP source at the proxy
	// is their real public IP; the proxy appends THAT to the existing XFF — so the last
	// entry is the proxy-set real public IP, not the spoofed private one. Bypass denied.
	s := newTestServer(t, []string{"10.0.0.0/8"})
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.RemoteAddr = "10.0.8.2:54321"
	// Real-world XFF after Traefik appends: "spoofed-private-from-client, real-public-from-traefik"
	req.Header.Set("X-Forwarded-For", "10.0.0.99, 203.0.113.7")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("spoofed XFF with proxy-appended public tail must 401, got %d", rec.Code)
	}
}

func TestNoTrustedCIDRsKeepsExistingBehaviour(t *testing.T) {
	s := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.RemoteAddr = "10.0.8.2:54321"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("with no trusted CIDRs, anonymous reads must 401; got %d", rec.Code)
	}
}
