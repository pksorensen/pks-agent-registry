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
