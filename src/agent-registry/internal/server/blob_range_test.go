package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// writeBlob stores content as a blob via the upload flow and returns its digest.
func writeBlob(t *testing.T, s *Server, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	id, err := s.cfg.Store.StartUpload()
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	if _, err := s.cfg.Store.AppendUpload(id, bytes.NewReader(content)); err != nil {
		t.Fatalf("AppendUpload: %v", err)
	}
	if err := s.cfg.Store.FinalizeUpload(id, digest); err != nil {
		t.Fatalf("FinalizeUpload: %v", err)
	}
	return digest
}

// The blob GET must honour HTTP Range requests with a 206 + Content-Range.
// `az acr import` copies blobs with ranged reads and fails with
// "want PartialContent: got OK" if the server always returns 200.
func TestBlobGetHonoursRangeRequests(t *testing.T) {
	s := newTestServer(t, []string{"10.0.0.0/8"})
	content := []byte("hello world, this is a ranged blob body")
	digest := writeBlob(t, s, content)
	path := "/v2/agentics/app/blobs/" + digest

	// Ranged GET → 206 with the requested slice.
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "10.0.8.2:54321"
	req.Header.Set("X-Forwarded-For", "10.0.8.1") // trusted-proxy read bypass
	req.Header.Set("Range", "bytes=0-4")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("ranged GET: want 206, got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "hello" {
		t.Fatalf("ranged GET body: want %q, got %q", "hello", got)
	}
	wantCR := fmt.Sprintf("bytes 0-4/%d", len(content))
	if cr := rec.Header().Get("Content-Range"); cr != wantCR {
		t.Fatalf("Content-Range: want %q, got %q", wantCR, cr)
	}

	// Plain GET → 200, full body, and Accept-Ranges advertised.
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	req2.RemoteAddr = "10.0.8.2:54321"
	req2.Header.Set("X-Forwarded-For", "10.0.8.1")
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("plain GET: want 200, got %d", rec2.Code)
	}
	if !bytes.Equal(rec2.Body.Bytes(), content) {
		t.Fatalf("plain GET body mismatch")
	}
	if ar := rec2.Header().Get("Accept-Ranges"); !strings.Contains(ar, "bytes") {
		t.Fatalf("Accept-Ranges: want bytes, got %q", ar)
	}
	if dg := rec2.Header().Get("Docker-Content-Digest"); dg != digest {
		t.Fatalf("Docker-Content-Digest: want %q, got %q", digest, dg)
	}
}
