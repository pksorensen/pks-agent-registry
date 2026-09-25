package store

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestUploadDigestIsMaintainedAcrossChunks(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.StartUpload()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendUpload(id, strings.NewReader("hello ")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendUpload(id, strings.NewReader("world")); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hello world"))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if err := s.FinalizeUpload(id, digest); err != nil {
		t.Fatal(err)
	}
	if ok, size, err := s.HasBlob(digest); err != nil || !ok || size != 11 {
		t.Fatalf("final blob: ok=%v size=%d err=%v", ok, size, err)
	}
}

func TestUploadDigestRecoversWhenSidecarIsMissing(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.StartUpload()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendUpload(id, strings.NewReader("recover me")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.uploadDigestPath(id)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("recover me"))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if err := s.FinalizeUpload(id, digest); err != nil {
		t.Fatal(err)
	}
}
