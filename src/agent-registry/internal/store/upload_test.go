package store

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"
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

func TestUploadDigestMatchesConcurrentAppends(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.StartUpload()
	if err != nil {
		t.Fatal(err)
	}

	const writers = 16
	const chunkSize = 512 * 1024
	start := make(chan struct{})
	errCh := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(value byte) {
			defer wg.Done()
			<-start
			_, appendErr := s.AppendUpload(id, strings.NewReader(strings.Repeat(string(value), chunkSize)))
			errCh <- appendErr
		}(byte('a' + i))
	}
	close(start)
	wg.Wait()
	close(errCh)
	for appendErr := range errCh {
		if appendErr != nil {
			t.Fatal(appendErr)
		}
	}

	body, err := os.ReadFile(s.uploadPath(id))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != writers*chunkSize {
		t.Fatalf("upload size = %d, want %d", len(body), writers*chunkSize)
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if err := s.FinalizeUpload(id, digest); err != nil {
		t.Fatal(err)
	}
}
