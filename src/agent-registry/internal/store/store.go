package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrDigestMismatch = errors.New("digest mismatch")
	ErrInvalidName    = errors.New("invalid name")
	ErrExists         = errors.New("already exists")
)

type Store struct {
	DataDir string
}

func New(dataDir string) (*Store, error) {
	for _, sub := range []string{"blobs", "uploads", "repos", "owners"} {
		if err := os.MkdirAll(filepath.Join(dataDir, sub), 0o755); err != nil {
			return nil, err
		}
	}
	return &Store{DataDir: dataDir}, nil
}

// ValidName allows lowercase alnum + . _ -, length 1..255. No slashes.
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// ParseRepo splits "owner/name" and validates both segments.
func ParseRepo(full string) (owner, name string, err error) {
	parts := strings.SplitN(full, "/", 2)
	if len(parts) != 2 || !ValidName(parts[0]) || !ValidName(parts[1]) {
		return "", "", ErrInvalidName
	}
	return parts[0], parts[1], nil
}

// ValidDigest accepts only "sha256:<64 hex>".
func ValidDigest(d string) bool {
	if !strings.HasPrefix(d, "sha256:") {
		return false
	}
	hex := d[len("sha256:"):]
	if len(hex) != 64 {
		return false
	}
	for _, r := range hex {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// -------- Owners --------

// Permissions scopes what an owner credential may do. A nil *Permissions on an
// Owner means "legacy full access" (push to own namespace + pull everything) —
// this preserves the behaviour of owners created before permissions existed, so
// no migration is needed. A non-nil *Permissions is enforced exactly.
type Permissions struct {
	// Push allows writing/deleting in the owner's OWN namespace. False = pull-only.
	Push bool `json:"push"`
	// PullScopes are glob patterns over "owner/name" granting cross-namespace
	// reads. An owner can always read its own namespace regardless of this list.
	// Patterns use path.Match semantics: "agentics/pks-agent-marketplace" (exact),
	// "agentics/*" (all repos of an owner), "*" or "*/*" (everything).
	PullScopes []string `json:"pullScopes"`
}

type Owner struct {
	Name         string       `json:"name"`
	PasswordHash string       `json:"passwordHash"`
	CreatedAt    time.Time    `json:"createdAt"`
	Permissions  *Permissions `json:"permissions,omitempty"`
}

// CanPush reports whether this owner may push/delete in its own namespace.
// A nil owner (anonymous trusted-proxy read path) can never push. A nil
// Permissions block means legacy full access.
func (o *Owner) CanPush() bool {
	if o == nil {
		return false
	}
	if o.Permissions == nil {
		return true
	}
	return o.Permissions.Push
}

// CanPull reports whether this owner may pull the repo "targetOwner/targetName".
// A nil owner (anonymous trusted-proxy read) and a nil Permissions block both
// mean full read access. Otherwise reads are limited to the owner's own
// namespace plus any matching PullScopes.
func (o *Owner) CanPull(targetOwner, targetName string) bool {
	if o == nil || o.Permissions == nil {
		return true
	}
	if targetOwner == o.Name {
		return true
	}
	full := targetOwner + "/" + targetName
	for _, p := range o.Permissions.PullScopes {
		if scopeMatch(p, full) {
			return true
		}
	}
	return false
}

// scopeMatch matches a pull-scope glob against an "owner/name" string.
func scopeMatch(pattern, full string) bool {
	if pattern == "*" || pattern == "*/*" {
		return true
	}
	ok, err := path.Match(pattern, full)
	return err == nil && ok
}

func (s *Store) ownerPath(name string) string {
	return filepath.Join(s.DataDir, "owners", name+".json")
}

func (s *Store) GetOwner(name string) (*Owner, error) {
	if !ValidName(name) {
		return nil, ErrInvalidName
	}
	b, err := os.ReadFile(s.ownerPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	o := &Owner{}
	if err := json.Unmarshal(b, o); err != nil {
		return nil, err
	}
	return o, nil
}

func (s *Store) PutOwner(name, password string) (*Owner, error) {
	if !ValidName(name) {
		return nil, ErrInvalidName
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	o := &Owner{
		Name:         name,
		PasswordHash: string(hash),
		CreatedAt:    time.Now().UTC(),
	}
	if existing, err := s.GetOwner(name); err == nil && existing != nil {
		// Preserve metadata that a password change must not clobber.
		o.CreatedAt = existing.CreatedAt
		o.Permissions = existing.Permissions
	}
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(s.ownerPath(name), b, 0o600); err != nil {
		return nil, err
	}
	return o, nil
}

// CreateOwner creates a new owner with the given password and permissions,
// returning ErrExists if one already exists. Unlike PutOwner (which upserts),
// this never overwrites a live credential. A nil perms means legacy full access.
func (s *Store) CreateOwner(name, password string, perms *Permissions) (*Owner, error) {
	if !ValidName(name) {
		return nil, ErrInvalidName
	}
	if _, err := s.GetOwner(name); err == nil {
		return nil, ErrExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	o := &Owner{
		Name:         name,
		PasswordHash: string(hash),
		CreatedAt:    time.Now().UTC(),
		Permissions:  perms,
	}
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(s.ownerPath(name), b, 0o600); err != nil {
		return nil, err
	}
	return o, nil
}

// SetPermissions replaces an owner's permission block without touching its
// password. A nil perms restores legacy full access.
func (s *Store) SetPermissions(name string, perms *Permissions) error {
	o, err := s.GetOwner(name)
	if err != nil {
		return err
	}
	o.Permissions = perms
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.ownerPath(name), b, 0o600)
}

func (s *Store) DeleteOwner(name string) error {
	if !ValidName(name) {
		return ErrInvalidName
	}
	err := os.Remove(s.ownerPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

func (s *Store) ListOwners() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.DataDir, "owners"))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.TrimSuffix(e.Name(), ".json")
		if n == e.Name() {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) CheckPassword(name, password string) bool {
	o, err := s.GetOwner(name)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(o.PasswordHash), []byte(password)) == nil
}

// -------- Blobs --------

func (s *Store) blobPath(digest string) string {
	h := digest[len("sha256:"):]
	return filepath.Join(s.DataDir, "blobs", "sha256", h[:2], h)
}

func (s *Store) HasBlob(digest string) (bool, int64, error) {
	if !ValidDigest(digest) {
		return false, 0, ErrInvalidName
	}
	st, err := os.Stat(s.blobPath(digest))
	if errors.Is(err, os.ErrNotExist) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	return true, st.Size(), nil
}

func (s *Store) OpenBlob(digest string) (io.ReadCloser, int64, error) {
	if !ValidDigest(digest) {
		return nil, 0, ErrInvalidName
	}
	f, err := os.Open(s.blobPath(digest))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

func (s *Store) DeleteBlob(digest string) error {
	if !ValidDigest(digest) {
		return ErrInvalidName
	}
	err := os.Remove(s.blobPath(digest))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

// -------- Upload sessions --------

func (s *Store) uploadPath(id string) string {
	return filepath.Join(s.DataDir, "uploads", id)
}

func (s *Store) StartUpload() (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	f, err := os.Create(s.uploadPath(id))
	if err != nil {
		return "", err
	}
	f.Close()
	return id, nil
}

func (s *Store) UploadSize(id string) (int64, error) {
	st, err := os.Stat(s.uploadPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

func (s *Store) AppendUpload(id string, r io.Reader) (int64, error) {
	f, err := os.OpenFile(s.uploadPath(id), os.O_WRONLY|os.O_APPEND, 0o644)
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := io.Copy(f, r); err != nil {
		return 0, err
	}
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// FinalizeUpload hashes the upload, verifies it matches expectedDigest, and
// moves it into content-addressed blob storage. The upload session is removed
// on success.
func (s *Store) FinalizeUpload(id, expectedDigest string) error {
	if !ValidDigest(expectedDigest) {
		return ErrInvalidName
	}
	src := s.uploadPath(id)
	f, err := os.Open(src)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return err
	}
	f.Close()
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != expectedDigest {
		return fmt.Errorf("%w: got %s, expected %s", ErrDigestMismatch, got, expectedDigest)
	}
	dst := s.blobPath(expectedDigest)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	return nil
}

func (s *Store) AbortUpload(id string) error {
	err := os.Remove(s.uploadPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

// -------- Manifests + tags --------

type ManifestInfo struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
}

func (s *Store) repoDir(owner, name string) string {
	return filepath.Join(s.DataDir, "repos", owner, name)
}

func (s *Store) manifestPath(owner, name, digest string) string {
	h := digest[len("sha256:"):]
	return filepath.Join(s.repoDir(owner, name), "manifests", h)
}

func (s *Store) tagPath(owner, name, tag string) string {
	return filepath.Join(s.repoDir(owner, name), "tags", tag)
}

// PutManifest stores body under its digest and, if ref is a tag (not a
// digest), points the tag at it.
func (s *Store) PutManifest(owner, name, ref, mediaType string, body []byte) (ManifestInfo, error) {
	if !ValidName(owner) || !ValidName(name) {
		return ManifestInfo{}, ErrInvalidName
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	if err := os.MkdirAll(filepath.Join(s.repoDir(owner, name), "manifests"), 0o755); err != nil {
		return ManifestInfo{}, err
	}
	if err := os.MkdirAll(filepath.Join(s.repoDir(owner, name), "tags"), 0o755); err != nil {
		return ManifestInfo{}, err
	}
	mp := s.manifestPath(owner, name, digest)
	if err := writeFileAtomic(mp, body, 0o644); err != nil {
		return ManifestInfo{}, err
	}
	if err := writeFileAtomic(mp+".mediatype", []byte(mediaType), 0o644); err != nil {
		return ManifestInfo{}, err
	}
	info := ManifestInfo{Digest: digest, MediaType: mediaType, Size: int64(len(body))}
	if !ValidDigest(ref) {
		if !ValidName(ref) {
			return ManifestInfo{}, ErrInvalidName
		}
		if err := writeFileAtomic(s.tagPath(owner, name, ref), []byte(digest), 0o644); err != nil {
			return ManifestInfo{}, err
		}
	}
	return info, nil
}

// GetManifest resolves ref (digest or tag) to the manifest body + metadata.
func (s *Store) GetManifest(owner, name, ref string) ([]byte, ManifestInfo, error) {
	if !ValidName(owner) || !ValidName(name) {
		return nil, ManifestInfo{}, ErrInvalidName
	}
	digest := ref
	if !ValidDigest(ref) {
		if !ValidName(ref) {
			return nil, ManifestInfo{}, ErrInvalidName
		}
		b, err := os.ReadFile(s.tagPath(owner, name, ref))
		if errors.Is(err, os.ErrNotExist) {
			return nil, ManifestInfo{}, ErrNotFound
		}
		if err != nil {
			return nil, ManifestInfo{}, err
		}
		digest = strings.TrimSpace(string(b))
		if !ValidDigest(digest) {
			return nil, ManifestInfo{}, ErrNotFound
		}
	}
	mp := s.manifestPath(owner, name, digest)
	body, err := os.ReadFile(mp)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ManifestInfo{}, ErrNotFound
	}
	if err != nil {
		return nil, ManifestInfo{}, err
	}
	mt, _ := os.ReadFile(mp + ".mediatype")
	return body, ManifestInfo{
		Digest:    digest,
		MediaType: strings.TrimSpace(string(mt)),
		Size:      int64(len(body)),
	}, nil
}

func (s *Store) DeleteManifest(owner, name, ref string) error {
	if ValidDigest(ref) {
		mp := s.manifestPath(owner, name, ref)
		if err := os.Remove(mp); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return ErrNotFound
			}
			return err
		}
		_ = os.Remove(mp + ".mediatype")
		return nil
	}
	return s.DeleteTag(owner, name, ref)
}

func (s *Store) DeleteTag(owner, name, tag string) error {
	err := os.Remove(s.tagPath(owner, name, tag))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

func (s *Store) ListTags(owner, name string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.repoDir(owner, name), "tags"))
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// -------- Repos --------

func (s *Store) ListRepos() ([]string, error) {
	root := filepath.Join(s.DataDir, "repos")
	owners, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, o := range owners {
		if !o.IsDir() {
			continue
		}
		names, err := os.ReadDir(filepath.Join(root, o.Name()))
		if err != nil {
			continue
		}
		for _, n := range names {
			if n.IsDir() {
				out = append(out, o.Name()+"/"+n.Name())
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) ListReposByOwner(owner string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.DataDir, "repos", owner))
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, owner+"/"+e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) DeleteRepo(owner, name string) error {
	return os.RemoveAll(s.repoDir(owner, name))
}

// -------- GC --------

// GC removes blobs not referenced by any manifest in any repo. Returns the
// list of deleted digests.
func (s *Store) GC() ([]string, error) {
	referenced := map[string]struct{}{}

	root := filepath.Join(s.DataDir, "repos")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".mediatype") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 4 {
			return nil
		}
		if parts[2] == "manifests" {
			digest := "sha256:" + parts[3]
			if ValidDigest(digest) {
				referenced[digest] = struct{}{}
				b, err := os.ReadFile(path)
				if err == nil {
					for _, d := range extractDigests(b) {
						referenced[d] = struct{}{}
					}
				}
			}
		}
		return nil
	})

	var deleted []string
	blobRoot := filepath.Join(s.DataDir, "blobs", "sha256")
	_ = filepath.WalkDir(blobRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		digest := "sha256:" + d.Name()
		if !ValidDigest(digest) {
			return nil
		}
		if _, ok := referenced[digest]; ok {
			return nil
		}
		if err := os.Remove(path); err == nil {
			deleted = append(deleted, digest)
		}
		return nil
	})
	return deleted, nil
}

// extractDigests scans a manifest body for "sha256:<64-hex>" occurrences. It's
// intentionally a string scan rather than a JSON parse so it works for any
// manifest schema (image, index, OCI artifact).
func extractDigests(body []byte) []string {
	s := string(body)
	var out []string
	for i := 0; i+71 <= len(s); i++ {
		if s[i:i+7] != "sha256:" {
			continue
		}
		hex := s[i+7 : i+71]
		valid := true
		for _, r := range hex {
			switch {
			case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			default:
				valid = false
			}
			if !valid {
				break
			}
		}
		if valid {
			out = append(out, "sha256:"+hex)
		}
	}
	return out
}

// -------- helpers --------

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
