package remote

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

// Client implements cli.Admin against a remote /_mgmt/ HTTP API.
type Client struct {
	BaseURL    string
	AdminToken string
	HTTP       *http.Client
}

func New(baseURL, adminToken string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		AdminToken: adminToken,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) do(method, path string, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AdminToken)
	}
	return c.HTTP.Do(req)
}

// expect reads a response and decodes it into v if status is in `ok`. Returns
// store.ErrNotFound on 404 so callers can use errors.Is for the existence
// check that the local Store also uses.
func (c *Client) expect(resp *http.Response, v any, ok ...int) error {
	defer resp.Body.Close()
	for _, code := range ok {
		if resp.StatusCode == code {
			if v == nil || resp.ContentLength == 0 {
				return nil
			}
			return json.NewDecoder(resp.Body).Decode(v)
		}
	}
	if resp.StatusCode == http.StatusNotFound {
		return store.ErrNotFound
	}
	b, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("remote: %s — %s", resp.Status, strings.TrimSpace(string(b)))
}

// -------- Owners --------

type ownerView struct {
	Name        string             `json:"name"`
	CreatedAt   string             `json:"createdAt"`
	Permissions *store.Permissions `json:"permissions,omitempty"`
}

type ownersListResp struct {
	Owners []ownerView `json:"owners"`
}

func (v ownerView) toOwner() *store.Owner {
	t, _ := time.Parse("2006-01-02T15:04:05Z", v.CreatedAt)
	return &store.Owner{Name: v.Name, CreatedAt: t, Permissions: v.Permissions}
}

func (c *Client) PutOwner(name, password string) (*store.Owner, error) {
	// PutOwner is upsert in the local store. The mgmt API splits it into
	// "create" (POST /_mgmt/owners) and "rotate password" (PUT
	// /_mgmt/owners/{name}/password) — try create first, fall back to
	// password rotation if the owner already exists.
	resp, err := c.do(http.MethodPost, "/_mgmt/owners", map[string]string{
		"name":     name,
		"password": password,
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusCreated {
		var v ownerView
		if err := c.expect(resp, &v, http.StatusCreated); err != nil {
			return nil, err
		}
		return v.toOwner(), nil
	}
	// Treat anything other than 201 as "try rotate". Server returns 500 with
	// "already exists"-style error today; rotating + GET gives us the right
	// shape regardless.
	resp.Body.Close()

	pwResp, err := c.do(http.MethodPut, "/_mgmt/owners/"+url.PathEscape(name)+"/password",
		map[string]string{"password": password})
	if err != nil {
		return nil, err
	}
	if err := c.expect(pwResp, nil, http.StatusNoContent); err != nil {
		return nil, err
	}
	return c.GetOwner(name)
}

func (c *Client) CreateOwner(name, password string, perms *store.Permissions) (*store.Owner, error) {
	body := map[string]any{"name": name, "password": password}
	if perms != nil {
		body["push"] = perms.Push
		body["pullScopes"] = perms.PullScopes
	}
	resp, err := c.do(http.MethodPost, "/_mgmt/owners", body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusConflict {
		resp.Body.Close()
		return nil, store.ErrExists
	}
	var v ownerView
	if err := c.expect(resp, &v, http.StatusCreated); err != nil {
		return nil, err
	}
	return v.toOwner(), nil
}

func (c *Client) SetPermissions(name string, perms *store.Permissions) error {
	if perms == nil {
		perms = &store.Permissions{}
	}
	resp, err := c.do(http.MethodPut, "/_mgmt/owners/"+url.PathEscape(name)+"/permissions",
		map[string]any{"push": perms.Push, "pullScopes": perms.PullScopes})
	if err != nil {
		return err
	}
	return c.expect(resp, nil, http.StatusNoContent)
}

func (c *Client) GetOwner(name string) (*store.Owner, error) {
	resp, err := c.do(http.MethodGet, "/_mgmt/owners/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	var v ownerView
	if err := c.expect(resp, &v, http.StatusOK); err != nil {
		return nil, err
	}
	return v.toOwner(), nil
}

func (c *Client) ListOwners() ([]string, error) {
	resp, err := c.do(http.MethodGet, "/_mgmt/owners", nil)
	if err != nil {
		return nil, err
	}
	var body ownersListResp
	if err := c.expect(resp, &body, http.StatusOK); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(body.Owners))
	for _, o := range body.Owners {
		out = append(out, o.Name)
	}
	return out, nil
}

func (c *Client) DeleteOwner(name string) error {
	resp, err := c.do(http.MethodDelete, "/_mgmt/owners/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	return c.expect(resp, nil, http.StatusNoContent)
}

// -------- Repos --------

type reposListResp struct {
	Repositories []string `json:"repositories"`
}

func (c *Client) ListRepos() ([]string, error) {
	resp, err := c.do(http.MethodGet, "/_mgmt/repos", nil)
	if err != nil {
		return nil, err
	}
	var body reposListResp
	if err := c.expect(resp, &body, http.StatusOK); err != nil {
		return nil, err
	}
	return body.Repositories, nil
}

func (c *Client) ListReposByOwner(owner string) ([]string, error) {
	resp, err := c.do(http.MethodGet, "/_mgmt/repos?owner="+url.QueryEscape(owner), nil)
	if err != nil {
		return nil, err
	}
	var body reposListResp
	if err := c.expect(resp, &body, http.StatusOK); err != nil {
		return nil, err
	}
	return body.Repositories, nil
}

func (c *Client) DeleteRepo(owner, name string) error {
	resp, err := c.do(http.MethodDelete, "/_mgmt/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	return c.expect(resp, nil, http.StatusNoContent)
}

// -------- Tags --------

type tagsListResp struct {
	Repository string   `json:"repository"`
	Tags       []string `json:"tags"`
}

func (c *Client) ListTags(owner, name string) ([]string, error) {
	resp, err := c.do(http.MethodGet, "/_mgmt/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/tags", nil)
	if err != nil {
		return nil, err
	}
	var body tagsListResp
	if err := c.expect(resp, &body, http.StatusOK); err != nil {
		return nil, err
	}
	if body.Tags == nil {
		return []string{}, nil
	}
	return body.Tags, nil
}

func (c *Client) DeleteTag(owner, name, tag string) error {
	resp, err := c.do(http.MethodDelete,
		"/_mgmt/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/tags/"+url.PathEscape(tag), nil)
	if err != nil {
		return err
	}
	return c.expect(resp, nil, http.StatusNoContent)
}

// -------- Federated trust bindings (ADR 0003) --------

type bindingsListResp struct {
	Bindings []*store.TrustBinding `json:"bindings"`
}

func (c *Client) CreateTrustBinding(b *store.TrustBinding) (*store.TrustBinding, error) {
	perms := b.Permissions
	if perms == nil {
		perms = &store.Permissions{}
	}
	resp, err := c.do(http.MethodPost, "/_mgmt/federation", map[string]any{
		"description":       b.Description,
		"repository":        b.Repository,
		"repositoryId":      b.RepositoryID,
		"repositoryOwnerId": b.RepositoryOwnerID,
		"environment":       b.Environment,
		"owner":             b.Owner,
		"push":              perms.Push,
		"pullScopes":        perms.PullScopes,
		"createdBy":         b.CreatedBy,
	})
	if err != nil {
		return nil, err
	}
	var created store.TrustBinding
	if err := c.expect(resp, &created, http.StatusCreated); err != nil {
		return nil, err
	}
	return &created, nil
}

func (c *Client) ListTrustBindings() ([]*store.TrustBinding, error) {
	resp, err := c.do(http.MethodGet, "/_mgmt/federation", nil)
	if err != nil {
		return nil, err
	}
	var body bindingsListResp
	if err := c.expect(resp, &body, http.StatusOK); err != nil {
		return nil, err
	}
	return body.Bindings, nil
}

func (c *Client) DeleteTrustBinding(id string) error {
	resp, err := c.do(http.MethodDelete, "/_mgmt/federation/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	return c.expect(resp, nil, http.StatusNoContent)
}

// -------- GC --------

type gcResp struct {
	Deleted []string `json:"deleted"`
	Count   int      `json:"count"`
}

func (c *Client) GC() ([]string, error) {
	resp, err := c.do(http.MethodPost, "/_mgmt/gc", nil)
	if err != nil {
		return nil, err
	}
	var body gcResp
	if err := c.expect(resp, &body, http.StatusOK); err != nil {
		return nil, err
	}
	return body.Deleted, nil
}

// Compile-time assertion that *Client satisfies the cli.Admin contract. We
// can't import cli (would be a cycle), so we restate the interface here. If
// you add a method to cli.Admin, mirror it here so the build fails fast.
var _ interface {
	PutOwner(name, password string) (*store.Owner, error)
	CreateOwner(name, password string, perms *store.Permissions) (*store.Owner, error)
	SetPermissions(name string, perms *store.Permissions) error
	GetOwner(name string) (*store.Owner, error)
	ListOwners() ([]string, error)
	DeleteOwner(name string) error
	ListRepos() ([]string, error)
	ListReposByOwner(owner string) ([]string, error)
	DeleteRepo(owner, name string) error
	ListTags(owner, name string) ([]string, error)
	DeleteTag(owner, name, tag string) error
	CreateTrustBinding(b *store.TrustBinding) (*store.TrustBinding, error)
	ListTrustBindings() ([]*store.TrustBinding, error)
	DeleteTrustBinding(id string) error
	GC() ([]string, error)
} = (*Client)(nil)
