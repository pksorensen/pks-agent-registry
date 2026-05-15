package cli

import "github.com/pksorensen/pks-agent-registry/internal/store"

// Admin is the surface the admin subcommands operate against. It is satisfied
// by both *store.Store (local, filesystem) and *remote.Client (HTTP). Defined
// here on the consumer side so adding a new backend doesn't ripple changes
// into the store or remote packages.
type Admin interface {
	// Owners
	PutOwner(name, password string) (*store.Owner, error)
	GetOwner(name string) (*store.Owner, error)
	ListOwners() ([]string, error)
	DeleteOwner(name string) error

	// Repos
	ListRepos() ([]string, error)
	ListReposByOwner(owner string) ([]string, error)
	DeleteRepo(owner, name string) error

	// Tags
	ListTags(owner, name string) ([]string, error)
	DeleteTag(owner, name, tag string) error

	// Maintenance
	GC() ([]string, error)
}
