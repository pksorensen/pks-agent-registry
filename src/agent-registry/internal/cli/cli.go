package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

// Run dispatches the given args ([]string after the program name). Returns an
// exit code.
func Run(adm Admin, args []string) int {
	if len(args) == 0 {
		printHelp()
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		printHelp()
		return 0
	case "owner":
		return runOwner(adm, args[1:])
	case "repo":
		return runRepo(adm, args[1:])
	case "tag":
		return runTag(adm, args[1:])
	case "gc":
		return runGC(adm)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", args[0])
		printHelp()
		return 2
	}
}

func printHelp() {
	fmt.Println(`agent-registry — OCI registry + admin CLI

Usage:
  agent-registry serve                                Run the registry server (default)
  agent-registry owner add <name> [--no-push] [--pull <scope>]...
                                                      Create an owner (password from REGISTRY_PASSWORD or stdin).
                                                      With no flags the owner gets full access; --no-push makes it
                                                      pull-only; --pull adds a cross-namespace pull scope glob
                                                      (e.g. agentics/pks-agent-marketplace, agentics/*, */*).
  agent-registry owner perms <name> [--push] [--pull <scope>]... | --full
                                                      Replace an owner's permissions. --full restores full access.
  agent-registry owner list                           List owners
  agent-registry owner password <name>                Reset an owner's password
  agent-registry owner delete <name>                  Delete an owner
  agent-registry repo list [<owner>]                  List all repos, or those under an owner
  agent-registry repo delete <owner>/<name>           Delete a repo (all manifests + tags)
  agent-registry tag list <owner>/<name>              List tags
  agent-registry tag delete <owner>/<name>:<tag>      Delete a tag
  agent-registry gc                                   Remove blobs not referenced by any manifest
  agent-registry help                                 Show this help

Environment:
  USER_DATA_DIR           Persistent storage path (default /data)
  REGISTRY_ADDR           Listen address for serve (default :5000)
  REGISTRY_ADMIN_TOKEN    Bearer token for /_mgmt/ API (mgmt API disabled if unset)
  REGISTRY_PASSWORD       Used as the password when stdin is not a TTY`)
}

func runOwner(adm Admin, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "owner: missing subcommand")
		return 2
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "owner add <name> [--no-push] [--pull <scope>]...")
			return 2
		}
		name := args[1]
		perms, hasPerms, err := parsePermFlags(args[2:], false)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		pw, err := readPassword("Password")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		// No perm flags → nil perms (legacy full access). Flags → restricted owner.
		var p *store.Permissions
		if hasPerms {
			p = perms
		}
		o, err := adm.CreateOwner(name, pw, p)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("created owner %q at %s%s\n", o.Name, o.CreatedAt.Format("2006-01-02T15:04:05Z"), permSummary(o.Permissions))
		return 0
	case "perms":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "owner perms <name> [--push] [--pull <scope>]... | --full")
			return 2
		}
		name := args[1]
		rest := args[2:]
		if len(rest) == 1 && rest[0] == "--full" {
			if err := adm.SetPermissions(name, nil); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fmt.Printf("owner %q set to full access\n", name)
			return 0
		}
		perms, _, err := parsePermFlags(rest, true)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err := adm.SetPermissions(name, perms); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("updated permissions for owner %q%s\n", name, permSummary(perms))
		return 0
	case "list":
		names, err := adm.ListOwners()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return 0
	case "password":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "owner password <name>")
			return 2
		}
		if _, err := adm.GetOwner(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		pw, err := readPassword("New password")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if _, err := adm.PutOwner(args[1], pw); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("password updated for owner %q\n", args[1])
		return 0
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "owner delete <name>")
			return 2
		}
		if err := adm.DeleteOwner(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("deleted owner %q\n", args[1])
		return 0
	default:
		fmt.Fprintf(os.Stderr, "owner: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runRepo(adm Admin, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "repo: missing subcommand")
		return 2
	}
	switch args[0] {
	case "list":
		var (
			repos []string
			err   error
		)
		if len(args) >= 2 {
			repos, err = adm.ListReposByOwner(args[1])
		} else {
			repos, err = adm.ListRepos()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, r := range repos {
			fmt.Println(r)
		}
		return 0
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "repo delete <owner>/<name>")
			return 2
		}
		owner, name, err := store.ParseRepo(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err := adm.DeleteRepo(owner, name); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("deleted repo %s/%s\n", owner, name)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "repo: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runTag(adm Admin, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "tag: missing subcommand")
		return 2
	}
	switch args[0] {
	case "list":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "tag list <owner>/<name>")
			return 2
		}
		owner, name, err := store.ParseRepo(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		tags, err := adm.ListTags(owner, name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, t := range tags {
			fmt.Println(t)
		}
		return 0
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "tag delete <owner>/<name>:<tag>")
			return 2
		}
		repo, tag, ok := splitRepoTag(args[1])
		if !ok {
			fmt.Fprintln(os.Stderr, "expected <owner>/<name>:<tag>")
			return 2
		}
		owner, name, err := store.ParseRepo(repo)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err := adm.DeleteTag(owner, name, tag); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("deleted tag %s/%s:%s\n", owner, name, tag)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "tag: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runGC(adm Admin) int {
	deleted, err := adm.GC()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, d := range deleted {
		fmt.Println(d)
	}
	fmt.Fprintf(os.Stderr, "removed %d unreferenced blob(s)\n", len(deleted))
	return 0
}

// parsePermFlags parses [--push] [--no-push] [--pull <scope>]... into a
// Permissions. defaultPush sets the Push value when neither flag is given.
// hasPerms reports whether any flag was present (so callers can distinguish
// "no flags" from "explicit empty scopes").
func parsePermFlags(args []string, defaultPush bool) (perms *store.Permissions, hasPerms bool, err error) {
	push := defaultPush
	var scopes []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--push":
			push, hasPerms = true, true
		case "--no-push":
			push, hasPerms = false, true
		case "--pull":
			if i+1 >= len(args) {
				return nil, false, fmt.Errorf("--pull requires a scope (e.g. agentics/pks-agent-marketplace)")
			}
			scopes = append(scopes, args[i+1])
			hasPerms = true
			i++
		default:
			return nil, false, fmt.Errorf("unknown flag %q", args[i])
		}
	}
	return &store.Permissions{Push: push, PullScopes: scopes}, hasPerms, nil
}

func permSummary(p *store.Permissions) string {
	if p == nil {
		return " (full access)"
	}
	push := "pull-only"
	if p.Push {
		push = "push+pull"
	}
	if len(p.PullScopes) == 0 {
		return fmt.Sprintf(" (%s, own namespace only)", push)
	}
	return fmt.Sprintf(" (%s, scopes: %s)", push, strings.Join(p.PullScopes, ", "))
}

func splitRepoTag(s string) (repo, tag string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// readPassword reads a password from REGISTRY_PASSWORD env or, failing that,
// the first line of stdin. Kept simple on purpose — admin CLI runs via
// `docker exec` where echo is acceptable.
func readPassword(prompt string) (string, error) {
	if v := os.Getenv("REGISTRY_PASSWORD"); v != "" {
		return v, nil
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return "", fmt.Errorf("password is empty")
	}
	return pw, nil
}
