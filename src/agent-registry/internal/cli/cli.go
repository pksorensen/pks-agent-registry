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
func Run(st *store.Store, args []string) int {
	if len(args) == 0 {
		printHelp()
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		printHelp()
		return 0
	case "owner":
		return runOwner(st, args[1:])
	case "repo":
		return runRepo(st, args[1:])
	case "tag":
		return runTag(st, args[1:])
	case "gc":
		return runGC(st)
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
  agent-registry owner add <name>                     Create an owner (password from REGISTRY_PASSWORD or stdin)
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

func runOwner(st *store.Store, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "owner: missing subcommand")
		return 2
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "owner add <name>")
			return 2
		}
		pw, err := readPassword("Password")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		o, err := st.PutOwner(args[1], pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("created owner %q at %s\n", o.Name, o.CreatedAt.Format("2006-01-02T15:04:05Z"))
		return 0
	case "list":
		names, err := st.ListOwners()
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
		if _, err := st.GetOwner(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		pw, err := readPassword("New password")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if _, err := st.PutOwner(args[1], pw); err != nil {
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
		if err := st.DeleteOwner(args[1]); err != nil {
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

func runRepo(st *store.Store, args []string) int {
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
			repos, err = st.ListReposByOwner(args[1])
		} else {
			repos, err = st.ListRepos()
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
		if err := st.DeleteRepo(owner, name); err != nil {
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

func runTag(st *store.Store, args []string) int {
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
		tags, err := st.ListTags(owner, name)
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
		if err := st.DeleteTag(owner, name, tag); err != nil {
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

func runGC(st *store.Store) int {
	deleted, err := st.GC()
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
