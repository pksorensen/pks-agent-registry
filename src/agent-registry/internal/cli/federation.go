package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/pksorensen/pks-agent-registry/internal/ghoidc"
	"github.com/pksorensen/pks-agent-registry/internal/store"
)

func runFederation(adm Admin, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "federation: missing subcommand (add|list|remove)")
		return 2
	}
	switch args[0] {
	case "add":
		return runFederationAdd(adm, args[1:])
	case "list":
		return runFederationList(adm)
	case "remove", "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "federation remove <id>")
			return 2
		}
		if err := adm.DeleteTrustBinding(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("removed trust binding %s\n", args[1])
		return 0
	default:
		fmt.Fprintf(os.Stderr, "federation: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runFederationAdd(adm Admin, args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "--") {
		fmt.Fprintln(os.Stderr, "federation add <github-org/repo> [--environment <env>] [--pull <scope>]... [--push --owner <registry-owner>] [--repository-id <id>] [--description <text>]")
		return 2
	}
	b := &store.TrustBinding{
		Issuer:      ghoidc.DefaultIssuer,
		Repository:  args[0],
		Permissions: &store.Permissions{},
	}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		flagValue := func() (string, bool) {
			if i+1 >= len(rest) {
				fmt.Fprintf(os.Stderr, "%s requires a value\n", rest[i])
				return "", false
			}
			i++
			return rest[i], true
		}
		switch rest[i] {
		case "--environment":
			v, ok := flagValue()
			if !ok {
				return 2
			}
			b.Environment = v
		case "--pull":
			v, ok := flagValue()
			if !ok {
				return 2
			}
			b.Permissions.PullScopes = append(b.Permissions.PullScopes, v)
		case "--push":
			b.Permissions.Push = true
		case "--owner":
			v, ok := flagValue()
			if !ok {
				return 2
			}
			b.Owner = v
		case "--repository-id":
			v, ok := flagValue()
			if !ok {
				return 2
			}
			b.RepositoryID = v
		case "--description":
			v, ok := flagValue()
			if !ok {
				return 2
			}
			b.Description = v
		default:
			fmt.Fprintf(os.Stderr, "federation add: unknown flag %q\n", rest[i])
			return 2
		}
	}
	if b.Permissions.Push && b.Owner == "" {
		fmt.Fprintln(os.Stderr, "--push requires --owner <registry-owner> (the namespace the identity may push to)")
		return 2
	}
	created, err := adm.CreateTrustBinding(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("created trust binding %s: %s\n", created.ID, bindingSummary(created))
	if !created.Pinned() {
		fmt.Println("note: repository ID not pinned yet — it will be pinned on the first successful workflow login (TOFU)")
	}
	return 0
}

func runFederationList(adm Admin) int {
	bindings, err := adm.ListTrustBindings()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, b := range bindings {
		fmt.Printf("%s  %s\n", b.ID, bindingSummary(b))
	}
	return 0
}

func bindingSummary(b *store.TrustBinding) string {
	repo := b.Repository
	if b.Environment != "" {
		repo += "@" + b.Environment
	}
	pinned := "pinned=no"
	if b.Pinned() {
		pinned = "pinned=yes"
	}
	s := repo + "  " + pinned + permSummary(b.Permissions)
	if b.Owner != "" {
		s += " owner=" + b.Owner
	}
	if b.Description != "" {
		s += "  # " + b.Description
	}
	return s
}
