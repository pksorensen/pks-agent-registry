package main

import (
	"fmt"
	"log"
	"os"

	"github.com/pksorensen/pks-agent-registry/internal/cli"
	"github.com/pksorensen/pks-agent-registry/internal/remote"
	"github.com/pksorensen/pks-agent-registry/internal/server"
	"github.com/pksorensen/pks-agent-registry/internal/store"
)

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	args := os.Args[1:]
	wantsServer := len(args) == 0 || args[0] == "serve"

	// Remote admin mode: REGISTRY_REMOTE set + a non-serve subcommand. The
	// CLI talks to a remote /_mgmt/ API instead of the local filesystem.
	if remoteURL := os.Getenv("REGISTRY_REMOTE"); remoteURL != "" && !wantsServer {
		token := os.Getenv("REGISTRY_ADMIN_TOKEN")
		if token == "" {
			fmt.Fprintln(os.Stderr, "REGISTRY_REMOTE is set but REGISTRY_ADMIN_TOKEN is not — the management API requires a bearer token")
			os.Exit(2)
		}
		os.Exit(cli.Run(remote.New(remoteURL, token), args))
	}

	dataDir := getEnv("USER_DATA_DIR", "/data")
	st, err := store.New(dataDir)
	if err != nil {
		log.Fatalf("store.New: %v", err)
	}

	if !wantsServer {
		os.Exit(cli.Run(st, args))
	}

	addr := getEnv("REGISTRY_ADDR", ":5000")
	adminToken := os.Getenv("REGISTRY_ADMIN_TOKEN")

	srv := server.New(server.Config{
		Addr:       addr,
		AdminToken: adminToken,
		Store:      st,
	})

	log.Printf("agent-registry listening on %s (data=%s, admin-api=%t)", addr, dataDir, adminToken != "")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
