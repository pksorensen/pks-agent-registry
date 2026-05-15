package main

import (
	"log"
	"os"

	"github.com/pksorensen/pks-agent-registry/internal/cli"
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
	dataDir := getEnv("USER_DATA_DIR", "/data")
	st, err := store.New(dataDir)
	if err != nil {
		log.Fatalf("store.New: %v", err)
	}

	args := os.Args[1:]
	if len(args) > 0 && args[0] != "serve" {
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
