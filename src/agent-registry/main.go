package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/pksorensen/pks-agent-registry/internal/cli"
	"github.com/pksorensen/pks-agent-registry/internal/ghoidc"
	"github.com/pksorensen/pks-agent-registry/internal/kcoidc"
	"github.com/pksorensen/pks-agent-registry/internal/remote"
	"github.com/pksorensen/pks-agent-registry/internal/server"
	"github.com/pksorensen/pks-agent-registry/internal/store"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// resolvePublicURL returns the registry's externally reachable base URL:
// REGISTRY_PUBLIC_URL, else the Coolify-injected COOLIFY_URL / COOLIFY_FQDN
// (both may be comma-separated when multiple domains are attached; FQDN may
// lack a scheme). Empty means the token service stays disarmed.
func resolvePublicURL() string {
	for _, key := range []string{"REGISTRY_PUBLIC_URL", "COOLIFY_URL", "COOLIFY_FQDN"} {
		v := strings.TrimSpace(strings.Split(os.Getenv(key), ",")[0])
		if v == "" {
			continue
		}
		if !strings.Contains(v, "://") {
			v = "https://" + v
		}
		return strings.TrimRight(v, "/")
	}
	return ""
}

// Defaults for the interactive sign-in the CLI performs. The client is a
// public OAuth client, so none of these is a secret. offline_access is what
// keeps the Docker credential helper working past Keycloak's SSO idle
// timeout — without it the helper stops refreshing after ~30 minutes.
//
// One client per tool, not one shared across the family: `agent-registry-cli`
// talks to this registry and nothing else, which is what lets the audience
// mapper sit on the client itself rather than on a scope the CLI has to
// remember to request. It also means this tool's sessions can be revoked
// without signing the user out of every other one, and `azp` in the registry's
// logs names the actual software that pulled.
const (
	defaultKeycloakIssuer   = "https://login.agentics.dk/realms/agentics"
	defaultKeycloakClientID = "agent-registry-cli"
	defaultKeycloakScopes   = "openid offline_access"
)

// version is stamped at build time via -ldflags "-X main.version=<semver>".
// Defaults to "dev" for a plain `go build`/`go run` without the flag.
var version = "dev"

func main() {
	args := os.Args[1:]

	// Version probe — handled before any store/server setup so it works without
	// a data dir or remote config.
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-v":
			fmt.Println("agent-registry", version)
			return
		}
	}

	// Interactive sign-in and the docker credential helper come first. They run
	// on a developer's machine, where there is no data directory to open and no
	// admin token to demand — and where argv[0] may be the
	// docker-credential-agentics symlink rather than a subcommand at all.
	if code, handled := cli.RunAuth(args); handled {
		os.Exit(code)
	}

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

	// REGISTRY_TRUSTED_PROXY_CIDRS — comma-separated list of CIDRs whose TCP source
	// is allowed anonymous GET/HEAD on /v2/*. Intended for proxy-fronted deployments
	// where the proxy itself enforces the auth boundary. Empty disables the bypass.
	var trustedCIDRs []*net.IPNet
	if raw := os.Getenv("REGISTRY_TRUSTED_PROXY_CIDRS"); raw != "" {
		for _, c := range strings.Split(raw, ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				log.Fatalf("REGISTRY_TRUSTED_PROXY_CIDRS: invalid CIDR %q: %v", c, err)
			}
			trustedCIDRs = append(trustedCIDRs, n)
		}
	}

	cfg := server.Config{
		Addr:              addr,
		AdminToken:        adminToken,
		Store:             st,
		TrustedProxyCIDRs: trustedCIDRs,
	}

	// REGISTRY_PUBLIC_URL arms the Distribution token service + GitHub OIDC
	// federation (ADR 0003). Its hostname becomes the token "service" and the
	// required OIDC audience. Falls back to the Coolify-injected app URL
	// (COOLIFY_URL, then COOLIFY_FQDN) so proxied deployments get token auth
	// without extra configuration. Unset everywhere keeps Basic-only auth.
	if publicURL := resolvePublicURL(); publicURL != "" {
		key, kid, err := token.LoadOrCreateSigningKey(dataDir)
		if err != nil {
			log.Fatalf("token signing key: %v", err)
		}
		audience := publicURL
		if u, err := url.Parse(publicURL); err == nil && u.Host != "" {
			audience = u.Host
		}
		cfg.PublicURL = publicURL
		cfg.TokenKey = key
		cfg.TokenKid = kid
		cfg.OIDC = ghoidc.New(getEnv("REGISTRY_GH_OIDC_ISSUER", ghoidc.DefaultIssuer), audience)

		// Interactive human sign-in (ADR 0004): `agent-registry login` mints a
		// Keycloak token, and the registry accepts it as a second credential
		// type at /token. REGISTRY_KEYCLOAK_ISSUER overrides the issuer for
		// anyone running this registry against their own authorization server;
		// it defaults to ours rather than leaving sign-in disarmed, because a
		// deployment that inherits the default still grants nothing to anyone
		// without a trust binding. Set it to "off" to disarm deliberately.
		issuer := strings.TrimRight(getEnv("REGISTRY_KEYCLOAK_ISSUER", defaultKeycloakIssuer), "/")
		if issuer != "" && !strings.EqualFold(issuer, "off") {
			kcAudience := getEnv("REGISTRY_KEYCLOAK_AUDIENCE", audience)
			kc := kcoidc.New(issuer, kcAudience)

			// REGISTRY_KEYCLOAK_ACCEPT_AZP relaxes the audience check to an azp
			// match, for a realm nobody has added an audience mapper to. Off
			// unless set: see kcoidc.AcceptAuthorizedParty for why it must not
			// be the default.
			acceptAZP := strings.TrimSpace(os.Getenv("REGISTRY_KEYCLOAK_ACCEPT_AZP"))
			kc.AcceptAuthorizedParty(acceptAZP)
			if acceptAZP != "" {
				log.Printf("keycloak: audience check RELAXED — tokens with azp=%q are accepted without aud=%q", acceptAZP, kcAudience)
			}

			cfg.Keycloak = kc
			cfg.Login = server.LoginDiscovery{
				Issuer:   issuer,
				ClientID: getEnv("REGISTRY_KEYCLOAK_CLIENT_ID", defaultKeycloakClientID),
				Audience: kcAudience,
				Scopes:   strings.Fields(getEnv("REGISTRY_KEYCLOAK_SCOPES", defaultKeycloakScopes)),
				Registry: audience,
			}
		}
	}

	srv := server.New(cfg)

	log.Printf("agent-registry listening on %s (data=%s, admin-api=%t, trusted-proxy-cidrs=%d, token-auth=%t, keycloak-login=%t)", addr, dataDir, adminToken != "", len(trustedCIDRs), cfg.PublicURL != "", cfg.Keycloak != nil)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
