package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/dockercfg"
	"github.com/pksorensen/pks-agent-registry/internal/login"
)

// RunAuth handles the subcommands that sign a *person* in and hand the result
// to docker. They are dispatched before anything else in main, because none of
// them wants a data directory or an admin token: `agent-registry login` on a
// laptop must not create /data, and must not demand REGISTRY_ADMIN_TOKEN just
// because REGISTRY_REMOTE happens to be exported.
//
// handled is false when args are not an auth subcommand, so the caller can
// carry on to the admin CLI.
func RunAuth(args []string) (code int, handled bool) {
	// Invoked through the docker-credential-agentics symlink: everything after
	// the program name is the credential-helper protocol.
	if isCredentialHelperName(os.Args[0]) {
		return runCredentialHelper(args), true
	}
	if len(args) == 0 {
		return 0, false
	}
	// `<verb> --help` is what a person tries first, and answering it with
	// "unknown flag" is a dead end. Handled centrally so every verb gets it.
	if len(args) > 1 && wantsHelp(args[1:]) {
		if usage, ok := authUsage[args[0]]; ok {
			fmt.Print(usage)
			return 0, true
		}
	}
	switch args[0] {
	case "login":
		return runLogin(args[1:]), true
	case "logout":
		return runLogout(args[1:]), true
	case "whoami":
		return runWhoami(args[1:]), true
	case "token":
		return runPrintToken(args[1:]), true
	case "docker-credential":
		return runCredentialHelper(args[1:]), true
	case "credential-helper":
		return runCredentialHelperAdmin(args[1:]), true
	default:
		return 0, false
	}
}

func isCredentialHelperName(argv0 string) bool {
	base := filepath.Base(argv0)
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")
	return base == dockercfg.BinaryName
}

// --- login ---

func runLogin(args []string) int {
	registry := ""
	installHelper := ""
	helperDir := ""
	mode := login.ModeAuto
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--device":
			mode = login.ModeDevice
		case "--browser":
			mode = login.ModeBrowser
		case "--helper":
			installHelper = "yes"
		case "--no-helper":
			installHelper = "no"
		case "--helper-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--helper-dir requires a directory")
				return 2
			}
			i++
			helperDir = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "login: unknown flag %q\n", args[i])
				return 2
			}
			registry = args[i]
		}
	}
	registry = login.NormalizeRegistry(registry)
	client := &http.Client{Timeout: 30 * time.Second}

	disco, err := login.FetchDiscovery(client, registry)
	if errors.Is(err, login.ErrNotConfigured) {
		fmt.Fprintf(os.Stderr, "%s does not offer interactive sign-in.\n", registry)
		fmt.Fprintf(os.Stderr, "Sign in with an owner account instead:\n  docker login %s -u <owner>\n", registry)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not reach %s: %v\n", registry, err)
		return 1
	}

	fmt.Printf("Sign in to %s\n", registry)

	// Ctrl-C during the wait should stop the sign-in, not kill the shell's idea
	// of what happened: cancelling is a normal way to abandon a sign-in.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui := login.UI{
		ShowURL: func(u, userCode string) {
			fmt.Printf("\n  %s\n\n", u)
			if userCode != "" {
				fmt.Printf("  Code: %s\n\n", userCode)
			}
			fmt.Println("Waiting for approval… (Ctrl-C to stop)")
		},
		Notice: func(msg string) { fmt.Printf("\n%s\n", msg) },
	}

	cred, err := login.SignIn(ctx, client, disco, mode, ui)
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "\nsign-in cancelled")
		return 1
	}
	if errors.Is(err, login.ErrCallbackTimeout) {
		fmt.Fprintln(os.Stderr, "\nThe browser never reached this machine.")
		fmt.Fprintf(os.Stderr, "Sign in with a code instead:\n  agent-registry login %s --device\n", registry)
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := login.Put(cred); err != nil {
		fmt.Fprintf(os.Stderr, "signed in, but the credential could not be saved: %v\n", err)
		return 1
	}
	path, _ := login.Path()
	fmt.Printf("\nSigned in as %s. Credential saved to %s\n", displayName(cred), path)

	// A successful sign-in is not the same as a usable one. The audience is
	// stamped by a mapper on the realm client, so a realm that was never
	// reconciled hands back a perfectly valid token that this registry will
	// refuse. Left unsaid, that resurfaces much later as a bare 401 from
	// `docker pull` with nothing pointing at the realm.
	if !cred.HasRegistryAudience() {
		fmt.Fprintf(os.Stderr, "\nWarning: this token will be refused by %s.\n", registry)
		fmt.Fprintf(os.Stderr, "It carries audience %v, but %s requires %q.\n\n%s\n",
			cred.Audiences, registry, cred.Audience, login.AudienceSetupHint(disco))
	}

	// Signing in is only half the job: docker still has to be told to ask us.
	if installHelper == "no" {
		printHelperInstructions(registry)
		return 0
	}
	if installHelper == "" {
		if !isTTY(os.Stdin) {
			printHelperInstructions(registry)
			return 0
		}
		if !confirm(fmt.Sprintf("\nLet docker use this sign-in for %s (installs a credential helper)?", registry)) {
			printHelperInstructions(registry)
			return 0
		}
	}
	if code := installCredentialHelper(registry, helperDir); code != 0 {
		return code
	}
	fmt.Printf("\nTry it:\n  docker pull %s/agentics/pks-agent-doorman:latest\n", registry)
	return 0
}

func displayName(c *login.Credential) string {
	if c.Username != "" {
		return c.Username
	}
	if c.Subject != "" {
		return c.Subject
	}
	return "an unnamed subject"
}

func printHelperInstructions(registry string) {
	fmt.Printf(`
Docker does not know about this sign-in yet. To let it use the credential:

  agent-registry credential-helper install %s

Or, for a one-off login that lasts until the token expires:

  docker login %s -u %s -p "$(agent-registry token %s)"
`, registry, registry, login.HelperUsername, registry)
}

// --- logout / whoami / token ---

func runLogout(args []string) int {
	registry := login.NormalizeRegistry(firstArg(args))
	client := &http.Client{Timeout: 15 * time.Second}

	if cred, err := login.Get(registry); err == nil {
		if err := login.Logout(client, cred); err != nil {
			// The local credential still goes; a session left behind at the
			// issuer is a smaller problem than a token left on disk.
			fmt.Fprintf(os.Stderr, "warning: could not end the session at %s: %v\n", cred.Issuer, err)
		}
	}
	removed, err := login.Forget(registry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !removed {
		fmt.Printf("no stored credential for %s\n", registry)
		return 0
	}
	fmt.Printf("signed out of %s\n", registry)
	return 0
}

func runWhoami(args []string) int {
	if len(args) > 0 {
		return whoamiOne(login.NormalizeRegistry(args[0]))
	}
	creds, err := login.List()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(creds) == 0 {
		fmt.Println("not signed in to any registry")
		return 1
	}
	for _, c := range creds {
		whoamiOne(c.Registry)
	}
	return 0
}

func whoamiOne(registry string) int {
	c, err := login.Get(registry)
	if errors.Is(err, login.ErrNotSignedIn) {
		fmt.Printf("%s: not signed in\n", registry)
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	state := "token valid"
	if !c.Fresh(time.Now()) {
		state = "token expired (refreshes on next use)"
	}
	helper, _ := dockercfg.HelperFor(registry)
	docker := "docker: not wired up"
	if helper == dockercfg.HelperName {
		docker = "docker: uses this sign-in"
	} else if helper != "" {
		docker = "docker: uses helper " + helper
	}
	fmt.Printf("%s: %s (%s)\n", registry, displayName(c), c.Issuer)
	fmt.Printf("  %s\n", state)
	fmt.Printf("  %s\n", docker)
	return 0
}

func runPrintToken(args []string) int {
	registry := login.NormalizeRegistry(firstArg(args))
	c, err := login.AccessToken(&http.Client{Timeout: 30 * time.Second}, registry)
	if errors.Is(err, login.ErrNotSignedIn) {
		fmt.Fprintf(os.Stderr, "not signed in to %s — run `agent-registry login %s`\n", registry, registry)
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(c.AccessToken)
	return 0
}

// --- credential helper protocol ---

// Docker matches these strings, so they are load-bearing text, not messages.
// "credentials not found" tells docker to fall through to an anonymous pull
// instead of aborting; anything else it reads as a broken helper.
const (
	errCredentialsNotFound = "credentials not found in native keychain"
	errNoServerURL         = "no credentials server URL"
)

// runCredentialHelper implements docker's credential-helper protocol: one verb
// as argv, the payload on stdin, the answer as JSON on stdout.
//
// Every message a caller is meant to read goes to stdout, because docker
// captures stdout only and string-matches it. Stderr passes through to the
// user's terminal, so it stays quiet — this runs on every docker operation.
func runCredentialHelper(args []string) int {
	if len(args) == 0 {
		fmt.Println("usage: docker-credential-agentics <get|store|erase|list>")
		return 1
	}
	switch args[0] {
	case "get":
		return credentialGet()
	case "store":
		return credentialStore()
	case "erase":
		return credentialErase()
	case "list":
		return credentialList()
	case "version":
		fmt.Println(dockercfg.BinaryName)
		return 0
	default:
		fmt.Printf("unknown credential helper action %q\n", args[0])
		return 1
	}
}

func credentialGet() int {
	registry, ok := readServerURL()
	if !ok {
		fmt.Println(errNoServerURL)
		return 1
	}

	// The signed-in session wins over anything `docker login` stored: it is the
	// credential that refreshes itself, which is the entire point of the helper.
	cred, err := login.AccessToken(&http.Client{Timeout: 30 * time.Second}, registry)
	if err == nil {
		return writeJSON(map[string]string{
			"ServerURL": registry,
			"Username":  login.HelperUsername,
			"Secret":    cred.AccessToken,
		})
	}
	if !errors.Is(err, login.ErrNotSignedIn) {
		// A failed refresh is a real error and must not masquerade as
		// "no credentials" — that would turn an expired session into a
		// confusing anonymous 401 further down.
		fmt.Printf("agent-registry: %v\n", err)
		return 1
	}

	if st, found, err := login.GetStatic(registry); err == nil && found {
		return writeJSON(map[string]string{
			"ServerURL": registry,
			"Username":  st.Username,
			"Secret":    st.Secret,
		})
	}
	fmt.Println(errCredentialsNotFound)
	return 1
}

func credentialStore() int {
	var in struct {
		ServerURL string `json:"ServerURL"`
		Username  string `json:"Username"`
		Secret    string `json:"Secret"`
	}
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&in); err != nil {
		fmt.Printf("agent-registry: %v\n", err)
		return 1
	}
	if in.ServerURL == "" {
		fmt.Println(errNoServerURL)
		return 1
	}
	if err := login.PutStatic(&login.Static{
		Registry: login.NormalizeRegistry(in.ServerURL),
		Username: in.Username,
		Secret:   in.Secret,
	}); err != nil {
		fmt.Printf("agent-registry: %v\n", err)
		return 1
	}
	return 0
}

func credentialErase() int {
	registry, ok := readServerURL()
	if !ok {
		fmt.Println(errNoServerURL)
		return 1
	}
	// `docker logout` means logged out — including the OIDC session. Leaving
	// it behind would make the next pull succeed and look like a bug.
	if _, err := login.Forget(registry); err != nil {
		fmt.Printf("agent-registry: %v\n", err)
		return 1
	}
	return 0
}

func credentialList() int {
	registries, err := login.Registries()
	if err != nil {
		fmt.Printf("agent-registry: %v\n", err)
		return 1
	}
	out := map[string]string{}
	for _, r := range registries {
		username := login.HelperUsername
		if _, err := login.Get(r); err != nil {
			if st, found, _ := login.GetStatic(r); found {
				username = st.Username
			}
		}
		out[r] = username
	}
	return writeJSON(out)
}

func readServerURL() (string, bool) {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		return "", false
	}
	url := strings.TrimSpace(string(raw))
	if url == "" {
		return "", false
	}
	return login.NormalizeRegistry(url), true
}

func writeJSON(v any) int {
	body, err := json.Marshal(v)
	if err != nil {
		fmt.Printf("agent-registry: %v\n", err)
		return 1
	}
	fmt.Println(string(body))
	return 0
}

// --- credential helper installation ---

func runCredentialHelperAdmin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "credential-helper: missing subcommand (install|uninstall|status)")
		return 2
	}
	sub := args[0]
	rest := args[1:]
	registry := ""
	helperDir := ""
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--helper-dir":
			if i+1 >= len(rest) {
				fmt.Fprintln(os.Stderr, "--helper-dir requires a directory")
				return 2
			}
			i++
			helperDir = rest[i]
		default:
			if strings.HasPrefix(rest[i], "-") {
				fmt.Fprintf(os.Stderr, "credential-helper: unknown flag %q\n", rest[i])
				return 2
			}
			registry = rest[i]
		}
	}
	registry = login.NormalizeRegistry(registry)

	switch sub {
	case "install":
		return installCredentialHelper(registry, helperDir)
	case "uninstall":
		changed, err := dockercfg.UnregisterHelper(registry)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		path, removed, err := dockercfg.Uninstall(helperDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if changed {
			fmt.Printf("docker no longer asks us for %s\n", registry)
		}
		if removed {
			fmt.Printf("removed %s\n", path)
		}
		if !changed && !removed {
			fmt.Println("nothing to remove")
		}
		return 0
	case "status":
		helper, err := dockercfg.HelperFor(registry)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		path, _ := dockercfg.Path()
		switch helper {
		case dockercfg.HelperName:
			fmt.Printf("%s: docker asks %s for credentials (%s)\n", registry, dockercfg.BinaryName, path)
		case "":
			fmt.Printf("%s: no credential helper registered (%s)\n", registry, path)
			return 1
		default:
			fmt.Printf("%s: docker asks docker-credential-%s for credentials (%s)\n", registry, helper, path)
			return 1
		}
		if _, err := exec.LookPath(dockercfg.BinaryName); err != nil {
			fmt.Printf("warning: %s is not on PATH — docker will not find it\n", dockercfg.BinaryName)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "credential-helper: unknown subcommand %q\n", sub)
		return 2
	}
}

func installCredentialHelper(registry, helperDir string) int {
	res, err := dockercfg.Install(helperDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not install the credential helper: %v\n", err)
		return 1
	}
	if _, err := dockercfg.RegisterHelper(registry); err != nil {
		fmt.Fprintf(os.Stderr, "could not update docker's config: %v\n", err)
		return 1
	}
	verb := "installed"
	if res.Existed {
		verb = "already installed at"
	}
	fmt.Printf("credential helper %s %s\n", verb, res.Path)
	fmt.Printf("docker will now ask it for %s\n", registry)
	if !res.OnPath {
		fmt.Printf("\nwarning: docker looks for %s on PATH and will not find it there.\n", dockercfg.BinaryName)
		fmt.Printf("Add %s to PATH, or re-run with --helper-dir <a directory on PATH>.\n", filepath.Dir(res.Path))
	}
	return 0
}

// --- small helpers ---

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func confirm(prompt string) bool {
	fmt.Printf("%s [Y/n] ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true
	default:
		return false
	}
}

// openBrowser is a convenience, never a requirement: the URL is printed first
// and the device grant works fine when the browser is on another machine.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		if _, err := exec.LookPath("xdg-open"); err != nil {
			return
		}
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" || a == "help" {
			return true
		}
	}
	return false
}

// authUsage is the per-verb help text. Kept next to the dispatcher so a new
// verb that forgets its entry simply falls through to the general help rather
// than printing something stale.
var authUsage = map[string]string{
	"login": `Usage: agent-registry login [<registry>] [flags]

Sign in with a browser and keep the credential on this machine.

The browser is sent to a callback on 127.0.0.1, so nothing has to be typed
back — this works in a devcontainer or an editor's remote session, because
the editor forwards the port. When the callback cannot reach this machine
(a raw SSH login, a tmux pane with no forwarding) the sign-in continues by
itself with a code instead.

Arguments:
  <registry>      Registry to sign in to (default: ` + login.DefaultRegistry + `)

Flags:
  --device        Skip the browser callback and sign in with a code
  --browser       Require the browser callback; fail rather than fall back
  --helper        Install the docker credential helper without asking
  --no-helper     Skip the helper and print the manual instructions
  --helper-dir D  Install the helper binary into D instead of the default

After signing in, docker pulls from the registry without a stored password:
the helper is asked on every operation and returns a freshly refreshed token.
`,
	"logout": `Usage: agent-registry logout [<registry>]

End the session and delete the local credential. Best-effort revocation at the
issuer; the credential is removed either way.
`,
	"whoami": `Usage: agent-registry whoami [<registry>]

Show who is signed in, when the credential expires, and whether docker has
been told to ask this CLI for it.
`,
	"token": `Usage: agent-registry token [<registry>]

Print a valid access token to stdout, refreshing it first if needed. For
scripts and one-off logins:

  docker login ` + login.DefaultRegistry + ` -u oauth2 -p "$(agent-registry token)"
`,
	"credential-helper": `Usage: agent-registry credential-helper <install|uninstall|status> [<registry>]

Manage the docker credential helper registration for a registry. install
writes a per-registry credHelpers entry, so it sits beside a global credsStore
rather than replacing it.
`,
}
