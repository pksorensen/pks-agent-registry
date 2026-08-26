package login

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"
)

// HelperUsername is the username handed to docker alongside the JWT.
//
// Deliberately NOT "<token>": docker treats that magic username as "this
// secret is an identity token" and switches to an OAuth2 POST refresh flow
// against the registry, which this registry does not implement. With any
// ordinary username docker sends plain Basic auth to the token endpoint, and
// the registry ignores the username entirely for JWT credentials.
const HelperUsername = "oauth2"

// AccessToken returns a usable Keycloak access token for a registry,
// refreshing and re-persisting it when the cached one is spent. This is the
// call the credential helper makes on every single docker operation, so the
// happy path is a file read and nothing else.
func AccessToken(client *http.Client, registry string) (*Credential, error) {
	c, err := Get(registry)
	if err != nil {
		return nil, err
	}
	if c.Fresh(time.Now()) {
		return c, nil
	}
	fresh, err := Refresh(client, c)
	if err != nil {
		return nil, err
	}
	if err := Put(fresh); err != nil {
		// The token is good even if we could not cache it; a read-only home
		// directory should slow docker down, not break it.
		return fresh, nil
	}
	return fresh, nil
}

// Mode selects the sign-in flow.
type Mode int

const (
	// ModeAuto runs the loopback flow and falls back to the device grant when
	// the browser never reaches this machine. The default.
	ModeAuto Mode = iota
	// ModeBrowser runs the loopback flow only, and fails rather than falling back.
	ModeBrowser
	// ModeDevice runs the device grant only.
	ModeDevice
)

// UI is how SignIn talks to the human. Both are called from the flow, so the
// caller decides formatting and SignIn stays free of it.
type UI struct {
	// ShowURL presents the URL to open. userCode is set only by the device
	// grant, and only when the issuer offers no URL with the code already in it.
	ShowURL func(url, userCode string)
	// Notice reports something the human should know mid-flow, such as a
	// fallback from one flow to the other.
	Notice func(msg string)
}

func (u UI) showURL(url, code string) {
	if u.ShowURL != nil {
		u.ShowURL(url, code)
	}
}

func (u UI) notice(msg string) {
	if u.Notice != nil {
		u.Notice(msg)
	}
}

// SignIn obtains a credential, choosing between the loopback flow and the
// device grant.
//
// The loopback flow always gets its chance first, and no check of the
// environment is allowed to take that away from it. In particular DISPLAY is
// not consulted: this CLI's most common home is a devcontainer, which has no
// DISPLAY and where loopback nonetheless works, because the editor forwards the
// port and the printed URL is clickable. A predicate that reads DISPLAY would
// send exactly the normal case down the fallback path.
//
// What the environment is allowed to decide is only how long to wait before
// concluding the browser cannot reach us — see loopbackWait.
func SignIn(ctx context.Context, client *http.Client, d *Discovery, mode Mode, ui UI) (*Credential, error) {
	ep, err := FetchEndpoints(client, d.Issuer)
	if err != nil {
		return nil, err
	}

	if mode != ModeDevice {
		cred, err := loopbackWithWait(ctx, client, ep, d, ui, loopbackWait())
		if err == nil {
			return cred, nil
		}
		// A denial or a cancellation is the human's answer, not a broken
		// flow — retrying it in another shape would just ask them twice.
		if errors.Is(err, ErrDenied) || errors.Is(err, context.Canceled) {
			return nil, err
		}
		if mode == ModeBrowser {
			return nil, err
		}
		switch {
		case errors.Is(err, ErrLoopbackUnavailable):
			ui.notice("No loopback port was free, so this sign-in continues with a code instead.")
		case errors.Is(err, ErrCallbackTimeout):
			ui.notice("The browser did not reach this machine, so this sign-in continues with a code instead.")
		default:
			return nil, err
		}
	}

	auth, err := StartDevice(client, ep, d)
	if err != nil {
		return nil, err
	}
	code := auth.UserCode
	if auth.VerificationURIComplete != "" {
		// The URL already carries the code, so asking the human to read one
		// out would be asking for nothing.
		code = ""
	}
	ui.showURL(auth.BestURL(), code)
	tryOpenBrowser(auth.BestURL())
	return PollDevice(ctx, client, ep, d, auth)
}

func loopbackWithWait(ctx context.Context, client *http.Client, ep *Endpoints, d *Discovery, ui UI, wait time.Duration) (*Credential, error) {
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := time.AfterFunc(wait, cancel)
	defer timer.Stop()

	cred, err := Loopback(waitCtx, client, ep, d, func(u string) {
		ui.showURL(u, "")
		tryOpenBrowser(u)
	})
	// A cancel that came from our own timer is a timeout, not the user
	// pressing Ctrl-C; the caller distinguishes the two by error.
	if errors.Is(err, context.Canceled) && ctx.Err() == nil {
		return nil, ErrCallbackTimeout
	}
	return cred, err
}

// loopbackWait is how long to wait for the browser before giving up on it.
//
// A raw SSH session with no port forwarding is the one place the callback
// genuinely cannot arrive, and there a five-minute wait is five minutes of a
// person watching a prompt that will never move. SSH_TTY on its own does not
// prove that, though: an editor attached over Remote-SSH sets it too and
// forwards the port perfectly well. So the editor's presence wins, and the
// short wait applies only to a bare SSH login — where it costs a minute before
// the device grant takes over, rather than skipping loopback outright.
func loopbackWait() time.Duration {
	if os.Getenv("SSH_TTY") != "" && os.Getenv("VSCODE_IPC_HOOK_CLI") == "" && os.Getenv("TERM_PROGRAM") != "vscode" {
		return time.Minute
	}
	return waitForCallback
}
