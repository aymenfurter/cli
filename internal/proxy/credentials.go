package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cli/safeexec"
)

// credential is a user name and password for a proxy.
type credential struct {
	username string
	password string
	// fromGit is true when the credential came from "git credential fill".
	// Only these credentials are sent back with approve or reject.
	fromGit bool
}

// credentialStore gets proxy credentials and records whether the proxy
// accepted them.
type credentialStore interface {
	// fill returns credentials for the proxy, or an error when none exist.
	fill(ctx context.Context, proxyURL *url.URL) (*credential, error)
	// approve records that the proxy accepted c.
	approve(ctx context.Context, proxyURL *url.URL, c *credential)
	// reject records that the proxy rejected c.
	reject(ctx context.Context, proxyURL *url.URL, c *credential)
}

var errNoCredential = errors.New("no proxy credentials found")

// gitCredentials gets proxy credentials from the proxy URL user info first,
// and then from the Git credential helpers ("git credential fill"). Git uses
// the same helpers for http.proxy authentication, so a proxy sign-in that
// works for Git also works for gh.
type gitCredentials struct {
	// run runs git with args and stdin and returns stdout. Tests replace it.
	run func(ctx context.Context, stdin string, args ...string) ([]byte, error)
}

const gitCredentialTimeout = 30 * time.Second

func (g *gitCredentials) fill(ctx context.Context, proxyURL *url.URL) (*credential, error) {
	var username string
	if u := proxyURL.User; u != nil {
		username = u.Username()
		if p, ok := u.Password(); ok {
			return &credential{username: username, password: p}, nil
		}
	}
	out, err := g.git(ctx, credentialInput(proxyURL, &credential{username: username}), "credential", "fill")
	if err != nil {
		return nil, fmt.Errorf("%w for proxy %s: %v", errNoCredential, proxyURL.Host, err)
	}
	c := &credential{fromGit: true}
	for line := range strings.SplitSeq(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimRight(line, "\r"), "=")
		switch k {
		case "username":
			c.username = v
		case "password":
			c.password = v
		}
	}
	if c.username == "" && c.password == "" {
		return nil, fmt.Errorf("%w for proxy %s", errNoCredential, proxyURL.Host)
	}
	return c, nil
}

func (g *gitCredentials) approve(ctx context.Context, proxyURL *url.URL, c *credential) {
	if c.fromGit {
		_, _ = g.git(ctx, credentialInput(proxyURL, c), "credential", "approve")
	}
}

func (g *gitCredentials) reject(ctx context.Context, proxyURL *url.URL, c *credential) {
	if c.fromGit {
		_, _ = g.git(ctx, credentialInput(proxyURL, c), "credential", "reject")
	}
}

func (g *gitCredentials) git(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gitCredentialTimeout)
	defer cancel()
	run := g.run
	if run == nil {
		run = runGit
	}
	return run(ctx, stdin, args...)
}

// credentialInput makes the "git credential" input for a proxy. Git asks
// for proxy credentials with protocol "http" for both http and https
// proxies, and with the host and port of the proxy.
func credentialInput(proxyURL *url.URL, c *credential) string {
	var b strings.Builder
	b.WriteString("protocol=http\n")
	fmt.Fprintf(&b, "host=%s\n", proxyHostPort(proxyURL))
	if c.username != "" {
		fmt.Fprintf(&b, "username=%s\n", c.username)
	}
	if c.password != "" {
		fmt.Fprintf(&b, "password=%s\n", c.password)
	}
	b.WriteString("\n")
	return b.String()
}

func proxyHostPort(proxyURL *url.URL) string {
	if proxyURL.Port() != "" {
		return proxyURL.Host
	}
	port := "80"
	if proxyURL.Scheme == "https" {
		port = "443"
	}
	return proxyURL.Hostname() + ":" + port
}

func runGit(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	gitExe, err := safeexec.LookPath("git")
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, gitExe, args...)
	cmd.Stdin = strings.NewReader(stdin)
	// The credential helpers must not prompt: gh can run without a terminal,
	// and a prompt would block the request. An empty GIT_ASKPASS stops Git
	// from falling back to core.askPass and SSH_ASKPASS.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "GCM_INTERACTIVE=never")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}
