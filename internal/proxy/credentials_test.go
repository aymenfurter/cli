package proxy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialInput(t *testing.T) {
	tests := []struct {
		proxy   string
		cred    credential
		want    string
		wantErr bool
	}{
		{proxy: "http://proxy:8080", want: "protocol=http\nhost=proxy:8080\n\n"},
		{proxy: "https://proxy", cred: credential{username: "u", password: "p"}, want: "protocol=http\nhost=proxy:443\nusername=u\npassword=p\n\n"},
		{proxy: "http://proxy", want: "protocol=http\nhost=proxy:80\n\n"},
		{proxy: "http://proxy", cred: credential{username: "u\nhost=evil"}, wantErr: true},
		{proxy: "http://proxy", cred: credential{password: "p\x00"}, wantErr: true},
	}
	for _, tt := range tests {
		got, err := credentialInput(mustURL(t, tt.proxy), &tt.cred)
		if tt.wantErr {
			assert.Error(t, err)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}
}

func TestGitCredentialsNewlineInUserInfo(t *testing.T) {
	g := &gitCredentials{run: func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("git must not run")
		return nil, nil
	}}
	_, err := g.fill(context.Background(), mustURL(t, "http://u%0Ahost=evil@proxy:3128"))
	assert.ErrorIs(t, err, errNoCredential)
}

func TestGitCredentialsURLUserInfo(t *testing.T) {
	g := &gitCredentials{run: func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("git must not run")
		return nil, nil
	}}
	c, err := g.fill(context.Background(), mustURL(t, "http://u%5Cx:p%40ss@proxy:3128"))
	require.NoError(t, err)
	assert.Equal(t, &credential{username: `u\x`, password: "p@ss"}, c)
	// Credentials from the URL are not sent to git.
	g.approve(context.Background(), mustURL(t, "http://proxy:3128"), c)
	g.reject(context.Background(), mustURL(t, "http://proxy:3128"), c)
}

// setupGitHelper configures a Git credential helper for the proxy host in
// GIT_CONFIG_PARAMETERS, as the GitHub Copilot app does. The helper returns
// monalisa:s3cret and logs its input to the returned file.
func setupGitHelper(t *testing.T, proxyHost string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	logFile := filepath.ToSlash(filepath.Join(dir, "helper.log"))
	helper := `!f() { echo "$1" >> '` + logFile + `'; cat >> '` + logFile + `'; if [ "$1" = get ]; then echo username=monalisa; echo password=s3cret; fi; }; f`
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	key := "credential.http://" + proxyHost + ".helper"
	t.Setenv("GIT_CONFIG_PARAMETERS", "'"+key+"=' '"+key+"="+strings.ReplaceAll(helper, "'", `'\''`)+"'")
	return logFile
}

// TestTransportBasicWithGitHelper is the GitHub Copilot app setup: the
// proxy asks for Basic, and the app credential helper has the sign-in.
func TestTransportBasicWithGitHelper(t *testing.T) {
	want := "Basic " + b64("monalisa:s3cret")
	var logFile string
	s := newSetup(t, func(origin string) string {
		p := startFakeProxy(t, origin, nil, func(_ int, authz string) proxyReply {
			return proxyReply{ok: authz == want, challenge: []string{`Basic realm="corp"`}}
		})
		logFile = setupGitHelper(t, p.ln.Addr().String())
		return p.url()
	}, &gitCredentials{}, nil)

	got, err := s.post(t, "x")
	require.NoError(t, err)
	assert.Equal(t, "ok x", got)
	b, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Regexp(t, `(?s)^get\nprotocol=http\nhost=127\.0\.0\.1:\d+\n.*store\n`, strings.ReplaceAll(string(b), "\r", ""))
}

// TestGitCredentialsHelper runs git with a credential helper in the same
// way as the GitHub Copilot app: a helper for the proxy origin in
// GIT_CONFIG_PARAMETERS.
func TestGitCredentialsHelper(t *testing.T) {
	logFile := setupGitHelper(t, "proxy.corp:3128")
	g := &gitCredentials{}
	ctx := context.Background()
	u := mustURL(t, "http://proxy.corp:3128")
	c, err := g.fill(ctx, u)
	require.NoError(t, err)
	assert.Equal(t, &credential{username: "monalisa", password: "s3cret", fromGit: true}, c)
	g.approve(ctx, u, c)
	g.reject(ctx, u, c)

	_, err = g.fill(ctx, mustURL(t, "http://other.corp:3128"))
	require.Error(t, err)

	b, err := os.ReadFile(logFile)
	require.NoError(t, err)
	log := strings.ReplaceAll(string(b), "\r", "")
	assert.Contains(t, log, "get\nprotocol=http\nhost=proxy.corp:3128\n")
	assert.Contains(t, log, "store\nprotocol=http\nhost=proxy.corp:3128\nusername=monalisa\npassword=s3cret\n")
	assert.Contains(t, log, "erase\nprotocol=http\nhost=proxy.corp:3128\nusername=monalisa\npassword=s3cret\n")
	assert.NotContains(t, log, "other.corp")
}
