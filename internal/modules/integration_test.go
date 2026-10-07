//go:build integration

package modules

// Интеграционная проверка: скачивает последние релизы (с проверкой сумм) и
// валидирует сгенерированные конфигурации настоящими бинарниками.
//   go test -tags integration -run Integration -v ./internal/modules

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

func setupDirs(t *testing.T) {
	root := t.TempDir()
	BinDir, EtcDir, DataDir = filepath.Join(root, "bin"), filepath.Join(root, "etc"), filepath.Join(root, "data")
	xrayDir = filepath.Join(root, "xray")
	SiteDir = filepath.Join(DataDir, "site")
	os.MkdirAll(BinDir, 0o755)
	sys.Log = os.Stderr
}

func runFor(t *testing.T, d time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, _ := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out)
}

func TestIntegrationConfigs(t *testing.T) {
	setupDirs(t)
	env := testEnv()

	// Caddy: скачать и проверить Caddyfile.
	c := &Caddy{base{id: "caddy"}}
	tag, err := c.download(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Caddy %s", tag)
	ensureSite()
	if err := os.MkdirAll(c.cfgDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	cf := c.Render(env)
	os.WriteFile(c.caddyfile(), []byte(cf), 0o644)
	if out, err := exec.Command(c.bin(), "validate", "--config", c.caddyfile(), "--adapter", "caddyfile").CombinedOutput(); err != nil {
		t.Fatalf("caddy validate: %v\n%s\n%s", err, out, cf)
	}

	// Xray: скачать и xray run -test.
	x := &Xray{base{id: "xray"}}
	if tag, err = x.download(env); err != nil {
		t.Fatal(err)
	}
	t.Logf("Xray %s", tag)
	s := &state.Service{Params: map[string]string{}}
	_ = x.AutoDefaults(env, s)
	x.AddUser(env, s, "alice", nil)
	os.MkdirAll(x.cfgDir(), 0o755)
	if err := x.write(env, s); err != nil {
		b, _ := os.ReadFile(x.cfgPath())
		t.Fatalf("xray: %v\n%s", err, b)
	}

	// Hysteria: скачать и запустить на высоком порту с самоподписанным сертификатом.
	h := &Hysteria{base{id: "hysteria"}}
	if tag, err = h.download(env); err != nil {
		t.Fatal(err)
	}
	t.Logf("Hysteria %s", tag)
	hs := &state.Service{Params: map[string]string{"port": "24443"}}
	_ = h.AutoDefaults(env, hs)
	hs.Secrets["stats_secret"] = "s"
	os.MkdirAll(h.cfgDir(), 0o755)
	if err := h.syncCert(env, hs, 0); err != nil {
		t.Fatal(err)
	}
	hs.Users = []*state.User{{Name: "bob", Data: map[string]string{"password": "pw"}}}
	os.WriteFile(h.cfgPath(), []byte(strings.ReplaceAll(h.render(hs), "127.0.0.1:9998", "127.0.0.1:29998")), 0o644)
	out := runFor(t, 3*time.Second, h.bin(), "server", "-c", h.cfgPath(), "--disable-update-check")
	if !strings.Contains(out, "server up and running") {
		t.Fatalf("hysteria не запустился:\n%s", out)
	}

	// telemt: скачать и запустить на высоком порту.
	tm := &Telemt{base{id: "telemt"}}
	if tag, err = tm.download(env); err != nil {
		t.Fatal(err)
	}
	t.Logf("telemt %s", tag)
	ts := &state.Service{Params: map[string]string{"tls_domain": "example.com", "own_domain": "false", "middle_proxy": "false"}, Secrets: map[string]string{"api_token": "tok"}}
	ts.Users = []*state.User{{Name: "a", Data: map[string]string{"secret": sys.RandHex(16)}}}
	cfg := tm.render(env, ts)
	cfg = strings.ReplaceAll(cfg, "port = 10444", "port = 20444")
	cfg = strings.ReplaceAll(cfg, "127.0.0.1:9091", "127.0.0.1:29091")
	cfg = strings.ReplaceAll(cfg, tm.dataDir(), t.TempDir())
	os.MkdirAll(tm.cfgDir(), 0o755)
	os.WriteFile(tm.cfgPath(), []byte(cfg), 0o644)
	out = runFor(t, 6*time.Second, tm.bin(), tm.cfgPath())
	t.Logf("telemt:\n%s", tail(out, 25))
	if strings.Contains(strings.ToLower(out), "config error") || strings.Contains(out, "failed to parse") || strings.Contains(out, "unknown field") {
		t.Fatalf("telemt отверг конфигурацию:\n%s", out)
	}
}

func tail(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}
