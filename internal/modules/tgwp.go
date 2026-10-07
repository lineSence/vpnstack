package modules

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// TGWP — «TG WEB proxy»: официальный tproxy-server (telegramdesktop) + MTProxy.
// Ставится штатным deploy/install.sh закреплённой ревизии, но без его Caddy:
// сайт на домене обслуживает общий Caddy стека (за общим входом 443).
type TGWP struct{ base }

const (
	tgwpRepoURL = "https://github.com/telegramdesktop/tproxy-server"
	// Проверенная ревизия (2026-09-29). Патч установщика сверяется с ней.
	tgwpDefaultRef = "c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8"
	tgwpSrc        = "/opt/vpnstack/src/tproxy-server"
)

func init() {
	module.Register(&TGWP{base{id: "tgwp", title: "TG WEB proxy", order: 70,
		desc:  "Официальный WEB-прокси Telegram (tproxy-server + MTProxy) за HTTPS вашего домена",
		units: []string{"tproxy-server.service", "mtproxy.service"}}})
}

func (t *TGWP) Params() []module.Param {
	return []module.Param{
		{Key: "domain", Label: "Домен", Type: module.TDomain, Required: true, Restart: true,
			Help: "Поддомен с A-записью на сервер, например tg.example.com."},
		{Key: "base_path", Label: "Базовый путь (пусто — случайный, none — корень)", Type: module.TString, Advanced: true, Restart: true},
		{Key: "ref", Label: "Ревизия tproxy-server", Type: module.TString, Advanced: true,
			Help: "Коммит telegramdesktop/tproxy-server. Другая ревизия может не пройти проверку патча установщика."},
		{Key: "workers", Label: "Воркеры MTProxy", Type: module.TInt, Advanced: true, Restart: true},
	}
}

func (t *TGWP) AutoDefaults(env *module.Env, s *state.Service) error {
	if s.P("domain") == "" {
		return fmt.Errorf("TG WEB proxy: нужен домен")
	}
	s.Default("ref", tgwpDefaultRef)
	s.Default("workers", "1")
	s.Secret("secret", func() string { return sys.RandHex(16) })
	return nil
}

func (t *TGWP) Needs(env *module.Env, s *state.Service) []module.Need {
	return []module.Need{
		{Proto: "tcp", Port: 8080, Purpose: "tproxy-server"},
		{Proto: "tcp", Port: 8081, Purpose: "tproxy-server admin"},
		{Proto: "tcp", Port: 2398, Purpose: "MTProxy backend"},
		{Proto: "tcp", Port: 8888, Purpose: "MTProxy stats"},
	}
}

// CaddySites — сайт домена целиком проксируется в tproxy-server (как в штатном Caddyfile).
func (t *TGWP) CaddySites(env *module.Env, s *state.Service) []module.CaddySite {
	return []module.CaddySite{{Host: s.P("domain"), Order: 30, Block: `encode zstd gzip
header {
	-Via
	Strict-Transport-Security "max-age=31536000; includeSubDomains"
}
reverse_proxy 127.0.0.1:8080 {
	transport http {
		response_header_timeout 40s
	}
}
handle_errors {
	header {
		Cache-Control "no-store"
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
	}
	respond "{http.error.status_code} {http.error.status_text}" {http.error.status_code}
}`}}
}

func (t *TGWP) Latest(env *module.Env) (string, error) {
	out, err := sys.Output("git", "ls-remote", tgwpRepoURL, "HEAD")
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	if len(f) == 0 {
		return "", fmt.Errorf("пустой ответ git ls-remote")
	}
	return f[0], nil
}

// patchInstaller убирает из штатного install.sh установку и запуск Caddy.
func patchInstaller(src string) (string, error) {
	lines := strings.Split(src, "\n")
	var out []string
	removed := map[string]bool{}
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		switch {
		case strings.HasPrefix(l, "caddy_version="):
			for ; i < len(lines) && strings.TrimSpace(lines[i]) != "trap - EXIT"; i++ {
			}
			removed["download"] = true
			continue
		case strings.HasPrefix(l, `install -m 0644 "$repository/deploy/Caddyfile" /etc/caddy/Caddyfile.tproxy`):
			for ; i < len(lines) && !strings.Contains(lines[i], "caddy.service.d/tproxy.conf <<EOF"); i++ {
			}
			for ; i < len(lines) && strings.TrimSpace(lines[i]) != "EOF"; i++ {
			}
			removed["config"] = true
			continue
		case strings.HasPrefix(l, `TPROXY_HOSTNAME="$hostname" TPROXY_SITE_ROOT=`):
			i++ // и строка `caddy validate`
			removed["validate"] = true
			continue
		case l == "systemctl enable --now caddy.service" || l == "systemctl restart caddy.service":
			removed[l] = true
			continue
		}
		out = append(out, l)
	}
	if len(removed) != 5 {
		return "", fmt.Errorf("install.sh этой ревизии tproxy-server изменился (вырезано %d из 5 фрагментов) — используйте проверенную ревизию %s", len(removed), tgwpDefaultRef)
	}
	res := strings.Join(out, "\n")
	if strings.Contains(res, "caddy.service") && strings.Contains(res, "systemctl restart caddy") {
		return "", fmt.Errorf("не удалось убрать перезапуск Caddy из install.sh")
	}
	return res, nil
}

func (t *TGWP) fetch(s *state.Service) error {
	if !sys.Exists(filepath.Join(tgwpSrc, ".git")) {
		if _, err := sys.Run("git", "clone", tgwpRepoURL, tgwpSrc); err != nil {
			return err
		}
	} else if _, err := sys.Run("git", "-C", tgwpSrc, "fetch", "--all", "--tags"); err != nil {
		return err
	}
	if _, err := sys.Run("git", "-C", tgwpSrc, "checkout", "--force", s.P("ref")); err != nil {
		return err
	}
	_, err := sys.Run("git", "-C", tgwpSrc, "clean", "-fdx")
	return err
}

func (t *TGWP) runInstaller(env *module.Env, s *state.Service) error {
	if arch() != "amd64" {
		return fmt.Errorf("официальная сборка MTProxy требует x86_64")
	}
	if env.Stack.Email == "" {
		return fmt.Errorf("TG WEB proxy: нужен e-mail для ACME (общие настройки)")
	}
	if err := aptInstall("git", "ca-certificates", "curl", "nftables", "coreutils"); err != nil {
		return err
	}
	if err := t.fetch(s); err != nil {
		return err
	}
	src, err := os.ReadFile(filepath.Join(tgwpSrc, "deploy", "install.sh"))
	if err != nil {
		return err
	}
	patched, err := patchInstaller(string(src))
	if err != nil {
		return err
	}
	script := filepath.Join(tgwpSrc, "deploy", "install-vpnstack.sh")
	if err := sys.WriteFileAtomic(script, []byte(patched), 0o755); err != nil {
		return err
	}
	ensureSite()
	args := []string{script, "--hostname", s.P("domain"), "--email", env.Stack.Email,
		"--secret", s.Secrets["secret"], "--mtproxy-workers", s.P("workers")}
	if !sys.Exists("/srv/tproxy-site/index.html") {
		args = append(args, "--site-dir", SiteDir)
	}
	if bp := s.P("base_path"); bp != "" {
		args = append(args, "--base-path", bp)
	}
	if _, err := sys.Run("bash", args...); err != nil {
		return err
	}
	for _, u := range t.units {
		_ = sys.AttachToSlice(u, t.id)
	}
	_ = sys.EnsureSlice(t.id, t.title)
	_ = sys.Systemctl("daemon-reload")
	_ = sys.Systemctl("restart", t.units...)
	if b, err := os.ReadFile("/etc/tproxy-server/config.json"); err == nil {
		var c struct {
			BasePath string `json:"base_path"`
		}
		if json.Unmarshal(b, &c) == nil {
			s.Params["active_base_path"] = c.BasePath
		}
	}
	rev, _ := sys.Output("git", "-C", tgwpSrc, "rev-parse", "--short", "HEAD")
	s.Version = strings.TrimSpace(rev)
	return nil
}

func (t *TGWP) Install(env *module.Env, s *state.Service) error {
	if s.Params["adopted_inplace"] == "true" {
		return t.adoptInPlace(s)
	}
	return t.runInstaller(env, s)
}

// adoptInPlace — перенятая установка tproxy-server остаётся как есть (те же секрет, путь,
// ключ токенов): vpnstack лишь заменяет её Caddy своим и следит за юнитами.
func (t *TGWP) adoptInPlace(s *state.Service) error {
	if b, err := os.ReadFile("/etc/tproxy-server/config.json"); err == nil {
		var c struct {
			BasePath string `json:"base_path"`
		}
		if json.Unmarshal(b, &c) == nil {
			s.Params["active_base_path"] = c.BasePath
		}
	}
	if s.Version == "" {
		s.Version = "перенят"
	}
	for _, u := range t.units {
		if !sys.Active(u) {
			if err := sys.Systemctl("start", u); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *TGWP) Apply(env *module.Env, s *state.Service) error { return t.runInstaller(env, s) }

func (t *TGWP) Remove(env *module.Env, s *state.Service, purge bool) error {
	for _, u := range []string{"refresh-mtproxy-config.timer", "tproxy-server.service", "mtproxy.service", "tproxy-firewall.service"} {
		_ = sys.Systemctl("disable", "--now", u)
	}
	sys.RemoveUnit(sys.SliceName(t.id))
	if purge {
		_, _ = sys.Run("rm", "-rf", "/etc/tproxy-server", "/etc/mtproxy", "/opt/MTProxy", "/usr/local/bin/tproxy-server", tgwpSrc,
			"/etc/systemd/system/tproxy-server.service", "/etc/systemd/system/mtproxy.service", "/etc/systemd/system/tproxy-firewall.service",
			"/etc/systemd/system/refresh-mtproxy-config.service", "/etc/systemd/system/refresh-mtproxy-config.timer",
			"/etc/systemd/system/tproxy-server.service.d", "/etc/systemd/system/mtproxy.service.d")
	}
	_ = sys.Systemctl("daemon-reload")
	return nil
}

func (t *TGWP) Status(env *module.Env, s *state.Service) module.Status {
	st := unitsStatus(s, t.units)
	if st.State == "running" {
		if _, err := sys.Output("curl", "-fsS", "-o", "/dev/null", "http://127.0.0.1:8081/readyz"); err != nil {
			st.State, st.Detail = "partial", "tproxy-server не готов (/readyz)"
		}
	}
	return st
}

func (t *TGWP) Update(env *module.Env, s *state.Service) error {
	// Обновление — смена ревизии вручную (параметр ref): установщик патчится по известной ревизии.
	return t.runInstaller(env, s)
}

func (t *TGWP) ConfigFiles(*state.Service) []string {
	return []string{"/etc/tproxy-server/config.json", "/etc/mtproxy/mtproxy.env"}
}

// Links — ссылка t.me/webproxy (как печатает штатный установщик).
func (t *TGWP) Links(env *module.Env, s *state.Service) ([]module.Artifact, error) {
	secret := s.Secrets["secret"]
	bp := s.Params["active_base_path"]
	addr := s.P("domain")
	ps := secret
	if bp != "" {
		addr += "/" + bp
		raw, err := hex.DecodeString(secret)
		if err != nil {
			return nil, err
		}
		ps = base64.RawURLEncoding.EncodeToString(append([]byte{0x70}, raw...))
	}
	link := "https://t.me/webproxy?server=" + strings.ReplaceAll(addr, "/", "%2F") + "&secret=" + url.QueryEscape(ps)
	return []module.Artifact{
		{Kind: "uri", Title: "Ссылка TG WEB proxy", Value: link, QR: true},
		{Kind: "text", Title: "Сервер / секрет для ручного ввода", Value: addr + "\n" + ps},
	}, nil
}
