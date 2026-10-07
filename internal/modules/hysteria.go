package modules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Hysteria — Hysteria 2 (QUIC) на UDP 443. Сертификат выпускает Caddy (общий
// ACME-клиент), оркестратор копирует его; без домена — самоподписанный с pinSHA256.
type Hysteria struct{ base }

const (
	hyRepo  = "apernet/hysteria"
	hyStats = "127.0.0.1:9998"
)

func init() {
	module.Register(&Hysteria{base{id: "hysteria", title: "Hysteria 2", order: 40,
		desc:  "QUIC-протокол с BBR/Brutal, маскировка под HTTP/3-сайт; UDP 443",
		units: []string{"vpnstack-hysteria.service"}}})
}

func (h *Hysteria) Params() []module.Param {
	return []module.Param{
		{Key: "domain", Label: "Домен", Type: module.TDomain,
			Help: "Поддомен, указывающий на сервер (сертификат выпустит Caddy). Пусто — самоподписанный сертификат с привязкой отпечатка."},
		{Key: "port", Label: "UDP-порт", Type: module.TPort, Advanced: true, Restart: true},
		{Key: "obfs", Label: "Обфускация", Type: module.TBool, Advanced: true,
			Help: "Пакеты перестают быть похожи на QUIC/HTTP3; маскировка под сайт при этом не работает."},
		{Key: "obfs_type", Label: "Тип обфускации", Type: module.TSelect, Options: []string{"salamander", "gecko"}, Advanced: true},
		{Key: "sni", Label: "SNI самоподписанного сертификата", Type: module.TString, Advanced: true,
			Help: "Используется только без домена: имя в сертификате и в ссылках."},
		{Key: "up_mbps", Label: "Канал сервера вверх, Мбит/с (0 — BBR)", Type: module.TInt, Advanced: true},
		{Key: "down_mbps", Label: "Канал сервера вниз, Мбит/с (0 — BBR)", Type: module.TInt, Advanced: true},
	}
}

func (h *Hysteria) AutoDefaults(env *module.Env, s *state.Service) error {
	s.Default("port", "443")
	s.Default("obfs", "false")
	s.Default("obfs_type", "salamander")
	s.Default("sni", "bing.com")
	s.Default("up_mbps", "0")
	s.Default("down_mbps", "0")
	s.Secret("stats_secret", func() string { return sys.RandHex(16) })
	s.Secret("obfs_password", func() string { return password(24) })
	return nil
}

func (h *Hysteria) Needs(env *module.Env, s *state.Service) []module.Need {
	return []module.Need{
		{Proto: "udp", Port: atoi(s.P("port")), Public: true, Param: "port", Purpose: "Hysteria 2 (QUIC)"},
		{Proto: "tcp", Port: 9998, Purpose: "Hysteria trafficStats API"},
	}
}

// CaddySites — сайт для домена Hysteria: Caddy выпускает сертификат, а TCP-посетители
// видят тот же сайт, что отдаёт маскировка по HTTP/3.
func (h *Hysteria) CaddySites(env *module.Env, s *state.Service) []module.CaddySite {
	if d := s.P("domain"); d != "" {
		return []module.CaddySite{{Host: d, Order: 40}}
	}
	return nil
}

func (h *Hysteria) Latest(env *module.Env) (string, error) { return latestTag(env, hyRepo) }

func (h *Hysteria) bin() string { return filepath.Join(BinDir, "hysteria") }

func (h *Hysteria) download(env *module.Env) (string, error) {
	tag, err := h.Latest(env)
	if err != nil {
		return "", err
	}
	if haveBin(h.bin(), tag) {
		return tag, nil
	}
	rel, err := sys.ReleaseByTag(hyRepo, tag)
	if err != nil {
		return "", err
	}
	name := "hysteria-linux-" + arch()
	if arch() == "amd64" && cpuHasAVX() {
		name = "hysteria-linux-amd64-avx"
	}
	a, ok := rel.Find(name)
	hs, ok2 := rel.Find("hashes.txt")
	if !ok || !ok2 {
		return "", fmt.Errorf("в релизе Hysteria %s нет %s или hashes.txt", tag, name)
	}
	sums, err := sys.FetchText(hs.URL)
	if err != nil {
		return "", err
	}
	tmp := h.bin() + ".new"
	if err := sys.DownloadVerified(a.URL, tmp, sys.ChecksumFor(sums, name)); err != nil {
		return "", err
	}
	return tag, installBin(tmp, h.bin(), tag)
}

func cpuHasAVX() bool {
	b, _ := sys.Output("grep", "-m1", "-o", "-w", "avx", "/proc/cpuinfo")
	return strings.TrimSpace(b) == "avx"
}

func (h *Hysteria) certPaths() (string, string) {
	return filepath.Join(h.cfgDir(), "cert.pem"), filepath.Join(h.cfgDir(), "key.pem")
}

// syncCert копирует сертификат из Caddy (или создаёт самоподписанный).
// Hysteria перечитывает файлы сертификата сама — перезапуск не нужен.
func (h *Hysteria) syncCert(env *module.Env, s *state.Service, wait time.Duration) (err error) {
	cert, key := h.certPaths()
	// Fix permissions on every successful path, including an adopted certificate
	// or an unchanged copy. Atomic replacement also resets group ownership.
	defer func() {
		if err == nil {
			group, lookupErr := user.LookupGroup("hysteria")
			if lookupErr != nil {
				err = fmt.Errorf("Hysteria TLS group: %w", lookupErr)
				return
			}
			gid, parseErr := strconv.Atoi(group.Gid)
			if parseErr != nil {
				err = fmt.Errorf("Hysteria TLS gid: %w", parseErr)
				return
			}
			err = hysteriaTLSPermissions(cert, key, gid)
		}
	}()
	d := s.P("domain")
	if d == "" {
		if !sys.Exists(cert) || s.Secrets["self_signed"] != "true" {
			fp, err := selfSigned(cert, key, firstNonEmpty(s.P("sni"), "bing.com"))
			if err != nil {
				return err
			}
			s.Secrets["self_signed"] = "true"
			s.Secrets["pin_sha256"] = fp
		}
		return nil
	}
	delete(s.Secrets, "self_signed")
	deadline := time.Now().Add(wait)
	for {
		if c, k, ok := env.CaddyCert(d); ok {
			if _, err := copyIfChanged(c, cert, 0o644); err != nil {
				return err
			}
			if _, err := copyIfChanged(k, key, 0o640); err != nil {
				return err
			}
			return nil
		}
		if time.Now().After(deadline) || (wait > 0 && certValidFor(cert, d, 72*time.Hour)) {
			if certValidFor(cert, d, 72*time.Hour) {
				// Перенос: пока Caddy получает свой сертификат, работаем на перенятом.
				return nil
			}
			return fmt.Errorf("Caddy не выпустил сертификат для %s: проверьте A-запись и доступность TCP 80/443 (journalctl -u vpnstack-caddy)", d)
		}
		time.Sleep(3 * time.Second)
	}
}

// hysteriaTLSPermissions keeps the private key inaccessible to other users,
// while making both TLS files readable by the service's group.
func hysteriaTLSPermissions(cert, key string, gid int) error {
	for _, file := range []struct {
		path string
		mode os.FileMode
	}{{cert, 0o644}, {key, 0o640}} {
		if err := os.Chown(file.path, -1, gid); err != nil {
			return fmt.Errorf("Hysteria TLS group %s: %w", file.path, err)
		}
		if err := os.Chmod(file.path, file.mode); err != nil {
			return fmt.Errorf("Hysteria TLS mode %s: %w", file.path, err)
		}
	}
	return nil
}

// Tick вызывается сервисом vpnstack периодически: подхватывает продлённый сертификат.
func (h *Hysteria) Tick(env *module.Env, s *state.Service) {
	if s.Installed && s.P("domain") != "" {
		_ = h.syncCert(env, s, 0)
	}
}

func (h *Hysteria) cfgPath() string { return filepath.Join(h.cfgDir(), "config.yaml") }

func yq(s string) string { b, _ := json.Marshal(s); return string(b) } // JSON-строка — валидный YAML

func (h *Hysteria) render(s *state.Service) string {
	cert, key := h.certPaths()
	var b strings.Builder
	fmt.Fprintf(&b, "# Сгенерировано vpnstack\nlisten: :%s\n\ntls:\n  cert: %s\n  key: %s\n", s.P("port"), cert, key)
	if boolP(s, "obfs") {
		if s.P("obfs_type") == "gecko" {
			fmt.Fprintf(&b, "\nobfs:\n  type: gecko\n  gecko:\n    password: %s\n", yq(s.Secrets["obfs_password"]))
			if v := atoi(s.P("gecko_min")); v > 0 {
				fmt.Fprintf(&b, "    minPacketSize: %d\n", v)
			}
			if v := atoi(s.P("gecko_max")); v > 0 {
				fmt.Fprintf(&b, "    maxPacketSize: %d\n", v)
			}
		} else {
			fmt.Fprintf(&b, "\nobfs:\n  type: salamander\n  salamander:\n    password: %s\n", yq(s.Secrets["obfs_password"]))
		}
	}
	if up, down := atoi(s.P("up_mbps")), atoi(s.P("down_mbps")); up > 0 && down > 0 {
		fmt.Fprintf(&b, "\nbandwidth:\n  up: %d mbps\n  down: %d mbps\n", up, down)
	}
	// Пользователи проверяются командой vpnstack-hy-auth по файлу auth.json: добавление и
	// удаление не требуют перезапуска, а перенятый общий пароль (auth.type: password)
	// продолжает работать рядом с личными логинами.
	fmt.Fprintf(&b, "\nauth:\n  type: command\n  command: %s\n", HyAuthPath)
	fmt.Fprintf(&b, "\ntrafficStats:\n  listen: %s\n  secret: %s\n", hyStats, yq(s.Secrets["stats_secret"]))
	if !boolP(s, "obfs") {
		fmt.Fprintf(&b, "\nmasquerade:\n  type: file\n  file:\n    dir: %s\n", SiteDir)
	}
	return b.String()
}

func (h *Hysteria) write(s *state.Service) error {
	if err := h.writeAuth(s); err != nil {
		return err
	}
	if err := sys.WriteFileAtomic(h.cfgPath(), []byte(h.render(s)), 0o640); err != nil {
		return err
	}
	_, _ = sys.Run("chgrp", "hysteria", h.cfgPath())
	return nil
}

func (h *Hysteria) Install(env *module.Env, s *state.Service) error {
	ensureUser("hysteria")
	ensureSite()
	tag, err := h.download(env)
	if err != nil {
		return err
	}
	s.Version = tag
	if _, err := sys.Run("install", "-d", "-m", "0750", "-g", "hysteria", h.cfgDir()); err != nil {
		return fmt.Errorf("Hysteria config directory: %w", err)
	}
	if err := h.syncCert(env, s, 3*time.Minute); err != nil {
		return err
	}
	if err := h.write(s); err != nil {
		return err
	}
	unit := serviceUnit(h.id, h.title, h.bin()+" server --config "+h.cfgPath()+" --disable-update-check", `User=hysteria
Group=hysteria
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
`)
	if err := installUnit(h.id, h.title, h.units[0], unit); err != nil {
		return err
	}
	return waitActive(h.units[0], 10e9)
}

func (h *Hysteria) Apply(env *module.Env, s *state.Service) error {
	if err := h.syncCert(env, s, 3*time.Minute); err != nil {
		return err
	}
	if err := h.write(s); err != nil {
		return err
	}
	if err := sys.Systemctl("restart", h.units[0]); err != nil {
		return err
	}
	return waitActive(h.units[0], 10e9)
}

func (h *Hysteria) Remove(env *module.Env, s *state.Service, purge bool) error {
	removeUnits(h.id, h.units...)
	if purge {
		_, _ = sys.Run("rm", "-rf", h.cfgDir(), h.bin(), h.bin()+".prev")
	}
	return nil
}

func (h *Hysteria) Status(env *module.Env, s *state.Service) module.Status {
	return unitsStatus(s, h.units)
}

func (h *Hysteria) Update(env *module.Env, s *state.Service) error {
	tag, err := h.download(env)
	if err != nil {
		return err
	}
	s.Version = tag
	return h.Apply(env, s)
}

func (h *Hysteria) ConfigFiles(*state.Service) []string { return []string{h.cfgPath()} }

func (h *Hysteria) AddUser(env *module.Env, s *state.Service, name string, opts map[string]string) (*state.User, error) {
	u := &state.User{Name: name, Data: map[string]string{"password": password(24)}}
	if v := opts["password"]; v != "" {
		u.Data["password"] = v
	}
	s.Users = append(s.Users, u)
	if s.Installed {
		// Без перезапуска: команда авторизации читает auth.json при каждом подключении.
		if err := h.writeAuth(s); err != nil {
			s.RemoveUser(name)
			return nil, err
		}
	}
	return u, nil
}

func (h *Hysteria) DelUser(env *module.Env, s *state.Service, name string) error {
	if !s.RemoveUser(name) {
		return fmt.Errorf("нет пользователя %s", name)
	}
	if err := h.writeAuth(s); err != nil {
		return err
	}
	h.kick(s, name) // разорвать уже открытые сессии удалённого пользователя
	return nil
}

// kick разрывает сессии пользователя через trafficStats API.
func (h *Hysteria) kick(s *state.Service, ids ...string) {
	body, _ := json.Marshal(ids)
	req, _ := http.NewRequest("POST", "http://"+hyStats+"/kick", strings.NewReader(string(body)))
	req.Header.Set("Authorization", s.Secrets["stats_secret"])
	req.Header.Set("Content-Type", "application/json")
	if resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req); err == nil {
		resp.Body.Close()
	}
}

// Prefetch скачивает Hysteria заранее.
func (h *Hysteria) Prefetch(env *module.Env, s *state.Service) error {
	_, err := h.download(env)
	return err
}

// Rollback возвращает предыдущую версию Hysteria.
func (h *Hysteria) Rollback(env *module.Env, s *state.Service, prev string) error {
	tag, err := restoreBin(h.bin())
	if err != nil {
		return err
	}
	s.Version = firstNonEmpty(tag, prev)
	return h.Apply(env, s)
}

func (h *Hysteria) Artifacts(env *module.Env, s *state.Service, u *state.User) ([]module.Artifact, error) {
	q := url.Values{}
	hostName := env.Stack.PublicIP
	if d := s.P("domain"); d != "" {
		hostName = d
		q.Set("sni", d)
	} else {
		q.Set("sni", firstNonEmpty(s.P("sni"), "bing.com"))
		q.Set("insecure", "1")
		q.Set("pinSHA256", s.Secrets["pin_sha256"])
	}
	if boolP(s, "obfs") {
		q.Set("obfs", firstNonEmpty(s.P("obfs_type"), "salamander"))
		q.Set("obfs-password", s.Secrets["obfs_password"])
	}
	auth := url.UserPassword(hyLogin(u), u.Data["password"]).String()
	if u.Data["legacy"] == "1" {
		// Перенятый общий пароль: в ссылке только пароль, как было у клиентов.
		auth = url.User(u.Data["password"]).String()
	}
	link := fmt.Sprintf("hysteria2://%s@%s:%s/?%s#%s", auth, hostName, s.P("port"), q.Encode(), url.PathEscape(u.Name))
	return []module.Artifact{{Kind: "uri", Title: "Ссылка Hysteria 2 (Hiddify, NekoBox, v2rayN, Streisand, Karing)", Value: link, QR: true}}, nil
}

func (h *Hysteria) UserTraffic(env *module.Env, s *state.Service) (map[string]module.Traffic, error) {
	req, _ := http.NewRequest("GET", "http://"+hyStats+"/traffic", nil)
	req.Header.Set("Authorization", s.Secrets["stats_secret"])
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var m map[string]struct{ Tx, Rx uint64 }
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	out := map[string]module.Traffic{}
	for k, v := range m {
		out[k] = module.Traffic{Rx: v.Rx, Tx: v.Tx}
	}
	return out, nil
}
