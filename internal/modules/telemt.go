package modules

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Telemt — MTProto-прокси для Telegram (Rust, fake-TLS, маскировка).
// За общим входом слушает 127.0.0.1:10444 и принимает PROXY v2; не-MTProxy
// соединения (сканеры) отдаёт Caddy с настоящим сертификатом своего домена.
type Telemt struct{ base }

const (
	telemtRepo  = "telemt/telemt"
	telemtLocal = 10444
	telemtAPI   = "127.0.0.1:9091"
)

func init() {
	module.Register(&Telemt{base{id: "telemt", title: "MTProto (telemt)", order: 60,
		desc:  "Прокси Telegram: fake-TLS, маскировка под сайт, квоты пользователей",
		units: []string{"vpnstack-telemt.service"}}})
}

func (t *Telemt) Params() []module.Param {
	return []module.Param{
		{Key: "tls_domain", Label: "Домен fake-TLS", Type: module.TDomain, Required: true, Restart: true,
			Help: "Лучше свой поддомен с A-записью на сервер: проверяющим отдаётся настоящий сайт Caddy. Можно и чужой сайт. Смена домена меняет все ссылки."},
		{Key: "port", Label: "Порт (режим отдельных портов)", Type: module.TPort, Advanced: true, Restart: true},
		{Key: "ad_tag", Label: "ad_tag от @MTProxybot", Type: module.TString, Advanced: true},
		{Key: "middle_proxy", Label: "Через middle-proxy Telegram", Type: module.TBool, Advanced: true,
			Help: "Нужно для ad_tag. Выключение — прямое подключение к DC (быстрее)."},
		{Key: "legacy_tcp", Label: "Старые TCP-порты → общий вход", Type: module.TList, Advanced: true, Restart: true,
			Help: "Порты прежней установки: перенаправляются на 443, старые ссылки продолжают работать."},
	}
}

func (t *Telemt) AutoDefaults(env *module.Env, s *state.Service) error {
	s.Default("port", "2083")
	s.Default("middle_proxy", "true")
	if s.P("tls_domain") == "" {
		return fmt.Errorf("telemt: нужен домен fake-TLS (tls_domain)")
	}
	s.Secret("api_token", func() string { return sys.RandHex(24) })
	s.Params["own_domain"] = strconv.FormatBool(t.ownDomain(env, s))
	return nil
}

// ownDomain — домен указывает на этот сервер (тогда маскируемся своим Caddy).
func (t *Telemt) ownDomain(env *module.Env, s *state.Service) bool {
	ok, _ := sys.DNSPointsHere(s.P("tls_domain"), env.Stack.PublicIP)
	return ok
}

func (t *Telemt) Needs(env *module.Env, s *state.Service) []module.Need {
	n := []module.Need{{Proto: "tcp", Port: 9091, Purpose: "telemt API"}}
	if env.EdgeEnabled {
		n = append(n, module.Need{Proto: "tcp", Port: telemtLocal, Purpose: "telemt за общим входом",
			Edge: &module.EdgeRoute{SNI: []string{s.P("tls_domain")}, Backend: fmt.Sprintf("127.0.0.1:%d", telemtLocal), ProxyProtocol: true, Priority: 60}})
		n = append(n, legacyNeeds(s, "telemt")...)
	} else {
		n = append(n, module.Need{Proto: "tcp", Port: atoi(s.P("port")), Public: true, Param: "port", Purpose: "telemt"})
	}
	return n
}

func (t *Telemt) CaddySites(env *module.Env, s *state.Service) []module.CaddySite {
	if s.Params["own_domain"] == "true" {
		return []module.CaddySite{{Host: s.P("tls_domain"), Order: 60}}
	}
	return nil
}

func (t *Telemt) Latest(env *module.Env) (string, error) { return latestTag(env, telemtRepo) }

func (t *Telemt) bin() string { return filepath.Join(BinDir, "telemt") }

func (t *Telemt) download(env *module.Env) (string, error) {
	tag, err := t.Latest(env)
	if err != nil {
		return "", err
	}
	if haveBin(t.bin(), tag) {
		return tag, nil
	}
	rel, err := sys.ReleaseByTag(telemtRepo, tag)
	if err != nil {
		return "", err
	}
	a := "x86_64"
	if arch() == "arm64" {
		a = "aarch64"
	}
	name := fmt.Sprintf("telemt-%s-linux-gnu.tar.gz", a)
	f, ok := rel.Find(name)
	sf, ok2 := rel.Find(name + ".sha256")
	if !ok || !ok2 {
		return "", fmt.Errorf("в релизе telemt %s нет %s или .sha256", tag, name)
	}
	txt, err := sys.FetchText(sf.URL)
	if err != nil {
		return "", err
	}
	sum := sys.ChecksumFor(txt, name)
	if sum == "" {
		sum = sys.ChecksumFor(txt, "")
	}
	tmp := filepath.Join("/tmp", name)
	if err := sys.DownloadVerified(f.URL, tmp, sum); err != nil {
		return "", err
	}
	if err := sys.ExtractFile(tmp, "telemt", t.bin()+".new", 0o755); err != nil {
		return "", err
	}
	return tag, installBin(t.bin()+".new", t.bin(), tag)
}

func (t *Telemt) cfgPath() string { return filepath.Join(t.cfgDir(), "telemt.toml") }

func tq(s string) string { return strconv.Quote(s) }

func (t *Telemt) render(env *module.Env, s *state.Service) string {
	var b strings.Builder
	b.WriteString("# Сгенерировано vpnstack\n[general]\n")
	fmt.Fprintf(&b, "use_middle_proxy = %t\nlog_level = \"normal\"\n", boolP(s, "middle_proxy"))
	if v := s.P("ad_tag"); v != "" {
		fmt.Fprintf(&b, "ad_tag = %s\n", tq(v))
	}
	b.WriteString("\n[general.modes]\nclassic = false\nsecure = false\ntls = true\n")
	fmt.Fprintf(&b, "\n[general.links]\nshow = \"*\"\npublic_host = %s\npublic_port = %d\n", tq(t.linkHost(env, s)), publicPort(env, s, "port"))
	b.WriteString("\n[server]\n")
	if env.EdgeEnabled {
		fmt.Fprintf(&b, "port = %d\nproxy_protocol = true\nproxy_protocol_trusted_cidrs = [\"127.0.0.1/32\"]\n", telemtLocal)
	} else {
		fmt.Fprintf(&b, "port = %s\n", s.P("port"))
	}
	fmt.Fprintf(&b, "\n[server.api]\nenabled = true\nlisten = %s\nwhitelist = [\"127.0.0.1/32\"]\nauth_header = %s\n", tq(telemtAPI), tq(s.Secrets["api_token"]))
	b.WriteString("\n[[server.listeners]]\n")
	if env.EdgeEnabled {
		b.WriteString("ip = \"127.0.0.1\"\n")
	} else {
		b.WriteString("ip = \"0.0.0.0\"\n")
	}
	fmt.Fprintf(&b, "\n[censorship]\ntls_domain = %s\nmask = true\ntls_emulation = true\ntls_front_dir = %s\n", tq(s.P("tls_domain")), tq(filepath.Join(t.dataDir(), "tlsfront")))
	if s.Params["own_domain"] == "true" {
		port := 443
		if env.EdgeEnabled {
			port = CaddyInternalPort
		}
		fmt.Fprintf(&b, "mask_host = \"127.0.0.1\"\nmask_port = %d\n", port)
	}
	b.WriteString("\n[access.users]\n")
	for _, u := range s.Users {
		fmt.Fprintf(&b, "%s = %s\n", tq(u.Name), tq(u.Data["secret"]))
	}
	// Перенятые лимиты/квоты пользователей ([access.user_*]) — как были.
	if v := strings.TrimSpace(s.P("access_extra")); v != "" {
		b.WriteString("\n" + v + "\n")
	}
	return b.String()
}

func (t *Telemt) linkHost(env *module.Env, s *state.Service) string {
	if s.Params["own_domain"] == "true" {
		return s.P("tls_domain")
	}
	return env.Stack.PublicIP
}

func (t *Telemt) write(env *module.Env, s *state.Service) error {
	if t.ownDomain(env, s) {
		s.Params["own_domain"] = "true"
	} else {
		s.Params["own_domain"] = "false"
	}
	if err := sys.WriteFileAtomic(t.cfgPath(), []byte(t.render(env, s)), 0o640); err != nil {
		return err
	}
	_, _ = sys.Run("chgrp", "telemt", t.cfgPath())
	return nil
}

func (t *Telemt) Install(env *module.Env, s *state.Service) error {
	ensureUser("telemt")
	tag, err := t.download(env)
	if err != nil {
		return err
	}
	s.Version = tag
	_, _ = sys.Run("install", "-d", "-m", "0750", "-g", "telemt", t.cfgDir())
	_, _ = sys.Run("install", "-d", "-m", "0750", "-o", "telemt", "-g", "telemt", t.dataDir())
	if err := t.write(env, s); err != nil {
		return err
	}
	unit := serviceUnit(t.id, t.title, t.bin()+" "+t.cfgPath(), `User=telemt
Group=telemt
WorkingDirectory=`+t.dataDir()+`
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=true
`)
	if err := installUnit(t.id, t.title, t.units[0], unit); err != nil {
		return err
	}
	return waitActive(t.units[0], 15e9)
}

func (t *Telemt) Apply(env *module.Env, s *state.Service) error {
	if err := t.write(env, s); err != nil {
		return err
	}
	if err := sys.Systemctl("restart", t.units[0]); err != nil {
		return err
	}
	return waitActive(t.units[0], 15e9)
}

func (t *Telemt) Remove(env *module.Env, s *state.Service, purge bool) error {
	removeUnits(t.id, t.units...)
	if purge {
		_, _ = sys.Run("rm", "-rf", t.cfgDir(), t.dataDir(), t.bin(), t.bin()+".prev")
	}
	return nil
}

func (t *Telemt) Status(env *module.Env, s *state.Service) module.Status {
	return unitsStatus(s, t.units)
}

func (t *Telemt) Update(env *module.Env, s *state.Service) error {
	tag, err := t.download(env)
	if err != nil {
		return err
	}
	s.Version = tag
	return t.Apply(env, s)
}

// Prefetch скачивает telemt заранее.
func (t *Telemt) Prefetch(env *module.Env, s *state.Service) error {
	_, err := t.download(env)
	return err
}

// Rollback возвращает предыдущую версию telemt.
func (t *Telemt) Rollback(env *module.Env, s *state.Service, prev string) error {
	tag, err := restoreBin(t.bin())
	if err != nil {
		return err
	}
	s.Version = firstNonEmpty(tag, prev)
	return t.Apply(env, s)
}

func (t *Telemt) ConfigFiles(*state.Service) []string { return []string{t.cfgPath()} }

func (t *Telemt) AddUser(env *module.Env, s *state.Service, name string, opts map[string]string) (*state.User, error) {
	u := &state.User{Name: name, Data: map[string]string{"secret": sys.RandHex(16)}}
	s.Users = append(s.Users, u)
	if s.Installed {
		if err := t.reload(env, s); err != nil {
			s.RemoveUser(name)
			return nil, err
		}
	}
	return u, nil
}

func (t *Telemt) DelUser(env *module.Env, s *state.Service, name string) error {
	if !s.RemoveUser(name) {
		return fmt.Errorf("нет пользователя %s", name)
	}
	return t.reload(env, s)
}

// reload — пользователи и квоты telemt применяются на лету (hot reload по inotify/SIGHUP),
// без разрыва соединений остальных.
func (t *Telemt) reload(env *module.Env, s *state.Service) error {
	if err := t.write(env, s); err != nil {
		return err
	}
	if !sys.Active(t.units[0]) {
		return t.Apply(env, s)
	}
	return sys.Systemctl("kill", "-s", "HUP", t.units[0])
}

// Artifacts — ссылка fake-TLS: секрет = "ee" + 16 байт + домен в hex.
func (t *Telemt) Artifacts(env *module.Env, s *state.Service, u *state.User) ([]module.Artifact, error) {
	secret := "ee" + u.Data["secret"] + hex.EncodeToString([]byte(s.P("tls_domain")))
	q := url.Values{}
	q.Set("server", t.linkHost(env, s))
	q.Set("port", itoa(publicPort(env, s, "port")))
	q.Set("secret", secret)
	return []module.Artifact{
		{Kind: "uri", Title: "Ссылка для Telegram", Value: "tg://proxy?" + q.Encode(), QR: true},
		{Kind: "uri", Title: "Веб-ссылка", Value: "https://t.me/proxy?" + q.Encode()},
	}, nil
}

// UserTraffic — telemt отдаёт только суммарный трафик (в обе стороны): пишем его в Tx.
func (t *Telemt) UserTraffic(env *module.Env, s *state.Service) (map[string]module.Traffic, error) {
	req, _ := http.NewRequest("GET", "http://"+telemtAPI+"/v1/users", nil)
	req.Header.Set("Authorization", s.Secrets["api_token"])
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		OK   bool `json:"ok"`
		Data []struct {
			Username    string `json:"username"`
			TotalOctets uint64 `json:"total_octets"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	out := map[string]module.Traffic{}
	for _, u := range r.Data {
		out[u.Username] = module.Traffic{Tx: u.TotalOctets}
	}
	return out, nil
}
