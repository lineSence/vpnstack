package modules

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Caddy — общий веб-сервер: единственный ACME-клиент стека, сайты-прикрытия,
// обратный прокси для TG WEB proxy. В режиме общего входа слушает 127.0.0.1:7443
// (через edge, с PROXY v2) и TCP 80 (ACME HTTP-01 и редирект).
type Caddy struct{ base }

// Внутренний HTTPS-порт Caddy в режиме общего входа.
const CaddyInternalPort = 7443

const caddyRepo = "caddyserver/caddy"

func init() {
	module.Register(&Caddy{base{id: "caddy", title: "Caddy", order: 10,
		desc:  "Веб-сервер: сертификаты Let's Encrypt, сайты-прикрытия, прокси для TG WEB",
		units: []string{"vpnstack-caddy.service"}}})
}

func (c *Caddy) Core() bool { return true }

func (c *Caddy) Params() []module.Param { return nil }

func (c *Caddy) AutoDefaults(env *module.Env, s *state.Service) error { return nil }

func (c *Caddy) Needs(env *module.Env, s *state.Service) []module.Need {
	n := []module.Need{{Proto: "tcp", Port: 80, Public: true, Purpose: "Caddy: ACME HTTP-01 и редирект на HTTPS"},
		{Proto: "tcp", Port: 2029, Purpose: "Caddy admin API"}}
	if env.EdgeEnabled {
		n = append(n, module.Need{Proto: "tcp", Port: CaddyInternalPort, Purpose: "Caddy HTTPS за общим входом",
			Edge: &module.EdgeRoute{SNI: c.domains(env), Backend: fmt.Sprintf("127.0.0.1:%d", CaddyInternalPort), ProxyProtocol: true, Default: true, Priority: 10}})
	} else {
		n = append(n, module.Need{Proto: "tcp", Port: 443, Public: true, Purpose: "Caddy HTTPS"})
	}
	return n
}

func (c *Caddy) domains(env *module.Env) []string {
	var d []string
	if env.Sites != nil {
		for _, s := range env.Sites() {
			d = append(d, s.Host)
		}
	}
	return d
}

func (c *Caddy) Latest(env *module.Env) (string, error) { return latestTag(env, caddyRepo) }

func (c *Caddy) bin() string { return filepath.Join(BinDir, "caddy") }

func (c *Caddy) download(env *module.Env) (string, error) {
	tag, err := c.Latest(env)
	if err != nil {
		return "", err
	}
	rel, err := sys.ReleaseByTag(caddyRepo, tag)
	if err != nil {
		return "", err
	}
	v := strings.TrimPrefix(tag, "v")
	name := fmt.Sprintf("caddy_%s_linux_%s.tar.gz", v, arch())
	a, ok := rel.Find(name)
	if !ok {
		return "", fmt.Errorf("в релизе Caddy %s нет %s", tag, name)
	}
	sumA, ok := rel.Find(fmt.Sprintf("caddy_%s_checksums.txt", v))
	if !ok {
		return "", fmt.Errorf("в релизе Caddy %s нет файла сумм", tag)
	}
	sums, err := sys.FetchText(sumA.URL)
	if err != nil {
		return "", err
	}
	tmp := filepath.Join("/tmp", name)
	if err := sys.DownloadVerified(a.URL, tmp, sys.ChecksumFor(sums, name)); err != nil {
		return "", err
	}
	if err := sys.ExtractFile(tmp, "caddy", c.bin()+".new", 0o755); err != nil {
		return "", err
	}
	if err := sys.InstallBinary(c.bin()+".new", c.bin()); err != nil {
		return "", err
	}
	return tag, nil
}

func (c *Caddy) Install(env *module.Env, s *state.Service) error {
	ensureUser("caddy")
	tag, err := c.download(env)
	if err != nil {
		return err
	}
	s.Version = tag
	if _, err := sys.Run("install", "-d", "-o", "caddy", "-g", "caddy", "-m", "0750", c.dataDir()); err != nil {
		return err
	}
	_, _ = sys.Run("install", "-d", "-o", "root", "-g", "caddy", "-m", "0750", c.cfgDir())
	ensureSite()
	if err := c.writeConfig(env); err != nil {
		return err
	}
	unit := serviceUnit(c.id, "Caddy", c.bin()+" run --environ --config "+c.caddyfile(), `Type=notify
User=caddy
Group=caddy
Environment=HOME=`+c.dataDir()+`
Environment=XDG_DATA_HOME=`+c.dataDir()+`
Environment=XDG_CONFIG_HOME=`+c.cfgDir()+`
ExecReload=`+c.bin()+` reload --config `+c.caddyfile()+` --force
TimeoutStopSec=10s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
`)
	if err := installUnit(c.id, c.title, c.units[0], unit); err != nil {
		return err
	}
	return waitActive(c.units[0], 20e9)
}

func (c *Caddy) caddyfile() string { return filepath.Join(c.cfgDir(), "Caddyfile") }

// Render собирает Caddyfile из сайтов сервисов.
func (c *Caddy) Render(env *module.Env) string {
	var b strings.Builder
	httpsPort := 443
	if env.EdgeEnabled {
		httpsPort = CaddyInternalPort
	}
	fmt.Fprintf(&b, "# Сгенерировано vpnstack — изменения будут перезаписаны.\n{\n")
	if env.Stack.Email != "" {
		fmt.Fprintf(&b, "\temail %s\n", env.Stack.Email)
	}
	fmt.Fprintf(&b, "\tadmin 127.0.0.1:2029\n\thttp_port 80\n\thttps_port %d\n", httpsPort)
	fmt.Fprintf(&b, "\tservers :%d {\n", httpsPort)
	if env.EdgeEnabled {
		b.WriteString("\t\tlistener_wrappers {\n\t\t\tproxy_protocol {\n\t\t\t\ttimeout 5s\n\t\t\t\tallow 127.0.0.1/32\n\t\t\t}\n\t\t\ttls\n\t\t}\n")
	}
	// HTTP/3 выключен: UDP 443 занят Hysteria. Таймауты — как в tproxy-server
	// (read_body выше long-poll 25 с).
	b.WriteString("\t\tprotocols h1 h2\n\t\ttimeouts {\n\t\t\tread_header 10s\n\t\t\tread_body 60s\n\t\t}\n\t}\n}\n")
	var sites []module.CaddySite
	if env.Sites != nil {
		sites = env.Sites()
	}
	sort.SliceStable(sites, func(i, j int) bool { return sites[i].Order < sites[j].Order })
	seen := map[string]bool{}
	for _, s := range sites {
		if s.Host == "" || seen[s.Host] {
			continue
		}
		seen[s.Host] = true
		blk := s.Block
		if strings.TrimSpace(blk) == "" {
			blk = CoverBlock()
		}
		fmt.Fprintf(&b, "\n%s {\n%s\n}\n", s.Host, indent(blk))
	}
	return b.String()
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = "\t" + l
		}
	}
	return strings.Join(lines, "\n")
}

func (c *Caddy) writeConfig(env *module.Env) error {
	cf := c.Render(env)
	if err := sys.WriteFileAtomic(c.caddyfile(), []byte(cf), 0o640); err != nil {
		return err
	}
	_, _ = sys.Run("chgrp", "caddy", c.caddyfile())
	if sys.Exists(c.bin()) {
		if _, err := sys.Run(c.bin(), "validate", "--config", c.caddyfile(), "--adapter", "caddyfile"); err != nil {
			return fmt.Errorf("Caddyfile не прошёл проверку: %w", err)
		}
	}
	return nil
}

func (c *Caddy) Apply(env *module.Env, s *state.Service) error {
	if err := c.writeConfig(env); err != nil {
		return err
	}
	if sys.Active(c.units[0]) {
		return sys.Systemctl("reload", c.units[0])
	}
	return sys.Systemctl("restart", c.units[0])
}

func (c *Caddy) Remove(env *module.Env, s *state.Service, purge bool) error {
	removeUnits(c.id, c.units...)
	if purge {
		_, _ = sys.Run("rm", "-rf", c.dataDir(), c.cfgDir(), c.bin(), c.bin()+".prev")
	}
	return nil
}

func (c *Caddy) Status(env *module.Env, s *state.Service) module.Status {
	return unitsStatus(s, c.units)
}

func (c *Caddy) Update(env *module.Env, s *state.Service) error {
	tag, err := c.download(env)
	if err != nil {
		return err
	}
	s.Version = tag
	if err := sys.Systemctl("restart", c.units[0]); err != nil {
		return err
	}
	return waitActive(c.units[0], 20e9)
}

func (c *Caddy) ConfigFiles(*state.Service) []string { return []string{c.caddyfile()} }

// CaddyCertPaths ищет сертификат, выпущенный Caddy для домена.
func CaddyCertPaths(domain string) (string, string, bool) {
	m, _ := filepath.Glob(filepath.Join(DataDir, "caddy", "caddy", "certificates", "*", domain, domain+".crt"))
	for _, crt := range m {
		key := strings.TrimSuffix(crt, ".crt") + ".key"
		if sys.Exists(key) {
			return crt, key, true
		}
	}
	return "", "", false
}
