package modules

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Xray — VLESS + REALITY (XTLS Vision). Ключи генерируются в Go (X25519).
type Xray struct{ base }

const (
	xrayRepo    = "XTLS/Xray-core"
	xrayLocal   = 10443
	xrayAPI     = "127.0.0.1:10085"
	xrayFlow    = "xtls-rprx-vision"
	xrayInbound = "vless-reality"
)

var xrayDir = "/opt/vpnstack/xray"

func init() {
	module.Register(&Xray{base{id: "xray", title: "VLESS + REALITY (Xray)", order: 30,
		desc:  "Xray-core: VLESS, XTLS Vision, REALITY — маскировка под чужой TLS-сайт",
		units: []string{"vpnstack-xray.service"}}})
}

func (x *Xray) Params() []module.Param {
	return []module.Param{
		{Key: "sni", Label: "SNI REALITY", Type: module.TDomain, Required: true,
			Help: "Чужой сайт с TLS 1.3 и HTTP/2, под который маскируется соединение (не ваш домен)."},
		{Key: "target", Label: "Цель REALITY (host:port)", Type: module.TString, Advanced: true,
			Help: "Куда пересылаются проверяющие. По умолчанию <SNI>:443."},
		{Key: "fingerprint", Label: "uTLS-отпечаток клиента", Type: module.TSelect, Advanced: true,
			Options: []string{"chrome", "firefox", "safari", "edge", "random"}},
		{Key: "port", Label: "Порт (режим отдельных портов)", Type: module.TPort, Advanced: true, Restart: true},
	}
}

func (x *Xray) AutoDefaults(env *module.Env, s *state.Service) error {
	s.Default("sni", "www.microsoft.com")
	s.Default("target", s.P("sni")+":443")
	s.Default("fingerprint", "chrome")
	s.Default("port", "2053")
	s.Secret("private_key", func() string {
		p, _ := x25519()
		return base64.RawURLEncoding.EncodeToString(p)
	})
	s.Secret("short_id", func() string { return sys.RandHex(8) })
	return nil
}

func (x *Xray) Needs(env *module.Env, s *state.Service) []module.Need {
	n := []module.Need{{Proto: "tcp", Port: 10085, Purpose: "Xray API (статистика)"}}
	if env.EdgeEnabled {
		n = append(n, module.Need{Proto: "tcp", Port: xrayLocal, Purpose: "Xray REALITY за общим входом",
			Edge: &module.EdgeRoute{SNI: []string{s.P("sni")}, Backend: fmt.Sprintf("127.0.0.1:%d", xrayLocal), ProxyProtocol: true, Priority: 50}})
	} else {
		n = append(n, module.Need{Proto: "tcp", Port: atoi(s.P("port")), Public: true, Param: "port", Purpose: "Xray REALITY"})
	}
	return n
}

func (x *Xray) Latest(env *module.Env) (string, error) { return latestTag(env, xrayRepo) }

func (x *Xray) asset() string {
	if arch() == "arm64" {
		return "Xray-linux-arm64-v8a.zip"
	}
	return "Xray-linux-64.zip"
}

func (x *Xray) download(env *module.Env) (string, error) {
	tag, err := x.Latest(env)
	if err != nil {
		return "", err
	}
	rel, err := sys.ReleaseByTag(xrayRepo, tag)
	if err != nil {
		return "", err
	}
	a, ok := rel.Find(x.asset())
	d, ok2 := rel.Find(x.asset() + ".dgst")
	if !ok || !ok2 {
		return "", fmt.Errorf("в релизе Xray %s нет %s или .dgst", tag, x.asset())
	}
	dg, err := sys.FetchText(d.URL)
	if err != nil {
		return "", err
	}
	tmp := filepath.Join("/tmp", x.asset())
	if err := sys.DownloadVerified(a.URL, tmp, sys.ChecksumFor(dg, "")); err != nil {
		return "", err
	}
	for _, f := range []string{"geoip.dat", "geosite.dat"} {
		if err := sys.ExtractFile(tmp, f, filepath.Join(xrayDir, f), 0o644); err != nil {
			return "", err
		}
	}
	bin := filepath.Join(xrayDir, "xray")
	if err := sys.ExtractFile(tmp, "xray", bin+".new", 0o755); err != nil {
		return "", err
	}
	return tag, sys.InstallBinary(bin+".new", bin)
}

func (x *Xray) cfgPath() string { return filepath.Join(x.cfgDir(), "config.json") }

func (x *Xray) config(env *module.Env, s *state.Service) map[string]any {
	clients := []map[string]any{}
	for _, u := range s.Users {
		clients = append(clients, map[string]any{"id": u.Data["uuid"], "flow": xrayFlow, "email": u.Name})
	}
	listen, port := "127.0.0.1", xrayLocal
	sockopt := map[string]any{"acceptProxyProtocol": true}
	if !env.EdgeEnabled {
		listen, port = "0.0.0.0", atoi(s.P("port"))
		sockopt = map[string]any{}
	}
	return map[string]any{
		"log":   map[string]any{"loglevel": "warning"},
		"api":   map[string]any{"tag": "api", "listen": xrayAPI, "services": []string{"HandlerService", "StatsService"}},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		"inbounds": []any{map[string]any{
			"tag": xrayInbound, "listen": listen, "port": port, "protocol": "vless",
			"settings": map[string]any{"clients": clients, "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "raw", "security": "reality",
				"realitySettings": map[string]any{
					"target": s.P("target"), "serverNames": []string{s.P("sni")},
					"privateKey": s.Secrets["private_key"], "shortIds": []string{s.Secrets["short_id"]},
				},
				"sockopt": sockopt,
			},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		}},
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "tag": "direct"},
			map[string]any{"protocol": "blackhole", "tag": "block"},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"ip": []string{"geoip:private"}, "outboundTag": "block"},
			map[string]any{"protocol": []string{"bittorrent"}, "outboundTag": "block"},
		}},
	}
}

func (x *Xray) write(env *module.Env, s *state.Service) error {
	b, _ := json.MarshalIndent(x.config(env, s), "", "  ")
	if err := sys.WriteFileAtomic(x.cfgPath(), b, 0o640); err != nil {
		return err
	}
	_, _ = sys.Run("chgrp", "nogroup", x.cfgPath())
	if _, err := sys.Run(filepath.Join(xrayDir, "xray"), "run", "-test", "-c", x.cfgPath()); err != nil {
		return fmt.Errorf("конфигурация Xray не прошла проверку: %w", err)
	}
	return nil
}

func (x *Xray) Install(env *module.Env, s *state.Service) error {
	tag, err := x.download(env)
	if err != nil {
		return err
	}
	s.Version = tag
	if err := x.write(env, s); err != nil {
		return err
	}
	unit := serviceUnit(x.id, x.title, filepath.Join(xrayDir, "xray")+" run -c "+x.cfgPath(), `User=nobody
Group=nogroup
Environment=XRAY_LOCATION_ASSET=`+xrayDir+`
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
`)
	if err := installUnit(x.id, x.title, x.units[0], unit); err != nil {
		return err
	}
	return waitActive(x.units[0], 10e9)
}

func (x *Xray) Apply(env *module.Env, s *state.Service) error {
	if err := x.write(env, s); err != nil {
		return err
	}
	if err := sys.Systemctl("restart", x.units[0]); err != nil {
		return err
	}
	return waitActive(x.units[0], 10e9)
}

func (x *Xray) Remove(env *module.Env, s *state.Service, purge bool) error {
	removeUnits(x.id, x.units...)
	if purge {
		_, _ = sys.Run("rm", "-rf", xrayDir, x.cfgDir())
	}
	return nil
}

func (x *Xray) Status(env *module.Env, s *state.Service) module.Status {
	return unitsStatus(s, x.units)
}

func (x *Xray) Update(env *module.Env, s *state.Service) error {
	tag, err := x.download(env)
	if err != nil {
		return err
	}
	s.Version = tag
	return x.Apply(env, s)
}

func (x *Xray) ConfigFiles(*state.Service) []string { return []string{x.cfgPath()} }

// --- пользователи ---

func (x *Xray) AddUser(env *module.Env, s *state.Service, name string, opts map[string]string) (*state.User, error) {
	u := &state.User{Name: name, Data: map[string]string{"uuid": uuid4()}}
	if v := opts["uuid"]; v != "" {
		u.Data["uuid"] = v
	}
	s.Users = append(s.Users, u)
	if s.Installed {
		if err := x.Apply(env, s); err != nil {
			s.RemoveUser(name)
			return nil, err
		}
	}
	return u, nil
}

func (x *Xray) DelUser(env *module.Env, s *state.Service, name string) error {
	if !s.RemoveUser(name) {
		return fmt.Errorf("нет пользователя %s", name)
	}
	return x.Apply(env, s)
}

func (x *Xray) Artifacts(env *module.Env, s *state.Service, u *state.User) ([]module.Artifact, error) {
	pub, err := realityPub(s.Secrets["private_key"])
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", xrayFlow)
	q.Set("security", "reality")
	q.Set("sni", s.P("sni"))
	q.Set("fp", s.P("fingerprint"))
	q.Set("pbk", pub)
	q.Set("sid", s.Secrets["short_id"])
	q.Set("type", "tcp")
	link := fmt.Sprintf("vless://%s@%s:%d?%s#%s", u.Data["uuid"], env.Stack.PublicIP, publicPort(env, s, "port"), q.Encode(), url.PathEscape(u.Name))
	return []module.Artifact{{Kind: "uri", Title: "Ссылка VLESS (v2rayN, v2rayNG, Hiddify, Streisand, NekoBox)", Value: link, QR: true}}, nil
}

// UserTraffic читает накопительные счётчики через `xray api statsquery`.
func (x *Xray) UserTraffic(env *module.Env, s *state.Service) (map[string]module.Traffic, error) {
	out, err := sys.Output(filepath.Join(xrayDir, "xray"), "api", "statsquery", "--server="+xrayAPI)
	if err != nil {
		return nil, err
	}
	var r struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return nil, err
	}
	res := map[string]module.Traffic{}
	for _, st := range r.Stat {
		p := strings.Split(st.Name, ">>>")
		if len(p) != 4 || p[0] != "user" {
			continue
		}
		v, _ := strconv.ParseUint(strings.Trim(string(st.Value), `"`), 10, 64)
		t := res[p[1]]
		if p[3] == "uplink" {
			t.Rx += v
		} else {
			t.Tx += v
		}
		res[p[1]] = t
	}
	return res, nil
}
