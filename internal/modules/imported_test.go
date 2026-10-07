package modules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lineSence/vpnstack/internal/state"
)

// Сервисы, перенятые из старых установок, должны отдавать прежние ключи и ссылки.

func TestXrayImported(t *testing.T) {
	x := &Xray{}
	env := testEnv()
	s := &state.Service{
		Params: map[string]string{"sni": "www.microsoft.com", "server_names": "microsoft.com", "target": "www.microsoft.com:443",
			"port": "8443", "legacy_tcp": "8443", "fingerprint": "chrome"},
		Secrets: map[string]string{"private_key": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvMTI", "short_id": "abcd", "short_ids": `["","abcd"]`},
		Users: []*state.User{
			{Name: "a", Data: map[string]string{"uuid": "11111111-1111-1111-1111-111111111111", "flow": "xtls-rprx-vision", "imported": "1"}},
			{Name: "b", Data: map[string]string{"uuid": "22222222-2222-2222-2222-222222222222", "flow": "", "imported": "1"}},
		},
	}
	if err := x.AutoDefaults(env, s); err != nil {
		t.Fatal(err)
	}
	if s.Secrets["private_key"] != "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvMTI" || s.Secrets["short_id"] != "abcd" {
		t.Fatal("AutoDefaults перезаписал импортированные ключи")
	}
	b, _ := json.Marshal(x.config(env, s))
	cfg := string(b)
	for _, want := range []string{`"serverNames":["www.microsoft.com","microsoft.com"]`, `"shortIds":["abcd",""]`, `"flow":"xtls-rprx-vision"`, `"id":"22222222-2222-2222-2222-222222222222"`} {
		if !strings.Contains(cfg, want) {
			t.Errorf("нет %s в %s", want, cfg)
		}
	}
	if strings.Count(cfg, "xtls-rprx-vision") != 1 {
		t.Errorf("flow пустого клиента должен остаться пустым: %s", cfg)
	}
	a, _ := x.Artifacts(env, s, s.Users[1])
	if strings.Contains(a[0].Value, "flow=") || !strings.Contains(a[0].Value, "sid=abcd") {
		t.Errorf("ссылка: %s", a[0].Value)
	}
	for _, n := range x.Needs(env, s) {
		if n.Port == 8443 && !n.Redirect {
			t.Errorf("старый порт 8443 должен перенаправляться на общий вход: %+v", n)
		}
	}

	g := &state.Service{Params: map[string]string{"sni": "a.com", "target": "a.com:443",
		"stream_json": `{"network":"xhttp","xhttpSettings":{"path":"/p","mode":"auto"}}`, "xhttp_path": "/p", "xhttp_mode": "auto"},
		Secrets: map[string]string{"private_key": s.Secrets["private_key"], "short_id": "01"}}
	_ = x.AutoDefaults(env, g)
	u, _ := x.AddUser(env, g, "c", nil)
	b, _ = json.Marshal(x.config(env, g))
	if !strings.Contains(string(b), `"network":"xhttp"`) || !strings.Contains(string(b), `"path":"/p"`) {
		t.Errorf("транспорт не сохранён: %s", b)
	}
	a, _ = x.Artifacts(env, g, u)
	if !strings.Contains(a[0].Value, "type=xhttp") || !strings.Contains(a[0].Value, "path=%2Fp") {
		t.Errorf("ссылка xhttp: %s", a[0].Value)
	}
}

func TestAWGImported(t *testing.T) {
	a := &AWG{}
	env := testEnv()
	s := &state.Service{
		Params: map[string]string{"subnet": "10.8.1.0/24", "port": "51820", "mtu": "1420", "awg_version": "1.5",
			"jc": "4", "jmin": "10", "jmax": "50", "s1": "20", "s2": "30", "s3": "0", "s4": "0", "h1": "1111", "h2": "2222", "h3": "3333", "h4": "4444",
			"iface_extra": "Itime = 120"},
		Secrets: map[string]string{"private_key": "SERVERKEY"},
		Users: []*state.User{
			{Name: "phone", Data: map[string]string{"public_key": "PUB1", "psk": "PSK1", "ip": "10.8.1.2", "imported": "1"}},
			{Name: "laptop", Data: map[string]string{"public_key": "PUB2", "ip": "10.8.1.3", "allowed_ips": "10.8.1.3/32, 192.168.5.0/24", "imported": "1"}},
		},
	}
	if err := a.AutoDefaults(env, s); err != nil {
		t.Fatal(err)
	}
	conf := a.render(s)
	for _, want := range []string{"PrivateKey = SERVERKEY", "Jc = 4", "H4 = 4444", "Itime = 120", "PresharedKey = PSK1", "AllowedIPs = 10.8.1.3/32, 192.168.5.0/24", "# laptop"} {
		if !strings.Contains(conf, want) {
			t.Errorf("нет %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "HeaderProtectionKey") {
		t.Error("версия 1.5 не должна получать параметры 3.x")
	}
	if strings.Count(conf, "PresharedKey") != 1 {
		t.Errorf("пир без PSK не должен получить PSK:\n%s", conf)
	}
	if ip, _ := a.nextIP(s); ip != "10.8.1.4" {
		t.Errorf("следующий адрес %s", ip)
	}
	if _, err := a.Artifacts(env, s, s.Users[0]); err == nil {
		// у импортированного клиента нет закрытого ключа — конфиг не выдаётся, но и не падает
		arts, _ := a.Artifacts(env, s, s.Users[0])
		if len(arts) > 0 && strings.Contains(arts[0].Value, "PrivateKey = \n") {
			t.Error("пустой PrivateKey в клиентском конфиге")
		}
	}
}

func TestTelemtImported(t *testing.T) {
	tm := &Telemt{}
	env := testEnv()
	s := &state.Service{Params: map[string]string{"tls_domain": "example.com", "own_domain": "false", "port": "8443", "legacy_tcp": "8443",
		"access_extra": "[access.user_max_tcp_conns]\nalice = 10"}, Secrets: map[string]string{"api_token": "x"}}
	s.Users = []*state.User{{Name: "alice", Data: map[string]string{"secret": "00112233445566778899aabbccddeeff"}}}
	cfg := tm.render(env, s)
	if !strings.Contains(cfg, "[access.user_max_tcp_conns]\nalice = 10") {
		t.Errorf("квоты не перенесены:\n%s", cfg)
	}
	a, _ := tm.Artifacts(env, s, s.Users[0])
	if !strings.Contains(a[0].Value, "port=8443") && !strings.Contains(a[0].Value, "port=443") {
		t.Errorf("ссылка %s", a[0].Value)
	}
}
