package modules

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
)

func testEnv() *module.Env {
	st := state.New()
	st.PublicIP = "203.0.113.1"
	st.Email = "admin@example.com"
	return &module.Env{Stack: st, EdgePort: 443, EdgeEnabled: true,
		Sites: func() []module.CaddySite {
			return []module.CaddySite{{Host: "tg.example.com", Block: "reverse_proxy 127.0.0.1:8080"}, {Host: "hy.example.com"}}
		}}
}

func TestCaddyRender(t *testing.T) {
	c := &Caddy{}
	out := c.Render(testEnv())
	for _, want := range []string{"https_port 7443", "proxy_protocol", "allow 127.0.0.1/32", "protocols h1 h2", "tg.example.com {", "\treverse_proxy 127.0.0.1:8080", "hy.example.com {", "file_server"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q в Caddyfile:\n%s", want, out)
		}
	}
}

func TestXrayLink(t *testing.T) {
	x := &Xray{}
	env := testEnv()
	s := &state.Service{Params: map[string]string{}}
	_ = x.AutoDefaults(env, s)
	u, _ := x.AddUser(env, s, "alice", nil)
	a, err := x.Artifacts(env, s, u)
	if err != nil {
		t.Fatal(err)
	}
	l := a[0].Value
	if !strings.HasPrefix(l, "vless://"+u.Data["uuid"]+"@203.0.113.1:443?") || !strings.Contains(l, "security=reality") || !strings.Contains(l, "pbk=") {
		t.Fatalf("ссылка: %s", l)
	}
	cfg := x.config(env, s)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["listen"] != "127.0.0.1" || in["port"] != xrayLocal {
		t.Fatalf("inbound: %+v", in)
	}
	pk, _ := base64.RawURLEncoding.DecodeString(s.Secrets["private_key"])
	if len(pk) != 32 {
		t.Fatal("ключ REALITY не 32 байта")
	}
}

func TestHysteriaRender(t *testing.T) {
	h := &Hysteria{}
	env := testEnv()
	s := &state.Service{Params: map[string]string{"domain": "hy.example.com"}}
	_ = h.AutoDefaults(env, s)
	s.Users = []*state.User{{Name: "bob", Data: map[string]string{"password": "p@ss:word"}}}
	y := h.render(s)
	for _, want := range []string{"listen: :443", "type: command", "command: " + HyAuthPath, "trafficStats:", "masquerade:"} {
		if !strings.Contains(y, want) {
			t.Errorf("нет %q:\n%s", want, y)
		}
	}
	a, _ := h.Artifacts(env, s, s.Users[0])
	if !strings.HasPrefix(a[0].Value, "hysteria2://bob:p%40ss%3Aword@hy.example.com:443/?sni=hy.example.com") {
		t.Fatalf("ссылка: %s", a[0].Value)
	}
	legacy := &state.User{Name: "legacy", Data: map[string]string{"password": "oldpw", "legacy": "1"}}
	a, _ = h.Artifacts(env, s, legacy)
	if !strings.HasPrefix(a[0].Value, "hysteria2://oldpw@hy.example.com:443/") {
		t.Fatalf("ссылка общего пароля: %s", a[0].Value)
	}
}

func TestHyAuth(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/auth.json"
	f := `{"users":{"bob":{"name":"Bob","pass":"p@ss:word"}},"shared":{"old:shared":"legacy"}}`
	if err := os.WriteFile(path, []byte(f), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		auth, id string
		ok       bool
	}{
		{"bob:p@ss:word", "Bob", true},
		{"BOB:p@ss:word", "Bob", true},
		{"bob:wrong", "", false},
		{"old:shared", "legacy", true},
		{"nobody", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		id, ok := HyAuthCheck(path, c.auth)
		if ok != c.ok || id != c.id {
			t.Errorf("%q: %q %v", c.auth, id, ok)
		}
	}
	if _, ok := HyAuthCheck(dir+"/missing.json", "bob:p@ss:word"); ok {
		t.Fatal("без файла вход запрещён")
	}
}

func TestAWG(t *testing.T) {
	a := &AWG{}
	env := testEnv()
	s := &state.Service{Params: map[string]string{"subnet": "10.66.66.0/24", "port": "51820"}}
	if err := a.AutoDefaults(env, s); err != nil {
		t.Fatal(err)
	}
	u1, _ := a.AddUser(env, s, "u1", nil)
	u2, _ := a.AddUser(env, s, "u2", nil)
	if u1.Data["ip"] != "10.66.66.2" || u2.Data["ip"] != "10.66.66.3" {
		t.Fatalf("адреса: %s %s", u1.Data["ip"], u2.Data["ip"])
	}
	conf := a.render(s)
	for _, want := range []string{"Address = 10.66.66.1/24", "ListenPort = 51820", "Jc = ", "S3 = ", "H1 = ", "HeaderProtectionKey = ", "ContentPaddingAddition = 0-", "RandomTrailers = true", "# u2"} {
		if !strings.Contains(conf, want) {
			t.Errorf("нет %q:\n%s", want, conf)
		}
	}
	if atoi(s.P("s1"))+56 == atoi(s.P("s2")) {
		t.Fatal("S1+56 == S2")
	}
	arts, err := a.Artifacts(env, s, u1)
	if err != nil || !strings.Contains(arts[0].Value, "Endpoint = 203.0.113.1:51820") {
		t.Fatalf("клиент: %v %v", err, arts)
	}
	if !strings.Contains(arts[0].Value, "HeaderProtectionKey = "+s.Secrets["header_protection_key"]) || strings.Contains(arts[0].Value, "DisableCookies") {
		t.Fatalf("клиент без параметров AWG 3: %s", arts[0].Value)
	}
	old := &state.Service{Params: map[string]string{"subnet": "10.66.66.0/24", "port": "51820", "awg_version": "2.0"}}
	_ = a.AutoDefaults(env, old)
	if strings.Contains(a.render(old), "HeaderProtectionKey") {
		t.Fatal("AWG 2.0 не должен получать параметры 3.x")
	}
	pub, _ := wgPub(u1.Data["private_key"])
	if pub != u1.Data["public_key"] {
		t.Fatal("открытый ключ не совпадает")
	}
}

func TestTelemtLink(t *testing.T) {
	tm := &Telemt{}
	env := testEnv()
	s := &state.Service{Params: map[string]string{"tls_domain": "example.com", "own_domain": "false"}, Secrets: map[string]string{"api_token": "x"}}
	u := &state.User{Name: "a", Data: map[string]string{"secret": "00112233445566778899aabbccddeeff"}}
	s.Users = []*state.User{u}
	a, _ := tm.Artifacts(env, s, u)
	if !strings.Contains(a[0].Value, "secret=ee00112233445566778899aabbccddeeff6578616d706c652e636f6d") || !strings.Contains(a[0].Value, "port=443") {
		t.Fatalf("ссылка: %s", a[0].Value)
	}
	cfg := tm.render(env, s)
	for _, want := range []string{"port = 10444", "proxy_protocol = true", `ip = "127.0.0.1"`, `tls_domain = "example.com"`, `"a" = "00112233445566778899aabbccddeeff"`} {
		if !strings.Contains(cfg, want) {
			t.Errorf("нет %q:\n%s", want, cfg)
		}
	}
}

func TestTGWPLink(t *testing.T) {
	g := &TGWP{}
	s := &state.Service{Params: map[string]string{"domain": "tg.example.com", "active_base_path": "abc"}, Secrets: map[string]string{"secret": "00112233445566778899aabbccddeeff"}}
	a, _ := g.Links(testEnv(), s)
	if !strings.HasPrefix(a[0].Value, "https://t.me/webproxy?server=tg.example.com%2Fabc&secret=cAARIjNEVWZ3iJmqu8zd7v8") {
		t.Fatalf("ссылка: %s", a[0].Value)
	}
}
