package adopt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lineSence/vpnstack/internal/state"
)

func nf(id string) *Found {
	return newFound(id, id, state.Origin{Source: "test", Files: map[string]string{}})
}

func TestYAML(t *testing.T) {
	src := `# comment
listen: :8443 # порт
tls:
  cert: "/etc/hy/c.crt"
  key: /etc/hy/c.key
Auth:
  type: userpass
  userpass:
    Alice: "p#1"
    bob: 'x y'
masquerade: {type: proxy, proxy: {url: "https://a.b/"}}
list:
  - a
  - "b"
flow: [1, two]
text: |
  line1
  line2
`
	v, err := parseYAML(src)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"listen": ":8443", "tls.cert": "/etc/hy/c.crt", "auth.type": "userpass",
		"auth.userpass.Alice": "p#1", "auth.userpass.bob": "x y", "masquerade.type": "proxy", "masquerade.proxy.url": "https://a.b/"} {
		if got := getStr(v, strings.Split(k, ".")...); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if l := getList(v, "list"); len(l) != 2 || l[1] != "b" {
		t.Errorf("list = %v", l)
	}
	if l := getList(v, "flow"); len(l) != 2 || l[1] != "two" {
		t.Errorf("flow = %v", l)
	}
	if s := getStr(v, "text"); !strings.HasPrefix(s, "line1\nline2") {
		t.Errorf("text = %q", s)
	}
}

func TestTOML(t *testing.T) {
	src := `[general]
use_middle_proxy = false
ad_tag = "abc" # tag
[general.modes]
classic = false
secure = false
tls = true
[server]
port = 8443
[censorship]
tls_domain = "www.google.com"
[access.users]
alice = "0123456789abcdef0123456789abcdef"
"b o b" = "00112233445566778899aabbccddeeff"
[access.user_max_tcp_conns]
alice = 10
`
	d, err := parseTOML(src)
	if err != nil {
		t.Fatal(err)
	}
	if getStr(d.Root, "censorship", "tls_domain") != "www.google.com" || anyInt(getPath(d.Root, "server", "port")) != 8443 {
		t.Fatalf("root %+v", d.Root)
	}
	f := nf("telemt")
	importTelemt(f, src)
	if len(f.Blocking) > 0 || len(f.Risky) == 0 {
		// «b o b» переименован → предупреждение о квотах
		t.Fatalf("blocking %v risky %v", f.Blocking, f.Risky)
	}
	if f.Params["port"] != "8443" || f.Params["legacy_tcp"] != "8443" || f.Params["middle_proxy"] != "false" || f.Params["ad_tag"] != "abc" {
		t.Errorf("params %v", f.Params)
	}
	if len(f.Users) != 2 || f.Users[0].Name != "alice" || f.Users[0].Data["secret"] != "0123456789abcdef0123456789abcdef" {
		t.Errorf("users %v", f.UserNames)
	}
	if !strings.Contains(f.Params["access_extra"], "[access.user_max_tcp_conns]") {
		t.Errorf("access_extra %q", f.Params["access_extra"])
	}
}

func TestFakeTLS(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	sec := "ee" + key + hex.EncodeToString([]byte("example.com"))
	k, d, err := decodeFakeTLS(sec)
	if err != nil || k != key || d != "example.com" {
		t.Fatalf("%v %v %v", k, d, err)
	}
	if _, _, err := decodeFakeTLS("dd" + key); err == nil {
		t.Error("ожидалась ошибка")
	}
	f := nf("telemt")
	importMTG(f, sec, "0.0.0.0:3128")
	if f.Params["tls_domain"] != "example.com" || f.Params["legacy_tcp"] != "3128" || f.Users[0].Data["secret"] != key {
		t.Errorf("%v %v", f.Params, f.Users[0].Data)
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{"user@mail.ru": "user_mail.ru", "  Вася ": "user3", "a b/c": "a_b_c", strings.Repeat("x", 40): strings.Repeat("x", 32)} {
		if got := sanitizeName(in, 3); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
	f := nf("x")
	f.addUser("a", nil)
	f.addUser("A", nil)
	if f.Users[1].Name != "A-2" || f.Users[1].Data["imported"] != "1" {
		t.Errorf("%v", f.UserNames)
	}
}

func selfSigned(t *testing.T, dir, name string) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, "c.crt")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	return p
}

func TestImportHysteria(t *testing.T) {
	procDir = t.TempDir()
	defer func() { procDir = "/proc" }()
	selfSigned(t, filepath.Join(procDir, "1", "root", "etc", "hy"), "bing.com")
	p := proc{PID: 1}
	f := nf("hysteria")
	importHysteria(f, `listen: :8443
tls:
  cert: /etc/hy/c.crt
  key: /etc/hy/c.key
obfs:
  type: salamander
  salamander:
    password: ob
auth:
  type: password
  password: secret
bandwidth:
  up: 1 gbps
  down: 200 mbps
acl:
  inline: [reject(all)]
`, p)
	if len(f.Blocking) > 0 {
		t.Fatal(f.Blocking)
	}
	if f.Params["port"] != "8443" || f.Params["sni"] != "bing.com" || f.Secrets["self_signed"] != "true" || len(f.Secrets["pin_sha256"]) != 64 {
		t.Errorf("params %v secrets %v", f.Params, f.Secrets)
	}
	if f.Params["obfs_type"] != "salamander" || f.Secrets["obfs_password"] != "ob" || f.Params["up_mbps"] != "1000" || f.Params["down_mbps"] != "200" {
		t.Errorf("params %v", f.Params)
	}
	if len(f.Users) != 1 || f.Users[0].Data["legacy"] != "1" || f.Users[0].Data["password"] != "secret" {
		t.Errorf("users %v", f.Users)
	}
	if len(f.Risky) != 1 {
		t.Errorf("risky %v", f.Risky)
	}
	if strings.Join(f.Origin.Ports, ",") != "udp/8443" {
		t.Errorf("ports %v", f.Origin.Ports)
	}

	g := nf("hysteria")
	importHysteria(g, "auth: {type: userpass, userpass: {Bob: pw}}\nacme: {domains: [hy.example.com]}\n", p)
	if g.Params["domain"] != "hy.example.com" || g.Users[0].Data["login"] != "bob" || len(g.Blocking) > 0 {
		t.Errorf("%v %v %v", g.Params, g.Users[0].Data, g.Blocking)
	}
}

func TestImportXray(t *testing.T) {
	cfg := `// x-ui
{"inbounds": [
 {"tag": "api", "protocol": "dokodemo-door", "port": 62789},
 {"tag": "in-1", "protocol": "vless", "port": 8443,
  "settings": {"clients": [{"id": "11111111-1111-1111-1111-111111111111", "email": "a@b.c", "flow": "xtls-rprx-vision"},
                           {"id": "22222222-2222-2222-2222-222222222222"}], "decryption": "none"},
  "streamSettings": {"network": "tcp", "security": "reality",
   "realitySettings": {"dest": "www.microsoft.com:443", "serverNames": ["www.microsoft.com", "microsoft.com"],
     "privateKey": "PRIV", "shortIds": ["", "abcd"]}}},
 {"protocol": "vmess", "port": 1000, "settings": {"clients": [{"id": "x"}]}}
]}`
	var v struct {
		Inbounds []any `json:"inbounds"`
	}
	if err := json.Unmarshal(stripJSONComments([]byte(cfg)), &v); err != nil {
		t.Fatal(err)
	}
	f := nf("xray")
	importXray(f, v.Inbounds)
	if len(f.Blocking) > 0 || len(f.Risky) != 1 {
		t.Fatalf("blocking %v risky %v", f.Blocking, f.Risky)
	}
	if f.Params["sni"] != "www.microsoft.com" || f.Params["server_names"] != "microsoft.com" || f.Params["target"] != "www.microsoft.com:443" || f.Params["legacy_tcp"] != "8443" {
		t.Errorf("params %v", f.Params)
	}
	if f.Secrets["private_key"] != "PRIV" || f.Secrets["short_id"] != "abcd" || f.Secrets["short_ids"] != `["","abcd"]` {
		t.Errorf("secrets %v", f.Secrets)
	}
	if len(f.Users) != 2 || f.Users[0].Name != "a_b.c" || f.Users[0].Data["flow"] != "xtls-rprx-vision" || f.Users[1].Data["flow"] != "" {
		t.Errorf("users %v", f.UserNames)
	}
}

func TestImportAWG(t *testing.T) {
	src := `[Interface]
PrivateKey = SERVERKEY
Address = 10.8.1.1/24, fd00::1/64
ListenPort = 51820
Jc = 4
Jmin = 10
Jmax = 50
S1 = 20
S2 = 30
H1 = 1111
H2 = 2222
H3 = 3333
H4 = 4444
PostUp = iptables -A FORWARD -i %i -j ACCEPT
Itime = 120

# Client: phone
[Peer]
PublicKey = PUB1
PresharedKey = PSK1
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = PUB2
AllowedIPs = 10.8.1.3/32, 192.168.5.0/24
`
	f := nf("awg")
	importAWG(f, src, map[string]string{"PUB2": "laptop"})
	if len(f.Blocking) > 0 {
		t.Fatal(f.Blocking)
	}
	if f.Params["subnet"] != "10.8.1.0/24" || f.Params["server_ip"] != "" || f.Params["awg_version"] != "1.5" || f.Params["s3"] != "0" || f.Params["jc"] != "4" {
		t.Errorf("params %v", f.Params)
	}
	if f.Params["iface_extra"] != "Itime = 120" {
		t.Errorf("iface_extra %q", f.Params["iface_extra"])
	}
	if strings.Join(f.UserNames, ",") != "phone,laptop" || f.Users[0].Data["ip"] != "10.8.1.2" || f.Users[0].Data["psk"] != "PSK1" ||
		f.Users[1].Data["allowed_ips"] != "10.8.1.3/32, 192.168.5.0/24" {
		t.Errorf("users %v %v", f.UserNames, f.Users[1].Data)
	}

	g := nf("awg")
	importAWG(g, "[Interface]\nPrivateKey = K\nAddress = 10.9.0.5/24\nListenPort = 1\nS3 = 5\nH1 = 100-200\nHeaderProtectionKey = HPK\nRandomTrailers = true\n", nil)
	if g.Params["awg_version"] != "3.1" || g.Secrets["header_protection_key"] != "HPK" || g.Params["server_ip"] != "10.9.0.5" || g.Params["random_trailers"] != "true" {
		t.Errorf("params %v", g.Params)
	}
}

func TestImportTGWP(t *testing.T) {
	f := nf("tgwp")
	importTGWP(f, []byte(`{"public_hostname":"tg.example.com","base_path":"/abc"}`), []byte(`{"profiles":[{"secret":"S"}]}`),
		"tg.example.com {\n reverse_proxy 127.0.0.1:8080\n}\nsite.example.com {\n root * /var/www\n}\n", "", true)
	if len(f.Blocking) > 0 || f.Params["domain"] != "tg.example.com" || f.Params["base_path"] != "/abc" || f.Secrets["secret"] != "S" || f.Params["adopted_inplace"] != "true" {
		t.Fatalf("%v %v %v", f.Blocking, f.Params, f.Secrets)
	}
	if len(f.Risky) == 0 {
		t.Error("ожидалось предупреждение о других сайтах Caddy")
	}
}
