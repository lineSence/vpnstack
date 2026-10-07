package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// FPTN — VPN с маскировкой под HTTPS (SNI-spoofing, Reality-режим). Ставится в Docker
// по официальному docker-compose, контейнер помещается в slice vpnstack-fptn.slice.
type FPTN struct{ base }

const (
	fptnRepo  = "batchar2/fptn"
	fptnImage = "fptnvpn/fptn-vpn-server"
	fptnDir   = "/opt/vpnstack/fptn"
	fptnLocal = 10445
)

// Список доменов-приманок из официального .env (docker-compose/README.md).
const fptnDefaultSNI = "dashboard.cdnvideo.ru,cdnvideo.ru,gosuslugi.ru,sber.ru,id.sber.ru,tbank.ru,cdn.tbank.ru,alfabank.ru,mos.ru,vk.com,wildberries.ru,ozon.ru,2gis.ru,mts.ru,dzen.ru,vprok.ru,x5.ru,perekrestok.ru,yandex.ru,yandex.com,yandex.net,max.ru"

func init() {
	module.Register(&FPTN{base{id: "fptn", title: "FPTN", order: 20,
		desc:  "VPN под видом HTTPS к популярным сайтам (SNI-spoofing / Reality), Docker",
		units: []string{"vpnstack-fptn.service"}}})
}

func (f *FPTN) Params() []module.Param {
	return []module.Param{
		{Key: "sni_list", Label: "Домены-приманки (ALLOWED_SNI_LIST)", Type: module.TList,
			Help: "SNI, которые используют клиенты; общий вход направит их в FPTN. Проверяющие проксируются на настоящий сайт. Поддомены совпадают тоже."},
		{Key: "bandwidth", Label: "Скорость нового пользователя, Мбит/с", Type: module.TInt},
		{Key: "max_sessions", Label: "Сессий на пользователя", Type: module.TInt, Restart: true},
		{Key: "port", Label: "Порт (режим отдельных портов)", Type: module.TPort, Advanced: true, Restart: true},
		{Key: "ads_filter", Label: "Блокировать рекламу", Type: module.TBool, Advanced: true, Restart: true},
		{Key: "torrent_filter", Label: "Блокировать BitTorrent", Type: module.TBool, Advanced: true, Restart: true},
		{Key: "spam_filter", Label: "Блокировать спам-трафик (SMTP и т. п.)", Type: module.TBool, Advanced: true, Restart: true},
		{Key: "mtu", Label: "MTU", Type: module.TInt, Advanced: true, Restart: true},
	}
}

func (f *FPTN) AutoDefaults(env *module.Env, s *state.Service) error {
	s.Default("sni_list", fptnDefaultSNI)
	s.Default("bandwidth", "100")
	s.Default("max_sessions", "3")
	s.Default("port", "2087")
	s.Default("ads_filter", "true")
	s.Default("torrent_filter", "true")
	s.Default("spam_filter", "true")
	s.Default("mtu", "1400")
	if s.P("subnet4") == "" {
		for _, c := range []string{"192.168.200.0/24", "192.168.201.0/24", "192.168.210.0/24", "172.30.200.0/24"} {
			if sys.SubnetFree(c) {
				s.Default("subnet4", c)
				break
			}
		}
	}
	s.Default("subnet6", fmt.Sprintf("fd%s:%s::/48", sys.RandHex(1), sys.RandHex(2)))
	s.Secret("prometheus_key", func() string { return sys.RandHex(16) })
	return nil
}

func (f *FPTN) Needs(env *module.Env, s *state.Service) []module.Need {
	if env.EdgeEnabled {
		return []module.Need{{Proto: "tcp", Port: fptnLocal, Purpose: "FPTN за общим входом",
			Edge: &module.EdgeRoute{SNI: list(s, "sni_list"), Backend: fmt.Sprintf("127.0.0.1:%d", fptnLocal), Priority: 20}}}
	}
	return []module.Need{{Proto: "tcp", Port: atoi(s.P("port")), Public: true, Param: "port", Purpose: "FPTN"}}
}

func (f *FPTN) Latest(env *module.Env) (string, error) {
	t, err := latestTag(env, fptnRepo)
	return strings.TrimPrefix(t, "v"), err
}

func (f *FPTN) compose(env *module.Env, s *state.Service) string {
	gw4 := strings.TrimSuffix(s.P("subnet4"), ".0/24") + ".1"
	gw6 := strings.TrimSuffix(s.P("subnet6"), "::/48") + "::1"
	port := fmt.Sprintf("127.0.0.1:%d:443/tcp", fptnLocal)
	if !env.EdgeEnabled {
		port = s.P("port") + ":443/tcp"
	}
	return fmt.Sprintf(`# Сгенерировано vpnstack по официальному docker-compose FPTN
services:
  fptn-server:
    restart: unless-stopped
    image: %[1]s:%[2]s
    cgroup_parent: %[3]s
    privileged: true
    cap_add: [NET_ADMIN, SYS_MODULE, NET_RAW, SYS_ADMIN, SYS_RESOURCE]
    sysctls:
      net.ipv4.ip_local_port_range: "6890 65535"
      net.ipv4.tcp_congestion_control: "bbr"
      net.ipv4.tcp_rmem: "4096 131072 33554432"
      net.ipv4.tcp_wmem: "4096 65536 33554432"
    ulimits:
      nproc: {soft: 524288, hard: 524288}
      nofile: {soft: 524288, hard: 524288}
      memlock: {soft: 524288, hard: 524288}
    devices: ["/dev/net/tun:/dev/net/tun"]
    ports: ["%[4]s"]
    volumes: ["./fptn-server-data:/etc/fptn"]
    env_file: [fptn.env]
    healthcheck:
      test: ["CMD", "sh", "-c", "pgrep fptn-server"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks: [fptn-network]
networks:
  fptn-network:
    driver: bridge
    enable_ipv6: true
    ipam:
      config:
        - {subnet: "%[5]s", gateway: "%[6]s"}
        - {subnet: "%[7]s", gateway: "%[8]s"}
`, fptnImage, s.Version, sys.SliceName(f.id), port, s.P("subnet6"), gw6, s.P("subnet4"), gw4)
}

func (f *FPTN) envFile(env *module.Env, s *state.Service) string {
	ips := append([]string{env.Stack.PublicIP}, env.Stack.ExtraIPs...)
	kv := [][2]string{
		{"SERVER_EXTERNAL_IPS", strings.Join(ips, ",")},
		{"ENABLE_DETECT_PROBING", "true"},
		{"ALLOWED_SNI_LIST", strings.Join(list(s, "sni_list"), ",")},
		{"ENABLE_ADS_FILTER", s.P("ads_filter")},
		{"ENABLE_TORRENT_FILTER", s.P("torrent_filter")},
		{"ENABLE_SPAM_FILTER", s.P("spam_filter")},
		{"ENABLE_DOMAIN_BLACKLIST_FILTER", "true"},
		{"DOMAIN_BLACKLIST_URLS", "https://raw.githubusercontent.com/fptn-project/fptn/refs/heads/master/deploy/domain_blacklist/russia.txt"},
		{"DATA_DIR", "/etc/fptn/data"},
		{"PROMETHEUS_SECRET_ACCESS_KEY", s.Secrets["prometheus_key"]},
		{"USE_REMOTE_SERVER_AUTH", "false"},
		{"REMOTE_SERVER_AUTH_HOST", ""},
		{"REMOTE_SERVER_AUTH_PORT", "443"},
		{"MAX_ACTIVE_SESSIONS_PER_USER", s.P("max_sessions")},
		{"MTU_SIZE", s.P("mtu")},
		{"USING_DNS_SERVER", "unbound"},
		{"DNS_IPV6_ENABLE", "false"},
		{"DNS_IPV4_PRIMARY", "8.8.8.8"},
		{"DNS_IPV4_SECONDARY", "8.8.4.4"},
	}
	var b strings.Builder
	for _, p := range kv {
		fmt.Fprintf(&b, "%s=%s\n", p[0], p[1])
	}
	return b.String()
}

func (f *FPTN) dc(args ...string) (string, error) {
	return sys.Run("docker", append([]string{"compose", "--project-directory", fptnDir, "-p", "vpnstack-fptn"}, args...)...)
}

func (f *FPTN) dcIn(stdin string, args ...string) (string, error) {
	return sys.RunIn(stdin, "docker", append([]string{"compose", "--project-directory", fptnDir, "-p", "vpnstack-fptn"}, args...)...)
}

func ensureDocker() error {
	if sys.Has("docker") {
		if _, err := sys.Output("docker", "compose", "version"); err == nil {
			return nil
		}
	}
	if err := aptInstall("docker.io", "docker-compose-v2"); err != nil {
		return err
	}
	_ = sys.Systemctl("enable", "--now", "docker.service")
	return nil
}

func (f *FPTN) write(env *module.Env, s *state.Service) error {
	if err := sys.WriteFileAtomic(filepath.Join(fptnDir, "docker-compose.yml"), []byte(f.compose(env, s)), 0o644); err != nil {
		return err
	}
	return sys.WriteFileAtomic(filepath.Join(fptnDir, "fptn.env"), []byte(f.envFile(env, s)), 0o600)
}

func (f *FPTN) Install(env *module.Env, s *state.Service) error {
	if s.P("subnet4") == "" {
		return fmt.Errorf("нет свободной подсети для сети Docker FPTN")
	}
	if err := ensureDocker(); err != nil {
		return err
	}
	v, err := f.Latest(env)
	if err != nil {
		return err
	}
	s.Version = v
	if err := sys.EnsureSlice(f.id, f.title); err != nil {
		return err
	}
	_ = sys.Systemctl("daemon-reload")
	if err := f.write(env, s); err != nil {
		return err
	}
	if _, err := f.dc("pull"); err != nil {
		return err
	}
	data := filepath.Join(fptnDir, "fptn-server-data")
	_ = os.MkdirAll(data, 0o700)
	if !sys.Exists(filepath.Join(data, "server.key")) {
		if _, err := f.dc("run", "--rm", "--no-deps", "fptn-server", "sh", "-c",
			"cd /etc/fptn && openssl genrsa -out server.key 2048 && openssl req -new -x509 -key server.key -out server.crt -days 3650 -subj /CN=localhost"); err != nil {
			return err
		}
	}
	unit := fmt.Sprintf(`[Unit]
Description=vpnstack: FPTN (docker compose)
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
Slice=%s
WorkingDirectory=%s
ExecStart=/usr/bin/docker compose -p vpnstack-fptn up -d --remove-orphans
ExecStop=/usr/bin/docker compose -p vpnstack-fptn down
ExecReload=/usr/bin/docker compose -p vpnstack-fptn up -d --remove-orphans
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
`, sys.SliceName(f.id), fptnDir)
	if err := installUnit(f.id, f.title, f.units[0], unit); err != nil {
		return err
	}
	return nil
}

func (f *FPTN) Apply(env *module.Env, s *state.Service) error {
	if err := f.write(env, s); err != nil {
		return err
	}
	_, err := f.dc("up", "-d", "--remove-orphans")
	return err
}

func (f *FPTN) Remove(env *module.Env, s *state.Service, purge bool) error {
	_, _ = f.dc("down")
	removeUnits(f.id, f.units...)
	if purge {
		_, _ = sys.Run("rm", "-rf", fptnDir)
	}
	return nil
}

func (f *FPTN) Status(env *module.Env, s *state.Service) module.Status {
	st := unitsStatus(s, f.units)
	if st.State == "running" {
		out, _ := sys.Output("docker", "inspect", "-f", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", "vpnstack-fptn-fptn-server-1")
		st.Detail = strings.TrimSpace(out)
		if !strings.HasPrefix(st.Detail, "running") {
			st.State = "failed"
		}
	}
	return st
}

func (f *FPTN) Update(env *module.Env, s *state.Service) error {
	v, err := f.Latest(env)
	if err != nil {
		return err
	}
	s.Version = v
	if err := f.write(env, s); err != nil {
		return err
	}
	if _, err := f.dc("pull"); err != nil {
		return err
	}
	_, err = f.dc("up", "-d", "--remove-orphans")
	return err
}

func (f *FPTN) ConfigFiles(*state.Service) []string {
	return []string{filepath.Join(fptnDir, "docker-compose.yml"), filepath.Join(fptnDir, "fptn.env")}
}

func (f *FPTN) AddUser(env *module.Env, s *state.Service, name string, opts map[string]string) (*state.User, error) {
	if !s.Installed {
		return nil, fmt.Errorf("FPTN ещё не установлен")
	}
	bw := opts["bandwidth"]
	if bw == "" {
		bw = s.P("bandwidth")
	}
	pass := password(20)
	if _, err := f.dcIn(pass+"\n"+pass+"\n", "exec", "-T", "fptn-server", "fptn-passwd", "--add-user", name, "--bandwidth", bw); err != nil {
		return nil, err
	}
	out, err := f.dc("exec", "-T", "fptn-server", "token-generator", "--user", name, "--password", pass,
		"--server-ip", env.Stack.PublicIP, "--port", itoa(publicPort(env, s, "port")))
	if err != nil {
		return nil, err
	}
	token := ""
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "fptn:") {
			token = l
		}
	}
	u := &state.User{Name: name, Data: map[string]string{"password": pass, "bandwidth": bw, "token": token}}
	if token == "" {
		u.Data["token_output"] = strings.TrimSpace(out)
	}
	s.Users = append(s.Users, u)
	return u, nil
}

func (f *FPTN) DelUser(env *module.Env, s *state.Service, name string) error {
	if _, err := f.dc("exec", "-T", "fptn-server", "fptn-passwd", "--del-user", name); err != nil {
		return err
	}
	s.RemoveUser(name)
	return nil
}

func (f *FPTN) Artifacts(env *module.Env, s *state.Service, u *state.User) ([]module.Artifact, error) {
	if t := u.Data["token"]; t != "" {
		return []module.Artifact{{Kind: "token", Title: "Токен FPTN (вставить в клиент FPTN)", Value: t, QR: true}}, nil
	}
	return []module.Artifact{{Kind: "text", Title: "Вывод token-generator", Value: u.Data["token_output"]}}, nil
}
