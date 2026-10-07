package modules

import (
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// AWG — AmneziaWG (WireGuard с обфускацией). Модуль ядра из PPA amnezia/ppa,
// при неудаче — userspace amneziawg-go, собранный из исходников.
type AWG struct{ base }

const (
	awgIface = "awgvs0" // своё имя, чтобы не трогать существующие установки Amnezia
	awgConf  = "/etc/amnezia/amneziawg/" + awgIface + ".conf"
)

func init() {
	module.Register(&AWG{base{id: "awg", title: "AmneziaWG", order: 50,
		desc:  "WireGuard с обфускацией заголовков и мусорными пакетами (AmneziaWG 3.1, совместимость с 3.0/2.0/1.5)",
		units: []string{"awg-quick@" + awgIface + ".service"}}})
}

func (a *AWG) Params() []module.Param {
	return []module.Param{
		{Key: "port", Label: "UDP-порт", Type: module.TPort, Restart: true},
		{Key: "subnet", Label: "Подсеть клиентов", Type: module.TString, Advanced: true, Restart: true},
		{Key: "dns", Label: "DNS для клиентов", Type: module.TList},
		{Key: "awg_version", Label: "Версия протокола", Type: module.TSelect, Options: []string{"3.1", "3.0", "2.0", "1.5"}, Restart: true,
			Help: "3.1 — защита заголовков (HeaderProtectionKey), паддинг содержимого и случайные хвосты пакетов; нужны клиенты с поддержкой AWG 3 (AmneziaVPN 5.0+, свежие AmneziaWG). " +
				"3.0 — то же без случайных хвостов. 2.0 — диапазоны H1–H4 и S3/S4. 1.5 — для старых клиентов. Смена версии требует раздать всем клиентам новые конфиги."},
		{Key: "mtu", Label: "MTU", Type: module.TInt, Advanced: true},
		{Key: "jc", Label: "Jc", Type: module.TInt, Advanced: true, Restart: true},
		{Key: "jmin", Label: "Jmin", Type: module.TInt, Advanced: true, Restart: true},
		{Key: "jmax", Label: "Jmax", Type: module.TInt, Advanced: true, Restart: true},
		{Key: "s1", Label: "S1", Type: module.TInt, Advanced: true, Restart: true},
		{Key: "s2", Label: "S2", Type: module.TInt, Advanced: true, Restart: true},
		{Key: "s3", Label: "S3", Type: module.TInt, Advanced: true, Restart: true},
		{Key: "s4", Label: "S4", Type: module.TInt, Advanced: true, Restart: true},
		{Key: "h1", Label: "H1", Type: module.TString, Advanced: true, Restart: true},
		{Key: "h2", Label: "H2", Type: module.TString, Advanced: true, Restart: true},
		{Key: "h3", Label: "H3", Type: module.TString, Advanced: true, Restart: true},
		{Key: "h4", Label: "H4", Type: module.TString, Advanced: true, Restart: true},
		{Key: "content_padding", Label: "ContentPaddingAddition (AWG 3+)", Type: module.TString, Advanced: true, Restart: true,
			Help: "Диапазон дополнительного паддинга данных, например 0-32. Пусто — выключено."},
		{Key: "random_trailers", Label: "RandomTrailers (AWG 3.1)", Type: module.TBool, Advanced: true, Restart: true},
		{Key: "disable_cookies", Label: "DisableCookies (AWG 3.1, только сервер)", Type: module.TBool, Advanced: true, Restart: true,
			Help: "Сервер не отправляет cookie-ответы (ещё один узнаваемый тип пакета), ценой защиты от handshake-флуда."},
		{Key: "i1", Label: "I1 (сигнатурный пакет, необязательно)", Type: module.TString, Advanced: true, Restart: true,
			Help: "Например <b 0x...><r 16> — имитация первого пакета другого протокола. Пусто — не используется."},
	}
}

func (a *AWG) AutoDefaults(env *module.Env, s *state.Service) error {
	s.Default("port", itoa(randInt(30000, 60000)))
	if s.P("subnet") == "" {
		for _, c := range []string{"10.66.66.0/24", "10.67.67.0/24", "10.88.0.0/24", "172.29.88.0/24"} {
			if sys.SubnetFree(c) {
				s.Default("subnet", c)
				break
			}
		}
		if s.P("subnet") == "" {
			return fmt.Errorf("не нашлось свободной подсети для AmneziaWG — задайте её вручную")
		}
	}
	s.Default("dns", "1.1.1.1, 1.0.0.1")
	s.Default("awg_version", "3.1")
	s.Default("mtu", "1280")
	s.Default("jc", itoa(randInt(4, 12)))
	s.Default("jmin", "8")
	s.Default("jmax", "80")
	s1 := randInt(15, 150)
	s2 := randInt(15, 150)
	for s1+56 == s2 {
		s2 = randInt(15, 150)
	}
	s.Default("s1", itoa(s1))
	s.Default("s2", itoa(s2))
	s.Default("s3", itoa(randInt(12, 64)))
	s.Default("s4", itoa(randInt(12, 32)))
	if s.P("h1") == "" {
		// Четыре непересекающихся диапазона в 5..2147483647 (для 1.5 — одиночные значения).
		const lo, hi = 5, 2147483647
		step := (hi - lo) / 4
		for i := 0; i < 4; i++ {
			from := lo + i*step + randInt(0, step/4)
			to := from + randInt(step/8, step/2)
			v := fmt.Sprintf("%d-%d", from, to)
			if s.P("awg_version") == "1.5" {
				v = itoa(from)
			}
			s.Default(fmt.Sprintf("h%d", i+1), v)
		}
	}
	if awgMajor(s) >= 3 {
		s.Default("content_padding", "0-"+itoa(randInt(16, 48)))
		if s.P("awg_version") == "3.1" {
			s.Default("random_trailers", "true")
		}
		s.Default("disable_cookies", "false")
		s.Secret("header_protection_key", func() string {
			p, _ := x25519()
			return base64.StdEncoding.EncodeToString(p)
		})
		// Защита заголовков использует паддинги S1–S4 как nonce: каждый должен быть ≥ 12.
		for _, k := range []string{"s1", "s2", "s3", "s4"} {
			if atoi(s.P(k)) < 12 {
				return fmt.Errorf("AmneziaWG %s: %s должен быть не меньше 12", s.P("awg_version"), strings.ToUpper(k))
			}
		}
	}
	s.Secret("private_key", func() string {
		p, _ := x25519()
		return base64.StdEncoding.EncodeToString(p)
	})
	return nil
}

func (a *AWG) Needs(env *module.Env, s *state.Service) []module.Need {
	return []module.Need{{Proto: "udp", Port: atoi(s.P("port")), Public: true, Param: "port", Purpose: "AmneziaWG"}}
}

func (a *AWG) Latest(env *module.Env) (string, error) {
	out, err := sys.Output("apt-cache", "policy", "amneziawg-tools")
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Candidate:"); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", nil
}

func (a *AWG) Sysctls() map[string]string {
	return map[string]string{"net.ipv4.ip_forward": "1"}
}

// NFT — NAT клиентов наружу и разрешение форвардинга.
func (a *AWG) NFT(env *module.Env, s *state.Service) string {
	out := sys.DefaultInterface()
	return fmt.Sprintf(`chain awg_postrouting {
	type nat hook postrouting priority srcnat; policy accept;
	ip saddr %[1]s oifname "%[2]s" masquerade
}
chain awg_forward {
	type filter hook forward priority filter - 5; policy accept;
	iifname "%[3]s" accept
	oifname "%[3]s" ct state established,related accept
}
`, s.P("subnet"), out, awgIface)
}

func (a *AWG) Install(env *module.Env, s *state.Service) error {
	if err := a.Prefetch(env, s); err != nil {
		return err
	}
	v, _ := a.Latest(env)
	s.Version = v
	return a.start(s)
}

// Prefetch ставит пакеты и модуль ядра (или userspace) заранее, не трогая интерфейсы.
func (a *AWG) Prefetch(env *module.Env, s *state.Service) error {
	if !sys.Has("awg") {
		kver, _ := sys.Output("uname", "-r")
		if err := aptInstall("software-properties-common", "gnupg"); err != nil {
			return err
		}
		if _, err := sys.Run("add-apt-repository", "-y", "ppa:amnezia/ppa"); err != nil {
			return err
		}
		_ = aptInstall("linux-headers-" + strings.TrimSpace(kver))
		if err := aptInstall("amneziawg"); err != nil {
			return err
		}
	}
	if _, err := sys.Run("modprobe", "amneziawg"); err != nil {
		sys.Logf("Модуль ядра amneziawg не загрузился — ставлю userspace amneziawg-go")
		if err := a.userspace(env); err != nil {
			return err
		}
	}
	return nil
}

func (a *AWG) start(s *state.Service) error {
	if err := a.write(s); err != nil {
		return err
	}
	if err := sys.EnsureSlice(a.id, a.title); err != nil {
		return err
	}
	if err := sys.AttachToSlice(a.units[0], a.id); err != nil {
		return err
	}
	_ = sys.Systemctl("daemon-reload")
	if err := sys.Systemctl("enable", a.units[0]); err != nil {
		return err
	}
	if err := sys.Systemctl("restart", a.units[0]); err != nil {
		return err
	}
	return waitActive(a.units[0], 10e9)
}

// userspace собирает amneziawg-go (у проекта нет бинарных релизов).
func (a *AWG) userspace(env *module.Env) error {
	gobin, err := env.GoBinary()
	if err != nil {
		return err
	}
	dir := "/opt/vpnstack/src/amneziawg-go"
	_, _ = sys.Run("rm", "-rf", dir)
	if _, err := sys.Run("git", "clone", "--depth", "1", "https://github.com/amnezia-vpn/amneziawg-go", dir); err != nil {
		return err
	}
	if _, err := sys.Run("sh", "-c", "cd "+dir+" && "+gobin+" build -trimpath -ldflags='-s -w' -o /usr/local/bin/amneziawg-go ."); err != nil {
		return err
	}
	return sys.WriteDropIn(a.units[0], "20-userspace.conf", "[Service]\nEnvironment=WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go\n")
}

func (a *AWG) serverAddr(s *state.Service) (string, *net.IPNet) {
	ip, n, _ := net.ParseCIDR(s.P("subnet"))
	if v := s.P("server_ip"); v != "" { // перенятая установка: адрес сервера как был
		ones, _ := n.Mask.Size()
		return fmt.Sprintf("%s/%d", v, ones), n
	}
	ip = ip.To4()
	gw := net.IPv4(ip[0], ip[1], ip[2], ip[3]+1)
	ones, _ := n.Mask.Size()
	return fmt.Sprintf("%s/%d", gw, ones), n
}

// awgMajor — мажорная версия протокола (1 для 1.5).
func awgMajor(s *state.Service) int {
	v, _, _ := strings.Cut(s.P("awg_version"), ".")
	return atoi(v)
}

// obf — параметры обфускации для секции [Interface]. server — конфиг сервера
// (DisableCookies нужен только там).
func (a *AWG) obf(s *state.Service, server bool) string {
	var b strings.Builder
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2"} {
		fmt.Fprintf(&b, "%s = %s\n", strings.ToUpper(k[:1])+k[1:], s.P(k))
	}
	if s.P("awg_version") != "1.5" {
		fmt.Fprintf(&b, "S3 = %s\nS4 = %s\n", s.P("s3"), s.P("s4"))
	}
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&b, "H%d = %s\n", i, s.P(fmt.Sprintf("h%d", i)))
	}
	for i := 1; i <= 5; i++ {
		if v := s.P(fmt.Sprintf("i%d", i)); v != "" {
			fmt.Fprintf(&b, "I%d = %s\n", i, v)
		}
	}
	if awgMajor(s) >= 3 {
		fmt.Fprintf(&b, "HeaderProtectionKey = %s\n", s.Secrets["header_protection_key"])
		if v := s.P("content_padding"); v != "" {
			fmt.Fprintf(&b, "ContentPaddingAddition = %s\n", v)
		}
		if s.P("awg_version") != "3.0" && s.P("random_trailers") == "true" {
			b.WriteString("RandomTrailers = true\n")
		}
		if server && s.P("awg_version") != "3.0" && s.P("disable_cookies") == "true" {
			b.WriteString("DisableCookies = true\n")
		}
	}
	return b.String()
}

func (a *AWG) render(s *state.Service) string {
	addr, _ := a.serverAddr(s)
	var b strings.Builder
	fmt.Fprintf(&b, "# Сгенерировано vpnstack\n[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %s\nMTU = %s\n%s",
		s.Secrets["private_key"], addr, s.P("port"), s.P("mtu"), a.obf(s, true))
	// Прочие параметры перенятой установки (тайминги AWG 3 и т. п.) — без изменений.
	for _, l := range strings.Split(s.P("iface_extra"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			b.WriteString(l + "\n")
		}
	}
	for _, u := range s.Users {
		fmt.Fprintf(&b, "\n# %s\n[Peer]\nPublicKey = %s\n", u.Name, u.Data["public_key"])
		if u.Data["psk"] != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", u.Data["psk"])
		}
		allowed := u.Data["allowed_ips"]
		if allowed == "" {
			allowed = u.Data["ip"] + "/32"
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	}
	return b.String()
}

func (a *AWG) write(s *state.Service) error {
	return sys.WriteFileAtomic(awgConf, []byte(a.render(s)), 0o600)
}

func (a *AWG) Apply(env *module.Env, s *state.Service) error {
	if err := a.write(s); err != nil {
		return err
	}
	if err := sys.Systemctl("restart", a.units[0]); err != nil {
		return err
	}
	return waitActive(a.units[0], 10e9)
}

// sync применяет список пиров без разрыва текущих соединений.
func (a *AWG) sync(env *module.Env, s *state.Service) error {
	if err := a.write(s); err != nil {
		return err
	}
	if !sys.Active(a.units[0]) {
		return a.Apply(env, s)
	}
	_, err := sys.Run("bash", "-c", fmt.Sprintf("awg syncconf %[1]s <(awg-quick strip %[1]s)", awgIface))
	return err
}

func (a *AWG) Remove(env *module.Env, s *state.Service, purge bool) error {
	_ = sys.Systemctl("disable", "--now", a.units[0])
	_, _ = sys.Run("rm", "-rf", "/etc/systemd/system/"+a.units[0]+".d")
	sys.RemoveUnit(sys.SliceName(a.id))
	_ = sys.Systemctl("daemon-reload")
	if purge {
		_, _ = sys.Run("rm", "-f", awgConf)
	}
	return nil
}

func (a *AWG) Status(env *module.Env, s *state.Service) module.Status { return unitsStatus(s, a.units) }

func (a *AWG) Update(env *module.Env, s *state.Service) error {
	if err := aptInstall("amneziawg"); err != nil {
		return err
	}
	v, _ := a.Latest(env)
	s.Version = v
	return a.Apply(env, s)
}

func (a *AWG) ConfigFiles(*state.Service) []string { return []string{awgConf} }

func (a *AWG) nextIP(s *state.Service) (string, error) {
	_, n := a.serverAddr(s)
	used := map[string]bool{s.P("server_ip"): true}
	for _, u := range s.Users {
		used[u.Data["ip"]] = true
	}
	base := n.IP.To4()
	ones, bits := n.Mask.Size()
	size := 1 << (bits - ones)
	for i := 2; i < size-1; i++ {
		v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
		v += uint32(i)
		ip := net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
		if !used[ip] {
			return ip, nil
		}
	}
	return "", fmt.Errorf("в подсети %s закончились адреса", s.P("subnet"))
}

func (a *AWG) AddUser(env *module.Env, s *state.Service, name string, opts map[string]string) (*state.User, error) {
	ip, err := a.nextIP(s)
	if err != nil {
		return nil, err
	}
	priv, pub := x25519()
	psk, _ := x25519()
	u := &state.User{Name: name, Data: map[string]string{
		"private_key": base64.StdEncoding.EncodeToString(priv),
		"public_key":  base64.StdEncoding.EncodeToString(pub),
		"psk":         base64.StdEncoding.EncodeToString(psk),
		"ip":          ip,
	}}
	s.Users = append(s.Users, u)
	if s.Installed {
		if err := a.sync(env, s); err != nil {
			s.RemoveUser(name)
			return nil, err
		}
	}
	return u, nil
}

func (a *AWG) DelUser(env *module.Env, s *state.Service, name string) error {
	if !s.RemoveUser(name) {
		return fmt.Errorf("нет пользователя %s", name)
	}
	return a.sync(env, s)
}

func (a *AWG) Artifacts(env *module.Env, s *state.Service, u *state.User) ([]module.Artifact, error) {
	if u.Data["private_key"] == "" {
		return []module.Artifact{{Kind: "text", Title: "Пользователь перенят",
			Value: "Конфиг выдан раньше и продолжает работать (ключ сервера, порт и параметры обфускации сохранены). " +
				"Закрытый ключ клиента на сервере не хранится, поэтому показать конфиг нельзя. Новый конфиг: " +
				"vpnstack users awg del " + u.Name + " && vpnstack users awg add " + u.Name}}, nil
	}
	spub, err := wgPub(s.Secrets["private_key"])
	if err != nil {
		return nil, err
	}
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = %s\nMTU = %s\n%s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s:%s\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
		u.Data["private_key"], u.Data["ip"], s.P("dns"), s.P("mtu"), a.obf(s, false), spub, u.Data["psk"], env.Stack.PublicIP, s.P("port"))
	return []module.Artifact{{Kind: "file", Title: "Конфигурация AmneziaWG (AmneziaVPN / AmneziaWG — импорт файла или QR)", Name: safeName(u.Name) + ".conf", Value: conf, QR: true}}, nil
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func (a *AWG) UserTraffic(env *module.Env, s *state.Service) (map[string]module.Traffic, error) {
	out, err := sys.Output("awg", "show", awgIface, "dump")
	if err != nil {
		return nil, err
	}
	byKey := map[string]string{}
	for _, u := range s.Users {
		byKey[u.Data["public_key"]] = u.Name
	}
	res := map[string]module.Traffic{}
	for i, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(l, "\t")
		if i == 0 || len(f) < 7 {
			continue
		}
		name, ok := byKey[f[0]]
		if !ok {
			continue
		}
		rx, _ := strconv.ParseUint(f[5], 10, 64)
		tx, _ := strconv.ParseUint(f[6], 10, 64)
		res[name] = module.Traffic{Rx: rx, Tx: tx}
	}
	return res, nil
}

var _ = filepath.Join
