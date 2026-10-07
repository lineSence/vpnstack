// Package netfilter управляет таблицей nftables `inet vpnstack`:
// защита внутренних портов, счётчики трафика UDP-сервисов и правила модулей (NAT).
package netfilter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/lineSence/vpnstack/internal/sys"
)

// ConfPath — файл правил, загружаемый юнитом vpnstack-nft.service при загрузке.
var ConfPath = "/etc/vpnstack/nft.conf"

// Counter — именованный счётчик трафика для UDP-порта сервиса.
type Counter struct {
	Service string
	Port    int
}

// Spec — что нужно отразить в таблице.
type Spec struct {
	InternalTCP []int     // порты только для loopback
	UDP         []Counter // публичные UDP-порты с учётом трафика
	Extra       []string  // цепочки модулей
}

func cname(id, dir string) string { return strings.ReplaceAll(id, "-", "_") + "_" + dir }

// Render собирает файл правил (идемпотентный: таблица пересоздаётся целиком).
func Render(sp Spec) string {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n# Сгенерировано vpnstack\ntable inet vpnstack\ndelete table inet vpnstack\n\ntable inet vpnstack {\n")
	for _, c := range sp.UDP {
		fmt.Fprintf(&b, "\tcounter %s {}\n\tcounter %s {}\n", cname(c.Service, "rx"), cname(c.Service, "tx"))
	}
	b.WriteString("\n\tchain input {\n\t\ttype filter hook input priority filter - 10; policy accept;\n")
	if len(sp.InternalTCP) > 0 {
		sort.Ints(sp.InternalTCP)
		var ps []string
		for _, p := range sp.InternalTCP {
			ps = append(ps, fmt.Sprint(p))
		}
		fmt.Fprintf(&b, "\t\tiifname != \"lo\" tcp dport { %s } drop\n", strings.Join(ps, ", "))
	}
	for _, c := range sp.UDP {
		fmt.Fprintf(&b, "\t\tudp dport %d counter name %s\n", c.Port, cname(c.Service, "rx"))
	}
	b.WriteString("\t}\n\n\tchain output {\n\t\ttype filter hook output priority filter - 10; policy accept;\n")
	for _, c := range sp.UDP {
		fmt.Fprintf(&b, "\t\tudp sport %d counter name %s\n", c.Port, cname(c.Service, "tx"))
	}
	b.WriteString("\t}\n")
	for _, e := range sp.Extra {
		for _, l := range strings.Split(strings.TrimRight(e, "\n"), "\n") {
			b.WriteString("\n\t" + l)
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

const unit = `[Unit]
Description=vpnstack: правила nftables
After=nftables.service
PartOf=nftables.service
Before=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/vpnstack/nft.conf
ExecReload=/usr/sbin/nft -f /etc/vpnstack/nft.conf
ExecStop=-/usr/sbin/nft delete table inet vpnstack

[Install]
WantedBy=multi-user.target
`

// Apply проверяет и применяет правила, включает загрузку при старте.
func Apply(sp Spec) error {
	if !sys.Has("nft") {
		if _, err := sys.Run("apt-get", "install", "-y", "--no-install-recommends", "nftables"); err != nil {
			return err
		}
	}
	conf := Render(sp)
	tmp := ConfPath + ".check"
	if err := sys.WriteFileAtomic(tmp, []byte(conf), 0o600); err != nil {
		return err
	}
	if _, err := sys.Run("nft", "-c", "-f", tmp); err != nil {
		return fmt.Errorf("правила nftables не прошли проверку: %w", err)
	}
	if err := sys.WriteFileAtomic(ConfPath, []byte(conf), 0o600); err != nil {
		return err
	}
	if err := sys.WriteUnit("vpnstack-nft.service", unit); err != nil {
		return err
	}
	_ = sys.Systemctl("enable", "vpnstack-nft.service")
	return sys.Systemctl("restart", "vpnstack-nft.service")
}

// Counters читает счётчики: service -> (rx, tx) байт.
func Counters() map[string][2]uint64 {
	out, err := sys.Output("nft", "-j", "list", "counters", "table", "inet", "vpnstack")
	res := map[string][2]uint64{}
	if err != nil {
		return res
	}
	var r struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &r) != nil {
		return res
	}
	for _, it := range r.Nftables {
		raw, ok := it["counter"]
		if !ok {
			continue
		}
		var c struct {
			Name  string `json:"name"`
			Bytes uint64 `json:"bytes"`
		}
		if json.Unmarshal(raw, &c) != nil {
			continue
		}
		i := strings.LastIndex(c.Name, "_")
		if i < 0 {
			continue
		}
		id, dir := c.Name[:i], c.Name[i+1:]
		v := res[id]
		if dir == "rx" {
			v[0] = c.Bytes
		} else {
			v[1] = c.Bytes
		}
		res[id] = v
	}
	return res
}

// SysctlPath — параметры ядра стека.
var SysctlPath = "/etc/sysctl.d/90-vpnstack.conf"

// ApplySysctl пишет и применяет параметры ядра (BBR, буферы для QUIC, форвардинг).
func ApplySysctl(extra map[string]string) error {
	m := map[string]string{
		"net.core.default_qdisc":          "fq",
		"net.ipv4.tcp_congestion_control": "bbr",
		// Hysteria рекомендует буферы UDP 16 МБ.
		"net.core.rmem_max": "16777216",
		"net.core.wmem_max": "16777216",
	}
	for k, v := range extra {
		m[k] = v
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Сгенерировано vpnstack\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, m[k])
	}
	if err := sys.WriteFileAtomic(SysctlPath, []byte(b.String()), 0o644); err != nil {
		return err
	}
	_, err := sys.Run("sysctl", "-p", SysctlPath)
	return err
}
