package adopt

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lineSence/vpnstack/internal/state"
)

const ownAWGIface = "awgvs0"

func scanAWG(ps []proc) []*Found {
	var out []*Found
	// Нативные интерфейсы awg-quick@IFACE.
	units, _ := run("systemctl", "list-units", "awg-quick@*", "--plain", "--no-legend", "--state=active")
	for _, l := range strings.Split(units, "\n") {
		fs := strings.Fields(l)
		if len(fs) == 0 || !strings.HasPrefix(fs[0], "awg-quick@") {
			continue
		}
		unit := fs[0]
		iface := strings.TrimSuffix(strings.TrimPrefix(unit, "awg-quick@"), ".service")
		if iface == ownAWGIface {
			continue
		}
		conf := firstExisting(hostPath("/etc/amnezia/amneziawg/"+iface+".conf"), hostPath("/etc/amneziawg/"+iface+".conf"))
		o := state.Origin{Kind: "systemd", Source: "AmneziaWG (" + unit + ")", Units: []string{unit}, State: state.OriginImported,
			ImportedAt: time.Now(), Files: map[string]string{}}
		f := newFound("awg", "AmneziaWG ("+iface+")", o)
		b, err := os.ReadFile(conf)
		if err != nil {
			f.Blocking = append(f.Blocking, "не прочитан конфиг "+iface+": "+err.Error())
		} else {
			f.Origin.Configs = []string{conf}
			importAWG(f, string(b), nil)
		}
		out = append(out, f)
	}
	// Контейнер приложения AmneziaVPN (amnezia-awg, amnezia-awg2).
	for _, c := range dockerPS() {
		if !strings.HasPrefix(c.Name, "amnezia-awg") {
			continue
		}
		o := state.Origin{Kind: "docker", Source: "AmneziaWG из приложения AmneziaVPN (контейнер " + c.Name + ")", Containers: []string{c.ID},
			State: state.OriginImported, ImportedAt: time.Now(), Files: map[string]string{}}
		f := newFound("awg", "AmneziaWG (AmneziaVPN, "+c.Name+")", o)
		root := filepath.Join(procDir, strconv.Itoa(c.Pid), "root")
		m, _ := filepath.Glob(filepath.Join(root, "opt/amnezia/awg/*.conf"))
		if c.Pid == 0 || len(m) == 0 {
			f.Blocking = append(f.Blocking, "не найден конфиг в контейнере "+c.Name+" (/opt/amnezia/awg/*.conf)")
			out = append(out, f)
			continue
		}
		sort.Strings(m)
		b, _ := os.ReadFile(m[0])
		names := map[string]string{}
		if tb, err := os.ReadFile(filepath.Join(root, "opt/amnezia/awg/clientsTable")); err == nil {
			var tbl []struct {
				ClientID string `json:"clientId"`
				UserData struct {
					ClientName string `json:"clientName"`
				} `json:"userData"`
			}
			if json.Unmarshal(tb, &tbl) == nil {
				for _, t := range tbl {
					names[t.ClientID] = t.UserData.ClientName
				}
			}
		}
		f.Origin.Configs = []string{m[0]}
		importAWG(f, string(b), names)
		f.Risky = append(f.Risky, "сервер перестанет управляться из приложения AmneziaVPN (контейнер будет остановлен); клиенты продолжат работать")
		out = append(out, f)
	}
	_ = ps
	return out
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return paths[0]
}

// importAWG переносит интерфейс: ключ сервера, порт, адрес, все параметры обфускации
// и пиров (открытые ключи, PSK, адреса). names — имена клиентов по открытому ключу.
func importAWG(f *Found, src string, names map[string]string) {
	secs := parseWGConf(src)
	var iface *iniSection
	for i := range secs {
		if secs[i].Name == "interface" {
			iface = &secs[i]
			break
		}
	}
	if iface == nil {
		f.Blocking = append(f.Blocking, "в конфиге нет [Interface]")
		return
	}
	k := iface.Keys
	f.Secrets["private_key"] = k["privatekey"]
	if k["privatekey"] == "" {
		f.Blocking = append(f.Blocking, "в [Interface] нет PrivateKey")
	}
	port, _ := strconv.Atoi(k["listenport"])
	if port == 0 {
		f.Blocking = append(f.Blocking, "в [Interface] нет ListenPort")
	}
	f.Params["port"] = strconv.Itoa(port)
	f.port("udp", port)
	var addr4 string
	for _, a := range strings.Split(k["address"], ",") {
		if a = strings.TrimSpace(a); strings.Contains(a, ".") {
			addr4 = a
			break
		}
	}
	ip, n, err := net.ParseCIDR(addr4)
	if err != nil {
		f.Blocking = append(f.Blocking, "в [Interface] нет IPv4-адреса (Address)")
		return
	}
	if strings.Contains(k["address"], ":") {
		f.Warnings = append(f.Warnings, "IPv6-адрес интерфейса не переносится (клиенты подключатся, но без IPv6 внутри туннеля)")
	}
	f.Params["subnet"] = n.String()
	gw := n.IP.To4()
	gw = net.IPv4(gw[0], gw[1], gw[2], gw[3]+1)
	if !ip.Equal(gw) {
		f.Params["server_ip"] = ip.String()
	}
	f.Params["mtu"] = firstNonEmpty(k["mtu"], "1420")
	// Обфускация: отсутствующий параметр AWG считает нулём — переносим явно.
	defs := map[string]string{"jc": "0", "jmin": "0", "jmax": "0", "s1": "0", "s2": "0", "s3": "0", "s4": "0", "h1": "1", "h2": "2", "h3": "3", "h4": "4"}
	for key, def := range defs {
		f.Params[key] = firstNonEmpty(k[key], def)
	}
	for i := 1; i <= 5; i++ {
		f.Params[fmt.Sprintf("i%d", i)] = k[fmt.Sprintf("i%d", i)]
	}
	switch {
	case k["headerprotectionkey"] != "":
		f.Secrets["header_protection_key"] = k["headerprotectionkey"]
		f.Params["content_padding"] = firstNonEmpty(k["contentpaddingaddition"], "0")
		f.Params["random_trailers"] = boolStr(k["randomtrailers"])
		f.Params["disable_cookies"] = boolStr(k["disablecookies"])
		f.Params["awg_version"] = "3.0"
		if _, ok := k["randomtrailers"]; ok {
			f.Params["awg_version"] = "3.1"
		} else if _, ok := k["disablecookies"]; ok {
			f.Params["awg_version"] = "3.1"
		}
	case f.Params["s3"] != "0" || f.Params["s4"] != "0" || strings.Contains(k["h1"]+k["h2"]+k["h3"]+k["h4"], "-"):
		f.Params["awg_version"] = "2.0"
	default:
		f.Params["awg_version"] = "1.5"
		if k["jc"] == "" && k["h1"] == "" {
			f.Warnings = append(f.Warnings, "параметров обфускации нет — это обычный WireGuard-совместимый режим")
		}
	}
	known := map[string]bool{"privatekey": true, "address": true, "listenport": true, "mtu": true, "dns": true, "postup": true, "postdown": true,
		"preup": true, "predown": true, "table": true, "saveconfig": true, "fwmark": true, "headerprotectionkey": true,
		"contentpaddingaddition": true, "randomtrailers": true, "disablecookies": true}
	for key := range defs {
		known[key] = true
	}
	for i := 1; i <= 5; i++ {
		known[fmt.Sprintf("i%d", i)] = true
	}
	var extra []string
	for _, orig := range iface.Order {
		if !known[strings.ToLower(orig)] {
			extra = append(extra, orig+" = "+k[strings.ToLower(orig)])
		}
	}
	f.Params["iface_extra"] = strings.Join(extra, "\n")
	if k["postup"] != "" {
		f.Warnings = append(f.Warnings, "PostUp/PostDown заменяются правилами nftables vpnstack (NAT клиентов наружу)")
	}
	// Пиры.
	for _, s := range secs {
		if s.Name != "peer" {
			continue
		}
		pub := s.Keys["publickey"]
		if pub == "" {
			continue
		}
		var ip4 string
		for _, a := range strings.Split(s.Keys["allowedips"], ",") {
			a = strings.TrimSpace(a)
			if strings.HasSuffix(a, "/32") && strings.Contains(a, ".") {
				ip4 = strings.TrimSuffix(a, "/32")
				break
			}
		}
		data := map[string]string{"public_key": pub, "psk": s.Keys["presharedkey"], "ip": ip4}
		if ip4 == "" || strings.Contains(s.Keys["allowedips"], ",") {
			data["allowed_ips"] = s.Keys["allowedips"]
		}
		name := firstNonEmpty(names[pub], s.Comment, "peer")
		f.addUser(name, data)
	}
}

func boolStr(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return "true"
	}
	return "false"
}
