package adopt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func scanXray(ps []proc) []*Found {
	var out []*Found
	for _, p := range ps {
		if ours(p) || !(strings.HasPrefix(p.Exe, "xray") || strings.HasPrefix(p.Exe, "Xray")) {
			continue
		}
		title := "Xray"
		o := originOf(p, title)
		if strings.HasPrefix(p.Unit, "x-ui") || strings.Contains(p.Unit, "3x-ui") {
			o.Kind = "x-ui"
			title = "Xray (панель " + strings.TrimSuffix(p.Unit, ".service") + ")"
			o.Source = title
		}
		f := newFound("xray", title, o)
		files, err := xrayConfigFiles(p)
		if err != nil || len(files) == 0 {
			f.Blocking = append(f.Blocking, fmt.Sprintf("не найден конфиг Xray: %v", err))
			out = append(out, f)
			continue
		}
		var inbounds []any
		for _, fp := range files {
			b, err := os.ReadFile(fp)
			if err != nil {
				f.Blocking = append(f.Blocking, "не прочитан "+fp+": "+err.Error())
				continue
			}
			var cfg map[string]any
			if err := json.Unmarshal(stripJSONComments(b), &cfg); err != nil {
				f.Blocking = append(f.Blocking, "конфиг "+fp+" не разобран: "+err.Error())
				continue
			}
			if l, ok := cfg["inbounds"].([]any); ok {
				inbounds = append(inbounds, l...)
			}
			f.Origin.Configs = append(f.Origin.Configs, fp)
		}
		if o.Kind == "x-ui" {
			f.Risky = append(f.Risky, "панель "+p.Unit+" будет остановлена (она перезапускала бы Xray); лимиты трафика и сроки клиентов из её базы не переносятся")
		}
		importXray(f, inbounds)
		out = append(out, f)
	}
	return out
}

// xrayConfigFiles — конфиги процесса Xray (-c/-config, -confdir, переменные окружения, путь по умолчанию).
func xrayConfigFiles(p proc) ([]string, error) {
	var files []string
	for i, a := range p.Args {
		var v string
		switch {
		case (a == "-c" || a == "-config" || a == "--config") && i+1 < len(p.Args):
			v = p.Args[i+1]
		case strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config=") || strings.HasPrefix(a, "-c="):
			_, v, _ = strings.Cut(a, "=")
		case (a == "-confdir" || a == "--confdir") && i+1 < len(p.Args):
			m, _ := filepath.Glob(filepath.Join(p.path(p.Args[i+1]), "*.json"))
			sort.Strings(m)
			files = append(files, m...)
			continue
		default:
			continue
		}
		if v != "" && v != "stdin:" {
			files = append(files, p.path(v))
		}
	}
	if len(files) == 0 {
		if d := p.env("XRAY_LOCATION_CONFDIR"); d != "" {
			m, _ := filepath.Glob(filepath.Join(p.path(d), "*.json"))
			files = append(files, m...)
		}
	}
	if len(files) == 0 {
		for _, c := range []string{p.env("XRAY_LOCATION_CONFIG"), "/usr/local/etc/xray/config.json", "/etc/xray/config.json", "config.json"} {
			if c != "" {
				if _, err := os.Stat(p.path(c)); err == nil {
					files = append(files, p.path(c))
					break
				}
			}
		}
	}
	return files, nil
}

// importXray берёт первый inbound VLESS + REALITY: клиентов (UUID, flow), ключи,
// все shortIds и serverNames, транспорт — чтобы старые ссылки продолжили работать.
func importXray(f *Found, inbounds []any) {
	var reality []map[string]any
	var others []string
	for _, it := range inbounds {
		in, _ := it.(map[string]any)
		if in == nil {
			continue
		}
		proto, _ := in["protocol"].(string)
		sec := getStr(in, "streamSettings", "security")
		tag, _ := in["tag"].(string)
		if proto == "vless" && sec == "reality" {
			reality = append(reality, in)
			continue
		}
		if proto == "dokodemo-door" && tag == "api" || proto == "" {
			continue
		}
		if n := len(clientsOf(in)); n > 0 {
			others = append(others, fmt.Sprintf("%s/%s (%s, %d клиентов)", proto, firstNonEmpty(sec, "none"), firstNonEmpty(tag, "без тега"), n))
		}
	}
	if len(reality) == 0 {
		f.Blocking = append(f.Blocking, "нет inbound VLESS + REALITY — переносится только он")
		return
	}
	if len(reality) > 1 {
		f.Risky = append(f.Risky, fmt.Sprintf("inbound'ов VLESS + REALITY: %d — переносится первый (порт %v), остальные перестанут работать", len(reality), reality[0]["port"]))
	}
	if len(others) > 0 {
		f.Risky = append(f.Risky, "другие inbound'ы не переносятся и перестанут работать: "+strings.Join(others, "; "))
	}
	in := reality[0]
	port := anyInt(in["port"])
	if port == 0 {
		f.Blocking = append(f.Blocking, fmt.Sprintf("порт inbound не число: %v", in["port"]))
		return
	}
	f.port("tcp", port)
	f.Params["port"] = strconv.Itoa(port)
	if port != 443 {
		f.Params["legacy_tcp"] = strconv.Itoa(port)
	}
	rs := getMap(in, "streamSettings", "realitySettings")
	f.Secrets["private_key"] = getStr(rs, "privateKey")
	if f.Secrets["private_key"] == "" {
		f.Blocking = append(f.Blocking, "в realitySettings нет privateKey")
	}
	names := getList(rs, "serverNames")
	var primary string
	var rest []string
	for _, n := range names {
		if primary == "" && n != "" && !strings.HasPrefix(n, "*") {
			primary = n
		} else if n != "" {
			rest = append(rest, n)
		}
	}
	if primary == "" {
		f.Blocking = append(f.Blocking, "в realitySettings нет serverNames")
	}
	f.Params["sni"] = primary
	f.Params["server_names"] = strings.Join(rest, ",")
	target := getStr(rs, "target")
	if target == "" {
		target = getStr(rs, "dest")
	}
	if _, err := strconv.Atoi(target); err == nil || strings.HasPrefix(target, "127.") || strings.HasPrefix(target, "localhost") || strings.HasPrefix(target, "/") || strings.HasPrefix(target, "@") {
		f.Risky = append(f.Risky, "цель REALITY «"+target+"» — локальный адрес; после переноса она будет заменена на "+primary+":443")
		target = primary + ":443"
	}
	f.Params["target"] = target
	f.Params["fingerprint"] = "chrome"
	sids := getList(rs, "shortIds")
	f.Secrets["short_id"] = ""
	for _, id := range sids {
		if id != "" {
			f.Secrets["short_id"] = id
			break
		}
	}
	f.Secrets["short_ids"] = jsonString(sids)
	if v := getStr(rs, "mldsa65Seed"); v != "" {
		f.Secrets["mldsa65_seed"] = v
		f.Warnings = append(f.Warnings, "включён ML-DSA-65: старые ссылки работают; для новых ссылок укажите pqv: vpnstack set xray mldsa65_verify=…")
	}
	if dec := getStr(in, "settings", "decryption"); dec != "" && dec != "none" {
		f.Secrets["decryption"] = dec
		f.Warnings = append(f.Warnings, "включено VLESS Encryption: старые ссылки работают; для новых укажите клиентскую строку: vpnstack set xray client_encryption=…")
	}
	// Транспорт: raw/tcp — штатный; остальные переносятся целиком.
	st := getMap(in, "streamSettings")
	netw := strings.ToLower(firstNonEmpty(getStr(st, "network"), "raw"))
	if netw != "raw" && netw != "tcp" {
		keep := map[string]any{}
		for k, v := range st {
			if k != "security" && k != "realitySettings" && k != "sockopt" {
				keep[k] = v
			}
		}
		f.Params["stream_json"] = jsonString(keep)
		switch netw {
		case "xhttp", "splithttp":
			f.Params["xhttp_path"] = getStr(st, "xhttpSettings", "path")
			f.Params["xhttp_mode"] = getStr(st, "xhttpSettings", "mode")
		case "grpc":
			f.Params["grpc_service"] = getStr(st, "grpcSettings", "serviceName")
		default:
			f.Warnings = append(f.Warnings, "транспорт "+netw+" перенесён как есть; ссылки для новых пользователей проверьте вручную")
		}
	} else if h := getStr(st, "rawSettings", "header", "type"); h != "" && h != "none" {
		f.Risky = append(f.Risky, "rawSettings.header "+h+" не переносится")
	}
	for i, c := range clientsOf(in) {
		id := getStr(c, "id")
		if id == "" {
			continue
		}
		data := map[string]string{"uuid": id, "flow": getStr(c, "flow")}
		f.addUser(firstNonEmpty(getStr(c, "email"), fmt.Sprintf("user%d", i+1)), data)
	}
	if len(f.Users) == 0 {
		f.Warnings = append(f.Warnings, "в inbound нет клиентов")
	}
}

func clientsOf(in map[string]any) []map[string]any {
	var out []map[string]any
	for _, k := range []string{"clients", "users"} {
		if l, ok := getPath(in, "settings", k).([]any); ok {
			for _, c := range l {
				if m, ok := c.(map[string]any); ok {
					out = append(out, m)
				}
			}
		}
	}
	return out
}

// stripJSONComments убирает // и /* */ вне строк (Xray принимает такие конфиги).
func stripJSONComments(b []byte) []byte {
	var out []byte
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		case c == '#' && (len(out) == 0 || out[len(out)-1] == '\n'):
			for i < len(b) && b[i] != '\n' {
				i++
			}
		default:
			out = append(out, c)
		}
	}
	return out
}
