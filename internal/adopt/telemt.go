package adopt

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var hex32 = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

func scanTelemt(ps []proc) []*Found {
	var out []*Found
	for _, p := range ps {
		if ours(p) {
			continue
		}
		switch {
		case p.Exe == "telemt":
			cfgPath := "config.toml"
			for _, a := range p.Args {
				if !strings.HasPrefix(a, "-") {
					cfgPath = a
					break
				}
			}
			f := newFound("telemt", "MTProto (telemt)", originOf(p, "telemt"))
			b, err := p.read(cfgPath)
			if err != nil {
				f.Blocking = append(f.Blocking, "не прочитан конфиг "+cfgPath+": "+err.Error())
			} else {
				f.Origin.Configs = []string{p.path(cfgPath)}
				importTelemt(f, string(b))
			}
			out = append(out, f)
		case p.Exe == "mtg" && len(p.Args) > 0:
			f := newFound("telemt", "MTProto (mtg → telemt)", originOf(p, "mtg"))
			var secret, bind string
			switch p.Args[0] {
			case "simple-run":
				var pos []string
				for _, a := range p.Args[1:] {
					if !strings.HasPrefix(a, "-") {
						pos = append(pos, a)
					}
				}
				if len(pos) >= 2 {
					bind, secret = pos[0], pos[1]
				}
			case "run":
				cfgPath := "/etc/mtg.toml"
				if len(p.Args) > 1 {
					cfgPath = p.Args[len(p.Args)-1]
				}
				b, err := p.read(cfgPath)
				if err != nil {
					f.Blocking = append(f.Blocking, "не прочитан конфиг mtg "+cfgPath+": "+err.Error())
					break
				}
				f.Origin.Configs = []string{p.path(cfgPath)}
				d, err := parseTOML(string(b))
				if err != nil {
					f.Blocking = append(f.Blocking, "конфиг mtg не разобран: "+err.Error())
					break
				}
				secret = getStr(d.Root, "secret")
				bind = getStr(d.Root, "bind-to")
			}
			importMTG(f, secret, bind)
			out = append(out, f)
		}
	}
	return out
}

// importTelemt переносит конфиг telemt: пользователей с секретами, домен fake-TLS,
// ad_tag, порт и таблицы лимитов [access.user_*].
func importTelemt(f *Found, src string) {
	d, err := parseTOML(src)
	if err != nil {
		f.Blocking = append(f.Blocking, "конфиг telemt не разобран: "+err.Error())
		return
	}
	r := d.Root
	f.Params["tls_domain"] = getStr(r, "censorship", "tls_domain")
	if f.Params["tls_domain"] == "" {
		f.Blocking = append(f.Blocking, "в [censorship] нет tls_domain")
	}
	if v, ok := getPath(r, "general", "use_middle_proxy").(bool); ok {
		f.Params["middle_proxy"] = strconv.FormatBool(v)
	}
	f.Params["ad_tag"] = getStr(r, "general", "ad_tag")
	port := anyInt(getPath(r, "server", "port"))
	if port == 0 {
		if l, ok := getPath(r, "server", "listeners").([]any); ok && len(l) > 0 {
			port = anyInt(getPath(l[0], "port"))
		}
	}
	if port == 0 {
		port = 443
	}
	f.port("tcp", port)
	f.Params["port"] = strconv.Itoa(port)
	if port != 443 {
		f.Params["legacy_tcp"] = strconv.Itoa(port)
	}
	if m, ok := getPath(r, "general", "modes").(map[string]any); ok {
		if v, _ := m["tls"].(bool); !v {
			f.Risky = append(f.Risky, "режим fake-TLS выключен — vpnstack поддерживает только его; клиенты classic/secure перестанут работать")
		} else if c, _ := m["classic"].(bool); c {
			f.Risky = append(f.Risky, "включён режим classic — после переноса работают только ссылки fake-TLS (ee…)")
		} else if s, _ := m["secure"].(bool); s {
			f.Risky = append(f.Risky, "включён режим secure (dd…) — после переноса работают только ссылки fake-TLS (ee…)")
		}
	}
	users := getMap(r, "access", "users")
	var names []string
	for k := range users {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		sec := fmt.Sprint(users[n])
		if !hex32.MatchString(sec) {
			f.Warnings = append(f.Warnings, "у пользователя "+n+" необычный секрет — пропущен")
			continue
		}
		f.addUser(n, map[string]string{"secret": strings.ToLower(sec)})
		if f.Users[len(f.Users)-1].Name != n {
			f.Risky = append(f.Risky, "имя пользователя telemt «"+n+"» изменено на «"+f.Users[len(f.Users)-1].Name+"» — его квоты из [access.user_*] не совпадут")
		}
	}
	// Лимиты, квоты, сроки пользователей переносятся без изменений.
	var extra []string
	for _, k := range d.Keys {
		if strings.HasPrefix(k, "access.") && k != "access.users" {
			extra = append(extra, strings.TrimSpace(d.Raw[k]))
		}
	}
	f.Params["access_extra"] = strings.Join(extra, "\n\n")
	if a, ok := r["access"].(map[string]any); ok {
		for k, v := range a {
			if _, isTable := v.(map[string]any); !isTable {
				f.Warnings = append(f.Warnings, "параметр [access] "+k+" не переносится")
			}
		}
	}
}

// importMTG переводит mtg на telemt с тем же секретом: ссылка ee<ключ><домен> не меняется.
func importMTG(f *Found, secret, bind string) {
	key, domain, err := decodeFakeTLS(secret)
	if err != nil {
		f.Blocking = append(f.Blocking, "секрет mtg: "+err.Error())
		return
	}
	port := portOf(bind)
	if port == 0 {
		port = 443
	}
	f.port("tcp", port)
	f.Params["tls_domain"] = domain
	f.Params["port"] = strconv.Itoa(port)
	f.Params["middle_proxy"] = "false"
	if port != 443 {
		f.Params["legacy_tcp"] = strconv.Itoa(port)
	}
	f.addUser("legacy", map[string]string{"secret": key})
	f.Warnings = append(f.Warnings, "mtg заменяется на telemt с тем же секретом и доменом — ссылка tg://proxy не меняется")
}

// decodeFakeTLS разбирает секрет fake-TLS: ee + 16 байт ключа + домен (hex или base64).
func decodeFakeTLS(s string) (key, domain string, err error) {
	s = strings.TrimSpace(s)
	var raw []byte
	if b, e := hex.DecodeString(s); e == nil {
		raw = b
	} else {
		for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
			if b, e := enc.DecodeString(s); e == nil {
				raw = b
				break
			}
		}
	}
	if len(raw) < 18 || raw[0] != 0xee {
		return "", "", fmt.Errorf("ожидался секрет fake-TLS (ee…), получено %q", s)
	}
	return hex.EncodeToString(raw[1:17]), string(raw[17:]), nil
}
