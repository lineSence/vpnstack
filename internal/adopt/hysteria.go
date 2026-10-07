package adopt

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

func scanHysteria(ps []proc) []*Found {
	var out []*Found
	for _, p := range ps {
		if ours(p) || !strings.HasPrefix(p.Exe, "hysteria") || !contains(p.Args, "server") {
			continue
		}
		cfgPath := p.flag("-c", "--config")
		var data []byte
		var err error
		if cfgPath == "" {
			for _, c := range []string{"config.yaml", "config.yml", "/etc/hysteria/config.yaml"} {
				if data, err = p.read(c); err == nil {
					cfgPath = c
					break
				}
			}
		} else {
			data, err = p.read(cfgPath)
		}
		o := originOf(p, "Hysteria 2")
		f := newFound("hysteria", "Hysteria 2", o)
		if err != nil {
			f.Blocking = append(f.Blocking, fmt.Sprintf("не удалось прочитать конфиг %q: %v", cfgPath, err))
			out = append(out, f)
			continue
		}
		f.Origin.Configs = []string{p.path(cfgPath)}
		importHysteria(f, string(data), p)
		out = append(out, f)
	}
	return out
}

// importHysteria переносит конфиг Hysteria 2 в параметры модуля hysteria.
func importHysteria(f *Found, src string, p proc) {
	cfg, err := parseYAML(src)
	if err != nil {
		f.Blocking = append(f.Blocking, "конфиг Hysteria не разобран: "+err.Error())
		return
	}
	listen := getStr(cfg, "listen")
	if listen == "" {
		listen = ":443"
	}
	port := portOf(listen)
	f.Params["port"] = strconv.Itoa(port)
	f.port("udp", port)

	// Сертификат.
	switch {
	case getMap(cfg, "acme") != nil:
		doms := getList(cfg, "acme", "domains")
		if len(doms) == 0 {
			f.Blocking = append(f.Blocking, "acme без доменов")
			break
		}
		f.Params["domain"] = doms[0]
		if len(doms) > 1 {
			f.Warnings = append(f.Warnings, "в acme несколько доменов — используется "+doms[0])
		}
		dir := getStr(cfg, "acme", "dir")
		if dir == "" {
			dir = firstNonEmpty(p.env("HYSTERIA_ACME_DIR"), "acme")
		}
		// certmagic: <dir>/certificates/<issuer>/<domain>/<domain>.crt
		if m, _ := filepath.Glob(filepath.Join(p.path(dir), "certificates", "*", doms[0], doms[0]+".crt")); len(m) > 0 {
			f.Origin.Files["cert"] = m[0]
			f.Origin.Files["key"] = strings.TrimSuffix(m[0], ".crt") + ".key"
			f.Origin.Files["certmagic"] = filepath.Dir(m[0])
		} else {
			f.Warnings = append(f.Warnings, "сертификат ACME не найден в "+dir+" — Caddy выпустит новый (нужны A-запись и TCP 80/443)")
		}
	case getStr(cfg, "tls", "cert") != "":
		certPath, keyPath := getStr(cfg, "tls", "cert"), getStr(cfg, "tls", "key")
		f.Origin.Files["cert"], f.Origin.Files["key"] = p.path(certPath), p.path(keyPath)
		b, err := p.read(certPath)
		if err != nil {
			f.Blocking = append(f.Blocking, "не прочитан сертификат "+certPath+": "+err.Error())
			break
		}
		c, der := firstCert(b)
		if c == nil {
			f.Blocking = append(f.Blocking, "в "+certPath+" нет сертификата")
			break
		}
		if selfSignedCert(c) {
			// Клиенты, скорее всего, держат pinSHA256 или insecure=1: сертификат сохраняется как есть.
			sum := sha256.Sum256(der)
			f.Secrets["self_signed"] = "true"
			f.Secrets["pin_sha256"] = hex.EncodeToString(sum[:])
			f.Params["sni"] = firstNonEmpty(firstOf(c.DNSNames), c.Subject.CommonName, "bing.com")
			f.Params["domain"] = ""
		} else {
			d := ""
			for _, n := range c.DNSNames {
				if !strings.HasPrefix(n, "*.") {
					d = n
					break
				}
			}
			if d == "" {
				f.Blocking = append(f.Blocking, "в сертификате нет подходящего имени (только wildcard) — укажите домен вручную после импорта: vpnstack set hysteria domain=…")
				break
			}
			f.Params["domain"] = d
			f.Warnings = append(f.Warnings, "сертификат "+certPath+" (выдан "+c.Issuer.CommonName+") будет использоваться, пока Caddy не получит свой для "+d)
		}
	default:
		f.Blocking = append(f.Blocking, "в конфиге нет ни tls, ни acme")
	}

	// Обфускация.
	switch t := strings.ToLower(getStr(cfg, "obfs", "type")); t {
	case "":
	case "salamander", "gecko":
		f.Params["obfs"] = "true"
		f.Params["obfs_type"] = t
		f.Secrets["obfs_password"] = getStr(cfg, "obfs", t, "password")
		if t == "gecko" {
			f.Params["gecko_min"] = getStr(cfg, "obfs", "gecko", "minPacketSize")
			f.Params["gecko_max"] = getStr(cfg, "obfs", "gecko", "maxPacketSize")
		}
	default:
		f.Blocking = append(f.Blocking, "неизвестный тип obfs: "+t)
	}
	if f.Params["obfs"] == "" {
		f.Params["obfs"] = "false"
	}

	// Пользователи.
	switch t := strings.ToLower(getStr(cfg, "auth", "type")); t {
	case "password":
		pw := getStr(cfg, "auth", "password")
		if pw == "" {
			f.Blocking = append(f.Blocking, "auth.password пуст")
			break
		}
		f.addUser("legacy", map[string]string{"password": pw, "legacy": "1"})
		f.Warnings = append(f.Warnings, "общий пароль сохранён как пользователь «legacy»: старые ссылки работают, новым людям выдавайте личные логины (vpnstack users hysteria add NAME)")
	case "userpass":
		up := getMap(cfg, "auth", "userpass")
		for _, name := range sortedKeys(up) {
			// login — логин как в старом конфиге (имя в vpnstack может отличаться).
			f.addUser(name, map[string]string{"password": fmt.Sprint(up[name]), "login": strings.ToLower(name)})
		}
	case "":
		f.Blocking = append(f.Blocking, "в конфиге нет auth")
	default:
		f.Blocking = append(f.Blocking, "auth.type "+t+": пользователи хранятся во внешней системе — автоматический перенос невозможен")
	}

	// Скорость.
	if up, down := mbps(getStr(cfg, "bandwidth", "up")), mbps(getStr(cfg, "bandwidth", "down")); up > 0 && down > 0 {
		f.Params["up_mbps"], f.Params["down_mbps"] = strconv.Itoa(up), strconv.Itoa(down)
	}
	if m := strings.ToLower(getStr(cfg, "masquerade", "type")); m != "" && m != "file" {
		f.Warnings = append(f.Warnings, "маскировка «"+m+"» заменяется сайтом-прикрытием vpnstack (клиентов не касается)")
	}
	for _, k := range []string{"acl", "outbounds"} {
		if getPath(cfg, k) != nil {
			f.Risky = append(f.Risky, "в конфиге есть «"+k+"» (маршрутизация трафика) — vpnstack его не переносит, трафик пойдёт напрямую")
		}
	}
	for _, k := range []string{"resolver", "sniff", "quic", "udpIdleTimeout", "ignoreClientBandwidth", "speedTest", "disableUDP"} {
		if getPath(cfg, k) != nil {
			f.Warnings = append(f.Warnings, "параметр «"+k+"» не переносится (используются значения по умолчанию)")
		}
	}
}

// mbps — «100 mbps», «1 gbps», «50m» → Мбит/с.
func mbps(s string) int {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if s == "" {
		return 0
	}
	mult := 1.0
	for _, u := range []struct {
		suf string
		m   float64
	}{{"gbps", 1000}, {"g", 1000}, {"mbps", 1}, {"m", 1}, {"kbps", 0.001}, {"k", 0.001}, {"bps", 1e-6}} {
		if strings.HasSuffix(s, u.suf) {
			s, mult = strings.TrimSuffix(s, u.suf), u.m
			break
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int(v * mult)
}

func firstCert(b []byte) (*x509.Certificate, []byte) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, nil
		}
		if blk.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(blk.Bytes)
			if err == nil {
				return c, blk.Bytes
			}
		}
	}
}

func selfSignedCert(c *x509.Certificate) bool {
	// CheckSignatureFrom требует CA:TRUE, а самоподписанные сертификаты часто без него.
	return c.Issuer.String() == c.Subject.String() && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func firstOf(l []string) string {
	if len(l) > 0 {
		return l[0]
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sortStrings(k)
	return k
}
