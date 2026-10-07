package adopt

import "strings"

// Разбор конфигов WireGuard/AmneziaWG: секции [Interface] и [Peer], «Ключ = значение».
// Комментарий перед [Peer] (# имя, ### Client имя) считается именем клиента.

type iniSection struct {
	Name    string
	Keys    map[string]string // ключи в нижнем регистре
	Order   []string          // исходные имена ключей по порядку
	Comment string
}

func parseWGConf(src string) []iniSection {
	var out []iniSection
	var cur *iniSection
	lastComment := ""
	for _, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		l := strings.TrimSpace(raw)
		switch {
		case l == "":
			continue
		case strings.HasPrefix(l, "#"):
			c := strings.TrimSpace(strings.TrimLeft(l, "#"))
			c = strings.TrimSpace(strings.TrimPrefix(c, "Client"))
			c = strings.TrimSpace(strings.TrimPrefix(c, ":"))
			if c != "" && !strings.Contains(c, "=") {
				lastComment = c
			}
			continue
		case strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]"):
			out = append(out, iniSection{Name: strings.ToLower(strings.Trim(l, "[] ")), Keys: map[string]string{}, Comment: lastComment})
			cur = &out[len(out)-1]
			lastComment = ""
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		lk := strings.ToLower(k)
		if _, dup := cur.Keys[lk]; dup && lk == "allowedips" {
			cur.Keys[lk] += ", " + v
			continue
		}
		cur.Keys[lk] = v
		cur.Order = append(cur.Order, k)
	}
	return out
}
