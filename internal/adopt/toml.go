package adopt

import (
	"fmt"
	"strconv"
	"strings"
)

// Минимальный разбор TOML для конфигов telemt и mtg: [таблицы], [[массивы таблиц]],
// ключи (в т. ч. "в кавычках" и a.b), строки "…"/'…', числа, true/false, массивы
// (в т. ч. многострочные), встроенные таблицы {…} — как строка. Кроме дерева
// сохраняется исходный текст каждой таблицы (Raw) — чтобы перенести её без изменений.

type tomlDoc struct {
	Root map[string]any
	Raw  map[string]string // имя таблицы → её исходный текст (с заголовком)
	Keys []string          // порядок таблиц
}

func parseTOML(src string) (*tomlDoc, error) {
	d := &tomlDoc{Root: map[string]any{}, Raw: map[string]string{}}
	cur := d.Root
	curName := ""
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		l := strings.TrimSpace(stripTOMLComment(raw))
		if l == "" {
			if curName != "" {
				d.Raw[curName] += raw + "\n"
			}
			continue
		}
		if strings.HasPrefix(l, "[[") && strings.HasSuffix(l, "]]") {
			name := strings.TrimSpace(l[2 : len(l)-2])
			parent, last, err := d.walk(splitDotted(name))
			if err != nil {
				return nil, fmt.Errorf("строка %d: %w", i+1, err)
			}
			arr, _ := parent[last].([]any)
			t := map[string]any{}
			parent[last] = append(arr, t)
			cur, curName = t, name+"[]"
			d.Raw[curName] += raw + "\n"
			d.Keys = append(d.Keys, curName)
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			name := strings.TrimSpace(l[1 : len(l)-1])
			parent, last, err := d.walk(splitDotted(name))
			if err != nil {
				return nil, fmt.Errorf("строка %d: %w", i+1, err)
			}
			t, ok := parent[last].(map[string]any)
			if !ok {
				t = map[string]any{}
				parent[last] = t
			}
			cur, curName = t, name
			d.Raw[curName] += raw + "\n"
			d.Keys = append(d.Keys, curName)
			continue
		}
		k, v, ok := splitTOMLKey(l)
		if !ok {
			return nil, fmt.Errorf("строка %d: ожидалось «ключ = значение»", i+1)
		}
		text := raw + "\n"
		// Многострочный массив.
		for strings.HasPrefix(v, "[") && !balanced(v) && i+1 < len(lines) {
			i++
			text += lines[i] + "\n"
			v += " " + strings.TrimSpace(stripTOMLComment(lines[i]))
		}
		val, err := tomlValue(v)
		if err != nil {
			return nil, fmt.Errorf("строка %d: %w", i+1, err)
		}
		keys := splitDotted(k)
		t := cur
		for _, kk := range keys[:len(keys)-1] {
			n, ok := t[kk].(map[string]any)
			if !ok {
				n = map[string]any{}
				t[kk] = n
			}
			t = n
		}
		t[keys[len(keys)-1]] = val
		if curName != "" {
			d.Raw[curName] += text
		}
	}
	return d, nil
}

func (d *tomlDoc) walk(keys []string) (map[string]any, string, error) {
	t := d.Root
	for _, k := range keys[:len(keys)-1] {
		switch n := t[k].(type) {
		case map[string]any:
			t = n
		case []any:
			if len(n) == 0 {
				return nil, "", fmt.Errorf("пустой массив таблиц %s", k)
			}
			t = n[len(n)-1].(map[string]any)
		case nil:
			m := map[string]any{}
			t[k] = m
			t = m
		default:
			return nil, "", fmt.Errorf("%s — не таблица", k)
		}
	}
	return t, keys[len(keys)-1], nil
}

func balanced(v string) bool {
	depth := 0
	var q byte
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[':
			depth++
		case c == ']':
			depth--
		}
	}
	return depth == 0
}

func splitDotted(k string) []string {
	var out []string
	cur := ""
	var q byte
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else {
				cur += string(c)
			}
		case c == '"' || c == '\'':
			q = c
		case c == '.':
			out = append(out, strings.TrimSpace(cur))
			cur = ""
		default:
			cur += string(c)
		}
	}
	return append(out, strings.TrimSpace(cur))
}

func splitTOMLKey(l string) (string, string, bool) {
	var q byte
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '=':
			return strings.TrimSpace(l[:i]), strings.TrimSpace(l[i+1:]), true
		}
	}
	return "", "", false
}

func tomlValue(v string) (any, error) {
	v = strings.TrimSpace(v)
	switch {
	case strings.HasPrefix(v, `"""`) || strings.HasPrefix(v, "'''"):
		return nil, fmt.Errorf("многострочные строки не поддерживаются")
	case strings.HasPrefix(v, `"`):
		return strconv.Unquote(v)
	case strings.HasPrefix(v, "'"):
		if len(v) < 2 || !strings.HasSuffix(v, "'") {
			return nil, fmt.Errorf("незакрытая кавычка")
		}
		return v[1 : len(v)-1], nil
	case strings.HasPrefix(v, "["):
		inner := strings.TrimSpace(v[1 : len(v)-1])
		var out []any
		for _, it := range splitFlow(inner) {
			x, err := tomlValue(it)
			if err != nil {
				return nil, err
			}
			out = append(out, x)
		}
		return out, nil
	case strings.HasPrefix(v, "{"):
		return v, nil
	case v == "true":
		return true, nil
	case v == "false":
		return false, nil
	}
	if n, err := strconv.ParseInt(strings.ReplaceAll(v, "_", ""), 0, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return f, nil
	}
	return v, nil // даты и прочее — строкой
}

func stripTOMLComment(l string) string {
	var q byte
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#':
			return l[:i]
		}
	}
	return l
}
