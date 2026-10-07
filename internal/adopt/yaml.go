package adopt

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Минимальный разбор YAML — ровно столько, сколько нужно для конфигов Hysteria:
// блочные словари и списки, скаляры (обычные, '…', "…"), простые [a, b] и {a: b},
// комментарии и блочные строки | и >. Якоря, теги и многодокументность не поддерживаются.

type yline struct {
	indent int
	text   string
	num    int
}

// parseYAML разбирает документ в map[string]any / []any / string.
func parseYAML(src string) (any, error) {
	var lines []yline
	for i, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		t := strings.TrimRight(stripYAMLComment(raw), " \t")
		if strings.TrimSpace(t) == "" || strings.TrimSpace(t) == "---" {
			continue
		}
		if strings.Contains(t[:len(t)-len(strings.TrimLeft(t, " \t"))], "\t") {
			return nil, fmt.Errorf("строка %d: табуляция в отступе", i+1)
		}
		ind := len(t) - len(strings.TrimLeft(t, " "))
		lines = append(lines, yline{ind, strings.TrimSpace(t), i + 1})
	}
	if len(lines) == 0 {
		return map[string]any{}, nil
	}
	p := &yparser{lines: lines, src: strings.Split(src, "\n")}
	v, err := p.block(lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.i < len(p.lines) {
		return nil, fmt.Errorf("строка %d: неожиданный отступ", p.lines[p.i].num)
	}
	return v, nil
}

type yparser struct {
	lines []yline
	i     int
	src   []string
}

func isSeqItem(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func (p *yparser) block(indent int) (any, error) {
	if p.i >= len(p.lines) {
		return nil, nil
	}
	if isSeqItem(p.lines[p.i].text) {
		return p.seq(indent)
	}
	return p.mapping(indent)
}

func (p *yparser) seq(indent int) (any, error) {
	var out []any
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent != indent || !isSeqItem(l.text) {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		if rest == "" {
			p.i++
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				v, err := p.block(p.lines[p.i].indent)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
			continue
		}
		if _, _, ok := splitKey(rest); ok && !strings.HasPrefix(rest, "{") && !strings.HasPrefix(rest, "[") && !isQuoted(rest) {
			// «- key: value» — словарь, первая строка которого сдвинута за «- ».
			off := indent + (len(l.text) - len(rest))
			p.lines[p.i] = yline{off, rest, l.num}
			v, err := p.mapping(off)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		v, err := scalar(rest)
		if err != nil {
			return nil, fmt.Errorf("строка %d: %w", l.num, err)
		}
		out = append(out, v)
		p.i++
	}
	return out, nil
}

func (p *yparser) mapping(indent int) (any, error) {
	out := map[string]any{}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, fmt.Errorf("строка %d: неожиданный отступ", l.num)
		}
		if isSeqItem(l.text) {
			break
		}
		k, v, ok := splitKey(l.text)
		if !ok {
			return nil, fmt.Errorf("строка %d: ожидалось «ключ: значение»", l.num)
		}
		p.i++
		switch {
		case v == "|" || v == ">" || strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">"):
			out[k] = p.blockScalar(indent, strings.HasPrefix(v, ">"))
		case v != "":
			sv, err := scalar(v)
			if err != nil {
				return nil, fmt.Errorf("строка %d: %w", l.num, err)
			}
			out[k] = sv
		case p.i < len(p.lines) && p.lines[p.i].indent > indent:
			cv, err := p.block(p.lines[p.i].indent)
			if err != nil {
				return nil, err
			}
			out[k] = cv
		case p.i < len(p.lines) && p.lines[p.i].indent == indent && isSeqItem(p.lines[p.i].text):
			cv, err := p.seq(indent)
			if err != nil {
				return nil, err
			}
			out[k] = cv
		default:
			out[k] = nil
		}
	}
	return out, nil
}

// blockScalar собирает строки блочного скаляра (берутся из исходного текста как есть).
func (p *yparser) blockScalar(parent int, folded bool) string {
	var parts []string
	for p.i < len(p.lines) && p.lines[p.i].indent > parent {
		parts = append(parts, p.lines[p.i].text)
		p.i++
	}
	if folded {
		return strings.Join(parts, " ")
	}
	return strings.Join(parts, "\n")
}

func isQuoted(s string) bool { return strings.HasPrefix(s, `"`) || strings.HasPrefix(s, "'") }

// splitKey делит «ключ: значение» (ключ может быть в кавычках).
func splitKey(t string) (string, string, bool) {
	if isQuoted(t) {
		q := t[0]
		end := -1
		for i := 1; i < len(t); i++ {
			if t[i] == '\\' && q == '"' {
				i++
				continue
			}
			if t[i] == q {
				end = i
				break
			}
		}
		if end < 0 || end+1 >= len(t) || t[end+1] != ':' {
			return "", "", false
		}
		k, err := scalar(t[:end+1])
		if err != nil {
			return "", "", false
		}
		return fmt.Sprint(k), strings.TrimSpace(t[end+2:]), true
	}
	for i := 0; i < len(t); i++ {
		if t[i] == ':' && (i+1 == len(t) || t[i+1] == ' ') {
			return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:]), true
		}
	}
	return "", "", false
}

// scalar разбирает значение: строки в кавычках, [..], {..}; остальное — строка как есть.
func scalar(v string) (any, error) {
	v = strings.TrimSpace(v)
	switch {
	case strings.HasPrefix(v, `"`):
		var s string
		if err := json.Unmarshal([]byte(v), &s); err != nil {
			// YAML допускает \x.. и т. п.; strconv.Unquote понимает больше.
			u, err2 := strconv.Unquote(v)
			if err2 != nil {
				return nil, fmt.Errorf("строка в кавычках: %v", err)
			}
			return u, nil
		}
		return s, nil
	case strings.HasPrefix(v, "'"):
		if len(v) < 2 || !strings.HasSuffix(v, "'") {
			return nil, fmt.Errorf("незакрытая кавычка")
		}
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'"), nil
	case strings.HasPrefix(v, "["):
		if !strings.HasSuffix(v, "]") {
			return nil, fmt.Errorf("незакрытый список")
		}
		var out []any
		for _, it := range splitFlow(v[1 : len(v)-1]) {
			x, err := scalar(it)
			if err != nil {
				return nil, err
			}
			out = append(out, x)
		}
		return out, nil
	case strings.HasPrefix(v, "{"):
		if !strings.HasSuffix(v, "}") {
			return nil, fmt.Errorf("незакрытый словарь")
		}
		out := map[string]any{}
		for _, it := range splitFlow(v[1 : len(v)-1]) {
			k, val, ok := splitKey(it)
			if !ok {
				k, val = strings.TrimSuffix(it, ":"), ""
			}
			x, err := scalar(val)
			if err != nil {
				return nil, err
			}
			out[k] = x
		}
		return out, nil
	case v == "~" || v == "null":
		return nil, nil
	}
	return v, nil
}

// splitFlow делит содержимое [..]/{..} по запятым верхнего уровня.
func splitFlow(s string) []string {
	var out []string
	depth, start := 0, 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			if t := strings.TrimSpace(s[start:i]); t != "" {
				out = append(out, t)
			}
			start = i + 1
		}
	}
	if t := strings.TrimSpace(s[start:]); t != "" {
		out = append(out, t)
	}
	return out
}

// stripYAMLComment убирает комментарий « #…» вне кавычек.
func stripYAMLComment(l string) string {
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
			// кавычка открывает строку только в начале значения
			if i == 0 || l[i-1] == ' ' || l[i-1] == '[' || l[i-1] == ',' || l[i-1] == '{' || l[i-1] == '-' || l[i-1] == ':' {
				q = c
			}
		case c == '#' && (i == 0 || l[i-1] == ' ' || l[i-1] == '\t'):
			return l[:i]
		}
	}
	return l
}

// --- доступ к разобранному дереву ---

func getPath(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		// Hysteria (viper) не различает регистр ключей.
		found := false
		for mk, mv := range m {
			if strings.EqualFold(mk, k) {
				v, found = mv, true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return v
}

func getStr(v any, path ...string) string {
	switch x := getPath(v, path...).(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func getMap(v any, path ...string) map[string]any {
	m, _ := getPath(v, path...).(map[string]any)
	return m
}

func getList(v any, path ...string) []string {
	var out []string
	switch x := getPath(v, path...).(type) {
	case []any:
		for _, it := range x {
			if it != nil {
				out = append(out, fmt.Sprint(it))
			}
		}
	case string:
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}
