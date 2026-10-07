package adopt

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/lineSence/vpnstack/internal/state"
)

func scanTGWP() []*Found {
	b, err := readHost("/etc/tproxy-server/config.json")
	if err != nil {
		return nil
	}
	if u, _ := run("systemctl", "show", "-p", "Description", "--value", "tproxy-server.service"); strings.Contains(u, "vpnstack") {
		return nil
	}
	o := state.Origin{Kind: "inplace", InPlace: true, Source: "TG WEB proxy (tproxy-server, штатный установщик)", State: state.OriginImported,
		ImportedAt: time.Now(), Files: map[string]string{}, Configs: []string{hostPath("/etc/tproxy-server/config.json"), hostPath("/etc/tproxy-server/profiles.json"), hostPath("/etc/caddy/Caddyfile")}}
	f := newFound("tgwp", "TG WEB proxy", o)
	prof, _ := readHost("/etc/tproxy-server/profiles.json")
	caddyfile, _ := readHost("/etc/caddy/Caddyfile")
	caddyEnv, _ := run("systemctl", "show", "-p", "Environment", "--value", "caddy.service")
	caddyActive, _ := run("systemctl", "is-active", "caddy.service")
	importTGWP(f, b, prof, string(caddyfile), caddyEnv, strings.TrimSpace(caddyActive) == "active")
	return []*Found{f}
}

// importTGWP: tproxy-server остаётся на месте (те же секрет, путь, ключ токенов);
// меняется только Caddy — его заменяет Caddy стека с перенесёнными сертификатами.
func importTGWP(f *Found, cfg, profiles []byte, caddyfile, caddyEnv string, caddyActive bool) {
	var c struct {
		Host     string `json:"public_hostname"`
		BasePath string `json:"base_path"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil || c.Host == "" {
		f.Blocking = append(f.Blocking, "в /etc/tproxy-server/config.json нет public_hostname")
		return
	}
	var p struct {
		Profiles []struct {
			Secret string `json:"secret"`
		} `json:"profiles"`
	}
	if json.Unmarshal(profiles, &p) != nil || len(p.Profiles) == 0 || p.Profiles[0].Secret == "" {
		f.Blocking = append(f.Blocking, "не прочитан секрет из /etc/tproxy-server/profiles.json")
		return
	}
	f.Params["domain"] = c.Host
	f.Params["base_path"] = firstNonEmpty(c.BasePath, "none")
	f.Params["active_base_path"] = c.BasePath
	f.Params["adopted_inplace"] = "true"
	f.Secrets["secret"] = p.Profiles[0].Secret
	if caddyActive {
		f.Origin.Units = []string{"caddy.service"}
		f.port("tcp", 80)
		f.port("tcp", 443)
	}
	// Хранилище сертификатов старого Caddy: XDG_DATA_HOME/caddy, иначе HOME/.local/share/caddy.
	store := ""
	for _, kv := range strings.Fields(caddyEnv) {
		if v, ok := strings.CutPrefix(kv, "XDG_DATA_HOME="); ok {
			store = v + "/caddy"
		}
	}
	if store == "" {
		store = firstExistingDir(hostPath("/var/lib/caddy/caddy"), hostPath("/var/lib/caddy/.local/share/caddy"))
	} else {
		store = hostPath(store)
	}
	if store != "" {
		f.Origin.Files["caddy_storage"] = store
	}
	if hosts := caddyHosts(caddyfile); len(hosts) > 0 {
		var other []string
		for _, h := range hosts {
			if h != c.Host && h != "{$TPROXY_HOSTNAME}" && !strings.HasPrefix(h, "http://") {
				other = append(other, h)
			}
		}
		if len(other) > 0 {
			f.Risky = append(f.Risky, "в /etc/caddy/Caddyfile есть другие сайты ("+strings.Join(other, ", ")+") — после остановки старого Caddy они перестанут открываться; "+
				"перенесите их вручную (vpnstack route add …) или в /var/lib/vpnstack/site")
		}
	}
}

// Ignore inline placeholders and quoted strings when counting block braces.
var caddyInlineRe = regexp.MustCompile("\"(?:\\\\.|[^\"\\\\])*\"|`[^`]*`|\\{[^{}\\s]+\\}")

// caddyHosts reads only top-level site headers. A regexp over the full file
// could consume closing braces/comments across newlines as a bogus hostname.
func caddyHosts(src string) []string {
	var out []string
	depth := 0
	var header []string
	for _, raw := range strings.Split(src, "\n") {
		structural := caddyInlineRe.ReplaceAllString(raw, "")
		if i := strings.IndexByte(structural, '#'); i >= 0 {
			structural = structural[:i]
		}
		structural = strings.TrimSpace(structural)
		if depth == 0 && structural != "" {
			if i := strings.IndexByte(structural, '{'); i >= 0 {
				// Use the original line to retain {$TPROXY_HOSTNAME}.
				line := raw
				if j := strings.IndexByte(line, '#'); j >= 0 {
					line = line[:j]
				}
				j := strings.LastIndexByte(line, '{')
				header = append(header, strings.TrimSpace(line[:j]))
				for _, h := range strings.Fields(strings.Join(header, " ")) {
					for _, host := range strings.Split(h, ",") {
						if host != "" && !strings.HasPrefix(host, "(") {
							out = append(out, host)
						}
					}
				}
				header = nil
			} else if !strings.Contains(structural, "}") {
				header = append(header, strings.TrimSpace(raw))
			}
		}
		depth += strings.Count(structural, "{") - strings.Count(structural, "}")
		if depth < 0 {
			depth = 0
		}
	}
	return out
}

func firstExistingDir(paths ...string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return ""
}
