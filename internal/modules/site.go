package modules

import (
	"fmt"
	"path/filepath"

	"github.com/lineSence/vpnstack/internal/sys"
)

// SiteDir — статический сайт-прикрытие (общий для всех доменов).
var SiteDir = filepath.Join(DataDir, "site")

// CoverBlock — блок Caddyfile, отдающий сайт-прикрытие.
func CoverBlock() string {
	return fmt.Sprintf("encode zstd gzip\nheader -Server\nroot * %s\nfile_server", SiteDir)
}

// ensureSite создаёт простой нейтральный сайт, если его ещё нет.
// Свой сайт можно положить в /var/lib/vpnstack/site — он не перезаписывается.
func ensureSite() {
	idx := filepath.Join(SiteDir, "index.html")
	if sys.Exists(idx) {
		return
	}
	names := []string{"Northwind Studio", "Bluefield Labs", "Atlas Workshop", "Greenline Consulting", "Harbor Design"}
	name := names[randInt(0, len(names)-1)]
	html := fmt.Sprintf(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%[1]s</title>
<style>body{font-family:system-ui,sans-serif;margin:0;color:#222;background:#fafafa}
header{padding:48px 24px;background:#1f3b57;color:#fff}main{max-width:760px;margin:0 auto;padding:24px}
h1{margin:0 0 8px}footer{color:#888;font-size:13px;padding:24px;text-align:center}</style></head>
<body><header><h1>%[1]s</h1><p>Small team. Careful work.</p></header>
<main><h2>About</h2><p>We build and maintain web services for small businesses: hosting, integrations and long-term support.</p>
<h2>Services</h2><ul><li>Web development</li><li>Infrastructure maintenance</li><li>Consulting</li></ul>
<h2>Contact</h2><p>Projects are accepted by referral only.</p></main>
<footer>&copy; %[1]s</footer></body></html>
`, name)
	_ = sys.WriteFileAtomic(idx, []byte(html), 0o644)
	_ = sys.WriteFileAtomic(filepath.Join(SiteDir, "robots.txt"), []byte("User-agent: *\nDisallow:\n"), 0o644)
	_, _ = sys.Run("chmod", "0755", DataDir, SiteDir)
}
