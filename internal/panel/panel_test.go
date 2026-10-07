package panel

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lineSence/vpnstack/internal/core"
	_ "github.com/lineSence/vpnstack/internal/modules"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/stats"
)

func TestPanelSmoke(t *testing.T) {
	state.Path = filepath.Join(t.TempDir(), "stack.json")
	e, err := core.Open()
	if err != nil {
		t.Fatal(err)
	}
	e.St.PublicIP = "203.0.113.1"
	h, _ := HashPassword("secret-password")
	e.St.Panel.PassHash = h
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	s := New(e, stats.New())
	go s.Run(addr)
	time.Sleep(200 * time.Millisecond)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	base := "http://" + addr
	if r, _ := c.Get(base + "/api/services"); r.StatusCode != 401 {
		t.Fatalf("без входа: %d", r.StatusCode)
	}
	r, err := c.Post(base+"/api/login", "application/json", strings.NewReader(`{"login":"admin","password":"secret-password"}`))
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("вход: %v %v", err, r.StatusCode)
	}
	var lr struct{ CSRF string }
	json.NewDecoder(r.Body).Decode(&lr)
	r, _ = c.Get(base + "/api/services")
	var svcs []core.SvcInfo
	json.NewDecoder(r.Body).Decode(&svcs)
	if len(svcs) < 6 {
		t.Fatalf("сервисов: %d", len(svcs))
	}
	// Изменяющий запрос без CSRF отклоняется.
	r, _ = c.Post(base+"/api/settings", "application/json", strings.NewReader(`{"channel":"stable"}`))
	if r.StatusCode != 403 {
		t.Fatalf("CSRF: %d", r.StatusCode)
	}
	req, _ := http.NewRequest("POST", base+"/api/services/xray/check", strings.NewReader(`{"params":{}}`))
	req.Header.Set("X-CSRF", lr.CSRF)
	r, _ = c.Do(req)
	if r.StatusCode != 200 {
		t.Fatalf("check: %d", r.StatusCode)
	}
	if e.St.Svc("xray").Enabled {
		t.Fatal("проверка не должна включать сервис")
	}
	r, _ = c.Get(base + "/")
	if r.StatusCode != 200 {
		t.Fatalf("index: %d", r.StatusCode)
	}
}
