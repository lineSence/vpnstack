// Package panel — веб-панель и API. Слушает только loopback (доступ через SSH-туннель).
package panel

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lineSence/vpnstack/internal/core"
	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/ota"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/stats"
	"github.com/lineSence/vpnstack/internal/sys"
	"github.com/lineSence/vpnstack/internal/version"
)

//go:embed web
var webFS embed.FS

type session struct {
	csrf    string
	expires time.Time
}

// Server — панель.
type Server struct {
	E     *core.Engine
	Stats *stats.Store

	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string][]time.Time
	jobs     map[string]*Job
	jobOrder []string
	jobMu    sync.Mutex // одна задача одновременно
	otaInfo  ota.Info
}

// Job — фоновая операция с журналом.
type Job struct {
	ID    string    `json:"id"`
	Title string    `json:"title"`
	Start time.Time `json:"start"`
	End   time.Time `json:"end,omitempty"`
	Done  bool      `json:"done"`
	Error string    `json:"error,omitempty"`
	mu    sync.Mutex
	buf   bytes.Buffer
}

func (j *Job) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.buf.Len() > 4<<20 {
		return len(p), nil
	}
	return j.buf.Write(p)
}

func (j *Job) log() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.String()
}

// New создаёт панель.
func New(e *core.Engine, st *stats.Store) *Server {
	return &Server{E: e, Stats: st, sessions: map[string]*session{}, fails: map[string][]time.Time{}, jobs: map[string]*Job{}}
}

func rnd(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run запускает HTTP-сервер.
func (s *Server) Run(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("панель слушает только loopback (%s) — доступ через SSH-туннель", addr)
	}
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.auth(s.logout))
	mux.HandleFunc("GET /api/overview", s.auth(s.overview))
	mux.HandleFunc("GET /api/services", s.auth(s.services))
	mux.HandleFunc("GET /api/plan", s.auth(s.plan))
	mux.HandleFunc("POST /api/services/{id}/{action}", s.auth(s.serviceAction))
	mux.HandleFunc("GET /api/services/{id}/config", s.auth(s.serviceConfig))
	mux.HandleFunc("GET /api/services/{id}/links", s.auth(s.links))
	mux.HandleFunc("POST /api/services/{id}/users", s.auth(s.addUser))
	mux.HandleFunc("DELETE /api/services/{id}/users/{name}", s.auth(s.delUser))
	mux.HandleFunc("GET /api/services/{id}/users/{name}", s.auth(s.userArtifacts))
	mux.HandleFunc("GET /api/services/{id}/logs", s.auth(s.serviceLogs))
	mux.HandleFunc("GET /api/jobs", s.auth(s.jobList))
	mux.HandleFunc("GET /api/jobs/{id}", s.auth(s.jobGet))
	mux.HandleFunc("GET /api/stats", s.auth(s.stats))
	mux.HandleFunc("POST /api/qr", s.auth(s.qr))
	mux.HandleFunc("POST /api/settings", s.auth(s.settings))
	mux.HandleFunc("POST /api/password", s.auth(s.password))
	mux.HandleFunc("POST /api/ota/{action}", s.auth(s.otaAction))
	mux.HandleFunc("POST /api/stop-unit", s.auth(s.stopUnit))
	mux.HandleFunc("GET /api/adopt", s.auth(s.adoptScan))
	mux.HandleFunc("POST /api/adopt/{action}", s.auth(s.adoptAction))
	srv := &http.Server{Addr: addr, Handler: secHeaders(mux), ReadHeaderTimeout: 10 * time.Second}
	go s.sweep()
	return srv.ListenAndServe()
}

func secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) sweep() {
	for range time.Tick(time.Minute) {
		s.mu.Lock()
		for k, v := range s.sessions {
			if time.Now().After(v.expires) {
				delete(s.sessions, k)
			}
		}
		s.mu.Unlock()
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

// auth — проверка сессии и CSRF (для изменяющих запросов).
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("vs_session")
		s.mu.Lock()
		var sess *session
		if err == nil {
			sess = s.sessions[c.Value]
		}
		if sess != nil && time.Now().After(sess.expires) {
			delete(s.sessions, c.Value)
			sess = nil
		}
		s.mu.Unlock()
		if sess == nil {
			fail(w, 401, fmt.Errorf("нужен вход"))
			return
		}
		if r.Method != "GET" && r.Header.Get("X-CSRF") != sess.csrf {
			fail(w, 403, fmt.Errorf("неверный CSRF-токен"))
			return
		}
		h(w, r)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Login, Password, TOTP string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.mu.Lock()
	var recent []time.Time
	for _, t := range s.fails[ip] {
		if time.Since(t) < 15*time.Minute {
			recent = append(recent, t)
		}
	}
	s.fails[ip] = recent
	s.mu.Unlock()
	if len(recent) >= 10 {
		fail(w, 429, fmt.Errorf("слишком много попыток — подождите 15 минут"))
		return
	}
	p := s.E.PanelAuth() // пароль мог смениться из CLI, пока панель работает
	if p.PassHash == "" {
		fail(w, 403, fmt.Errorf("пароль панели не задан: выполните на сервере `vpnstack panel passwd`"))
		return
	}
	ok := strings.EqualFold(strings.TrimSpace(in.Login), p.Login) && CheckPassword(p.PassHash, in.Password)
	if ok && p.TOTP != "" {
		ok = CheckTOTP(p.TOTP, in.TOTP)
	}
	if !ok {
		s.mu.Lock()
		s.fails[ip] = append(s.fails[ip], time.Now())
		s.mu.Unlock()
		time.Sleep(time.Second)
		fail(w, 401, fmt.Errorf("неверный логин, пароль или код"))
		return
	}
	id, csrf := rnd(32), rnd(16)
	s.mu.Lock()
	s.sessions[id] = &session{csrf: csrf, expires: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "vs_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	writeJSON(w, 200, map[string]any{"csrf": csrf, "totp": p.TOTP != ""})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("vs_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	last, totals := s.Stats.Snapshot()
	st := s.E.St
	hostname, _ := os.Hostname()
	up, _ := os.ReadFile("/proc/uptime")
	writeJSON(w, 200, map[string]any{
		"version": version.Version, "commit": version.Commit, "hostname": hostname,
		"uptime":    strings.Fields(string(up) + " 0")[0],
		"public_ip": st.PublicIP, "email": st.Email, "edge_mode": st.EdgeMode, "channel": st.Channel,
		"ota":  map[string]any{"auto": st.OTA.Auto, "channel": st.OTA.Channel, "info": s.otaInfo},
		"last": last, "totals": totals, "totp": st.Panel.TOTP != "", "login": st.Panel.Login,
	})
}

func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	list := s.E.Services()
	// Секреты не отдаём: только параметры.
	writeJSON(w, 200, list)
}

func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.E.Plan())
}

// startJob запускает операцию в фоне, журнал — в задаче.
func (s *Server) startJob(title string, fn func() error) *Job {
	j := &Job{ID: rnd(6), Title: title, Start: time.Now()}
	s.mu.Lock()
	s.jobs[j.ID] = j
	s.jobOrder = append(s.jobOrder, j.ID)
	if len(s.jobOrder) > 50 {
		delete(s.jobs, s.jobOrder[0])
		s.jobOrder = s.jobOrder[1:]
	}
	s.mu.Unlock()
	go func() {
		s.jobMu.Lock()
		defer s.jobMu.Unlock()
		prev := sys.Log
		sys.Log = io.MultiWriter(j, os.Stderr)
		defer func() {
			if rec := recover(); rec != nil {
				j.Error = fmt.Sprint("сбой: ", rec)
			}
			sys.Log = prev
			j.End, j.Done = time.Now(), true
		}()
		if err := fn(); err != nil {
			j.Error = err.Error()
			fmt.Fprintf(j, "\n[x] %v\n", err)
		} else {
			fmt.Fprintf(j, "\n[✓] готово\n")
		}
	}()
	return j
}

func (s *Server) serviceAction(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	var in struct {
		Params map[string]string `json:"params"`
		Purge  bool              `json:"purge"`
	}
	_ = readJSON(r, &in)
	var fn func() error
	switch action {
	case "install":
		fn = func() error { return s.E.Install(id, in.Params) }
	case "reconfigure":
		fn = func() error { return s.E.Reconfigure(id, in.Params) }
	case "remove":
		fn = func() error { return s.E.Remove(id, in.Purge) }
	case "update":
		fn = func() error { return s.E.Update(id) }
	case "restart":
		fn = func() error { return s.E.Restart(id) }
	case "check":
		// Проверка плана без установки: временно применяем параметры.
		res, err := s.E.Preview(id, in.Params)
		if err != nil {
			fail(w, 400, err)
			return
		}
		writeJSON(w, 200, res)
		return
	default:
		fail(w, 404, fmt.Errorf("неизвестное действие"))
		return
	}
	j := s.startJob(action+" "+id, fn)
	writeJSON(w, 202, map[string]string{"job": j.ID})
}

func (s *Server) serviceConfig(w http.ResponseWriter, r *http.Request) {
	m, ok := module.Get(r.PathValue("id"))
	if !ok {
		fail(w, 404, fmt.Errorf("нет сервиса"))
		return
	}
	out := map[string]string{}
	if c, ok := m.(module.Configurer); ok {
		for _, f := range c.ConfigFiles(s.E.St.Svc(m.ID())) {
			b, err := os.ReadFile(f)
			if err != nil {
				out[f] = "(" + err.Error() + ")"
				continue
			}
			out[f] = string(b)
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) serviceLogs(w http.ResponseWriter, r *http.Request) {
	m, ok := module.Get(r.PathValue("id"))
	if !ok {
		fail(w, 404, fmt.Errorf("нет сервиса"))
		return
	}
	args := []string{"--no-pager", "-n", "200", "-o", "short-iso"}
	for _, u := range m.Units(s.E.St.Svc(m.ID())) {
		args = append(args, "-u", u)
	}
	out, _ := sys.Output("journalctl", args...)
	writeJSON(w, 200, map[string]string{"log": out})
}

func (s *Server) links(w http.ResponseWriter, r *http.Request) {
	a, err := s.E.Artifacts(r.PathValue("id"), "")
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) addUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string            `json:"name"`
		Opts map[string]string `json:"opts"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	id := r.PathValue("id")
	j := s.startJob("add user "+in.Name+" @ "+id, func() error {
		_, err := s.E.AddUser(id, in.Name, in.Opts)
		return err
	})
	writeJSON(w, 202, map[string]string{"job": j.ID})
}

func (s *Server) delUser(w http.ResponseWriter, r *http.Request) {
	id, name := r.PathValue("id"), r.PathValue("name")
	j := s.startJob("del user "+name+" @ "+id, func() error { return s.E.DelUser(id, name) })
	writeJSON(w, 202, map[string]string{"job": j.ID})
}

func (s *Server) userArtifacts(w http.ResponseWriter, r *http.Request) {
	a, err := s.E.Artifacts(r.PathValue("id"), r.PathValue("name"))
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) jobList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	out := []*Job{}
	for i := len(s.jobOrder) - 1; i >= 0; i-- {
		out = append(out, s.jobs[s.jobOrder[i]])
	}
	s.mu.Unlock()
	writeJSON(w, 200, out)
}

func (s *Server) jobGet(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j := s.jobs[r.PathValue("id")]
	s.mu.Unlock()
	if j == nil {
		fail(w, 404, fmt.Errorf("нет задачи"))
		return
	}
	writeJSON(w, 200, map[string]any{"id": j.ID, "title": j.Title, "done": j.Done, "error": j.Error, "log": j.log(), "start": j.Start, "end": j.End})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	out := map[string][]stats.Point{}
	for _, k := range strings.Split(r.URL.Query().Get("keys"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			out[k] = s.Stats.Query(k, rng)
		}
	}
	writeJSON(w, 200, out)
}

// qr — SVG через qrencode (ставится установщиком).
func (s *Server) qr(w http.ResponseWriter, r *http.Request) {
	var in struct{ Text string }
	if err := readJSON(r, &in); err != nil || in.Text == "" {
		fail(w, 400, fmt.Errorf("пустой текст"))
		return
	}
	cmd := exec.Command("qrencode", "-t", "SVG", "-m", "2", "-o", "-")
	cmd.Stdin = strings.NewReader(in.Text)
	out, err := cmd.Output()
	if err != nil {
		fail(w, 501, fmt.Errorf("qrencode недоступен: %v", err))
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write(out)
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email      *string `json:"email"`
		EdgeMode   *string `json:"edge_mode"`
		Channel    *string `json:"channel"`
		OTAAuto    *bool   `json:"ota_auto"`
		OTAChannel *string `json:"ota_channel"`
		PublicIP   *string `json:"public_ip"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	reapply := false
	err := s.E.Mutate(func(st *state.Stack) error {
		if in.Email != nil {
			st.Email = strings.TrimSpace(*in.Email)
			reapply = true
		}
		if in.PublicIP != nil && net.ParseIP(*in.PublicIP) != nil {
			st.PublicIP = *in.PublicIP
			reapply = true
		}
		if in.EdgeMode != nil && (*in.EdgeMode == "sni" || *in.EdgeMode == "ports") && *in.EdgeMode != st.EdgeMode {
			st.EdgeMode = *in.EdgeMode
			reapply = true
		}
		if in.Channel != nil && (*in.Channel == "stable" || *in.Channel == "prerelease") {
			st.Channel = *in.Channel
		}
		if in.OTAAuto != nil {
			st.OTA.Auto = *in.OTAAuto
		}
		if in.OTAChannel != nil && (*in.OTAChannel == "stable" || *in.OTAChannel == "prerelease") {
			st.OTA.Channel = *in.OTAChannel
		}
		return nil
	})
	if err != nil {
		fail(w, 500, err)
		return
	}
	if reapply {
		j := s.startJob("apply settings", s.E.ApplyAll)
		writeJSON(w, 202, map[string]string{"job": j.ID})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) password(w http.ResponseWriter, r *http.Request) {
	var in struct{ Old, New string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if !CheckPassword(s.E.PanelAuth().PassHash, in.Old) {
		fail(w, 403, fmt.Errorf("текущий пароль неверен"))
		return
	}
	if len(in.New) < 10 {
		fail(w, 400, fmt.Errorf("пароль — не короче 10 символов"))
		return
	}
	h, err := HashPassword(in.New)
	if err != nil {
		fail(w, 500, err)
		return
	}
	if err := s.E.Mutate(func(st *state.Stack) error { st.Panel.PassHash = h; return nil }); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) otaAction(w http.ResponseWriter, r *http.Request) {
	ch := s.E.St.OTA.Channel
	switch r.PathValue("action") {
	case "check":
		in, err := ota.Check(ch)
		if err != nil {
			fail(w, 502, err)
			return
		}
		s.otaInfo = in
		s.E.TryRun(func() {
			s.E.St.OTA.Checked, s.E.St.OTA.Latest = time.Now().Format(time.RFC3339), in.Latest
			_ = s.E.St.Save()
		})
		writeJSON(w, 200, in)
	case "apply":
		j := s.startJob("self-update", func() error {
			tag, err := ota.Apply(ch, "")
			if err != nil {
				return err
			}
			sys.Logf("Установлена %s, перезапуск vpnstack…", tag)
			ota.RestartServices()
			return nil
		})
		writeJSON(w, 202, map[string]string{"job": j.ID})
	case "versions":
		j := s.startJob("check service versions", func() error {
			for id, v := range s.E.LatestVersions() {
				sys.Logf("%s: установлено %s, доступно %s", id, s.E.St.Svc(id).Version, v)
			}
			return nil
		})
		writeJSON(w, 202, map[string]string{"job": j.ID})
	default:
		fail(w, 404, fmt.Errorf("неизвестное действие"))
	}
}

// stopUnit — остановить мешающий юнит (из списка конфликтов плана).
func (s *Server) stopUnit(w http.ResponseWriter, r *http.Request) {
	var in struct{ Unit string }
	if err := readJSON(r, &in); err != nil || !strings.HasSuffix(in.Unit, ".service") || strings.HasPrefix(in.Unit, "vpnstack") || in.Unit == "ssh.service" || in.Unit == "sshd.service" {
		fail(w, 400, fmt.Errorf("недопустимый юнит"))
		return
	}
	j := s.startJob("stop "+in.Unit, func() error { return sys.Systemctl("disable", "--now", in.Unit) })
	writeJSON(w, 202, map[string]string{"job": j.ID})
}

// SetOTAInfo — результат фоновой проверки обновлений.
func (s *Server) SetOTAInfo(in ota.Info) { s.otaInfo = in }

var _ = strconv.Itoa

// adoptScan — установки без vpnstack и уже перенятые сервисы.
func (s *Server) adoptScan(w http.ResponseWriter, r *http.Request) {
	s.E.Lock()
	rep := s.E.AdoptScan()
	ad := s.E.Adopted()
	s.E.Unlock()
	writeJSON(w, 200, map[string]any{"report": rep, "adopted": ad})
}

func (s *Server) adoptAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs        []string `json:"ids"`
		Force      bool     `json:"force"`
		NoRollback bool     `json:"no_rollback"`
	}
	_ = readJSON(r, &in)
	action := r.PathValue("action")
	var fn func() error
	switch action {
	case "summary":
		s.E.Lock()
		txt := s.E.MigrateSummary(in.IDs)
		s.E.Unlock()
		writeJSON(w, 200, map[string]string{"summary": txt})
		return
	case "import":
		fn = func() error {
			msgs, err := s.E.AdoptImport(in.IDs, in.Force)
			for _, m := range msgs {
				sys.Logf("%s", m)
			}
			return err
		}
	case "migrate":
		fn = func() error {
			if _, err := s.E.AdoptImport(in.IDs, in.Force); err != nil {
				return err
			}
			return s.E.AdoptMigrate(in.IDs, core.MigrateOpts{Force: in.Force, NoRollback: in.NoRollback})
		}
	case "rollback":
		fn = func() error { return s.E.AdoptRollback(in.IDs) }
	case "cleanup":
		fn = func() error { return s.E.AdoptCleanup(in.IDs) }
	default:
		fail(w, 404, fmt.Errorf("неизвестное действие"))
		return
	}
	j := s.startJob("adopt "+action+" "+strings.Join(in.IDs, ","), fn)
	writeJSON(w, 202, map[string]string{"job": j.ID})
}
