package edge

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ConfigPath — файл маршрутов, который пишет оркестратор.
var ConfigPath = "/etc/vpnstack/edge.json"

// Route — маршрут по SNI.
type Route struct {
	Name          string   `json:"name"`
	SNI           []string `json:"sni"`
	Backend       string   `json:"backend"`
	ProxyProtocol bool     `json:"proxy_protocol"`
	Default       bool     `json:"default"`
	Priority      int      `json:"priority"`
}

// Config — конфигурация общего входа.
type Config struct {
	Listen      string  `json:"listen"`       // ":443"
	StatsListen string  `json:"stats_listen"` // "127.0.0.1:8898"
	MaxConns    int     `json:"max_conns"`
	Routes      []Route `json:"routes"`
}

type counters struct{ Rx, Tx, Conns, Active atomic.Uint64 }

// Server — работающий общий вход.
type Server struct {
	mu    sync.RWMutex
	cfg   Config
	stats sync.Map // имя маршрута -> *counters
	sem   chan struct{}
}

// LoadConfig читает конфигурацию маршрутов.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Listen == "" {
		c.Listen = ":443"
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 20000
	}
	sort.SliceStable(c.Routes, func(i, j int) bool { return c.Routes[i].Priority > c.Routes[j].Priority })
	return c, nil
}

func (s *Server) route(sni string) (Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var def *Route
	for i := range s.cfg.Routes {
		r := &s.cfg.Routes[i]
		if sni != "" {
			for _, p := range r.SNI {
				if MatchSNI(sni, p) {
					return *r, true
				}
			}
		}
		if r.Default && def == nil {
			def = r
		}
	}
	if def != nil {
		return *def, true
	}
	return Route{}, false
}

func (s *Server) ctr(name string) *counters {
	v, _ := s.stats.LoadOrStore(name, &counters{})
	return v.(*counters)
}

// Run запускает общий вход и блокируется. SIGHUP перечитывает маршруты.
func Run() error {
	if p := os.Getenv("VPNSTACK_EDGE_CONFIG"); p != "" {
		ConfigPath = p
	}
	cfg, err := LoadConfig(ConfigPath)
	if err != nil {
		return err
	}
	s := &Server{cfg: cfg, sem: make(chan struct{}, cfg.MaxConns)}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			c, err := LoadConfig(ConfigPath)
			if err != nil {
				log.Printf("ошибка перечитывания маршрутов: %v", err)
				continue
			}
			s.mu.Lock()
			s.cfg.Routes = c.Routes
			s.mu.Unlock()
			log.Printf("маршруты перечитаны: %d", len(c.Routes))
		}
	}()
	if cfg.StatsListen != "" {
		go s.serveStats(cfg.StatsListen)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("общий вход слушает %s, маршрутов: %d", cfg.Listen, len(cfg.Routes))
	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case s.sem <- struct{}{}:
			go func() { defer func() { <-s.sem }(); s.handle(c) }()
		default:
			c.Close()
		}
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	raw, sni, err := readClientHello(c)
	if err != nil && err != errNotTLS {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	r, ok := s.route(sni)
	if !ok {
		return
	}
	up, err := net.DialTimeout("tcp", r.Backend, 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	ct := s.ctr(r.Name)
	ct.Conns.Add(1)
	ct.Active.Add(1)
	defer ct.Active.Add(^uint64(0))
	if r.ProxyProtocol {
		if _, err := up.Write(proxyV2(c.RemoteAddr(), c.LocalAddr())); err != nil {
			return
		}
	}
	if _, err := up.Write(raw); err != nil {
		return
	}
	ct.Rx.Add(uint64(len(raw)))
	done := make(chan struct{}, 2)
	go func() { n, _ := io.Copy(up, c); ct.Rx.Add(uint64(n)); closeWrite(up); done <- struct{}{} }()
	go func() { n, _ := io.Copy(c, up); ct.Tx.Add(uint64(n)); closeWrite(c); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

var sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// proxyV2 строит заголовок PROXY protocol v2 (TCP over IPv4/IPv6).
func proxyV2(src, dst net.Addr) []byte {
	sa, _ := src.(*net.TCPAddr)
	da, _ := dst.(*net.TCPAddr)
	var b bytes.Buffer
	b.Write(sig)
	b.WriteByte(0x21) // v2, PROXY
	if sa == nil || da == nil {
		b.Write([]byte{0x00, 0, 0})
		return b.Bytes()
	}
	if s4, d4 := sa.IP.To4(), da.IP.To4(); s4 != nil && d4 != nil {
		b.WriteByte(0x11)
		_ = binary.Write(&b, binary.BigEndian, uint16(12))
		b.Write(s4)
		b.Write(d4)
	} else {
		b.WriteByte(0x21)
		_ = binary.Write(&b, binary.BigEndian, uint16(36))
		b.Write(sa.IP.To16())
		b.Write(da.IP.To16())
	}
	_ = binary.Write(&b, binary.BigEndian, uint16(sa.Port))
	_ = binary.Write(&b, binary.BigEndian, uint16(da.Port))
	return b.Bytes()
}

// RouteStats — счётчики маршрута для оркестратора.
type RouteStats struct {
	Rx     uint64 `json:"rx"`
	Tx     uint64 `json:"tx"`
	Conns  uint64 `json:"conns"`
	Active uint64 `json:"active"`
}

func (s *Server) serveStats(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		out := map[string]RouteStats{}
		s.stats.Range(func(k, v any) bool {
			c := v.(*counters)
			out[k.(string)] = RouteStats{c.Rx.Load(), c.Tx.Load(), c.Conns.Load(), c.Active.Load()}
			return true
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	_ = srv.ListenAndServe()
}

// FetchStats читает счётчики работающего общего входа.
func FetchStats(addr string) (map[string]RouteStats, error) {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/stats")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := map[string]RouteStats{}
	return out, json.NewDecoder(resp.Body).Decode(&out)
}
