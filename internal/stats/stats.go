// Package stats собирает статистику: CPU/RAM хоста и сервисов (cgroup slice),
// трафик сервисов (счётчики общего входа и nftables) и пользователей (API сервисов).
// Хранение — кольцевые буферы в памяти с сохранением в JSON.
package stats

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/lineSence/vpnstack/internal/edge"
	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/netfilter"
	"github.com/lineSence/vpnstack/internal/plan"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Path — файл сохранённой статистики.
var Path = "/var/lib/vpnstack/stats.json"

const (
	minuteCap = 24 * 60     // сутки поминутно
	hourCap   = 30 * 24     // 30 дней почасово
	interval  = time.Minute // период опроса
)

// Point — точка ряда.
type Point struct {
	T int64   `json:"t"` // unix-время
	V float64 `json:"v"`
}

// Series — ряд с двумя разрешениями.
type Series struct {
	Minute []Point `json:"m"`
	Hour   []Point `json:"h"`
	Sum    bool    `json:"sum"` // для часовых точек суммировать (трафик), иначе усреднять
	acc    float64
	accN   int
	accH   int64
}

func (s *Series) add(t time.Time, v float64) {
	s.Minute = append(s.Minute, Point{t.Unix(), v})
	if len(s.Minute) > minuteCap {
		s.Minute = s.Minute[len(s.Minute)-minuteCap:]
	}
	h := t.Truncate(time.Hour).Unix()
	if s.accH != 0 && h != s.accH {
		v := s.acc
		if !s.Sum && s.accN > 0 {
			v = s.acc / float64(s.accN)
		}
		s.Hour = append(s.Hour, Point{s.accH, v})
		if len(s.Hour) > hourCap {
			s.Hour = s.Hour[len(s.Hour)-hourCap:]
		}
		s.acc, s.accN = 0, 0
	}
	s.accH = h
	s.acc += v
	s.accN++
}

// Totals — накопленный трафик за всё время.
type Totals struct {
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

// Store — вся статистика.
type Store struct {
	mu     sync.RWMutex
	Series map[string]*Series `json:"series"`
	Totals map[string]*Totals `json:"totals"` // svc.<id> | user.<id>.<name>
	prev   map[string]uint64
	Last   map[string]float64 `json:"last"` // последние значения для обзора
}

// New — пустое хранилище.
func New() *Store {
	return &Store{Series: map[string]*Series{}, Totals: map[string]*Totals{}, prev: map[string]uint64{}, Last: map[string]float64{}}
}

// Load читает сохранённую статистику.
func Load() *Store {
	s := New()
	if b, err := os.ReadFile(Path); err == nil {
		_ = json.Unmarshal(b, s)
	}
	if s.Series == nil {
		s.Series = map[string]*Series{}
	}
	if s.Totals == nil {
		s.Totals = map[string]*Totals{}
	}
	if s.Last == nil {
		s.Last = map[string]float64{}
	}
	s.prev = map[string]uint64{}
	return s
}

// Save сохраняет статистику.
func (s *Store) Save() error {
	s.mu.RLock()
	b, err := json.Marshal(s)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	return sys.WriteFileAtomic(Path, b, 0o600)
}

func (s *Store) put(t time.Time, key string, v float64, sum bool) {
	se := s.Series[key]
	if se == nil {
		se = &Series{Sum: sum}
		s.Series[key] = se
	}
	se.add(t, v)
	s.Last[key] = v
}

// delta — прирост накопительного счётчика (сброс счётчика — значение с нуля).
func (s *Store) delta(key string, cur uint64) uint64 {
	p, ok := s.prev[key]
	s.prev[key] = cur
	if !ok {
		return 0
	}
	if cur >= p {
		return cur - p
	}
	return cur
}

func (s *Store) traffic(t time.Time, key string, rx, tx uint64) {
	drx, dtx := s.delta(key+".rx", rx), s.delta(key+".tx", tx)
	s.put(t, key+".rx", float64(drx), true)
	s.put(t, key+".tx", float64(dtx), true)
	tot := s.Totals[key]
	if tot == nil {
		tot = &Totals{}
		s.Totals[key] = tot
	}
	tot.Rx += drx
	tot.Tx += dtx
}

// Collector периодически собирает данные.
type Collector struct {
	Store   *Store
	Env     *module.Env
	St      *state.Stack
	prevCPU [2]uint64
	prevSvc map[string]uint64
	prevT   time.Time
	// Guard — обёртка для синхронизации с движком (сбор пропускается, если он занят).
	Guard func(fn func())
}

// Collect — один проход сбора.
func (c *Collector) Collect() {
	now := time.Now()
	s := c.Store
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.prevSvc == nil {
		c.prevSvc = map[string]uint64{}
	}
	elapsed := now.Sub(c.prevT).Seconds()
	first := c.prevT.IsZero()
	c.prevT = now

	// Хост: CPU, память, сеть.
	total, idle := sys.HostCPU()
	if !first && total > c.prevCPU[0] {
		s.put(now, "host.cpu", 100*(1-float64(idle-c.prevCPU[1])/float64(total-c.prevCPU[0])), false)
	}
	c.prevCPU = [2]uint64{total, idle}
	mt, ma := sys.HostMem()
	s.put(now, "host.mem", float64(mt-ma), false)
	s.Last["host.mem_total"] = float64(mt)
	if ifc := sys.DefaultInterface(); ifc != "" {
		rx, tx := sys.IfaceCounters(ifc)
		s.traffic(now, "host", rx, tx)
	}

	// Сервисы: cgroup slice.
	ids := plan.Active(c.St)
	for _, core := range []string{"caddy", "edge"} {
		if c.St.Svc(core).Installed {
			ids = append(ids, core)
		}
	}
	for _, id := range ids {
		if u, ok := sys.ReadCgroup(sys.SlicePath(id)); ok {
			if p, ok := c.prevSvc[id]; ok && elapsed > 0 && u.CPUUsec >= p {
				s.put(now, "svc."+id+".cpu", float64(u.CPUUsec-p)/(elapsed*1e6)*100, false)
			}
			c.prevSvc[id] = u.CPUUsec
			s.put(now, "svc."+id+".mem", float64(u.MemBytes), false)
		}
	}
	// Трафик сервисов: общий вход (TCP 443) + nftables (UDP).
	if es, err := edge.FetchStats("127.0.0.1:8898"); err == nil {
		for name, r := range es {
			s.traffic(now, "svc."+name, r.Rx, r.Tx)
			s.Last["svc."+name+".conns"] = float64(r.Active)
		}
	}
	for id, v := range netfilter.Counters() {
		s.traffic(now, "svc."+id, v[0], v[1])
	}
	// Пользователи.
	for _, id := range plan.Active(c.St) {
		m, _ := module.Get(id)
		tr, ok := m.(module.TrafficReporter)
		svc := c.St.Svc(id)
		if !ok || !svc.Installed {
			continue
		}
		users, err := tr.UserTraffic(c.Env, svc)
		if err != nil {
			continue
		}
		for name, t := range users {
			s.traffic(now, "user."+id+"."+name, t.Rx, t.Tx)
		}
	}
}

// Query — точки ряда за период ("24h" — поминутно, иначе почасово).
func (s *Store) Query(key, rng string) []Point {
	s.mu.RLock()
	defer s.mu.RUnlock()
	se := s.Series[key]
	if se == nil {
		return []Point{}
	}
	src := se.Hour
	if rng == "24h" || rng == "" {
		src = se.Minute
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	switch rng {
	case "7d":
		cutoff = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		cutoff = time.Now().Add(-30 * 24 * time.Hour)
	}
	out := []Point{}
	for _, p := range src {
		if p.T >= cutoff.Unix() {
			out = append(out, p)
		}
	}
	return out
}

// Snapshot — последние значения и итоги.
func (s *Store) Snapshot() (map[string]float64, map[string]Totals) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l := make(map[string]float64, len(s.Last))
	for k, v := range s.Last {
		l[k] = v
	}
	t := make(map[string]Totals, len(s.Totals))
	for k, v := range s.Totals {
		t[k] = *v
	}
	return l, t
}

// Run — цикл сбора до остановки.
func (c *Collector) Run(stop <-chan struct{}) {
	tk := time.NewTicker(interval)
	defer tk.Stop()
	saveTk := time.NewTicker(5 * time.Minute)
	defer saveTk.Stop()
	run := func() {
		if c.Guard != nil {
			c.Guard(c.Collect)
		} else {
			c.Collect()
		}
	}
	run()
	for {
		select {
		case <-stop:
			_ = c.Store.Save()
			return
		case <-tk.C:
			run()
		case <-saveTk.C:
			_ = c.Store.Save()
		}
	}
}
