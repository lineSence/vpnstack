package module

import (
	"sort"
	"sync"
)

var (
	mu  sync.RWMutex
	reg = map[string]Module{}
)

// Register добавляет модуль в реестр (встроенные — из init, внешние — при загрузке манифестов).
func Register(m Module) {
	mu.Lock()
	defer mu.Unlock()
	reg[m.ID()] = m
}

// Get возвращает модуль по идентификатору.
func Get(id string) (Module, bool) {
	mu.RLock()
	defer mu.RUnlock()
	m, ok := reg[id]
	return m, ok
}

// All — все модули: сначала служебные, затем по порядку Order (если задан) и имени.
func All() []Module {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Module, 0, len(reg))
	for _, m := range reg {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Core() != out[j].Core() {
			return out[i].Core()
		}
		return order(out[i]) < order(out[j])
	})
	return out
}

// Ordered — модуль может задать порядок установки.
type Ordered interface{ Order() int }

func order(m Module) int {
	if o, ok := m.(Ordered); ok {
		return o.Order()
	}
	return 500
}
