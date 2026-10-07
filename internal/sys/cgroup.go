package sys

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CgroupRoot — корень cgroup v2.
const CgroupRoot = "/sys/fs/cgroup"

// SlicePath возвращает путь cgroup для slice модуля (вложен в vpnstack.slice).
func SlicePath(id string) string {
	if id == "" {
		return filepath.Join(CgroupRoot, "vpnstack.slice")
	}
	return filepath.Join(CgroupRoot, "vpnstack.slice", SliceName(id))
}

// CgroupUsage — потребление ресурсов группой.
type CgroupUsage struct {
	CPUUsec  uint64 `json:"cpu_usec"`  // накопленное процессорное время, мкс
	MemBytes uint64 `json:"mem_bytes"` // текущая память
	Tasks    uint64 `json:"tasks"`
}

// ReadCgroup читает cpu.stat, memory.current и pids.current.
func ReadCgroup(path string) (CgroupUsage, bool) {
	var u CgroupUsage
	b, err := os.ReadFile(filepath.Join(path, "cpu.stat"))
	if err != nil {
		return u, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
			u.CPUUsec, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	if b, err := os.ReadFile(filepath.Join(path, "memory.current")); err == nil {
		u.MemBytes, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	if b, err := os.ReadFile(filepath.Join(path, "pids.current")); err == nil {
		u.Tasks, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	return u, true
}

// HostMem возвращает общую и доступную память (байты).
func HostMem() (total, avail uint64) {
	b, _ := os.ReadFile("/proc/meminfo")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	return
}

// HostCPU возвращает суммарное и простойное время CPU в тиках из /proc/stat.
func HostCPU() (total, idle uint64) {
	b, _ := os.ReadFile("/proc/stat")
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	for i, s := range f[1:] {
		v, _ := strconv.ParseUint(s, 10, 64)
		total += v
		if i == 3 || i == 4 {
			idle += v
		}
	}
	return
}
