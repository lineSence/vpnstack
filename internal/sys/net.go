package sys

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PublicIPv4 определяет внешний IPv4 сервера.
func PublicIPv4() string {
	c := HTTPv4(8 * time.Second)
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.co/ip", "https://icanhazip.com"} {
		resp, err := c.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		ip := net.ParseIP(strings.TrimSpace(string(b)))
		if ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// ResolveA возвращает IPv4-адреса домена.
func ResolveA(host string) []string {
	ips, _ := net.LookupIP(host)
	var out []string
	for _, ip := range ips {
		if ip.To4() != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

// DNSPointsHere проверяет, что A-запись домена ведёт на ip.
func DNSPointsHere(host, ip string) (bool, []string) {
	got := ResolveA(host)
	for _, g := range got {
		if g == ip {
			return true, got
		}
	}
	return false, got
}

// Listener — слушающий сокет в системе.
type Listener struct {
	Proto   string // tcp | udp
	Addr    string
	Port    int
	Process string
	PID     int
}

var ssUsers = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)

// Listeners возвращает слушающие TCP и UDP сокеты (через ss).
func Listeners() []Listener {
	var out []Listener
	for _, proto := range []string{"tcp", "udp"} {
		flag := "-Hltnp"
		if proto == "udp" {
			flag = "-Hlunp"
		}
		text, err := Output("ss", flag)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(text))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 5 {
				continue
			}
			local := f[3]
			i := strings.LastIndex(local, ":")
			if i < 0 {
				continue
			}
			port, _ := strconv.Atoi(local[i+1:])
			l := Listener{Proto: proto, Addr: local[:i], Port: port}
			if m := ssUsers.FindStringSubmatch(sc.Text()); m != nil {
				l.Process = m[1]
				l.PID, _ = strconv.Atoi(m[2])
			}
			out = append(out, l)
		}
	}
	return out
}

// PortOwner возвращает процесс, слушающий порт (пусто — свободен).
func PortOwner(proto string, port int) (Listener, bool) {
	for _, l := range Listeners() {
		if l.Proto == proto && l.Port == port {
			return l, true
		}
	}
	return Listener{}, false
}

// UnitOfPID определяет systemd-юнит процесса по его cgroup.
func UnitOfPID(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, part := range strings.Split(strings.TrimSpace(string(b)), "/") {
		if strings.HasSuffix(part, ".service") || strings.HasSuffix(part, ".scope") {
			return part
		}
	}
	return ""
}

// DefaultInterface — интерфейс маршрута по умолчанию.
func DefaultInterface() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "eth0"
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return "eth0"
}

// IfaceCounters читает rx/tx байты интерфейса из /proc/net/dev.
func IfaceCounters(iface string) (rx, tx uint64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != iface {
			continue
		}
		f := strings.Fields(rest)
		if len(f) >= 9 {
			rx, _ = strconv.ParseUint(f[0], 10, 64)
			tx, _ = strconv.ParseUint(f[8], 10, 64)
		}
	}
	return
}

// UsedSubnets возвращает IPv4-подсети существующих маршрутов (для выбора непересекающихся).
func UsedSubnets() []*net.IPNet {
	var out []*net.IPNet
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] == "00000000" {
			continue
		}
		dst, _ := strconv.ParseUint(f[1], 16, 32)
		mask, _ := strconv.ParseUint(f[7], 16, 32)
		ip := net.IPv4(byte(dst), byte(dst>>8), byte(dst>>16), byte(dst>>24))
		m := net.IPv4Mask(byte(mask), byte(mask>>8), byte(mask>>16), byte(mask>>24))
		out = append(out, &net.IPNet{IP: ip.Mask(m), Mask: m})
	}
	return out
}

// SubnetFree проверяет, что подсеть не пересекается с маршрутами.
func SubnetFree(cidr string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, u := range UsedSubnets() {
		if u.Contains(n.IP) || n.Contains(u.IP) {
			return false
		}
	}
	return true
}
