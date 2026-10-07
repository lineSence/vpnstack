package edge

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestReadClientHelloSNI(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: "www.Example.com", InsecureSkipVerify: true})
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_ = c.Handshake()
	}()
	_ = b.SetDeadline(time.Now().Add(2 * time.Second))
	raw, sni, err := readClientHello(b)
	if err != nil {
		t.Fatal(err)
	}
	if sni != "www.example.com" || len(raw) < 100 {
		t.Fatalf("sni=%q len=%d", sni, len(raw))
	}
}

func TestProxyEndToEnd(t *testing.T) {
	back, _ := net.Listen("tcp", "127.0.0.1:0")
	got := make(chan []byte, 1)
	go func() {
		c, _ := back.Accept()
		b := make([]byte, 16)
		io.ReadFull(c, b)
		got <- b
		c.Close()
	}()
	s := &Server{cfg: Config{Routes: []Route{{Name: "x", SNI: []string{"example.com"}, Backend: back.Addr().String(), ProxyProtocol: true}}}}
	a, b := net.Pipe()
	go s.handle(b)
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: "api.example.com", InsecureSkipVerify: true})
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_ = c.Handshake()
	}()
	select {
	case h := <-got:
		if string(h[:12]) != string(sig) {
			t.Fatalf("нет PROXY v2: %x", h)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("бэкенд не получил соединение")
	}
}

func TestMatchSNI(t *testing.T) {
	for _, c := range []struct {
		sni, p string
		ok     bool
	}{{"a.b.com", "b.com", true}, {"b.com", "b.com", true}, {"xb.com", "b.com", false}, {"a.b.com", "*.b.com", true}} {
		if MatchSNI(c.sni, c.p) != c.ok {
			t.Errorf("%s ~ %s", c.sni, c.p)
		}
	}
}
