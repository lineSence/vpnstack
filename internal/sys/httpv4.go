package sys

import (
	"context"
	"net"
	"net/http"
	"time"
)

// HTTPv4 — HTTP-клиент, принудительно использующий IPv4.
func HTTPv4(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp4", addr)
	}}
	return &http.Client{Timeout: timeout, Transport: tr}
}
