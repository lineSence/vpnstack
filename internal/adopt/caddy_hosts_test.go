package adopt

import (
	"reflect"
	"testing"
)

func TestCaddyHostsNestedAndACME(t *testing.T) {
	src := `{
email {$ACME_EMAIL}
servers {
protocols h1 h2
timeouts {
read_header 10s
}
}
}

{$TPROXY_HOSTNAME} {
header {
-Via
}
reverse_proxy 127.0.0.1:8080 {
transport http {
response_header_timeout 40s
}
}
handle_errors {
respond "{http.error.status_code} {http.error.status_text}" {http.error.status_code}
}
}

# ACME HTTP-01 for Hysteria
http://uwu.example.com {
handle /.well-known/acme-challenge/* {
reverse_proxy 127.0.0.1:8880
}
handle {
respond 404
}
}
`
	want := []string{"{$TPROXY_HOSTNAME}", "http://uwu.example.com"}
	if got := caddyHosts(src); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	f := nf("tgwp")
	importTGWP(f, []byte(`{"public_hostname":"tg.example.com"}`), []byte(`{"profiles":[{"secret":"S"}]}`), src, "", true)
	if len(f.Risky) != 0 {
		t.Fatalf("false warning: %v", f.Risky)
	}
}

func TestCaddyHostsRealForeignSites(t *testing.T) {
	src := `{
admin off
}
tg.example.com {
 respond "brace { and # inside string"
}
# A real unrelated HTTPS site must still require confirmation.
other.example.com, www.other.example.com {
 reverse_proxy localhost:9000
}
`
	want := []string{"tg.example.com", "other.example.com", "www.other.example.com"}
	if got := caddyHosts(src); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	f := nf("tgwp")
	importTGWP(f, []byte(`{"public_hostname":"tg.example.com"}`), []byte(`{"profiles":[{"secret":"S"}]}`), src, "", true)
	if len(f.Risky) != 1 {
		t.Fatalf("missing foreign site warning: %v", f.Risky)
	}
}
