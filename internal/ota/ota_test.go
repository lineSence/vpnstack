package ota

import "testing"

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"v0.2.0", "v0.1.9", true}, {"v0.1.0", "v0.1.0", false}, {"v0.1.0", "v0.1.0-rc.1", true}, {"v0.1.0-rc.2", "v0.1.0-rc.1", true}, {"v1.0.0", "dev", true}, {"v0.1.0", "v0.10.0", false}}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s,%s)=%v", c.a, c.b, got)
		}
	}
}
