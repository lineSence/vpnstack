package adopt

import "testing"

func TestScanSmoke(t *testing.T) {
	r := Scan()
	if r == nil {
		t.Fatal("nil report")
	}
	t.Logf("found %d, foreign %d", len(r.Found), len(r.Foreign))
}
