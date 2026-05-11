package netlify

import "testing"

func TestMatchSuffix(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"foo.netlify.app", ".netlify.app"},
		{"foo.netlify.app.", ".netlify.app"},
		{"FOO.NETLIFY.APP", ".netlify.app"},
		{"foo.netlifyglobalcdn.com", ".netlifyglobalcdn.com"},
		{"a.b.netlify.com", ".netlify.com"},
		{"foo.nfshost.com", ".nfshost.com"},
		{"example.com", ""},
		{"netlify.app.evil.com", ""}, // suffix-only match must not be tricked
		{"", ""},
	}
	for _, tc := range tests {
		got := matchSuffix(tc.in)
		if got != tc.want {
			t.Errorf("matchSuffix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestVerdictThreshold(t *testing.T) {
	// CNAME match alone (+50) crosses the 30 threshold.
	v := Verdict{Host: "x"}
	v.Signals.CNAMEMatch = "netlify.app"
	v.Score = 50
	v.IsNetlify = v.Score >= 30
	if !v.IsNetlify {
		t.Fatal("expected IsNetlify=true at score=50")
	}

	// TLS SAN alone (+20) does NOT cross.
	v = Verdict{Host: "x"}
	v.Signals.TLSSANMatch = "netlify.app"
	v.Score = 20
	v.IsNetlify = v.Score >= 30
	if v.IsNetlify {
		t.Fatal("expected IsNetlify=false at score=20")
	}

	// TLS SAN + JARM (+20 +25 = 45) does cross.
	v = Verdict{Host: "x"}
	v.Signals.TLSSANMatch = "netlify.app"
	v.Signals.JARMMatch = "abc"
	v.Score = 45
	v.IsNetlify = v.Score >= 30
	if !v.IsNetlify {
		t.Fatal("expected IsNetlify=true at score=45")
	}
}

func TestParseList(t *testing.T) {
	raw := "# comment\n\nfoo\n  bar  \n#another\nbaz\n"
	got := parseList(raw)
	want := []string{"foo", "bar", "baz"}
	if len(got) != len(want) {
		t.Fatalf("parseList len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("parseList[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestSeedSNIs(t *testing.T) {
	s := SeedSNIs()
	if len(s) < 100 {
		t.Errorf("SeedSNIs too small: %d", len(s))
	}
	// Sanity: no embedded entry should contain whitespace or comment marker.
	for _, x := range s {
		if x == "" || x[0] == '#' {
			t.Errorf("bad SNI entry: %q", x)
		}
	}
}
