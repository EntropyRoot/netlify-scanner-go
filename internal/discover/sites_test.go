package discover

import (
	"strings"
	"testing"
)

func TestExtractSiteSlugs(t *testing.T) {
	in := []string{
		"acme.netlify.app",
		"acme-dev.netlify.app",
		"ACME.netlify.app", // case
		"*.acme.netlify.app",
		"acme.netlify.app.", // trailing dot stays — extractor strips lowercase only
		"foo.bar.netlify.app", // not a top-level slug, must NOT match
		"unrelated.example.com",
		"",
	}
	got := ExtractSiteSlugs(in)
	want := map[string]bool{"acme": true, "acme-dev": true}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected slug: %q", g)
		}
		delete(want, g)
	}
	for k := range want {
		t.Errorf("missing slug: %q", k)
	}
}

func TestSiteSlugFromCNAME(t *testing.T) {
	tests := map[string]string{
		"acme.netlify.app.":         "acme",
		"acme.netlify.app":          "acme",
		"  ACME.netlify.app  ":      "acme",
		"apex-loadbalancer.netlify.com.": "",
		"":                          "",
	}
	for in, want := range tests {
		if got := SiteSlugFromCNAME(in); got != want {
			t.Errorf("SiteSlugFromCNAME(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMutateSlugs(t *testing.T) {
	got := MutateSlugs([]string{"acme"})
	seen := map[string]bool{}
	for _, s := range got {
		if seen[s] {
			t.Errorf("dup slug: %q", s)
		}
		seen[s] = true
		if !validSlug.MatchString(s) {
			t.Errorf("invalid slug emitted: %q", s)
		}
	}
	// Must include identity and a few obvious variants.
	must := []string{"acme", "acme-dev", "dev-acme", "acme-staging"}
	for _, m := range must {
		if !seen[m] {
			t.Errorf("missing variant %q in %d outputs", m, len(got))
		}
	}
}

func TestValidSlug(t *testing.T) {
	good := []string{"abc", "abc-def", "a1b2c3", "x-y-z", strings.Repeat("a", 63)}
	bad := []string{"", "ab", "-abc", "abc-", "Abc", "abc_def", "abc.def", strings.Repeat("a", 64)}
	for _, s := range good {
		if !validSlug.MatchString(s) {
			t.Errorf("validSlug rejected %q (should accept)", s)
		}
	}
	for _, s := range bad {
		if validSlug.MatchString(s) {
			t.Errorf("validSlug accepted %q (should reject)", s)
		}
	}
}

func TestMutateSlugsLengthFilter(t *testing.T) {
	// 60-char slug + "-staging" = 68 chars → must be dropped.
	long := strings.Repeat("a", 60)
	got := MutateSlugs([]string{long})
	for _, s := range got {
		if len(s) < 3 || len(s) > 63 {
			t.Errorf("emitted out-of-range slug (%d chars): %q", len(s), s)
		}
	}
}
