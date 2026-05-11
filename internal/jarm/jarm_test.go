package jarm

import (
	"os"
	"testing"
)

func TestParseHashes(t *testing.T) {
	raw := "# comment\n\nABC\n  def  \n# nope\n123\n"
	got := parseHashes(raw)
	if _, ok := got["abc"]; !ok {
		t.Errorf("missing lowercased 'abc' in %v", got)
	}
	if _, ok := got["def"]; !ok {
		t.Errorf("missing trimmed 'def' in %v", got)
	}
	if _, ok := got["123"]; !ok {
		t.Errorf("missing '123'")
	}
	if len(got) != 3 {
		t.Errorf("got %d entries, want 3: %v", len(got), got)
	}
}

func TestIsNetlifyAndAppend(t *testing.T) {
	// Redirect user cache to a tmpdir so we don't pollute the real one.
	tmp := t.TempDir()
	t.Setenv("NETLIFY_SCANNER_CACHE", tmp)
	// Reset the once + global so the package re-reads the new cache.
	resetForTest()

	if IsNetlify("zzzzzz-not-a-real-hash-zzzzzz") {
		t.Fatal("unexpected match for unknown hash")
	}

	n, err := AppendLearned([]string{"zzz-hash-1", "zzz-hash-1", "zzz-hash-2"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("appended %d, want 2", n)
	}
	if !IsNetlify("zzz-hash-1") {
		t.Error("expected match after AppendLearned")
	}
	// Ensure the cache file actually got written.
	if _, err := os.Stat(userCachePath()); err != nil {
		t.Errorf("cache file not created: %v", err)
	}
}
