package jarm

import "sync"

// resetForTest is a test-only helper that drops the loaded-once state so a
// subsequent IsNetlify / AppendLearned re-reads the user cache.
func resetForTest() {
	loadOnce = sync.Once{}
	known = nil
}
