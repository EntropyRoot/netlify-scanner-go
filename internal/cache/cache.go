package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Entry struct {
	Key       string    `json:"key"`
	StoredAt  time.Time `json:"stored_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Payload   any       `json:"payload"`
}

type Cache struct {
	Dir string
	TTL time.Duration
}

func Default(ttl time.Duration) (*Cache, error) {
	dir, err := defaultDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Cache{Dir: dir, TTL: ttl}, nil
}

func defaultDir() (string, error) {
	if v := os.Getenv("NETLIFY_SCANNER_CACHE"); v != "" {
		return v, nil
	}
	cdir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cdir, "netlify-scanner-go"), nil
}

func (c *Cache) path(key string) string {
	h := sha256.Sum256([]byte(key))
	return filepath.Join(c.Dir, hex.EncodeToString(h[:])+".json")
}

func (c *Cache) Get(key string, dst any) (bool, error) {
	path := c.path(key)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()

	var raw struct {
		Key       string          `json:"key"`
		StoredAt  time.Time       `json:"stored_at"`
		ExpiresAt time.Time       `json:"expires_at"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return false, err
	}
	if time.Now().After(raw.ExpiresAt) {
		_ = os.Remove(path)
		return false, nil
	}
	if err := json.Unmarshal(raw.Payload, dst); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Cache) Put(key string, payload any) error {
	path := c.path(key)
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(Entry{
		Key:       key,
		StoredAt:  time.Now(),
		ExpiresAt: time.Now().Add(c.TTL),
		Payload:   payload,
	}); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

func (c *Cache) Purge() error {
	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		return err
	}
	now := time.Now()
	purged := 0
	for _, e := range entries {
		p := filepath.Join(c.Dir, e.Name())
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		var raw struct {
			ExpiresAt time.Time `json:"expires_at"`
		}
		_ = json.NewDecoder(f).Decode(&raw)
		f.Close()
		if now.After(raw.ExpiresAt) {
			_ = os.Remove(p)
			purged++
		}
	}
	return nil
}

func (c *Cache) Stats() (string, error) {
	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		return "", err
	}
	var total int64
	for _, e := range entries {
		fi, err := e.Info()
		if err == nil {
			total += fi.Size()
		}
	}
	return fmt.Sprintf("%s: %d entries, %d KB", c.Dir, len(entries), total/1024), nil
}
