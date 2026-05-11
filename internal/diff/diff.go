package diff

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/ir-netlify/netlify-scanner-go/internal/netlify"
)

type Change struct {
	Host       string          `json:"host"`
	Kind       string          `json:"kind"` // added | removed | changed
	OldScore   int             `json:"old_score,omitempty"`
	NewScore   int             `json:"new_score,omitempty"`
	OldSignals netlify.Signal  `json:"old_signals,omitempty"`
	NewSignals netlify.Signal  `json:"new_signals,omitempty"`
}

type Result struct {
	Added   []Change `json:"added"`
	Removed []Change `json:"removed"`
	Changed []Change `json:"changed"`
	Stats   struct {
		OldTotal int `json:"old_total"`
		NewTotal int `json:"new_total"`
	} `json:"stats"`
}

func ReadJSONL(path string) (map[string]netlify.Verdict, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]netlify.Verdict{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var v netlify.Verdict
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			continue
		}
		out[v.Host] = v
	}
	return out, sc.Err()
}

func Compute(oldM, newM map[string]netlify.Verdict) Result {
	var r Result
	r.Stats.OldTotal = len(oldM)
	r.Stats.NewTotal = len(newM)

	for h, nv := range newM {
		ov, ok := oldM[h]
		if !ok {
			r.Added = append(r.Added, Change{Host: h, Kind: "added", NewScore: nv.Score, NewSignals: nv.Signals})
			continue
		}
		if !signalsEqual(ov.Signals, nv.Signals) || ov.Score != nv.Score {
			r.Changed = append(r.Changed, Change{
				Host: h, Kind: "changed",
				OldScore: ov.Score, NewScore: nv.Score,
				OldSignals: ov.Signals, NewSignals: nv.Signals,
			})
		}
	}
	for h, ov := range oldM {
		if _, ok := newM[h]; !ok {
			r.Removed = append(r.Removed, Change{Host: h, Kind: "removed", OldScore: ov.Score, OldSignals: ov.Signals})
		}
	}
	sort.Slice(r.Added, func(i, j int) bool { return r.Added[i].Host < r.Added[j].Host })
	sort.Slice(r.Removed, func(i, j int) bool { return r.Removed[i].Host < r.Removed[j].Host })
	sort.Slice(r.Changed, func(i, j int) bool { return r.Changed[i].Host < r.Changed[j].Host })
	return r
}

func signalsEqual(a, b netlify.Signal) bool {
	return a.CNAMEMatch == b.CNAMEMatch &&
		a.APEXFallback == b.APEXFallback &&
		a.HeaderMatch == b.HeaderMatch &&
		a.ServerHeader == b.ServerHeader &&
		a.TLSSANMatch == b.TLSSANMatch &&
		a.ASNMatch == b.ASNMatch
}

func WriteJSON(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func WriteText(w io.Writer, r Result) {
	fmt.Fprintf(w, "old=%d  new=%d  Δ=%+d\n",
		r.Stats.OldTotal, r.Stats.NewTotal, r.Stats.NewTotal-r.Stats.OldTotal)
	fmt.Fprintf(w, "added:   %d\nremoved: %d\nchanged: %d\n\n", len(r.Added), len(r.Removed), len(r.Changed))
	for _, c := range r.Added {
		fmt.Fprintf(w, "+ %s  score=%d\n", c.Host, c.NewScore)
	}
	for _, c := range r.Removed {
		fmt.Fprintf(w, "- %s  score=%d\n", c.Host, c.OldScore)
	}
	for _, c := range r.Changed {
		fmt.Fprintf(w, "~ %s  %d → %d\n", c.Host, c.OldScore, c.NewScore)
	}
}
