package replay

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/ir-netlify/netlify-scanner-go/internal/pipeline"
)

type Frame struct {
	OffsetMs int64           `json:"t_ms"`
	Kind     string          `json:"kind"`
	Stage    string          `json:"stage,omitempty"`
	Message  string          `json:"msg,omitempty"`
	Verdict  json.RawMessage `json:"verdict,omitempty"`
}

type Recorder struct {
	w     io.Writer
	start time.Time
	enc   *json.Encoder
}

func NewRecorder(w io.Writer) *Recorder {
	return &Recorder{w: w, start: time.Now(), enc: json.NewEncoder(w)}
}

func (r *Recorder) On(ev pipeline.Event) {
	f := Frame{
		OffsetMs: time.Since(r.start).Milliseconds(),
		Kind:     string(ev.Kind),
		Stage:    ev.Stage,
		Message:  ev.Message,
	}
	if ev.Verdict != nil {
		b, _ := json.Marshal(ev.Verdict)
		f.Verdict = b
	}
	_ = r.enc.Encode(f)
}

func Play(ctx context.Context, path string, speed float64, emit func(pipeline.Event)) error {
	if speed <= 0 {
		speed = 1
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)

	wallStart := time.Now()
	for sc.Scan() {
		var fr Frame
		if err := json.Unmarshal(sc.Bytes(), &fr); err != nil {
			continue
		}
		due := wallStart.Add(time.Duration(float64(fr.OffsetMs)/speed) * time.Millisecond)
		if d := time.Until(due); d > 0 {
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		ev := pipeline.Event{
			Kind:    pipeline.EventKind(fr.Kind),
			Stage:   fr.Stage,
			Message: fr.Message,
		}
		if len(fr.Verdict) > 0 {
			var v = new(struct {
				Host      string `json:"host"`
			})
			_ = json.Unmarshal(fr.Verdict, v)
		}
		emit(ev)
	}
	return sc.Err()
}
