package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

type Options struct {
	Level    string
	Format   string
	Output   io.Writer
	NoColor  bool
}

func Setup(o Options) *slog.Logger {
	if o.Output == nil {
		o.Output = os.Stderr
	}
	lvl := parseLevel(o.Level)
	var h slog.Handler
	switch strings.ToLower(o.Format) {
	case "json":
		h = slog.NewJSONHandler(o.Output, &slog.HandlerOptions{Level: lvl, AddSource: lvl == slog.LevelDebug})
	default:
		h = newPrettyHandler(o.Output, lvl, !o.NoColor)
	}
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

type prettyHandler struct {
	w     io.Writer
	level slog.Level
	color bool
	attrs []slog.Attr
	group string
}

func newPrettyHandler(w io.Writer, lvl slog.Level, color bool) slog.Handler {
	return &prettyHandler{w: w, level: lvl, color: color}
}

const (
	cReset   = "\x1b[0m"
	cDim     = "\x1b[90m"
	cInfo    = "\x1b[36m"
	cWarn    = "\x1b[33m"
	cErr     = "\x1b[31m"
	cDebug   = "\x1b[35m"
	cAccent  = "\x1b[96m"
)

func (h *prettyHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }
func (h *prettyHandler) WithAttrs(a []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr{}, h.attrs...), a...)
	return &cp
}
func (h *prettyHandler) WithGroup(g string) slog.Handler {
	cp := *h
	cp.group = g
	return &cp
}

func (h *prettyHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	if h.color {
		b.WriteString(cDim)
	}
	b.WriteString(r.Time.Format("15:04:05.000"))
	if h.color {
		b.WriteString(cReset)
	}
	b.WriteByte(' ')

	lvlColor := ""
	switch r.Level {
	case slog.LevelDebug:
		lvlColor = cDebug
	case slog.LevelInfo:
		lvlColor = cInfo
	case slog.LevelWarn:
		lvlColor = cWarn
	case slog.LevelError:
		lvlColor = cErr
	}
	if h.color {
		b.WriteString(lvlColor)
	}
	b.WriteString(padRight(r.Level.String(), 5))
	if h.color {
		b.WriteString(cReset)
	}
	b.WriteByte(' ')

	if h.color {
		b.WriteString(cAccent)
	}
	b.WriteString(r.Message)
	if h.color {
		b.WriteString(cReset)
	}

	for _, a := range h.attrs {
		writeAttr(&b, a, h.color)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, a, h.color)
		return true
	})
	b.WriteByte('\n')
	_, err := h.w.Write([]byte(b.String()))
	return err
}

func writeAttr(b *strings.Builder, a slog.Attr, color bool) {
	b.WriteByte(' ')
	if color {
		b.WriteString(cDim)
	}
	b.WriteString(a.Key)
	b.WriteByte('=')
	if color {
		b.WriteString(cReset)
	}
	b.WriteString(a.Value.String())
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
