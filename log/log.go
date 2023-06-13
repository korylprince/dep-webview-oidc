package log

import (
	"context"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"golang.org/x/exp/slog"
)

type ctxKeyLog struct{}

type statusWriter struct {
	http.ResponseWriter
	status int
	size   int64
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.size += int64(n)
	return n, err
}

type record struct {
	id     uint64
	minlvl slog.Level
	attrs  []slog.Attr
	mu     sync.RWMutex
}

func (r *record) set(attrs ...slog.Attr) {
	r.mu.Lock()
	r.attrs = append(r.attrs, attrs...)
	r.mu.Unlock()
}

// RequestID returns the id of the log record stored on the context
func RequestID(ctx context.Context) uint64 {
	rec, ok := ctx.Value(ctxKeyLog{}).(*record)
	if !ok || rec == nil {
		return 0
	}
	return rec.id
}

// Attrs adds attrs to the log record stored on the context
func Attrs(ctx context.Context, attrs ...slog.Attr) {
	rec, ok := ctx.Value(ctxKeyLog{}).(*record)
	if !ok || rec == nil {
		return
	}
	rec.set(attrs...)
}

// LevelAttrs adds attrs to the log record stored on the context if lvl is not below the minimum logger level
func LevelAttrs(ctx context.Context, lvl slog.Level, attrs ...slog.Attr) {
	rec, ok := ctx.Value(ctxKeyLog{}).(*record)
	if !ok || rec == nil {
		return
	}
	if lvl < rec.minlvl {
		return
	}
	rec.set(attrs...)
}

// WithLogging configures an http request logging middleware
func WithLogging(logger *slog.Logger, next http.Handler) http.Handler {
	// find minimum log level
	var minlvl slog.Level = slog.LevelDebug
	for ; minlvl <= slog.LevelError; minlvl++ {
		if logger.Enabled(context.Background(), minlvl) {
			break
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// create log record
		before := time.Now()
		id := rand.Uint64()

		// only log url query params if log level is DEBUG
		var url string
		if minlvl > slog.LevelDebug {
			url = r.URL.Path
		} else {
			url = r.URL.String()
		}

		rec := &record{id: id, minlvl: minlvl, attrs: []slog.Attr{
			slog.Uint64("req-id", id),
			slog.String("remote", r.RemoteAddr),
			slog.Time("start", before),
			slog.String("proto", r.Proto),
			slog.String("method", r.Method),
			slog.String("host", r.Host),
			slog.String("path", url),
		}}
		ctx := context.WithValue(r.Context(), ctxKeyLog{}, rec)

		// wrap ResponseWriter
		sw := &statusWriter{ResponseWriter: w}

		// run handler
		next.ServeHTTP(sw, r.WithContext(ctx))

		// set level
		lvl := slog.LevelInfo
		if sw.status > 400 {
			lvl = slog.LevelWarn
		} else if sw.status > 500 {
			lvl = slog.LevelError
		}

		// log event after returning
		defer func() {
			rec.set([]slog.Attr{
				slog.Duration("duration", time.Since(before)),
				slog.String("status", http.StatusText(sw.status)),
				slog.Int("status-code", sw.status),
				slog.Int64("size", sw.size),
			}...)
			logger.LogAttrs(context.Background(), lvl, "", rec.attrs...)
		}()
	})
}
