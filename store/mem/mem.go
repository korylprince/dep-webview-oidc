package mem

import (
	"context"
	"io"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/korylprince/dep-webview-oidc/header"
	"golang.org/x/exp/slog"
)

// StateStore is a StateStore using memory
type StateStore struct {
	logger   *slog.Logger
	ttl      time.Duration
	capacity uint64
	cache    *ttlcache.Cache[string, *header.MachineInfo]
}

type Option func(s *StateStore)

// WithLogger configures the store with the given logger
// If left unconfigured, logging will be disabled
func WithLogger(logger *slog.Logger) Option {
	return func(s *StateStore) {
		s.logger = logger
	}
}

// WithTTL configures the store to automatically expire states after ttl
// If left unconfigured, a default of 5 minutes will be used
func WithTTL(ttl time.Duration) Option {
	return func(s *StateStore) {
		s.ttl = ttl
	}
}

// WithCapacity configures the store to automatically expire states after ttl
// If left unconfigured, a default of 5 minutes will be used
func WithCapacity(capacity uint64) Option {
	return func(s *StateStore) {
		s.capacity = capacity
	}
}

func NewStateStore(opts ...Option) *StateStore {
	s := &StateStore{
		ttl:      5 * time.Minute,
		capacity: 1024,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.logger == nil {
		s.logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}

	s.cache = ttlcache.New(
		ttlcache.WithTTL[string, *header.MachineInfo](s.ttl),
		ttlcache.WithCapacity[string, *header.MachineInfo](s.capacity),
	)

	// log when capacity is reached
	last := time.Now()
	s.cache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[string, *header.MachineInfo]) {
		if reason == ttlcache.EvictionReasonCapacityReached {
			// log at most every 10 seconds
			if time.Now().After(last.Add(10 * time.Second)) {
				s.logger.Warn("capacity reached", "capacity", s.capacity)
				last = time.Now()
			}
		}
	})

	s.logger.Info("started", "ttl", s.ttl, "capacity", s.capacity)

	return s
}

// SetState associates key with info in the store
func (m *StateStore) SetState(key string, info *header.MachineInfo) error {
	m.cache.Set(key, info, ttlcache.DefaultTTL)
	return nil
}

// GetState returns the info assocated with key. If key is not in the store, the returned info will be nil
func (m *StateStore) GetState(key string) (*header.MachineInfo, error) {
	item := m.cache.Get(key)
	if item == nil {
		return nil, nil
	}
	v := item.Value()
	m.cache.Delete(key)
	return v, nil
}
