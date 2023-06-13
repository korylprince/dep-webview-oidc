package mem

import (
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/korylprince/dep-webview-oidc/header"
)

// MemoryStateStore is a StateStore using memory
type MemoryStateStore struct {
	cache *ttlcache.Cache[string, *header.MachineInfo]
}

func NewMemoryStateStore(ttl time.Duration) MemoryStateStore {
	return MemoryStateStore{
		cache: ttlcache.New(ttlcache.WithTTL[string, *header.MachineInfo](ttl)),
	}
}

// SetState associates key with info in the store
func (m MemoryStateStore) SetState(key string, info *header.MachineInfo) error {
	m.cache.Set(key, info, ttlcache.DefaultTTL)
	return nil
}

// GetState returns the info assocated with key. If key is not in the store, the returned info will be nil
func (m MemoryStateStore) GetState(key string) (*header.MachineInfo, error) {
	item := m.cache.Get(key)
	if item == nil {
		return nil, nil
	}
	v := item.Value()
	m.cache.Delete(key)
	return v, nil
}
