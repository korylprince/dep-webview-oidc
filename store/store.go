package store

import (
	"github.com/korylprince/dep-webview-oidc/header"
)

// StateStore is storage for OAuth 2.0 states. Implementers should automatically expire states after they are no longer valid
type StateStore interface {
	// SetState associates key with info in the store
	SetState(key string, info *header.MachineInfo) error
	// GetState returns the info assocated with key. If key is not in the store, the returned info will be nil
	GetState(key string) (*header.MachineInfo, error)
}
