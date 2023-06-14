package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jellydator/ttlcache/v3"
	"github.com/korylprince/dep-webview-oidc/enrollprofile"
	"github.com/korylprince/dep-webview-oidc/header"
	"github.com/korylprince/dep-webview-oidc/log"
	"golang.org/x/exp/slog"
	"golang.org/x/oauth2"
)

type AuthorizationError struct {
	Err error
}

func (e *AuthorizationError) Error() string {
	return fmt.Sprintf("unauthorized: %v", e.Err)
}

func (e *AuthorizationError) Unwrap() error {
	return e.Err
}

type Authorizer interface {
	// AuthorizeSession authorizes the user/device session and returns an EnrollContext that can be passed to an EnrollmentGenerator.
	// If the request is not authorized, an error of type AuthorizationError is returned.
	AuthorizeSession(ctx context.Context, info *header.MachineInfo, oauth2Token *oauth2.Token, idToken *oidc.IDToken) (enrollprofile.Context, error)
}

// NopAuthorizer authorizes every session
type NopAuthorizer struct{}

func (a NopAuthorizer) AuthorizeSession(_ context.Context, _ *header.MachineInfo, _ *oauth2.Token, _ *oidc.IDToken) (enrollprofile.Context, error) {
	return make(enrollprofile.Context), nil
}

// CacheAuthorizer wraps an Authorizer and caches results for configurable durations.
// The cache uses the OIDC id_token subject as the cache key.
// Note: only errors that are AuthorizationError (when checked with errors.As) are cached.
type CacheAuthorizer struct {
	authorizer Authorizer
	logger     *slog.Logger
	ttl        time.Duration
	failttl    time.Duration
	cache      *ttlcache.Cache[string, enrollprofile.Context]
	failcache  *ttlcache.Cache[string, error]
}

type CacheOption func(a *CacheAuthorizer)

// WithLogger configures the authorizer with the given logger
// If left unconfigured, logging will be disabled
func WithLogger(logger *slog.Logger) CacheOption {
	return func(a *CacheAuthorizer) {
		a.logger = logger
	}
}

// WithSuccessCacheTTL configures the cache to cache successful authorizations for the given duration.
// If left unconfigured, a default of 10 minutes will be used
func WithSuccessCacheTTL(ttl time.Duration) CacheOption {
	return func(a *CacheAuthorizer) {
		a.ttl = ttl
	}
}

// WithFailurCacheTTL configures the cache to cache failed authorizations for the given duration.
// If left unconfigured, a default of 1 minute will be used.
func WithFailureCacheTTL(ttl time.Duration) CacheOption {
	return func(a *CacheAuthorizer) {
		a.failttl = ttl
	}
}

func NewCacheAuthorizer(authorizer Authorizer, opts ...CacheOption) *CacheAuthorizer {
	a := &CacheAuthorizer{
		authorizer: authorizer,
		ttl:        10 * time.Minute,
		failttl:    time.Minute,
	}

	for _, opt := range opts {
		opt(a)
	}

	a.cache = ttlcache.New(
		ttlcache.WithTTL[string, enrollprofile.Context](a.ttl),
		ttlcache.WithDisableTouchOnHit[string, enrollprofile.Context](),
	)

	a.failcache = ttlcache.New(
		ttlcache.WithTTL[string, error](a.failttl),
		ttlcache.WithDisableTouchOnHit[string, error](),
	)

	if a.logger == nil {
		a.logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}

	a.logger.Info("started", "success-ttl", a.ttl.String(), "fail-ttl", a.failttl.String())

	return a
}

func (a CacheAuthorizer) AuthorizeSession(ctx context.Context, info *header.MachineInfo, oauth2Token *oauth2.Token, idToken *oidc.IDToken) (enrollprofile.Context, error) {
	item := a.cache.Get(idToken.Subject)
	if item != nil {
		log.Attrs(ctx, slog.Bool("auth-cached", true))
		return item.Value(), nil
	}

	fail := a.failcache.Get(idToken.Subject)
	if fail != nil {
		log.Attrs(ctx, slog.Bool("auth-cached", true))
		return nil, fail.Value()
	}

	log.Attrs(ctx, slog.Bool("auth-cached", false))

	profilectx, err := a.authorizer.AuthorizeSession(ctx, info, oauth2Token, idToken)
	if err == nil {
		a.cache.Set(idToken.Subject, profilectx, ttlcache.DefaultTTL)
	} else {
		aerr := new(AuthorizationError)
		if errors.As(err, &aerr) {
			a.failcache.Set(idToken.Subject, err, ttlcache.DefaultTTL)
		}
	}

	return profilectx, err
}
