package google

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/korylprince/dep-webview-oidc/auth"
	"github.com/korylprince/dep-webview-oidc/enrollprofile"
	"github.com/korylprince/dep-webview-oidc/header"
	"github.com/korylprince/dep-webview-oidc/log"
	"golang.org/x/exp/slog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/errgroup"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

var (
	ErrInvalidEmail      = errors.New("invalid email")
	ErrUnauthorizedEmail = errors.New("unauthorized email")
)

// Authorizer verifies a user is in a Google Group or Groups and sets those groups in the returned Context
type Authorizer struct {
	svc     *admin.MembersService
	allowed []string
	logger  *slog.Logger
	pool    chan struct{}
}

type Option func(a *Authorizer)

// WithLogger configures the authorizer with the given logger
// If left unconfigured, logging will be disabled
func WithLogger(logger *slog.Logger) Option {
	return func(a *Authorizer) {
		a.logger = logger
	}
}

// WithWorkerLimit configures the authorizer to limit the number of concurrent API requests across all AuthorizeSession calls.
// If left unconfigured, there is no limit enforced
func WithWorkerLimit(limit int) Option {
	return func(a *Authorizer) {
		a.pool = make(chan struct{}, limit)
	}
}

// New returns a new Authorizer with the given service account json path, user to impersonate, and list of groups (by group email)
func New(jsonPath, impersonateUser string, allowedGroups []string, opts ...Option) (*Authorizer, error) {
	buf, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("could not read json auth file: %w", err)
	}
	config, err := google.JWTConfigFromJSON(buf, admin.AdminDirectoryGroupMemberReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("could not create config: %w", err)
	}

	if impersonateUser != "" {
		config.Subject = impersonateUser
	}

	adminSvc, err := admin.NewService(context.Background(), option.WithHTTPClient(config.Client(context.Background())))
	if err != nil {
		return nil, fmt.Errorf("could not create admin service: %w", err)
	}

	a := &Authorizer{svc: admin.NewMembersService(adminSvc), allowed: allowedGroups}

	for _, opt := range opts {
		opt(a)
	}

	if a.logger == nil {
		a.logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}

	a.logger.Info("started", "impersonate_user", impersonateUser)

	return a, nil
}

// AuthorizeSession authorizes the user/device session and returns an EnrollContext that can be passed to an EnrollmentGenerator.
// If the request is not authorized, an error of type AuthorizationError is returned.
func (a *Authorizer) AuthorizeSession(ctx context.Context, _ *header.MachineInfo, _ *oauth2.Token, idToken *oidc.IDToken) (enrollprofile.Context, error) {
	type claims struct {
		Email string `json:"email"`
	}

	// get email from id_token
	email := new(claims)
	if err := idToken.Claims(email); err != nil {
		return nil, fmt.Errorf("could not parse email from id_token: %w", err)
	}

	if email.Email == "" {
		return nil, ErrInvalidEmail
	}

	// concurrently check each group for membership
	errgrp := new(errgroup.Group)
	var mu sync.Mutex
	results := make(map[string]bool)

	for _, g := range a.allowed {
		grp := g
		errgrp.Go(func() error {
			if a.pool != nil {
				a.pool <- struct{}{}
				defer func() { <-a.pool }()
			}
			check, err := a.svc.HasMember(grp, email.Email).Do()
			if err != nil {
				return fmt.Errorf("could not check membership (%s): %w", grp, err)
			}
			mu.Lock()
			results[grp] = check.IsMember
			mu.Unlock()
			return nil
		})
	}

	// check authorization
	err := errgrp.Wait()
	authed := false
	var grps []string
	for grp, ok := range results {
		if ok {
			authed = true
			grps = append(grps, grp)
		}
	}

	log.Attrs(ctx, slog.String("email", email.Email))

	if !authed {
		if err != nil {
			// if all queries failed, don't return AuthorizationError
			if len(results) == 0 {
				return nil, fmt.Errorf("could not query group(s): %w", err)
			}
			return nil, &auth.AuthorizationError{Err: fmt.Errorf("could not query group(s): %w", err)}
		}
		return nil, &auth.AuthorizationError{Err: ErrUnauthorizedEmail}
	}

	log.LevelAttrs(ctx, slog.LevelDebug, slog.Any("groups", grps))

	if err != nil {
		id := log.RequestID(ctx)
		a.logger.Warn("error during successful authorization", "req-id", id, "error", err.Error())
	}

	return enrollprofile.Context{"email": email.Email, "groups": grps}, nil
}
