package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/handlers"
	"github.com/korylprince/dep-webview-oidc/auth"
	"github.com/korylprince/dep-webview-oidc/enrollprofile"
	"github.com/korylprince/dep-webview-oidc/header"
	"github.com/korylprince/dep-webview-oidc/log"
	"github.com/korylprince/dep-webview-oidc/store"
	"github.com/korylprince/dep-webview-oidc/store/mem"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"
	"golang.org/x/oauth2"
)

var (
	ErrMissingRedirectURLBase = errors.New("missing redirect URL base")
	ErrMissingOIDCConfig      = errors.New("missing OIDC config")
	ErrMissingGenerator       = errors.New("missing enrollment profile generator")
)

// Service manages the HTTP endpoints and all dependent services
type Service struct {
	logger *slog.Logger

	listenAddr   string
	prefix       string
	proxyHeaders bool

	certPath string
	keyPath  string

	oauth2Config *oauth2.Config
	authOpts     []oauth2.AuthCodeOption
	redirectBase string
	verifier     *oidc.IDTokenVerifier

	parserDisabled bool
	parser         *header.Parser

	store           store.StateStore
	errWriter       ErrorWriter
	authorizer      auth.SessionAuthorizer
	enrollGenerator enrollprofile.Generator
}

type Option func(s *Service) error

// WithLogger configures the service with the given logger
// If left unconfigured, logging will be disabled
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) error {
		s.logger = logger
		return nil
	}
}

// WithListenAddr configures the service's listening address ([host]:port pair).
// If left unconfigured, it will default to net/http's default of :80 or :443 depending on if TLS is enabled
func WithListenAddr(addr string) Option {
	return func(s *Service) error {
		s.listenAddr = addr
		return nil
	}
}

// WithURLPrefix configures the service with a URL prefix, e.g. prefix = "/dep" -> "https://hostname/dep/v1/authorize"
// If left unconfigured, no prefix will be used
func WithURLPrefix(prefix string) Option {
	return func(s *Service) error {
		s.prefix = prefix
		return nil
	}
}

// WithProxyHeaders configures the service to parse proxy headers to update the HTTP request with the "real" remote.
// If left unconfigured, proxy headers will not be parsed
func WithProxyHeaders(enabled bool) Option {
	return func(s *Service) error {
		s.proxyHeaders = enabled
		return nil
	}
}

// WithTLS configures the service to use TLS with the given cert and key paths
// If left unconfigured, the service will not use TLS
func WithTLS(certPath, keyPath string) Option {
	return func(s *Service) error {
		s.certPath = certPath
		s.keyPath = keyPath
		return nil
	}
}

// WithOIDCConfig configures the service with the given provider and OAuth 2.0 config.
// redirectURLBase is the base url that will form the redirect url given to the provider, e.g. https://hostname[:port].
// authOpts may be specified to include extra parameters in the redirected authorization URL
func WithOIDCConfig(providerURL string, config *oauth2.Config, redirectURLBase string, authOpts ...oauth2.AuthCodeOption) Option {
	return func(s *Service) error {
		if redirectURLBase == "" {
			return ErrMissingRedirectURLBase
		}
		s.redirectBase = redirectURLBase
		provider, err := oidc.NewProvider(context.Background(), providerURL)
		if err != nil {
			return fmt.Errorf("could not query provider: %w", err)
		}
		s.oauth2Config = config
		if !slices.Contains(s.oauth2Config.Scopes, oidc.ScopeOpenID) {
			s.oauth2Config.Scopes = append(s.oauth2Config.Scopes, oidc.ScopeOpenID)
		}
		s.authOpts = authOpts
		s.oauth2Config.Endpoint = provider.Endpoint()
		s.verifier = provider.Verifier(&oidc.Config{ClientID: config.ClientID})
		return nil
	}
}

// WithHeaderParserDisabled configures the service to parse the x-apple-aspen-deviceinfo header or not.
// If left unconfigured, the header will be parsed.
// If disabled is true, an empty, non-nil *header.MachineInfo will be passed to the service's SessionAuthorizer
func WithHeaderParserDisabled(disabled bool) Option {
	return func(s *Service) error {
		s.parserDisabled = disabled
		return nil
	}
}

// WithHeaderParser configures the service with the given header parser.
// If left unconfigured, header.DefaultParser is used
func WithHeaderParser(parser *header.Parser) Option {
	return func(s *Service) error {
		s.parser = parser
		return nil
	}
}

// WithStateStore configures the service with the given store.
// If left unconfigured, an in-memory store will be used with an expiry of 5 minutes
func WithStateStore(store store.StateStore) Option {
	return func(s *Service) error {
		s.store = store
		return nil
	}
}

// WithErrorWriter configures the service with the given error writer.
// If left unconfigured, a text error writer will be used
func WithErrorWriter(errWriter ErrorWriter) Option {
	return func(s *Service) error {
		s.errWriter = errWriter
		return nil
	}
}

// WithSessionAuthorizer configures the service with the given session authorizer.
// If left unconfigured, all sessions will be authorized
func WithSessionAuthorizer(authorizer auth.SessionAuthorizer) Option {
	return func(s *Service) error {
		s.authorizer = authorizer
		return nil
	}
}

// WithEnrollProfileGenerator configures the service with the given enrollment profile generator
func WithEnrollProfileGenerator(generator enrollprofile.Generator) Option {
	return func(s *Service) error {
		s.enrollGenerator = generator
		return nil
	}
}

func New(opts ...Option) (*Service, error) {
	s := &Service{}

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	if s.oauth2Config == nil {
		return nil, ErrMissingOIDCConfig
	}

	if s.enrollGenerator == nil {
		return nil, ErrMissingGenerator
	}

	if s.logger == nil {
		s.logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}

	svclogger := s.logger.With("svc", "service")

	s.oauth2Config.RedirectURL = fmt.Sprintf("%s%s/v1/callback", s.redirectBase, s.prefix)
	svclogger.Info("starting", "redirect-url", s.oauth2Config.RedirectURL)

	if s.parser == nil {
		s.parser = header.DefaultParser
	}
	if s.authorizer == nil {
		svclogger.Info("using default no-op authorizer")
		s.authorizer = auth.NopAuthorizer{}
	}
	if s.errWriter == nil {
		s.errWriter = TextErrorWriter{}
	}
	if s.store == nil {
		ttl := 5 * time.Minute
		svclogger.Info("using default in-memory state store", "ttl", ttl.String())
		s.store = mem.NewMemoryStateStore(ttl)
	}

	return s, nil
}

// Run starts the service and returns an error if the underlying http listener fails
func (s *Service) Run() error {
	mux := http.NewServeMux()
	mux.Handle(fmt.Sprintf("%s/v1/authorize", s.prefix), s.RedirectHandler())
	mux.Handle(fmt.Sprintf("%s/v1/callback", s.prefix), s.CallbackHandler())

	handler := log.WithLogging(s.logger.With("svc", "http"), mux)
	if s.proxyHeaders {
		handler = handlers.ProxyHeaders(handler)
	}

	if s.certPath != "" && s.keyPath != "" {
		s.logger.Info("starting", "svc", "http", "tls", true, "addr", s.listenAddr)
		return http.ListenAndServeTLS(s.listenAddr, s.certPath, s.keyPath, handler)
	}

	s.logger.Info("starting", "svc", "http", "tls", false, "addr", s.listenAddr)
	return http.ListenAndServe(s.listenAddr, handler)
}
