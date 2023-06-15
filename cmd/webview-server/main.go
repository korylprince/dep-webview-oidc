package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/korylprince/dep-webview-oidc/auth"
	"github.com/korylprince/dep-webview-oidc/auth/google"
	"github.com/korylprince/dep-webview-oidc/enrollprofile"
	"github.com/korylprince/dep-webview-oidc/enrollprofile/micromdm"
	"github.com/korylprince/dep-webview-oidc/header"
	"github.com/korylprince/dep-webview-oidc/service"
	"github.com/korylprince/dep-webview-oidc/store/mem"
	"golang.org/x/exp/slog"
	"golang.org/x/oauth2"
)

func run() (runErr error) {
	flLogOutput := flag.String("log-output", EnvString("LOG_OUTPUT", ""), "The log output path. If left empty or set to \"-\", stdout will be used instead")
	flLogLevel := flag.String("log-level", EnvString("LOG_LEVEL", "INFO"), "The log level. This is any level parseable by Go's slog library, e.g. DEBUG, INFO, WARN or ERROR")

	flListenAddr := flag.String("listen-addr", EnvString("LISTEN_ADDR", ""), "The host:port pair to listen on, e.g. \"[optional host]:port\"")
	flURLPrefix := flag.String("url-prefix", EnvString("URL_PREFIX", ""), "The URL prefix to use for API endpoints, e.g. \"/dep\"")
	flProxyHeaders := flag.Bool("proxy-headers", EnvBool("PROXY_HEADERS", false), "If true, proxy headers (X-Forwarded-For, etc) will be parsed to update requests and logging with the \"real\" remote")

	flTLSCert := flag.String("tls-cert", EnvString("TLS_CERT", ""), "The path to a TLS certificate")
	flTLSKey := flag.String("tls-key", EnvString("TLS_KEY", ""), "The path to a TLS key")

	flOIDCDisable := flag.Bool("oidc-disable", EnvBool("OIDC_DISABLE", false), "If true, OIDC authentication is skipped completely and authentication only fails if header verification fails")
	flOIDCClientID := flag.String("oidc-client-id", EnvString("OIDC_CLIENT_ID", ""), "The OIDC client ID")
	flOIDCClientSecret := flag.String("oidc-client-secret", EnvString("OIDC_CLIENT_SECRET", ""), "The OIDC client secret")
	flOIDCScopes := flag.String("oidc-scopes", EnvString("OIDC_SCOPES", ""), "A list of comma separated OIDC scopes to include in flow. The openid scope will always be requested, e.g. \"email, profile\"")
	flOIDCProviderURL := flag.String("oidc-provider-url", EnvString("OIDC_PROVIDER_URL", ""), "The OIDC provider URL")
	flOIDCRedirectURLBase := flag.String("oidc-redirect-url-base", EnvString("OIDC_REDIRECT_URL_BASE", ""), "The URL base where the provider should redirect after successful authentication, e.g. \"https://hostname[:port]\"")
	flOIDCURLParams := flag.String("oidc-url-params", EnvString("OIDC_URL_PARAMS", ""), "A list of comma separated keys and values to append to the provider auth url, e.g. \"key1, val1, key2, val2, ...\"")
	flOIDCStateTTL := flag.Duration("oidc-state-ttl", EnvDuration("OIDC_STATE_TTL", 5*time.Minute), "The ttl of the randomly generated OIDC state parameter. This is effectively how long the user has to enter their credentials at the provider and return to the callback URL. This should be formatted as a Go duration, e.g. \"10s\", \"15m\", \"4h\", etc")
	flOIDCStateCapacity := flag.Int("oidc-state-capacity", EnvInt("OIDC_STATE_CAPACITY", 1024), "The total number of sessions permitted. If this number is exceeded, old sessions will be evicted prematurely")

	flHeaderVerifyDisabled := flag.Bool("header-verify-disabled", EnvBool("HEADER_VERIFY_DISABLED", false), "If true, this option disables verifying of the x-apple-aspen-deviceinfo header. This can be useful for testing, but isn't recommended for production")
	flHeaderParserDisabled := flag.Bool("header-parser-disabled", EnvBool("HEADER_PARSER_DISABLED", false), "If true, this option disables parsing of the x-apple-aspen-deviceinfo header. This can be useful for testing, but isn't recommended for production")

	flEnrollProfile := flag.String("enroll-profile", EnvString("ENROLL_PROFILE", ""), "The path to the enrollment profile")
	flSignIdentity := flag.String("sign-identity", EnvString("SIGN_IDENTITY", ""), "The path to a PKCS12 identity (e.g. a developer identity from Apple). If given, the enrollment profile will be signed with this identity")
	flSignIdentityPass := flag.String("sign-identity-pass", EnvString("SIGN_IDENTITY_PASS", ""), "The passwword for -sign-identity")
	flDynamicSCEP := flag.Bool("dynamic-scep", EnvBool("DYNAMIC_SCEP", false), "If true, and -micromdm-* flags are configured, MicroMDM's dynamic SCEP challenge will be inserted into the enrollment profile")

	flMicroMDMURL := flag.String("micromdm-url", EnvString("MICROMDM_URL", ""), "The base URL of the MicroMDM server, e.g. \"https://mdm.example.com\". For use with -dynamic-scep")
	flMicroMDMKey := flag.String("micromdm-key", EnvString("MICROMDM_KEY", ""), "The API key of the MicroMDM server. For use with -dynamic-scep")

	flAuthCache := flag.Bool("auth-cache", EnvBool("AUTH_CACHE", false), "If true, cache authorizer results. This is useful with non-default authorizers like -google-auth")
	flCacheSuccessTTL := flag.Duration("cache-success-ttl", EnvDuration("CACHE_SUCCESS_TTL", 10*time.Minute), "The cache ttl of successful authorizations. This should be formatted as a Go duration, e.g. \"10s\", \"15m\", \"4h\", etc")
	flCacheFailureTTL := flag.Duration("cache-failure-ttl", EnvDuration("CACHE_FAILURE_TTL", time.Minute), "The cache ttl of failed authorizations. This should be formatted as a Go duration, e.g. \"10s\", \"15m\", \"4h\", etc")

	flGoogleAuth := flag.Bool("google-auth", EnvBool("GOOGLE_AUTH", false), "If true, and -google-* flags are configured, the Google authorizer will be enabled, which authorizes Google authentications against specific Google Groups")
	flGoogleAuthPath := flag.String("google-auth-path", EnvString("GOOGLE_AUTH_PATH", ""), "The path to a JSON OAuth 2.0 credentials file")
	flGoogleImpersonate := flag.String("google-impersonate", EnvString("GOOGLE_IMPERSONATE", ""), "The email address of the impersonated user for API calls")
	flGoogleAllowedGroups := flag.String("google-allowed-groups", EnvString("GOOGLE_ALLOWED_GROUPS", ""), "A list of comma separated Google Groups (by email) that successful authentications will be authorized against, e.g. \"admins@example.com, staff@example.com\"")
	flGoogleWorkerLimit := flag.Int("google-worker-limit", EnvInt("GOOGLE_WORKER_LIMIT", 10), "The limit of concurrent Google API requests")

	flag.Parse()

	var output io.Writer
	if *flLogOutput == "" || *flLogOutput == "-" {
		output = os.Stdout
	} else {
		w, err := os.OpenFile(*flLogOutput, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("could not open log file: %w", err)
		}
		output = w
	}

	lvl := new(slog.Level)
	if err := lvl.UnmarshalText([]byte(*flLogLevel)); err != nil {
		return fmt.Errorf("could not parse log level: %w", err)
	}

	mainlogger := slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{
		AddSource: *lvl <= slog.LevelDebug,
		Level:     lvl,
	}))
	slog.SetDefault(mainlogger.With("svc", "go/log"))
	defer func() {
		if runErr != nil {
			mainlogger.Error("service failed", "svc", "service", "error", runErr.Error())
		}
	}()

	var opts []service.Option

	opts = append(opts, service.WithLogger(mainlogger))

	if *flListenAddr != "" {
		opts = append(opts, service.WithListenAddr(*flListenAddr))
	}

	if *flURLPrefix != "" {
		opts = append(opts, service.WithURLPrefix(*flURLPrefix))
	}

	if *flProxyHeaders {
		opts = append(opts, service.WithProxyHeaders())
	}

	if *flTLSCert != "" && *flTLSKey != "" {
		opts = append(opts, service.WithTLS(*flTLSCert, *flTLSKey))
	}

	if *flOIDCDisable {
		opts = append(opts, service.WithSkipOIDC())
	} else {
		if *flOIDCClientID == "" || *flOIDCClientSecret == "" || *flOIDCProviderURL == "" || *flOIDCRedirectURLBase == "" {
			return errors.New("-oidc-client-id, -oidc-client-secret, -oidc-provider-url, and -oidc-redirect-url-base are required if -oidc-disable=false")
		}
		authOptsList := toList(*flOIDCURLParams)
		if len(authOptsList)%2 != 0 {
			return fmt.Errorf("could not parse -oidc-url-params: number of params (%d) is not even", len(authOptsList))
		}
		authOpts := make([]oauth2.AuthCodeOption, len(authOptsList)/2)
		for i := 0; i < len(authOpts); i += 2 {
			authOpts[i/2] = oauth2.SetAuthURLParam(authOptsList[i], authOptsList[i+1])
		}

		opts = append(opts, service.WithOIDCConfig(
			*flOIDCProviderURL,
			&oauth2.Config{
				ClientID:     *flOIDCClientID,
				ClientSecret: *flOIDCClientSecret,
				Scopes:       toList(*flOIDCScopes),
			},
			*flOIDCRedirectURLBase,
			authOpts...,
		))
	}

	statestore := mem.NewStateStore(
		mem.WithLogger(mainlogger.With("svc", "store")),
		mem.WithTTL(*flOIDCStateTTL),
		mem.WithCapacity(uint64(*flOIDCStateCapacity)),
	)
	opts = append(opts, service.WithStateStore(statestore))

	if *flHeaderVerifyDisabled {
		opts = append(opts, service.WithHeaderParser(header.NewParser(header.WithVerify(false))))
	}

	if *flHeaderParserDisabled {
		opts = append(opts, service.WithHeaderParserDisabled())
	}

	if *flEnrollProfile == "" {
		return errors.New("missing -enroll-profile")
	}

	var generator enrollprofile.Generator = &enrollprofile.FileGenerator{Path: *flEnrollProfile}

	if *flDynamicSCEP {
		if *flMicroMDMURL == "" || *flMicroMDMKey == "" {
			return errors.New("-dynamic-scep requires -micromdm-url and -micromdm-key")
		}
		generator = micromdm.New(generator, *flMicroMDMURL, *flMicroMDMKey,
			micromdm.WithLogger(mainlogger.With("svc", "micromdm-scep")),
		)
	}

	if *flSignIdentity != "" {
		signGenerator, err := enrollprofile.NewSigner(
			generator, *flSignIdentity, *flSignIdentityPass,
			enrollprofile.WithLogger(mainlogger.With("svc", "profile-signer")),
		)
		if err != nil {
			return fmt.Errorf("could not create enrollment profile signer: %w", err)
		}
		generator = signGenerator
	}

	opts = append(opts, service.WithEnrollProfileGenerator(generator))

	var authorizer auth.Authorizer = &auth.NopAuthorizer{}

	if *flGoogleAuth {
		if *flOIDCDisable {
			return errors.New("-google-auth requires -oidc-disable=false")
		}
		if *flGoogleAuthPath == "" || *flGoogleImpersonate == "" || *flGoogleAllowedGroups == "" {
			return errors.New("-google-auth requires -google-auth-path, -google-impersonate, and -google-allowed-groups")
		}
		googleAuthorizer, err := google.New(*flGoogleAuthPath, *flGoogleImpersonate, toList(*flGoogleAllowedGroups),
			google.WithLogger(mainlogger.With("svc", "google-auth")),
			google.WithWorkerLimit(*flGoogleWorkerLimit),
		)
		if err != nil {
			return fmt.Errorf("could not create google authorizer: %w", err)
		}
		authorizer = googleAuthorizer
	}

	if *flAuthCache {
		authorizer = auth.NewCacheAuthorizer(authorizer,
			auth.WithLogger(mainlogger.With("svc", "auth-cache")),
			auth.WithSuccessCacheTTL(*flCacheSuccessTTL),
			auth.WithFailureCacheTTL(*flCacheFailureTTL),
		)
	}
	opts = append(opts, service.WithAuthorizer(authorizer))

	svc, err := service.New(opts...)
	if err != nil {
		return fmt.Errorf("could not create service: %w", err)
	}

	if err := svc.Run(); err != nil {
		return fmt.Errorf("listener failed: %w", err)
	}

	return nil
}

func main() {
	//nolint:errcheck
	run()
}
