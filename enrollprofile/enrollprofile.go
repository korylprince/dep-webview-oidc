package enrollprofile

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/korylprince/dep-webview-oidc/log"
	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/exp/slog"
)

// Context stores custom context data for generating an enrollment profile
type Context map[string]any

type Generator interface {
	// GenerateEnrollProfile returns the a new enrollment profile generated from ctx
	GenerateEnrollProfile(reqctx context.Context, ctx Context) ([]byte, error)
}

// StaticGenerator generates a static profile
type StaticGenerator struct {
	Profile []byte
}

// NewStaticGenerator returns a new StaticGenerator by reading the profile at filepath.
// The file is only read once at creation time
func NewStaticGenerator(filepath string) (*StaticGenerator, error) {
	buf, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", filepath, err)
	}
	return &StaticGenerator{Profile: buf}, nil
}

func (g *StaticGenerator) GenerateEnrollProfile(_ context.Context, _ Context) ([]byte, error) {
	return g.Profile, nil
}

// FileGenerator generates a profile by reading a file.
// The file is read every time GenerateEnrollProfile is called
type FileGenerator struct {
	Path string
}

func (g *FileGenerator) GenerateEnrollProfile(_ context.Context, _ Context) ([]byte, error) {
	buf, err := os.ReadFile(g.Path)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", g.Path, err)
	}
	return buf, nil
}

// Signer wraps a Generator and signs the profile after it is generated
type Signer struct {
	logger *slog.Logger
	gen    Generator
	cert   *x509.Certificate
	key    crypto.PrivateKey
}

type SignerOption func(s *Signer)

// WithLogger configures the service with the given logger
// If left unconfigured, logging will be disabled
func WithLogger(logger *slog.Logger) SignerOption {
	return func(s *Signer) {
		s.logger = logger
	}
}

// NewSigner reads the identity keypair and returns the wrapped generator
func NewSigner(gen Generator, identityPath, pass string, opts ...SignerOption) (*Signer, error) {
	identity, err := os.ReadFile(identityPath)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", identityPath, err)
	}
	key, cert, err := pkcs12.Decode(identity, pass)
	if err != nil {
		return nil, fmt.Errorf("could not decode identity: %w", err)
	}

	s := &Signer{gen: gen, cert: cert, key: key}

	for _, opt := range opts {
		opt(s)
	}

	if s.logger == nil {
		s.logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}

	s.logger.Info("started", "identity", cert.Subject.CommonName)

	return s, nil
}

func (s *Signer) GenerateEnrollProfile(reqctx context.Context, ctx Context) ([]byte, error) {
	buf, err := s.gen.GenerateEnrollProfile(reqctx, ctx)
	if err != nil {
		return nil, err
	}

	sd, err := pkcs7.NewSignedData(buf)
	if err != nil {
		return nil, fmt.Errorf("could not create signed data: %w", err)
	}

	if err = sd.AddSigner(s.cert, s.key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("could not add signer: %w", err)
	}

	signed, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("could not sign profile: %w", err)
	}

	log.Attrs(reqctx, slog.Bool("profile-signed", true))

	return signed, nil
}
