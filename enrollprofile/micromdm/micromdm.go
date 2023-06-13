package micromdm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/groob/plist"
	enrollprofile "github.com/korylprince/dep-webview-oidc/enrollprofile"
	"github.com/korylprince/dep-webview-oidc/log"
	"golang.org/x/exp/slog"
)

const (
	KeyPayloadContent = "PayloadContent"
	KeyPayloadType    = "PayloadType"
	KeyChallenge      = "Challenge"

	PayloadTypeSCEP = "com.apple.security.scep"
)

var ErrEmptyChallenge = errors.New("empty challenge")

type MalformedProfileError struct {
	Err string
}

func (e *MalformedProfileError) Error() string {
	return fmt.Sprintf("malformed profile: %s", e.Err)
}

// DynamicGenerator wraps an enrollprofile.Generator, getting a MicroMDM dynamic SCEP challenge and inserting it into the generated profile.
// The wrapped generator is expected to return a plain XML profile that is not signed
type DynamicGenerator struct {
	enrollprofile.Generator
	logger       *slog.Logger
	challengeURL string
	mdmKey       string
	client       *http.Client
}

type Option func(g *DynamicGenerator)

// WithLogger configures the service with the given logger
// If left unconfigured, logging will be disabled
func WithLogger(logger *slog.Logger) Option {
	return func(g *DynamicGenerator) {
		g.logger = logger
	}
}

// WithHTTPClient configured the generator to use the http client.
// If left unconfigured, http.DefaultClient will be used
func WithHTTPClient(client *http.Client) Option {
	return func(g *DynamicGenerator) {
		g.client = client
	}
}

// New returns a new DynamicGenerator with the wrapped generator and MicroMDM API URL and key.
// baseurl should be of the form http(s)://host[:port], e.g. "https://mdm.example.com"
func New(gen enrollprofile.Generator, baseURL, apiKey string, opts ...Option) *DynamicGenerator {
	g := &DynamicGenerator{
		Generator:    gen,
		challengeURL: fmt.Sprintf("%s/v1/challenge", baseURL),
		mdmKey:       apiKey,
		client:       http.DefaultClient,
	}

	for _, opt := range opts {
		opt(g)
	}

	if g.logger == nil {
		g.logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}

	g.logger.Info("started", "challenge-endpoint", g.challengeURL)

	return g
}

// insertChallenge inserts the challenge into profile bytes by unmarshaling to a generic data structure.
// TODO: would be nice to use an XML stream processor to avoid relying on github.com/groob/plist's generic data structures
func insertChallenge(buf []byte, challenge string) ([]byte, error) {
	// unmarshal to generic structure
	var data any
	if err := plist.Unmarshal(buf, &data); err != nil {
		return nil, fmt.Errorf("could not unmarshal data: %w", err)
	}

	// open profile payload
	profile, ok := data.(map[string]any)
	if !ok {
		return nil, &MalformedProfileError{Err: "unexpected profile type"}
	}
	if _, ok := profile[KeyPayloadContent]; !ok {
		return nil, &MalformedProfileError{Err: "profile PayloadContent missing"}
	}

	// open payloads array
	payloads, ok := profile[KeyPayloadContent].([]any)
	if !ok {
		return nil, &MalformedProfileError{Err: "unexpected payloads type"}
	}

	found := false

	// iterate over payloads
	for _, p := range payloads {
		// open payload
		payload, ok := p.(map[string]any)
		if !ok {
			return nil, &MalformedProfileError{Err: "unexpected payload type"}
		}

		// check payload type is correct
		if typ, ok := payload[KeyPayloadType].(string); !ok || typ != PayloadTypeSCEP {
			continue
		}

		// open inner payload data
		if _, ok := payload[KeyPayloadContent]; !ok {
			return nil, &MalformedProfileError{Err: "payload PayloadContent missing"}
		}

		payloadData, ok := payload[KeyPayloadContent].(map[string]any)
		if !ok {
			return nil, &MalformedProfileError{Err: "unexpected payload data format"}
		}

		payloadData[KeyChallenge] = challenge
		found = true
	}

	if !found {
		return nil, &MalformedProfileError{Err: "missing scep payload"}
	}

	// marshal modified data
	modified, err := plist.MarshalIndent(data, "  ")
	if err != nil {
		return nil, fmt.Errorf("could not marshal data: %w", err)
	}

	return modified, nil
}

func (g *DynamicGenerator) GenerateEnrollProfile(reqctx context.Context, ctx enrollprofile.Context) ([]byte, error) {
	type response struct {
		Challenge string `json:"string"`
	}

	buf, err := g.Generator.GenerateEnrollProfile(reqctx, ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, g.challengeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create challenge request: %w", err)
	}
	req.SetBasicAuth("micromdm", g.mdmKey)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not post challenge request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not post challenge request: http status %d", resp.StatusCode)
	}

	challenge := new(response)
	if err = json.NewDecoder(resp.Body).Decode(challenge); err != nil {
		return nil, fmt.Errorf("could not decode challenge response: %w", err)
	}

	if challenge.Challenge == "" {
		return nil, ErrEmptyChallenge
	}

	log.Attrs(reqctx, slog.String("challenge", challenge.Challenge))

	inserted, err := insertChallenge(buf, challenge.Challenge)
	if err != nil {
		return nil, fmt.Errorf("could not insert challenge: %w", err)
	}

	return inserted, nil
}
