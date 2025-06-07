package header

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/groob/plist"
	"go.mozilla.org/pkcs7"
)

const DeviceInfoHeader = "x-apple-aspen-deviceinfo"

var (
	ErrEmptyHeader        = errors.New("empty header")
	ErrMissingMachineInfo = errors.New("missing MachineInfo")
	ErrNotSigned          = errors.New("not signed")
	ErrCertRootNotFound   = errors.New("certificate root not found")
)

type InvalidHeaderError struct {
	Err error
}

func (e *InvalidHeaderError) Error() string {
	return fmt.Sprintf("invalid %s header: %v", DeviceInfoHeader, e.Err)
}

func (e *InvalidHeaderError) Unwrap() error {
	return e.Err
}

// appleRootCert is https://www.apple.com/appleca/AppleIncRootCertificate.cer
//
//go:embed AppleIncRootCertificate.cer
var appleRootCert []byte

func newAppleRootCert() *x509.Certificate {
	cert, err := x509.ParseCertificate(appleRootCert)
	if err != nil {
		panic(fmt.Errorf("could not parse cert: %w", err))
	}
	return cert
}

// AppleRootCert is Apple's Root CA parsed to an *x509.Certificate
var AppleRootCert = newAppleRootCert()

type Context map[string]any

// Origin is the origin of the MachineInfo
type Origin string

const (
	OriginHeader = "header"
	OriginBody   = "body"
)

// MachineInfo is a [device's information] sent as part of an MDM enrollment profile request
//
// [device's information]: https://developer.apple.com/documentation/devicemanagement/machineinfo
type MachineInfo struct {
	// Origin is the origin of the MachineInfo, either header or body.
	// This field is not a part of the MachineInfo itself.
	Origin Origin `plist:"-"`

	IMEI                        string `plist:"IMEI,omitempty"`
	Language                    string `plist:"LANGUAGE,omitempty"`
	MDMCanRequestSoftwareUpdate bool   `plist:"MDM_CAN_REQUEST_SOFTWARE_UPDATE,omitempty"`
	MEID                        string `plist:"MEID,omitempty"`
	OSVersion                   string `plist:"OS_VERSION,omitempty"`
	PairingToken                string `plist:"PAIRING_TOKEN,omitempty"`
	Product                     string `plist:"PRODUCT"`
	Serial                      string `plist:"SERIAL"`
	SoftwareUpdateDeviceID      string `plist:"SOFTWARE_UPDATE_DEVICE_ID"`
	SupplementalBuildVersion    string `plist:"SUPPLEMENTAL_BUILD_VERSION,omitempty"`
	SupplementalOSVersionExtra  string `plist:"SUPPLEMENTAL_OS_VERSION_EXTRA,omitempty"`
	UDID                        string `plist:"UDID"`
	Version                     string `plist:"VERSION"`

	// VerifyContext is optionally populated by VerifyFuncs set on the Parser.
	// Parser.Parse guarantees VerifyContext to be non-nil
	VerifyContext Context `plist:"-"`
}

// VerifyFunc is used to add additional verification of the initial device request.
// The original request, r, verified PKCS7 header, p7, additional context, ctx, and the MachineInfo origin are passed to the function.
// ctx is passed through the chain of VerifyFuncs,
// with the final result being added to the *MachineInfo returned by the parser.
// ctx should not be modified outside of the scope of the function.
type VerifyFunc func(r *http.Request, p7 *pkcs7.PKCS7, ctx Context, origin Origin) error

// Parser parses the x-apple-aspen-deviceinfo header from requests sent to the configuration_web_url
// as part of the [Authenticating Through Web Views] enrollment process
//
// [Authenticating Through Web Views]: https://developer.apple.com/documentation/devicemanagement/device_assignment/authenticating_through_web_views
type Parser struct {
	verify      bool
	verifyFuncs []VerifyFunc
}

type ParserOption func(p *Parser)

// WithVerify configures the parser to verify the signature against the Apple Root CA if verify is true
func WithVerify(verify bool) ParserOption {
	return func(p *Parser) {
		p.verify = verify
	}
}

// WithVerifyFunc configures the parser with a custom verify function that is run after other verifications take place.
// Multiple VerifyFuncs can be used, and they're executed in the order they're configured.
// If f returns an error, verification fails when Parse is called, and the error is returned.
// See VerifyFunc for more information
func WithVerifyFunc(f VerifyFunc) ParserOption {
	return func(p *Parser) {
		p.verifyFuncs = append(p.verifyFuncs, f)
	}
}

func NewParser(opts ...ParserOption) *Parser {
	p := new(Parser)
	for _, opt := range opts {
		opt(p)
	}
	return p
}

var DefaultParser = NewParser(WithVerify(true))

// verifyPKCS7SHA1RSA performs a manual SHA1withRSA verification, since it's deprecated in Go 1.18.
// If verifyChain is true, the signer certificate and its chain of certificates is verified against Apple's Root CA.
// Also note that the certificate validity time window of the signing cert is not checked, since the cert is expired.
// This follows guidance from Apple on the expired certificate.
func verifyPKCS7SHA1RSA(p7 *pkcs7.PKCS7, verifyChain bool) error {
	if len(p7.Signers) == 0 {
		return fmt.Errorf("not signed")
	}

	// get signing cert
	issuer := p7.Signers[0].IssuerAndSerialNumber
	var signer *x509.Certificate
	for _, cert := range p7.Certificates {
		if bytes.Equal(cert.RawIssuer, issuer.IssuerName.FullBytes) && cert.SerialNumber.Cmp(issuer.SerialNumber) == 0 {
			signer = cert
		}
	}

	// get sha1 hash of content
	hashed := sha1.Sum(p7.Content)

	// verify content signature
	signature := p7.Signers[0].EncryptedDigest
	if err := rsa.VerifyPKCS1v15(signer.PublicKey.(*rsa.PublicKey), crypto.SHA1, hashed[:], signature); err != nil {
		return fmt.Errorf("signature could not be verified: %w", err)
	}

	if !verifyChain {
		return nil
	}

	// verify chain from signer to root
	cert := signer
outer:
	for {
		// check if cert is signed by root
		if bytes.Equal(cert.RawIssuer, AppleRootCert.RawSubject) {
			hashed := sha1.Sum(cert.RawTBSCertificate)
			// check signature
			if err := rsa.VerifyPKCS1v15(AppleRootCert.PublicKey.(*rsa.PublicKey), crypto.SHA1, hashed[:], cert.Signature); err != nil {
				return fmt.Errorf("could not verify root CA signature: %w", err)
			}
			return nil
		}
		for _, c := range p7.Certificates {
			if cert == c {
				continue
			}
			// check if cert is signed by intermediate cert in chain
			if bytes.Equal(cert.RawIssuer, c.RawSubject) {
				// check signature
				hashed := sha1.Sum(cert.RawTBSCertificate)
				if err := rsa.VerifyPKCS1v15(c.PublicKey.(*rsa.PublicKey), crypto.SHA1, hashed[:], cert.Signature); err != nil {
					return fmt.Errorf("could not verify chained certificate signature: %w", err)
				}
				cert = c
				continue outer
			}
		}
		return ErrCertRootNotFound
	}
}

func (p *Parser) parseFromBody(r *http.Request) (*MachineInfo, error) {
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read body: %w", err)
	}

	if len(buf) == 0 {
		return nil, ErrMissingMachineInfo
	}

	return p.parse(r, buf, OriginBody)
}

func (p *Parser) parse(r *http.Request, b []byte, origin Origin) (*MachineInfo, error) {
	p7, err := pkcs7.Parse(b)
	if err != nil {
		return nil, &InvalidHeaderError{Err: fmt.Errorf("could not decode pkcs7: %w", err)}
	}

	// verify signature and certificate chain
	if p.verify {
		if err = verifyPKCS7SHA1RSA(p7, p.verify); err != nil {
			return nil, fmt.Errorf("could not verify signature: %w", err)
		}
	}

	ctx := make(Context)
	for _, f := range p.verifyFuncs {
		if err = f(r, p7, ctx, origin); err != nil {
			return nil, fmt.Errorf("could not verify header: %w", err)
		}
	}

	info := new(MachineInfo)
	if err = plist.Unmarshal(p7.Content, info); err != nil {
		return nil, &InvalidHeaderError{Err: fmt.Errorf("could not decode plist: %w", err)}
	}

	info.Origin = origin
	info.VerifyContext = ctx

	return info, nil
}

// Parse parses the [MachineInfo] from the request, either from the x-apple-aspen-deviceinfo header
// or from the request body, verifies the request as configured by the Parser, and returns the parsed *MachineInfo
//
// [MachineInfo]: https://developer.apple.com/documentation/devicemanagement/machineinfo
func (p *Parser) Parse(r *http.Request) (*MachineInfo, error) {
	hdr := r.Header.Get(DeviceInfoHeader)
	if hdr == "" {
		return p.parseFromBody(r)
	}

	buf, err := base64.StdEncoding.DecodeString(hdr)
	if err != nil {
		return nil, &InvalidHeaderError{Err: fmt.Errorf("could not decode base64: %w", err)}
	}

	return p.parse(r, buf, OriginHeader)
}
