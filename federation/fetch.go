package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// FetchOption is an option used when dialing the bundle endpoint.
type FetchOption interface {
	apply(*fetchOptions) error
}

type fetchOptions struct {
	transport  *http.Transport
	authMethod authMethod
}

const (
	// maxRedirects is the maximum number of redirects that FetchBundle
	// follows. It matches the default limit used by http.Client.
	maxRedirects = 10
	// maxBundleBytes is the maximum size of a bundle response. Bundles are
	// small JWKS documents, so this bounds the memory consumed when an
	// endpoint streams an unbounded response.
	maxBundleBytes = 10 * 1024 * 1024
)

// errCrossOriginRedirect is returned when a bundle endpoint attempts to
// redirect the request to a different origin (scheme or host) than the
// origin of the requested URL.
var errCrossOriginRedirect = errors.New("redirect to a different origin is not allowed")

// WithSPIFFEAuth authenticates the bundle endpoint with SPIFFE authentication
// using the provided root store. It validates that the endpoint presents the
// expected SPIFFE ID. This option cannot be used in conjuntion with WithWebPKIRoots
// option.
func WithSPIFFEAuth(bundleSource x509bundle.Source, endpointID spiffeid.ID) FetchOption {
	return fetchOption(func(o *fetchOptions) error {
		if o.authMethod != authMethodDefault {
			return wrapFederationErr(errors.New("cannot use both SPIFFE and Web PKI authentication"))
		}
		o.transport.TLSClientConfig = tlsconfig.TLSClientConfig(bundleSource, tlsconfig.AuthorizeID(endpointID))
		o.authMethod = authMethodSPIFFE
		return nil
	})
}

// WithWebPKIRoots authenticates the bundle endpoint using Web PKI authentication
// using the provided X.509 root certificates instead of the system ones. This option
// cannot be used in conjuntion with WithSPIFFEAuth option.
func WithWebPKIRoots(rootCAs *x509.CertPool) FetchOption {
	return fetchOption(func(o *fetchOptions) error {
		if o.authMethod != authMethodDefault {
			return wrapFederationErr(errors.New("cannot use both SPIFFE and Web PKI authentication"))
		}
		o.transport.TLSClientConfig = &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		}
		o.authMethod = authMethodWebPKI
		return nil
	})
}

// FetchBundle retrieves a bundle from a bundle endpoint.
func FetchBundle(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
	opts := fetchOptions{
		transport: http.DefaultTransport.(*http.Transport).Clone(),
	}
	for _, o := range option {
		if err := o.apply(&opts); err != nil {
			return nil, err
		}
	}

	var client = &http.Client{
		Transport:     opts.transport,
		CheckRedirect: checkRedirect,
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, wrapFederationErr(fmt.Errorf("could not create request: %w", err))
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, wrapFederationErr(fmt.Errorf("could not GET bundle: %w", err))
	}
	defer response.Body.Close()

	// Read at most maxBundleBytes plus one byte so that an oversized body can
	// be detected even if the endpoint keeps streaming data indefinitely.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBundleBytes+1))
	if err != nil {
		return nil, wrapFederationErr(fmt.Errorf("could not read bundle: %w", err))
	}
	if int64(len(body)) > maxBundleBytes {
		return nil, wrapFederationErr(fmt.Errorf("bundle exceeds maximum allowed size of %d bytes", maxBundleBytes))
	}

	bundle, err := spiffebundle.Parse(trustDomain, body)
	if err != nil {
		return nil, wrapFederationErr(err)
	}
	return bundle, nil
}

// checkRedirect only allows redirects that stay on the same origin as the
// original bundle endpoint URL. Redirects to a different scheme or host are
// rejected so that a compromised endpoint cannot steer the client into
// fetching untrusted content from another host or over a downgraded
// connection.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}

	original := via[0].URL
	target := req.URL
	if !strings.EqualFold(original.Scheme, target.Scheme) ||
		!strings.EqualFold(original.Hostname(), target.Hostname()) ||
		original.Port() != target.Port() {
		return fmt.Errorf("%w: %q", errCrossOriginRedirect, target.String())
	}
	return nil
}

func wrapFederationErr(err error) error {
	return fmt.Errorf("federation: %w", err)
}

type fetchOption func(*fetchOptions) error

func (fo fetchOption) apply(opts *fetchOptions) error {
	return fo(opts)
}

type authMethod int

const (
	authMethodDefault authMethod = iota
	authMethodSPIFFE
	authMethodWebPKI
)
