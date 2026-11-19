package federation_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebundleendpoint"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

var (
	td           = spiffeid.RequireTrustDomainFromString("domain.test")
	localhostIPs = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
)

func TestFetchBundle_WebPKIRoots(t *testing.T) {
	ca := test.NewCA(t, td)
	bundle := ca.Bundle()

	be := fakebundleendpoint.New(t, fakebundleendpoint.WithTestBundles(bundle))
	defer be.Shutdown()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, be.FetchBundleURL(),
		federation.WithWebPKIRoots(be.RootCAs()))
	assert.NoError(t, err)
	assert.Equal(t, fetchedBundle, bundle)
}

func TestFetchBundle_SPIFFEAuth(t *testing.T) {
	id := spiffeid.RequireFromPath(td, "/control-plane/test-bundle-endpoint")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(id, test.WithIPAddresses(localhostIPs...))
	bundle := ca.Bundle()

	be := fakebundleendpoint.New(t,
		fakebundleendpoint.WithTestBundles(bundle),
		fakebundleendpoint.WithSPIFFEAuth(bundle, svid))
	defer be.Shutdown()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, be.FetchBundleURL(),
		federation.WithSPIFFEAuth(bundle, id))
	assert.NoError(t, err)
	assert.Equal(t, fetchedBundle, bundle)
}

func TestFetchBundle_SPIFFEAuth_UnexpectedID(t *testing.T) {
	id := spiffeid.RequireFromPath(td, "/control-plane/test-bundle-endpoint")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(id, test.WithIPAddresses(localhostIPs...))
	bundle := ca.Bundle()

	be := fakebundleendpoint.New(t,
		fakebundleendpoint.WithTestBundles(bundle),
		fakebundleendpoint.WithSPIFFEAuth(bundle, svid))
	defer be.Shutdown()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, be.FetchBundleURL(),
		federation.WithSPIFFEAuth(bundle, spiffeid.RequireFromPath(td, "/other/id")))
	assert.Regexp(t, `federation: could not GET bundle: Get "?`+be.FetchBundleURL()+`"?: unexpected ID "spiffe://domain.test/control-plane/test-bundle-endpoint"`, err.Error())
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_SPIFFEAuthAndWebPKIRoots(t *testing.T) {
	fetchedBundle, err := federation.FetchBundle(context.Background(), td, "url not used",
		federation.WithSPIFFEAuth(nil, spiffeid.ID{}),
		federation.WithWebPKIRoots(nil))
	assert.EqualError(t, err, `federation: cannot use both SPIFFE and Web PKI authentication`)
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_WebPKIRootsAndSPIFFEAuth(t *testing.T) {
	fetchedBundle, err := federation.FetchBundle(context.Background(), td, "url not used",
		federation.WithWebPKIRoots(nil),
		federation.WithSPIFFEAuth(nil, spiffeid.ID{}))
	assert.EqualError(t, err, `federation: cannot use both SPIFFE and Web PKI authentication`)
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_ErrorCreatingRequest(t *testing.T) {
	fetchedBundle, err := federation.FetchBundle(nil, td, "url not used") //nolint
	assert.EqualError(t, err, `federation: could not create request: net/http: nil Context`)
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_ErrorGettingBundle(t *testing.T) {
	be := fakebundleendpoint.New(t)
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fetchedBundle, err := federation.FetchBundle(ctx, td, be.FetchBundleURL(),
		federation.WithWebPKIRoots(be.RootCAs()))
	assert.Regexp(t, `federation: could not GET bundle: Get "?`+be.FetchBundleURL()+`"?: context canceled`, err.Error())
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_ErrorReadingBundleBody(t *testing.T) {
	be := fakebundleendpoint.New(t)
	defer be.Shutdown()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, be.FetchBundleURL(),
		federation.WithWebPKIRoots(be.RootCAs()))
	assert.EqualError(t, err, `federation: spiffebundle: unable to parse JWKS: unexpected end of JSON input`)
	assert.Nil(t, fetchedBundle)
}

func writeTestBundle(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	ca := test.NewCA(t, td)
	data, err := ca.Bundle().Marshal()
	assert.NoError(t, err)
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(data)
	assert.NoError(t, err)
}

func TestFetchBundle_SameOriginRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/test-bundle", http.StatusFound)
	})
	mux.HandleFunc("/test-bundle", func(w http.ResponseWriter, r *http.Request) {
		writeTestBundle(t, w)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, server.URL+"/redirect")
	assert.NoError(t, err)
	assert.NotNil(t, fetchedBundle)
	assert.Equal(t, td, fetchedBundle.TrustDomain())
}

func TestFetchBundle_CrossOriginRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestBundle(t, w)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/test-bundle", http.StatusFound)
	}))
	defer redirector.Close()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, redirector.URL+"/redirect")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "federation: could not GET bundle:")
	assert.Contains(t, err.Error(), "redirect to a different origin is not allowed")
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_SchemeDowngradeRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestBundle(t, w)
	}))
	defer target.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(target.URL, "127.0.0.1", "localhost", 1)+"/test-bundle", http.StatusFound)
	}))
	defer secure.Close()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, secure.URL+"/redirect",
		federation.WithWebPKIRoots(secure.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redirect to a different origin is not allowed")
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_TLSSameOriginRedirect_WebPKI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/test-bundle", http.StatusFound)
	})
	mux.HandleFunc("/test-bundle", func(w http.ResponseWriter, r *http.Request) {
		writeTestBundle(t, w)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, server.URL+"/redirect",
		federation.WithWebPKIRoots(server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs))
	assert.NoError(t, err)
	assert.NotNil(t, fetchedBundle)
	assert.Equal(t, td, fetchedBundle.TrustDomain())
}

func TestFetchBundle_TLSSameOriginRedirect_SPIFFEAuth(t *testing.T) {
	id := spiffeid.RequireFromPath(td, "/control-plane/test-bundle-endpoint")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(id, test.WithIPAddresses(localhostIPs...))
	bundle := ca.Bundle()

	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/test-bundle", http.StatusFound)
	})
	mux.HandleFunc("/test-bundle", func(w http.ResponseWriter, r *http.Request) {
		data, err := bundle.Marshal()
		assert.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(data)
		assert.NoError(t, err)
	})
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{svid.Certificates[0].Raw},
			PrivateKey:  svid.PrivateKey,
		}},
		MinVersion: tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, server.URL+"/redirect",
		federation.WithSPIFFEAuth(bundle, id))
	assert.NoError(t, err)
	assert.Equal(t, bundle, fetchedBundle)
}

func TestFetchBundle_OversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 11*1024*1024))
	}))
	defer server.Close()

	fetchedBundle, err := federation.FetchBundle(context.Background(), td, server.URL+"/bundle")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "federation: bundle exceeds maximum allowed size of")
	assert.Nil(t, fetchedBundle)
}

func TestFetchBundle_UnboundedStreamResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not implement http.Flusher")
		}
		for {
			if _, err := w.Write([]byte("not-a-bundle")); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fetchedBundle, err := federation.FetchBundle(ctx, td, server.URL+"/bundle")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "federation: bundle exceeds maximum allowed size of")
	assert.Nil(t, fetchedBundle)
}
