package spiffetls_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

// rotationEnv holds two generations of trust material for the test trust
// domain along with the Workload API sources serving them to the server
// and client sides of a connection.
type rotationEnv struct {
	caOld *test.CA
	caNew *test.CA

	serverSVIDOld *x509svid.SVID
	serverSVIDNew *x509svid.SVID
	clientSVIDOld *x509svid.SVID
	clientSVIDNew *x509svid.SVID

	bundleOld     *x509bundle.Bundle
	bundleNew     *x509bundle.Bundle
	bundleOverlap *x509bundle.Bundle

	serverAPI    *fakeworkloadapi.WorkloadAPI
	clientAPI    *fakeworkloadapi.WorkloadAPI
	serverSource *workloadapi.X509Source
	clientSource *workloadapi.X509Source
}

func setupRotationEnv(t *testing.T) (*rotationEnv, func()) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)

	env := &rotationEnv{
		caOld: test.NewCA(t, td),
		caNew: test.NewCA(t, td),
	}

	env.serverSVIDOld = env.caOld.CreateX509SVID(serverID)
	env.serverSVIDNew = env.caNew.CreateX509SVID(serverID)
	env.clientSVIDOld = env.caOld.CreateX509SVID(clientID)
	env.clientSVIDNew = env.caNew.CreateX509SVID(clientID)

	env.bundleOld = env.caOld.X509Bundle()
	env.bundleNew = env.caNew.X509Bundle()

	env.bundleOverlap = x509bundle.New(td)
	for _, authority := range env.caOld.X509Authorities() {
		env.bundleOverlap.AddX509Authority(authority)
	}
	for _, authority := range env.caNew.X509Authorities() {
		env.bundleOverlap.AddX509Authority(authority)
	}

	env.serverAPI = fakeworkloadapi.New(t)
	env.clientAPI = fakeworkloadapi.New(t)

	// Both sides start at the old generation with the overlap bundle.
	setGeneration(env.serverAPI, env.serverSVIDOld, env.bundleOverlap)
	setGeneration(env.clientAPI, env.clientSVIDOld, env.bundleOverlap)

	var err error
	env.serverSource, err = workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(env.serverAPI.Addr())))
	require.NoError(t, err)
	env.clientSource, err = workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(env.clientAPI.Addr())))
	require.NoError(t, err)

	cleanup := func() {
		cancel()
		env.serverSource.Close()
		env.clientSource.Close()
		env.serverAPI.Stop()
		env.clientAPI.Stop()
	}
	return env, cleanup
}

func setGeneration(api *fakeworkloadapi.WorkloadAPI, svid *x509svid.SVID, bundle *x509bundle.Bundle) {
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{svid},
		Bundle: bundle,
	})
}

// updateSource pushes a new generation to the fake Workload API and waits
// until the source has consumed it.
func updateSource(t *testing.T, api *fakeworkloadapi.WorkloadAPI, source *workloadapi.X509Source, svid *x509svid.SVID, bundle *x509bundle.Bundle) {
	setGeneration(api, svid, bundle)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, source.WaitUntilUpdated(ctx))
}

// dialOnce performs one mTLS handshake against the listener using the
// client source and asserts both peer IDs.
func dialOnce(t *testing.T, listener net.Listener, clientSource *workloadapi.X509Source) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := spiffetls.DialWithMode(ctx, "tcp", listener.Addr().String(),
		spiffetls.MTLSClientWithSource(tlsconfig.AuthorizeID(serverID), clientSource))
	require.NoError(t, err)
	defer conn.Close()

	peerID, err := spiffetls.PeerIDFromConn(conn)
	require.NoError(t, err)
	require.Equal(t, serverID, peerID)
}

// acceptOne accepts a single connection, asserts the client peer ID, and
// echoes a byte to complete the handshake data flow.
func acceptOne(t *testing.T, listener net.Listener) {
	conn, err := listener.Accept()
	require.NoError(t, err)
	defer conn.Close()

	peerID, err := spiffetls.PeerIDFromConn(conn)
	require.NoError(t, err)
	require.Equal(t, clientID, peerID)
}

func listenMTLS(t *testing.T, source *workloadapi.X509Source) net.Listener {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := spiffetls.ListenWithMode(ctx, defaultListenProtocol, defaultListenLAddr,
		spiffetls.MTLSServerWithSource(tlsconfig.AuthorizeID(clientID), source))
	require.NoError(t, err)
	return listener
}

// TestMTLSHandshakeRotationOverlap fixtures the rotation overlap window
// end to end: while the bundles trust both the old and new roots, every
// combination of old and new generation SVIDs handshakes successfully.
func TestMTLSHandshakeRotationOverlap(t *testing.T) {
	env, cleanup := setupRotationEnv(t)
	defer cleanup()

	serverSVIDs := map[string]*x509svid.SVID{
		"old": env.serverSVIDOld,
		"new": env.serverSVIDNew,
	}
	clientSVIDs := map[string]*x509svid.SVID{
		"old": env.clientSVIDOld,
		"new": env.clientSVIDNew,
	}

	for _, serverGen := range []string{"old", "new"} {
		for _, clientGen := range []string{"old", "new"} {
			t.Run("server="+serverGen+" client="+clientGen, func(t *testing.T) {
				updateSource(t, env.serverAPI, env.serverSource, serverSVIDs[serverGen], env.bundleOverlap)
				updateSource(t, env.clientAPI, env.clientSource, clientSVIDs[clientGen], env.bundleOverlap)

				listener := listenMTLS(t, env.serverSource)
				defer listener.Close()

				var wg sync.WaitGroup
				defer wg.Wait()
				wg.Add(1)
				go func() {
					defer wg.Done()
					acceptOne(t, listener)
				}()

				dialOnce(t, listener, env.clientSource)
			})
		}
	}
}

// TestMTLSHandshakeRotationCompletes fixtures the end of the rotation:
// once both sides serve only the new generation and the bundles trust only
// the new root, handshakes still succeed.
func TestMTLSHandshakeRotationCompletes(t *testing.T) {
	env, cleanup := setupRotationEnv(t)
	defer cleanup()

	updateSource(t, env.serverAPI, env.serverSource, env.serverSVIDNew, env.bundleNew)
	updateSource(t, env.clientAPI, env.clientSource, env.clientSVIDNew, env.bundleNew)

	listener := listenMTLS(t, env.serverSource)
	defer listener.Close()

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptOne(t, listener)
	}()

	dialOnce(t, listener, env.clientSource)
}

// TestMTLSHandshakeDuringRotation fixtures updates interleaving with
// handshakes: the server source rotates back and forth between generations
// while clients dial. Every handshake binds a single snapshot of the
// source, so every dial succeeds deterministically.
func TestMTLSHandshakeDuringRotation(t *testing.T) {
	env, cleanup := setupRotationEnv(t)
	defer cleanup()

	listener := listenMTLS(t, env.serverSource)
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Rotate the server source between the old and new SVID for the
	// duration of the test. The bundle always trusts both roots.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(stop)
		wg.Wait()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		svids := []*x509svid.SVID{env.serverSVIDNew, env.serverSVIDOld}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			setGeneration(env.serverAPI, svids[i%2], env.bundleOverlap)
			if err := env.serverSource.WaitUntilUpdated(ctx); err != nil {
				return
			}
		}
	}()

	// Accept connections until the dial loop is done.
	acceptDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Complete the handshake before closing so the client side
			// of the connection is not torn down mid-handshake.
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_ = conn.(interface{ Handshake() error }).Handshake()
			conn.Close()
		}
	}()

	const dials = 50
	for range dials {
		dialOnce(t, listener, env.clientSource)
	}

	require.NoError(t, listener.Close())
	<-acceptDone
}

// TestMTLSHandshakeMissingBundle fixtures a client whose source has no
// bundle for the server trust domain: the dial fails deterministically.
func TestMTLSHandshakeMissingBundle(t *testing.T) {
	env, cleanup := setupRotationEnv(t)
	defer cleanup()

	// The client workload lives in another trust domain, so its source has
	// no bundle for the server trust domain.
	otherTD := spiffeid.RequireTrustDomainFromString("other.test")
	otherCA := test.NewCA(t, otherTD)
	otherSVID := otherCA.CreateX509SVID(spiffeid.RequireFromPath(otherTD, "/client"))
	updateSource(t, env.clientAPI, env.clientSource, otherSVID, otherCA.X509Bundle())

	listener := listenMTLS(t, env.serverSource)
	defer listener.Close()

	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		defer conn.Close()
		// Drive the handshake. It fails once the client rejects the
		// server certificate, but the server side of the exchange is
		// needed for the client to observe its verification error.
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_ = conn.(interface{ Handshake() error }).Handshake()
		acceptErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := spiffetls.DialWithMode(ctx, "tcp", listener.Addr().String(),
		spiffetls.MTLSClientWithSource(tlsconfig.AuthorizeID(serverID), env.clientSource))
	require.ErrorContains(t, err, `no X.509 bundle for trust domain "example.org"`)

	require.NoError(t, <-acceptErr)
}
