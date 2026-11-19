package tlsconfig_test

import (
	"crypto/tls"
	"errors"
	"sync"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snapshotGeneration is one rotation generation of trust material: an SVID
// and the bundle set belonging to the same Workload API update.
type snapshotGeneration struct {
	svid    *x509svid.SVID
	bundles *x509bundle.Set
}

func (g *snapshotGeneration) GetX509SVID() (*x509svid.SVID, error) {
	return g.svid, nil
}

func (g *snapshotGeneration) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return g.bundles.GetX509BundleForTrustDomain(trustDomain)
}

// rotatingSource simulates a source whose trust material rotates. It hands
// out the current generation and can deterministically rotate to the next
// one in between callbacks via the afterSVID hook.
type rotatingSource struct {
	mu          sync.Mutex
	gen         *snapshotGeneration
	snapshotErr error
	snapshots   int
	afterSVID   func()
}

func (s *rotatingSource) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.Lock()
	gen := s.gen
	s.mu.Unlock()

	svid, err := gen.GetX509SVID()
	if s.afterSVID != nil {
		s.afterSVID()
	}
	return svid, err
}

func (s *rotatingSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.Lock()
	gen := s.gen
	s.mu.Unlock()

	return gen.GetX509BundleForTrustDomain(trustDomain)
}

func (s *rotatingSource) GetX509Snapshot() (tlsconfig.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshots++
	if s.snapshotErr != nil {
		return nil, s.snapshotErr
	}
	return s.gen, nil
}

func (s *rotatingSource) rotateTo(gen *snapshotGeneration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen = gen
}

func (s *rotatingSource) snapshotCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshots
}

// rotationFixture holds two generations of trust material for one trust
// domain: the old generation rooted at one CA, the new generation rooted
// at another.
type rotationFixture struct {
	td       spiffeid.TrustDomain
	serverID spiffeid.ID
	clientID spiffeid.ID

	serverSVIDOld *x509svid.SVID
	serverSVIDNew *x509svid.SVID
	clientSVIDOld *x509svid.SVID
	clientSVIDNew *x509svid.SVID

	bundleOld     *x509bundle.Bundle
	bundleNew     *x509bundle.Bundle
	bundleOverlap *x509bundle.Bundle
}

func newRotationFixture(t *testing.T) *rotationFixture {
	td := spiffeid.RequireTrustDomainFromString("domain1.test")
	caOld := test.NewCA(t, td)
	caNew := test.NewCA(t, td)

	serverID := spiffeid.RequireFromPath(td, "/server")
	clientID := spiffeid.RequireFromPath(td, "/client")

	overlap := x509bundle.New(td)
	for _, authority := range caOld.X509Authorities() {
		overlap.AddX509Authority(authority)
	}
	for _, authority := range caNew.X509Authorities() {
		overlap.AddX509Authority(authority)
	}

	return &rotationFixture{
		td:            td,
		serverID:      serverID,
		clientID:      clientID,
		serverSVIDOld: caOld.CreateX509SVID(serverID),
		serverSVIDNew: caNew.CreateX509SVID(serverID),
		clientSVIDOld: caOld.CreateX509SVID(clientID),
		clientSVIDNew: caNew.CreateX509SVID(clientID),
		bundleOld:     caOld.X509Bundle(),
		bundleNew:     caNew.X509Bundle(),
		bundleOverlap: overlap,
	}
}

func (f *rotationFixture) serverGen(svid *x509svid.SVID, bundle *x509bundle.Bundle) *snapshotGeneration {
	return &snapshotGeneration{
		svid:    svid,
		bundles: x509bundle.NewSet(bundle),
	}
}

func TestBindSnapshotsUsesSingleSnapshot(t *testing.T) {
	f := newRotationFixture(t)

	gen1 := f.serverGen(f.serverSVIDOld, f.bundleOld)
	gen2 := f.serverGen(f.serverSVIDNew, f.bundleNew)

	source := &rotatingSource{gen: gen1}
	svidSource, bundleSource := tlsconfig.BindSnapshots(source.GetX509Snapshot)

	// Rotate the live source before any use; the first use captures gen2.
	source.rotateTo(gen2)

	svid, err := svidSource.GetX509SVID()
	require.NoError(t, err)
	assert.Equal(t, f.serverSVIDNew.Certificates, svid.Certificates)

	// Rotate again in between the SVID and bundle reads. The bound sources
	// must still serve the captured generation.
	source.rotateTo(gen1)

	bundle, err := bundleSource.GetX509BundleForTrustDomain(f.td)
	require.NoError(t, err)
	assert.Equal(t, f.bundleNew.X509Authorities(), bundle.X509Authorities())

	// The snapshot is captured exactly once.
	assert.Equal(t, 1, source.snapshotCalls())

	// A freshly bound pair observes the latest generation.
	svidSource, bundleSource = tlsconfig.BindSnapshots(source.GetX509Snapshot)
	svid, err = svidSource.GetX509SVID()
	require.NoError(t, err)
	assert.Equal(t, f.serverSVIDOld.Certificates, svid.Certificates)
	bundle, err = bundleSource.GetX509BundleForTrustDomain(f.td)
	require.NoError(t, err)
	assert.Equal(t, f.bundleOld.X509Authorities(), bundle.X509Authorities())
}

func TestBindSnapshotsError(t *testing.T) {
	f := newRotationFixture(t)

	snapshotErr := errors.New("x509source: source is closed")
	source := &rotatingSource{
		gen:         f.serverGen(f.serverSVIDOld, f.bundleOld),
		snapshotErr: snapshotErr,
	}

	svidSource, bundleSource := tlsconfig.BindSnapshots(source.GetX509Snapshot)

	_, err := svidSource.GetX509SVID()
	require.ErrorIs(t, err, snapshotErr)

	_, err = bundleSource.GetX509BundleForTrustDomain(f.td)
	require.ErrorIs(t, err, snapshotErr)

	// The failure is captured once and reported consistently.
	assert.Equal(t, 1, source.snapshotCalls())
}

// TestBoundSnapshotMTLSHandshakeInterleavedUpdate fixtures a rotation that
// lands in the middle of a handshake, between the SVID read and the bundle
// read. Unbound sources observe a mix of generations and reject a valid
// peer; bound sources pin the handshake to a single generation and succeed.
func TestBoundSnapshotMTLSHandshakeInterleavedUpdate(t *testing.T) {
	f := newRotationFixture(t)

	gen1 := f.serverGen(f.serverSVIDOld, f.bundleOld)
	gen2 := f.serverGen(f.serverSVIDNew, f.bundleNew)

	newSource := func() *rotatingSource {
		source := &rotatingSource{gen: gen1}
		// The rotation to gen2 lands right after the server SVID is read,
		// i.e. in the middle of the handshake.
		source.afterSVID = func() {
			source.rotateTo(gen2)
		}
		return source
	}

	newClientConfig := func() *tls.Config {
		return tlsconfig.MTLSClientConfig(f.clientSVIDOld, x509bundle.NewSet(f.bundleOld), tlsconfig.AuthorizeID(f.serverID))
	}

	t.Run("unbound sources mix generations and reject the client", func(t *testing.T) {
		source := newSource()
		serverConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeID(f.clientID))

		// The server presents the gen1 SVID but verifies the client against
		// the gen2 bundle, which no longer trusts the gen1 root.
		testConnection(t, serverConfig, newClientConfig(),
			"x509svid: could not verify leaf certificate: x509: certificate signed by unknown authority",
			"remote error: tls: bad certificate")
	})

	t.Run("bound sources pin a single generation and succeed", func(t *testing.T) {
		source := newSource()
		svidSource, bundleSource := tlsconfig.BindSnapshots(source.GetX509Snapshot)
		serverConfig := tlsconfig.MTLSServerConfig(svidSource, bundleSource, tlsconfig.AuthorizeID(f.clientID))

		testConnection(t, serverConfig, newClientConfig(), "", "")

		// The whole handshake used a single snapshot of the source.
		assert.Equal(t, 1, source.snapshotCalls())
	})
}

// TestBoundSnapshotMTLSHandshakeMissingBundle fixtures a snapshot that does
// not contain a bundle for the peer trust domain. Verification fails
// deterministically.
func TestBoundSnapshotMTLSHandshakeMissingBundle(t *testing.T) {
	f := newRotationFixture(t)

	// The snapshot carries the server SVID but no bundle for the trust
	// domain at all.
	gen := &snapshotGeneration{
		svid:    f.serverSVIDOld,
		bundles: x509bundle.NewSet(),
	}
	source := &rotatingSource{gen: gen}
	svidSource, bundleSource := tlsconfig.BindSnapshots(source.GetX509Snapshot)

	serverConfig := tlsconfig.MTLSServerConfig(svidSource, bundleSource, tlsconfig.AuthorizeID(f.clientID))
	clientConfig := tlsconfig.MTLSClientConfig(f.clientSVIDOld, x509bundle.NewSet(f.bundleOld), tlsconfig.AuthorizeID(f.serverID))

	testConnection(t, serverConfig, clientConfig,
		`x509svid: could not get X509 bundle: x509bundle: no X.509 bundle for trust domain "domain1.test"`,
		"remote error: tls: bad certificate")
}

// TestBoundSnapshotMTLSHandshakeRotationOverlap fixtures the rotation
// overlap window: bundles trust both the old and new roots, so handshakes
// succeed for every combination of old and new generation SVIDs.
func TestBoundSnapshotMTLSHandshakeRotationOverlap(t *testing.T) {
	f := newRotationFixture(t)

	overlapSet := x509bundle.NewSet(f.bundleOverlap)

	serverSVIDs := map[string]*x509svid.SVID{
		"old": f.serverSVIDOld,
		"new": f.serverSVIDNew,
	}
	clientSVIDs := map[string]*x509svid.SVID{
		"old": f.clientSVIDOld,
		"new": f.clientSVIDNew,
	}

	for _, serverGen := range []string{"old", "new"} {
		for _, clientGen := range []string{"old", "new"} {
			t.Run("server="+serverGen+" client="+clientGen, func(t *testing.T) {
				source := &rotatingSource{
					gen: f.serverGen(serverSVIDs[serverGen], f.bundleOverlap),
				}
				svidSource, bundleSource := tlsconfig.BindSnapshots(source.GetX509Snapshot)

				serverConfig := tlsconfig.MTLSServerConfig(svidSource, bundleSource, tlsconfig.AuthorizeID(f.clientID))
				clientConfig := tlsconfig.MTLSClientConfig(clientSVIDs[clientGen], overlapSet, tlsconfig.AuthorizeID(f.serverID))

				testConnection(t, serverConfig, clientConfig, "", "")
			})
		}
	}
}
