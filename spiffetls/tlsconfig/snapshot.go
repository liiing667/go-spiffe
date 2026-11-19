package tlsconfig

import (
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Snapshot is a consistent, immutable view of an X509-SVID and the X.509
// bundles belonging to a single generation of trust material, e.g. as
// returned by workloadapi.X509Source.GetX509Snapshot.
type Snapshot interface {
	x509svid.Source
	x509bundle.Source
}

// BindSnapshots returns an X509-SVID source and X.509 bundle source that
// share a single snapshot obtained from getSnapshot. The snapshot is
// captured lazily on first use and is then retained, so all certificates
// and bundles served through the returned sources belong to the same
// generation of trust material, even if the underlying source is updated
// (or closed) in between.
//
// Binding sources to a single snapshot prevents a TLS handshake from
// presenting an X509-SVID from one rotation generation while verifying the
// peer against bundles from another, which can reject freshly rotated
// identities or verify chains against stale trust.
//
// The returned sources are intended to be scoped to a single TLS handshake:
// callers should bind new sources for each connection (e.g. when building
// per-connection tls.Config values) so that later handshakes observe
// rotated trust material. If getSnapshot fails, the same error is returned
// by both sources.
func BindSnapshots(getSnapshot func() (Snapshot, error)) (x509svid.Source, x509bundle.Source) {
	b := &boundSnapshot{getSnapshot: getSnapshot}
	return b, b
}

type boundSnapshot struct {
	getSnapshot func() (Snapshot, error)

	mtx  sync.Mutex
	snap Snapshot
	err  error
	done bool
}

func (b *boundSnapshot) GetX509SVID() (*x509svid.SVID, error) {
	snap, err := b.snapshot()
	if err != nil {
		return nil, err
	}
	return snap.GetX509SVID()
}

func (b *boundSnapshot) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	snap, err := b.snapshot()
	if err != nil {
		return nil, err
	}
	return snap.GetX509BundleForTrustDomain(trustDomain)
}

func (b *boundSnapshot) snapshot() (Snapshot, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	if !b.done {
		b.snap, b.err = b.getSnapshot()
		b.done = true
	}
	return b.snap, b.err
}
