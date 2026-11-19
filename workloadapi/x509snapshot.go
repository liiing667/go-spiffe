package workloadapi

import (
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// X509Snapshot is a consistent snapshot of the X509-SVID and X.509 bundles
// held by an X509Source at a single point in time. The SVID and bundles are
// guaranteed to belong to the same Workload API update, so they can safely
// be used together, e.g. to bind a single TLS handshake to one generation
// of trust material. The snapshot is immutable, safe for concurrent use,
// and remains valid and unchanged even if the source is updated or closed
// afterwards.
type X509Snapshot struct {
	svid    *x509svid.SVID
	bundles *x509bundle.Set
}

// GetX509SVID returns the X509-SVID captured by the snapshot. It implements
// the x509svid.Source interface.
func (s *X509Snapshot) GetX509SVID() (*x509svid.SVID, error) {
	return s.svid, nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain captured by the snapshot. It implements the x509bundle.Source
// interface.
func (s *X509Snapshot) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundles.GetX509BundleForTrustDomain(trustDomain)
}
