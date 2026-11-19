package spiffetls

import (
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// sourceSnapshotter adapts a workloadapi.X509Source to a snapshot getter
// suitable for tlsconfig.BindSnapshots.
func sourceSnapshotter(source *workloadapi.X509Source) func() (tlsconfig.Snapshot, error) {
	return func() (tlsconfig.Snapshot, error) {
		return source.GetX509Snapshot()
	}
}
