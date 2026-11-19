package workloadapi_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestX509SourceDoesNotReturnUntilInitialUpdate(t *testing.T) {
	api := fakeworkloadapi.New(t)
	defer api.Stop()

	// Using a timeout here to detect that it doesn't return isn't ideal. Not
	// sure how to deterministically test it otherwise.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	if !assert.EqualError(t, err, context.DeadlineExceeded.Error()) {
		source.Close()
	}
}

func TestX509SourceFailsCallsIfClosed(t *testing.T) {
	// Time out the test after a minute if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)

	// Set the initial X509SVIDResponse with the X509-SVID and key
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))},
		Bundle: ca.X509Bundle(),
	})

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)

	// Close the source
	require.NoError(t, source.Close())

	_, err = source.GetX509SVID()
	require.EqualError(t, err, "x509source: source is closed")

	_, err = source.GetX509BundleForTrustDomain(td)
	require.EqualError(t, err, "x509source: source is closed")
}

func TestX509SourceGetX509Snapshot(t *testing.T) {
	// Time out the test after a minute if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca1 := test.NewCA(t, td)
	ca2 := test.NewCA(t, td)

	svid1 := ca1.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	svid2 := ca2.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))

	// Set the initial X509SVIDResponse (generation 1).
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{svid1},
		Bundle: ca1.X509Bundle(),
	})

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)

	// Take a snapshot of generation 1.
	snap1, err := source.GetX509Snapshot()
	require.NoError(t, err)

	gotSVID, err := snap1.GetX509SVID()
	require.NoError(t, err)
	require.Equal(t, svid1.Certificates, gotSVID.Certificates)

	gotBundle, err := snap1.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, ca1.X509Authorities(), gotBundle.X509Authorities())

	// The snapshot bundles verify the snapshot SVID.
	_, _, err = x509svid.Verify(gotSVID.Certificates, snap1)
	require.NoError(t, err)

	// A trust domain outside the snapshot has no bundle.
	otherTD := spiffeid.RequireTrustDomainFromString("other.test")
	_, err = snap1.GetX509BundleForTrustDomain(otherTD)
	require.EqualError(t, err, `x509bundle: no X.509 bundle for trust domain "other.test"`)

	// Rotate the source to generation 2 (new SVID and new bundle).
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{svid2},
		Bundle: ca2.X509Bundle(),
	})
	require.NoError(t, source.WaitUntilUpdated(ctx))

	snap2, err := source.GetX509Snapshot()
	require.NoError(t, err)

	gotSVID, err = snap2.GetX509SVID()
	require.NoError(t, err)
	require.Equal(t, svid2.Certificates, gotSVID.Certificates)

	gotBundle, err = snap2.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, ca2.X509Authorities(), gotBundle.X509Authorities())

	// The first snapshot is immutable: it still serves generation 1.
	gotSVID, err = snap1.GetX509SVID()
	require.NoError(t, err)
	require.Equal(t, svid1.Certificates, gotSVID.Certificates)

	gotBundle, err = snap1.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, ca1.X509Authorities(), gotBundle.X509Authorities())

	// Snapshots remain usable after the source is closed.
	require.NoError(t, source.Close())

	_, err = source.GetX509Snapshot()
	require.EqualError(t, err, "x509source: source is closed")

	gotSVID, err = snap1.GetX509SVID()
	require.NoError(t, err)
	require.Equal(t, svid1.Certificates, gotSVID.Certificates)

	_, err = snap1.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
}

func TestX509SourceGetX509SnapshotConsistentUnderUpdates(t *testing.T) {
	// Time out the test after three minutes if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")

	// Two generations rooted at different CAs. A snapshot mixing the SVID
	// of one generation with the bundle of the other fails verification,
	// so any inconsistency is detected deterministically.
	ca1 := test.NewCA(t, td)
	svid1 := ca1.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	ca2 := test.NewCA(t, td)
	svid2 := ca2.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))

	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{svid1},
		Bundle: ca1.X509Bundle(),
	})

	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, source.Close())
	}()

	// Fetch snapshots from several goroutines while repeatedly rotating
	// the source between the two generations. Every snapshot must be
	// internally consistent: its SVID must verify against its bundles.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(stop)
		wg.Wait()
	}()
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap, err := source.GetX509Snapshot()
				if !assert.NoError(t, err) {
					return
				}
				svid, err := snap.GetX509SVID()
				if !assert.NoError(t, err) {
					return
				}
				_, _, err = x509svid.Verify(svid.Certificates, snap)
				assert.NoError(t, err)
			}
		}()
	}

	for i := range 200 {
		if i%2 == 0 {
			api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
				SVIDs:  []*x509svid.SVID{svid2},
				Bundle: ca2.X509Bundle(),
			})
		} else {
			api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
				SVIDs:  []*x509svid.SVID{svid1},
				Bundle: ca1.X509Bundle(),
			})
		}
		// Wait for the watcher to consume the update before pushing the
		// next one, so the fake Workload API's response channel (used to
		// fan the update out to the watch stream) isn't hammered faster
		// than its single consumer can drain it.
		require.NoError(t, source.WaitUntilUpdated(ctx))
	}
}

func TestX509SourceGetX509BundleForTrustDomainRace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))

	// Set the initial X509SVIDResponse with the X509-SVID and key.
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{svid},
		Bundle: ca.X509Bundle(),
	})

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, source.Close())
	}()

	// Call GetX509BundleForTrustDomain from several goroutines
	// while repeatedly pushing X509Context updates through the fake
	// Workload API to trigger concurrent access.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(stop)
		wg.Wait()
	}()
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, err := source.GetX509BundleForTrustDomain(td)
				assert.NoError(t, err)
			}
		}()
	}

	for range 200 {
		api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
			SVIDs:  []*x509svid.SVID{svid},
			Bundle: ca.X509Bundle(),
		})
		// Wait for the watcher to consume the update before pushing the
		// next one, so the fake Workload API's response channel (used to
		// fan the update out to the watch stream) isn't hammered faster
		// than its single consumer can drain it.
		require.NoError(t, source.WaitUntilUpdated(ctx))
	}
}

func TestX509SourceGetsUpdates(t *testing.T) {
	// Time out the test after a minute if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	// Set up the CA for a few trust domains
	domain1TD := spiffeid.RequireTrustDomainFromString("domain1.test")
	domain1CA := test.NewCA(t, domain1TD)
	domain1Bundle := domain1CA.X509Bundle()

	domain2TD := spiffeid.RequireTrustDomainFromString("domain2.test")
	domain2CA := test.NewCA(t, domain2TD)
	domain2Bundle := domain2CA.X509Bundle()

	svid1 := domain1CA.CreateX509SVID(spiffeid.RequireFromPath(domain1TD, "/initial"))

	// Set the initial X509SVIDResponse with the X509-SVID and key
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{svid1},
		Bundle: domain1Bundle,
	})

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, source.Close())
	}()

	// Assert that the SVID matches.
	requireX509SVID(t, source, svid1)

	// Assert that the bundle for domain1.test is available but not domain2.test.
	requireX509Bundle(t, source, domain1TD, domain1Bundle)
	requireNoX509Bundle(t, source, domain2TD, `x509bundle: no X.509 bundle for trust domain "domain2.test"`)

	// Swap out a new SVID and send a federated bundle with the next response.
	svid2 := domain1CA.CreateX509SVID(spiffeid.RequireFromPath(domain1TD, "/update"))
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:            []*x509svid.SVID{svid2},
		Bundle:           domain1Bundle,
		FederatedBundles: []*x509bundle.Bundle{domain2Bundle},
	})

	// Wait for the source to be updated with the new response.
	require.NoError(t, source.WaitUntilUpdated(ctx))

	// Assert that the SVID matches.
	requireX509SVID(t, source, svid2)

	// Assert that the bundle for both trust domains are now available.
	requireX509Bundle(t, source, domain1TD, domain1Bundle)
	requireX509Bundle(t, source, domain2TD, domain2Bundle)
}

func TestX509SourceX509SVIDPicker(t *testing.T) {
	// Time out the test after a minute if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	// Set up the CA for a few trust domains
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)

	svid1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload1"))
	svid2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload2"))
	svid3 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload3"))

	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs: []*x509svid.SVID{
			svid1,
			svid2,
			svid3,
		},
		Bundle: ca.X509Bundle(),
	})

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewX509Source(ctx, withAddr(api),
		workloadapi.WithDefaultX509SVIDPicker(func(svids []*x509svid.SVID) *x509svid.SVID {
			for _, svid := range svids {
				if svid.ID == svid2.ID {
					return svid
				}
			}
			assert.Fail(t, "expected X509-SVID was not found")
			return nil
		}))
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, source.Close())
	}()

	// Assert that the right SVID was picked.
	requireX509SVID(t, source, svid2)
}
