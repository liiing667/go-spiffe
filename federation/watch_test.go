package federation_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakebundleendpoint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchBundle_OnUpdate(t *testing.T) {
	var watcher *fakewatcher
	ca1 := test.NewCA(t, td)
	bundle1 := ca1.Bundle()
	bundle1.SetRefreshHint(time.Second)
	ca2 := test.NewCA(t, td)
	bundle2 := ca2.Bundle()
	bundle2.SetRefreshHint(2 * time.Second)
	bundles := []*spiffebundle.Bundle{bundle1, bundle2}

	be := fakebundleendpoint.New(t, fakebundleendpoint.WithTestBundles(bundle1, bundle2))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	watcher = &fakewatcher{
		t:               t,
		nextRefresh:     time.Second,
		expectedBundles: bundles,
		cancel: func() {
			if watcher.onUpdateCalls > 1 {
				cancel()
			}
		},
		latestBundle: &spiffebundle.Bundle{},
	}

	err := federation.WatchBundle(ctx, td, be.FetchBundleURL(), watcher, federation.WithWebPKIRoots(be.RootCAs()))
	assert.Equal(t, 2, watcher.onUpdateCalls)
	assert.Equal(t, 0, watcher.onErrorCalls)
	assert.Equal(t, context.Canceled, err)
}

func TestWatchBundle_OnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	watcher := &fakewatcher{
		t:            t,
		nextRefresh:  time.Second,
		expectedErr:  `federation: could not GET bundle: Get "?wrong%20url"?: unsupported protocol scheme ""`,
		cancel:       cancel,
		latestBundle: &spiffebundle.Bundle{},
	}

	err := federation.WatchBundle(ctx, td, "wrong url", watcher)
	assert.Equal(t, 0, watcher.onUpdateCalls)
	assert.Equal(t, 1, watcher.onErrorCalls)
	assert.Equal(t, context.Canceled, err)
}

func TestWatchBundle_NilWatcher(t *testing.T) {
	err := federation.WatchBundle(context.Background(), td, "some url", nil)
	assert.EqualError(t, err, "federation: watcher cannot be nil")
}

func TestWatchBundle_FetchBundleCanceled(t *testing.T) {
	be := fakebundleendpoint.New(t)
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	watcher := &fakewatcher{
		t:           t,
		nextRefresh: time.Second,
	}
	cancel()
	err := federation.WatchBundle(ctx, td, be.FetchBundleURL(), watcher, federation.WithWebPKIRoots(be.RootCAs()))
	assert.Equal(t, context.Canceled, err)
}

func TestWatchBundle_RejectsReplayedSequenceNumber(t *testing.T) {
	ca1 := test.NewCA(t, td)
	bundle1 := ca1.Bundle()
	bundle1.SetSequenceNumber(2)

	// The replayed bundle is an older generation that restores a revoked
	// X.509 authority under a lower sequence number.
	ca2 := test.NewCA(t, td)
	replayedBundle := ca2.Bundle()
	replayedBundle.SetSequenceNumber(1)

	be := fakebundleendpoint.New(t, fakebundleendpoint.WithTestBundles(bundle1, replayedBundle))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher := &sequenceWatcher{t: t, cancel: cancel, cancelAfterError: true}

	err := federation.WatchBundle(ctx, td, be.FetchBundleURL(), watcher, federation.WithWebPKIRoots(be.RootCAs()))

	assert.Equal(t, context.Canceled, err)
	assert.Equal(t, 1, watcher.onUpdateCalls)
	assert.Equal(t, bundle1, watcher.latestBundle)
	assert.False(t, watcher.latestBundle.HasX509Authority(ca2.X509Authorities()[0]))
	require.Len(t, watcher.errs, 1)
	assert.Regexp(t, `federation: rejected bundle with sequence number 1 that does not exceed the current sequence number 2`, watcher.errs[0].Error())
}

func TestWatchBundle_RejectsEqualSequenceNumberWithDifferentContents(t *testing.T) {
	ca1 := test.NewCA(t, td)
	bundle1 := ca1.Bundle()
	bundle1.SetSequenceNumber(1)

	ca2 := test.NewCA(t, td)
	conflictingBundle := ca2.Bundle()
	conflictingBundle.SetSequenceNumber(1)

	be := fakebundleendpoint.New(t, fakebundleendpoint.WithTestBundles(bundle1, conflictingBundle))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher := &sequenceWatcher{t: t, cancel: cancel, cancelAfterError: true}

	err := federation.WatchBundle(ctx, td, be.FetchBundleURL(), watcher, federation.WithWebPKIRoots(be.RootCAs()))

	assert.Equal(t, context.Canceled, err)
	assert.Equal(t, 1, watcher.onUpdateCalls)
	assert.Equal(t, bundle1, watcher.latestBundle)
	require.Len(t, watcher.errs, 1)
	assert.Regexp(t, `federation: rejected bundle with sequence number 1 that does not exceed the current sequence number 1`, watcher.errs[0].Error())
}

func TestWatchBundle_AcceptsIncrementingSequenceNumber(t *testing.T) {
	ca1 := test.NewCA(t, td)
	bundle1 := ca1.Bundle()
	bundle1.SetSequenceNumber(1)

	ca2 := test.NewCA(t, td)
	bundle2 := ca2.Bundle()
	bundle2.SetSequenceNumber(2)

	be := fakebundleendpoint.New(t, fakebundleendpoint.WithTestBundles(bundle1, bundle2))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher := &sequenceWatcher{t: t, cancel: cancel, cancelAfterUpdates: 2}

	err := federation.WatchBundle(ctx, td, be.FetchBundleURL(), watcher, federation.WithWebPKIRoots(be.RootCAs()))

	assert.Equal(t, context.Canceled, err)
	assert.Equal(t, 2, watcher.onUpdateCalls)
	assert.Equal(t, bundle2, watcher.latestBundle)
	assert.Empty(t, watcher.errs)
}

func TestWatchBundle_AcceptsBundlesWithoutSequenceNumber(t *testing.T) {
	ca1 := test.NewCA(t, td)
	bundle1 := ca1.Bundle()

	ca2 := test.NewCA(t, td)
	bundle2 := ca2.Bundle()

	be := fakebundleendpoint.New(t, fakebundleendpoint.WithTestBundles(bundle1, bundle2))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher := &sequenceWatcher{t: t, cancel: cancel, cancelAfterUpdates: 2}

	err := federation.WatchBundle(ctx, td, be.FetchBundleURL(), watcher, federation.WithWebPKIRoots(be.RootCAs()))

	assert.Equal(t, context.Canceled, err)
	assert.Equal(t, 2, watcher.onUpdateCalls)
	assert.Equal(t, bundle2, watcher.latestBundle)
	assert.Empty(t, watcher.errs)
}

func TestWatchBundle_KeepsRefreshHintWhenRejectingReplay(t *testing.T) {
	ca1 := test.NewCA(t, td)
	bundle1 := ca1.Bundle()
	bundle1.SetSequenceNumber(2)
	bundle1.SetRefreshHint(time.Hour)

	replayedBundle := spiffebundle.New(td)
	replayedBundle.SetSequenceNumber(1)

	be := fakebundleendpoint.New(t, fakebundleendpoint.WithTestBundles(bundle1, replayedBundle))
	defer be.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher := &sequenceWatcher{t: t, cancel: cancel, cancelAfterError: true}

	err := federation.WatchBundle(ctx, td, be.FetchBundleURL(), watcher, federation.WithWebPKIRoots(be.RootCAs()))

	assert.Equal(t, context.Canceled, err)
	require.Len(t, watcher.refreshHints, 2)
	assert.Equal(t, time.Hour, watcher.refreshHints[0])
	// The rejected replay must not replace the current bundle, so its refresh
	// hint cadence continues to be used for the next poll.
	assert.Equal(t, time.Hour, watcher.refreshHints[1])
}

// sequenceWatcher is a BundleWatcher that records updates and errors and
// cancels the watch after a configured number of updates or the first error.
type sequenceWatcher struct {
	t                  *testing.T
	cancel             context.CancelFunc
	nextRefresh        time.Duration
	cancelAfterUpdates int
	cancelAfterError   bool
	onUpdateCalls      int
	errs               []error
	refreshHints       []time.Duration
	latestBundle       *spiffebundle.Bundle
}

func (w *sequenceWatcher) NextRefresh(refreshHint time.Duration) time.Duration {
	w.refreshHints = append(w.refreshHints, refreshHint)
	if w.nextRefresh == 0 {
		return time.Millisecond
	}
	return w.nextRefresh
}

func (w *sequenceWatcher) OnUpdate(bundle *spiffebundle.Bundle) {
	w.latestBundle = bundle
	w.onUpdateCalls++
	if w.cancelAfterUpdates > 0 && w.onUpdateCalls >= w.cancelAfterUpdates {
		w.cancel()
	}
}

func (w *sequenceWatcher) OnError(err error) {
	w.errs = append(w.errs, err)
	if w.cancelAfterError {
		w.cancel()
	}
}

type fakewatcher struct {
	t               *testing.T
	nextRefresh     time.Duration
	expectedBundles []*spiffebundle.Bundle
	expectedErr     string
	cancel          context.CancelFunc
	onUpdateCalls   int
	onErrorCalls    int
	latestBundle    *spiffebundle.Bundle
}

func (w *fakewatcher) NextRefresh(refreshHint time.Duration) time.Duration {
	if rh, ok := w.latestBundle.RefreshHint(); ok {
		assert.Equal(w.t, rh, refreshHint)
	} else {
		assert.Equal(w.t, time.Duration(0), refreshHint)
	}
	return w.nextRefresh
}

func (w *fakewatcher) OnUpdate(bundle *spiffebundle.Bundle) {
	w.latestBundle = bundle
	assert.Equal(w.t, w.expectedBundles[w.onUpdateCalls], bundle)
	w.onUpdateCalls++
	w.cancel()
}

func (w *fakewatcher) OnError(err error) {
	assert.Regexp(w.t, w.expectedErr, err.Error())
	w.onErrorCalls++
	w.cancel()
}
