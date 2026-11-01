//! Connection pool using thread-local storage.
//!
//! This is a simple, single-threaded pool stored in thread-local storage.
//! Each thread owns its own pool exclusively, eliminating synchronization
//! overhead entirely.

use std::cell::UnsafeCell;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use std::thread::ThreadId;
use std::time::Duration;

use rustc_hash::FxHashMap;
use tokio::sync::Notify;

mod pool;
mod stats;

use self::pool::SingleThreadPool;
use crate::send_request::SendRequestWrapper;
use crate::types::upstream::ResolvedUpstream;

pub use stats::*;

/// Connection pool key type: (upstream via Arc for cheap cloning, optional client IP for PROXY protocol).
pub type PoolKey = (Arc<ResolvedUpstream>, Option<IpAddr>);

/// Thread-local pool storage.
///
/// Since we use a thread-per-core runtime, each thread gets its own pool.
/// The pools are stored in `UnsafeCell` for interior mutability within the thread.
struct ThreadLocalPools {
    /// TCP connection pool.
    tcp_pool: Rc<SingleThreadPool<PoolKey, Arc<ResolvedUpstream>, SendRequestWrapper>>,
    /// Unix socket pool (unbounded, separate from TCP pools).
    #[cfg(unix)]
    unix_pool: Rc<SingleThreadPool<PoolKey, Arc<ResolvedUpstream>, SendRequestWrapper>>,
    /// Last per-thread TCP capacity that was synced into this TLS pool.
    last_global_limit: usize,
    /// Cached thread ID for this thread, computed once at pool initialization.
    thread_id: ThreadId,
}

// Thread-local storage for connection pools.
thread_local! {
    static TLS_POOLS: UnsafeCell<Option<ThreadLocalPools>> = const { UnsafeCell::new(None) };
}

/// Key that a request parks on while the corresponding limit is reached.
///
/// The first element is the upstream whose local limit blocked the request, or
/// `None` when the global limit did; the second element separates the TCP and
/// Unix-socket pools, which release independently; the third is the worker
/// thread that owns the pool. Pools are thread-local, so capacity freed on one
/// thread can only be used by waiters on that same thread.
type WaiterKey = (Option<Arc<ResolvedUpstream>>, bool, ThreadId);

/// Wake handles for requests waiting on pool capacity.
///
/// `Notify` stores no permits: [`Notify::notify_waiters`] reaches exactly the
/// tasks registered at that instant, and a waiter registers (via
/// `Notified::enable`) before it re-checks the pool. That makes the handoff
/// immune to both failure modes of a token queue - a waiter dropped by the
/// pipeline timeout cannot swallow a wake meant for a live waiter, and a
/// release landing between the pool check and the await is still observed.
static PENDING_WAITERS: LazyLock<RwLock<FxHashMap<WaiterKey, Arc<Notify>>>> =
    LazyLock::new(|| RwLock::new(FxHashMap::default()));

/// Returns the wake handle for `key`, creating it on first use.
///
/// Unused entries are pruned while the map is held for writing; a live waiter
/// keeps a second reference to its handle, so a strong count of one means no
/// task is parked on it.
fn waiter_notify(key: &WaiterKey) -> Arc<Notify> {
    if let Some(notify) = PENDING_WAITERS
        .read()
        .expect("pool waiter lock poisoned")
        .get(key)
    {
        return notify.clone();
    }

    let mut waiters = PENDING_WAITERS.write().expect("pool waiter lock poisoned");
    waiters.retain(|_, notify| Arc::strong_count(notify) > 1);
    waiters
        .entry(key.clone())
        .or_insert_with(|| Arc::new(Notify::new()))
        .clone()
}

/// Concrete pool item type used throughout the proxy.
pub struct PooledConnection {
    inner: Option<self::pool::PoolItem<PoolKey, Arc<ResolvedUpstream>, SendRequestWrapper>>,
}

impl PooledConnection {
    /// Creates a pooled connection from pool item
    const fn new(
        inner: self::pool::PoolItem<PoolKey, Arc<ResolvedUpstream>, SendRequestWrapper>,
    ) -> Self {
        Self { inner: Some(inner) }
    }

    /// Takes the inner value from the item, preventing it from being returned to the pool.
    #[allow(dead_code)]
    #[inline]
    pub fn take(mut self) -> Option<SendRequestWrapper> {
        self.inner
            .take()
            .expect("invalid pooled connection state")
            .take()
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = self::pool::PoolItem<PoolKey, Arc<ResolvedUpstream>, SendRequestWrapper>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.inner
            .as_ref()
            .expect("invalid pooled connection state")
    }
}

impl std::ops::DerefMut for PooledConnection {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
            .as_mut()
            .expect("invalid pooled connection state")
    }
}

impl Drop for PooledConnection {
    #[inline]
    fn drop(&mut self) {
        let empty_slot = self
            .inner
            .as_ref()
            .is_some_and(|item| item.inner().is_none());
        let local_limit_key = self
            .inner
            .as_ref()
            .and_then(|item| item.local_limit_key().cloned());
        let is_unix = self
            .inner
            .as_ref()
            .and_then(|item| item.key())
            .is_some_and(|key| key.0.proxy_unix.is_some());

        if let Some(key) = self.inner.as_ref().and_then(|k| k.key()) {
            let stored = !empty_slot;
            let thread_id = get_tls_thread_id();
            POOL_STATS.record_return(thread_id, &key.0, stored);
        }

        // Drop the item first: its own drop updates the pool accounting.
        drop(self.inner.take());

        // Any released slot frees capacity this thread's waiters can use:
        // both an established connection returned by `PoolItem::drop` (which
        // goes through the generic pool-level return path and cannot notify)
        // and a slot whose connection was never established.
        wake_pool_waiters(&local_limit_key, is_unix);
    }
}

/// Connection pool manager for the reverse proxy.
///
/// This manager coordinates thread-local pools with a global concurrent limit.
/// Each thread owns its own pool instance, eliminating cross-thread contention.
pub struct ConnectionManager {
    /// Pre-thread global limit. Uses `AtomicUsize` for thread-safe interior mutability.
    global_limit_per_thread: AtomicUsize,
    /// Per-upstream local limits, already scaled to the per-thread capacity.
    local_limits: RwLock<FxHashMap<Arc<ResolvedUpstream>, usize>>,
    /// Available parallelism for thread-local pool sizing.
    available_parallelism: usize,
}

impl ConnectionManager {
    /// Creates a new `ConnectionManager` with the given global limit.
    #[inline]
    pub fn with_global_limit(global_limit: usize) -> Self {
        let available_parallelism = std::thread::available_parallelism()
            .ok()
            .map(|p| p.get())
            .unwrap_or(1);
        let per_thread = if available_parallelism > 0 {
            global_limit.div_ceil(available_parallelism)
        } else {
            global_limit
        };
        Self {
            global_limit_per_thread: AtomicUsize::new(per_thread),
            local_limits: RwLock::new(FxHashMap::default()),
            available_parallelism,
        }
    }

    /// Set or update a per-upstream local connection limit.
    #[inline]
    pub fn set_local_limit(&self, upstream: Arc<ResolvedUpstream>, limit: usize) -> usize {
        let mut limits = self
            .local_limits
            .write()
            .expect("local_limits lock poisoned");

        POOL_STATS.record_local_limit(&upstream, limit);
        limits.insert(upstream, limit);
        limit
    }

    /// Get the local limit value for an upstream.
    #[inline]
    pub fn get_local_limit(&self, upstream: Arc<ResolvedUpstream>) -> Option<usize> {
        self.local_limits
            .read()
            .expect("local_limits lock poisoned")
            .get(&upstream)
            .copied()
    }

    /// Updates the global concurrent connections limit.
    ///
    /// Existing thread-local pools observe the new capacity on their next access.
    #[inline]
    pub fn update_global_limit(&self, new_limit: usize) {
        let available_parallelism = self.available_parallelism;
        let per_thread = if available_parallelism > 0 {
            new_limit.div_ceil(available_parallelism)
        } else {
            new_limit
        };

        self.global_limit_per_thread
            .store(per_thread, Ordering::Relaxed);
    }

    /// Whether the given upstream already holds its local connection limit on
    /// this thread.
    #[inline]
    fn at_local_limit(&self, upstream: &Arc<ResolvedUpstream>, local_limit: Option<usize>) -> bool {
        let Some(local_limit) = local_limit else {
            return false;
        };

        TLS_POOLS.with(|c| {
            let ptr = c.get();
            // SAFETY: pool access is confined to the thread that owns it; see the
            // `ThreadLocalPools` documentation.
            let opt = unsafe { &*ptr };
            opt.as_ref().is_some_and(|p| {
                if upstream.proxy_unix.is_some() {
                    #[cfg(unix)]
                    let result = p.unix_pool.is_at_local_limit(upstream, local_limit);
                    #[cfg(not(unix))]
                    let result = false;

                    result
                } else {
                    p.tcp_pool.is_at_local_limit(upstream, local_limit)
                }
            })
        })
    }

    /// Returns the wake handle a request parks on while its limit is reached.
    ///
    /// The key is the limit that blocked the request: the upstream when its
    /// local limit is hit, otherwise the global key. Releases notify by the same
    /// key, so a wake is never spent on a request that the release cannot help.
    #[inline]
    fn waiter(&self, upstream: &Arc<ResolvedUpstream>, local_limit: Option<usize>) -> Arc<Notify> {
        let key = (
            self.at_local_limit(upstream, local_limit)
                .then(|| upstream.clone()),
            upstream.proxy_unix.is_some(),
            std::thread::current().id(),
        );
        waiter_notify(&key)
    }

    /// Pulls a connection from the pool, waiting if necessary for one to become available.
    #[inline]
    pub async fn pull(
        &self,
        upstream: Arc<ResolvedUpstream>,
        client_ip: Option<IpAddr>,
        idle_timeout: Duration,
    ) -> PooledConnection {
        loop {
            let notify = self.waiter(&upstream, None);
            let mut notified = std::pin::pin!(notify.notified_owned());
            // Register before the pool check: a release that lands between the
            // check and the await would otherwise be missed.
            notified.as_mut().enable();

            if let Some(conn) = self.try_pull(upstream.clone(), client_ip, idle_timeout) {
                // Pool not under capacity.
                return conn;
            }

            notified.await;
        }
    }

    /// Pull a connection from the pool with local limit, waiting if necessary for one to become
    /// available.
    ///
    /// Returns `None` if the pool is at capacity (caller should establish a new connection).
    #[inline]
    pub async fn pull_with_local_limit(
        &self,
        upstream: Arc<ResolvedUpstream>,
        client_ip: Option<IpAddr>,
        local_limit: Option<usize>,
        idle_timeout: Duration,
    ) -> PooledConnection {
        loop {
            let notify = self.waiter(&upstream, local_limit);
            let mut notified = std::pin::pin!(notify.notified_owned());
            notified.as_mut().enable();

            if let Some(conn) = self.try_pull_with_local_limit(
                upstream.clone(),
                client_ip,
                local_limit,
                idle_timeout,
            ) {
                // Pool not under capacity.
                return conn;
            }

            notified.await;
        }
    }

    /// Pulls an existing connection from the pool, waiting if necessary for one to become available.
    #[inline]
    pub async fn pull_existing(
        &self,
        upstream: Arc<ResolvedUpstream>,
        client_ip: Option<IpAddr>,
        idle_timeout: Duration,
    ) -> PooledConnection {
        loop {
            let notify = self.waiter(&upstream, None);
            let mut notified = std::pin::pin!(notify.notified_owned());
            notified.as_mut().enable();

            if let Some(conn) = self.try_pull_idle(upstream.clone(), client_ip, None, idle_timeout)
            {
                // Pool not under capacity.
                return conn;
            }

            notified.await;
        }
    }

    /// Pull an existing connection from the pool with local limit, waiting if necessary for
    /// one to become available.
    ///
    /// Returns `None` if the pool is at capacity (caller should establish a new connection).
    #[inline]
    pub async fn pull_existing_with_local_limit(
        &self,
        upstream: Arc<ResolvedUpstream>,
        client_ip: Option<IpAddr>,
        local_limit: Option<usize>,
        idle_timeout: Duration,
    ) -> PooledConnection {
        loop {
            let notify = self.waiter(&upstream, local_limit);
            let mut notified = std::pin::pin!(notify.notified_owned());
            notified.as_mut().enable();

            if let Some(conn) =
                self.try_pull_idle(upstream.clone(), client_ip, local_limit, idle_timeout)
            {
                // Pool not under capacity.
                return conn;
            }

            notified.await;
        }
    }

    /// Runs `f` against this thread's pool, initializing it and syncing the
    /// configured capacity on first use or after a limit change.
    #[inline]
    fn with_tls_pools<R>(&self, f: impl FnOnce(&ThreadLocalPools) -> R) -> R {
        let per_thread = self.global_limit_per_thread.load(Ordering::Relaxed);
        TLS_POOLS.with(|c| {
            let ptr = c.get();
            {
                // SAFETY: pool access is confined to the thread that owns it; see
                // the `ThreadLocalPools` documentation.
                let opt = unsafe { &mut *ptr };
                if opt.is_none() {
                    *opt = Some(ThreadLocalPools {
                        tcp_pool: Rc::new(SingleThreadPool::new(per_thread)),
                        #[cfg(unix)]
                        unix_pool: Rc::new(SingleThreadPool::new_unbounded()),
                        last_global_limit: per_thread,
                        thread_id: std::thread::current().id(),
                    });
                }
                // Here, `opt` is guaranteed to be `Some`, because we just
                // initialized it if it was `None`
                let pools = opt.as_mut().expect("invalid thread-local pool state");
                if pools.last_global_limit != per_thread {
                    pools.tcp_pool.update_capacity(per_thread);
                    pools.last_global_limit = per_thread;
                }
            }

            // SAFETY: the mutable borrow above has ended. `f` may drop a pool
            // item, whose `Drop` re-enters through a shared borrow of the same
            // cell; that is sound because no `&mut` is live here.
            let pools = unsafe { &*ptr }
                .as_ref()
                .expect("invalid thread-local pool state");
            f(pools)
        })
    }

    /// Pull a connection from the pool, returning immediately.
    ///
    /// Returns `None` if the pool is at capacity (caller should establish a new connection).
    #[inline]
    pub fn try_pull(
        &self,
        upstream: Arc<ResolvedUpstream>,
        client_ip: Option<IpAddr>,
        idle_timeout: Duration,
    ) -> Option<PooledConnection> {
        let upstream_for_stats = upstream.clone();
        let key = (upstream, client_ip);

        let result = self.with_tls_pools(|pools| {
            #[cfg(unix)]
            if key.0.proxy_unix.is_some() {
                return pools
                    .unix_pool
                    .pull(key, |c| c.check_ready(Some(idle_timeout)));
            }
            pools
                .tcp_pool
                .pull(key, |c| c.check_ready(Some(idle_timeout)))
        });

        if let Some(result) = &result {
            let thread_id = get_tls_thread_id();
            POOL_STATS.record_pull(thread_id, &upstream_for_stats, result.inner().is_some());
        }

        result.map(PooledConnection::new)
    }

    /// Pull a connection with a local limit applied, returning immediately.
    ///
    /// Returns `None` if the local or global limit is reached.
    #[inline]
    pub fn try_pull_with_local_limit(
        &self,
        upstream: Arc<ResolvedUpstream>,
        client_ip: Option<IpAddr>,
        local_limit: Option<usize>,
        idle_timeout: Duration,
    ) -> Option<PooledConnection> {
        let upstream_for_stats = upstream.clone();
        let upstream_key = upstream;
        let key = (upstream_key.clone(), client_ip);
        let limit = local_limit.map(|limit| (upstream_key, limit));

        let result = self.with_tls_pools(|pools| {
            #[cfg(unix)]
            if key.0.proxy_unix.is_some() {
                return pools
                    .unix_pool
                    .pull_with_local_limit(key, limit, |c| c.check_ready(Some(idle_timeout)));
            }
            pools
                .tcp_pool
                .pull_with_local_limit(key, limit, |c| c.check_ready(Some(idle_timeout)))
        });

        if let Some(result) = &result {
            let thread_id = get_tls_thread_id();
            POOL_STATS.record_pull(thread_id, &upstream_for_stats, result.inner().is_some());
        }

        result.map(PooledConnection::new)
    }

    /// Pull an idle connection from the pool, returning immediately.
    ///
    /// Returns `None` when no stored connection is available. Unlike
    /// [`Self::try_pull`] this never reserves a capacity slot, which is what
    /// the reuse-only callers need: reserving a slot and dropping it again would
    /// release capacity and wake the caller's own waiter, spinning.
    #[inline]
    pub fn try_pull_idle(
        &self,
        upstream: Arc<ResolvedUpstream>,
        client_ip: Option<IpAddr>,
        local_limit: Option<usize>,
        idle_timeout: Duration,
    ) -> Option<PooledConnection> {
        let upstream_for_stats = upstream.clone();
        let upstream_key = upstream;
        let key = (upstream_key.clone(), client_ip);
        let limit = local_limit.map(|limit| (upstream_key, limit));

        let result = self.with_tls_pools(|pools| {
            #[cfg(unix)]
            if key.0.proxy_unix.is_some() {
                return pools
                    .unix_pool
                    .pull_idle_with_local_limit(key, limit, |c| c.check_ready(Some(idle_timeout)));
            }
            pools
                .tcp_pool
                .pull_idle_with_local_limit(key, limit, |c| c.check_ready(Some(idle_timeout)))
        });

        if let Some(result) = &result {
            let thread_id = get_tls_thread_id();
            POOL_STATS.record_pull(thread_id, &upstream_for_stats, result.inner().is_some());
        }

        result.map(PooledConnection::new)
    }
}

/// Return a connection to the thread-local pool.
///
/// This is used by `TrackedBody` to return connections after the response body
/// is fully consumed.
#[inline]
pub fn return_connection_to_pool(
    key: &PoolKey,
    wrapper: SendRequestWrapper,
    local_limit_key: Option<Arc<ResolvedUpstream>>,
    is_unix: bool,
) {
    let stored = TLS_POOLS.with(|tls| {
        // SAFETY: We are strictly single-threaded per core, and no re-entrant
        // mutable borrows occur during connection pulls.
        let guard = unsafe { &*tls.get() };
        let Some(pools) = guard.as_ref() else {
            return false; // Pool not initialized, discard connection
        };

        let stored = if is_unix {
            #[cfg(unix)]
            let stored = pools.unix_pool.return_connection_with_local_limit(
                key.clone(),
                wrapper,
                local_limit_key.clone(),
            );
            #[cfg(not(unix))]
            let stored = false;

            stored
        } else {
            pools.tcp_pool.return_connection_with_local_limit(
                key.clone(),
                wrapper,
                local_limit_key.clone(),
            )
        };

        // Freed capacity may unblock a waiter regardless of storing.
        wake_pool_waiters(&local_limit_key, is_unix);

        stored
    });

    let thread_id = get_tls_thread_id();
    POOL_STATS.record_return(thread_id, &key.0, stored);
}

/// Discard a pulled pool slot without returning a connection.
///
/// Used when a proxied response body was truncated or abandoned mid-stream:
/// an HTTP/1 connection with unread bytes cannot be safely reused, so the
/// slot is released (outstanding is decremented, waiters are woken) and the
/// connection is dropped instead of parked as idle.
#[inline]
pub fn discard_connection_to_pool(
    key: &PoolKey,
    local_limit_key: Option<Arc<ResolvedUpstream>>,
    is_unix: bool,
) {
    TLS_POOLS.with(|tls| {
        // SAFETY: same single-threaded-per-core confinement as the return path.
        let guard = unsafe { &*tls.get() };
        let Some(pools) = guard.as_ref() else {
            return;
        };

        if is_unix {
            #[cfg(unix)]
            pools
                .unix_pool
                .discard_slot_with_local_limit(local_limit_key.as_ref());
        } else {
            pools
                .tcp_pool
                .discard_slot_with_local_limit(local_limit_key.as_ref());
        }

        wake_pool_waiters(&local_limit_key, is_unix);
    });

    let thread_id = get_tls_thread_id();
    POOL_STATS.record_return(thread_id, &key.0, false);
}

/// Wake the waiters that a released slot can help.
///
/// Shared by the return and discard paths: both release an outstanding slot. A
/// release frees capacity in the upstream's own (local-limit) budget and in the
/// global budget, so both keys are notified. Every waiter registered at this
/// instant is woken, which is what keeps a request whose upstream is unaffected
/// by this release from being starved by one that is.
#[inline]
fn wake_pool_waiters(local_limit_key: &Option<Arc<ResolvedUpstream>>, is_unix: bool) {
    let Ok(waiters) = PENDING_WAITERS.read() else {
        return;
    };

    let thread_id = std::thread::current().id();

    if let Some(upstream) = local_limit_key {
        if let Some(notify) = waiters.get(&(Some(upstream.clone()), is_unix, thread_id)) {
            notify.notify_waiters();
        }
    }
    if let Some(notify) = waiters.get(&(None, is_unix, thread_id)) {
        notify.notify_waiters();
    }
}

/// Get the cached thread ID from thread-local pool storage.
///
/// Returns the thread ID that was captured when the pool was first initialized,
/// avoiding repeated `std::thread::current().id()` calls.
#[inline]
fn get_tls_thread_id() -> ThreadId {
    TLS_POOLS.with(|c| {
        let ptr = c.get();
        let opt = unsafe { &*ptr };
        opt.as_ref()
            .map(|p| p.thread_id)
            .unwrap_or_else(|| std::thread::current().id())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    fn test_upstream() -> Arc<ResolvedUpstream> {
        Arc::new(crate::types::upstream::ResolvedUpstream {
            proxy_to: "http://backend".to_string(),
            connect_to: None,
            proxy_unix: None,
            inner: crate::types::upstream::UpstreamInner {
                weight: 1,
                mtls: None,
                priority: 0,
                connection_timeout: None,
                idle_timeout: std::time::Duration::from_secs(60),
                limit: None,
            },
            dns_status: Default::default(),
        })
    }

    fn obtain_test_connection() -> (PooledConnection, ConnectionManager, Arc<ResolvedUpstream>) {
        let upstream = test_upstream();
        let item = crate::send_request::SendRequestWrapper::empty();

        let cm = ConnectionManager::with_global_limit(2);
        let mut conn = cm
            .try_pull(upstream.clone(), None, Duration::from_secs(10))
            .expect("failed to pull connection");

        *conn.inner_mut() = Some(item);

        (conn, cm, upstream)
    }

    fn get_stats_snapshot(upstream: &Arc<ResolvedUpstream>) -> (usize, usize) {
        let snapshot = POOL_STATS.snapshot();
        let snapshot_for_upstream = snapshot
            .iter()
            .find(|p| Arc::ptr_eq(&p.0 .1, upstream))
            .expect("snapshot for tested upstream not found");
        snapshot_for_upstream.1
    }

    #[test]
    fn test_pooled_connection_lifecycle_drop() {
        let (conn, _cm, up) = obtain_test_connection();

        // There should be one outstanding connection that's just pulled
        assert_eq!(get_stats_snapshot(&up), (0, 1)); // stats: (idle, outstanding)

        drop(conn);

        // There should be one idle connection that's just returned to the pool
        assert_eq!(get_stats_snapshot(&up), (1, 0));
    }

    #[test]
    fn test_pooled_connection_lifecycle_returninfo() {
        let (mut conn, _cm, up) = obtain_test_connection();

        // There should be one outstanding connection that's just pulled
        assert_eq!(get_stats_snapshot(&up), (0, 1)); // stats: (idle, outstanding)

        let wrapper = conn.inner_mut().take().expect("invalid connection state");
        let ret_info = crate::send_request::PoolReturnInfo::from_item(conn, wrapper, false);
        drop(ret_info);

        // There should be one idle connection that's just returned to the pool
        assert_eq!(get_stats_snapshot(&up), (1, 0));
    }

    #[test]
    fn test_pooled_connection_lifecycle_returninfo_discard() {
        let (mut conn, _cm, up) = obtain_test_connection();

        // There should be one outstanding connection that's just pulled
        assert_eq!(get_stats_snapshot(&up), (0, 1)); // stats: (idle, outstanding)

        let wrapper = conn.inner_mut().take().expect("invalid connection state");
        let ret_info = crate::send_request::PoolReturnInfo::from_item(conn, wrapper, false);
        ret_info.discard();

        // There should be zero idle connections (the connection is discarded earlier)
        assert_eq!(get_stats_snapshot(&up), (0, 0));
    }

    /// A waiter dropped by its request lifetime (pipeline timeout, client
    /// disconnect) must not swallow the wake that belongs to a live waiter.
    ///
    /// With a queue of cancellation tokens the dropped waiter's token stays
    /// queued and the next release is spent on it, leaving the live waiter
    /// asleep next to a free slot until the pipeline timeout kills it too.
    #[tokio::test]
    async fn test_cancelled_waiter_does_not_starve_live_waiter() {
        let upstream = test_upstream();
        let cm = ConnectionManager::with_global_limit(1);

        let held = cm
            .try_pull(upstream.clone(), None, Duration::from_secs(10))
            .expect("failed to occupy the only pool slot");

        // Park a request, then drop it mid-wait.
        let abandoned = tokio::time::timeout(
            Duration::from_millis(20),
            cm.pull(upstream.clone(), None, Duration::from_secs(10)),
        )
        .await;
        assert!(
            abandoned.is_err(),
            "the pool accepted a second pull; the test setup is wrong"
        );

        // A second request must be woken by the release that follows.
        let mut live = std::pin::pin!(cm.pull(upstream.clone(), None, Duration::from_secs(10)));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), live.as_mut())
                .await
                .is_err(),
            "the live waiter returned while the pool was still saturated"
        );

        drop(held);

        let conn = tokio::time::timeout(Duration::from_secs(5), live.as_mut())
            .await
            .expect("live waiter was starved by the abandoned one");

        drop(conn);
        // The slot was pulled for a connection that was never established, so
        // releasing it leaves no idle connection behind.
        assert_eq!(get_stats_snapshot(&upstream), (0, 0));
    }

    /// The reuse-only pull must not reserve a slot: reserving and releasing one
    /// on every iteration wakes the caller's own waiter, spinning the loop.
    #[test]
    fn test_try_pull_idle_does_not_reserve_a_slot() {
        let upstream = test_upstream();
        let cm = ConnectionManager::with_global_limit(1);

        assert!(
            cm.try_pull_idle(upstream.clone(), None, None, Duration::from_secs(10))
                .is_none(),
            "the pool was expected to hold no idle connection"
        );

        let conn = cm
            .try_pull(upstream, None, Duration::from_secs(10))
            .expect("the idle-only pull consumed the only capacity slot");
        drop(conn);
    }
}
