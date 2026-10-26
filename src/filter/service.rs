//! The `SecblitzFilter` service: loopback listener, list refresh, status for the app.
//! `serve` is portable and tested on any host; service control lives in `scm.rs`.

use anyhow::{Context, Result};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::activity::{self, Writes};
use super::adapters;
use super::config::{self, ErrorCode, RecentList, State, Status};
use super::fetch;
use super::gaps;
use super::lists::{self, SOURCES};
use super::matcher::{Filter, KINDS};
use super::server::{self, upstream_addrs, BindError, Shared};
use super::store;

const TICK: Duration = Duration::from_millis(200);
pub const CONFIG_EVERY: Duration = Duration::from_secs(2);
const UPSTREAM_EVERY: Duration = Duration::from_secs(30);
const UPSTREAM_RETRY_MIN: Duration = Duration::from_secs(5);
const BIND_RETRY: Duration = Duration::from_secs(30);
const REFRESH_EVERY: Duration = Duration::from_secs(60 * 60);
const STATUS_EVERY: Duration = Duration::from_secs(10);
const GAPS_EVERY: Duration = Duration::from_secs(60);

pub struct Paths {
    pub config: PathBuf,
    pub status: PathBuf,
    pub lists: PathBuf,
    pub recent: PathBuf,
    pub stats: PathBuf,
    pub detail: PathBuf,
}

impl Paths {
    pub fn production() -> Result<Self> {
        Ok(Paths {
            config: config::config_path()?,
            status: config::status_path()?,
            lists: config::lists_dir()?,
            recent: config::recent_path()?,
            stats: config::stats_path()?,
            detail: config::stats_detail_path()?,
        })
    }
}

/// The only addresses the filter ever listens on.
pub fn listen_addresses() -> Vec<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        vec![SocketAddr::new(crate::linux::web::LISTEN.into(), 53)]
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![
            SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 53),
            SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 53),
        ]
    }
}

#[derive(Default)]
struct Meta {
    state: State,
    domains: [u64; KINDS],
    lists_updated: Option<u64>,
    refresh_error: Option<ErrorCode>,
}

type SharedMeta = Arc<Mutex<Meta>>;

fn lock(meta: &SharedMeta) -> MutexGuard<'_, Meta> {
    meta.lock().unwrap_or_else(PoisonError::into_inner)
}

fn rebuild_from_disk(paths: &Paths, shared: &Shared, meta: &SharedMeta) {
    let lists = fetch::load_all(&paths.lists);
    let candidate = fetch::rebuild(&lists);
    drop(lists);
    let newest = SOURCES
        .iter()
        .filter_map(|s| fetch::stored_at(&paths.lists, s.id))
        .max();
    let mut m = lock(meta);
    m.lists_updated = newest;
    match candidate {
        None => {
            if m.state != State::Ready {
                m.state = State::NoLists;
            }
        }
        Some(candidate) => {
            let previous =
                Arc::clone(&shared.filter.read().unwrap_or_else(PoisonError::into_inner));
            match fetch::accept(candidate, &previous) {
                Ok(filter) => {
                    let counts = lists::counts(&filter);
                    m.domains = counts.map(|n| n as u64);
                    *shared
                        .filter
                        .write()
                        .unwrap_or_else(PoisonError::into_inner) = Arc::new(filter);
                    m.state = State::Ready;
                    if m.refresh_error == Some(ErrorCode::ListInvalid) {
                        m.refresh_error = None;
                    }
                }
                Err(_) => m.refresh_error = Some(ErrorCode::ListInvalid),
            }
        }
    }
}

fn refresh(paths: &Paths, shared: &Shared, meta: &SharedMeta) {
    let Ok(client) = fetch::client() else {
        lock(meta).refresh_error = Some(ErrorCode::DownloadFailed);
        return;
    };
    let mut error = None;
    let mut stored = false;
    let config = shared
        .config
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    for source in &SOURCES {
        if !source.role.wanted(&config) {
            continue;
        }
        let last = fetch::stored_at(&paths.lists, source.id);
        if !fetch::due(source, last, server::unix_now()) {
            continue;
        }
        let text = match fetch::download(&client, source) {
            Ok(text) => text,
            Err(_) => {
                error = Some(ErrorCode::DownloadFailed);
                continue;
            }
        };
        if fetch::usable_entries(source, &text) == 0
            || fetch::store(&paths.lists, source.id, &text).is_err()
        {
            error = Some(ErrorCode::ListInvalid);
            continue;
        }
        drop(text);
        stored = true;
        // The first lists to arrive start protecting at once.
        if lock(meta).state != State::Ready {
            rebuild_from_disk(paths, shared, meta);
        }
    }
    if stored {
        rebuild_from_disk(paths, shared, meta);
    }
    let mut m = lock(meta);
    // A broken stored set (ListInvalid from the rebuild) stays reported.
    if error.is_some() || m.refresh_error != Some(ErrorCode::ListInvalid) {
        m.refresh_error = error;
    }
}

struct Background {
    busy: Arc<AtomicBool>,
    paths: Arc<Paths>,
    shared: Arc<Shared>,
    meta: SharedMeta,
}

impl Background {
    /// False when a refresh is already running and nothing was started.
    fn start(&self, download: bool, load_first: bool) -> bool {
        if self.busy.swap(true, Ordering::AcqRel) {
            return false;
        }
        let (busy, paths, shared, meta) = (
            Arc::clone(&self.busy),
            Arc::clone(&self.paths),
            Arc::clone(&self.shared),
            Arc::clone(&self.meta),
        );
        let spawned = thread::Builder::new()
            .name("secblitz-filter-lists".into())
            .spawn(move || {
                if load_first {
                    rebuild_from_disk(&paths, &shared, &meta);
                }
                // No downloads while Windows says the connection is metered.
                if download && !adapters::metered() {
                    refresh(&paths, &shared, &meta);
                }
                busy.store(false, Ordering::Release);
            });
        if spawned.is_err() {
            self.busy.store(false, Ordering::Release);
        }
        true
    }
}

struct Every {
    period: Duration,
    next: Instant,
}

impl Every {
    fn new(period: Duration) -> Self {
        Every {
            period,
            next: Instant::now(),
        }
    }

    fn due(&mut self) -> bool {
        let now = Instant::now();
        if now < self.next {
            return false;
        }
        self.next = now + self.period;
        true
    }

    fn reset(&mut self) {
        self.next = Instant::now() + self.period;
    }
}

/// Counts and the last dangerous block time go out only every 10 s. A new block notice goes out
/// on the next tick, because the tray shows its warning from it.
fn same_apart_from_counts(a: &Status, b: &Status) -> bool {
    let strip = |s: &Status| Status {
        written_at: 0,
        blocked: [0; KINDS],
        day: 0,
        dangerous_at: None,
        ..s.clone()
    };
    strip(a) == strip(b)
}

fn save_json<T: serde::Serialize>(path: &std::path::Path, value: &T) {
    if let Ok(bytes) = serde_json::to_vec(value) {
        let _ = store::write_private(path, &bytes);
    }
}

fn write_activity(paths: &Paths, writes: Writes) {
    if let Some(recent) = &writes.recent {
        save_json(&paths.recent, recent);
    }
    if let Some(stats) = &writes.stats {
        save_json(&paths.stats, stats);
    }
    if let Some(detail) = &writes.detail {
        save_json(&paths.detail, detail);
    }
}

struct Listeners {
    threads: Vec<JoinHandle<()>>,
}

fn listen(
    addrs: &[SocketAddr],
    shared: &Arc<Shared>,
    stop: &Arc<AtomicBool>,
) -> Result<Listeners, BindError> {
    let (udp, tcp) = server::bind(addrs)?;
    let mut threads = Vec::new();
    for socket in udp {
        let (shared, stop) = (Arc::clone(shared), Arc::clone(stop));
        threads.push(thread::spawn(move || {
            server::serve_udp(socket, shared, stop)
        }));
    }
    for listener in tcp {
        let (shared, stop) = (Arc::clone(shared), Arc::clone(stop));
        threads.push(thread::spawn(move || {
            server::serve_tcp(listener, shared, stop)
        }));
    }
    Ok(Listeners { threads })
}

/// The service's main loop. Returns after `stop` is set (within about a
/// second). `download` is false in tests.
pub fn serve(
    paths: Paths,
    addrs: &[SocketAddr],
    download: bool,
    stop: &Arc<AtomicBool>,
) -> Result<()> {
    serve_with(paths, addrs, download, stop, &|| {})
}

/// Like [`serve`]. `ready` runs once, after the first status that says the filter is listening has been saved.
pub fn serve_with(
    paths: Paths,
    addrs: &[SocketAddr],
    download: bool,
    stop: &Arc<AtomicBool>,
    ready: &dyn Fn(),
) -> Result<()> {
    // Best effort: the installer normally created it already.
    let _ = fs::create_dir_all(&paths.lists);
    let paths = Arc::new(paths);
    let mut network = adapters::upstream_servers();
    let mut config = config::load_config(&paths.config);
    // Fast Startup keeps uptime counting, so a service start is the end of "until restart".
    if let Some(ended) = config.after_service_start() {
        if config::save_config(&paths.config, &ended).is_ok() {
            config = ended;
        }
    }
    let shared = Arc::new(Shared::new(
        Filter::empty(),
        config,
        upstream_addrs(&network),
    ));
    shared.set_local_suffixes(adapters::dns_suffixes());
    if let Some(previous) = config::load_status(&paths.status) {
        shared
            .stats
            .resume(previous.day, previous.blocked, server::unix_now());
        shared.stats.resume_dangerous_at(previous.dangerous_at);
        shared.stats.resume_notice(previous.notice);
    }
    shared
        .activity
        .resume(activity::load_detail(&paths.detail), server::unix_now());
    if paths.recent.exists() {
        save_json(&paths.recent, &RecentList::default());
    }
    let meta: SharedMeta = Arc::new(Mutex::new(Meta::default()));
    let background = Background {
        busy: Arc::new(AtomicBool::new(false)),
        paths: Arc::clone(&paths),
        shared: Arc::clone(&shared),
        meta: Arc::clone(&meta),
    };
    background.start(download, true);

    let mut listeners: Option<Listeners> = None;
    let mut port_in_use = false;
    let mut bind_timer = Every::new(BIND_RETRY);
    let mut config_timer = Every::new(CONFIG_EVERY);
    let mut upstream_timer = Every::new(UPSTREAM_EVERY);
    let mut refresh_timer = Every::new(REFRESH_EVERY);
    let mut status_timer = Every::new(STATUS_EVERY);
    refresh_timer.reset();
    let mut last_status: Option<Status> = None;
    let mut upstream_checked = Instant::now();
    let mut lists_wanted = false;
    let mut announced = false;
    let mut gaps_timer = Every::new(GAPS_EVERY);
    let mut gaps = gaps::check();
    gaps_timer.reset();

    while !stop.load(Ordering::Acquire) {
        if listeners.is_none() && bind_timer.due() {
            match listen(addrs, &shared, stop) {
                Ok(l) => {
                    listeners = Some(l);
                    port_in_use = false;
                }
                Err(e) => port_in_use = e == BindError::PortInUse,
            }
        }
        if config_timer.due() {
            let fresh = config::load_config(&paths.config);
            {
                let before = shared.config.read().unwrap_or_else(PoisonError::into_inner);
                lists_wanted |= (fresh.adult && !before.adult)
                    || (fresh.gambling && !before.gambling)
                    || (fresh.scam && !before.scam)
                    || (fresh.popups && !before.popups);
            }
            let fresh = fresh.without_expired(server::unix_now()).unwrap_or(fresh);
            shared.set_config(fresh);
        }
        if lists_wanted && download && background.start(true, false) {
            lists_wanted = false;
        }
        let failed = shared.upstream_failed.load(Ordering::Acquire)
            && upstream_checked.elapsed() >= UPSTREAM_RETRY_MIN;
        if upstream_timer.due() || failed {
            shared.upstream_failed.store(false, Ordering::Release);
            network = adapters::upstream_servers();
            *shared
                .upstream
                .write()
                .unwrap_or_else(PoisonError::into_inner) = upstream_addrs(&network);
            shared.set_local_suffixes(adapters::dns_suffixes());
            upstream_checked = Instant::now();
            upstream_timer.reset();
        }
        if gaps_timer.due() {
            gaps = gaps::check();
        }
        if download && refresh_timer.due() {
            background.start(true, false);
        }

        let now = server::unix_now();
        let (day, blocked) = shared.stats.snapshot(now);
        let paused = shared
            .config
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .paused(now);
        if !paused {
            write_activity(&paths, shared.activity.take_writes(now, false));
        }
        let status = {
            let m = lock(&meta);
            let last_error = if port_in_use {
                Some(ErrorCode::PortInUse)
            } else if m.refresh_error.is_some() {
                m.refresh_error
            } else if network.is_empty() {
                Some(ErrorCode::NoUpstream)
            } else {
                None
            };
            Status {
                listening: listeners.is_some(),
                state: m.state,
                lists_updated: m.lists_updated,
                day,
                blocked,
                domains: m.domains,
                last_error,
                written_at: now,
                lookups: shared.lookups(now),
                dangerous_at: shared.stats.dangerous_at(),
                gaps: gaps.clone(),
                notice: shared.stats.notice(),
            }
        };
        let changed = last_status
            .as_ref()
            .is_none_or(|last| !same_apart_from_counts(last, &status));
        // A write that failed is tried again on the next tick, so a block notice is not late.
        if (changed || status_timer.due()) && config::save_status(&paths.status, &status).is_ok() {
            status_timer.reset();
            if status.listening && !announced {
                announced = true;
                ready();
            }
            last_status = Some(status);
        }
        thread::sleep(TICK);
    }

    // Tell the app right away that nothing is listening any more.
    let mut status = last_status.unwrap_or_default();
    status.listening = false;
    status.written_at = server::unix_now();
    let _ = config::save_status(&paths.status, &status);
    let mut last = shared.activity.take_writes(server::unix_now(), true);
    last.recent = paths.recent.exists().then(RecentList::default);
    write_activity(&paths, last);
    if let Some(l) = listeners {
        for t in l.threads {
            let _ = t.join();
        }
    }
    Ok(())
}

pub fn run() -> Result<()> {
    #[cfg(windows)]
    {
        scm::run()
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux::web_service::run()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        anyhow::bail!("The web protection service is not supported on this system")
    }
}

#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
pub(crate) fn run_production(stop: &Arc<AtomicBool>, ready: &dyn Fn()) -> Result<()> {
    let paths = Paths::production().context("Cannot find the filter folder")?;
    serve_with(paths, &listen_addresses(), true, stop, ready)
}

#[cfg(windows)]
mod scm {
    use super::*;
    use std::ffi::OsString;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
        service_dispatcher,
    };

    define_windows_service!(ffi_main, service_main);

    pub fn run() -> Result<()> {
        service_dispatcher::start(super::super::SERVICE_NAME, ffi_main)?;
        Ok(())
    }

    fn set_status(
        handle: &ServiceStatusHandle,
        state: ServiceState,
        checkpoint: u32,
        failed: bool,
    ) {
        let pending = matches!(
            state,
            ServiceState::StartPending | ServiceState::StopPending
        );
        let _ = handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: if failed {
                ServiceExitCode::ServiceSpecific(1)
            } else {
                ServiceExitCode::Win32(0)
            },
            checkpoint,
            wait_hint: if pending {
                Duration::from_secs(10)
            } else {
                Duration::ZERO
            },
            process_id: None,
        });
    }

    fn service_main(_: Vec<OsString>) {
        let stop = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&stop);
        let handle =
            match service_control_handler::register(super::super::SERVICE_NAME, move |control| {
                match control {
                    ServiceControl::Stop | ServiceControl::Shutdown => {
                        signal.store(true, Ordering::Release);
                        ServiceControlHandlerResult::NoError
                    }
                    ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            }) {
                Ok(h) => h,
                Err(_) => return,
            };
        set_status(&handle, ServiceState::StartPending, 1, false);
        // Running at once: the loop retries binding, so a taken port is
        // reported in the status file instead of failing the start.
        set_status(&handle, ServiceState::Running, 0, false);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_production(&stop, &|| {})
        }));
        let failed = !matches!(outcome, Ok(Ok(())));
        set_status(&handle, ServiceState::StopPending, 1, false);
        set_status(&handle, ServiceState::Stopped, 0, failed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::config::load_status;
    use std::net::{Ipv4Addr, UdpSocket};

    fn paths(dir: &std::path::Path) -> Paths {
        Paths {
            config: dir.join("config.json"),
            status: dir.join("status.json"),
            lists: dir.join("lists"),
            recent: dir.join("recent.json"),
            stats: dir.join("stats.json"),
            detail: dir.join("stats-detail.json"),
        }
    }

    fn wait_for<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
        for _ in 0..100 {
            if let Some(v) = probe() {
                return v;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("timed out waiting for {what}");
    }

    // The service binds UDP and TCP on the same port, and Windows reserves
    // TCP port ranges that a free UDP port can fall into.
    fn free_port() -> u16 {
        loop {
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = tcp.local_addr().unwrap().port();
            if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
                return port;
            }
        }
    }

    #[test]
    fn rebuild_from_disk_swaps_in_the_filter() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let shared = Shared::new(Filter::empty(), config::Config::default(), vec![]);
        let meta: SharedMeta = Arc::new(Mutex::new(Meta::default()));

        rebuild_from_disk(&p, &shared, &meta);
        assert_eq!(lock(&meta).state, State::NoLists);

        fetch::store(&p.lists, "adguard-dns", "||ads.example^\n").unwrap();
        fetch::store(
            &p.lists,
            "hagezi-tif",
            "||evil.example^\n||evil2.example^\n",
        )
        .unwrap();
        rebuild_from_disk(&p, &shared, &meta);
        let m = lock(&meta);
        assert_eq!(m.state, State::Ready);
        assert_eq!(m.domains, [1, 1, 2, 0, 0, 0, 0]);
        assert!(m.lists_updated.is_some());
        assert!(shared
            .filter
            .read()
            .unwrap()
            .dangerous
            .blocks("evil.example"));
    }

    #[test]
    fn broken_stored_list_keeps_the_working_set() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let shared = Shared::new(Filter::empty(), config::Config::default(), vec![]);
        let meta: SharedMeta = Arc::new(Mutex::new(Meta::default()));
        fetch::store(&p.lists, "adguard-dns", "||ads.example^\n").unwrap();
        rebuild_from_disk(&p, &shared, &meta);
        fetch::store(&p.lists, "adguard-dns", "<html>oops</html>").unwrap();
        rebuild_from_disk(&p, &shared, &meta);
        assert_eq!(lock(&meta).refresh_error, Some(ErrorCode::ListInvalid));
        assert!(shared.filter.read().unwrap().ads.blocks("ads.example"));
        fetch::store(&p.lists, "adguard-dns", "||ads.example^\n||b.example^\n").unwrap();
        rebuild_from_disk(&p, &shared, &meta);
        assert_eq!(lock(&meta).refresh_error, None);
    }

    #[test]
    fn serve_answers_reports_and_stops_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let addrs = vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)];
        let stop = Arc::new(AtomicBool::new(false));
        let p = paths(dir.path());
        let status_path = p.status.clone();
        let handle = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || serve(p, &addrs, false, &stop).unwrap())
        };

        let status = wait_for("a listening status", || {
            load_status(&status_path).filter(|s| s.listening && s.state == State::NoLists)
        });
        assert!(config::fresh(&status, server::unix_now()));

        // Firefox's canary name always gets NXDOMAIN, which proves the
        // listener answers.
        let mut query = vec![0x00, 0x2a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in crate::filter::dns::CANARY.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.send_to(&query, ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 512];
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..2], &[0x00, 0x2a]);
        assert!(n > 12 && buf[3] & 0x0F == 3);

        let started = Instant::now();
        stop.store(true, Ordering::Release);
        handle.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(!load_status(&status_path).unwrap().listening);
    }

    fn ask_for(name: &str, id: u16, port: u16) {
        let mut query = vec![
            (id >> 8) as u8,
            id as u8,
            0x01,
            0x00,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.send_to(&query, ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 512];
        client.recv(&mut buf).unwrap();
    }

    #[test]
    fn blocked_sites_reach_the_files_and_are_cleared_when_the_service_stops() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        config::save_config(
            &p.config,
            &config::Config {
                ads: true,
                ..config::Config::default()
            },
        )
        .unwrap();
        fetch::store(&p.lists, "adguard-dns", "||ads.example^\n").unwrap();
        let port = free_port();
        let addrs = vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)];
        let stop = Arc::new(AtomicBool::new(false));
        let (status_path, recent_path, stats_path, detail_path) = (
            p.status.clone(),
            p.recent.clone(),
            p.stats.clone(),
            p.detail.clone(),
        );
        let handle = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || serve(p, &addrs, false, &stop).unwrap())
        };
        wait_for("a ready status", || {
            load_status(&status_path).filter(|s| s.listening && s.state == State::Ready)
        });
        ask_for("cdn.ads.example", 1, port);
        let recent = wait_for("the recent list", || {
            config::load_recent(&recent_path).filter(|r| !r.items.is_empty())
        });
        assert_eq!(recent.items[0].name, "cdn.ads.example");
        let status = wait_for("the count", || {
            load_status(&status_path).filter(|s| s.blocked[0] == 1)
        });
        assert_eq!(status.dangerous_at, None);
        assert_eq!(status.domains, [1, 1, 0, 0, 0, 0, 0]);
        let stats = wait_for("the statistics", || config::load_stats(&stats_path));
        assert_eq!(stats.days[0].blocked, [1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(stats.top[0].site, "ads.example");

        stop.store(true, Ordering::Release);
        handle.join().unwrap();
        assert_eq!(config::load_recent(&recent_path).unwrap().items, []);
        let detail = activity::load_detail(&detail_path);
        assert_eq!(detail.days[0].blocked, [1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(detail.days[0].sites, [("ads.example".to_string(), 1)]);
    }

    #[test]
    fn counts_and_old_names_are_picked_up_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let now = server::unix_now();
        let saved = activity::Detail {
            days: vec![activity::DetailDay {
                day: crate::clock::local_day(now),
                blocked: [4, 0, 0, 0, 0, 0, 0],
                sites: vec![("ads.example".to_string(), 4)],
            }],
        };
        save_json(&p.detail, &saved);
        save_json(
            &p.recent,
            &config::RecentList {
                items: vec![config::RecentItem {
                    name: "left.over.example".into(),
                    kind: crate::filter::matcher::Kind::Ads,
                    at: now,
                }],
            },
        );
        let port = free_port();
        let addrs = vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)];
        let stop = Arc::new(AtomicBool::new(false));
        let (status_path, recent_path, stats_path) =
            (p.status.clone(), p.recent.clone(), p.stats.clone());
        let handle = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || serve(p, &addrs, false, &stop).unwrap())
        };
        wait_for("a listening status", || {
            load_status(&status_path).filter(|s| s.listening)
        });
        assert_eq!(config::load_recent(&recent_path).unwrap().items, []);
        stop.store(true, Ordering::Release);
        handle.join().unwrap();
        let stats = config::load_stats(&stats_path).unwrap();
        assert_eq!(stats.days[0].blocked, [4, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn starting_the_service_ends_a_pause_until_restart() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let paused = config::Config {
            ads: true,
            paused_boot: Some(config::boot_time(server::unix_now())),
            ..config::Config::default()
        };
        config::save_config(&p.config, &paused).unwrap();
        let (config_path, status_path) = (p.config.clone(), p.status.clone());
        let port = free_port();
        let addrs = vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)];
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || serve(p, &addrs, false, &stop).unwrap())
        };
        wait_for("a listening status", || {
            load_status(&status_path).filter(|s| s.listening)
        });
        let saved = config::load_config(&config_path);
        assert_eq!(saved.paused_boot, None);
        assert!(saved.ads);
        stop.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn port_in_use_is_reported_and_retried() {
        let dir = tempfile::tempdir().unwrap();
        let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let addrs = vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)];
        let stop = Arc::new(AtomicBool::new(false));
        let p = paths(dir.path());
        let status_path = p.status.clone();
        let handle = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || serve(p, &addrs, false, &stop).unwrap())
        };
        let status = wait_for("the port-in-use status", || {
            load_status(&status_path).filter(|s| s.last_error == Some(ErrorCode::PortInUse))
        });
        assert!(!status.listening);
        stop.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_new_notice_is_written_at_once_and_counts_wait_for_the_timer() {
        let base = Status::default();
        let counted = Status {
            blocked: [3; KINDS],
            written_at: 9,
            dangerous_at: Some(5),
            ..base.clone()
        };
        assert!(same_apart_from_counts(&base, &counted));
        let notice = |at| config::Notice {
            kind: crate::filter::matcher::Kind::Scam,
            site: "scam.example".into(),
            at,
        };
        let first = Status {
            notice: Some(notice(100)),
            ..base.clone()
        };
        assert!(!same_apart_from_counts(&base, &first));
        let again = Status {
            notice: Some(notice(101)),
            ..first.clone()
        };
        assert!(!same_apart_from_counts(&first, &again));
        assert!(same_apart_from_counts(&first, &first.clone()));
    }

    #[test]
    fn production_addresses_are_loopback_port_53() {
        for addr in listen_addresses() {
            assert!(addr.ip().is_loopback());
            assert_eq!(addr.port(), 53);
        }
    }
}
