//! The root helper: `org.secblitz.Helper1` on the system bus. Every `Begin` is checked with polkit for the
//! caller that sent it, then the request runs as one job whose events the same caller collects with `Next`.
use super::ops;
use super::polkit::{self, Action};
use crate::app::remote::{self, Event, Reply, Request};
use crate::app::worker::Session;
use secblitz::engine::recover::NotDamaged;
use secblitz::linux::backend::LinuxBackend;
use secblitz::linux::cmd::RealSys;
use secblitz::space::linux::RealFs;
use secblitz::updater;
use std::collections::VecDeque;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zbus::fdo;
use zbus::message::Header;
use zbus::{interface, Connection};

pub const NAME: &str = "org.secblitz.Helper1";
pub const PATH: &str = "/org/secblitz/Helper1";
pub const INTERFACE: &str = "org.secblitz.Helper1";

/// How long the helper stays up with nothing to do.
pub const IDLE_EXIT: Duration = Duration::from_secs(60);
/// How long `Next` waits for news before it returns an empty list.
const NEXT_WAIT: Duration = Duration::from_millis(250);
/// A finished job nobody collected makes room for the next one after this long.
const ABANDONED_AFTER: Duration = Duration::from_secs(30);

const BUSY: &str = "Secblitz is busy with another task. Try again in a moment.";
const STOPPED: &str = "Secblitz stopped unexpectedly. Try again in a moment.";
const TOO_LARGE: &str =
    "Secblitz could not send all the results at once. Try again with fewer settings.";

pub type Opener = Arc<dyn Fn() -> anyhow::Result<Box<dyn Session>> + Send + Sync>;
pub type Recover = Arc<dyn Fn() -> anyhow::Result<()> + Send + Sync>;
pub type Check<'a> = Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>>;

/// Decides whether a caller may do what its request needs.
pub trait Authorizer: Send + Sync + 'static {
    fn authorize<'a>(
        &'a self,
        connection: &'a Connection,
        sender: &'a str,
        action: Action,
    ) -> Check<'a>;
}

pub struct Polkit;

impl Authorizer for Polkit {
    fn authorize<'a>(
        &'a self,
        connection: &'a Connection,
        sender: &'a str,
        action: Action,
    ) -> Check<'a> {
        Box::pin(async move { Ok(polkit::is_authorized(connection, sender, action).await?) })
    }
}

struct Job {
    id: u64,
    owner: String,
    events: VecDeque<Vec<u8>>,
    done: bool,
    finished: Option<Instant>,
}

#[derive(Default)]
struct State {
    next_id: u64,
    job: Option<Job>,
}

struct Shared {
    state: Mutex<State>,
    news: Condvar,
    touched: Mutex<Instant>,
    asking: AtomicUsize,
}

/// Keeps the helper awake while a request waits on the permission prompt, which can take far longer than the idle time.
struct Asking<'a>(&'a Shared);

impl<'a> Asking<'a> {
    fn new(shared: &'a Shared) -> Self {
        shared.asking.fetch_add(1, Ordering::SeqCst);
        Self(shared)
    }
}

impl Drop for Asking<'_> {
    fn drop(&mut self) {
        self.0.touch();
        self.0.asking.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Shared {
    fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
            news: Condvar::new(),
            touched: Mutex::new(Instant::now()),
            asking: AtomicUsize::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn touch(&self) {
        *self.touched.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    fn idle_for(&self) -> Option<Duration> {
        let busy = self.lock().job.as_ref().is_some_and(|job| !job.done);
        if busy || self.asking.load(Ordering::SeqCst) > 0 {
            return None;
        }
        Some(
            self.touched
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed(),
        )
    }

    /// Takes the one job slot, or says why it cannot.
    fn start(&self, owner: &str) -> Result<u64, &'static str> {
        let mut state = self.lock();
        if let Some(job) = &state.job {
            let abandoned = job
                .finished
                .is_some_and(|at| job.owner == owner || at.elapsed() >= ABANDONED_AFTER);
            if !abandoned {
                return Err(BUSY);
            }
        }
        state.next_id += 1;
        let id = state.next_id;
        state.job = Some(Job {
            id,
            owner: owner.to_owned(),
            events: VecDeque::new(),
            done: false,
            finished: None,
        });
        Ok(id)
    }

    fn push(&self, id: u64, bytes: Vec<u8>, last: bool) {
        let mut state = self.lock();
        if let Some(job) = state.job.as_mut().filter(|job| job.id == id) {
            job.events.push_back(bytes);
            if last {
                job.done = true;
                job.finished = Some(Instant::now());
            }
        }
        drop(state);
        self.touch();
        self.news.notify_all();
    }

    fn take(&self, id: u64, owner: &str) -> Result<(Vec<Vec<u8>>, bool), fdo::Error> {
        let mut state = self.lock();
        let deadline = Instant::now() + NEXT_WAIT;
        loop {
            match state.job.as_mut() {
                Some(job) if job.id == id => {
                    if job.owner != owner {
                        return Err(fdo::Error::AccessDenied(polkit::NOT_ALLOWED.into()));
                    }
                    if !job.events.is_empty() || job.done {
                        let events: Vec<Vec<u8>> = job.events.drain(..).collect();
                        let finished = job.done;
                        if finished {
                            state.job = None;
                        }
                        return Ok((events, finished));
                    }
                }
                _ => return Err(fdo::Error::Failed(STOPPED.into())),
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok((Vec::new(), false));
            }
            state = self
                .news
                .wait_timeout(state, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

fn encode(event: &Event) -> Vec<u8> {
    match serde_json::to_vec(event) {
        Ok(bytes) if bytes.len() <= remote::MAX_MESSAGE => bytes,
        Ok(_) => failure(TOO_LARGE),
        Err(error) => failure(&format!("{error:#}")),
    }
}

fn failure(message: &str) -> Vec<u8> {
    serde_json::to_vec(&Event::Done(Reply::Failed(message.to_owned()))).unwrap_or_default()
}

#[cfg(not(test))]
fn remove_self() -> anyhow::Result<()> {
    secblitz::linux::remove::start_installed()
}

#[cfg(test)]
static REMOVALS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
fn remove_self() -> anyhow::Result<()> {
    REMOVALS.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

fn update_reply(result: anyhow::Result<updater::UpdateStatus>) -> Reply {
    match result {
        Ok(status) => Reply::Update(status),
        Err(error) => Reply::Failed(format!("{error:#}")),
    }
}

/// Runs one request to its final event. A start fresh needs no open session, since a damaged history is why none could open.
fn run_job(shared: &Shared, id: u64, request: Request, open: &Opener, recover: &Recover) {
    let mut finished = false;
    let mut emit = |event: Event| {
        let last = matches!(event, Event::Done(_));
        finished |= last;
        shared.push(id, encode(&event), last);
    };
    let _ = catch_unwind(AssertUnwindSafe(|| match request {
        Request::StartFresh => {
            let result = match recover() {
                Err(e) if e.downcast_ref::<NotDamaged>().is_some() => Ok(()),
                other => other,
            };
            emit(Event::Done(match result {
                Ok(()) => Reply::Ok,
                Err(error) => remote::failure(&error),
            }));
        }
        Request::RemoveSelf => {
            emit(Event::Done(match remove_self() {
                Ok(()) => Reply::Ok,
                Err(error) => remote::failure(&error),
            }));
        }
        Request::MonitorTimer { on } => emit(Event::Done(match updater::linux::set_monitor_timer(
            &RealSys, on,
        ) {
            Ok(()) => Reply::Ok,
            Err(error) => Reply::Failed(format!("{error:#}")),
        })),
        Request::UpdateStatus => emit(Event::Done(update_reply(updater::linux::status(&RealSys)))),
        Request::CheckUpdate => {
            // A failed check is written down as the status, so the person sees it the way the timer's would show.
            if let Err(e) = updater::linux::check(&RealSys) {
                eprintln!("The update check failed: {e:#}");
            }
            emit(Event::Done(update_reply(updater::linux::status(&RealSys))))
        }
        Request::InstallUpdate => emit(Event::Done(update_reply(
            updater::linux::install(&RealSys).and_then(|_| updater::linux::status(&RealSys)),
        ))),
        request if ops::handles(&request) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            ops::run(&RealSys, &RealFs, now, request, &mut emit);
        }
        request => match open() {
            Ok(mut session) => remote::serve(session.as_mut(), request, &mut emit),
            Err(error) => emit(Event::Done(remote::failure(&error))),
        },
    }));
    if !finished {
        shared.push(id, failure(STOPPED), true);
    }
}

pub struct Helper {
    shared: Arc<Shared>,
    authorizer: Arc<dyn Authorizer>,
    open: Opener,
    recover: Recover,
}

impl Helper {
    fn sender(header: &Header<'_>) -> Result<String, fdo::Error> {
        header
            .sender()
            .map(|name| name.to_string())
            .ok_or_else(|| fdo::Error::Failed(polkit::NOT_ALLOWED.into()))
    }
}

#[interface(name = "org.secblitz.Helper1")]
impl Helper {
    async fn begin(
        &self,
        request: Vec<u8>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<u64> {
        let _asking = Asking::new(&self.shared);
        let sender = Self::sender(&header)?;
        let request =
            remote::decode_request(&request).map_err(|e| fdo::Error::Failed(format!("{e:#}")))?;
        let allowed = self
            .authorizer
            .authorize(connection, &sender, polkit::action_for(&request))
            .await
            .map_err(|e| {
                eprintln!("The permission check failed: {e:#}");
                fdo::Error::Failed(polkit::NOT_ALLOWED.into())
            })?;
        if !allowed {
            return Err(fdo::Error::Failed(polkit::NOT_ALLOWED.into()));
        }
        let id = self
            .shared
            .start(&sender)
            .map_err(|m| fdo::Error::Failed(m.into()))?;
        let (shared, open, recover) =
            (self.shared.clone(), self.open.clone(), self.recover.clone());
        let spawned = std::thread::Builder::new()
            .name("job".into())
            .spawn(move || run_job(&shared, id, request, &open, &recover));
        if spawned.is_err() {
            self.shared.push(id, failure(STOPPED), true);
        }
        Ok(id)
    }

    #[zbus(out_args("events", "done"))]
    async fn next(
        &self,
        job: u64,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<(Vec<Vec<u8>>, bool)> {
        self.shared.touch();
        let sender = Self::sender(&header)?;
        let taken = self.shared.take(job, &sender);
        self.shared.touch();
        taken
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        remote::PROTOCOL
    }
}

/// Serves on `builder`'s bus until nothing has happened for `idle`, then returns.
pub fn serve(
    builder: zbus::connection::Builder<'static>,
    authorizer: Arc<dyn Authorizer>,
    open: Opener,
    recover: Recover,
    idle: Duration,
) -> anyhow::Result<()> {
    let shared = Arc::new(Shared::new());
    let helper = Helper {
        shared: shared.clone(),
        authorizer,
        open,
        recover,
    };
    let _connection = zbus::block_on(builder.name(NAME).serve_at(PATH, helper).build())?;
    loop {
        std::thread::sleep(Duration::from_millis(100));
        if shared.idle_for().is_some_and(|quiet| quiet >= idle) {
            return Ok(());
        }
    }
}

/// The system service: root only, polkit on every call, gone after a minute of quiet.
pub fn run(open: Opener, recover: Recover) -> anyhow::Result<()> {
    // SAFETY: geteuid has no preconditions.
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0,
        "Secblitz's helper only runs as part of the system. Open Secblitz from the applications menu instead."
    );
    serve(
        zbus::connection::Builder::system(),
        Arc::new(Polkit),
        open,
        recover,
        IDLE_EXIT,
    )
}

/// The helper as the system installs it: the engine on the protected state folder.
pub fn run_installed() -> anyhow::Result<()> {
    run(
        Arc::new(|| {
            let engine = secblitz::engine::Engine::open(
                secblitz::platform::state_dir()?,
                Box::new(LinuxBackend::installed()?),
            )?;
            Ok(Box::new(engine) as Box<dyn Session>)
        }),
        Arc::new(|| {
            secblitz::engine::recover::start_fresh(
                &secblitz::platform::state_dir()?,
                Box::new(LinuxBackend::installed()?),
            )
            .map(drop)
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::remote::RemoteSession;
    use crate::linux_bus::client::DbusTransport;
    use secblitz::engine::{Progress, ProgressStep, Report};
    use secblitz::model::CheckStatus;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn one_job_at_a_time_and_a_finished_one_makes_room_for_its_owner() {
        let shared = Shared::new();
        let first = shared.start(":1.1").unwrap();
        assert_eq!(shared.start(":1.2"), Err(BUSY));
        assert_eq!(shared.start(":1.1"), Err(BUSY));
        shared.push(first, b"x".to_vec(), true);
        assert_eq!(shared.start(":1.2"), Err(BUSY));
        let second = shared.start(":1.1").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn a_job_only_answers_the_caller_that_started_it() {
        let shared = Shared::new();
        let id = shared.start(":1.1").unwrap();
        shared.push(id, b"a".to_vec(), false);
        assert!(matches!(
            shared.take(id, ":1.2"),
            Err(fdo::Error::AccessDenied(_))
        ));
        assert_eq!(
            shared.take(id, ":1.1").unwrap(),
            (vec![b"a".to_vec()], false)
        );
        shared.push(id, b"b".to_vec(), true);
        assert_eq!(
            shared.take(id, ":1.1").unwrap(),
            (vec![b"b".to_vec()], true)
        );
        assert!(shared.take(id, ":1.1").is_err());
        assert!(shared.take(id + 1, ":1.1").is_err());
    }

    #[test]
    fn a_waiting_permission_prompt_keeps_the_helper_awake() {
        let shared = Shared::new();
        let asking = Asking::new(&shared);
        assert!(shared.idle_for().is_none());
        drop(asking);
        assert!(shared.idle_for().is_some());
    }

    #[test]
    fn a_job_that_panics_still_ends_with_one_final_event() {
        let shared = Shared::new();
        let id = shared.start(":1.1").unwrap();
        let open: Opener = Arc::new(|| Ok(Box::new(Panics) as Box<dyn Session>));
        let recover: Recover = Arc::new(|| Ok(()));
        run_job(&shared, id, Request::Available, &open, &recover);
        let (events, done) = shared.take(id, ":1.1").unwrap();
        assert!(done);
        assert_eq!(events.len(), 1);
        assert!(String::from_utf8(events[0].clone())
            .unwrap()
            .contains(STOPPED));
    }

    #[test]
    fn a_removal_needs_no_open_session_and_starts_once() {
        let shared = Shared::new();
        let id = shared.start(":1.1").unwrap();
        let open: Opener = Arc::new(|| Ok(Box::new(Panics) as Box<dyn Session>));
        let recover: Recover = Arc::new(|| Ok(()));
        let before = REMOVALS.load(Ordering::SeqCst);
        run_job(&shared, id, Request::RemoveSelf, &open, &recover);
        let (events, done) = shared.take(id, ":1.1").unwrap();
        assert!(done);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            serde_json::from_slice::<Event>(&events[0]).unwrap(),
            Event::Done(Reply::Ok)
        ));
        assert_eq!(REMOVALS.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn every_sentence_the_helper_shows_is_translated() {
        for text in [
            BUSY,
            STOPPED,
            TOO_LARGE,
            polkit::NOT_ALLOWED,
            secblitz::linux::remove::CANNOT_REMOVE,
        ] {
            assert_ne!(crate::i18n::Lang::De.t(text), text, "{text}");
        }
    }

    #[test]
    fn every_sentence_the_update_features_show_is_translated_in_every_language() {
        let others = [
            "This cannot be done from here.",
            "A newer version of Secblitz is ready to install.",
            "Look for updates automatically?",
            "Once a day, Secblitz looks for a newer version of itself. It never changes anything on its own.",
            "Stop looking for updates?",
            "Secblitz stops looking for updates by itself. You can still update it from your software app or from our website.",
            "Look for updates automatically",
            "Once a day, Secblitz looks for a newer version of itself.",
            "A new version is ready. Install it from your software app.",
            "A new version is ready to install.",
            "Secblitz is installing the update. It is ready the next time you open it.",
            "Secblitz has not looked for updates yet.",
        ];
        for text in secblitz::updater::linux::SENTENCES
            .into_iter()
            .chain(others)
        {
            for lang in ["es", "fr", "de", "pt", "it"] {
                let lang = crate::i18n::Lang::parse(lang).unwrap();
                assert_ne!(lang.t(text), text, "{text} in {lang:?}");
                assert!(!lang.t(text).contains('\u{2014}'), "{text}");
            }
        }
    }

    #[test]
    fn every_sentence_the_linux_checks_show_is_translated_in_every_language() {
        use secblitz::linux::controls::{findings, SENTENCES};
        let names = ["AppArmor", "SELinux", "Secure Boot", "Firewall"];
        let all = SENTENCES
            .iter()
            .chain(&findings::SENTENCES)
            .copied()
            .chain(secblitz::linux::backend::texts());
        for text in all.filter(|t| !names.contains(t)) {
            for lang in ["es", "fr", "de", "pt", "it"] {
                let lang = crate::i18n::Lang::parse(lang).unwrap();
                assert_ne!(lang.t(text), text, "{text} in {lang:?}");
            }
        }
    }

    #[test]
    fn next_waits_a_moment_then_returns_nothing() {
        let shared = Shared::new();
        let id = shared.start(":1.1").unwrap();
        let began = Instant::now();
        assert_eq!(shared.take(id, ":1.1").unwrap(), (Vec::new(), false));
        assert!(began.elapsed() >= NEXT_WAIT);
        assert!(began.elapsed() < NEXT_WAIT * 4);
    }

    #[test]
    fn a_running_job_keeps_the_helper_awake() {
        let shared = Shared::new();
        assert!(shared.idle_for().is_some());
        let id = shared.start(":1.1").unwrap();
        assert!(shared.idle_for().is_none());
        shared.push(id, b"x".to_vec(), true);
        assert!(shared.idle_for().is_some());
    }

    struct Bus(Child, String);

    impl Bus {
        fn start() -> Option<Self> {
            let mut child = Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--print-address=1"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;
            let mut line = String::new();
            BufReader::new(child.stdout.take()?)
                .read_line(&mut line)
                .ok()?;
            Some(Self(child, line.trim().to_owned()))
        }
    }

    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    type Asked = Arc<Mutex<Vec<(String, Action)>>>;

    struct Fixed {
        allow: bool,
        asked: Asked,
    }

    impl Authorizer for Fixed {
        fn authorize<'a>(
            &'a self,
            _: &'a Connection,
            sender: &'a str,
            action: Action,
        ) -> Check<'a> {
            self.asked.lock().unwrap().push((sender.to_owned(), action));
            let allow = self.allow;
            Box::pin(async move { Ok(allow) })
        }
    }

    struct Fake {
        fail: bool,
    }

    impl Session for Fake {
        fn available(&self) -> Vec<String> {
            vec!["a".into()]
        }
        fn restart_ids(&self) -> Vec<String> {
            Vec::new()
        }
        fn audit(&mut self, progress: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
            progress(Progress::new(
                "a",
                ProgressStep::Result(CheckStatus::Compliant),
            ));
            Ok(Report {
                transaction: Some("audit".into()),
                ..Report::default()
            })
        }
        fn apply(
            &mut self,
            _: &[String],
            _: &mut dyn FnMut(Progress<'_>),
        ) -> anyhow::Result<Report> {
            anyhow::ensure!(!self.fail, "disk full");
            Ok(Report::default())
        }
        fn undo(&mut self, _: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
            Ok(Report::default())
        }
        fn undo_selected(
            &mut self,
            _: &[String],
            _: &mut dyn FnMut(Progress<'_>),
        ) -> anyhow::Result<Report> {
            Ok(Report::default())
        }
        fn history(&mut self) -> anyhow::Result<Vec<String>> {
            Ok(vec!["one".into()])
        }
        fn can_start(&mut self, _: bool) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct Panics;

    impl Session for Panics {
        fn available(&self) -> Vec<String> {
            panic!("boom")
        }
        fn restart_ids(&self) -> Vec<String> {
            Vec::new()
        }
        fn audit(&mut self, _: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
            unreachable!()
        }
        fn apply(
            &mut self,
            _: &[String],
            _: &mut dyn FnMut(Progress<'_>),
        ) -> anyhow::Result<Report> {
            unreachable!()
        }
        fn undo(&mut self, _: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
            unreachable!()
        }
        fn undo_selected(
            &mut self,
            _: &[String],
            _: &mut dyn FnMut(Progress<'_>),
        ) -> anyhow::Result<Report> {
            unreachable!()
        }
        fn history(&mut self) -> anyhow::Result<Vec<String>> {
            unreachable!()
        }
        fn can_start(&mut self, _: bool) -> anyhow::Result<()> {
            unreachable!()
        }
    }

    struct Running {
        _bus: Bus,
        address: String,
        asked: Asked,
        recovered: Arc<AtomicUsize>,
        thread: std::thread::JoinHandle<anyhow::Result<()>>,
    }

    fn owns_the_name(address: &str) -> bool {
        zbus::block_on(async {
            let Ok(c) = zbus::connection::Builder::address(address).build().await else {
                return false;
            };
            let reply = c
                .call_method(
                    Some("org.freedesktop.DBus"),
                    "/org/freedesktop/DBus",
                    Some("org.freedesktop.DBus"),
                    "NameHasOwner",
                    &NAME,
                )
                .await;
            reply.is_ok_and(|r| r.body().deserialize::<bool>().unwrap_or(false))
        })
    }

    fn running(allow: bool, fail: bool, idle: Duration) -> Option<Running> {
        let Some(bus) = Bus::start() else {
            eprintln!("dbus-daemon is not installed; skipping the bus test");
            return None;
        };
        let address = bus.1.clone();
        let asked = Asked::default();
        let recovered = Arc::new(AtomicUsize::new(0));
        let builder = zbus::connection::Builder::address(address.as_str());
        let authorizer = Arc::new(Fixed {
            allow,
            asked: asked.clone(),
        });
        let count = recovered.clone();
        let thread = std::thread::spawn(move || {
            serve(
                builder,
                authorizer,
                Arc::new(move || Ok(Box::new(Fake { fail }) as Box<dyn Session>)),
                Arc::new(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
                idle,
            )
        });
        for _ in 0..100 {
            if owns_the_name(&address) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Some(Running {
            _bus: bus,
            address,
            asked,
            recovered,
            thread,
        })
    }

    #[test]
    fn a_window_drives_the_helper_over_a_real_bus() {
        let Some(run) = running(true, true, Duration::from_secs(60)) else {
            return;
        };
        let mut session = RemoteSession::connect(DbusTransport::at(&run.address)).unwrap();
        assert_eq!(session.available(), vec!["a".to_owned()]);
        let mut seen = Vec::new();
        let report = session
            .audit(&mut |p: Progress<'_>| seen.push(p.id.to_owned()))
            .unwrap();
        assert_eq!(report.transaction.as_deref(), Some("audit"));
        assert_eq!(seen, vec!["a".to_owned()]);
        assert_eq!(session.history().unwrap(), vec!["one".to_owned()]);
        let error = session.apply(&["a".into()], &mut |_| {}).unwrap_err();
        assert_eq!(format!("{error:#}"), "disk full");
        let asked = run.asked.lock().unwrap();
        assert!(asked.iter().any(|(_, a)| *a == Action::Check));
        assert!(asked.iter().any(|(_, a)| *a == Action::Change));
        assert!(asked.iter().all(|(name, _)| name.starts_with(':')));
    }

    #[test]
    fn a_refused_password_changes_nothing_and_says_so_plainly() {
        let Some(run) = running(false, false, Duration::from_secs(60)) else {
            return;
        };
        let error = RemoteSession::connect(DbusTransport::at(&run.address))
            .err()
            .expect("the call is refused");
        assert_eq!(format!("{error:#}"), polkit::NOT_ALLOWED);
    }

    #[test]
    fn a_damaged_history_can_be_started_fresh_without_a_session() {
        let Some(run) = running(true, false, Duration::from_secs(60)) else {
            return;
        };
        remote::start_fresh(&mut DbusTransport::at(&run.address)).unwrap();
        assert_eq!(run.recovered.load(Ordering::SeqCst), 1);
        assert!(run
            .asked
            .lock()
            .unwrap()
            .iter()
            .all(|(_, action)| *action == Action::Change));
    }

    #[test]
    fn another_program_cannot_read_a_job_and_garbage_is_refused() {
        let Some(run) = running(true, false, Duration::from_secs(60)) else {
            return;
        };
        let address = run.address.clone();
        let (garbage, stolen) = zbus::block_on(async move {
            let build = || async {
                zbus::connection::Builder::address(address.as_str())
                    .build()
                    .await
                    .unwrap()
            };
            let (owner, thief) = (build().await, build().await);
            let garbage = owner
                .call_method(
                    Some(NAME),
                    PATH,
                    Some(INTERFACE),
                    "Begin",
                    &b"not json".to_vec(),
                )
                .await;
            let request = remote::encode_request(&Request::History).unwrap();
            let job: u64 = owner
                .call_method(Some(NAME), PATH, Some(INTERFACE), "Begin", &request)
                .await
                .unwrap()
                .body()
                .deserialize()
                .unwrap();
            let stolen = thief
                .call_method(Some(NAME), PATH, Some(INTERFACE), "Next", &job)
                .await;
            (garbage, stolen)
        });
        assert!(garbage.is_err());
        assert!(stolen.is_err());
    }

    #[test]
    fn the_helper_leaves_after_a_quiet_spell() {
        let Some(run) = running(true, false, Duration::from_millis(400)) else {
            return;
        };
        assert!(run.thread.join().unwrap().is_ok());
    }

    #[test]
    fn the_version_property_is_the_protocol_number() {
        let Some(run) = running(true, false, Duration::from_secs(60)) else {
            return;
        };
        let version: u32 = zbus::block_on(async {
            let c = zbus::connection::Builder::address(run.address.as_str())
                .build()
                .await
                .unwrap();
            c.call_method(
                Some(NAME),
                PATH,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(INTERFACE, "Version"),
            )
            .await
            .unwrap()
            .body()
            .deserialize::<zbus::zvariant::OwnedVariant>()
            .unwrap()
            .try_into()
            .unwrap()
        });
        assert_eq!(version, remote::PROTOCOL);
    }
}
