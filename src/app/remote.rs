//! The typed requests an unprivileged window sends to a helper that holds the
//! rights, and the helper side that answers them. Windows keeps its own
//! elevated window; this is the cut the Unix helper will use.
use super::worker::Session;
use secblitz::engine::recover::{DamageKind, JournalDamaged};
use secblitz::engine::{ItemChoice, Progress, ProgressStep, Report};
use secblitz::model::CheckStatus;
use secblitz::space::{Item, Tally};
use secblitz::updater::UpdateStatus;
use serde::{Deserialize, Serialize};

pub const PROTOCOL: u32 = 2;
pub const MAX_MESSAGE: usize = 1 << 20;
const MAX_IDS: usize = 512;
const MAX_ID_LEN: usize = 128;
const MAX_ITEM_LEN: usize = 512;
const MAX_SPACE_ITEMS: usize = 8;
const MAX_PACKAGES: usize = 32;

use crate::launcher::NOT_INSTALLED;
const BAD_ANSWER: &str = NOT_INSTALLED;
const NOT_DAMAGED: &str = "Nothing needs to be started fresh.";
const NOT_HERE: &str = "This cannot be done from here.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "op", rename_all = "snake_case")]
pub enum Request {
    Available,
    RestartIds,
    Audit,
    Apply {
        ids: Vec<String>,
    },
    Undo,
    UndoSelected {
        ids: Vec<String>,
    },
    History,
    CanStart {
        undo: bool,
    },
    ChooseItems {
        picked: ItemChoice,
    },
    StartFresh,
    /// Takes Secblitz's own package off the computer. It needs no open session.
    RemoveSelf,
    MonitorTimer {
        on: bool,
    },
    UpdateStatus,
    /// Looks at the signed feed now instead of waiting for the daily timer.
    CheckUpdate,
    InstallUpdate,
    SpaceMeasure {
        items: Vec<SpaceWire>,
    },
    SpaceClean {
        items: Vec<SpaceWire>,
    },
    Apps,
    RemoveApps {
        packages: Vec<String>,
    },
}

/// The Free up space items that need the helper's rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceWire {
    PackageCaches,
    CrashReports,
    FlatpakRuntimes,
    OldSnaps,
    OldKernels,
}

impl SpaceWire {
    pub fn of(item: Item) -> Option<Self> {
        match item {
            Item::PackageCaches => Some(Self::PackageCaches),
            Item::CrashReports => Some(Self::CrashReports),
            Item::FlatpakRuntimes => Some(Self::FlatpakRuntimes),
            Item::OldSnaps => Some(Self::OldSnaps),
            Item::OldKernels => Some(Self::OldKernels),
            _ => None,
        }
    }

    pub fn item(self) -> Item {
        match self {
            Self::PackageCaches => Item::PackageCaches,
            Self::CrashReports => Item::CrashReports,
            Self::FlatpakRuntimes => Item::FlatpakRuntimes,
            Self::OldSnaps => Item::OldSnaps,
            Self::OldKernels => Item::OldKernels,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppWire {
    pub index: u16,
    pub package: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppStep {
    Started,
    Removed,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepWire {
    Pending,
    Complete,
    Result(String),
}

impl From<&ProgressStep> for StepWire {
    fn from(step: &ProgressStep) -> Self {
        match step {
            ProgressStep::Pending => Self::Pending,
            ProgressStep::Complete => Self::Complete,
            ProgressStep::Result(status) => Self::Result(status.as_str().to_owned()),
        }
    }
}

impl From<StepWire> for ProgressStep {
    fn from(step: StepWire) -> Self {
        match step {
            StepWire::Pending => Self::Pending,
            StepWire::Complete => Self::Complete,
            StepWire::Result(text) => Self::Result(CheckStatus::from(text.as_str())),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    Ids(Vec<String>),
    Report(Report),
    History(Vec<String>),
    Update(UpdateStatus),
    Ok,
    Failed(String),
    /// The saved undo history cannot be trusted. Typed, so the window can offer a fresh start.
    Damaged {
        kind: DamageKind,
        files: usize,
    },
    Apps(Vec<AppWire>),
}

/// The reply for an error. A damaged undo history keeps its type across the cut.
pub fn failure(error: &anyhow::Error) -> Reply {
    match error.downcast_ref::<JournalDamaged>() {
        Some(damage) => Reply::Damaged {
            kind: damage.kind,
            files: damage.files,
        },
        None => Reply::Failed(format!("{error:#}")),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Progress {
        id: String,
        step: StepWire,
    },
    /// What one Free up space item came to: the size it holds or freed, or why it could not be read.
    Space {
        item: SpaceWire,
        outcome: Result<Tally, String>,
    },
    App {
        package: String,
        step: AppStep,
    },
    Done(Reply),
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

fn check_ids(ids: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(ids.len() <= MAX_IDS, "the request names too many settings");
    anyhow::ensure!(
        ids.iter().all(|id| valid_id(id)),
        "the request names a setting that is not valid"
    );
    Ok(())
}

fn check_request(request: &Request) -> anyhow::Result<()> {
    match request {
        Request::Apply { ids } | Request::UndoSelected { ids } => check_ids(ids),
        Request::ChooseItems { picked } => {
            anyhow::ensure!(
                picked.len() <= MAX_IDS,
                "the request names too many settings"
            );
            for (id, items) in picked {
                anyhow::ensure!(
                    valid_id(id),
                    "the request names a setting that is not valid"
                );
                anyhow::ensure!(items.len() <= MAX_IDS, "the request names too many items");
                anyhow::ensure!(
                    items
                        .iter()
                        .all(|i| i.len() <= MAX_ITEM_LEN && !i.chars().any(char::is_control)),
                    "the request names an item that is not valid"
                );
            }
            Ok(())
        }
        Request::SpaceMeasure { items } | Request::SpaceClean { items } => {
            anyhow::ensure!(
                items.len() <= MAX_SPACE_ITEMS,
                "the request names too many items"
            );
            anyhow::ensure!(
                items
                    .iter()
                    .enumerate()
                    .all(|(i, item)| !items[..i].contains(item)),
                "the request names an item twice"
            );
            Ok(())
        }
        Request::RemoveApps { packages } => {
            anyhow::ensure!(
                packages.len() <= MAX_PACKAGES,
                "the request names too many apps"
            );
            anyhow::ensure!(
                packages
                    .iter()
                    .all(|p| secblitz::debloat::linux::owner(p).is_some()),
                "the request names an app that is not in the catalog"
            );
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Reads one request from the unprivileged side. Anything oversized, from
/// another protocol version, or not exactly a known request is refused.
pub fn decode_request(bytes: &[u8]) -> anyhow::Result<Request> {
    anyhow::ensure!(bytes.len() <= MAX_MESSAGE, "the request is too large");
    let serde_json::Value::Object(mut envelope) = serde_json::from_slice(bytes)? else {
        anyhow::bail!("the request is not an envelope");
    };
    let version = envelope.remove("v").and_then(|v| v.as_u64());
    anyhow::ensure!(
        version == Some(PROTOCOL.into()),
        "the request has the wrong version"
    );
    let request = envelope
        .remove("request")
        .ok_or_else(|| anyhow::anyhow!("the request is empty"))?;
    anyhow::ensure!(envelope.is_empty(), "the request has unknown fields");
    let parsed: Request = serde_json::from_value(request.clone())?;
    // serde ignores extra fields next to a tag on variants without fields.
    anyhow::ensure!(
        serde_json::to_value(&parsed)? == request,
        "the request has unknown fields"
    );
    let request = parsed;
    check_request(&request)?;
    Ok(request)
}

pub fn encode_request(request: &Request) -> anyhow::Result<Vec<u8>> {
    check_request(request)?;
    let bytes = serde_json::to_vec(&serde_json::json!({ "v": PROTOCOL, "request": request }))?;
    anyhow::ensure!(bytes.len() <= MAX_MESSAGE, "the request is too large");
    Ok(bytes)
}

fn decode_event(bytes: &[u8]) -> anyhow::Result<Event> {
    anyhow::ensure!(bytes.len() <= MAX_MESSAGE, "the answer is too large");
    Ok(serde_json::from_slice(bytes)?)
}

/// Answers one request on the helper side, streaming progress before the final reply.
pub fn serve(session: &mut dyn Session, request: Request, emit: &mut dyn FnMut(Event)) {
    let mut emit_progress = |p: Progress<'_>| {
        emit(Event::Progress {
            id: p.id.to_owned(),
            step: (&p.step).into(),
        })
    };
    let reply = match request {
        Request::Available => Reply::Ids(session.available()),
        Request::RestartIds => Reply::Ids(session.restart_ids()),
        Request::Audit => report(session.audit(&mut emit_progress)),
        Request::Apply { ids } => report(session.apply(&ids, &mut emit_progress)),
        Request::Undo => report(session.undo(&mut emit_progress)),
        Request::UndoSelected { ids } => report(session.undo_selected(&ids, &mut emit_progress)),
        Request::History => match session.history() {
            Ok(lines) => Reply::History(lines),
            Err(error) => failure(&error),
        },
        Request::CanStart { undo } => done(session.can_start(undo)),
        Request::ChooseItems { picked } => done(session.choose_items(picked)),
        Request::StartFresh => Reply::Failed(NOT_DAMAGED.to_owned()),
        Request::RemoveSelf => Reply::Failed(BAD_ANSWER.to_owned()),
        Request::MonitorTimer { .. }
        | Request::UpdateStatus
        | Request::CheckUpdate
        | Request::InstallUpdate => Reply::Failed(NOT_HERE.to_owned()),
        Request::SpaceMeasure { .. }
        | Request::SpaceClean { .. }
        | Request::Apps
        | Request::RemoveApps { .. } => Reply::Failed(BAD_ANSWER.to_owned()),
    };
    emit(Event::Done(reply));
}

fn report(result: anyhow::Result<Report>) -> Reply {
    match result {
        Ok(report) => Reply::Report(report),
        Err(error) => failure(&error),
    }
}

fn done(result: anyhow::Result<()>) -> Reply {
    match result {
        Ok(()) => Reply::Ok,
        Err(error) => failure(&error),
    }
}

/// Carries one request to the helper and hands every event back as it arrives.
pub trait Transport {
    fn call(
        &mut self,
        request: &[u8],
        on_event: &mut dyn FnMut(&[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<()>;
}

/// Sends one request and hands every event to `on_event` as it arrives. The final reply is returned; a `Failed` reply becomes an error with its plain message.
pub fn stream<T: Transport>(
    transport: &mut T,
    request: &Request,
    on_event: &mut dyn FnMut(Event),
) -> anyhow::Result<Reply> {
    let bytes = encode_request(request)?;
    let mut reply = None;
    transport.call(&bytes, &mut |event| {
        anyhow::ensure!(reply.is_none(), BAD_ANSWER);
        match decode_event(event)? {
            Event::Done(done) => reply = Some(done),
            other => on_event(other),
        }
        Ok(())
    })?;
    match reply.ok_or_else(|| anyhow::anyhow!(NOT_INSTALLED))? {
        Reply::Failed(message) => anyhow::bail!(message),
        Reply::Damaged { kind, files } => Err(anyhow::Error::new(JournalDamaged { kind, files })),
        reply => Ok(reply),
    }
}

/// A `Session` whose work happens in a helper on the other end of a `Transport`.
pub struct RemoteSession<T: Transport> {
    transport: T,
    available: Vec<String>,
    restart: Vec<String>,
}

impl<T: Transport> RemoteSession<T> {
    pub fn connect(transport: T) -> anyhow::Result<Self> {
        let mut session = Self {
            transport,
            available: Vec::new(),
            restart: Vec::new(),
        };
        session.available = session.ids(Request::Available)?;
        session.restart = session.ids(Request::RestartIds)?;
        Ok(session)
    }

    fn ids(&mut self, request: Request) -> anyhow::Result<Vec<String>> {
        match self.ask(&request, &mut |_| {})? {
            Reply::Ids(ids) => Ok(ids),
            _ => anyhow::bail!(BAD_ANSWER),
        }
    }

    fn ask(
        &mut self,
        request: &Request,
        progress: &mut dyn FnMut(Progress<'_>),
    ) -> anyhow::Result<Reply> {
        stream(&mut self.transport, request, &mut |event| {
            if let Event::Progress { id, step } = event {
                progress(Progress::new(&id, step.into()));
            }
        })
    }

    fn report(
        &mut self,
        request: Request,
        progress: &mut dyn FnMut(Progress<'_>),
    ) -> anyhow::Result<Report> {
        match self.ask(&request, progress)? {
            Reply::Report(report) => Ok(report),
            _ => anyhow::bail!(BAD_ANSWER),
        }
    }

    fn unit(&mut self, request: Request) -> anyhow::Result<()> {
        match self.ask(&request, &mut |_| {})? {
            Reply::Ok => Ok(()),
            _ => anyhow::bail!(BAD_ANSWER),
        }
    }
}

impl<T: Transport> Session for RemoteSession<T> {
    fn available(&self) -> Vec<String> {
        self.available.clone()
    }
    fn restart_ids(&self) -> Vec<String> {
        self.restart.clone()
    }
    fn audit(&mut self, progress: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
        self.report(Request::Audit, progress)
    }
    fn apply(
        &mut self,
        ids: &[String],
        progress: &mut dyn FnMut(Progress<'_>),
    ) -> anyhow::Result<Report> {
        self.report(Request::Apply { ids: ids.to_vec() }, progress)
    }
    fn undo(&mut self, progress: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
        self.report(Request::Undo, progress)
    }
    fn undo_selected(
        &mut self,
        ids: &[String],
        progress: &mut dyn FnMut(Progress<'_>),
    ) -> anyhow::Result<Report> {
        self.report(Request::UndoSelected { ids: ids.to_vec() }, progress)
    }
    fn history(&mut self) -> anyhow::Result<Vec<String>> {
        match self.ask(&Request::History, &mut |_| {})? {
            Reply::History(lines) => Ok(lines),
            _ => anyhow::bail!(BAD_ANSWER),
        }
    }
    fn can_start(&mut self, undo: bool) -> anyhow::Result<()> {
        self.unit(Request::CanStart { undo })
    }
    fn choose_items(&mut self, picked: ItemChoice) -> anyhow::Result<()> {
        self.unit(Request::ChooseItems { picked })
    }
}

/// Asks the helper to set the damaged undo history aside and begin a new one. It needs no open session, because a damaged history is why none could open.
pub fn start_fresh<T: Transport>(transport: &mut T) -> anyhow::Result<()> {
    let bytes = encode_request(&Request::StartFresh)?;
    let mut reply = None;
    transport.call(&bytes, &mut |event| {
        anyhow::ensure!(reply.is_none(), BAD_ANSWER);
        if let Event::Done(done) = decode_event(event)? {
            reply = Some(done);
        }
        Ok(())
    })?;
    match reply.ok_or_else(|| anyhow::anyhow!(NOT_INSTALLED))? {
        Reply::Ok => Ok(()),
        Reply::Failed(message) => anyhow::bail!(message),
        Reply::Damaged { kind, files } => Err(anyhow::Error::new(JournalDamaged { kind, files })),
        _ => anyhow::bail!(BAD_ANSWER),
    }
}

/// Asks the helper to take Secblitz's package off the computer. The answer only says the removal has started.
pub fn remove_self<T: Transport>(transport: &mut T) -> anyhow::Result<()> {
    let bytes = encode_request(&Request::RemoveSelf)?;
    let mut reply = None;
    transport.call(&bytes, &mut |event| {
        anyhow::ensure!(reply.is_none(), BAD_ANSWER);
        if let Event::Done(done) = decode_event(event)? {
            reply = Some(done);
        }
        Ok(())
    })?;
    match reply.ok_or_else(|| anyhow::anyhow!(NOT_INSTALLED))? {
        Reply::Ok => Ok(()),
        Reply::Failed(message) => anyhow::bail!(message),
        _ => anyhow::bail!(BAD_ANSWER),
    }
}

/// Sends one request that needs no open session and returns its final reply.
fn ask_once<T: Transport>(transport: &mut T, request: &Request) -> anyhow::Result<Reply> {
    let bytes = encode_request(request)?;
    let mut reply = None;
    transport.call(&bytes, &mut |event| {
        anyhow::ensure!(reply.is_none(), BAD_ANSWER);
        if let Event::Done(done) = decode_event(event)? {
            reply = Some(done);
        }
        Ok(())
    })?;
    match reply.ok_or_else(|| anyhow::anyhow!(NOT_INSTALLED))? {
        Reply::Failed(message) => anyhow::bail!(message),
        reply => Ok(reply),
    }
}

/// Turns the daily background check on or off.
pub fn set_monitor_timer<T: Transport>(transport: &mut T, on: bool) -> anyhow::Result<()> {
    match ask_once(transport, &Request::MonitorTimer { on })? {
        Reply::Ok => Ok(()),
        _ => anyhow::bail!(BAD_ANSWER),
    }
}

/// What the last background check found.
pub fn update_status<T: Transport>(transport: &mut T) -> anyhow::Result<UpdateStatus> {
    match ask_once(transport, &Request::UpdateStatus)? {
        Reply::Update(status) => Ok(status),
        _ => anyhow::bail!(BAD_ANSWER),
    }
}

/// Looks for a new version now and returns what was found.
pub fn check_update<T: Transport>(transport: &mut T) -> anyhow::Result<UpdateStatus> {
    match ask_once(transport, &Request::CheckUpdate)? {
        Reply::Update(status) => Ok(status),
        _ => anyhow::bail!(BAD_ANSWER),
    }
}

/// Installs the waiting version when no software repository looks after Secblitz.
pub fn install_update<T: Transport>(transport: &mut T) -> anyhow::Result<UpdateStatus> {
    match ask_once(transport, &Request::InstallUpdate)? {
        Reply::Update(status) => Ok(status),
        _ => anyhow::bail!(BAD_ANSWER),
    }
}

/// An in-process transport: the helper side runs in the same process.
pub struct Loopback<'a> {
    pub session: &'a mut dyn Session,
}

impl Transport for Loopback<'_> {
    fn call(
        &mut self,
        request: &[u8],
        on_event: &mut dyn FnMut(&[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let request = decode_request(request)?;
        let mut failure = None;
        serve(self.session, request, &mut |event| {
            if failure.is_some() {
                return;
            }
            let sent = serde_json::to_vec(&event)
                .map_err(Into::into)
                .and_then(|bytes| on_event(&bytes));
            if let Err(error) = sent {
                failure = Some(error);
            }
        });
        failure.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        log: Vec<String>,
        fail: bool,
    }

    fn report(tag: &str) -> Report {
        Report {
            transaction: Some(tag.to_owned()),
            ..Report::default()
        }
    }

    impl Session for Fake {
        fn available(&self) -> Vec<String> {
            vec!["a".into(), "b".into()]
        }
        fn restart_ids(&self) -> Vec<String> {
            vec!["b".into()]
        }
        fn choose_items(&mut self, picked: ItemChoice) -> anyhow::Result<()> {
            self.log.push(format!("choose {picked:?}"));
            Ok(())
        }
        fn audit(&mut self, progress: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
            self.log.push("audit".into());
            progress(Progress::new("a", ProgressStep::Pending));
            progress(Progress::new(
                "a",
                ProgressStep::Result(CheckStatus::Compliant),
            ));
            progress(Progress::new("readiness", ProgressStep::Complete));
            progress(Progress::new(
                "a",
                ProgressStep::Result(CheckStatus::Other("odd".into())),
            ));
            Ok(report("audit"))
        }
        fn apply(
            &mut self,
            ids: &[String],
            progress: &mut dyn FnMut(Progress<'_>),
        ) -> anyhow::Result<Report> {
            self.log.push(format!("apply {}", ids.join(",")));
            for id in ids {
                progress(Progress::new(
                    id,
                    ProgressStep::Result(CheckStatus::Applied),
                ));
            }
            if self.fail {
                anyhow::bail!("disk full");
            }
            Ok(report("apply"))
        }
        fn undo(&mut self, progress: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
            self.log.push("undo".into());
            progress(Progress::new(
                "a",
                ProgressStep::Result(CheckStatus::Restored),
            ));
            Ok(report("undo"))
        }
        fn undo_selected(
            &mut self,
            ids: &[String],
            progress: &mut dyn FnMut(Progress<'_>),
        ) -> anyhow::Result<Report> {
            self.log.push(format!("undo_selected {}", ids.join(",")));
            for id in ids {
                progress(Progress::new(
                    id,
                    ProgressStep::Result(CheckStatus::Restored),
                ));
            }
            Ok(report("undo_selected"))
        }
        fn history(&mut self) -> anyhow::Result<Vec<String>> {
            Ok(vec!["tx applied".into()])
        }
        fn can_start(&mut self, undo: bool) -> anyhow::Result<()> {
            self.log.push(format!("can_start {undo}"));
            if self.fail && !undo {
                anyhow::bail!("Repair readiness blocks new changes");
            }
            Ok(())
        }
    }

    type Seen = Vec<(String, String)>;

    fn collector(seen: &mut Seen) -> impl FnMut(Progress<'_>) + '_ {
        |p| seen.push((p.id.to_owned(), p.step.as_str().to_owned()))
    }

    fn json(report: &Report) -> String {
        serde_json::to_string(report).unwrap()
    }

    #[test]
    fn remote_session_matches_the_session_it_wraps() {
        let mut direct = Fake::default();
        let mut wrapped = Fake::default();
        let mut remote = RemoteSession::connect(Loopback {
            session: &mut wrapped,
        })
        .unwrap();
        assert_eq!(remote.available(), direct.available());
        assert_eq!(remote.restart_ids(), direct.restart_ids());

        let ids = vec!["a".to_owned(), "b.c-d_1".to_owned()];
        let picked = ItemChoice::from([("a".to_owned(), vec!["Add-on one".to_owned()])]);
        let (mut want, mut got) = (Seen::new(), Seen::new());

        let a = direct.audit(&mut collector(&mut want)).unwrap();
        let b = remote.audit(&mut collector(&mut got)).unwrap();
        assert_eq!(json(&a), json(&b));
        let a = direct.apply(&ids, &mut collector(&mut want)).unwrap();
        let b = remote.apply(&ids, &mut collector(&mut got)).unwrap();
        assert_eq!(json(&a), json(&b));
        let a = direct.undo(&mut collector(&mut want)).unwrap();
        let b = remote.undo(&mut collector(&mut got)).unwrap();
        assert_eq!(json(&a), json(&b));
        let a = direct
            .undo_selected(&ids, &mut collector(&mut want))
            .unwrap();
        let b = remote
            .undo_selected(&ids, &mut collector(&mut got))
            .unwrap();
        assert_eq!(json(&a), json(&b));
        assert_eq!(direct.history().unwrap(), remote.history().unwrap());
        direct.can_start(true).unwrap();
        remote.can_start(true).unwrap();
        direct.choose_items(picked.clone()).unwrap();
        remote.choose_items(picked).unwrap();

        assert_eq!(want, got);
        assert!(want.contains(&("a".into(), "odd".into())));
        drop(remote);
        assert_eq!(direct.log, wrapped.log);
    }

    #[test]
    fn a_failed_reply_keeps_its_plain_message() {
        let mut fake = Fake {
            fail: true,
            ..Fake::default()
        };
        let mut remote = RemoteSession::connect(Loopback { session: &mut fake }).unwrap();
        let ids = vec!["a".to_owned()];
        let mut seen = Seen::new();
        let error = remote.apply(&ids, &mut collector(&mut seen)).unwrap_err();
        assert_eq!(format!("{error:#}"), "disk full");
        assert_eq!(seen.len(), 1);
        let error = remote.can_start(false).unwrap_err();
        assert_eq!(format!("{error:#}"), "Repair readiness blocks new changes");
    }

    #[test]
    fn a_silent_helper_reads_as_not_installed() {
        struct Silent;
        impl Transport for Silent {
            fn call(
                &mut self,
                _: &[u8],
                _: &mut dyn FnMut(&[u8]) -> anyhow::Result<()>,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }
        let error = RemoteSession::connect(Silent).err().unwrap();
        assert_eq!(format!("{error:#}"), NOT_INSTALLED);
    }

    fn envelope(request: &str) -> Vec<u8> {
        format!(r#"{{"v":{PROTOCOL},"request":{request}}}"#).into_bytes()
    }

    #[test]
    fn decoder_accepts_known_requests() {
        assert_eq!(
            decode_request(&envelope(r#"{"op":"audit"}"#)).unwrap(),
            Request::Audit
        );
        assert_eq!(
            decode_request(&envelope(r#"{"op":"apply","ids":["firewall.on","a_b-1"]}"#)).unwrap(),
            Request::Apply {
                ids: vec!["firewall.on".into(), "a_b-1".into()]
            }
        );
        let sent = Request::CanStart { undo: true };
        assert_eq!(
            decode_request(&encode_request(&sent).unwrap()).unwrap(),
            sent
        );
    }

    #[test]
    fn decoder_refuses_what_it_does_not_know() {
        let refused = |bytes: Vec<u8>| {
            assert!(
                decode_request(&bytes).is_err(),
                "{}",
                String::from_utf8_lossy(&bytes[..bytes.len().min(80)])
            )
        };
        refused(br#"{"v":1,"request":{"op":"audit"}}"#.to_vec());
        refused(br#"{"v":3,"request":{"op":"audit"}}"#.to_vec());
        refused(br#"{"request":{"op":"audit"}}"#.to_vec());
        refused(envelope(r#"{"op":"run_command","cmd":"id"}"#));
        refused(envelope(r#"{"op":"audit","extra":1}"#));
        refused(format!(r#"{{"v":{PROTOCOL},"request":{{"op":"audit"}},"extra":1}}"#).into_bytes());
        refused(envelope(r#"{"op":"apply","ids":["a/b"]}"#));
        refused(envelope(r#"{"op":"apply","ids":["Upper"]}"#));
        refused(envelope(r#"{"op":"apply","ids":[""]}"#));
        refused(envelope(&format!(
            r#"{{"op":"apply","ids":["{}"]}}"#,
            "a".repeat(MAX_ID_LEN + 1)
        )));
        let many = vec![r#""a""#; MAX_IDS + 1].join(",");
        refused(envelope(&format!(
            r#"{{"op":"undo_selected","ids":[{many}]}}"#
        )));
        refused(envelope(r#"{"op":"choose_items","picked":{"BAD":[]}}"#));
        refused(b"[]".to_vec());
        refused(b"{".to_vec());
        let mut big = envelope(r#"{"op":"audit"}"#);
        big.resize(MAX_MESSAGE + 1, b' ');
        refused(big);
    }

    #[test]
    fn decoder_accepts_the_largest_allowed_id_list() {
        let id = "a".repeat(MAX_ID_LEN);
        let ids = vec![format!("\"{id}\""); MAX_IDS].join(",");
        let request = decode_request(&envelope(&format!(r#"{{"op":"apply","ids":[{ids}]}}"#)));
        assert!(request.is_ok());
    }

    #[test]
    fn oversized_events_are_refused() {
        let mut bytes = br#"{"done":"ok"}"#.to_vec();
        bytes.resize(MAX_MESSAGE + 1, b' ');
        assert!(decode_event(&bytes).is_err());
    }

    struct Damaged;

    impl Session for Damaged {
        fn available(&self) -> Vec<String> {
            Vec::new()
        }
        fn restart_ids(&self) -> Vec<String> {
            Vec::new()
        }
        fn audit(&mut self, _: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
            Err(anyhow::Error::new(JournalDamaged {
                kind: DamageKind::Partial,
                files: 3,
            })
            .context("outer"))
        }
        fn apply(
            &mut self,
            _: &[String],
            _: &mut dyn FnMut(Progress<'_>),
        ) -> anyhow::Result<Report> {
            anyhow::bail!("disk full")
        }
        fn undo(&mut self, _: &mut dyn FnMut(Progress<'_>)) -> anyhow::Result<Report> {
            anyhow::bail!("disk full")
        }
        fn undo_selected(
            &mut self,
            _: &[String],
            _: &mut dyn FnMut(Progress<'_>),
        ) -> anyhow::Result<Report> {
            anyhow::bail!("disk full")
        }
        fn history(&mut self) -> anyhow::Result<Vec<String>> {
            anyhow::bail!("disk full")
        }
        fn can_start(&mut self, _: bool) -> anyhow::Result<()> {
            anyhow::bail!("disk full")
        }
    }

    #[test]
    fn a_damaged_undo_history_keeps_its_type_across_the_cut() {
        let reply = failure(&anyhow::Error::new(JournalDamaged {
            kind: DamageKind::OtherPc,
            files: 7,
        }));
        let bytes = serde_json::to_vec(&Event::Done(reply)).unwrap();
        let Event::Done(Reply::Damaged { kind, files }) = decode_event(&bytes).unwrap() else {
            panic!("the type was lost");
        };
        assert_eq!((kind, files), (DamageKind::OtherPc, 7));

        let mut damaged = Damaged;
        let mut remote = RemoteSession::connect(Loopback {
            session: &mut damaged,
        })
        .unwrap();
        let error = remote.audit(&mut |_| {}).unwrap_err();
        let damage = error.downcast_ref::<JournalDamaged>().unwrap();
        assert_eq!((damage.kind, damage.files), (DamageKind::Partial, 3));
        let error = remote.undo(&mut |_| {}).unwrap_err();
        assert!(error.downcast_ref::<JournalDamaged>().is_none());
        assert_eq!(format!("{error:#}"), "disk full");
    }

    #[test]
    fn the_update_requests_round_trip_and_refuse_extra_fields() {
        for (text, want) in [
            (
                r#"{"op":"monitor_timer","on":true}"#,
                Request::MonitorTimer { on: true },
            ),
            (
                r#"{"op":"monitor_timer","on":false}"#,
                Request::MonitorTimer { on: false },
            ),
            (r#"{"op":"update_status"}"#, Request::UpdateStatus),
            (r#"{"op":"check_update"}"#, Request::CheckUpdate),
            (r#"{"op":"install_update"}"#, Request::InstallUpdate),
        ] {
            assert_eq!(decode_request(&envelope(text)).unwrap(), want);
            assert_eq!(
                decode_request(&encode_request(&want).unwrap()).unwrap(),
                want
            );
        }
        for text in [
            r#"{"op":"monitor_timer"}"#,
            r#"{"op":"monitor_timer","on":"yes"}"#,
            r#"{"op":"monitor_timer","on":true,"unit":"ssh.service"}"#,
            r#"{"op":"install_update","url":"https://example.invalid/x.deb"}"#,
            r#"{"op":"update_status","path":"/etc/shadow"}"#,
        ] {
            assert!(decode_request(&envelope(text)).is_err(), "{text}");
        }
    }

    #[test]
    fn a_session_alone_does_not_answer_the_update_requests() {
        let mut fake = Fake::default();
        let error = set_monitor_timer(&mut Loopback { session: &mut fake }, true).unwrap_err();
        assert_eq!(format!("{error:#}"), NOT_HERE);
        assert!(update_status(&mut Loopback { session: &mut fake }).is_err());
        assert!(install_update(&mut Loopback { session: &mut fake }).is_err());
        assert!(fake.log.is_empty());
    }

    #[test]
    fn start_fresh_is_a_request_of_its_own_and_needs_no_session_to_say_so() {
        assert_eq!(
            decode_request(&envelope(r#"{"op":"start_fresh"}"#)).unwrap(),
            Request::StartFresh
        );
        let mut fake = Fake::default();
        let error = start_fresh(&mut Loopback { session: &mut fake }).unwrap_err();
        assert_eq!(format!("{error:#}"), NOT_DAMAGED);
        assert!(fake.log.is_empty());
    }
}
