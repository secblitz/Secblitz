//! The Secblitz program: the GUI, the command line, the launcher and the admin helper (`broker`). Logic that depends on neither the GUI nor the command line lives in the library crate (`lib.rs`).
#![cfg_attr(windows, windows_subsystem = "windows")]
mod app;
mod broker;
mod gui;
mod guide;
mod i18n;
mod launcher;
mod linux_bus;
mod tray;
mod uninstall;

use anyhow::{bail, Result};
use clap::{Arg, ArgAction, ArgMatches, Command};
use i18n::Lang;
use secblitz::{platform, service, updater};
use std::io::{self, IsTerminal, Write};

fn command(lang: Lang) -> Command {
    fn text(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }
    let sub = |name, key| Command::new(name).about(text(lang.t(key)));
    let cmd = Command::new("secblitz")
        .version(env!("CARGO_PKG_VERSION"))
        .about(text(lang.t("A safer computer. Without headaches.")))
        .arg(
            Arg::new("lang")
                .long("lang")
                .global(true)
                .value_name("en|es|fr|de|pt|it")
                .hide_possible_values(true)
                .value_parser(["en", "es", "fr", "de", "pt", "it"])
                .help(text(lang.t("Language (default: Windows display language)"))),
        )
        .arg(
            Arg::new("open")
                .long("open")
                .value_name("page")
                .hide(true)
                .num_args(1),
        )
        .arg(
            Arg::new("no-animation")
                .long("no-animation")
                .global(true)
                .action(ArgAction::SetTrue)
                .help(text(lang.t("Disable terminal animation"))),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help(text(
                    lang.t("Output raw JSON reports (including update check/status)"),
                )),
        )
        .arg(
            Arg::new("details")
                .long("details")
                .global(true)
                .action(ArgAction::SetTrue)
                .help(text(lang.t("Show technical report details"))),
        )
        .subcommand(
            sub("update", "Keep Secblitz up to date")
                .subcommand_required(true)
                .subcommand(sub("check", "Check for Secblitz updates"))
                .subcommand(sub("status", "Show the latest update status"))
                .subcommand(Command::new("health").hide(true))
                .subcommand(Command::new("install-staged").hide(true)),
        )
        .subcommand(
            sub("service", "Manage the optional service")
                .subcommand_required(true)
                .subcommand(sub("install", "Install the service"))
                .subcommand(sub("start", "Start the optional monitoring service"))
                .subcommand(sub("uninstall", "Uninstall the service"))
                .subcommand(sub("status", "Query service status"))
                .subcommand(sub("run", "Run the service dispatcher")),
        )
        .subcommand(
            Command::new("uninstall-revert")
                .hide(true)
                .arg(Arg::new("user").long("user").action(ArgAction::SetTrue)),
        )
        .subcommand(Command::new("helper").hide(true))
        .subcommand(Command::new("monitor-once").hide(true))
        .subcommand(
            Command::new("uninstall-cleanup").hide(true).arg(
                Arg::new("user")
                    .long("user")
                    .action(ArgAction::SetTrue)
                    .required(true),
            ),
        )
        .subcommand(
            Command::new("filter")
                .hide(true)
                .subcommand_required(true)
                .subcommand(Command::new("run").hide(true))
                .subcommand(Command::new("reconcile").hide(true))
                .subcommand(Command::new("install").hide(true))
                .subcommand(Command::new("uninstall").hide(true))
                .subcommand(
                    Command::new("allow-once")
                        .hide(true)
                        .arg(Arg::new("site").required(true).value_parser(clean_site)),
                ),
        );
    #[cfg(target_os = "linux")]
    let cmd = cmd.mut_subcommand("filter", |filter| {
        filter
            .subcommand(Command::new("add-rule").hide(true))
            .subcommand(Command::new("remove-rule").hide(true))
    });
    fn localize(cmd: Command, lang: Lang, parent: &str) -> Command {
        let path = if parent.is_empty() {
            cmd.get_name().to_owned()
        } else {
            format!("{parent} {}", cmd.get_name())
        };
        let suffix = if cmd.get_subcommands().next().is_some() {
            if parent.is_empty() {
                format!(" [{}]", lang.t("Commands"))
            } else {
                format!(" <{}>", lang.t("Commands"))
            }
        } else {
            String::new()
        };
        let positional = cmd
            .get_positionals()
            .map(|arg| {
                let name = arg
                    .get_value_names()
                    .and_then(|v| v.first())
                    .map(|v| v.as_str())
                    .unwrap_or(arg.get_id().as_str());
                format!(" <{name}>")
            })
            .collect::<String>();
        let usage = format!("{path} [{}]{positional}{suffix}", lang.t("Options"));
        let template = format!("{{before-help}}{{name}} {{version}}\n{{about-with-newline}}\n{}: {{usage}}\n\n{{all-args}}{{after-help}}", lang.t("Usage"));
        cmd.disable_help_flag(true)
            .disable_version_flag(true)
            .disable_help_subcommand(true)
            .override_usage(Box::leak(usage.into_boxed_str()) as &'static str)
            .help_template(Box::leak(template.into_boxed_str()) as &'static str)
            .subcommand_help_heading(Box::leak(lang.t("Commands").into_boxed_str()) as &'static str)
            .next_help_heading(Box::leak(lang.t("Options").into_boxed_str()) as &'static str)
            .arg(
                Arg::new("help")
                    .short('h')
                    .long("help")
                    .action(ArgAction::Help)
                    .help(Box::leak(lang.t("Show help").into_boxed_str()) as &'static str),
            )
            .mut_args(|a| {
                a.help_heading(Box::leak(lang.t("Options").into_boxed_str()) as &'static str)
            })
            .mut_subcommands(|c| localize(c, lang, &path))
    }
    let cmd = localize(cmd, lang, "");
    cmd.arg(
        Arg::new("version")
            .short('V')
            .long("version")
            .action(ArgAction::Version)
            .help(text(lang.t("Show version"))),
    )
}

fn selected_language(args: &[std::ffi::OsString]) -> Lang {
    let mut lang = Lang::detect();
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        let value = if arg == "--lang" {
            args.next().and_then(|s| s.to_str())
        } else {
            arg.to_str().and_then(|s| s.strip_prefix("--lang="))
        };
        if let Some(value) = value.and_then(Lang::parse) {
            lang = value;
        }
    }
    lang
}

fn elevated_args(matches: &ArgMatches, lang: Lang) -> Vec<String> {
    let mut args = vec!["--lang".into(), lang.code().into()];
    for flag in ["no-animation", "json", "details"] {
        if matches.get_flag(flag) {
            args.push(format!("--{flag}"));
        }
    }
    if let Some((name, sub)) = matches.subcommand() {
        match name {
            "update" => {
                if let Some(action @ ("check" | "status")) = sub.subcommand_name() {
                    args.extend(["update".into(), action.into()]);
                } else {
                    unreachable!();
                }
            }
            "service" => {
                args.push("service".into());
                if let Some(name @ ("install" | "start" | "uninstall" | "status")) =
                    sub.subcommand_name()
                {
                    args.push(name.into());
                }
            }
            _ => unreachable!(),
        }
    }
    args
}

fn execute(matches: &ArgMatches, lang: Lang) -> Result<i32> {
    if matches.subcommand_matches("helper").is_some() {
        #[cfg(target_os = "linux")]
        {
            linux_bus::helper::run_installed()?;
            return Ok(0);
        }
        #[cfg(not(target_os = "linux"))]
        bail!(launcher::NOT_INSTALLED);
    }
    if matches.subcommand_matches("monitor-once").is_some() {
        #[cfg(target_os = "linux")]
        return monitor_once(lang);
        #[cfg(not(target_os = "linux"))]
        bail!(launcher::NOT_INSTALLED);
    }
    if update_command(matches) == Some(UpdateCommand::Health) {
        anyhow::ensure!(matches.get_flag("json"), "update-health-requires-json");
        return write_health(updater::health()?, &mut io::stdout().lock());
    }
    if let Some(command) = uninstall_command(matches) {
        return execute_uninstall(command, matches.get_flag("json"), lang);
    }
    if let Some(filter) = matches.subcommand_matches("filter") {
        #[cfg(target_os = "linux")]
        if let Some(action) = filter_command(matches) {
            return run_filter_linux(action);
        }
        return match filter.subcommand_name() {
            Some("run") => {
                secblitz::filter::service::run()?;
                Ok(0)
            }
            _ => match filter_command(matches) {
                Some(action) => run_filter_request(action, platform::is_elevated, run_filter),
                None => unreachable!(),
            },
        };
    }
    let json = matches.get_flag("json");
    if json && !json_allowed(matches) {
        bail!(lang.t(
            "JSON is available only for report commands, not interactive guides or desktop tools."
        ));
    }
    if let Some(action) = update_command(matches) {
        return execute_update(matches, lang, action);
    }
    let Some(service_action) = matches
        .subcommand_matches("service")
        .and_then(ArgMatches::subcommand_name)
    else {
        return launcher::run(lang, matches.get_one::<String>("open").map(String::as_str));
    };
    if service_action == "run" {
        service::run()?;
        return Ok(0);
    }
    if !platform::is_elevated()? {
        return elevate_and_wait(&elevated_args(matches, lang));
    }
    let mut out = io::stdout().lock();
    match service_action {
        "start" => {
            service::start()?;
            writeln!(
                out,
                "{}",
                lang.t(
                    "Monitoring is running. Check reports separately to verify their freshness."
                )
            )?;
        }
        "install" => {
            service::install()?;
            writeln!(out, "{}", lang.t("Installed SecblitzMonitor as LocalService; it has not been started. Binary and reports are retained on uninstall."))?;
        }
        "uninstall" => {
            service::uninstall()?;
            writeln!(out, "{}", lang.t("SecblitzMonitor registration is removed or was already absent. Binary, reports and journals are preserved."))?;
        }
        "status" => writeln!(out, "{}", service::status_details()?)?,
        _ => unreachable!(),
    }
    Ok(0)
}

/// The daily background check the packaged timer starts. It runs as root only and never changes the computer: it
/// looks at the signed update feed and keeps what it found for the window to show.
#[cfg(target_os = "linux")]
fn monitor_once(lang: Lang) -> Result<i32> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("{}", lang.t(updater::linux::NOT_ROOT));
        return Ok(2);
    }
    let outcome = updater::linux::check(&secblitz::linux::cmd::RealSys)?;
    Ok(i32::from(matches!(
        outcome,
        updater::UpdateOutcome::Failed { .. }
    )))
}

/// A site name exactly as Web protection writes it, so the argument cannot be anything else.
fn clean_site(value: &str) -> Result<String, String> {
    secblitz::filter::config::normalized_site(value)
        .filter(|site| site == value)
        .ok_or_else(String::new)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FilterCommand {
    Reconcile,
    Install,
    Uninstall,
    AllowOnce(String),
    #[cfg(target_os = "linux")]
    AddRule,
    #[cfg(target_os = "linux")]
    RemoveRule,
}

fn filter_command(matches: &ArgMatches) -> Option<FilterCommand> {
    let filter = matches.subcommand_matches("filter")?;
    match filter.subcommand()? {
        ("reconcile", _) => Some(FilterCommand::Reconcile),
        ("install", _) => Some(FilterCommand::Install),
        ("uninstall", _) => Some(FilterCommand::Uninstall),
        ("allow-once", sub) => Some(FilterCommand::AllowOnce(
            sub.get_one::<String>("site")?.clone(),
        )),
        #[cfg(target_os = "linux")]
        ("add-rule", _) => Some(FilterCommand::AddRule),
        #[cfg(target_os = "linux")]
        ("remove-rule", _) => Some(FilterCommand::RemoveRule),
        ("run", _) => None,
        _ => unreachable!(),
    }
}

/// The unit's own steps and the package's. Only root runs them; anyone else gets exit code 2 and nothing happens.
#[cfg(target_os = "linux")]
fn run_filter_linux(action: FilterCommand) -> Result<i32> {
    use secblitz::linux::cmd::RealSys;
    use secblitz::linux::web;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(2);
    }
    let sys = RealSys;
    let now = secblitz::filter::server::unix_now();
    match action {
        FilterCommand::Reconcile => web::reconcile(&sys, web::service_state(&sys), now)?,
        FilterCommand::Install => {}
        FilterCommand::Uninstall => web::remove_everything(&sys)?,
        FilterCommand::AllowOnce(site) => web::allow_site_once(&sys, &site, now)?,
        FilterCommand::AddRule => web::add_rule_when_ready(&sys, now)?,
        FilterCommand::RemoveRule => web::remove_rule(&sys)?,
    }
    Ok(0)
}

/// Runs only for an administrator or SYSTEM; anyone else gets exit code 2
/// and nothing happens (these commands never ask for elevation).
fn run_filter_request(
    action: FilterCommand,
    elevated: impl FnOnce() -> Result<bool>,
    run: impl FnOnce(FilterCommand) -> Result<()>,
) -> Result<i32> {
    if !elevated()? {
        return Ok(2);
    }
    run(action)?;
    Ok(0)
}

fn run_filter(action: FilterCommand) -> Result<()> {
    #[cfg(windows)]
    {
        use secblitz::filter::control;
        match action {
            FilterCommand::Reconcile => control::reconcile(),
            FilterCommand::Install => control::install_all(),
            FilterCommand::Uninstall => control::remove_everything(),
            FilterCommand::AllowOnce(site) => control::allow_site_once(&site),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        platform::backend().map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpdateCommand {
    Check,
    Status,
    InstallStaged,
    Health,
}

fn update_command(matches: &ArgMatches) -> Option<UpdateCommand> {
    match matches.subcommand_matches("update")?.subcommand_name()? {
        "check" => Some(UpdateCommand::Check),
        "status" => Some(UpdateCommand::Status),
        "install-staged" => Some(UpdateCommand::InstallStaged),
        "health" => Some(UpdateCommand::Health),
        _ => unreachable!(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UninstallCommand {
    Revert,
    RevertUser,
    CleanupUser,
}

fn uninstall_command(matches: &ArgMatches) -> Option<UninstallCommand> {
    let (name, sub) = matches.subcommand()?;
    match name {
        "uninstall-revert" if sub.get_flag("user") => Some(UninstallCommand::RevertUser),
        "uninstall-revert" => Some(UninstallCommand::Revert),
        "uninstall-cleanup" => Some(UninstallCommand::CleanupUser),
        _ => None,
    }
}

#[cfg(windows)]
const UNINSTALL_REFUSED: i32 = 2;
#[cfg(windows)]
fn execute_uninstall(command: UninstallCommand, json: bool, lang: Lang) -> Result<i32> {
    use uninstall::{left_line, Summary};
    fn print(summary: &Summary, json: bool, lang: Lang) {
        // Output problems (no console, closed pipe) must never change the exit code.
        let mut out = io::stdout().lock();
        if json {
            let _ = serde_json::to_writer(&mut out, summary);
            let _ = writeln!(out);
        } else {
            for left in &summary.left {
                let _ = writeln!(out, "{}", left_line(left, lang));
            }
        }
    }
    match command {
        UninstallCommand::Revert => {
            if !platform::is_elevated_or_false() {
                return Ok(UNINSTALL_REFUSED);
            }
            print(&uninstall::revert_machine(&|_, _| {}), json, lang);
            Ok(0)
        }
        UninstallCommand::RevertUser => {
            let summary = uninstall::revert_user();
            print(&summary, json, lang);
            Ok(summary.left.len().min(6) as i32)
        }
        UninstallCommand::CleanupUser => Ok(i32::from(uninstall::cleanup_user().is_err())),
    }
}

#[cfg(not(windows))]
fn execute_uninstall(_: UninstallCommand, _: bool, _: Lang) -> Result<i32> {
    Ok(1)
}

fn json_allowed(matches: &ArgMatches) -> bool {
    matches!(
        update_command(matches),
        Some(UpdateCommand::Check | UpdateCommand::Status | UpdateCommand::Health)
    )
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum UpdateReport {
    Outcome(updater::UpdateOutcome),
    Status(updater::UpdateStatus),
}

impl UpdateReport {
    fn outcome(&self) -> &updater::UpdateOutcome {
        match self {
            Self::Outcome(outcome) => outcome,
            Self::Status(status) => &status.result,
        }
    }

    fn message(&self) -> &'static str {
        use updater::UpdateOutcome;
        if matches!(self, Self::Status(status) if status.checked_at == 0 && matches!(status.result, UpdateOutcome::NotConfigured))
        {
            return "No update information yet.";
        }
        match self.outcome() {
            UpdateOutcome::NotConfigured => "Updates aren't available for this installation.",
            UpdateOutcome::UpToDate => "Secblitz is up to date.",
            UpdateOutcome::NotPublished => "No update has been published for your computer yet.",
            UpdateOutcome::DeferredBusy => "We'll try updating when Secblitz is closed.",
            UpdateOutcome::DeferredRollout { .. } => {
                "This update is not yet offered to this device."
            }
            UpdateOutcome::WorkerStarted { .. } => {
                "Your update is ready. Close Secblitz so the installer can continue."
            }
            UpdateOutcome::Installed { .. } => "Secblitz was updated.",
            UpdateOutcome::Available { .. } => "A newer version of Secblitz is ready to install.",
            UpdateOutcome::Failed { .. } => "The update could not be completed. Check your internet connection and try again later. If it keeps happening, download the latest Secblitz from our website.",
        }
    }
}

enum UpdateRun {
    ElevatedExit(i32),
    Report(UpdateReport),
}

/// Worker authorization belongs to the core. In particular, even a manually
/// invoked worker must reach its path/token checks without a UAC relaunch.
fn run_update_request(
    action: UpdateCommand,
    interactive: bool,
    json: bool,
    elevated: impl FnOnce() -> Result<bool>,
    elevate: impl FnOnce() -> Result<i32>,
    run: impl FnOnce(UpdateCommand) -> Result<UpdateReport>,
) -> Result<UpdateRun> {
    if !matches!(action, UpdateCommand::InstallStaged | UpdateCommand::Health) && !elevated()? {
        anyhow::ensure!(
            interactive && !json,
            "Run update commands from an administrator terminal."
        );
        return elevate().map(UpdateRun::ElevatedExit);
    }
    run(action).map(UpdateRun::Report)
}

fn execute_update(matches: &ArgMatches, lang: Lang, action: UpdateCommand) -> Result<i32> {
    let interactive = action != UpdateCommand::InstallStaged
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal();
    let json = matches.get_flag("json");
    let result = run_update_request(
        action,
        interactive,
        json,
        platform::is_elevated,
        || {
            eprintln!("{}", lang.t("Requesting administrator access"));
            elevate_and_wait(&elevated_args(matches, lang))
        },
        |action| match action {
            UpdateCommand::Check => updater::check_and_stage().map(UpdateReport::Outcome),
            UpdateCommand::Status => updater::status().map(UpdateReport::Status),
            UpdateCommand::InstallStaged => updater::install_staged().map(UpdateReport::Outcome),
            UpdateCommand::Health => unreachable!(),
        },
    );
    write_update_result(
        result,
        lang,
        json,
        interactive,
        matches.get_flag("details"),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

fn write_health(health: updater::UpdateHealth, out: &mut impl Write) -> Result<i32> {
    serde_json::to_writer(&mut *out, &health)?;
    writeln!(out)?;
    Ok(0)
}

fn write_update_result(
    result: Result<UpdateRun>,
    lang: Lang,
    json: bool,
    interactive: bool,
    details: bool,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<i32> {
    let (report, failure) = match result {
        Ok(UpdateRun::ElevatedExit(code)) => return Ok(code),
        Ok(UpdateRun::Report(report)) => (report, None),
        Err(error) => (
            UpdateReport::Outcome(updater::UpdateOutcome::Failed {
                reason: "The update could not be completed.".into(),
            }),
            Some(error),
        ),
    };
    let failed = matches!(report.outcome(), updater::UpdateOutcome::Failed { .. });
    if json {
        serde_json::to_writer(&mut *out, &report)?;
        writeln!(out)?;
    } else if interactive {
        writeln!(out, "{}", lang.t(report.message()))?;
        if failed {
            if details {
                if let Some(error) = failure {
                    writeln!(err, "{error:#}")?;
                } else if let updater::UpdateOutcome::Failed { reason } = report.outcome() {
                    writeln!(err, "{reason}")?;
                }
            } else {
                writeln!(err, "{}", lang.t("Run update status --details from an administrator terminal for more information."))?;
            }
        }
    }
    Ok(i32::from(failed))
}

fn elevate_and_wait(args: &[String]) -> Result<i32> {
    launcher::elevate_and_wait(args)
}

fn first_word(args: &[std::ffi::OsString]) -> Option<&str> {
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--lang" || arg == "--open" {
            args.next();
            continue;
        }
        let arg = arg.to_str()?;
        if !arg.starts_with("--") {
            return Some(arg);
        }
    }
    None
}

fn flag_value<'a>(args: &'a [std::ffi::OsString], flag: &str) -> Option<&'a str> {
    let at = args.iter().position(|a| a == flag)?;
    args.get(at + 1)?.to_str()
}

fn run_gui(args: &[std::ffi::OsString], lang: Lang) -> i32 {
    let result = (|| -> Result<i32> {
        let broker = flag_value(args, "--broker")
            .filter(|id| broker::valid_id(id))
            .map(str::to_owned);
        let open = flag_value(args, "--open");
        let start = flag_value(args, "--self-test")
            .and_then(gui::Page::parse)
            .or_else(|| open.map(gui::Page::open_target))
            .map(|page| page.on(secblitz::os::Os::CURRENT));
        #[cfg(windows)]
        {
            if !platform::is_elevated_or_false() {
                return launcher::run(lang, open);
            }
            if broker.is_none() && launcher::reopen_normally(lang, open) {
                return Ok(0);
            }
        }
        let _guard = match launcher::single_instance(open)? {
            launcher::Instance::First(guard) => guard,
            launcher::Instance::Existing => return Ok(0),
        };
        gui::run(gui::Options {
            lang,
            broker,
            start,
        })?;
        Ok(0)
    })();
    result.unwrap_or_else(|error| {
        launcher::show_failure(lang, &error);
        1
    })
}

fn dispatch_gui(args: &[std::ffi::OsString], lang: Lang) -> Option<i32> {
    match first_word(args) {
        Some("gui") => Some(run_gui(args, lang)),
        Some("tray") => Some(tray::run(lang).unwrap_or(1)),
        Some("warn") => Some(gui::warn::run(args, lang)),
        #[cfg(not(windows))]
        None if opens_window(args) => Some(run_gui(args, lang)),
        _ => None,
    }
}

/// Off Windows there is no elevation launcher: the menu entry starts the window
/// directly, with nothing but a language or a page to open.
#[cfg(not(windows))]
fn opens_window(args: &[std::ffi::OsString]) -> bool {
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next() {
        if !(arg == "--lang" || arg == "--open") || args.next().is_none() {
            return false;
        }
    }
    true
}

fn main() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{
            SetDefaultDllDirectories, SetDllDirectoryW, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        };
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        SetDllDirectoryW([0u16].as_ptr());
    }
    let args: Vec<_> = std::env::args_os().collect();
    let lang = selected_language(&args);
    if let Some(code) = dispatch_gui(&args, lang) {
        std::process::exit(code);
    }
    let json_requested = args.iter().any(|a| a == "--json");
    let mut update = false;
    let mut gui_entry = false;
    let mut plumbing = false;
    let result = match command(lang).try_get_matches_from(args) {
        Ok(matches) => {
            update = update_command(&matches).is_some();
            gui_entry = matches.subcommand_name().is_none();
            plumbing = matches!(
                matches.subcommand_name(),
                Some("filter" | "uninstall-revert" | "uninstall-cleanup" | "monitor-once")
            );
            execute(&matches, lang)
        }
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            Ok(0)
        }
        Err(_) => {
            // Clap's parser diagnostics are English-only. Use a localized
            // diagnostic rather than leaking untranslated generated prose.
            if json_requested {
                let _ = writeln!(
                    io::stdout(),
                    "{}",
                    serde_json::json!({"error":{"code":"invalid_command", "message":lang.t("Invalid command")}})
                );
            } else {
                eprintln!(
                    "{} - {}",
                    lang.t("Invalid command"),
                    lang.t("Use --help for usage.")
                );
            }
            Ok(2)
        }
    };
    let code = match result {
        Ok(code) => code,
        Err(error) => {
            if gui_entry {
                launcher::show_failure(lang, &error);
            } else if json_requested && !update {
                let _ = writeln!(
                    io::stdout(),
                    "{}",
                    serde_json::json!({"error":{"code":"operation_failed", "message":lang.t("Operation failed")}})
                );
            } else if plumbing {
                eprintln!("{}: {error:#}", lang.t("Operation failed"));
            } else if !update {
                eprintln!("{}", lang.t("Operation failed"));
            }
            1
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Windows shows these file details in Properties and Task Manager, and
    /// security products read them. They must name this exact release.
    #[test]
    fn windows_file_details_match_the_package_version() {
        let version = env!("CARGO_PKG_VERSION");
        let numbers = format!("{},0", version.replace('.', ","));
        let rc = include_str!("../assets/secblitz.rc");
        for line in [
            format!("FILEVERSION {numbers}"),
            format!("PRODUCTVERSION {numbers}"),
            format!("VALUE \"FileVersion\", \"{version}\""),
            format!("VALUE \"ProductVersion\", \"{version}\""),
        ] {
            assert!(rc.contains(&line), "secblitz.rc lacks {line}");
        }
        for name in [
            "CompanyName",
            "FileDescription",
            "ProductName",
            "OriginalFilename",
            "LegalCopyright",
        ] {
            assert!(
                rc.contains(&format!("VALUE \"{name}\"")),
                "secblitz.rc lacks {name}"
            );
        }
        let manifest = include_str!("../assets/secblitz.manifest");
        assert!(
            manifest.contains(&format!("version=\"{version}.0\"")),
            "secblitz.manifest names another version"
        );
    }

    #[test]
    fn health_is_raw_json_and_routes_before_privilege_or_state_access() {
        let health = updater::UpdateHealth {
            schema: 1,
            version: "0.5.0".into(),
            task: updater::TaskHealth::Ready,
            monitor: updater::MonitorHealth::Stopped,
        };
        let mut bytes = Vec::new();
        assert_eq!(write_health(health.clone(), &mut bytes).unwrap(), 0);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::to_value(health).unwrap()
        );
        assert_eq!(bytes.last(), Some(&b'\n'));
        let matches = command(Lang::En)
            .try_get_matches_from(["secblitz", "update", "health", "--json"])
            .unwrap();
        assert!(json_allowed(&matches));
        #[cfg(not(windows))]
        assert_eq!(
            execute(&matches, Lang::En).unwrap_err().to_string(),
            "Update health requires Windows"
        );
        let no_json = command(Lang::En)
            .try_get_matches_from(["secblitz", "update", "health"])
            .unwrap();
        assert_eq!(
            execute(&no_json, Lang::En).unwrap_err().to_string(),
            "update-health-requires-json"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_bare_start_opens_the_window_but_commands_and_help_do_not() {
        let words = |list: &[&str]| -> Vec<std::ffi::OsString> {
            std::iter::once("secblitz")
                .chain(list.iter().copied())
                .map(Into::into)
                .collect()
        };
        assert!(opens_window(&words(&[])));
        assert!(opens_window(&words(&["--lang", "fr"])));
        assert!(opens_window(&words(&["--open", "network", "--lang", "de"])));
        for other in [
            &["--help"][..],
            &["--version"],
            &["--lang"],
            &["check"],
            &["--json"],
        ] {
            assert!(!opens_window(&words(other)), "{other:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_filter_units_steps_are_hidden_take_no_arguments_and_only_root_runs_them() {
        let root = command(Lang::En);
        let filter = root.find_subcommand("filter").unwrap();
        for (word, expected) in [
            ("add-rule", FilterCommand::AddRule),
            ("remove-rule", FilterCommand::RemoveRule),
        ] {
            assert!(
                filter.find_subcommand(word).unwrap().is_hide_set(),
                "{word}"
            );
            let matches = command(Lang::En)
                .try_get_matches_from(["secblitz", "filter", word])
                .unwrap();
            assert_eq!(filter_command(&matches), Some(expected.clone()));
            assert!(!json_allowed(&matches));
            assert!(command(Lang::En)
                .try_get_matches_from(["secblitz", "filter", word, "extra"])
                .is_err());
            // SAFETY: geteuid has no preconditions and cannot fail.
            if unsafe { libc::geteuid() } != 0 {
                assert_eq!(run_filter_linux(expected).unwrap(), 2);
            }
        }
    }

    #[test]
    fn filter_commands_are_hidden_and_never_elevate() {
        let root = command(Lang::En);
        let filter = root.find_subcommand("filter").unwrap();
        assert!(filter.is_hide_set());
        for (words, expected) in [
            (&["reconcile"][..], FilterCommand::Reconcile),
            (&["install"][..], FilterCommand::Install),
            (&["uninstall"][..], FilterCommand::Uninstall),
            (
                &["allow-once", "evil.example"][..],
                FilterCommand::AllowOnce("evil.example".into()),
            ),
        ] {
            assert!(filter.find_subcommand(words[0]).unwrap().is_hide_set());
            let matches = command(Lang::En)
                .try_get_matches_from(
                    ["secblitz", "filter"]
                        .into_iter()
                        .chain(words.iter().copied()),
                )
                .unwrap();
            assert_eq!(filter_command(&matches), Some(expected.clone()));
            assert!(!json_allowed(&matches));
            let code = run_filter_request(
                expected.clone(),
                || Ok(false),
                |_| panic!("an unelevated caller must not run web protection changes"),
            )
            .unwrap();
            assert_eq!(code, 2);
            let mut ran = None;
            let code = run_filter_request(
                expected.clone(),
                || Ok(true),
                |a| {
                    ran = Some(a);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!((code, ran), (0, Some(expected)));
        }
        for bad in [
            &["allow-once"][..],
            &["allow-once", "Evil.example"][..],
            &["allow-once", "evil.example."][..],
            &["allow-once", "https://evil.example"][..],
            &["allow-once", "evil"][..],
            &["allow-once", "a.example", "b.example"][..],
        ] {
            assert!(
                command(Lang::En)
                    .try_get_matches_from(
                        ["secblitz", "filter"]
                            .into_iter()
                            .chain(bad.iter().copied())
                    )
                    .is_err(),
                "{bad:?}"
            );
        }
        assert!(command(Lang::En)
            .try_get_matches_from(["secblitz", "filter"])
            .is_err());
        assert!(command(Lang::En)
            .try_get_matches_from(["secblitz", "filter", "unknown"])
            .is_err());
        let help = command(Lang::En).render_help().to_string();
        assert!(!help.contains("filter"), "{help}");
    }

    #[test]
    fn the_background_check_is_hidden_and_takes_nothing() {
        let matches = command(Lang::En)
            .try_get_matches_from(["secblitz", "monitor-once"])
            .unwrap();
        assert!(matches.subcommand_matches("monitor-once").is_some());
        for extra in ["--url=https://example.invalid", "now", "--force"] {
            assert!(command(Lang::En)
                .try_get_matches_from(["secblitz", "monitor-once", extra])
                .is_err());
        }
        let help = command(Lang::En).render_help().to_string();
        assert!(!help.contains("monitor-once"), "{help}");
    }

    #[test]
    fn updater_commands_are_closed_and_worker_is_hidden() {
        for (word, expected) in [
            ("check", UpdateCommand::Check),
            ("status", UpdateCommand::Status),
            ("install-staged", UpdateCommand::InstallStaged),
        ] {
            let matches = command(Lang::En)
                .try_get_matches_from(["secblitz", "update", word])
                .unwrap();
            assert_eq!(update_command(&matches), Some(expected));
            assert_eq!(
                json_allowed(&matches),
                expected != UpdateCommand::InstallStaged
            );
            for extra in [
                "https://example.invalid/update",
                "C:\\Downloads\\setup.exe",
                "--url=https://example.invalid/update",
                "--path=C:\\Downloads\\setup.exe",
                "--token=arbitrary",
                "--yes",
                "--desktop-broker",
            ] {
                assert!(command(Lang::En)
                    .try_get_matches_from(["secblitz", "update", word, extra])
                    .is_err());
            }
        }
        for args in [
            vec!["secblitz", "update"],
            vec!["secblitz", "update", "install"],
            vec!["secblitz", "update", "run"],
            vec!["secblitz", "update", "check", "status"],
        ] {
            assert!(command(Lang::En).try_get_matches_from(args).is_err());
        }
        for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            let help = command(lang)
                .try_get_matches_from(["secblitz", "update", "--help"])
                .unwrap_err()
                .to_string();
            assert!(help.contains("check") && help.contains("status"));
            assert!(!help.contains("install-staged"));
            assert!(help.contains(&lang.t("Keep Secblitz up to date")));
        }
    }

    #[test]
    fn updater_uac_is_canonical_and_never_brokers_desktop_work() {
        for action in ["check", "status"] {
            let matches = command(Lang::It)
                .try_get_matches_from([
                    "secblitz",
                    "update",
                    action,
                    "--lang=it",
                    "--details",
                    "--no-animation",
                ])
                .unwrap();
            let args = elevated_args(&matches, Lang::It);
            assert_eq!(
                args,
                [
                    "--lang",
                    "it",
                    "--no-animation",
                    "--details",
                    "update",
                    action
                ]
            );
            assert!(args
                .iter()
                .all(|a| a.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')));
            let result = run_update_request(
                update_command(&matches).unwrap(),
                true,
                false,
                || Ok(false),
                || Ok(27),
                |_| panic!("parent must not run updater after UAC"),
            )
            .unwrap();
            assert!(matches!(result, UpdateRun::ElevatedExit(27)));
        }
        let cancelled = run_update_request(
            UpdateCommand::Check,
            true,
            false,
            || Ok(false),
            || Err(anyhow::anyhow!("cancelled")),
            |_| panic!("declined elevation must not run updater"),
        );
        assert!(cancelled.is_err());
    }

    #[test]
    fn scheduled_checks_and_worker_never_elevate_or_require_a_terminal() {
        for action in [UpdateCommand::Check, UpdateCommand::Status] {
            run_update_request(
                action,
                false,
                false,
                || Ok(true),
                || panic!("SYSTEM must not request UAC"),
                |received| {
                    assert_eq!(received, action);
                    Ok(UpdateReport::Outcome(updater::UpdateOutcome::UpToDate))
                },
            )
            .unwrap();
            for (interactive, json) in [(false, false), (false, true), (true, true)] {
                assert!(run_update_request(
                    action,
                    interactive,
                    json,
                    || Ok(false),
                    || panic!("background/JSON request must not elevate"),
                    |_| panic!("unelevated request must not run updater"),
                )
                .is_err());
            }
        }
        // A spoofed worker invocation still goes to core verification. The CLI
        // neither infers authorization nor offers the caller a UAC shortcut.
        let refused = run_update_request(
            UpdateCommand::InstallStaged,
            true,
            false,
            || panic!("worker authorization belongs to core"),
            || panic!("worker must never elevate"),
            |action| {
                assert_eq!(action, UpdateCommand::InstallStaged);
                Err(anyhow::anyhow!("untrusted worker"))
            },
        );
        assert!(refused.is_err());
        let worker_json = command(Lang::En)
            .try_get_matches_from(["secblitz", "update", "install-staged", "--json"])
            .unwrap();
        assert!(execute(&worker_json, Lang::En).is_err());
    }

    #[test]
    fn update_json_is_exact_and_failures_have_failure_exit_codes() {
        use updater::{UpdateOutcome, UpdateStatus};
        for outcome in [
            UpdateOutcome::NotConfigured,
            UpdateOutcome::NotPublished,
            UpdateOutcome::UpToDate,
            UpdateOutcome::DeferredBusy,
            UpdateOutcome::WorkerStarted {
                version: "0.4.1".into(),
            },
            UpdateOutcome::Installed {
                version: "0.4.1".into(),
            },
            UpdateOutcome::Failed {
                reason: "Staged installation failed".into(),
            },
        ] {
            let failed = matches!(outcome, UpdateOutcome::Failed { .. });
            for report in [
                UpdateReport::Outcome(outcome.clone()),
                UpdateReport::Status(UpdateStatus {
                    checked_at: 123,
                    result: outcome.clone(),
                }),
            ] {
                let expected = serde_json::to_value(&report).unwrap();
                let (mut out, mut err) = (Vec::new(), Vec::new());
                let code = write_update_result(
                    Ok(UpdateRun::Report(report)),
                    Lang::It,
                    true,
                    false,
                    true,
                    &mut out,
                    &mut err,
                )
                .unwrap();
                assert_eq!(code, i32::from(failed));
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
                    expected
                );
                assert!(err.is_empty());
            }
        }
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = write_update_result(
            Err(anyhow::anyhow!(
                "native cause with private operational data"
            )),
            Lang::It,
            true,
            true,
            true,
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(code, 1);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
            serde_json::json!({"outcome":"failed", "reason":"The update could not be completed."})
        );
        assert!(err.is_empty());
    }

    #[test]
    fn updater_background_and_worker_results_are_silent_and_never_pause() {
        for result in [
            Ok(UpdateRun::Report(UpdateReport::Outcome(
                updater::UpdateOutcome::WorkerStarted {
                    version: "0.4.1".into(),
                },
            ))),
            Ok(UpdateRun::Report(UpdateReport::Outcome(
                updater::UpdateOutcome::Failed {
                    reason: "failed".into(),
                },
            ))),
            Err(anyhow::anyhow!("native failure")),
        ] {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let _code =
                write_update_result(result, Lang::En, false, false, true, &mut out, &mut err)
                    .unwrap();
            assert!(out.is_empty() && err.is_empty());
        }
        for action in ["check", "status"] {
            let matches = command(Lang::En)
                .try_get_matches_from(["secblitz", "update", action, "--json"])
                .unwrap();
            assert!(json_allowed(&matches));
        }
    }

    #[test]
    fn updater_human_status_is_localized_without_native_evidence_by_default() {
        use updater::{UpdateOutcome, UpdateStatus};
        for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            for outcome in [
                UpdateOutcome::NotConfigured,
                UpdateOutcome::NotPublished,
                UpdateOutcome::UpToDate,
                UpdateOutcome::DeferredBusy,
                UpdateOutcome::WorkerStarted {
                    version: "0.4.1".into(),
                },
                UpdateOutcome::Installed {
                    version: "0.4.1".into(),
                },
                UpdateOutcome::Failed {
                    reason: "native evidence, not a friendly status".into(),
                },
            ] {
                let failed = matches!(outcome, UpdateOutcome::Failed { .. });
                let report = UpdateReport::Status(UpdateStatus {
                    checked_at: 0,
                    result: outcome,
                });
                let message = report.message();
                if lang != Lang::En {
                    assert_ne!(lang.t(message), message);
                }
                if failed {
                    assert_eq!(message, "The update could not be completed. Check your internet connection and try again later. If it keeps happening, download the latest Secblitz from our website.");
                }
                let (mut out, mut err) = (Vec::new(), Vec::new());
                let code = write_update_result(
                    Ok(UpdateRun::Report(report)),
                    lang,
                    false,
                    true,
                    false,
                    &mut out,
                    &mut err,
                )
                .unwrap();
                assert_eq!(code, i32::from(failed));
                assert_eq!(
                    String::from_utf8(out).unwrap(),
                    format!("{}\n", lang.t(message))
                );
                assert!(!String::from_utf8(err).unwrap().contains("native evidence"));
            }
        }
    }

    #[test]
    fn service_start_is_explicit_and_canonical() {
        let matches = command(Lang::En)
            .try_get_matches_from(["secblitz", "service", "start"])
            .unwrap();
        assert_eq!(
            elevated_args(&matches, Lang::En),
            ["--lang", "en", "service", "start"]
        );
    }

    fn os(words: &[&str]) -> Vec<std::ffi::OsString> {
        words.iter().map(Into::into).collect()
    }

    #[test]
    fn gui_entry_points_are_found_past_language_options() {
        assert_eq!(first_word(&os(&["secblitz"])), None);
        assert_eq!(first_word(&os(&["secblitz", "--lang", "es"])), None);
        assert_eq!(
            first_word(&os(&["secblitz", "--lang", "es", "gui"])),
            Some("gui")
        );
        assert_eq!(
            first_word(&os(&["secblitz", "tray", "--lang=fr"])),
            Some("tray")
        );
        assert_eq!(
            first_word(&os(&["secblitz", "update", "check"])),
            Some("update")
        );
        let args = os(&["secblitz", "gui", "--broker", "abc", "--self-test", "home"]);
        assert_eq!(flag_value(&args, "--broker"), Some("abc"));
        assert_eq!(flag_value(&args, "--self-test"), Some("home"));
        assert_eq!(flag_value(&args, "--missing"), None);
        let m = command(Lang::En)
            .try_get_matches_from(["secblitz"])
            .unwrap();
        assert!(m.subcommand_name().is_none());
    }

    #[test]
    fn open_picks_the_page_the_app_starts_on() {
        let m = command(Lang::En)
            .try_get_matches_from(["secblitz", "--open", "protection"])
            .unwrap();
        assert!(m.subcommand_name().is_none());
        assert_eq!(
            m.get_one::<String>("open").map(String::as_str),
            Some("protection")
        );
        let none = command(Lang::En)
            .try_get_matches_from(["secblitz"])
            .unwrap();
        assert!(none.get_one::<String>("open").is_none());
        assert_eq!(first_word(&os(&["secblitz", "--open", "protection"])), None);
        assert_eq!(
            first_word(&os(&["secblitz", "--open", "web", "gui"])),
            Some("gui")
        );
        let args = os(&["secblitz", "gui", "--broker", "abc", "--open", "tools"]);
        assert_eq!(flag_value(&args, "--open"), Some("tools"));
        for (word, page) in [
            ("protection", gui::Page::Fixes),
            ("web", gui::Page::Web),
            ("tools", gui::Page::Tools),
            ("history", gui::Page::History),
            ("History", gui::Page::History),
            ("settings", gui::Page::Home),
            ("home", gui::Page::Home),
            ("", gui::Page::Home),
            ("nonsense", gui::Page::Home),
        ] {
            assert_eq!(gui::Page::open_target(word), page, "{word}");
        }
    }

    #[test]
    fn human_cli_commands_are_gone() {
        for word in [
            "guide",
            "audit",
            "apply",
            "revert",
            "history",
            "password",
            "tools",
            "diagnostics",
            "operations",
            "quality-updates",
        ] {
            assert!(command(Lang::En)
                .try_get_matches_from(["secblitz", word])
                .is_err());
        }
        for words in [
            vec!["secblitz", "uninstall-revert"],
            vec!["secblitz", "uninstall-cleanup", "--user"],
        ] {
            assert!(command(Lang::En).try_get_matches_from(words).is_ok());
        }
        assert!(command(Lang::En)
            .try_get_matches_from(["secblitz", "uninstall-cleanup"])
            .is_err());
    }

    #[test]
    fn uninstall_commands_are_hidden() {
        let help = command(Lang::En).render_help().to_string();
        assert!(!help.contains("uninstall-revert"), "{help}");
        assert!(!help.contains("uninstall-cleanup"), "{help}");
    }

    #[test]
    fn uninstall_commands_never_elevate() {
        for (words, expected) in [
            (
                vec!["secblitz", "uninstall-revert"],
                UninstallCommand::Revert,
            ),
            (
                vec!["secblitz", "uninstall-revert", "--user"],
                UninstallCommand::RevertUser,
            ),
            (
                vec!["secblitz", "--json", "uninstall-revert"],
                UninstallCommand::Revert,
            ),
            (
                vec!["secblitz", "uninstall-cleanup", "--user"],
                UninstallCommand::CleanupUser,
            ),
        ] {
            let m = command(Lang::En).try_get_matches_from(words).unwrap();
            assert_eq!(uninstall_command(&m), Some(expected));
        }
        let m = command(Lang::En)
            .try_get_matches_from(["secblitz", "service", "start"])
            .unwrap();
        assert_eq!(uninstall_command(&m), None);
        let m = command(Lang::En)
            .try_get_matches_from(["secblitz"])
            .unwrap();
        assert_eq!(uninstall_command(&m), None);
    }

    #[test]
    fn every_language_builds_a_valid_command() {
        for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            command(lang).debug_assert();
        }
    }
}
