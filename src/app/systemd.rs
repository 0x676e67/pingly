//! systemd service installation and control for Linux.
//!
//! Pingly stays in the foreground while systemd owns startup, restart, logging, and process state.

use std::{
    env, io,
    path::PathBuf,
    sync::mpsc::TryRecvError,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sdjournal::{EntryOwned, LiveJournal, SubscriptionOptions};
use unitbus::{
    BlockingJobHandle, BlockingUnitBus, JobOutcome, ServiceType, ServiceUnitSpec, UnitStartMode,
    UnitStatus,
};

use crate::{args::ServerArgs, Result};

const SERVICE_NAME: &str = "pingly.service";
const JOB_TIMEOUT: Duration = Duration::from_secs(30);
const RECENT_LOG_LIMIT: usize = 100;

#[derive(Clone, Copy)]
struct ServiceIdentity {
    uid: u32,
    gid: u32,
}

/// Installs, enables, and starts the service with the supplied server settings.
pub(crate) fn start(config: ServerArgs) -> Result<()> {
    let bus = BlockingUnitBus::connect_system()?;
    install(&bus, config)?;

    let status = wait_for_job(
        bus.units().start(SERVICE_NAME, UnitStartMode::Replace)?,
        "start",
    )?;
    print_action("started", &status);
    Ok(())
}

/// Updates the installed unit and restarts the service.
pub(crate) fn restart(config: ServerArgs) -> Result<()> {
    let bus = BlockingUnitBus::connect_system()?;
    install(&bus, config)?;

    let status = wait_for_job(
        bus.units().restart(SERVICE_NAME, UnitStartMode::Replace)?,
        "restart",
    )?;
    print_action("restarted", &status);
    Ok(())
}

/// Stops the service without disabling boot startup.
pub(crate) fn stop() -> Result<()> {
    let bus = BlockingUnitBus::connect_system()?;
    let status = wait_for_job(
        bus.units().stop(SERVICE_NAME, UnitStartMode::Replace)?,
        "stop",
    )?;
    print_action("stopped", &status);
    Ok(())
}

/// Shows recent service logs and follows new entries from the system journal.
pub(crate) fn log() -> Result<()> {
    let captured_at = unix_micros(SystemTime::now())?;
    let journal = sdjournal::Journal::open_default()?;
    let mut query = journal.query();
    query
        .match_unit(SERVICE_NAME)
        .seek_tail()
        .limit(RECENT_LOG_LIMIT);

    let mut recent = query.collect_owned()?;
    let newest_cursor = recent.first().map(EntryOwned::cursor).transpose()?;
    recent.reverse();
    for entry in &recent {
        print_log_entry(entry.get("MESSAGE"), entry.get("_PID"));
    }

    let mut live = LiveJournal::open_default()?;
    let mut filter = live.filter();
    filter.match_unit(SERVICE_NAME);

    let mut options = SubscriptionOptions::new(filter);
    if let Some(cursor) = newest_cursor {
        options.after_cursor(cursor);
    } else {
        options.since_realtime(captured_at);
    }

    let subscription = live.subscribe_with_options(options)?;
    loop {
        live.poll_once()?;
        loop {
            match subscription.try_recv() {
                Ok(entry) => {
                    let entry = entry?;
                    print_log_entry(entry.get("MESSAGE"), entry.get("_PID"));
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(io::Error::other("system journal subscription closed").into());
                }
            }
        }
    }
}

/// Shows service and process state through systemd's D-Bus API.
pub(crate) fn status() -> Result<()> {
    let bus = BlockingUnitBus::connect_system()?;
    let status = bus.units().get_status(SERVICE_NAME)?;

    match status.description.as_deref() {
        Some(description) => println!("{} - {description}", status.id),
        None => println!("{}", status.id),
    }
    println!(
        "  Loaded: {} ({})",
        status.load_state.as_str(),
        status.fragment_path.as_deref().unwrap_or("no unit file")
    );
    println!(
        "  Active: {} ({})",
        status.active_state.as_str(),
        status.sub_state.as_deref().unwrap_or("unknown")
    );

    if let Some(pid) = status.main_pid.filter(|pid| *pid != 0) {
        println!("  Main PID: {pid}");
    }
    if let Some(result) = status.result.as_deref() {
        println!("  Result: {result}");
    }
    if let Some(restarts) = status.n_restarts.filter(|count| *count != 0) {
        println!("  Restarts: {restarts}");
    }

    Ok(())
}

fn install(bus: &BlockingUnitBus, config: ServerArgs) -> Result<()> {
    let spec = service_unit(env::current_exe()?, config, invoking_user())?;
    let report = bus
        .config()
        .install_service_unit(spec, Default::default())?;

    let state = if report.wrote.changed {
        "updated"
    } else {
        "unchanged"
    };
    println!("systemd unit {state}: {}", report.wrote.path_written);
    Ok(())
}

/// Returns the original user when the command is run through sudo.
///
/// Direct root invocations leave the service identity unset so executables and TLS files under
/// `/root` remain accessible.
fn invoking_user() -> Option<ServiceIdentity> {
    let uid = env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid = env::var("SUDO_GID").ok()?.parse().ok()?;

    (uid != 0).then_some(ServiceIdentity { uid, gid })
}

fn service_unit(
    executable: PathBuf,
    config: ServerArgs,
    identity: Option<ServiceIdentity>,
) -> Result<ServiceUnitSpec> {
    let ServerArgs {
        log,
        bind,
        concurrent,
        keep_alive_timeout,
        tls_cert,
        tls_key,
        tcp_capture_packet,
        tcp_capture_interface,
    } = config;

    let mut exec_start = Vec::with_capacity(16);
    exec_start.push(path_arg(executable, "server executable")?);
    exec_start.extend([
        "run".to_owned(),
        "--log".to_owned(),
        log,
        "--bind".to_owned(),
        bind.to_string(),
        "--concurrent".to_owned(),
        concurrent.to_string(),
        "--keep-alive-timeout".to_owned(),
        keep_alive_timeout.to_string(),
    ]);

    if let Some(cert) = tls_cert {
        exec_start.push("--tls-cert".to_owned());
        exec_start.push(path_arg(cert, "TLS certificate path")?);
    }
    if let Some(key) = tls_key {
        exec_start.push("--tls-key".to_owned());
        exec_start.push(path_arg(key, "TLS private key path")?);
    }
    if tcp_capture_packet {
        exec_start.push("--tcp-capture-packet".to_owned());
    }
    if let Some(interface) = tcp_capture_interface {
        exec_start.push("--tcp-capture-interface".to_owned());
        exec_start.push(interface);
    }

    for argument in &mut exec_start {
        escape_systemd_expansions(argument);
    }

    let mut extra_service = Vec::with_capacity(5);
    if tcp_capture_packet {
        extra_service.push("AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN".to_owned());
        extra_service.push("CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN".to_owned());
    }
    extra_service.extend([
        "NoNewPrivileges=yes".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=read-only".to_owned(),
    ]);

    let mut spec = ServiceUnitSpec::default();
    spec.unit = SERVICE_NAME.to_owned();
    spec.description = Some("Pingly TLS and HTTP analysis server".to_owned());
    spec.after = vec!["network.target".to_owned()];
    spec.service_type = Some(ServiceType::Exec);
    spec.exec_start = exec_start;
    spec.restart = Some("on-failure".to_owned());
    spec.restart_sec = Some(3);
    spec.timeout_stop_sec = Some(10);
    spec.standard_output = Some("journal".to_owned());
    spec.standard_error = Some("journal".to_owned());
    spec.wanted_by = vec!["multi-user.target".to_owned()];
    spec.extra_unit = vec!["Documentation=https://github.com/0x676e67/pingly".to_owned()];
    spec.extra_service = extra_service;

    if let Some(identity) = identity {
        spec.user = Some(identity.uid.to_string());
        spec.group = Some(identity.gid.to_string());
    }

    Ok(spec)
}

fn path_arg(path: PathBuf, description: &'static str) -> Result<String> {
    let path = std::path::absolute(path)?;
    let path = path.into_os_string().into_string().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} is not valid UTF-8"),
        )
    })?;
    Ok(path)
}

/// Escapes expansion markers before unitbus applies systemd command-line quoting.
///
/// systemd expands percent specifiers and dollar environment references even though no shell is
/// involved. Doubling them preserves the literal argument supplied through the CLI.
/// https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#Command%20Lines
fn escape_systemd_expansions(argument: &mut String) {
    let extra = argument
        .bytes()
        .filter(|byte| matches!(byte, b'%' | b'$'))
        .count();
    if extra == 0 {
        return;
    }

    let mut escaped = String::with_capacity(argument.len().saturating_add(extra));
    for character in argument.chars() {
        if matches!(character, '%' | '$') {
            escaped.push(character);
        }
        escaped.push(character);
    }
    *argument = escaped;
}

fn wait_for_job(job: BlockingJobHandle, action: &'static str) -> Result<UnitStatus> {
    match job.wait(JOB_TIMEOUT)? {
        JobOutcome::Success { unit_status } => Ok(unit_status),
        JobOutcome::Failed {
            unit_status,
            reason,
        } => Err(io::Error::other(format!(
            "systemd failed to {action} {SERVICE_NAME}: {reason:?} (active={}, sub={})",
            unit_status.active_state.as_str(),
            unit_status.sub_state.as_deref().unwrap_or("unknown")
        ))
        .into()),
        JobOutcome::Canceled { unit_status } => Err(io::Error::other(format!(
            "systemd canceled {action} for {SERVICE_NAME} (active={})",
            unit_status.active_state.as_str()
        ))
        .into()),
        _ => Err(io::Error::other(format!(
            "systemd returned an unsupported result while trying to {action} {SERVICE_NAME}"
        ))
        .into()),
    }
}

fn print_action(action: &str, status: &UnitStatus) {
    let state = status.active_state.as_str();
    let sub_state = status.sub_state.as_deref().unwrap_or("unknown");
    println!("{} {action}: {state} ({sub_state})", status.id);
}

fn print_log_entry(message: Option<&[u8]>, pid: Option<&[u8]>) {
    let Some(message) = message else {
        return;
    };
    let message = String::from_utf8_lossy(message);

    if let Some(pid) = pid {
        println!("[{}] {message}", String::from_utf8_lossy(pid));
    } else {
        println!("{message}");
    }
}

fn unix_micros(time: SystemTime) -> Result<u64> {
    let duration = time.duration_since(UNIX_EPOCH).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("system time is before the Unix epoch: {error}"),
        )
    })?;
    let micros = u64::try_from(duration.as_micros()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("system timestamp is too large: {error}"),
        )
    })?;
    Ok(micros)
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        path::{Path, PathBuf},
    };

    use super::*;

    #[test]
    fn unit_contains_server_configuration_and_invoking_user() {
        let unit = service_unit(
            PathBuf::from("/opt/pingly % $ build/pingly"),
            server_config(),
            Some(ServiceIdentity {
                uid: 1000,
                gid: 1001,
            }),
        )
        .expect("service unit should build")
        .render()
        .expect("service unit should render");

        assert!(unit.starts_with("# Managed by unitbus."));
        assert!(unit.contains("User=1000\nGroup=1001\n"));
        assert!(unit.contains("ExecStart=\"/opt/pingly %% $$ build/pingly\" run --log debug"));
        assert!(unit.contains("--bind 127.0.0.1:9443"));
        assert!(unit.contains("--tls-cert \"/etc/pingly/client cert.pem\""));
        assert!(!unit.contains("DynamicUser=yes"));
        assert!(!unit.contains("AmbientCapabilities="));
    }

    #[test]
    fn capture_configuration_uses_network_capabilities() {
        let mut config = server_config();
        config.tcp_capture_packet = true;
        config.tcp_capture_interface = Some("capture $lan".to_owned());

        let unit = service_unit(PathBuf::from("/usr/local/bin/pingly"), config, None)
            .expect("service unit should build")
            .render()
            .expect("service unit should render");

        assert!(!unit.contains("DynamicUser=yes\n"));
        assert!(!unit.contains("PrivateTmp=yes\n"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN\n"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\n"));
        assert!(unit.contains("--tcp-capture-packet"));
        assert!(unit.contains("--tcp-capture-interface \"capture $$lan\""));
    }

    #[test]
    fn root_install_keeps_the_executable_visible() {
        let unit = service_unit(
            PathBuf::from("/root/.cargo/bin/pingly"),
            server_config(),
            None,
        )
        .expect("service unit should build")
        .render()
        .expect("service unit should render");

        assert!(unit.contains("ExecStart=/root/.cargo/bin/pingly"));
        assert!(!unit.contains("DynamicUser=yes"));
        assert!(!unit.contains("PrivateTmp=yes"));
    }

    #[test]
    fn expansion_markers_are_escaped_only_when_present() {
        let mut plain = "plain".to_owned();
        escape_systemd_expansions(&mut plain);
        assert_eq!(plain, "plain");

        let mut expanded = "percent% dollar$".to_owned();
        escape_systemd_expansions(&mut expanded);
        assert_eq!(expanded, "percent%% dollar$$");
    }

    #[test]
    fn service_paths_are_made_absolute() {
        let path = path_arg(PathBuf::from("certificate.pem"), "test path")
            .expect("relative path should resolve");

        assert!(Path::new(&path).is_absolute());
    }

    fn server_config() -> ServerArgs {
        ServerArgs {
            log: "debug".to_owned(),
            bind: "127.0.0.1:9443"
                .parse::<SocketAddr>()
                .expect("test address should parse"),
            concurrent: 64,
            keep_alive_timeout: 30,
            tls_cert: Some(PathBuf::from("/etc/pingly/client cert.pem")),
            tls_key: Some(PathBuf::from("/etc/pingly/client key.pem")),
            tcp_capture_packet: false,
            tcp_capture_interface: None,
        }
    }
}
