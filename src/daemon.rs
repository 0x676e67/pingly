use std::{
    fs::{File, Permissions},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use daemonize::Daemonize;

use crate::{config::Config, serve};

const PID_PATH: &str = "/var/run/pingly.pid";
const DEFAULT_STDOUT_PATH: &str = "/var/run/pingly.out";
const DEFAULT_STDERR_PATH: &str = "/var/run/pingly.err";

/// Get the pid of the daemon
fn get_pid() -> Option<String> {
    if let Ok(data) = std::fs::read(PID_PATH) {
        let binding = String::from_utf8(data).expect("pid file is not utf8");
        return Some(binding.trim().to_string());
    }
    None
}

/// Check if the current user is root
pub fn root() {
    if !nix::unistd::Uid::effective().is_root() {
        println!("You must run this executable with root permissions");
        std::process::exit(-1)
    }
}

/// Start the daemon
pub fn start(config: Config) -> crate::Result<()> {
    if let Some(pid) = get_pid() {
        println!("pingly is already running with pid: {}", pid);
        return Ok(());
    }

    root();

    let pid_file = File::create(PID_PATH)?;
    pid_file.set_permissions(Permissions::from_mode(0o755))?;

    let stdout = File::create(DEFAULT_STDOUT_PATH)?;
    stdout.set_permissions(Permissions::from_mode(0o755))?;

    let stderr = File::create(DEFAULT_STDERR_PATH)?;
    stdout.set_permissions(Permissions::from_mode(0o755))?;

    let mut daemonize = Daemonize::new()
        .pid_file(PID_PATH) // Every method except `new` and `start`
        .chown_pid_file(true) // is optional, see `Daemonize` documentation
        .umask(0o777) // Set umask, `0o027` by default.
        .stdout(stdout) // Redirect stdout to `/tmp/daemon.out`.
        .stderr(stderr) // Redirect stderr to `/tmp/daemon.err`.
        .privileged_action(|| "Executed before drop privileges");

    if let Ok(user) = std::env::var("SUDO_USER") {
        if let Ok(Some(real_user)) = nix::unistd::User::from_name(&user) {
            daemonize = daemonize
                .user(real_user.name.as_str())
                .group(real_user.gid.as_raw());
        }
    }

    if let Some(err) = daemonize.start().err() {
        eprintln!("Error: {err}");
        std::process::exit(-1)
    }

    serve::run(config)
}

/// Stop the daemon
pub fn stop() -> crate::Result<()> {
    use nix::{sys::signal, unistd::Pid};

    root();

    if let Some(pid) = get_pid() {
        let pid = pid.parse::<i32>()?;
        for _ in 0..360 {
            if signal::kill(Pid::from_raw(pid), signal::SIGINT).is_err() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1))
        }
        let _ = std::fs::remove_file(PID_PATH);
    }

    Ok(())
}

/// Restart the daemon
pub fn restart(config: Config) -> crate::Result<()> {
    stop()?;
    start(config)
}

/// Show the status of the daemon
pub fn status() -> crate::Result<()> {
    match get_pid() {
        None => println!("pingly is not running"),
        Some(pid) => {
            let mut sys = sysinfo::System::new();

            // First, we update all information of our `System` struct.
            sys.refresh_all();

            // Display processes ID
            for (raw_pid, process) in sys.processes().iter() {
                if raw_pid.as_u32().eq(&(pid.parse::<u32>()?)) {
                    println!("{:<6} {:<6}  {:<6}", "PID", "CPU(%)", "MEM(MB)");
                    println!(
                        "{:<6}   {:<6.1}  {:<6.1}",
                        raw_pid,
                        process.cpu_usage(),
                        (process.memory() as f64) / 1024.0 / 1024.0
                    );
                }
            }
        }
    }
    Ok(())
}

/// Show the log of the daemon
pub fn log() -> crate::Result<()> {
    fn read_and_print_file(file_path: &Path, placeholder: &str) -> crate::Result<()> {
        if !file_path.exists() {
            return Ok(());
        }

        // Check if the file is empty before opening it
        let metadata = std::fs::metadata(file_path)?;
        if metadata.len() == 0 {
            return Ok(());
        }

        let file = File::open(file_path)?;
        let reader = std::io::BufReader::new(file);
        let mut start = true;

        use std::io::BufRead;

        for line in reader.lines() {
            if let Ok(content) = line {
                if start {
                    start = false;
                    println!("{placeholder}");
                }
                println!("{}", content);
            } else if let Err(err) = line {
                eprintln!("Error reading line: {}", err);
            }
        }

        Ok(())
    }

    let stdout_path = Path::new(DEFAULT_STDOUT_PATH);
    read_and_print_file(stdout_path, "STDOUT>")?;

    let stderr_path = Path::new(DEFAULT_STDERR_PATH);
    read_and_print_file(stderr_path, "STDERR>")?;

    Ok(())
}
