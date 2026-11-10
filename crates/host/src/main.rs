//! `ainkrad-host`: started by systemd per connection (`Accept=yes`), the connected socket is
//! standard input. It handles one request and exits.

#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "ainkrad-host: Linux only (needs SO_PEERCRED and systemd)"
    );
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let Ok(fd) = std::io::stdin().as_fd().try_clone_to_owned() else {
        return ExitCode::FAILURE;
    };
    ainkrad_host::serve(&ainkrad_host::Ctx::production(), UnixStream::from(fd));
    ExitCode::SUCCESS
}
