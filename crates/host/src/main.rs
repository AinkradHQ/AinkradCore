//! `ainkrad-host`: started by systemd per connection (`Accept=yes`), the connected socket is
//! standard input. It handles one request and exits.

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Ok(fd) = std::io::stdin().as_fd().try_clone_to_owned() else {
        return ExitCode::FAILURE;
    };
    ainkrad_host::serve(&ainkrad_host::Ctx::production(), UnixStream::from(fd));
    ExitCode::SUCCESS
}
