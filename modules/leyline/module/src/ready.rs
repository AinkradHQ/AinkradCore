//! The ready command a Mac-direct lease answers with, and the paths a runner may name in it.

use crate::terminal::Stop;

/// `ssh -F <config> [-J hops] -p <port> user@host`: the config names the agent, a private known-hosts
/// file and public-key login only. `stops` is the jump hosts, then the target.
pub(crate) fn ready(config: &str, stops: &[Stop]) -> String {
    let (target, jumps) = stops.split_last().expect("a path has a target");
    let at = |s: &Stop| {
        let a = &s.address;
        let a = if a.contains(':') {
            format!("[{a}]")
        } else {
            a.clone()
        };
        format!("{}@{a}:{}", s.user, s.port)
    };
    let jump = match jumps {
        [] => String::new(),
        j => format!("-J {} ", j.iter().map(at).collect::<Vec<_>>().join(",")),
    };
    format!(
        "ssh -F '{config}' {jump}-p {} {}@{}",
        target.port, target.user, target.address
    )
}

/// A path the ready command can hold inside single quotes.
pub(crate) fn sane(p: &str) -> bool {
    !p.is_empty() && p.len() <= 512 && p.bytes().all(|b| b.is_ascii_graphic() && b != b'\'')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(address: &str, user: &str, port: u16) -> Stop {
        Stop {
            address: address.into(),
            port,
            user: user.into(),
            secret: String::new(),
            pinned: vec![],
        }
    }

    #[test]
    fn the_ready_command_names_the_config_the_hops_and_the_target() {
        let one = ready("/t/cfg", &[s("a.example.com", "deploy", 22)]);
        assert_eq!(one, "ssh -F '/t/cfg' -p 22 deploy@a.example.com");
        let two = ready(
            "/t/cfg",
            &[
                s("j.example.com", "jumper", 2222),
                s("fe80::1%en0", "root", 22),
                s("t", "me", 22),
            ],
        );
        assert_eq!(
            two,
            "ssh -F '/t/cfg' -J jumper@j.example.com:2222,root@[fe80::1%en0]:22 -p 22 me@t"
        );
    }

    #[test]
    fn a_path_with_a_quote_or_a_space_is_not_taken_from_a_runner() {
        assert!(sane("/var/folders/x/T/ainkrad-ssh.ab12/agent.sock"));
        for bad in ["", "/a b", "/a'b", "/a\nb"] {
            assert!(!sane(bad), "{bad:?}");
        }
    }
}
