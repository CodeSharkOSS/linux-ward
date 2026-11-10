//! Listening TCP ports and the processes behind them: finds leftover dev servers and anything
//! exposed beyond localhost.

use std::os::unix::fs::MetadataExt;

use crate::util::run;

#[derive(Clone, Debug)]
pub struct Listener {
    pub addr: String,
    pub port: u16,
    pub process: String,
    pub pid: Option<u32>,
    /// Reachable from other machines (not bound to loopback only).
    pub exposed: bool,
    /// Owned by the current user, so it can be stopped without root.
    pub mine: bool,
}

pub fn parse_ss(text: &str, my_uid: u32) -> Vec<Listener> {
    let mut v = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 || f[0] != "LISTEN" {
            continue;
        }
        let Some((addr, port)) = f[3].rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        let addr = addr.trim_matches(['[', ']']).to_string();
        let users = f.get(5).copied().unwrap_or("");
        let process = users
            .split("((\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("")
            .to_string();
        let pid = users
            .split("pid=")
            .nth(1)
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|s| s.parse::<u32>().ok());
        let loopback = addr == "::1" || addr.starts_with("127.") || addr == "localhost";
        let mine = pid
            .and_then(|p| std::fs::metadata(format!("/proc/{p}")).ok())
            .is_some_and(|m| m.uid() == my_uid);
        v.push(Listener {
            addr,
            port,
            process,
            pid,
            exposed: !loopback,
            mine,
        });
    }
    v.sort_by_key(|l| (!l.exposed, l.port));
    v.dedup_by(|a, b| a.port == b.port && a.pid == b.pid && a.exposed == b.exposed);
    v
}

pub fn listeners() -> Result<Vec<Listener>, String> {
    let out = run("ss", &["-H", "-ltnp"]);
    if !out.ok {
        return Err(out.combined());
    }
    // SAFETY: geteuid has no preconditions.
    Ok(parse_ss(&out.stdout, unsafe { libc::geteuid() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ss_output() {
        let t = "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=812,fd=3))\n\
                 LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:((\"node\",pid=4242,fd=19))\n\
                 LISTEN 0 128 [::]:631 [::]:*\n";
        let v = parse_ss(t, u32::MAX);
        assert_eq!(v.len(), 3);
        let ssh = v.iter().find(|l| l.port == 22).unwrap();
        assert!(ssh.exposed && ssh.process == "sshd" && ssh.pid == Some(812));
        let node = v.iter().find(|l| l.port == 3000).unwrap();
        assert!(!node.exposed && node.process == "node");
        let cups = v.iter().find(|l| l.port == 631).unwrap();
        assert!(cups.exposed && cups.pid.is_none());
    }
}
