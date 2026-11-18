#!/usr/bin/env bash
# Installs the ainkrad-runner systemd unit (E1-12.3; protocol v2 since E1-14.5; terminals and pairing E2-15).
# Idempotent; does not start unless --start or --pair. Works on the Core's own host and on a remote Linux host.
#   install-linux.sh [--binary PATH] [--ptyhost PATH] [--pty] [--ca PEM]
#                    [--agents] [--exec] [--root] [--with-run] [--pair https://<core> --code - | --invite -] [--start]
#                    [--prefix DIR] [--dry-run]
# --pty      offer terminals (--enable-pty); needs ainkrad-ptyhost (--ptyhost, default: beside --binary). The shell
#            runs as the unprivileged ainkrad-runner user inside the unit's sandbox. Off unless asked. Also installs zsh
#            and the read-only Ainkrad shell profile (deploy/shell) in /usr/local/share/ainkrad/shell: every terminal
#            then starts `zsh -l` with that profile, the same on every runner. Without zsh the runner starts the login shell.
# --agents   offer agent sessions (--enable-agents) with the egress filter on: sessions reach only api.anthropic.com
#            (AINKRAD_AGENT_NETWORK=filtered, AINKRAD_AGENT_EGRESS_HOSTS=api.anthropic.com in runner.env). Needs the harness
#            (claude) on PATH. Off unless asked.
# --ca       a PEM the runner trusts instead of the system roots (a test Core's CA only).
# --pair     pair as the service user now (waits for the approver; compare the SAS it prints), then start.
# --invite   pair with a runner invite (`<host>/<fingerprint>.<secret>`, from the App's Add device or `POST /api/v1/pairings/invites`
#            with kind runner): single use, 15 minutes, no code and no SAS; then start. Takes the place of --pair and --code.
# --exec     turn exec.run on (--enable-exec). WARNING: opt-in only; a compromised Core can then run any program as
#            the runner's user (as root with --root). The guided installer never passes it.
# --root     WARNING: opt-in only, never the default. Runs the unit as root with no unit sandbox (drop-in
#            ainkrad-runner.service.d/authority.conf). A compromised Core is then root on this host, root terminals
#            can overwrite /usr/local/bin and /etc/systemd/system, and agent sessions are refused at uid 0. The
#            guided installer never passes it. A re-run without it removes that one file.
# --with-run set this host up to run project containers with rootless Podman (Core 0.9 Projects). Opt-in, idempotent:
#            installs podman, uidmap, passt, aardvark-dns and nftables (deploy/tools.manifest.json `distro.podman`), creates the system user
#            ainkrad-run (not the runner's) with its own subuid/subgid block, turns on linger for it, writes the cgroup
#            delegation drop-in user@.service.d/delegate.conf and waits for its runtime dir. The runner then reports `run_caps`.
#            Also installs the run helper (ainkrad-run.socket + ainkrad-run@.service: Podman as ainkrad-run, reached only by
#            the runner's group) and ainkrad-run-egress.service (nftables: ainkrad-run's traffic cannot reach the cloud
#            metadata address or private ranges). Needs the whole host, so it is skipped under --prefix except for the
#            drop-in and those files. Nothing else (no sysctl, no AppArmor).
# --prefix installs under DIR (a throwaway root, for tests): no user creation, no systemctl, no shell profile download.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
binary="$HERE/../target/release/ainkrad-runner" ptyhost='' with_run=0 pty=0 agents=0 ca='' pair='' code='' invite='' prefix='' start=0 dry=0 exec_on=0 root=0
run() { printf '+ %s\n' "$*"; [ "$dry" = 1 ] || "$@"; }
WAS_ACTIVE=1
# Demoting a root runner: its terminal hosts (ptyhosts, started as root; KillMode=process keeps them alive across a restart)
# must end too. The unprivileged runner cannot adopt them (a ptyhost serves only its own uid, and the runner's state dir
# must belong to its user), and root shells should not outlive the demotion. `kill --kill-whom=all` also SIGTERMs the
# runner itself, which Restart=on-failure treats as a clean exit and does not restart: so whether it was running is noted
# first and runner_restart_if_needed starts it again. Reads the globals old_root root prefix dry set below.
runner_demote_kill() {
  { [ "$old_root" = 1 ] && [ "$root" = 0 ] && { [ -z "$prefix" ] || [ "$dry" = 1 ]; }; } || return 0
  if [ "$dry" != 1 ]; then if systemctl is-active --quiet ainkrad-runner.service; then WAS_ACTIVE=1; else WAS_ACTIVE=0; fi; fi
  echo "demoting the runner from root: ending its terminal hosts (they run as root and cannot be adopted by the unprivileged runner)"
  run systemctl kill --kill-whom=all ainkrad-runner.service || true
}
# A runner that is already running keeps its old user and flags until restarted: pick the change up now (also for a dry run
# with --prefix, so it can be seen and tested). After a demotion the runner is restarted (not try-restarted: the kill
# stopped it) when it was running before.
runner_restart_if_needed() {
  { [ "$start" != 1 ] && [ -z "$pair" ] && { [ -z "$prefix" ] || [ "$dry" = 1 ]; }; } || return 0
  if [ "$old_root" = 1 ] && [ "$root" = 0 ]; then
    if [ "$WAS_ACTIVE" = 1 ]; then run systemctl restart ainkrad-runner.service; fi
  elif [ "$old_root" != "$root" ] || [ "$old_args" != "$args" ]; then
    run systemctl try-restart ainkrad-runner.service
  fi
}
RUN_USER=ainkrad-run RUN_HOME=/var/lib/ainkrad-run
# First free uid/gid of a 65536 block after every range in the given subuid/subgid files (at least 100000).
sub_next() { awk -F: 'BEGIN { m = 99999 } { e = $2 + $3 - 1; if (e > m) m = e } END { print m + 1 }' "$@" 2>/dev/null || echo 100000; }
# The cgroup v2 delegation of cpu, memory and pids to user managers: default on systemd 258+, but older ones delegate only
# memory and pids, and then --cpus would be silently ignored. Harmless where it is already the default.
DELEGATE_CONF='# Written by deploy/install-linux.sh --with-run: project containers run under the ainkrad-run user manager, which needs these controllers.
[Service]
Delegate=cpu cpuset io memory pids'
# Rootless Podman for project runs (--with-run). Reads the globals prefix and dry; the system steps run only on the real host.
run_setup() {
  local d="$prefix/etc/systemd/system/user@.service.d" cur='' changed=0 uid pk
  if [ -f "$d/delegate.conf" ]; then cur=$(cat "$d/delegate.conf"); fi
  if [ "$cur" = "$DELEGATE_CONF" ]; then echo "delegation drop-in already in place: $d/delegate.conf"
  else
    changed=1; run install -d "$d"; printf '+ write %s/delegate.conf\n' "$d"
    if [ "$dry" = 0 ]; then printf '%s\n' "$DELEGATE_CONF" >"$d/delegate.conf"; fi
  fi
  # The run helper (Podman as $RUN_USER, behind a socket only the runner's group reaches) and the egress block.
  run install -d "$prefix/etc/ainkrad-runner"
  run install -m 0644 "$HERE/run-egress.nft" "$prefix/etc/ainkrad-runner/run-egress.nft"
  local u; for u in ainkrad-run.socket ainkrad-run@.service ainkrad-run-egress.service; do
    run install -m 0644 "$HERE/systemd/$u" "$prefix/etc/systemd/system/$u"
  done
  if [ -n "$prefix" ] && [ "$dry" = 0 ]; then echo "+ skipped under --prefix: podman packages, the $RUN_USER user, linger"; return 0; fi
  if [ "$dry" = 1 ] || ! { command -v podman && command -v newuidmap && command -v pasta && [ -x /usr/lib/podman/aardvark-dns ]; } >/dev/null 2>&1; then
    if [ "$dry" = 1 ] || command -v apt-get >/dev/null 2>&1; then
      run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends podman uidmap passt aardvark-dns nftables
    elif command -v dnf >/dev/null 2>&1; then run dnf install -y --setopt=install_weak_deps=False podman shadow-utils passt aardvark-dns nftables
    else echo "--with-run needs apt-get or dnf to install podman" >&2; return 1; fi
  else echo "podman, uidmap, passt and aardvark-dns are already installed"; fi
  if id "$RUN_USER" >/dev/null 2>&1; then echo "user $RUN_USER already exists"
  else run useradd --system --user-group --create-home --home-dir "$RUN_HOME" --shell /usr/sbin/nologin "$RUN_USER"; fi
  run chmod 0700 "$RUN_HOME"
  # A system user gets no subuid/subgid from useradd; without them podman silently maps a single uid (postgres etc. then break).
  if grep -q "^$RUN_USER:" /etc/subuid 2>/dev/null && grep -q "^$RUN_USER:" /etc/subgid 2>/dev/null; then echo "subuid/subgid of $RUN_USER already set"
  else
    local s; s=$(sub_next /etc/subuid /etc/subgid)
    run usermod --add-subuids "$s-$((s + 65535))" --add-subgids "$s-$((s + 65535))" "$RUN_USER"
  fi
  run systemctl daemon-reload
  run loginctl enable-linger "$RUN_USER"
  # After the user exists: the nftables rule names it.
  run systemctl enable --now ainkrad-run-egress.service
  run systemctl restart ainkrad-run-egress.service
  run systemctl enable --now ainkrad-run.socket
  [ "$dry" = 1 ] && return 0
  uid=$(id -u "$RUN_USER")
  # Linger starts the user manager (and /run/user/UID with its bus); a manager that was already up must restart to take a new drop-in.
  if [ "$changed" = 1 ] && systemctl is-active --quiet "user@$uid.service"; then run systemctl restart "user@$uid.service"
  else run systemctl start "user@$uid.service"; fi
  for _ in $(seq 1 30); do [ -S "/run/user/$uid/bus" ] && break; sleep 0.5; done
  [ -S "/run/user/$uid/bus" ] || { echo "WARNING: /run/user/$uid/bus did not appear: projects cannot run until user@$uid.service is up" >&2; return 1; }
  pk=$(tr '\n' ' ' <"/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/cgroup.controllers" 2>/dev/null || true)
  if [ "$(for c in cpu memory pids; do case " $pk " in *" $c "*) echo y ;; esac; done | wc -l)" -ge 3 ]; then echo "controllers delegated to $RUN_USER: $pk"
  else echo "WARNING: cpu, memory and pids are not all delegated to $RUN_USER ($pk): the runner will not offer project runs" >&2; fi
  run runuser -u "$RUN_USER" -- env -C "$RUN_HOME" "XDG_RUNTIME_DIR=/run/user/$uid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" "HOME=$RUN_HOME" \
    podman info --format 'rootless={{.Host.Security.Rootless}} cgroups={{.Host.CgroupManager}}'
}
[ "${AINKRAD_INSTALL_SOURCE_ONLY:-}" != 1 ] || [ "${BASH_SOURCE[0]}" = "$0" ] || return 0
usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
# A secret flag's value: `-` reads it from the terminal (no echo) or stdin; a literal still works, with a warning (argv shows in `ps`).
secret_arg() {
  local v
  if [ "$2" = - ]; then
    if [ -t 0 ]; then IFS= read -rsp "${1#--}: " v; echo >&2; else IFS= read -r v; fi
  else echo "WARNING: $1 <value> puts the secret in argv (visible in ps and shell history); use '$1 -' or AINKRAD_PAIR_CODE or AINKRAD_PAIR_INVITE in the environment" >&2; v=$2; fi
  printf '%s' "$v"
}
while [ $# -gt 0 ]; do
  case $1 in
    --binary) binary=${2:?}; shift 2 ;;
    --ptyhost) ptyhost=${2:?}; shift 2 ;;
    --pty) pty=1; shift ;;
    --exec) exec_on=1; shift ;;
    --agents) agents=1; shift ;;
    --root) root=1; shift ;;
    --with-run) with_run=1; shift ;;
    --ca) ca=${2:?}; shift 2 ;;
    --pair) pair=${2:?}; shift 2 ;;
    --code) code=$(secret_arg --code "${2:?}"); shift 2 ;;
    --invite) invite=$(secret_arg --invite "${2:?}"); shift 2 ;;
    --prefix) prefix=${2:?}; shift 2 ;;
    --start) start=1; shift ;;
    --dry-run) dry=1; shift ;;
    *) usage ;;
  esac
done
[ "$dry" = 1 ] || [ "$(id -u)" = 0 ] || [ -n "$prefix" ] || { echo "run as root (or --prefix/--dry-run)" >&2; exit 1; }
[ "$dry" = 1 ] || [ -x "$binary" ] || { echo "no runner binary at $binary (cargo build --release -p ainkrad-runner, or --binary)" >&2; exit 1; }
code=${code:-${AINKRAD_PAIR_CODE:-}} invite=${invite:-${AINKRAD_PAIR_INVITE:-}}
[ -z "$invite" ] || [ -z "$code" ] || { echo "--invite and --code are two ways to pair: give one" >&2; exit 2; }
case $invite in '') ;; *[!A-Za-z0-9_./:-]*) echo "--invite is a runner invite: <host>/<fingerprint>.<secret>" >&2; exit 2 ;; esac
# A runner invite names its Core: `<host>/<fp>.<secret>`.
[ -z "$invite" ] || [ -n "$pair" ] || case $invite in */*) pair=https://${invite%%/*} ;; *) echo "--invite without a host needs --pair https://<core>" >&2; exit 2 ;; esac
[ -z "$pair" ] || [ -n "$code$invite" ] || { echo "--pair needs --code or --invite" >&2; exit 2; }
case $pair in '' | https://*) ;; *) echo "--pair takes an https:// URL" >&2; exit 2 ;; esac
case $code$ca$invite in *[[:space:]]*) echo "--code/--ca must not contain spaces (systemd splits RUNNER_ARGS on them)" >&2; exit 2 ;; esac
if [ "$pty" = 1 ]; then
  ptyhost=${ptyhost:-$(dirname "$binary")/ainkrad-ptyhost}
  [ "$dry" = 1 ] || [ -x "$ptyhost" ] || { echo "--pty needs ainkrad-ptyhost at $ptyhost (cargo build --release -p ainkrad-ptyhost, or --ptyhost)" >&2; exit 1; }
fi

if [ -z "$prefix" ]; then
  # Home is the runner's HOME; its work root is the short /var/lib/akrw (see the unit).
  id ainkrad-runner >/dev/null 2>&1 ||
    run useradd --system --user-group --home-dir /var/lib/ainkrad-runner --no-create-home \
      --shell /usr/sbin/nologin ainkrad-runner
  run install -d -m 0750 -o root -g ainkrad-runner /etc/ainkrad-runner
  # `pair` runs as the user before the unit's StateDirectory exists.
  run install -d -m 0700 -o ainkrad-runner -g ainkrad-runner /var/lib/ainkrad-runner
fi
run install -d "$prefix/usr/local/bin" "$prefix/etc/systemd/system"
# install_bin SRC DEST: copy and set 0755; when SRC already IS DEST (--binary pointing at the final path) `install` would die with
# "are the same file" under set -e, leaving a half-installed runner: only the mode is set then.
install_bin() { if [ "$1" -ef "$2" ]; then run chmod 0755 "$2"; else run install -m 0755 "$1" "$2"; fi; }
install_bin "$binary" "$prefix/usr/local/bin/ainkrad-runner"
# Beside the runner, where it looks first. Installed whenever it is at hand, so enabling pty later needs no re-install.
[ -n "$ptyhost" ] || [ ! -x "$(dirname "$binary")/ainkrad-ptyhost" ] || ptyhost=$(dirname "$binary")/ainkrad-ptyhost
[ -z "$ptyhost" ] || install_bin "$ptyhost" "$prefix/usr/local/bin/ainkrad-ptyhost"
run install -m 0644 "$HERE/systemd/ainkrad-runner.service" "$prefix/etc/systemd/system/ainkrad-runner.service"
# The root-side tool installer the App's one-click install uses: a socket only the runner's group can reach, and the unit it starts.
run install -m 0644 "$HERE/systemd/ainkrad-runner-tools.socket" "$prefix/etc/systemd/system/ainkrad-runner-tools.socket"
run install -m 0644 "$HERE/systemd/ainkrad-runner-tools@.service" "$prefix/etc/systemd/system/ainkrad-runner-tools@.service"
# runner.env: RUNNER_ARGS from these flags, replaced on every run (so a re-run without --pty turns terminals off).
args=''
[ "$pty" = 1 ] && args="--enable-pty"
[ "$agents" = 0 ] || args="${args:+$args }--enable-agents"
[ "$exec_on" = 1 ] && args="${args:+$args }--enable-exec"
[ -z "$ca" ] || args="${args:+$args }--ca $ca"
if [ -n "$prefix" ]; then run install -d "$prefix/etc/ainkrad-runner"; fi
dropin="$prefix/etc/systemd/system/ainkrad-runner.service.d"
envfile="$prefix/etc/ainkrad-runner/runner.env"
# What is installed now, to know after the rewrite whether a running runner must be restarted to pick the change up.
old_args=$(sed -n 's/^RUNNER_ARGS=//p' "$envfile" 2>/dev/null | tail -n1 || true)
old_root=0; [ ! -e "$dropin/authority.conf" ] || old_root=1
if [ "$root" = 1 ]; then
  run install -d "$dropin"
  printf '+ write %s/authority.conf\n' "$dropin"
  if [ "$dry" = 0 ]; then cat >"$dropin/authority.conf" <<'CONF'
# Written by deploy/install-linux.sh --root: the runner is the app's hands on this machine, so it runs as root with
# every capability and no filesystem sandbox. Agent sessions are sandboxed by the runner itself (bubblewrap).
[Service]
User=root
Group=root
NoNewPrivileges=no
CapabilityBoundingSet=
CapabilityBoundingSet=~
AmbientCapabilities=
ProtectSystem=no
ProtectHome=no
PrivateDevices=no
DevicePolicy=auto
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectKernelLogs=no
ProtectControlGroups=no
ProtectClock=no
ProtectHostname=no
RestrictNamespaces=no
SystemCallFilter=
CONF
  fi
else run rm -f "$dropin/authority.conf"; fi
printf '+ write %s: RUNNER_ARGS=%s%s\n' "$envfile" "$args" "$([ "$agents" = 0 ] || echo ' (+ AINKRAD_AGENT_NETWORK=filtered, AINKRAD_AGENT_EGRESS_HOSTS=api.anthropic.com)')"
if [ "$dry" = 0 ]; then
  printf '# Written by deploy/install-linux.sh. exec.run is off unless --enable-exec is added here.\nRUNNER_ARGS=%s\n' "$args" >"$envfile"
  [ "$agents" = 0 ] || printf 'AINKRAD_AGENT_NETWORK=filtered\nAINKRAD_AGENT_EGRESS_HOSTS=api.anthropic.com\n' >>"$envfile"
  chmod 0640 "$envfile"; [ -n "$prefix" ] || chown root:ainkrad-runner "$envfile"
fi
runner_demote_kill
# The Ainkrad shell (N20): zsh and the pinned profile, read-only, for the terminals this runner offers. A failure here
# never stops the runner: its terminals then start the login shell (the runner logs that).
if [ "$pty" = 1 ]; then
  shell_dest=/usr/local/share/ainkrad/shell
  if [ -n "$prefix" ] && [ "$dry" = 0 ]; then echo "+ skipped under --prefix: zsh and the Ainkrad shell profile"
  else
    if [ "$dry" = 1 ] || ! command -v zsh >/dev/null 2>&1; then
      if [ "$dry" = 1 ] || command -v apt-get >/dev/null 2>&1; then
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends zsh || echo "WARNING: zsh did not install; terminals start the login shell" >&2
      else echo "WARNING: zsh is not installed and there is no apt-get: terminals start the login shell" >&2; fi
    fi
    if [ "$dry" = 1 ]; then bash "$HERE/shell/install-shell.sh" --dest "$shell_dest" --dry-run
    else run bash "$HERE/shell/install-shell.sh" --dest "$shell_dest" || echo "WARNING: the Ainkrad shell profile did not install; terminals start the login shell" >&2; fi
  fi
fi
if [ -z "$prefix" ]; then
  run systemctl daemon-reload
  run systemctl enable --now ainkrad-runner-tools.socket
  if [ -n "$pair" ]; then
    # Blocks until the approver confirms the SAS (or the code expires); the Core's identity is pinned here.
    # The secret goes to the runner on stdin, never in argv.
    if [ -n "$invite" ]; then pa=(pair "$pair" --invite - --state /var/lib/ainkrad-runner/core); sec=$invite
    else pa=(pair "$pair" --code - --state /var/lib/ainkrad-runner/core); sec=$code; fi
    [ -z "$ca" ] || pa+=(--ca "$ca")
    printf '%s\n' "$sec" | run runuser -u ainkrad-runner -- /usr/local/bin/ainkrad-runner "${pa[@]}"
    start=1
  fi
  if [ "$start" = 1 ]; then
    [ "$dry" = 1 ] || [ -e /var/lib/ainkrad-runner/core/enrolment.json ] || { echo "pair it first: sudo -u ainkrad-runner ainkrad-runner pair https://<core> --code - --state /var/lib/ainkrad-runner/core" >&2; exit 1; }
    run systemctl enable ainkrad-runner.service
    # restart: a running runner picks up new flags; its terminal hosts keep running (KillMode=process).
    run systemctl restart ainkrad-runner.service
  else
    echo "installed, not started. Pair it (see the unit's header), then: systemctl enable --now ainkrad-runner"
  fi
fi
[ "$with_run" = 0 ] || run_setup
runner_restart_if_needed
