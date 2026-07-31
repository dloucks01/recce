# recce/scripts/lib.sh - shared helpers for the per-service enumeration scripts.
#
# Sourced by every recce/scripts/services/*.sh. These scripts run FROM Kali
# against a discovered service (the on-target companions live in recce/local/).
# They are READ-ONLY / safe by default: banner grabs, version + capability
# queries, anonymous/null-session checks, TLS and NSE "safe" scripts, and config
# disclosure. Anything intrusive (brute force, nikto, dir busting, user-enum
# spraying) is gated behind -a / AGGR=1 and never runs unless you ask.
#
# Every external tool is guarded - a missing tool self-skips with a note, so a
# script never dies just because one Kali package isn't installed. Findings are
# marked [!]; suggested next steps point at existing tools (searchsploit,
# metasploit modules, impacket, netexec, GTFOBins) - no exploit code is emitted.

[ -n "${_RECCE_SVC_LIB:-}" ] && return 0
_RECCE_SVC_LIB=1
export LC_ALL=C

if [ -t 1 ]; then CH=$'\e[1;36m'; CF=$'\e[1;33m'; CG=$'\e[1;32m'; CD=$'\e[0;90m'; CR=$'\e[0m'
else CH=''; CF=''; CG=''; CD=''; CR=''; fi

: "${AGGR:=0}"   # 1 = allow intrusive checks (set by -a or the dispatcher)

sec()   { printf '\n%s==== %s ====%s\n' "$CH" "$*" "$CR"; }
info()  { printf '    %s\n' "$*"; }
find_() { printf '%s[!] %s%s\n' "$CF" "$*" "$CR"; }   # a finding worth attention
ok()    { printf '%s[+] %s%s\n' "$CG" "$*" "$CR"; }   # something confirmed/reachable
note()  { printf '%s    # %s%s\n' "$CD" "$*" "$CR"; }  # aside / next-step hint
have()  { command -v "$1" >/dev/null 2>&1; }
need()  { have "$1" || { info "(skip: '$1' not installed)"; return 1; }; }

# Echo a command, run it, indent its output. Never lets a tool failure abort us.
run() { printf '    %s$ %s%s\n' "$CD" "$*" "$CR"; "$@" 2>&1 | sed 's/^/      /'; return 0; }

# TCP connect test using bash /dev/tcp - no nmap needed. port_open host port [timeout]
port_open() { timeout "${3:-4}" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null && return 0 || return 1; }

# Grab up to N bytes of a service banner (plain TCP). banner host port [bytes]
banner() { timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2; head -c ${3:-512} <&3" 2>/dev/null | tr -d '\000'; }

# Run one or more NSE scripts against host:port. nse host port "script,list" [args]
nse() { have nmap || { info "(skip: nmap not installed - NSE checks unavailable)"; return 1; }
        if [ -n "$4" ]; then run nmap -Pn -sV -p "$2" --script "$3" --script-args "$4" "$1"
        else run nmap -Pn -sV -p "$2" --script "$3" "$1"; fi; }

# Gate an intrusive block: aggr && { ... } else print why it was skipped.
aggr() { [ "$AGGR" = "1" ]; }
skip_aggr() { info "(intrusive: $* - skipped; add -a to enable)"; }

svc_header() { sec "$1  ->  $2:$3"; }
svc_start() {   # svc_start "NAME" host port  -> validates + prints header, or exits 0
  [ -z "$2" ] && { echo "usage: $0 <target> [port] [-a]"; exit 1; }
  svc_header "$1" "$2" "$3"
  if ! port_open "$2" "$3"; then info "port $3/tcp is not open or not reachable - nothing to do"; exit 0; fi
  ok "$3/tcp is open"
}
