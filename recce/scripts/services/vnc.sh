#!/usr/bin/env bash
# recce-service: VNC (5900+) - auth type, no-auth, auth-bypass CVE
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-5900}"; [ "$3" = "-a" ] && AGGR=1
svc_start "VNC" "$T" "$P"

B=$(banner "$T" "$P" 12); info "RFB banner: $(printf '%s' "$B" | tr -cd '[:print:]')"
nse "$T" "$P" "vnc-info,vnc-title,realvnc-auth-bypass"
note "realvnc-auth-bypass = CVE-2006-2369 (RealVNC 4.1.1 -> connect with no password)"
find_ "If security-type 1 (None) is offered -> connect with NO auth:  vncviewer $T:$P"
note "single shared password (no username) -> brute is cheap; screen access often = an interactive desktop as that user"

if aggr; then sec "VNC password brute (intrusive)"; need hydra && run hydra -P /usr/share/wordlists/rockyou.txt -f "vnc://$T:$P"
else skip_aggr "hydra vnc password brute"; fi
