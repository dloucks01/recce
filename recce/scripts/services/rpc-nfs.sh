#!/usr/bin/env bash
# recce-service: RPCbind/NFS (111/2049) - exports, no_root_squash
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-111}"; [ "$3" = "-a" ] && AGGR=1
svc_start "RPC/NFS" "$T" "$P"

have rpcinfo && { info "registered RPC programs:"; run rpcinfo -p "$T"; }
nse "$T" "$P" "rpcinfo,nfs-showmount,nfs-ls,nfs-statfs"

if have showmount; then
  info "NFS exports:"; EX=$(showmount -e "$T" 2>/dev/null); printf '%s\n' "$EX" | sed 's/^/      /'
  printf '%s' "$EX" | grep -qE '\*|/' && {
    printf '%s' "$EX" | grep -q '\*' && find_ "NFS export shared to * (everyone) -> mountable by any host"
    find_ "Mount + inspect the exports below:"
    printf '%s\n' "$EX" | awk 'NR>1{print $1}' | while read -r m; do note "mkdir -p /mnt/r; mount -t nfs -o vers=3 $T:$m /mnt/r  (then check for no_root_squash: drop a SUID binary as root)"; done
  }
fi
note "no_root_squash + you-are-root-on-a-client => copy /bin/bash in, chmod +s, root on the target"

aggr || skip_aggr "(no intrusive step for NFS - mounting is manual/consensual)"
