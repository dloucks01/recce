# Recce test-env AD DC provisioning
#
# Runs on the Vagrant Windows Server 2022 box after first boot. Idempotent —
# subsequent `vagrant provision` calls detect the existing domain and skip.
#
# Result: dc01.corp.local with a small realistic OU tree:
#   Administrator          / Passw0rd!
#   svc_backup             / Summer2024!            (SPN → kerberoastable)
#   svc_sql                / Autumn2024!            (SPN → kerberoastable)
#   alice   / alice1234                             (Domain Users)
#   bob     / bob1234                               (Domain Users)
#   legacy.app / (DONT_REQ_PREAUTH) → AS-REP roastable
#
# Every account is documented in the top-of-file banner AND in test_env/vagrant/README.md
# so recce's test-suite knows what to expect.
#
# Wall-clock: ~10-15 min on first run (dcpromo dominates). Idempotent skip: ~30 s.

$ErrorActionPreference = "Stop"
$domain     = "CORP.LOCAL"
$netbios    = "CORP"
$dsrmPasswd = ConvertTo-SecureString "P@ssw0rd_DSRM" -AsPlainText -Force
$adminPasswd = "Passw0rd!"

# ── 1. Static-IP-safe DNS setup on the private-network adapter. ──────────
$nic = Get-NetIPAddress -IPAddress 172.20.1.10 -ErrorAction SilentlyContinue
if ($nic) {
    Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses 127.0.0.1
}

# ── 2. If the AD DS role isn't present yet, install it + promote to DC. ──
$feature = Get-WindowsFeature -Name AD-Domain-Services
if (-not $feature.Installed) {
    Write-Host "[+] Installing AD-Domain-Services role"
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null

    Write-Host "[+] Promoting to forest root domain controller — this reboots"
    Install-ADDSForest `
        -DomainName $domain `
        -DomainNetbiosName $netbios `
        -SafeModeAdministratorPassword $dsrmPasswd `
        -InstallDns `
        -Force `
        -NoRebootOnCompletion:$false
    # NoRebootOnCompletion:$false triggers the reboot; Vagrant reboot: true
    # in Vagrantfile re-invokes provisioning to run the seeding block below.
    exit 0
}

# ── 3. Wait for AD Web Services if the DC role is present but ADWS hasn't
#      finished starting on this boot. ────────────────────────────────────
$deadline = (Get-Date).AddMinutes(5)
while ((Get-Service ADWS -ErrorAction SilentlyContinue).Status -ne "Running") {
    if ((Get-Date) -gt $deadline) { throw "ADWS didn't start in 5 min" }
    Start-Sleep 5
}

Import-Module ActiveDirectory
$dn = ((Get-ADDomain).DistinguishedName)

# ── 4. Seed test accounts (idempotent — skips ones that already exist). ──
function New-Recce-User($sam, $display, $pass, $spn = $null, $dontRequirePreauth = $false) {
    if (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        Write-Host "[=] user $sam already exists"
        return
    }
    Write-Host "[+] creating user $sam"
    $secure = ConvertTo-SecureString $pass -AsPlainText -Force
    New-ADUser -Name $display -SamAccountName $sam -AccountPassword $secure `
               -Enabled $true -PasswordNeverExpires $true `
               -UserPrincipalName "$sam@$domain" -Path "CN=Users,$dn"
    if ($spn) { Set-ADUser -Identity $sam -ServicePrincipalNames @{Add=$spn} }
    if ($dontRequirePreauth) {
        Set-ADAccountControl -Identity $sam -DoesNotRequirePreAuth $true
    }
}

# Administrator's password comes from the box image; force it to the docs value.
try {
    Set-ADAccountPassword -Identity Administrator -NewPassword `
        (ConvertTo-SecureString $adminPasswd -AsPlainText -Force) -Reset `
        -ErrorAction Stop
    Write-Host "[+] Administrator password set to test-doc value"
} catch {
    Write-Host "[~] Administrator password not rotated (already correct or policy blocked)"
}

New-Recce-User "svc_backup" "Backup Service" "Summer2024!" `
               -spn "MSSQLSvc/dc01.corp.local:1433"
New-Recce-User "svc_sql"    "SQL Service"    "Autumn2024!" `
               -spn "HTTP/dc01.corp.local"
New-Recce-User "alice"      "Alice"          "alice1234"
New-Recce-User "bob"        "Bob"            "bob1234"
New-Recce-User "legacy.app" "Legacy App"     "LegacyBadPass1" `
               -dontRequirePreauth $true

# ── 5. Allow private-network SMB from the recce host — off by default. ───
if (-not (Get-NetFirewallRule -Name RecceTestEnvSMB -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name RecceTestEnvSMB -DisplayName "Recce Test SMB" `
        -Direction Inbound -Protocol TCP -LocalPort 445,139 `
        -RemoteAddress 172.20.1.0/24 -Action Allow | Out-Null
}

Write-Host "[+] Recce test AD DC ready. Domain: $domain"
