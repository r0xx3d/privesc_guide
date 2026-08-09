# Network Discovery Cheat Sheet

A field reference for discovering hosts, ports, services, subdomains, web
content, cloud assets, and Active Directory attack surface. Covers the
modern 2022-2026 tooling ecosystem: ProjectDiscovery stack, masscan,
RustScan, ZMap/ZGrab2, Nuclei, BloodHound CE, chainreactors, and the
methodology that ties them together. Each year's research is taken
seriously, with emphasis on the newest tools and capabilities.

---

## 1. Discovery methodology

Discovery is a funnel, broad to narrow, passive to active:

1. **Scope and OSINT** - ranges, domains, cloud accounts, leaks.
2. **Host discovery** - which IPs are alive (ARP, ICMP, TCP ping).
3. **Port scanning** - fast sweep (masscan/naabu) then deep scan (nmap).
4. **Service and OS detection** - banners, probes, fingerprints.
5. **Web discovery** - vhosts, directories, tech stack, JS endpoints.
6. **Subdomain enumeration** - passive sources then active brute.
7. **Cloud and IAM discovery** - metadata, buckets, roles, K8s API.
8. **Active Directory discovery** - users, groups, ACLs, trusts, ADCS.
9. **Vulnerability discovery** - Nuclei templates, version matching.

The order matters. Burn 10 minutes on a full nmap before a masscan sweep
and you will lose the race. Sweep fast, then go deep on what is alive.

---

## 2. Host discovery

### Layer 2 (ARP)

ARP is the most reliable host discovery on a local subnet. Nothing beats
it for accuracy on a flat L2 segment.

```
arp-scan --interface=eth0 10.10.10.0/24
arp-scan -l                          # local subnet
nmap -PR -sn 10.10.10.0/24            # ARP ping only
netdiscover -r 10.10.10.0/24
```

### Layer 3 (ICMP)

```
nmap -PE -sn 10.10.10.0/24            # ICMP echo
nmap -PP -sn 10.10.10.0/24            # ICMP timestamp
nmap -PM -sn 10.10.10.0/24            # ICMP mask
fping -a -g 10.10.10.0/24 2>/dev/null
nmap -sn -n --disable-arp-ping 10.10.10.0/24 --packet-trace  # force ICMP
```

### Layer 4 (TCP/UDP ping)

```
nmap -PS22,80,443 -sn 10.10.10.0/24   # TCP SYN ping
nmap -PA22,80,443 -sn 10.10.10.0/24   # TCP ACK ping
nmap -PU53,161 -sn 10.10.10.0/24      # UDP ping
```

### Host discovery flags

```
-sn                        # ping scan only, no port scan
-Pn                        # skip host discovery, treat all as up (use when ping blocked)
-n                         # never resolve DNS, faster
-R                         # always reverse-DNS
--disable-arp-ping         # force ICMP/other discovery on same L2
--packet-trace             # show every packet sent and received
--reason                   # show why a port/host is in a given state
-iL targets.txt            # read targets from file
--exclude 10.10.10.5
--excludefile exclude.txt
```

On a VPN or HTB-style network, default to `-Pn` since hosts block ICMP.

### IPv6 neighbor discovery

IPv6 is default-on for Windows and many Linux distros. Discovery differs
from IPv4: no ARP, use Neighbor Discovery Protocol (NDP).

```
nmap -6 -sn 2001:db8::/64             # IPv6 ping sweep (slow, huge space)
nmap -6 -PR -sn fe80::/10             # NDP on link-local
# Tools:
alive6 eth0                            # THC IPv6 toolkit
detect-new-ips6 eth0                    # passive IPv6 host detection
python3 ipv6_neighbor_discovery.py      # custom NDP sweeper
```

IPv6 subnets are /64 by convention, so brute scanning is impractical. Use
passive collection (listen for NDP/RA), known addresses from DNS/SLAAC, and
targeted sweeps of dense ranges.

---

## 3. Port scanning

### Tier list by use case

| Tier | Tool | Use case |
|------|------|----------|
| Extreme | masscan | Internet-wide, 10M pps, single-port or small port set |
| Extreme | ZMap | Single-port research-grade scans at line rate |
| Fast sweep | Naabu | ProjectDiscovery fast scanner, integrates with nmap |
| Fast sweep | RustScan | Rust async scanner, pipes to nmap for service detection |
| Deep | Nmap | Accurate, NSE, version/OS detection, the gold standard |

### masscan - the fastest port scanner

```
masscan 10.10.10.0/24 -p1-65535 --rate=10000
masscan 10.10.10.0/24 -p80,443,22,445 --rate=100000
masscan 10.0.0.0/8 -p80 --rate=10000000 --wait 5
masscan -p1-65535 10.10.10.10 --rate=5000 -e tun0
masscan -p1-65535 10.10.10.0/24 --rate=10000 --banners
masscan -p1-65535 10.10.10.0/24 --rate=10000 -oJ scan.json
masscan -p1-65535 10.10.10.0/24 --rate=10000 --exclude 10.10.10.5
```

masscan has its own TCP/IP stack, so it needs raw socket access (root) and
a separate IP from your main interface to avoid breaking your SSH session.
Use `--src-ip` or a dedicated interface. Banners are limited (only a few
protocols). Always pipe results to nmap for real service detection.

```
# masscan sweep, then nmap for service detection
masscan 10.10.10.0/24 -p1-65535 --rate=10000 -oJ masscan.json
# extract open ports
jq -r '.[].ports[].port' masscan.json | sort -u | paste -sd,
nmap -sV -p<ports> 10.10.10.0/24
```

### ZMap - single-port research scanner

ZMap is designed for single-port internet-wide studies. It is the
foundation of academic scanning research.

```
zmap -p 80 10.10.10.0/24 -o results.csv
zmap -p 443 -B 100M 10.10.10.0/24 -o results.csv
zmap -p 22 --bandwidth=1G 10.10.10.0/24
```

### ZGrab2 - application layer scanner

ZGrab2 is the companion to ZMap, doing application-layer probes for 30+
protocols including AMQP, MQTT, BACnet, DNP3, Modbus (IoT/ICS coverage).

```
zgrab2 http -p 80 10.10.10.0/24
zgrab2 tls -p 443 10.10.10.0/24
zgrab2 ssh -p 22 10.10.10.0/24
zgrab2 smb -p 445 10.10.10.0/24
zgrab2 mqtt -p 1883 10.10.10.0/24
zgrab2 amqp -p 5672 10.10.10.0/24
zgrab2 modbus -p 502 10.10.10.0/24
```

### Naabu - ProjectDiscovery fast scanner

```
naabu -host 10.10.10.0/24 -p 1-65535
naabu -list hosts.txt -p 80,443,22,445,3389 -rate 5000
naabu -host 10.10.10.10 -p - -silent
naabu -host 10.10.10.0/24 -top-ports 1000
naabu -host 10.10.10.0/24 -uP                 # UDP payload probes (2024+)
naabu -host 10.10.10.0/24 -ss                 # smart scan, combines SYN+UDP
naabu -host 10.10.10.0/24 -p 1-65535 -nmap-cli "sV -sC"  # pipe to nmap
```

### RustScan - async port scanner

```
rustscan -a 10.10.10.10 -- -sV -sC -oN scan.txt
rustscan -a 10.10.10.0/24 -p 80,443,22 -- -sV
rustscan -a hosts.txt -p 1-65535 -t 2000 -- -sV -sC
```

RustScan opens ports quickly then hands the list to nmap for the real
work. Good middle ground between masscan speed and nmap accuracy.

### Nmap - the gold standard

```
# Quick triage
nmap -sS -sC -sV -Pn -oA nmap/quick <ip>
# Full port slow scan
sudo nmap -sS -sU -sV -O -p- -Pn --min-rate 1000 -oA nmap/full <ip>
# All scripts for SMB
sudo nmap -p 139,445 --script smb-enum-*,smb-vuln-*,smb-os-discovery,smb-protocols -oA nmap/smb <ip>
# Vuln sweep
sudo nmap -sV --script vuln -p 80,443,445,3389 -oA nmap/vuln <ip>
# UDP top ports
sudo nmap -sU --top-ports 200 -sV -O -oA nmap/udp <ip>
```

Nmap scan types:

| Flag | Name | What it does |
|------|------|--------------|
| `-sS` | SYN scan | Half-open, default when root. Stealthier than connect. |
| `-sT` | TCP connect | Full handshake, used when not root, logged by target. |
| `-sU` | UDP scan | Slow, sends empty datagrams. Combine with `-sS` for full coverage. |
| `-sN` | Null scan | No flags set. Bypasses stateless firewalls matching on SYN. |
| `-sF` | FIN scan | FIN flag only. Same response model as Null. |
| `-sX` | Xmas scan | FIN+PSH+URG. Same response model. |
| `-sM` | Maimon scan | FIN+ACK. Same response model. |
| `-sA` | ACK scan | Maps firewall rules, not open/closed. Returns unfiltered/filtered. |
| `-sW` | Window scan | Like ACK but reads TCP window field. Rarely reliable on modern stacks. |
| `-sI <zombie>` | Idle scan | Spoof scan using a zombie's IP ID. Stealthy, no traffic from you to target. |
| `-sO` | IP protocol scan | Enumerates which IP protocols (ICMP, TCP, UDP, GRE) are allowed. |

Port and timing options:

```
-p-                          # all 65535 ports
-p1-1023
-p 22,80,443,445,3389
--top-ports 1000             # default 1000, fastest first
-F                           # 100 most common ports
-T0 paranoid / -T1 sneaky / -T2 polite / -T3 normal / -T4 aggressive / -T5 insane
--max-rate 50 / --min-rate 15
--max-retries 0              # fewer retries, faster, may miss
--stats-every=5s             # progress every 5 seconds
-v / -vv                     # verbose / very verbose
--reason                     # show packet reason for each port state
```

Port states:

| State | Meaning |
|-------|---------|
| `open` | A service is listening and accepted the SYN. |
| `closed` | Port reachable, no service listening, RST received. |
| `filtered` | No response (dropped) or ICMP unreachable. Nmap cannot tell. |
| `unfiltered` | Port reachable but open/closed unknown, occurs with ACK scan. |
| `open|filtered` | No response, common for UDP and Null/FIN/Xmas. |
| `closed|filtered` | Only in IP ID idle scan. |

### Firewall and IDS/IPS evasion

```
-f                           # fragment packets into 8 bytes
-f -f                        # 16 bytes
--mtu 8                      # custom MTU, keep multiple of 8
--data-length 24             # add random data, change packet size
--source-port 53             # use DNS source port to bypass loose ACLs
--source-port 88             # Kerberos source port, also trusted
-S 10.10.10.200              # spoof source IP, needs -e
-e eth0                       # force interface
--spoof-mac 0                # random MAC
-D 10.10.10.5,10.10.10.6,ME  # decoys with your IP at position
-D RND:5                     # 5 random decoy IPs
--badsum                     # send invalid checksum to bypass stateless devices
--dns-servers 10.10.10.53,1.1.1.1
```

Combine for maximum stealth:

```
sudo nmap -sS -Pn -n -f --data-length 24 --source-port 53 \
  -D RND:5 --spoof-mac 0 -T2 -p 22,80,443 -oA stealth <ip>
```

### Ready-to-run scan patterns

```
# Quick triage
nmap -sS -sC -sV -Pn -oA nmap/quick <ip>
# Full port slow scan
sudo nmap -sS -sU -sV -O -p- -Pn --min-rate 1000 -oA nmap/full <ip>
# SMB everything
sudo nmap -p 139,445 --script smb-enum-*,smb-vuln-*,smb-os-discovery,smb-protocols -oA nmap/smb <ip>
# Vuln sweep
sudo nmap -sV --script vuln -p 80,443,445,3389 -oA nmap/vuln <ip>
# UDP top ports
sudo nmap -sU --top-ports 200 -sV -O -oA nmap/udp <ip>
```

---

## 4. Service and OS detection

```
-sV                          # service/version detection
-sV --version-intensity 5    # 1-9, default 7
-sV --version-light          # intensity 2, faster
-sV --version-all            # intensity 9, slowest, most thorough
-O                           # OS detection
-O --osscan-limit            # only OS-scan promising hosts
-A                           # shortcut for -sV -O -sC --traceroute
--traceroute
```

If `-sV` truncates the banner, manually grab it with `nc` and `tcpdump`.

---

## 5. Nmap Scripting Engine (NSE)

Scripts live under `/usr/share/nmap/scripts/`. Update with
`nmap --script-updatedb`.

### Categories

| Category | Use |
|----------|-----|
| `auth` | Authentication related, brute force login |
| `broadcast` | Discover hosts via broadcast protocols |
| `brute` | Brute force password auditing |
| `default` | Same as `-sC`, safe and useful |
| `discovery` | Enumerate info (DNS, SNMP, LDAP, SMB) |
| `dos` | Detect DoS-prone services, run sparingly |
| `exploit` | Try known exploits |
| `external` | Use a third party service (VirusTotal, GeoIP) |
| `fuzzer` | Fuzz services |
| `intrusive` | May crash or log on the target |
| `malware` | Look for backdoors |
| `safe` | Will not crash the target |
| `version` | Help version detection |
| `vuln` | Check for known vulnerabilities |

### Running scripts

```
-sC                          # default scripts
--script=vuln                # all vuln category
--script="ftp*"
--script="ssh2-enum-algos,ssh-auth-methods"
--script=banner,smtp-commands -p 25 <ip>
--script=smb-vuln* -p 445 <ip>
--script=http-enum -p 80 <ip>
--script-args 'user=foo,pass=bar'
```

### Nmap output and reporting

```
-oN normal.txt               # normal human-readable
-oG grep.txt                 # grepable one line per host
-oX scan.xml                 # XML for tools (metasploit, eye)
-oA base                     # all three at once
--append-output              # resume into existing file
-oX - | xsltproc -o scan.html -   # convert XML to HTML for reporting
```

Searching grepable output for live hosts and open ports:

```
grep 'Status: Up' scan.gnmap | cut -d' ' -f2
grep ' 445/open/' scan.gnmap | cut -d' ' -f2
```

---

## 6. Subdomain enumeration

### Passive sources (start here)

```
subfinder -d domain.com -all -o subs.txt
subfinder -d domain.com -all -recursive -o subs.txt
assetfinder domain.com | tee -a subs.txt
amass enum -d domain.com -passive -o subs.txt
chaos -d domain.com -key $CHAOS_KEY                # ProjectDiscovery Chaos API
curl -s "https://crt.sh/?q=%25.domain.com&output=json" | jq -r '.[].name_value' | sort -u
# GetAllURLs (gau) pulls from Wayback, CommonCrawl, OTX, URLScan
gau domain.com | unfurl --format list domains | sort -u
```

### Active brute force

```
gobuster dns -d domain.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
ffuf -u http://FUZZ.domain.com -w subs.txt -mc 200,301,302,401,403
massdns -r resolvers.txt subdomains.txt -o results.txt
 shuffledns -d domain.com -w subs.txt -r resolvers.txt
```

### DNS resolution and validation

```
dnsx -d domain.com -w subs.txt -a -resp -o resolved.txt
dnsx -d domain.com -w subs.txt -a -aaaa -cname -ns -mx -o resolved.txt
dnsx -d domain.com -w subs.txt -rcode noerror,servfail
```

### Subdomain takeover checks

```
nuclei -t takeovers/ -u <(cat subs.txt | sed 's/^/http:\/\//')
subzy run --targets subs.txt --verify
```

---

## 7. Web discovery

### Tech stack and headers

```
httpx -l hosts.txt -title -tech-detect -status-code -o httpx.txt
httpx -l hosts.txt -title -tech-detect -ip -cname -cdn -o httpx.txt
whatweb http://<ip>/
wappalyzer http://<ip>/
nmap -p 80,443 --script http-title,http-headers,http-enum <ip>
```

### Directory and content discovery

```
feroxbuster -u http://<ip> -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php,asp,aspx,jsp,html,bak,old
gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt -x php,bak,old
ffuf -u http://<ip>/FUZZ -w seclists/Discovery/Web-Content/raft.txt -mc 200,301,401,403
dirsearch -u http://<ip>
```

### Vhost discovery

```
ffuf -u http://<ip> -H "Host: FUZZ.domain.com" -w vhosts.txt -fs <original-size>
gobuster vhost -u http://<ip> -w vhosts.txt
```

### Web crawling and endpoint extraction

```
katana -u http://<ip> -d 3 -jc -o endpoints.txt
katana -u http://<ip> -kf all -aff -o endpoints.txt
gau domain.com | tee urls.txt
hakrawler -u http://<ip> -d 3
# JS endpoint extraction
linkfinder.py -i "http://<ip>" -o cli
jsfinder -u http://<ip>/script.js
```

### Nuclei - template based vulnerability scanning

Nuclei is the dominant vulnerability scanner in 2024-2026, with thousands
of templates and active community contributions.

```
nuclei -u http://<ip> -o nuclei.txt
nuclei -l hosts.txt -t cves/ -o nuclei-cves.txt
nuclei -u http://<ip> -severity critical,high
nuclei -u http://<ip> -t exposures/ -o nuclei-exposures.txt
nuclei -u http://<ip> -dast                    # DAST mode (2024+)
nuclei -u http://<ip> -hed                     # honeypot detection
nuclei -u http://<ip> -uc                      # uncover engine federation
```

2024-2026 Nuclei additions: DAST mode, honeypot detection, uncover engine
federation, AI prompt template generation (PDCP cloud).

---

## 8. Cloud discovery

### Cloud metadata

```
# AWS IMDSv1 (no auth) - still common on older instances
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# AWS IMDSv2 (requires token)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# GCP
curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -s -H 'Metadata: true' "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Alibaba Cloud
curl -s "http://100.100.100.200/latest/meta-data/"
```

### AWS bucket discovery

```
aws s3 ls s3://<bucket-name> --no-sign-request
aws s3 ls s3://<bucket-name> --recursive --no-sign-request
# Subdomain to bucket:
ffuf -u http://FUZZ.s3.amazonaws.com -w subs.txt
# Permutations:
permutations_service <tool> on domain permutations
```

### Kubernetes API discovery

```
ls -l /var/run/secrets/kubernetes.io/serviceaccount
cat /var/run/secrets/kubernetes.io/serviceaccount/token
env | grep KUBE
# If token present, talk to the API:
curl -k -H "Authorization: Bearer $(cat .../token)" \
  https://kubernetes.default.svc/api/v1/namespaces/default/pods
# From outside:
curl -k https://<k8s-api>:6443/api/v1/namespaces
kubectl auth can-i --list                  # RBAC check
```

---

## 9. Active Directory discovery

### BloodHound CE (Community Edition)

BloodHound Legacy (v4) is deprecated/archived. CE (v6) is the future: Go
REST API backend, PostgreSQL app DB, Neo4j graph DB, React frontend. In
2025, OpenGraph integration extends beyond AD/Azure to diverse identity
platforms (Okta, GitHub, AWS IAM) via a connector library.

```
# SharpHound from a shell (v2.X, SpecterOps)
SharpHound.exe -c All --zipfilename out.zip
SharpHound.exe -c DCOnly --stealth
SharpHound.exe -c Session,LoggedOn --loop --loopduration 02:00:00
SharpHound.exe -c Container,Group,ACL,ObjectProps --searchforest

# BloodHound.py CE branch (remote, no shell)
bloodhound-ce-python -u user -p 'pass' -d domain.local -dc-ip 10.10.10.10 -c all

# Legacy BloodHound.py (for BH v4)
bloodhound-python -u user -p 'pass' -d domain.local -dc dc -c All

# AzureHound (Azure/Entra)
./azurehound --tenant <id> --client-id <id> --client-secret <secret> list
```

SharpHound collection methods: Container, Group, LocalGroup, Session,
LoggedOn, ObjectProps, ACL, ComputerOnly, Trusts, Default, RDP, DCOM,
DCOnly, UserRights, CARegistry, DCRegistry, CertServices, WebClientService,
NTLMRegistry, SMBInfo, LdapServices.

### AD enumeration with NetExec

NetExec (CrackMapExec successor) is the active fork with 6700+ commits,
RDP/VNC/SSH/FTP support, and regular community PRs.

```
nxc smb 10.10.10.0/24 -u '' -p '' --shares
nxc smb 10.10.10.0/24 -u 'guest' -p '' --shares
nxc ldap 10.10.10.10 -u user -p pass --bloodhound -c All
nxc smb 10.10.10.0/24 -u user -p pass --rid-brute
nxc mssql 10.10.10.10 -u sa -p pass -x "whoami"
nxc winrm 10.10.10.10 -u user -p pass -x "hostname"
nxc smb 10.10.10.0/24 -u user -p pass --kerberoasting
```

### LDAP enumeration

```
ldapsearch -x -H ldap://<ip> -b "dc=domain,dc=local"
ldapsearch -x -H ldap://<ip> -s base '(objectclass=*)'
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

### Kerberos enumeration

```
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='DOMAIN.LOCAL' <ip>
kerbrute -d domain.local --dc <ip> userenum users.txt
kerbrute -d domain.local --dc <ip> passwordspray users.txt 'Fall2025!'

# AS-REP roasting (find accounts without pre-auth)
impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass -format hashcat
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Kerberoasting (find SPN accounts)
impacket-GetUserSPNs <domain>/<user>:<pass> -request -outputfile tgs.txt
Rubeus.exe kerberoast /rc4opsec /ldaps /outfile:hashes.txt
```

### ADCS discovery

```
certipy find -u user@domain.local -p 'pass' -dc-ip <ip> -vulnerable
Certify.exe find /vulnerable
Certify.exe cas
```

### chainreactors (Chinese red-team toolchain)

chainreactors is a serious red-team toolchain with ~1k followers:
- `gogo` - heuristic internal scanner (2.1k stars), fast multi-protocol sweep
- `spray` - HTTP fuzzer
- `zombie` - brute forcer
- `redboot` roadmap - IoM C2 + mapping ASM + remote tunnel

```
gogo -l 10.10.10.0/24 -m default
gogo -t 10.10.10.10 -p 1-65535
spray -u http://target -w wordlist
```

---

## 10. IoT and ICS discovery

ZGrab2 covers 30+ protocols including AMQP, MQTT, BACnet, DNP3, Modbus.

```
# MQTT (1883/8883) - IoT message broker
zgrab2 mqtt -p 1883 10.10.10.0/24
nmap -p 1883 --script mqtt-subscribe <ip>
# AMQP (5672) - message queue
zgrab2 amqp -p 5672 10.10.10.0/24
# Modbus (502) - ICS PLC
zgrab2 modbus -p 502 10.10.10.0/24
nmap -p 502 --script modbus-discover <ip>
# BACnet (47808) - building automation
zgrab2 bacnet -p 47808 10.10.10.0/24
# DNP3 (20000) - power systems
zgrab2 dnp3 -p 20000 10.10.10.0/24
```

---

## 11. Comparison matrix

| Tool | Category | Speed | Best for |
|------|----------|-------|----------|
| masscan | Port scan | 10M pps | Internet-wide single-port |
| ZMap | Port scan | line rate | Single-port research |
| Naabu | Port scan | fast | PD ecosystem integration |
| RustScan | Port scan | fast | Nmap handoff |
| Nmap | Port scan + service | slow | Accuracy, NSE, version |
| subfinder | Subdomain | fast | Passive sources |
| amass | Subdomain | medium | Deep passive + active |
| dnsx | DNS | fast | Resolution + validation |
| httpx | HTTP probe | fast | Title, tech, status |
| feroxbuster | Web content | medium | Recursive content |
| ffuf | Web fuzz | fast | Flexible fuzzing |
| gobuster | Web + DNS | medium | Simple brute |
| katana | Crawl | fast | JS endpoint extraction |
| nuclei | Vuln scan | fast | Template based |
| BloodHound CE | AD mapping | slow | Attack path analysis |
| NetExec | AD exec | fast | Multi-protocol sweep |
| Coercer | AD coerce | fast | NTLM relay triggers |
| gogo | Internal scan | fast | Heuristic multi-protocol |

---

## 12. Ready-to-use pipeline one-liners

### ProjectDiscovery recon pipeline (the 2024-2026 standard)

```
subfinder -d domain.com -all -recursive -o subs.txt
dnsx -l subs.txt -a -resp -o resolved.txt
naabu -list resolved.txt -top-ports 1000 -o ports.txt
httpx -l ports.txt -title -tech-detect -status-code -o live.txt
katana -u live.txt -d 3 -jc -o endpoints.txt
nuclei -l live.txt -severity critical,high -o vulns.txt
```

### Internal network sweep

```
masscan 10.10.10.0/24 -p1-65535 --rate=10000 -oJ masscan.json
jq -r '.[].ip + " " + (.[].ports[].port|tostring)' masscan.json > targets.txt
nmap -sV -sC -p<ports> 10.10.10.0/24 -oA nmap/internal
nxc smb 10.10.10.0/24 -u '' -p '' --shares
nxc smb 10.10.10.0/24 -u 'guest' -p '' --shares
```

### AD discovery chain

```
nxc smb 10.10.10.0/24 -u '' -p '' --shares
nxc ldap 10.10.10.10 -u user -p pass --bloodhound -c All
bloodhound-ce-python -u user -p pass -d domain.local -dc-ip 10.10.10.10 -c all
certipy find -u user@domain.local -p pass -dc-ip 10.10.10.10 -vulnerable
impacket-GetUserSPNs domain.local/user:pass -request -outputfile tgs.txt
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -format hashcat
```

### Stealth external scan

```
sudo nmap -sS -Pn -n -f --data-length 24 --source-port 53 \
  -D RND:5 --spoof-mac 0 -T2 -p 22,80,443,445,3389 -oA stealth <ip>
```

---

## 13. Quick reference table

```
# Host discovery
-sn / -Pn / -PE / -PS / -PA / -PU / -PR / arp-scan / fping

# Port scan
masscan / ZMap / Naabu / RustScan / Nmap -sS -sT -sU -sN -sF -sX -sM -sA -sW -sI -sO

# Detection
-sV / -O / -A / --traceroute / ZGrab2

# Subdomain
subfinder / amass / assetfinder / chaos / dnsx / massdns / shuffledns

# Web
httpx / whatweb / feroxbuster / ffuf / gobuster / katana / gau / nuclei

# Cloud
curl 169.254.169.254 / aws s3 / kubectl / k8s API

# AD
BloodHound CE / SharpHound / NetExec / ldapsearch / kerbrute / certipy / Coercer

# IoT/ICS
ZGrab2 mqtt/amqp/modbus/bacnet/dnp3 / nmap --script modbus-discover

# Evasion
-f / --mtu / --data-length / --source-port / -D / -S / -e / --spoof-mac / --badsum

# Output
-oN / -oG / -oX / -oA / --append-output
```

---

## 14. References

- Nmap book (free): <https://nmap.org/book/>
- Nmap NSE docs: <https://nmap.org/nsedoc/>
- masscan: <https://github.com/robertdavidgraham/masscan>
- RustScan: <https://github.com/RustScan/RustScan>
- Naabu: <https://github.com/projectdiscovery/naabu>
- ZMap: <https://github.com/zmap/zmap>
- ZGrab2: <https://github.com/zmap/zgrab2>
- subfinder: <https://github.com/projectdiscovery/subfinder>
- httpx: <https://github.com/projectdiscovery/httpx>
- nuclei: <https://github.com/projectdiscovery/nuclei>
- dnsx: <https://github.com/projectdiscovery/dnsx>
- katana: <https://github.com/projectdiscovery/katana>
- ProjectDiscovery: <https://github.com/projectdiscovery>
- feroxbuster: <https://github.com/epi052/feroxbuster>
- ffuf: <https://github.com/ffuf/ffuf>
- gobuster: <https://github.com/OJ/gobuster>
- gau: <https://github.com/lc/gau>
- assetfinder: <https://github.com/tomnomnom/assetfinder>
- massdns: <https://github.com/blechschmidt/massdns>
- BloodHound CE: <https://github.com/SpecterOps/BloodHound>
- SharpHound: <https://github.com/SpecterOps/SharpHound>
- BloodHound.py: <https://github.com/dirkjanm/BloodHound.py>
- NetExec: <https://github.com/Pennyw0rth/NetExec>
- chainreactors: <https://github.com/chainreactors>
- HackTricks Pentesting Methodology: <https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-methodology>