+++
title = "Nmap: The Operator's Field Manual — From Host Discovery to Firewall Bypass"
date = 2026-02-25T00:00:00Z
draft = false
description = "A complete Nmap field reference for penetration testers — covering host discovery, TCP/UDP scanning, NSE scripting, performance tuning, firewall and IDS evasion, output formats, and a phase-ordered scan playbook. Built for operators who need precision, not padding."
tags = ["Nmap", "Network Scanning", "Reconnaissance", "Enumeration", "Firewall Evasion", "NSE", "Penetration Testing", "Port Scanning", "Cybersecurity", "Red Teaming"]
+++

# Nmap: The Operator's Field Manual

Nmap is not a beginner tool that advanced operators graduate away from. It's the opposite — the deeper your tradecraft, the more you rely on it. From host discovery in a blind `/24` to firewall fingerprinting and NSE-driven vulnerability detection, Nmap underpins every phase of the reconnaissance and scanning lifecycle.

This post is a complete field reference. No theory padding. Every command is battle-tested.

---

## Host Discovery — Mapping the Terrain

Before scanning ports, confirm what's alive. Burning scan cycles against dead hosts is noise.

### ICMP Echo — Basic Ping Sweep

```bash
sudo nmap $TARGET_IP -sn -PE --packet-trace --reason
```

`-sn` disables port scanning. `-PE` sends ICMP echo requests. `--reason` tells you *why* Nmap called the host up or down — critical for diagnosing filtered environments.

### Network Range Sweep

```bash
sudo nmap $SUBNET/24 -sn -oA recon/discovery
```

### From an IP List

```bash
sudo nmap -sn -oA recon/sweep -iL hosts.lst
```

### IP Range (Sequential)

```bash
sudo nmap -sn -oA recon/range $TARGET_IP-20
```

> **Operator note**: On hardened networks, ICMP is often blocked at the perimeter. A host that doesn't respond to `-PE` is not necessarily dead. Validate with TCP probes (`-PS80,443`) before writing it off.

---

## Port Scanning — Finding Open Doors

### TCP SYN Scan — The Workhorse

```bash
sudo nmap $TARGET_IP -sS
```

The SYN scan sends a SYN, waits for SYN-ACK, then RSTs without completing the handshake. It's fast, relatively quiet, and requires root. This is your default for 90% of engagements.

### TCP Connect Scan — No Root Required

```bash
nmap $TARGET_IP -sT
```

Completes the full three-way handshake. Noisier — it will show up in connection logs. Use when you don't have raw socket access.

### Targeted Port Selection

```bash
# Specific ports
nmap -p 22,80,443 $TARGET_IP

# Port range
nmap -p 1-1000 $TARGET_IP

# All 65535 ports — never skip this on a thorough engagement
nmap -p- $TARGET_IP

# Top 10 most common ports
nmap --top-ports 10 $TARGET_IP

# Fast scan — top 100
nmap -F $TARGET_IP
```

### UDP Scan — The Forgotten Attack Surface

UDP is slow, but the services hiding there (SNMP, TFTP, DNS, NTP) are often the most exploitable.

```bash
sudo nmap $TARGET_IP -sU -F
```

> SNMP on UDP/161 with community string `public` is a full system info disclosure. Always scan UDP. Always.

---

## Service & Version Detection — Know What You're Hitting

Port state alone is not enough. Before you pull an exploit, you need the exact service version.

```bash
# Version detection
nmap -sV $TARGET_IP

# Full port sweep with version detection
nmap -p- -sV $TARGET_IP

# Monitor progress on long scans
nmap -p- -sV --stats-every=5s $TARGET_IP

# Verbose output
nmap -p- -sV -v $TARGET_IP
```

Combine with SYN scan on targeted ports after your initial full sweep:

```bash
sudo nmap -sS -sV -p 22,80,443 $TARGET_IP
```

---

## Nmap Scripting Engine (NSE) — Weaponizing the Scanner

NSE is where Nmap stops being a port scanner and starts being an enumeration framework.

### Script Categories

| Category | Purpose |
|---|---|
| `auth` | Test authentication mechanisms |
| `brute` | Brute-force credentials |
| `vuln` | Detect known vulnerabilities |
| `safe` | Non-intrusive enumeration |
| `discovery` | Service and host enumeration |
| `exploit` | Actively exploit vulnerabilities |

### Running Scripts

```bash
# Default safe scripts (equivalent to -sC)
nmap -sC $TARGET_IP

# Entire vulnerability category
nmap --script vuln $TARGET_IP

# Targeted scripts
nmap --script banner,smtp-commands $TARGET_IP

# Aggressive mode — OS detection + version + scripts + traceroute
nmap -A $TARGET_IP
```

### High-Value Script Combos

```bash
# HTTP enumeration
nmap --script http-enum,http-headers,http-methods -p 80,443 $TARGET_IP

# WordPress specific
nmap --script http-wordpress-enum -p 80 $TARGET_IP

# SMB vulnerability check
nmap --script smb-vuln-ms17-010,smb-enum-shares -p 445 $TARGET_IP

# SMB OS discovery
nmap --script smb-os-discovery -p 445 $TARGET_IP

# SSH algorithm enumeration
nmap --script ssh2-enum-algos -p 22 $TARGET_IP

# SNMP enumeration
nmap --script snmp-info,snmp-interfaces -p 161 -sU $TARGET_IP

# Banner grab
nmap --script banner -p 22,80,8080 $TARGET_IP
```

---

## Performance Tuning — Speed vs. Stealth

Nmap's timing and rate controls are not set-and-forget. Tune based on your operational context.

### Timing Templates

| Template | Use Case | Noise Level |
|---|---|---|
| `-T0` Paranoid | Maximum evasion, very slow | Minimal |
| `-T1` Sneaky | IDS evasion, long engagements | Low |
| `-T2` Polite | Stealth, avoid saturating network | Low |
| `-T3` Normal | Default behavior | Medium |
| `-T4` Aggressive | Lab/CTF environments | High |
| `-T5` Insane | Speed over accuracy | Maximum |

### Manual Rate and Timeout Control

```bash
# Tighten RTT timeouts for fast networks
nmap --initial-rtt-timeout 50ms --max-rtt-timeout 100ms $TARGET_IP

# Kill retries — speed at cost of accuracy
nmap --max-retries 0 $TARGET_IP

# Minimum packet rate
nmap --min-rate 300 $TARGET_IP

# Combined aggressive performance
nmap -T5 --min-rate 500 --max-retries 1 $TARGET_IP
```

> **Field rule**: `-T4` in controlled lab environments. `-T2` or manual tuning against production targets. `-T5` will cause dropped packets and false negatives on congested networks.

---

## Firewall & IDS Evasion — When the Target Fights Back

A `filtered` result is not a dead end. It's an invitation to get creative.

### ACK Scan — Map the Firewall Ruleset

```bash
sudo nmap -sA $TARGET_IP
```

ACK packets bypass stateless packet filters. If the port returns RST, it's unfiltered (regardless of open/closed). If there's no response — it's filtered. Use this to fingerprint firewall rules before attempting exploitation.

### Decoy Scanning — Obscure Your Origin

```bash
sudo nmap -D RND:5 $TARGET_IP
```

Nmap generates 5 random decoy IPs alongside your real source IP. The target's IDS sees multiple scanners, making attribution harder.

### Source IP Spoofing

```bash
sudo nmap -S $SPOOF_IP -e tun0 $TARGET_IP
```

Sends packets with a spoofed source IP. Use `-e` to specify the correct egress interface.

### Source Port Manipulation — Port 53 Bypass

Stateful firewalls often trust inbound traffic originating from port 53 (DNS). Exploit that trust:

```bash
sudo nmap --source-port 53 $TARGET_IP
```

**Full firewall bypass combo against a hardened target:**

```bash
sleep 600; nmap -sA -D RND:5 -p- -sVC --source-port 53 -T2 $TARGET_IP
```

The `sleep 600` lets any IDS alert cool down before the scan fires. The combination of ACK scan, decoys, source-port 53, and `-T2` timing is purpose-built for getting clean results through a stateful firewall.

**Verify an open port manually via source port 53:**

```bash
sudo nc -s $ATTACKER_IP -p 53 $TARGET_IP 50000
```

### Packet Fragmentation

```bash
# Fragment IP packets — evades some signature-based IDS
sudo nmap -f $TARGET_IP

# Custom MTU fragmentation
sudo nmap --mtu 24 $TARGET_IP
```

### IDS Rotation Strategy

If your source IP gets blocked:

- Pre-stage multiple VPS nodes across different ASNs
- Monitor for block events in scan output (sudden all-filtered responses)
- Rotate source IP and resume from last known-good port range

---

## Output Formats — Document Everything

Every scan gets saved. No exceptions. You cannot reconstruct scan state from memory during a debrief.

```bash
# Save all formats simultaneously (normal, grepable, XML)
nmap -oA results/targetA $TARGET_IP

# Normal text
nmap -oN results/targetA.txt $TARGET_IP

# Grepable — pipe to grep, awk, cut
nmap -oG results/targetA.gnmap $TARGET_IP

# XML — parse with scripts, import into tools
nmap -oX results/targetA.xml $TARGET_IP

# Convert XML to HTML report
xsltproc results/targetA.xml -o results/targetA.html
```

> Always use `-oA` with a descriptive path. `results/targetA_full_tcp_$(date +%Y%m%d)` beats `scan1.txt` every time.

---

## Port States — Decoding the Output

| State | Meaning | Operator Action |
|---|---|---|
| `open` | Service accepting connections | Enumerate and exploit |
| `closed` | Port reachable, no service listening | Note — may change; revisit |
| `filtered` | No response — firewall likely blocking | Apply bypass techniques |
| `unfiltered` | ACK reached, state unknown | Run `-sV` to clarify |
| `open\|filtered` | No response to SYN or UDP | Fragment, source-port manipulation |

---

## Scan Playbook — Ordered by Engagement Phase

### Phase 1: Initial Reconnaissance

```bash
# Host discovery — quiet sweep
sudo nmap $SUBNET/24 -sn -PE -oA recon/discovery
```

### Phase 2: Full Port Enumeration

```bash
# All TCP ports — never skip this
sudo nmap -sS -p- --min-rate 500 -oA scans/full_tcp $TARGET_IP

# Top 20 UDP ports
sudo nmap -sU --top-ports 20 -oA scans/udp_top20 $TARGET_IP
```

### Phase 3: Service Fingerprinting

```bash
# Extract open ports from grepable output and run service scan
ports=$(grep open scans/full_tcp.gnmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
sudo nmap -sS -sV -sC -O -p $ports -oA scans/services $TARGET_IP
```

### Phase 4: Vulnerability Detection

```bash
sudo nmap --script vuln -p $ports -oA scans/vulns $TARGET_IP
```

### Phase 5: Targeted Enumeration

```bash
# Web
sudo nmap --script http-enum,http-headers -p 80,443,8080 $TARGET_IP

# SMB
sudo nmap --script smb-vuln-ms17-010,smb-enum-shares -p 445 $TARGET_IP

# SNMP
sudo nmap --script snmp-info -sU -p 161 $TARGET_IP
```

### Phase 6: Firewall Bypass (Hardened Targets)

```bash
# ACK probe to map firewall rules
sudo nmap -sA -p- -oA scans/ack_probe $TARGET_IP

# Full bypass scan
sleep 600; nmap -sA -D RND:5 -p- -sVC --source-port 53 -T2 -oA scans/bypass $TARGET_IP
```

---

## Quick Reference — All Key Flags

| Flag | Function |
|---|---|
| `-sS` | SYN scan (stealth, requires root) |
| `-sT` | TCP connect scan (no root) |
| `-sU` | UDP scan |
| `-sA` | ACK scan (firewall mapping) |
| `-sV` | Service version detection |
| `-sC` | Default NSE scripts |
| `-O` | OS detection |
| `-A` | Aggressive (OS + version + scripts + traceroute) |
| `-p-` | All 65535 ports |
| `-F` | Fast — top 100 ports |
| `--top-ports N` | Top N most common ports |
| `-sn` | Host discovery only, no port scan |
| `-PE` | ICMP echo request |
| `--packet-trace` | Show all sent/received packets |
| `--reason` | Display why a port is in its state |
| `-D RND:N` | Decoy scan with N random IPs |
| `-S <IP>` | Spoof source IP |
| `--source-port N` | Set source port |
| `-f` | Fragment packets |
| `--mtu N` | Custom MTU fragmentation |
| `--min-rate N` | Minimum packets per second |
| `--max-retries N` | Probe retry limit |
| `--stats-every=Ns` | Progress update interval |
| `-oA <file>` | Save output in all formats |
| `-v` | Verbose output |
| `-T0` to `-T5` | Timing templates |

---

*Nmap is the first tool on the wire and the last one you'll stop needing. Master the flags, understand what each packet does, and the scan output stops being data — it becomes intelligence.*
