+++
title = "I Passed CPTS — From Exile, First Attempt Failure, to Certified Penetration Tester"
date = 2026-03-05T00:00:00Z
draft = false
description = "From fleeing Myanmar, failing the CPTS exam on my first attempt with only 5 flags, and starting from zero — to finally passing. The unfiltered story."
tags = ["CPTS", "HackTheBox", "Penetration Testing", "Cybersecurity Career", "Career Change", "eJPT", "TryHackMe", "Offensive Security", "HTB Certification", "My Story"]
+++

I'm from Myanmar.

If you've followed world news since 2021, you already know the rough shape of what that means. Military coup. Conflict. A country that changed overnight into something unrecognisable. I'm not going to write a political essay — there are better writers than me doing that work. What I will tell you is the personal part: in February 2024, I left. I exiled myself. I packed what I could and started over somewhere else with almost nothing.

This post is about what happened next.

---

## The First Hard Lesson

For years I worked in sales and marketing. I was genuinely good at it. I understood people, I understood campaigns, I knew how to move numbers — revenue up 13.9%, membership up 122%. I had a track record I was proud of.

What I didn't understand yet was how local those skills actually were.

Sales and marketing live inside language, culture, and relationships. The moment I crossed a border, most of that stopped working. My network didn't transfer. My language fluency didn't transfer. The market knowledge I'd built over years meant almost nothing in a new country where nobody knew me and the local language was everything.

I tried anyway. Kept applying for marketing roles. Kept picking up free certifications to pad a profile that wasn't landing. Spent months hoping the next application would be different.

Boy, I was wrong.

---

## May 2024: The Pivot

I was sitting online late one night, grinding through job boards, when something started clicking. Cybersecurity roles — everywhere. Junior analysts, SOC analysts, penetration testers. Remote positions. Global positions. The kind of work where your skills are the same whether you're in Singapore, Cambodia, Europe, or anywhere else.

You don't need to speak Khmer to run Nmap. BloodHound doesn't care what your passport says. A shell is a shell.

I started researching seriously. Went through CISO Learning, IBM's cybersecurity fundamentals, anything free I could find. And then I hit the wall every self-taught person hits eventually: free content will only carry you so far. If you want the industry to take you seriously, you need credentials the industry actually respects.

So I made a decision. I was going to spend the next two years becoming a penetration tester. No shortcuts. No easy cert followed by "let's see what happens." I was going to earn it properly.

---

## The Certification Path

Here's the honest timeline:

**December 2024 — eJPT (eLearnSecurity Junior Penetration Tester)**
My entry point. The INE course gave me real foundations — networking, basic exploitation, methodology. I came from zero technical background. It wasn't easy. I passed.

**August 2025 — PT1 / Junior Penetration Tester (TryHackMe)**
TryHackMe became my daily practice environment. 178 rooms completed. Top 2% globally. The structured path kept me moving on the days when motivation was genuinely hard to find. PT1 validated I could operate across a range of real attack scenarios.

**2026 — CPTS (HTB Certified Penetration Testing Specialist)**
This is the one. The one I built everything toward. And the one I failed the first time.

---

## First Attempt: 5 Flags. 25 Points. Failed.

I want to be honest about this because most people writing CPTS posts only share the pass.

I sat my first attempt after completing the HTB Penetration Tester path. I thought I was ready. I wasn't — not fully.

I found 5 flags. 25 points out of the 85 required to pass the lab portion. It wasn't close.

The examiner's feedback was detailed and worth sharing:

The core issue wasn't a lack of knowledge. It was mindset. I was approaching the exam like a CTF player — chasing individual flags in isolation, moving fast, not stopping to think about the full picture. Real penetration testing doesn't work like that. In a real engagement you keep meticulous notes on everything, because something you found on host A might be exactly what you need to unlock host B two hours later. I wasn't connecting the dots. I was hunting, not thinking.

The feedback also pointed to enumeration depth. I was moving on too quickly. Not thoroughly reading the web applications in front of me. Not doing proper post-exploitation on hosts I'd already compromised. Not extracting everything possible from Active Directory users I'd managed to get. In CTF you find the flag and move on. In a real pentest — and in CPTS — you stop, you document, you enumerate everything, and then you move on.

The third thing was getting stuck. I was sitting on single problems for too long, locked into one way of thinking, not stepping away and coming back with fresh eyes.

The report feedback was actually positive — well written, structured, professional. That part landed. The technical execution didn't.

---

## What Failing Taught Me

Failing the first attempt didn't break me. Honestly, it was one of the most useful things that could have happened.

It forced me to go back through the path with completely different eyes. Not "learn this to tick a box" — but "understand this deeply enough to apply it under pressure, in an unfamiliar environment, when nothing is labelled and nothing is handed to you."

I completed the path **three times in total** before my second attempt. By the end I had accumulated:

- **250+ compromised targets**
- **400+ module sections completed**
- **500+ challenge questions solved**
- **750,000+ words of technical content**

And I changed how I thought about attacking a network. Stop thinking like a CTF player. Start thinking like a penetration tester. The difference sounds simple. It isn't. CTF is about finding the intended path. Pentesting is about understanding the environment well enough that you find paths that weren't necessarily intended — and then documenting all of it clearly enough that a client can act on what you found.

**Second attempt: 90 points. Passed.**

---

## What the Examiner Said the Second Time

> *"We found your report to be very well done. You captured the description and impact of each vulnerability very well. You gave actionable remediation recommendations that do not break the line of independence that we must maintain as pentesters. Overall your report was good, well presented, precise, neat, and professional."*

Same person. Different result. Because I was a different candidate.

---

## What CPTS Actually Covers

For anyone evaluating this cert or building a study plan:

**Active Directory** — Kerberoasting, AS-REP Roasting, ACL abuse, Pass-the-Hash, DCSync, BloodHound path analysis, lateral movement via Impacket, Mimikatz, CrackMapExec/NetExec.

**Web Application** — Full OWASP Top 10: SQLi, XSS, SSRF, IDOR, authentication bypass, file upload bypass, command injection, XXE, file inclusion. Manual exploitation with Burp Suite — not automated scanning.

**Network Pentesting** — Host discovery, service enumeration, CVE-based exploitation, pivoting through segmented networks, post-exploitation enumeration.

**Privilege Escalation** — Windows and Linux, manual and tool-assisted.

**Reporting** — Commercial-grade pentest reports with executive summary, technical findings, CVSS scoring, and risk-based remediation for both CISO and SysAdmin audiences.

My current platform stats:
- **HackTheBox:** Global #752 · Top 10 Cambodia/Myanmar · 82 machines + 1 mini Pro Lab + 1 Fortress
- **TryHackMe:** Top 2% globally · 178 rooms completed
- **Also active on:** OffSec Labs · VulnLab · PortSwigger Web Academy · Hacker101

---

## If You're Going for CPTS — Read This

The learning path teaches you everything you need. Every technique, every tool, every methodology. It's genuinely comprehensive.

But the exam will not hold your hand. It will not tell you what to attack next. It will not label vulnerabilities for you. It will put a realistic network in front of you and ask whether you can think like a professional.

**The single biggest mistake you can make going into CPTS is thinking like a CTF player.**

CTF mindset: find the trick, pop the flag, move on.
Pentester mindset: understand the environment, enumerate thoroughly, take notes on everything, connect information across hosts, think about what each piece of access means for the next step.

That shift in thinking is what separates candidates who pass from candidates who don't. I know because I was on both sides of it.

Practical advice before you sit:
- Keep notes on absolutely everything — services, users, credentials, misconfigurations, anything. You will need something from hour two when you're in hour eight.
- Enumerate fully before you exploit. Understand what's in front of you.
- When you compromise a host, don't just grab the flag and leave. Do full post-exploitation. The thing you need next is probably already there.
- If you're stuck on something for more than an hour, step away. Come back. You're locked into one way of thinking and you need to break out of it.
- Have the module cheat sheets open. Use the Academy search function. This isn't cheating — it's how real work is done.

---

## What's Next

Passing CPTS changed how I think about attack and defence. Now that I understand how networks get compromised from an offensive perspective, I've started the **HTB CDSA (Certified Defensive Security Analyst) learning path** — because knowing how to break in is more useful when you also understand how defenders see the same environment.

Offence informs defence. Defence informs offence. Both make you better at both.

I'm actively looking for penetration testing roles — remote, global. If you're hiring or you know someone who is, my full profile is at [askbluecat.com](https://askbluecat.com) and I'm reachable on [LinkedIn](https://linkedin.com/in/danielminthu).

If you're somewhere in the middle of this journey — grinding through modules, just failed your first attempt, wondering if you made a mistake — reach out. I've been in that exact place.

It's worth it. Keep going.

---

*Daniel Min Thu | CPTS | Phnom Penh, Cambodia*
