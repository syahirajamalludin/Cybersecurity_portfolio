# Cybersecurity Portfolio
Hands-on projects in network security, threat detection, and fraud-to-cybersecurity — from building secure Cisco networks to hunting threats in logs with Python and SQL.

Hi, I’m Nurul 👋  
Currently a Risk Data Analyst (Fraud Detection) with a Master’s in Data Science.  
Transitioning into Cybersecurity Analyst roles with a focus on **network traffic analysis, SIEM logs, and anomaly detection**.  

This portfolio documents my **hands-on learning journey**.

## Objectives
To apply the skills I've learned to close the gap into cybersecurity.

## Certifications
![CCNA](https://img.shields.io/badge/Cisco-CCNA-blue)
![CCNP Security](https://img.shields.io/badge/Cisco-CCNP%20Security-red)
![Security Core](https://img.shields.io/badge/Cisco-Security%20Core-orange)
![Web Content Security](https://img.shields.io/badge/Cisco-Web%20Content%20Security-green)

## Tools
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?logo=wireshark&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![Excel](https://img.shields.io/badge/Excel-217346?logo=microsoftexcel&logoColor=white)
![SQL](https://img.shields.io/badge/SQL-4479A1?logo=postgresql&logoColor=white)
![Power BI](https://img.shields.io/badge/Power%20BI-F2C811?logo=powerbi&logoColor=black)
![Tableau](https://img.shields.io/badge/Tableau-E97627?logo=tableau&logoColor=white)
![Cisco Packet Tracer](https://img.shields.io/badge/Packet%20Tracer-1BA0D7?logo=cisco&logoColor=white)
![Squid](https://img.shields.io/badge/Squid%20Proxy-555555)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?logo=scikitlearn&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-555555)

## Projects

| # | Project | What I did | Tools | Status |
| --- | --- | --- | --- | --- |
| 1 | [PCAP Traffic Analysis – "It's a Trap!"](./pcap-analysis/its-a-trap-2018-07-20) | Traced a fake-software infection end to end: `setup.exe` download, a second-stage program disguised as a `.png`, and C2 check-ins every 60 s — the smallest conversation in the capture. Wireshark by hand, then automated in Python | Wireshark, Python (scapy) | ✅ Done |
| 2 | [Log Analysis – Brute-Force & Credential Stuffing](./log-analysis/brute-force) | Detected two password-based attacks in SSH logs, including a credential-stuffing break-in that per-account alerts would miss; linked to Malaysia's rising credential-theft trend | Python (pandas, matplotlib) | ✅ Done |
| 3 | [Network Lab – Secure Small Office Network](./network-labs/01-small-office-network) | Designed an HQ + branch network with 4 VLANs, OSPF, DHCP relay, NAT, and ACLs that isolate guests and protect Finance; hardened with SSH-only access and port security | Cisco Packet Tracer, Cisco IOS | 🛠️ Configs ready · lab build in progress |
| 4 | [Network Lab – Zone-Based Firewall + Site-to-Site VPN](./network-labs/02-firewall-vpn) | Designed a 3-zone firewall (Inside/DMZ/Outside) where a hacked web server can't reach the office, an AES-256 IPsec tunnel to a branch with NAT exemption, RADIUS admin logins, and syslog | Cisco Packet Tracer, Cisco IOS | 🛠️ Configs ready · lab build in progress |
| 5 | [Web Proxy – URL Filtering & Proxy Log Threat Hunting](./web-security/proxy-url-filtering) | Built and tested a Squid proxy policy mirroring Cisco WSA features, then found an infected PC beaconing every 300 s, its "patient zero" download, a phishing wave, and a 3.4 GB after-hours upload | Squid, Docker, Python | ✅ Done |
| 6 | [DDoS Detection – Rate Rule vs Machine Learning](./ml-detection/ddos-detection) | Showed a simple packets-per-second rule catches only 29% of attacks (4% of SYN floods); a Random Forest catches 98% and names the attack type | Python (scikit-learn) | ✅ Done |
| 7 | [Fraud → Cybersecurity: Account Takeover Detection](./fraud-to-cyber/account-takeover) | Mapped my fraud-analyst workflow to SOC work; 8 SQL/Python rules + risk scoring uncovered ~RM 36,300 stolen across 6 accounts through one mule account, plus a SIM swap caught before cash-out | SQL (SQLite), Python | ✅ Done |

> 🔁 Every project README ends with a **"Redo it yourself"** step-by-step checklist, so anyone (including me!) can rebuild it and understand each step.

## Projects by Skill Areas and Certifications
| Certificates | Skills | Associated Projects | 
| --- | --- | --- | 
| CCNA |Access Connectivity <br> Architectures and Services <br> Assurance and Automation <br> Automation <br> Connectivity <br> Core Routing <br> High Availability and Fast Convergence <br> IP <br> IP services <br> Network Access <br> Network Fundamentals <br> Programability <br> Security <br> Security Fundamentals| [Secure Small Office Network](./network-labs/01-small-office-network) <br> [Firewall + Site-to-Site VPN](./network-labs/02-firewall-vpn) <br> [PCAP Traffic Analysis](./pcap-analysis/its-a-trap-2018-07-20) <br> [Brute-Force & Credential Stuffing](./log-analysis/brute-force) |
| Cisco Certified Network Professional Security (CCNP Security) |802.1x <br> Access Solutions <br> Advanced Malware Protection <br> AMP <br> CCNP <br> Cloud Web Security <br> Email Security <br> FirePOWER <br> Firewalls <br> IPS <br> ISE <br> Mobility Solutions <br> NCIPS <br> Security <br> Threat Control Solutions <br> TrustSec. <br> VPNs <br> Web Security| [Firewall + Site-to-Site VPN](./network-labs/02-firewall-vpn) <br> [Web Proxy & URL Filtering](./web-security/proxy-url-filtering) <br> [Account Takeover Detection](./fraud-to-cyber/account-takeover) |
| Cisco Certified Specialist - Security Core |Cross-Site Scripting <br> DoS/DDoS Attacks <br> Endpoint Protection and Detection <br> Enforcement <br> Malware <br> man-in-the-middle attacks <br> Network Security <br> Phishing <br> Rootkits <br> Secure Network Access <br> Securing the Cloud <br> Security Concepts <br> SQL Injection <br> trojans <br> Viruses <br> Visibility| [DDoS Detection](./ml-detection/ddos-detection) <br> [Web Proxy & URL Filtering](./web-security/proxy-url-filtering) <br> [Firewall + Site-to-Site VPN](./network-labs/02-firewall-vpn) <br> [PCAP Traffic Analysis](./pcap-analysis/its-a-trap-2018-07-20) <br> [Brute-Force & Credential Stuffing](./log-analysis/brute-force) <br> [Account Takeover Detection](./fraud-to-cyber/account-takeover) |
| Cisco Certified Specialist - Web Content Security |Acceptable Use Control <br> Authentication <br> Cisco WSA Features <br> Configuration <br> Decryption Policies To Control HTTPS Traffic <br> Differentiated <br> Traffic Access Policies <br> Malware Defense <br> Proxy Services <br> Reporting And Tracking Web Transactions| [Web Proxy & URL Filtering](./web-security/proxy-url-filtering) |

---

📌 Next up: screenshots from the Packet Tracer labs, and running the DDoS model on the real CIC-DDoS2019 dataset.
