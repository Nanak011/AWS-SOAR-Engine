<img width="1380" height="752" alt="soar_architecture" src="https://github.com/user-attachments/assets/a6af42c6-1496-4a22-83a0-d3ca1a49ec0b" />





# Automated Cloud Threat Mitigation & SOAR Pipeline

An enterprise-grade **Security Orchestration, Automation, and Response (SOAR)** pipeline designed to automatically detect Layer 7 web attacks and instantly isolate a public-subnet cloud infrastructure using an out-of-band incident containment loop.

---

##  Project Overview

This project implements a live web application environment designed with strict proxy security boundaries. Although the backend EC2 server is located within a **public subnet**, its security group is hardened to completely drop direct public access from the internet. It relies entirely on an edge-defense Application Load Balancer to proxy clean traffic.

When a malicious exploitation attempt (such as an automated scanner web fingerprint) hits the environment, an inline Web Application Firewall (WAF) blocks the attack. The pipeline automatically handles log parsing, host isolation, and out-of-band notification asynchronous to core application traffic, responding in under two seconds upon log delivery.

###  How It Works (The Containment Loop)
1. **Attack Detection:** A malicious request targets the public **Application Load Balancer (ALB)** and is dropped instantly by **AWS WAF** with an `HTTP 403 Forbidden` response.
2. **Telemetry Buffering:** AWS WAF bundles access and block records into compressed `.gz` telemetry files and streams them into an **Amazon S3** bucket.
3. **Automated Trigger:** An S3 Object Creation Event natively wakes up a serverless **AWS Lambda** containment engine.
4. **In-Memory Analysis:** The Lambda script dynamically decompresses the log bundle, extracts individual json payloads, scans for `BLOCK` configurations, and fingerprints the attacker's client IP.
5. **Network Quarantine:** Lambda calls the Amazon EC2 API to instantly strip the targeted web server of its production security group (`soar_production_target_sg`) and attaches an empty **Quarantine Security Group** (`soar_production_quarantine_sg`), locking out all inbound connections (including the ALB).
6. **Out-of-Band Alerting:** Simultaneously, Lambda constructs a custom TwiML voice payload and sends a basic authentication webhook request out to the **Twilio Voice API** to dynamically place an emergency phone call to the security engineer on duty.

---

##  AWS & Third-Party Services Used

* **Amazon EC2:** Hosts the target application server inside a **Public Subnet** (Ubuntu 24.04 LTS), containerized via **Docker** running the Damn Vulnerable Web Application (DVWA).
* **AWS Application Load Balancer (ALB):** Acts as the public-facing edge proxy, accepting global web requests and routing them backend via strict security group targeting.
* **AWS WAF (Web Application Firewall):** Attached directly to the ALB to inspect incoming Layer 7 traffic against Core Rule Set (CRS) and Known Bad Inputs rules.
* **Amazon S3:** Functions as the forensic log repository where AWS WAF streams compressed log batches.
* **AWS Lambda:** Houses the Python 3.12 automation code that executes decompression, target identification, and automated quarantine blocks.
* **AWS IAM:** Enforces least-privilege policies allowing Lambda to safely modify EC2 attributes and read S3 objects.
* **Twilio Voice API:** Provides the out-of-band communication bridge to escalate security alerts to standard telephonic voice calls.

---

## Video: https://www.linkedin.com/posts/gurunanakadhikari_cybersecurity-aws-cloudsecurity-ugcPost-7463055634679377921-zPnm?utm_source=social_share_send&utm_medium=member_desktop_web&rcm=ACoAAEtEqhwBtd9Rjbr84IsWwWRE8ExCL1UNzXU

##  Infrastructure Blueprint

```text
[ Public Internet Traffic ]
           │
           ▼
┌─────────────────────────── AWS VPC ───────────────────────────┐
│                                                               │
│   ┌─────────────────── Public Subnet ─────────────────────┐   │
│   │                                                       │   │
│   │   [ Inbound Users ] ──> [ App Load Balancer ]         │   │
│   │                                │                      │   │
│   │                                ▼                      │   │
│   │                       [ AWS WAF Firewall ]            │   │
│   │                                │                      │   │
│   │                                │ (If Traffic is Clean)│   │
│   │                                ▼                      │   │
│   │                    [ EC2 Web Server ]                 │   │
│   │                 (soar_production_target_sg)           │   │
│   │                                                       │   │
│   └───────────────────────────────────────────────────────┘   │
└────────────────────────────────────┼──────────────────────────┘
                                     │ (If Attack Detected: Writes Log)
                                     ▼
                            [ Amazon S3 Bucket ]
                       (aws-waf-logs-soar-production)
                                     │
                                     │ (Triggers Event)
                                     ▼
                           [ AWS Lambda Engine ]
                     (soar_production_containment_engine)
                               /           \
                 (Swaps SG)   /             \ (Fires Webhook)
                             ▼               ▼
                   [ Quarantine Cell ]    [ Twilio API Gateway ]
               (soar_production_quarantine_sg)       │
                                                     ▼
                                            [ Emergency Phone Call ]
