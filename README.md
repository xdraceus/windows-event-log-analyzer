# 🛡️ Windows Event Log Analyzer

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)  
![Security](https://img.shields.io/badge/Cybersecurity-Log%20Analysis-red?style=for-the-badge)  
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-darkred?style=for-the-badge)  
![Status](https://img.shields.io/badge/Status-Operational-success?style=for-the-badge)

**A Python-based Windows Security Event Log Analyzer designed for security monitoring, threat detection, incident triage, and cybersecurity portfolio demonstration.**

----------

# 📌 Overview

The **Windows Event Log Analyzer** is a modular cybersecurity project built to simulate core functionality commonly associated with:

-   SIEM pipelines
    
-   Security monitoring systems
    
-   SOC alert triage
    
-   Detection engineering
    
-   Windows event auditing
    
-   Blue-team analysis workflows
    

The project parses Windows Security Event Logs from CSV exports, applies behavioral and event-based detection rules, and generates human-readable security reports suitable for:

-   Incident response investigations
    
-   Threat hunting exercises
    
-   SOC analyst training
    
-   Detection engineering demonstrations
    
-   Cybersecurity portfolio projects
    
-   Resume/GitHub showcasing
    

----------

# 🧠 Cybersecurity Concepts Demonstrated

## Security Monitoring & Detection

This project demonstrates practical implementation of:

-   Event log parsing
    
-   Security telemetry normalization
    
-   Detection engineering
    
-   IOC identification
    
-   Behavioral analytics
    
-   Log correlation
    
-   Alert generation
    
-   Security reporting
    

----------

## Windows Security Event IDs

The analyzer works with real-world Windows Security Event IDs commonly used in:

-   SOC operations
    
-   Threat hunting
    
-   SIEM detection pipelines
    
-   DFIR investigations
    
-   Compliance auditing
    

### Example Event IDs

| Detection Rule | Description |
|------|------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Privileged Logon |
| 4688 | Process Creation |
| 4720 | User account creation |
| 4726 | User account deletion |
| 4740 | Account Lockout |
| 4771 | Kerberos authentication failure |
| 4776 | NTLM authentication failure |
| 7045 | Service installation |
| 1102 | Audit log cleared

----------

# 🔍 Detection Capabilities

## 🚨 Brute Force Detection

Detects repeated failed logons from the same:

-   Source IP
    
-   Workstation
    

### Detection Logic

```text
5+ failed 4625 logons from the same source
```

### Example Threats

-   Password spraying
    
-   Credential stuffing
    
-   Brute force attacks
    

### MITRE ATT&CK

| Technique | Name |
|-----|-----|
| T1110 | Brute Force

----------

## 🔓 Failed Logons Followed by Success

Correlates:

```text
4625 → 4625 → 4624
```

This can indicate:

-   Successful credential compromise
    
-   Password guessing
    
-   Unauthorized account access
    

### MITRE ATT&CK

| Technique | Name |
|-----|-----|
| T1110 | Brute Force|
| T1078 | Valid Accounts|

----------

## 👑 Privileged Logon Monitoring

Flags Event ID:

```text
4672 — Special privileges assigned to new logon
```

Useful for detecting:

-   Administrative access
    
-   Privilege escalation
    
-   Lateral movement
    
-   Unauthorized privileged sessions
    

### MITRE ATT&CK

| Technique | Name |
|-----|-----|
| T1078 | Valid Accounts |

----------

## 🔒 Account Lockout Detection

Detects:

```text
4740 — Account lockout
```

Useful for identifying:

-   Password attacks
    
-   User enumeration attempts
    
-   Misconfigured services
    
-   Automated authentication abuse
    

----------

## 👤 Suspicious Account Creation

Detects:

```text
4720 — New user account created
```

Potential Indicators:

-   Persistence establishment
    
-   Rogue administrator creation
    
-   Insider abuse
    
-   Unauthorized provisioning
    

### MITRE ATT&CK


| Technique | Name |
|-----|-----|
| T1136 | Create Account |

----------

## ⚠️ Risky Process Execution Detection

Monitors potentially dangerous process creation events:

- Process

- powershell.exe

- cmd.exe

- wscript.exe

- cscript.exe

- rundll32.exe

- regsvr32.exe

### Event ID

```text
4688 — Process Creation
```

### Why It Matters

These executables are commonly abused for:

-   Malware execution
    
-   LOLBIN abuse
    
-   Script execution
    
-   Persistence
    
-   Payload staging
    
-   Evasion
    

### MITRE ATT&CK


| Technique | Name |
|-----|-----|
| T1059 | Command and Scripting Interpreter |

----------

# 🏗️ Project Architecture

```text
windows-event-log-analyzer/
│
├── logs/
│   └── sample_security_events.csv
│
├── src/
│   ├── parser.py
│   ├── detector.py
│   ├── reporter.py
│   └── main.py
│
├── output/
│   └── analysis_report.txt
│
├── README.md
├── requirements.txt
└── .gitignore

```

----------

# ⚙️ Module Breakdown

## parser.py

### Responsibilities

-   Reads CSV Windows event logs
    
-   Normalizes fields
    
-   Parses timestamps
    
-   Converts values into structured event objects
    
-   Cleans malformed/empty data
    

### Key Security Concept

```text
Log Normalization
```

This mirrors SIEM ingestion pipelines used in:

-   Splunk
    
-   Microsoft Sentinel
    
-   QRadar
    
-   Elastic Stack
    
-   ArcSight
    

----------

## detector.py

### Responsibilities

-   Applies behavioral detection logic
    
-   Correlates authentication activity
    
-   Detects suspicious process execution
    
-   Maps detections to MITRE ATT&CK
    
-   Generates structured findings
    

### Key Security Concepts

-   Detection engineering
    
-   Event correlation
    
-   Threat detection
    
-   Security analytics
    
-   IOC identification
    

----------

## reporter.py

### Responsibilities

-   Formats findings
    
-   Generates readable reports
    
-   Displays:
    
    -   Severity
        
    -   Alert type
        
    -   Related Event IDs
        
    -   User context
        
    -   MITRE ATT&CK mappings
        
    -   Recommendations
        

### Key Security Concept

```text
SOC Alert Triage
```

----------

## main.py

### Responsibilities

Coordinates the entire analysis workflow:

```text
CSV → Parser → Detector → Reporter
```

----------

# 🖥️ Example Report Output

```text
==== Windows Event Log Analysis Report ====

Summary:
- Total parsed events: 150
- Suspicious findings: 49

Findings:
- 192.168.1.25
  Severity: High
  Alert: Failed Logons Followed by Successful Logon
  Related Event IDs: 4625, 4624
  Target User: jsmith
  MITRE ATT&CK: T1110 - Brute Force / T1078 - Valid Accounts

```

----------

# 🚀 How to Run

## 1. Clone the Repository

```bash
git clone https://github.com/yourusername/windows-event-log-analyzer.git
cd windows-event-log-analyzer
```

----------

## 2. Install Requirements

```bash
pip install -r requirements.txt
```

----------

## 3. Run the Analyzer

```bash
python src/main.py
```

----------

# 📄 Output

Generated reports are saved to:

```text
output/analysis_report.txt
```

----------

# 🧪 Example Security Use Cases

This project can be adapted for:

-   SOC analyst training
    
-   Windows log triage practice
    
-   Threat hunting labs
    
-   SIEM rule prototyping
    
-   Detection engineering demonstrations
    
-   DFIR simulations
    
-   Blue-team portfolio projects
    
-   Cybersecurity coursework
    
-   Resume/GitHub portfolio enhancement
    

----------

# 🎯 Security+ Domain Alignment

This project demonstrates concepts aligned with:

## CompTIA Security+ (SY0-701)

### Domain 4.0 — Security Operations

-   Log monitoring
    
-   Alerting
    
-   Incident response
    
-   Detection techniques
    
-   Threat intelligence mapping
    

### Domain 2.0 — Threats, Vulnerabilities, and Mitigations

-   Brute force attacks
    
-   Privilege escalation
    
-   Malware execution
    
-   Account manipulation
    

### Domain 5.0 — Security Program Management and Oversight

-   Security monitoring
    
-   Auditing
    
-   Event logging
    
-   Risk detection
    

----------

# 🧠 CySA+ Alignment

This project strongly aligns with:

## CompTIA CySA+

### Threat and Vulnerability Management

-   Authentication analysis
    
-   Threat detection
    
-   Event correlation
    
-   Suspicious process monitoring
    

### Security Operations and Monitoring

-   Log analysis
    
-   Detection logic
    
-   Alert generation
    
-   SIEM-style workflows
    

### Incident Response

-   IOC analysis
    
-   Event triage
    
-   Threat investigation
    
-   Detection recommendations
    

----------


# 📈 Skills Demonstrated

## Technical Skills

-   Python programming
    
-   Detection engineering
    
-   Windows event analysis
    
-   Log parsing
    
-   Security monitoring
    
-   Threat detection
    
-   Event correlation
    
-   Report generation
    
-   Behavioral analysis
    
-   Security automation
    

----------

## Cybersecurity Skills

-   SOC workflows
    
-   SIEM concepts
    
-   MITRE ATT&CK mapping
    
-   Incident triage
    
-   Authentication analysis
    
-   Privileged activity monitoring
    
-   Threat hunting fundamentals
    
-   Blue-team operations
    
-   IOC analysis

----------

# 🧑‍💻 Why This Project Matters

This project demonstrates practical cybersecurity engineering skills beyond simple scripting.

It showcases the ability to:

-   Build modular security tooling
    
-   Understand Windows security telemetry
    
-   Engineer detection logic
    
-   Correlate security events
    
-   Produce actionable findings
    
-   Apply threat frameworks
    
-   Think like a SOC analyst
    
-   Simulate real-world blue-team workflows

----------

## ⭐ If you found this project useful, consider starring the repository.
