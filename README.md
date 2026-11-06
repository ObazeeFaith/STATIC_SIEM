# Windows DFIR-SIEM

A lightweight, offline Digital Forensics and Incident Response (DFIR) and Security Information and Event Management (SIEM) tool developed with Python and Streamlit.

The project is designed to help security analysts collect, analyse, and investigate Windows security events. It supports log ingestion, event normalisation, evidence management, and rule-based detection of suspicious activities.

### Key Features
- **Evidence Management:** Upload and manage digital evidence files.
- **Log Analysis:** Process Windows Security Event Logs and Sysmon records.
- **Authentication Monitoring:** Detect repeated failed logins, possible brute-force attacks, password guessing, and password spraying.
- **Suspicious Process Detection:** Identify potentially suspicious process execution and command-line activity.
- **Remote Login Monitoring:** Flag successful Windows RemoteInteractive logons.
- **Alert Management:** Generate and review detection alerts.
- **Evidence Integrity:** Calculate SHA-256 hashes to support evidence integrity verification.
- **Case Management:** Organise evidence and investigations into cases.

### Technology Stack
- Python
- Streamlit
- SQLite
- Sysmon
- Windows Event Logs

### Project Goal
The goal of this project is to develop an edycational, resource-efficient security monitoring and investigation tool that demonstrates core DFIR and SIEM concepts using locally collected Windows telemetry.

**Note:** This is an educational project under active development. Detection results are rule-based indicators that require analyst validation; they should not be treated as automatic proof of malicious activity.
