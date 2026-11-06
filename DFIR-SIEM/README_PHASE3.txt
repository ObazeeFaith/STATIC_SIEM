WINDOWS DFIR SIEM — PHASE 3

Files:
- app.py: Phase 2 app extended with Detections & Alerts page and SQLite alerts table.
- log_parser.py: Phase 2 parser retained.
- detection_engine.py: explainable local rules.
- requirements_phase3.txt: dependencies.

Install/update:
1. Back up your existing app.py and data folder.
2. Extract these files into the project folder, replacing app.py and log_parser.py only. Keep data/siem.db and data/evidence intact.
3. Activate the dfir-siem Conda environment.
4. Run: python -m pip install -r requirements_phase3.txt
5. Run: python -m streamlit run app.py
6. Ingest events in Event Analysis, then open Detections & Alerts and run the rules for a case.

Rules:
- AUTH-4625-BURST: five or more failed logons for the same account/computer in a 10-minute window.
- SYSMON-1-SUSPICIOUS-CLI: Sysmon Event ID 1 command line contains selected suspicious command patterns.

Alerts are triage leads, not proof of malicious activity. Rules are intentionally simple and should be validated against raw evidence.
