"""Explainable local authentication and process detections for Windows DFIR SIEM.

These detections create triage alerts. They do not prove malicious activity.
"""
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

RULES = [
    {
        "rule_id": "AUTH-001",
        "name": "Repeated failed logons",
        "severity": "Medium",
        "description": "Five or more Windows Security Event ID 4625 records for the same account and computer within a rolling ten-minute window. This may indicate password guessing, user error, or a misconfigured service.",
    },
    {
        "rule_id": "AUTH-002",
        "name": "Sustained password guessing",
        "severity": "High",
        "description": "Ten or more Windows Security Event ID 4625 records for the same account and computer within five minutes. This is consistent with rapid password guessing, but logs alone may not prove the exact technique.",
    },
    {
        "rule_id": "AUTH-003",
        "name": "Failed logons followed by successful logon",
        "severity": "High",
        "description": "A successful Windows Security Event ID 4624 follows at least five failed Event ID 4625 logons for the same account and computer within ten minutes. Correlation is stronger when source IPs also match.",
    },
    {
        "rule_id": "AUTH-004",
        "name": "Possible password spraying",
        "severity": "High",
        "description": "A single source IP has failed logons for five or more distinct accounts on the same computer within ten minutes. This pattern may indicate password spraying; validate against expected authentication activity.",
    },
    {
        "rule_id": "REMOTE-001",
        "name": "Successful Windows remote-interactive logon",
        "severity": "Informational",
        "description": "Windows Security Event ID 4624 with Logon Type 10 (RemoteInteractive, commonly Remote Desktop). A remote logon is not inherently malicious; investigate if the source, account, or timing is unexpected.",
    },
    {
        "rule_id": "SYSMON-1-SUSPICIOUS-CLI",
        "name": "Suspicious process command line",
        "severity": "High",
        "description": "A Sysmon Event ID 1 process-creation record contains a command-line pattern commonly associated with script execution, remote content retrieval, or proxy execution. These strings can also appear in legitimate administration.",
    },
]

SUSPICIOUS_PATTERNS = [
    ("powershell_encoded_command", ("-encodedcommand", " -enc ")),
    ("powershell_download_cradle", ("downloadstring(", "downloadfile(", "invoke-webrequest", " iwr ")),
    ("certutil_remote_download", ("certutil -urlcache", "certutil.exe -urlcache")),
    ("bitsadmin_transfer", ("bitsadmin /transfer", "bitsadmin.exe /transfer")),
    ("mshta_remote_script", ("mshta http://", "mshta https://", "mshta.exe http://", "mshta.exe https://")),
    ("rundll32_javascript", ("rundll32 javascript:", "rundll32.exe javascript:")),
]


def _as_dt(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _as_dict(row):
    return dict(row) if not isinstance(row, dict) else row


def _persist_alert(conn, *, alert_key, rule_id, case_id, severity, title,
                   description, first_seen, last_seen, event_ids, summary, now):
    cursor = conn.execute("""
        INSERT OR IGNORE INTO alerts (
            alert_key, rule_id, case_id, severity, title, description,
            status, first_seen, last_seen, event_ids, evidence_summary,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)
    """, (alert_key, rule_id, case_id, severity, title, description,
          first_seen, last_seen, json.dumps(event_ids), json.dumps(summary), now, now))
    return bool(cursor.rowcount)


def run_detections(case_id, event_rows, connection_factory, utc_now):
    """Evaluate normalized events and persist deduplicated alerts.

    Returns (created_count, already_existing_count).
    """
    events = [_as_dict(row) for row in event_rows]
    created = existing = 0
    candidates = []
    by_account_computer = defaultdict(list)
    by_source_computer = defaultdict(list)

    for event in events:
        if event.get("event_id") not in (4624, 4625):
            continue
        ts = _as_dt(event.get("timestamp"))
        account = (event.get("account") or "").strip()
        computer = (event.get("computer") or "Unknown computer").strip()
        if not ts or not account:
            continue
        item = (ts, event)
        by_account_computer[(computer.casefold(), account.casefold())].append(item)
        source_ip = (event.get("source_ip") or "").strip()
        if source_ip and source_ip not in {"-", "::1", "127.0.0.1"}:
            by_source_computer[(computer.casefold(), source_ip)].append(item)

    def add_candidate(rule_id, case_id, severity, title, description, matched, summary, identity_extra=""):
        ids = sorted({int(ev["id"]) for ev in matched if ev.get("id") is not None})
        if not ids:
            return
        first = min((_as_dt(ev.get("timestamp")) for ev in matched if _as_dt(ev.get("timestamp"))), default=None)
        last = max((_as_dt(ev.get("timestamp")) for ev in matched if _as_dt(ev.get("timestamp"))), default=None)
        identity = f"{rule_id}|{case_id}|{identity_extra}|" + ",".join(map(str, ids))
        key = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()
        candidates.append({
            "alert_key": key, "rule_id": rule_id, "case_id": case_id,
            "severity": severity, "title": title, "description": description,
            "first_seen": first.isoformat() if first else None,
            "last_seen": last.isoformat() if last else None,
            "event_ids": ids, "summary": summary,
        })

    # AUTH-001 / AUTH-002 / AUTH-003: account + computer correlation.
    for (computer_key, account_key), rows in by_account_computer.items():
        rows.sort(key=lambda pair: pair[0])
        failures = [(ts, ev) for ts, ev in rows if ev.get("event_id") == 4625]
        successes = [(ts, ev) for ts, ev in rows if ev.get("event_id") == 4624]

        # Sliding windows are based on the ending failed event. Emit only one
        # AUTH-001 burst alert per account/computer during this detection run.
        auth001_created = False
        auth002_created = False
        for end_index, (end_ts, end_event) in enumerate(failures):
            window5 = [(ts, ev) for ts, ev in failures if end_ts - timedelta(minutes=5) <= ts <= end_ts]
            window10 = [(ts, ev) for ts, ev in failures if end_ts - timedelta(minutes=10) <= ts <= end_ts]
            account = end_event.get("account") or "Unknown account"
            computer = end_event.get("computer") or "Unknown computer"
            ips = sorted({ev.get("source_ip") for _, ev in window10 if ev.get("source_ip")})

            if len(window10) >= 5 and not auth001_created:
                add_candidate(
                    "AUTH-001", case_id, "Medium", f"Repeated failed logons: {account}",
                    RULES[0]["description"], [ev for _, ev in window10],
                    {"computer": computer, "account": account, "attempt_count": len(window10), "source_ips": ips},
                    f"{computer_key}|{account_key}|burst10",
                )
                auth001_created = True
            if len(window5) >= 10 and not auth002_created:
                add_candidate(
                    "AUTH-002", case_id, "High", f"Sustained password guessing: {account}",
                    RULES[1]["description"], [ev for _, ev in window5],
                    {"computer": computer, "account": account, "attempt_count": len(window5), "source_ips": sorted({ev.get("source_ip") for _, ev in window5 if ev.get("source_ip")})},
                    f"{computer_key}|{account_key}|burst5",
                )
                auth002_created = True
            if auth001_created and auth002_created:
                break

        # AUTH-003: success after five or more failures in the prior 10 minutes.
        for success_ts, success_event in successes:
            prior = [(ts, ev) for ts, ev in failures if success_ts - timedelta(minutes=10) <= ts < success_ts]
            if len(prior) < 5:
                continue
            success_ip = (success_event.get("source_ip") or "").strip()
            failure_ips = { (ev.get("source_ip") or "").strip() for _, ev in prior if ev.get("source_ip") }
            # If both sides have IPs, require a match; if either side lacks IP, retain account/computer correlation.
            if success_ip and failure_ips and success_ip not in failure_ips:
                continue
            matched = [ev for _, ev in prior] + [success_event]
            add_candidate(
                "AUTH-003", case_id, "High",
                f"Successful logon after repeated failures: {success_event.get('account') or 'Unknown account'}",
                RULES[2]["description"], matched,
                {"computer": success_event.get("computer"), "account": success_event.get("account"),
                 "failed_attempts": len(prior), "success_source_ip": success_event.get("source_ip"),
                 "failure_source_ips": sorted(failure_ips)},
                f"{computer_key}|{account_key}|success-after-failures|{success_event.get('id')}",
            )

        # REMOTE-001: successful RemoteInteractive (RDP) logon. Informational by itself.
        for ts, event in successes:
            if str(event.get("logon_type") or "").strip() != "10" or event.get("id") is None:
                continue
            add_candidate(
                "REMOTE-001", case_id, "Informational",
                f"Successful remote-interactive logon: {event.get('account') or 'Unknown account'}",
                RULES[4]["description"], [event],
                {"computer": event.get("computer"), "account": event.get("account"),
                 "source_ip": event.get("source_ip"), "logon_type": event.get("logon_type")},
                f"{computer_key}|{account_key}|rdp|{event.get('id')}",
            )

    # AUTH-004: possible password spraying (one source IP, many accounts, same computer).
    for (computer_key, source_ip), rows in by_source_computer.items():
        failures = [(ts, ev) for ts, ev in rows if ev.get("event_id") == 4625]
        failures.sort(key=lambda pair: pair[0])
        for end_ts, end_event in failures:
            window = [(ts, ev) for ts, ev in failures if end_ts - timedelta(minutes=10) <= ts <= end_ts]
            accounts = {str(ev.get("account") or "").casefold() for _, ev in window if ev.get("account")}
            if len(accounts) < 5:
                continue
            computer = end_event.get("computer") or "Unknown computer"
            matched = [ev for _, ev in window]
            add_candidate(
                "AUTH-004", case_id, "High", f"Possible password spraying from {source_ip}",
                RULES[3]["description"], matched,
                {"computer": computer, "source_ip": source_ip, "distinct_accounts": sorted(accounts),
                 "failed_attempt_count": len(window)},
                f"{computer_key}|{source_ip}|spray",
            )
            break

    # SYSMON process command-line detections.
    for event in events:
        if event.get("event_id") != 1:
            continue
        command = (event.get("command_line") or "").lower()
        process = (event.get("process_name") or "").lower()
        combined = (process + " " + command).strip()
        if not command or event.get("id") is None:
            continue
        matches = [name for name, patterns in SUSPICIOUS_PATTERNS if any(p in combined for p in patterns)]
        if not matches:
            continue
        event_id = int(event["id"])
        add_candidate(
            "SYSMON-1-SUSPICIOUS-CLI", case_id, "High",
            "Suspicious process command line", RULES[5]["description"], [event],
            {"computer": event.get("computer"), "account": event.get("account"),
             "process_name": event.get("process_name"), "process_id": event.get("process_id"),
             "parent_process": event.get("parent_process"), "command_line": event.get("command_line"),
             "matched_patterns": matches, "source_file": event.get("evidence_name") or event.get("source_file")},
            f"{event_id}|{','.join(matches)}",
        )

    with connection_factory() as conn:
        for candidate in candidates:
            was_created = _persist_alert(
                conn, alert_key=candidate["alert_key"], rule_id=candidate["rule_id"],
                case_id=candidate["case_id"], severity=candidate["severity"],
                title=candidate["title"], description=candidate["description"],
                first_seen=candidate["first_seen"], last_seen=candidate["last_seen"],
                event_ids=candidate["event_ids"], summary=candidate["summary"], now=utc_now(),
            )
            if was_created:
                created += 1
            else:
                existing += 1
    return created, existing
