import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st
from log_parser import parse_log_file
from detection_engine import run_detections, RULES


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

APP_NAME = "Windows DFIR SIEM"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
DB_PATH = DATA_DIR / "siem.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                system_name TEXT NOT NULL,
                analyst TEXT NOT NULL,
                scope TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                evidence_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                event_id INTEGER,
                timestamp TEXT,
                computer TEXT,
                account TEXT,
                log_source TEXT,
                process_name TEXT,
                process_id TEXT,
                command_line TEXT,
                parent_process TEXT,
                logon_type TEXT,
                source_ip TEXT,
                event_record_id TEXT,
                source_format TEXT NOT NULL,
                source_file TEXT NOT NULL,
                raw_event TEXT NOT NULL,
                validation_warnings TEXT NOT NULL DEFAULT '[]',
                imported_at TEXT NOT NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id),
                FOREIGN KEY (case_id) REFERENCES cases(id)
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_account ON events(account)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_process ON events(process_name)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_key TEXT NOT NULL UNIQUE,
                rule_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                first_seen TEXT,
                last_seen TEXT,
                event_ids TEXT NOT NULL DEFAULT '[]',
                evidence_summary TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_case ON alerts(case_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")


initialize_database()


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def calculate_sha256(file_path):
    """Hash a file in chunks to limit memory usage."""
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def get_cases():
    with get_connection() as conn:
        return conn.execute("""
            SELECT
                c.*,
                COUNT(e.id) AS evidence_count
            FROM cases AS c
            LEFT JOIN evidence AS e ON e.case_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        """).fetchall()


def get_evidence(case_id=None):
    query = """
        SELECT e.*, c.title AS case_title
        FROM evidence AS e
        JOIN cases AS c ON c.id = e.case_id
    """
    params = ()

    if case_id:
        query += " WHERE e.case_id = ?"
        params = (case_id,)

    query += " ORDER BY e.uploaded_at DESC"

    with get_connection() as conn:
        return conn.execute(query, params).fetchall()


def get_events(case_id=None):
    query = """
        SELECT events.*, evidence.original_name AS evidence_name
        FROM events
        JOIN evidence ON evidence.id = events.evidence_id
    """
    params = ()
    if case_id:
        query += " WHERE events.case_id = ?"
        params = (case_id,)
    query += " ORDER BY events.timestamp DESC, events.id DESC"
    with get_connection() as conn:
        return conn.execute(query, params).fetchall()


def get_alerts(case_id=None):
    query = "SELECT alerts.*, cases.title AS case_title FROM alerts JOIN cases ON cases.id = alerts.case_id"
    params = ()
    if case_id:
        query += " WHERE alerts.case_id = ?"
        params = (case_id,)
    query += " ORDER BY CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, last_seen DESC"
    with get_connection() as conn:
        return conn.execute(query, params).fetchall()


def update_alert_status(alert_id, status):
    if status not in {"Open", "Investigating", "Resolved"}:
        raise ValueError("Invalid alert status.")
    with get_connection() as conn:
        conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (status, utc_now(), alert_id),
        )


def ingest_evidence_file(evidence_row):
    """Parse a registered evidence file and persist normalized events."""
    path = (BASE_DIR / evidence_row["stored_path"]).resolve()
    # Only parse files stored inside this application's evidence directory.
    if EVIDENCE_DIR.resolve() not in path.parents:
        raise ValueError("Evidence path is outside the evidence directory.")
    if path.suffix.lower() not in {".csv", ".xml", ".evtx"}:
        raise ValueError("Only .csv, .xml and .evtx files can be ingested.")

    parsed_events = parse_log_file(path)
    inserted = 0
    duplicates = 0
    warnings = 0

    with get_connection() as conn:
        for event in parsed_events:
            raw_event = event.get("raw_event") or "{}"
            # Stable per-evidence key prevents importing the same evidence twice.
            identity = "|".join([
                evidence_row["id"],
                str(event.get("event_record_id")
                    or event.get("source_line") or ""),
                str(event.get("event_id") or ""),
                str(event.get("timestamp") or ""),
                raw_event,
            ])
            event_key = hashlib.sha256(identity.encode(
                "utf-8", errors="replace")).hexdigest()
            event_warnings = event.get("validation_warnings", [])
            warnings += bool(event_warnings)
            cursor = conn.execute("""
                INSERT OR IGNORE INTO events (
                    event_key, evidence_id, case_id, event_id, timestamp,
                    computer, account, log_source, process_name, process_id,
                    command_line, parent_process, logon_type, source_ip,
                    event_record_id, source_format, source_file, raw_event,
                    validation_warnings, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_key, evidence_row["id"], evidence_row["case_id"],
                event.get("event_id"), event.get("timestamp"),
                event.get("computer"), event.get("account"),
                event.get("log_source"), event.get("process_name"),
                event.get("process_id"), event.get("command_line"),
                event.get("parent_process"), event.get("logon_type"),
                event.get("source_ip"), event.get("event_record_id"),
                event.get("source_format", path.suffix.lower().lstrip(".")),
                evidence_row["original_name"], raw_event,
                json.dumps(event_warnings, ensure_ascii=False), utc_now(),
            ))
            if cursor.rowcount:
                inserted += 1
            else:
                duplicates += 1

    return len(parsed_events), inserted, duplicates, warnings


def explain_event(event):
    """Provide cautious, rule-based explanations for selected Windows events."""
    event_id = event["event_id"]
    if event_id == 1:
        return (
            "Sysmon Process Create: a process started. Review Image, CommandLine, "
            "ParentImage, User and ProcessGuid where available. This event alone "
            "does not prove malicious activity."
        )
    if event_id == 4624:
        return (
            "Windows successful logon: an account logged on successfully. Review "
            "TargetUserName, LogonType, IpAddress, WorkstationName and authentication "
            "details. Confirm whether the account, source and logon type are expected."
        )
    if event_id == 4625:
        return (
            "Windows failed logon: an authentication attempt failed. Review "
            "TargetUserName, LogonType, IpAddress, WorkstationName and Status/SubStatus. "
            "Repeated failures may warrant investigation, but one failure is not proof of attack."
        )
    return "No Phase 2 explanation rule is available for this Event ID yet. Inspect the raw event."


def save_uploaded_evidence(case_id, uploaded_file):
    """Save a file without overwriting existing evidence."""
    evidence_id = str(uuid.uuid4())
    case_folder = EVIDENCE_DIR / case_id
    case_folder.mkdir(parents=True, exist_ok=True)

    # Never use the uploaded filename as a filesystem path.
    safe_name = Path(uploaded_file.name).name
    destination = case_folder / f"{evidence_id}_{safe_name}"

    digest = hashlib.sha256()
    size = 0

    try:
        with open(destination, "xb") as output:
            while True:
                chunk = uploaded_file.read(1024 * 1024)
                if not chunk:
                    break

                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)

        sha256 = digest.hexdigest()

        with get_connection() as conn:
            conn.execute("""
                INSERT INTO evidence (
                    id, case_id, original_name, stored_path,
                    file_size, sha256, uploaded_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence_id,
                case_id,
                safe_name,
                str(destination.relative_to(BASE_DIR)),
                size,
                sha256,
                utc_now(),
            ))

        return True, sha256

    except Exception:
        # Remove a partially saved file if registration fails.
        destination.unlink(missing_ok=True)
        raise

# --------------------------------------------------
# ANALYSIS SESSION MANAGEMENT
# --------------------------------------------------


def clear_analysis_view():
    """Clear displayed analysis results without deleting stored records."""
    st.session_state["analysis_results_visible"] = False
    st.session_state["analysis_evidence_ids"] = []
    st.session_state["analysis_context"] = None
    st.session_state["analysis_evidence_selection"] = []
    st.session_state.pop("analysis_selected_event", None)


def reset_analysis_on_case_change():
    """Clear previous results when another case is selected."""
    clear_analysis_view()

# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------


st.sidebar.title("🛡️ Windows DFIR SIEM")
st.sidebar.caption("Local investigation workspace")
page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Create Case",
        "Evidence Inventory",
        "Event Analysis",
        "Detections & Alerts",
        "About",
    ],
)
# Clear analysis results when entering or leaving Event Analysis.
if "_last_page" not in st.session_state:
    st.session_state["_last_page"] = page

elif st.session_state["_last_page"] != page:
    if (
        st.session_state["_last_page"] == "Event Analysis"
        or page == "Event Analysis"
    ):
        clear_analysis_view()

    st.session_state["_last_page"] = page

st.sidebar.divider()
st.sidebar.caption("Phase 3 — Detection & alerting")
st.sidebar.caption("Local database: data/siem.db")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

if page == "Dashboard":
    st.title("Investigation Dashboard")
    st.write(
        "Manage Windows log investigations and preserve "
        "the evidence associated with each case."
    )

    cases = get_cases()
    evidence = get_evidence()
    alerts = get_alerts()

    open_cases = sum(1 for c in cases if c["status"] == "Open")
    open_alerts = sum(1 for a in alerts if a["status"] == "Open")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Cases", len(cases))
    col2.metric("Open Cases", open_cases)
    col3.metric("Evidence Files", len(evidence))
    col4.metric("Open Alerts", open_alerts)

    st.subheader("Recent Cases")

    if cases:
        rows = [
            {
                "Case ID": c["id"][:8],
                "Title": c["title"],
                "System": c["system_name"],
                "Status": c["status"],
                "Evidence": c["evidence_count"],
                "Created (UTC)": c["created_at"],
            }
            for c in cases
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info(
            "No cases exist yet. Open Create Case to start "
            "your first investigation."
        )

    st.subheader("Current Capabilities")
    st.markdown("""
    - Local case registration
    - Evidence file storage and SHA-256 hashing
    - Evidence inventory
    - Persistent SQLite database
    - CSV, XML and EVTX event ingestion
    - Normalized searchable event records
    - Initial explanations for Sysmon Event ID 1 and Security 4624/4625
    - Explainable detection rules and SQLite-backed alerts
    """)

    st.info(
        "Run detections from the Detections & Alerts page after ingesting events. "
        "Alerts are investigation leads, not proof of compromise."
    )


# --------------------------------------------------
# CREATE CASE
# --------------------------------------------------

elif page == "Create Case":
    st.title("Create Investigation Case")

    with st.form("create_case_form"):
        title = st.text_input(
            "Case title",
            placeholder="Example: Suspicious Windows authentication",
        )
        system_name = st.text_input(
            "System or hostname",
            placeholder="Example: WIN11-LAB",
        )
        analyst = st.text_input(
            "Analyst",
            placeholder="Your analyst identifier",
        )
        scope = st.text_area(
            "Investigation scope",
            placeholder=(
                "Describe the system, time period, log sources "
                "and questions to investigate."
            ),
        )

        submitted = st.form_submit_button(
            "Create Case",
            type="primary",
        )

    if submitted:
        if not all(
            value.strip()
            for value in [title, system_name, analyst, scope]
        ):
            st.error("Please complete all four fields.")
        else:
            case_id = str(uuid.uuid4())

            with get_connection() as conn:
                conn.execute("""
                    INSERT INTO cases (
                        id, title, system_name, analyst,
                        scope, status, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, 'Open', ?)
                """, (
                    case_id,
                    title.strip(),
                    system_name.strip(),
                    analyst.strip(),
                    scope.strip(),
                    utc_now(),
                ))

            st.success(f"Case created successfully: {case_id}")
            st.info(
                "Save the case ID for your records. "
                "Your case is stored in the local database."
            )


# --------------------------------------------------
# EVIDENCE INVENTORY
# --------------------------------------------------

elif page == "Evidence Inventory":
    st.title("Evidence Inventory")
    st.write(
        "Upload evidence files into an existing case. "
        "Each file is stored locally and assigned a SHA-256 hash."
    )

    cases = get_cases()

    if not cases:
        st.info("Create an investigation case before uploading evidence.")
    else:
        case_options = {
            f'{c["title"]} — {c["id"][:8]}': c["id"]
            for c in cases
        }

        selected_label = st.selectbox(
            "Select investigation case",
            list(case_options.keys()),
        )
        selected_case_id = case_options[selected_label]

        with st.form("upload_evidence_form"):
            uploaded_files = st.file_uploader(
                "Select log or evidence files",
                accept_multiple_files=True,
                type=["evtx", "xml", "csv", "txt", "json", "log"],
                help=(
                    "Upload evidence for preservation. Event Analysis can parse "
                    "CSV, XML and EVTX files; TXT/LOG/JSON remain stored evidence only."
                ),
            )

            upload_submitted = st.form_submit_button(
                "Store Evidence",
                type="primary",
            )

        if upload_submitted:
            if not uploaded_files:
                st.warning("Choose at least one file.")
            else:
                saved_count = 0

                for uploaded_file in uploaded_files:
                    try:
                        success, digest = save_uploaded_evidence(
                            selected_case_id,
                            uploaded_file,
                        )

                        if success:
                            saved_count += 1
                            st.success(
                                f"Stored {uploaded_file.name} "
                                f"— SHA-256: {digest}"
                            )

                    except Exception as exc:
                        st.error(
                            f"Could not store {uploaded_file.name}: {exc}"
                        )

                if saved_count:
                    clear_analysis_view()

                    st.success(
                        f"Successfully stored {saved_count} evidence file(s)."
                    )

                    st.info(
                        "New evidence stored successfully. "
                        "Your historical records remain preserved in the database."
                    )
    st.subheader("Registered Evidence")
    evidence_rows = get_evidence()

    if evidence_rows:
        search = st.text_input("Filter by filename or case")

        filtered = [
            {
                "Case": row["case_title"],
                "Filename": row["original_name"],
                "Size (bytes)": row["file_size"],
                "SHA-256": row["sha256"],
                "Uploaded (UTC)": row["uploaded_at"],
            }
            for row in evidence_rows
            if search.lower() in (
                row["original_name"] + " " + row["case_title"]
            ).lower()
        ]

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No evidence files have been registered.")


# --------------------------------------------------
# EVENT ANALYSIS
# --------------------------------------------------

elif page == "Event Analysis":
    st.title("Event Analysis Workspace")

    st.write(
        "Analyse registered Windows event evidence. "
        "Only results from the currently selected evidence "
        "will be displayed."
    )

    cases = get_cases()

    if not cases:
        st.info("Create an investigation case before analysing evidence.")

    else:
        # Select investigation case first.
        case_options = {
            f'{c["title"]} — {c["id"][:8]}': c["id"]
            for c in cases
        }

        selected_case_label = st.selectbox(
            "Select investigation case",
            list(case_options.keys()),
            key="analysis_case_selector",
            on_change=reset_analysis_on_case_change,
        )

        selected_case_id = case_options[selected_case_label]

        # Retrieve only supported evidence belonging to this case.
        evidence_rows = get_evidence(selected_case_id)

        supported_rows = [
            row for row in evidence_rows
            if Path(row["original_name"]).suffix.lower()
            in {".csv", ".xml", ".evtx"}
        ]

        st.divider()
        st.subheader("Select evidence for analysis")

        if not supported_rows:
            clear_analysis_view()

            st.info(
                "This case has no supported evidence files yet. "
                "Upload a CSV, XML or EVTX file through Evidence Inventory."
            )

        else:
            evidence_options = {
                f'{row["original_name"]} — {row["id"][:8]}': row
                for row in supported_rows
            }

            selected_labels = st.multiselect(
                "Choose evidence files",
                list(evidence_options.keys()),
                key="analysis_evidence_selection",
                help="Only evidence selected here will be included in this analysis."
            )

            # Detect a change in the selected case or evidence.
            current_context = (
                selected_case_id,
                tuple(sorted(
                    evidence_options[label]["id"]
                    for label in selected_labels
                ))
            )

            if st.session_state.get("analysis_context") != current_context:
                st.session_state["analysis_context"] = current_context
                st.session_state["analysis_results_visible"] = False
                st.session_state["analysis_evidence_ids"] = []

            # Parse selected evidence.
            if st.button(
                "Analyse Selected Evidence",
                type="primary",
                disabled=not selected_labels,
            ):
                total_parsed = 0
                total_inserted = 0
                total_duplicates = 0
                total_warnings = 0

                successful_evidence_ids = []

                with st.spinner("Parsing and analysing evidence..."):

                    for label in selected_labels:
                        evidence_row = evidence_options[label]

                        try:
                            parsed, inserted, duplicates, warnings = (
                                ingest_evidence_file(evidence_row)
                            )

                            total_parsed += parsed
                            total_inserted += inserted
                            total_duplicates += duplicates
                            total_warnings += warnings

                            successful_evidence_ids.append(
                                evidence_row["id"]
                            )

                            st.success(
                                f'{evidence_row["original_name"]}: '
                                f'{parsed} parsed, '
                                f'{inserted} new events, '
                                f'{duplicates} duplicates skipped, '
                                f'{warnings} events with warnings.'
                            )

                        except Exception as exc:
                            st.error(
                                f'{evidence_row["original_name"]}: '
                                f'Analysis failed: {exc}'
                            )

                # Show only results from successfully processed evidence.
                st.session_state["analysis_evidence_ids"] = (
                    successful_evidence_ids
                )

                st.session_state["analysis_results_visible"] = (
                    bool(successful_evidence_ids)
                )

                st.info(
                    f"Analysis summary — "
                    f"Parsed: {total_parsed} | "
                    f"New events: {total_inserted} | "
                    f"Duplicates: {total_duplicates} | "
                    f"Warnings: {total_warnings}"
                )

            st.divider()

            # Results remain hidden until evidence is explicitly analysed.
            if not st.session_state.get("analysis_results_visible", False):

                st.info(
                    "No analysis results are currently displayed. "
                    "Select your evidence and click "
                    "'Analyse Selected Evidence' to begin."
                )

            else:
                st.subheader("Analysis Results")

                selected_evidence_ids = set(
                    st.session_state["analysis_evidence_ids"]
                )

                # Retrieve events belonging ONLY to the current evidence.
                all_events = get_events(selected_case_id)

                all_events = [
                    event for event in all_events
                    if event["evidence_id"] in selected_evidence_ids
                ]

                if not all_events:
                    st.warning(
                        "No events were extracted from the selected evidence."
                    )

                else:
                    st.caption(
                        f"Showing events from "
                        f"{len(selected_evidence_ids)} selected evidence file(s)."
                    )

                    # Event filters.
                    filter_col1, filter_col2, filter_col3 = st.columns(3)

                    event_id_filter = filter_col1.text_input(
                        "Event ID (e.g. 4624, 4625, 1)"
                    )

                    account_filter = filter_col2.text_input(
                        "Account contains"
                    )

                    process_filter = filter_col3.text_input(
                        "Process contains"
                    )

                    filter_col4, filter_col5 = st.columns(2)

                    source_filter = filter_col4.text_input(
                        "Log source contains"
                    )

                    computer_filter = filter_col5.text_input(
                        "Computer contains"
                    )

                    timestamp_filter = st.text_input(
                        "Timestamp contains (UTC date/time)"
                    )

                    filtered_events = []

                    for event in all_events:

                        if event_id_filter.strip():
                            try:
                                if event["event_id"] != int(
                                    event_id_filter.strip()
                                ):
                                    continue

                            except ValueError:
                                st.error(
                                    "Event ID filter must be an integer."
                                )
                                filtered_events = []
                                break

                        if account_filter.lower() not in (
                            event["account"] or ""
                        ).lower():
                            continue

                        if process_filter.lower() not in (
                            event["process_name"] or ""
                        ).lower():
                            continue

                        if source_filter.lower() not in (
                            event["log_source"] or ""
                        ).lower():
                            continue

                        if computer_filter.lower() not in (
                            event["computer"] or ""
                        ).lower():
                            continue

                        if timestamp_filter.lower() not in (
                            event["timestamp"] or ""
                        ).lower():
                            continue

                        filtered_events.append(event)

                    st.caption(
                        f"Showing {len(filtered_events)} of "
                        f"{len(all_events)} events"
                    )

                    display_rows = []

                    for event in filtered_events:
                        display_rows.append({
                            "Event ID": event["event_id"],
                            "Timestamp (UTC)": event["timestamp"],
                            "Computer": event["computer"],
                            "Account": event["account"],
                            "Log source": event["log_source"],
                            "Process": event["process_name"],
                            "Logon type": event["logon_type"],
                            "Source IP": event["source_ip"],
                            "File": event["evidence_name"],
                            "Warnings": event["validation_warnings"],
                        })

                    st.dataframe(
                        display_rows,
                        use_container_width=True,
                        hide_index=True,
                    )

                    if filtered_events:

                        selected_event_index = st.selectbox(
                            "Inspect event details",
                            range(len(filtered_events)),
                            format_func=lambda i: (
                                f'ID {filtered_events[i]["event_id"]} | '
                                f'{filtered_events[i]["timestamp"] or "No timestamp"} | '
                                f'{filtered_events[i]["account"] or "Unknown account"} | '
                                f'{filtered_events[i]["evidence_name"]}'
                            ),
                            key="analysis_selected_event",
                        )

                        selected_event = filtered_events[
                            selected_event_index
                        ]

                        st.markdown("#### Event explanation")

                        st.write(explain_event(selected_event))

                        if selected_event["validation_warnings"] != "[]":
                            st.warning(
                                "Validation warnings: "
                                + selected_event["validation_warnings"]
                            )

                        st.markdown("#### Original event data")

                        st.code(
                            selected_event["raw_event"],
                            language=(
                                "json"
                                if selected_event["source_format"] == "csv"
                                else "xml"
                            ),
                        )

                    st.caption(
                        "Explanations are preliminary triage guidance, "
                        "not a malicious/benign verdict. Always validate "
                        "findings against the original event data."
                    )

# --------------------------------------------------
# DETECTIONS & ALERTS
# --------------------------------------------------

elif page == "Detections & Alerts":
    st.title("Detections & Alerts")
    st.write(
        "Run transparent, local rules against normalized events. Review the supporting "
        "events before deciding whether activity is malicious."
    )

    st.subheader("Enabled detection rules")
    st.dataframe([
        {"Rule ID": r["rule_id"], "Rule": r["name"],
            "Severity": r["severity"], "Purpose": r["description"]}
        for r in RULES
    ], use_container_width=True, hide_index=True)

    cases = get_cases()
    if not cases:
        st.info("Create a case and ingest event evidence before running detections.")
    else:
        case_options = {f'{c["title"]} — {c["id"][:8]}': c["id"]
                        for c in cases}
        selected_case_label = st.selectbox("Investigation case", list(
            case_options.keys()), key="detection_case")
        selected_case_id = case_options[selected_case_label]
        case_events = get_events(selected_case_id)
        st.caption(f"Events available for detection: {len(case_events)}")
        if st.button("Run detection rules", type="primary", disabled=not case_events):
            with st.spinner("Evaluating events against detection rules..."):
                created, existing = run_detections(
                    selected_case_id, case_events, get_connection, utc_now)
            st.success(
                f"Detection run complete. New alerts: {created}; existing alerts unchanged: {existing}.")

    st.divider()
    st.subheader("Alert queue")

    all_alerts = get_alerts()
    cases = get_cases()

    if not cases:
        st.info("No investigation cases are available.")

    else:
        case_options = {
            f'{c["title"]} — {c["id"][:8]}': c["id"]
            for c in cases
        }

        selected_alert_case = st.selectbox(
            "Select case to view alerts",
            ["Select a case"] + list(case_options.keys()),
            key="alert_queue_case",
        )

        if selected_alert_case == "Select a case":
            st.info(
                "Select an investigation case to view its alerts. "
                "Alerts from other cases are hidden until you select them."
            )

        else:
            active_case_id = case_options[selected_alert_case]

            case_alerts = [
                a for a in all_alerts
                if a["case_id"] == active_case_id
            ]

            if not case_alerts:
                st.info(
                    "No alerts have been generated for this case yet. "
                    "Ingest evidence and run detection rules to generate alerts."
                )

            else:
                col1, col2 = st.columns(2)

                severity_filter = col1.selectbox(
                    "Severity",
                    ["All", "Critical", "High", "Medium", "Low", "Informational"],
                    key="alert_severity",
                )

                status_filter = col2.selectbox(
                    "Status",
                    ["All", "Open", "Investigating", "Resolved"],
                    key="alert_status",
                )

                visible = [
                    a for a in case_alerts
                    if (
                        severity_filter == "All"
                        or a["severity"] == severity_filter
                    )
                    and (
                        status_filter == "All"
                        or a["status"] == status_filter
                    )
                ]

                st.dataframe(
                    [{
                        "ID": a["id"],
                        "Severity": a["severity"],
                        "Status": a["status"],
                        "Rule": a["rule_id"],
                        "Alert": a["title"],
                        "Case": a["case_title"],
                        "First seen (UTC)": a["first_seen"],
                        "Last seen (UTC)": a["last_seen"],
                    } for a in visible],
                    use_container_width=True,
                    hide_index=True,
                )

                if visible:
                    selected_alert_id = st.selectbox(
                        "Inspect alert",
                        [a["id"] for a in visible],
                        format_func=lambda alert_id: next(
                            f'#{a["id"]} [{a["severity"]}] {a["title"]}'
                            for a in visible
                            if a["id"] == alert_id
                        ),
                        key="selected_alert_id",
                    )

                    selected_alert = next(
                        a for a in visible
                        if a["id"] == selected_alert_id
                    )

                    st.markdown("#### Alert explanation")
                    st.write(selected_alert["description"])

                    st.write(
                        "**Supporting event IDs:** "
                        + selected_alert["event_ids"]
                    )

                    st.write("**Evidence summary:**")
                    st.json(
                        json.loads(
                            selected_alert["evidence_summary"] or "{}"
                        )
                    )

                    new_status = st.selectbox(
                        "Update status",
                        ["Open", "Investigating", "Resolved"],
                        index=[
                            "Open",
                            "Investigating",
                            "Resolved",
                        ].index(selected_alert["status"]),
                        key=f'alert_status_{selected_alert_id}',
                    )

                    if st.button("Save alert status"):
                        update_alert_status(
                            selected_alert_id,
                            new_status,
                        )

                        st.success("Alert status updated.")
                        st.rerun()

    st.caption("Rules are heuristic and intentionally conservative. Validate every alert against raw event details and the investigation context.")


# --------------------------------------------------
# ABOUT
# --------------------------------------------------

elif page == "About":
    st.title("About This Project")

    st.write(
        "Windows DFIR SIEM is a local-first digital forensics "
        "and incident response investigation tool with event ingestion "
        "and explainable detection rules."
    )

    st.subheader("Design principles")
    st.markdown("""
    - Offline operation after dependencies are installed
    - Evidence stored locally
    - SHA-256 hashes for evidence integrity checking
    - Transparent, explainable detection rules
    - Case-based investigation and reporting
    """)

    st.subheader("Storage locations")
    st.code(
        f"Database: {DB_PATH}\n"
        f"Evidence: {EVIDENCE_DIR}",
        language="text",
    )

    st.caption(
        "This is a development prototype, not a certified "
        "forensic acquisition or evidence-preservation system."
    )
