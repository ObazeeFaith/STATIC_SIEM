import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from defusedxml import ElementTree as SafeET
from Evtx.Evtx import Evtx

SUPPORTED_FORMATS = {'.csv', '.xml', '.evtx'}


def parse_timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None


def find_value(data, *names):
    lowered = {str(k).lower(): v for k, v in data.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def local_name(tag):
    return tag.rsplit('}', 1)[-1]


def extract_event_data(root):
    result = {}
    system = next((e for e in root.iter() if local_name(e.tag) == 'System'), None)
    if system is not None:
        for element in system.iter():
            tag = local_name(element.tag)
            if tag == 'Provider':
                result['Provider'] = element.attrib.get('Name')
            elif tag == 'EventID':
                result['EventID'] = element.text
            elif tag == 'EventRecordID':
                result['EventRecordID'] = element.text
            elif tag == 'Computer':
                result['Computer'] = element.text
            elif tag == 'Channel':
                result['Channel'] = element.text
            elif tag == 'TimeCreated':
                result['TimeCreated'] = element.attrib.get('SystemTime')
            elif tag == 'Execution':
                result['ProcessID'] = element.attrib.get('ProcessID')
                result['ThreadID'] = element.attrib.get('ThreadID')
            elif tag == 'Security':
                result['UserID'] = element.attrib.get('UserID')

    for section in root.iter():
        if local_name(section.tag) not in {'EventData', 'UserData'}:
            continue
        for element in section.iter():
            if element is section:
                continue
            name = element.attrib.get('Name') or local_name(element.tag)
            value = element.text or ''
            if name in result:
                if not isinstance(result[name], list):
                    result[name] = [result[name]]
                result[name].append(value)
            else:
                result[name] = value
    return result


def normalize_event(data, source_format, source_file, raw_data):
    event_id_raw = find_value(data, 'EventID', 'EventId', 'Event ID', 'EventCode')
    try:
        event_id = int(event_id_raw) if event_id_raw is not None else None
    except (ValueError, TypeError):
        event_id = None
    timestamp_raw = find_value(data, 'TimeCreated', 'SystemTime', 'Timestamp', 'TimeCreated SystemTime', 'Date')
    timestamp = parse_timestamp(timestamp_raw)
    event = {
        'event_id': event_id,
        'timestamp': timestamp,
        'computer': find_value(data, 'Computer', 'ComputerName', 'Hostname'),
        'account': find_value(data, 'TargetUserName', 'SubjectUserName', 'AccountName', 'UserName', 'User'),
        'log_source': find_value(data, 'Channel', 'Provider', 'Source'),
        'process_name': find_value(data, 'Image', 'NewProcessName', 'ProcessName', 'Application', 'ExecutablePath'),
        'process_id': find_value(data, 'ProcessID', 'ProcessId', 'NewProcessId'),
        'command_line': find_value(data, 'CommandLine', 'ProcessCommandLine'),
        'parent_process': find_value(data, 'ParentImage', 'ParentProcessName', 'CreatorProcessName'),
        'logon_type': find_value(data, 'LogonType'),
        'source_ip': find_value(data, 'IpAddress', 'SourceIp', 'SourceAddress'),
        'event_record_id': find_value(data, 'EventRecordID', 'RecordId'),
        'source_format': source_format,
        'source_file': str(source_file),
        'raw_event': raw_data,
        'validation_warnings': [],
    }
    if event_id is None:
        event['validation_warnings'].append('Missing or invalid Event ID.')
    if timestamp is None:
        event['validation_warnings'].append('Missing or unrecognized timestamp.')
    return event


def parse_csv(path):
    events = []
    with open(path, 'r', encoding='utf-8-sig', newline='') as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames:
            raise ValueError('CSV file has no header row.')
        for line_number, row in enumerate(reader, start=2):
            if not any(value and value.strip() for value in row.values() if isinstance(value, str)):
                continue
            event = normalize_event(row, 'csv', path, json.dumps(row, ensure_ascii=False))
            event['source_line'] = line_number
            events.append(event)
    if not events:
        raise ValueError('CSV contains no event records.')
    return events


def parse_xml(path):
    root = SafeET.parse(path).getroot()
    elements = [root] if local_name(root.tag) == 'Event' else [e for e in root.iter() if local_name(e.tag) == 'Event']
    if not elements:
        raise ValueError('No Windows Event records found in XML.')
    events = []
    for element in elements:
        data = extract_event_data(element)
        raw = ET.tostring(element, encoding='unicode')
        events.append(normalize_event(data, 'xml', path, raw))
    return events


def parse_evtx(path):
    events = []
    with Evtx(str(path)) as log:
        for record in log.records():
            xml_text = record.xml()
            try:
                root = SafeET.fromstring(xml_text)
                data = extract_event_data(root)
                events.append(normalize_event(data, 'evtx', path, xml_text))
            except Exception as exc:
                events.append({
                    'event_id': None, 'timestamp': None, 'computer': None,
                    'account': None, 'log_source': None, 'process_name': None,
                    'process_id': None, 'command_line': None, 'parent_process': None,
                    'logon_type': None, 'source_ip': None,
                    'event_record_id': str(record.record_num()), 'source_format': 'evtx',
                    'source_file': str(path), 'raw_event': xml_text,
                    'validation_warnings': [f'Record parsing failed: {exc}'],
                })
    if not events:
        raise ValueError('EVTX file contains no readable records.')
    return events


def parse_log_file(file_path):
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f'File not found: {path}')
    extension = path.suffix.lower()
    if extension not in SUPPORTED_FORMATS:
        raise ValueError(f'Unsupported file type: {extension}. Use CSV, XML, or EVTX.')
    if extension == '.csv':
        return parse_csv(path)
    if extension == '.xml':
        return parse_xml(path)
    return parse_evtx(path)
