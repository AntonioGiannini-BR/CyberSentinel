from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+)\s+IP=(?P<ip>[\d.]+)\s+USER=(?P<user>[\w.-]+)\s+ACTION=(?P<action>\w+)\s+STATUS=(?P<status>\w+)',
    re.IGNORECASE,
)

LEGACY_LOG_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+)\s+-\s+(?P<ip>[\d.]+)\s+-\s+(?P<action>[A-Z_]+)\s+-\s+user=(?P<user>[\w.-]+)\s+-\s+status=(?P<status>\w+)',
    re.IGNORECASE,
)

ALLOWED_EXTENSIONS = ('.log', '.txt')
MAX_FILE_BYTES = 1_000_000


def validate_log_path(path: Path, allowed_extensions: tuple[str, ...] = ALLOWED_EXTENSIONS, max_bytes: int = MAX_FILE_BYTES) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.exists() or not resolved.is_file():
        raise FileNotFoundError('Log file not found.')
    if resolved.suffix.lower() not in allowed_extensions:
        raise ValueError('Only .log and .txt files are supported.')
    if resolved.stat().st_size > max_bytes:
        raise ValueError(f'Log file exceeds the maximum size of {max_bytes} bytes.')
    return resolved


def parse_log_file(path: Path) -> list[dict[str, str]]:
    resolved = validate_log_path(path)
    events: list[dict[str, str]] = []
    with resolved.open('r', encoding='utf-8', errors='replace') as file:
        for line_number, line in enumerate(file, start=1):
            match = LOG_PATTERN.search(line.strip()) or LEGACY_LOG_PATTERN.search(line.strip())
            if not match:
                continue
            event = match.groupdict()
            status = event.get('status', '').lower()
            event['status'] = 'failed' if status in ('fail', 'failed', 'failure') else 'success' if status in ('success', 'ok', 'successful') else status
            event['line_number'] = str(line_number)
            events.append(event)
    return events


def analyze_events(events: list[dict[str, str]], brute_force_threshold: int = 5) -> dict[str, Any]:
    ip_counter = Counter(event['ip'] for event in events)
    failed_by_ip: dict[str, int] = defaultdict(int)
    users_targeted = Counter(event['user'] for event in events if event['status'].lower() == 'failed')
    success_count = 0
    failed_count = 0

    for event in events:
        status = event['status'].lower()
        if status == 'failed':
            failed_count += 1
            failed_by_ip[event['ip']] += 1
        elif status == 'success':
            success_count += 1

    suspicious_ips = [
        {
            'ip': ip,
            'failed_attempts': attempts,
            'risk': ('CRITICAL' if attempts >= brute_force_threshold * 3 else 'HIGH' if attempts >= brute_force_threshold * 2 else 'MEDIUM'),
        }
        for ip, attempts in sorted(failed_by_ip.items(), key=lambda item: item[1], reverse=True)
        if attempts >= brute_force_threshold
    ]

    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'summary': {
            'total_events': len(events),
            'failed_logins': failed_count,
            'successful_logins': success_count,
            'unique_ips': len(ip_counter),
        },
        'top_ips': [{'ip': ip, 'events': count} for ip, count in ip_counter.most_common(10)],
        'targeted_users': [{'user': user, 'failed_attempts': count} for user, count in users_targeted.most_common(10)],
        'suspicious_ips': suspicious_ips,
    }


def save_report(result: dict[str, Any], reports_dir: Path, prefix: str = 'report') -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    report_path = reports_dir / f'{prefix}-{timestamp}.json'
    with report_path.open('w', encoding='utf-8') as file:
        json.dump(result, file, indent=2, ensure_ascii=False)
    return report_path


def analyze_log_file(path: Path, reports_dir: Path, brute_force_threshold: int = 5) -> tuple[dict[str, Any], Path]:
    events = parse_log_file(path)
    result = analyze_events(events, brute_force_threshold=brute_force_threshold)
    report_path = save_report(result, reports_dir)
    return result, report_path


def main() -> int:
    parser = argparse.ArgumentParser(description='CyberSentinel security log analyzer')
    parser.add_argument('log_file', help='Path to a .log or .txt authentication log')
    parser.add_argument('--threshold', type=int, default=5, help='Failed attempts required to flag an IP')
    parser.add_argument('--reports-dir', default='reports', help='Directory where JSON reports are saved')
    args = parser.parse_args()

    try:
        result, report_path = analyze_log_file(Path(args.log_file), Path(args.reports_dir), args.threshold)
    except (FileNotFoundError, ValueError) as exc:
        print(f'Error: {exc}')
        return 1

    print('CyberSentinel Analysis Summary')
    print(json.dumps(result['summary'], indent=2))
    print(f'Report saved to: {report_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
