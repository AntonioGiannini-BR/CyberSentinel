import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional

LOG_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+)\s+-\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+'
    r'(?P<event>[A-Z_]+)\s+-\s+user=(?P<user>[\w.@-]+)\s+-\s+status=(?P<status>\w+)'
)


def parse_log_line(line: str) -> Optional[Dict[str, str]]:
    match = LOG_PATTERN.search(line.strip())
    return match.groupdict() if match else None


def load_logs(file_path: str) -> List[Dict[str, str]]:
    events: List[Dict[str, str]] = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line_number, line in enumerate(file, start=1):
            parsed = parse_log_line(line)
            if parsed:
                parsed['line_number'] = str(line_number)
                events.append(parsed)
    return events


def analyze_events(events: List[Dict[str, str]], brute_force_threshold: int = 5) -> Dict:
    failed_by_ip = Counter()
    failed_by_user = Counter()
    success_by_ip = Counter()
    events_by_ip = defaultdict(list)

    for event in events:
        ip = event['ip']
        user = event['user']
        status = event['status'].upper()
        events_by_ip[ip].append(event)

        if status == 'FAIL':
            failed_by_ip[ip] += 1
            failed_by_user[user] += 1
        elif status == 'SUCCESS':
            success_by_ip[ip] += 1

    suspicious_ips = []
    for ip, count in failed_by_ip.items():
        if count >= brute_force_threshold:
            suspicious_ips.append({
                'ip': ip,
                'failed_attempts': count,
                'successful_attempts': success_by_ip[ip],
                'risk': 'high' if count >= brute_force_threshold * 2 else 'medium'
            })

    suspicious_users = [
        {'user': user, 'failed_attempts': count}
        for user, count in failed_by_user.most_common()
        if count >= 3
    ]

    summary = {
        'total_events': len(events),
        'failed_logins': sum(failed_by_ip.values()),
        'successful_logins': sum(success_by_ip.values()),
        'unique_ips': len(events_by_ip),
        'suspicious_ips': sorted(suspicious_ips, key=lambda x: x['failed_attempts'], reverse=True),
        'targeted_users': suspicious_users,
        'top_ips': [{'ip': ip, 'events': count} for ip, count in Counter(e['ip'] for e in events).most_common(5)]
    }
    return summary


def print_report(report: Dict) -> None:
    print('\n=== CyberSentinel Security Report ===')
    print(f"Total events: {report['total_events']}")
    print(f"Failed logins: {report['failed_logins']}")
    print(f"Successful logins: {report['successful_logins']}")
    print(f"Unique IPs: {report['unique_ips']}")

    print('\nTop IPs by activity:')
    for item in report['top_ips']:
        print(f"- {item['ip']}: {item['events']} events")

    print('\nSuspicious IPs:')
    if report['suspicious_ips']:
        for item in report['suspicious_ips']:
            print(
                f"- {item['ip']} | failed: {item['failed_attempts']} | "
                f"success: {item['successful_attempts']} | risk: {item['risk']}"
            )
    else:
        print('- None found')

    print('\nTargeted users:')
    if report['targeted_users']:
        for item in report['targeted_users']:
            print(f"- {item['user']}: {item['failed_attempts']} failed attempts")
    else:
        print('- None found')


def save_report(report: Dict, output_path: str) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, 'w', encoding='utf-8') as file:
        json.dump(report, file, indent=2, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser(description='CyberSentinel - Security log analyzer')
    parser.add_argument('logfile', help='Path to the log file')
    parser.add_argument('--threshold', type=int, default=5, help='Brute-force detection threshold')
    parser.add_argument('--output', default='report.json', help='Path to save the JSON report')
    args = parser.parse_args()

    events = load_logs(args.logfile)
    report = analyze_events(events, brute_force_threshold=args.threshold)
    print_report(report)
    save_report(report, args.output)
    print(f'\nJSON report saved to: {args.output}')


if __name__ == '__main__':
    main()
