import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.analyzer import analyze_events, parse_log_line


def test_parse_log_line():
    line = '2026-04-20 08:12:01 - 192.168.0.10 - LOGIN_ATTEMPT - user=admin - status=FAIL'
    parsed = parse_log_line(line)
    assert parsed is not None
    assert parsed['ip'] == '192.168.0.10'
    assert parsed['user'] == 'admin'
    assert parsed['status'] == 'FAIL'


def test_analyze_events_detects_suspicious_ip():
    events = [
        {'ip': '1.1.1.1', 'user': 'admin', 'status': 'FAIL'},
        {'ip': '1.1.1.1', 'user': 'admin', 'status': 'FAIL'},
        {'ip': '1.1.1.1', 'user': 'admin', 'status': 'FAIL'},
        {'ip': '1.1.1.1', 'user': 'admin', 'status': 'FAIL'},
        {'ip': '1.1.1.1', 'user': 'admin', 'status': 'FAIL'},
        {'ip': '2.2.2.2', 'user': 'maria', 'status': 'SUCCESS'},
    ]
    report = analyze_events(events, brute_force_threshold=5)
    assert report['failed_logins'] == 5
    assert len(report['suspicious_ips']) == 1
    assert report['suspicious_ips'][0]['ip'] == '1.1.1.1'
