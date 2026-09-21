from __future__ import annotations

from pathlib import Path

import pytest

from src.analyzer import analyze_events, parse_log_file, validate_log_path


def test_parse_log_file(sample_log: Path):
    events = parse_log_file(sample_log)
    assert len(events) == 7
    assert events[0]['ip'] == '192.168.0.10'


def test_analyze_events_flags_suspicious_ip(sample_log: Path):
    result = analyze_events(parse_log_file(sample_log), brute_force_threshold=3)
    assert result['summary']['failed_logins'] == 6
    assert result['suspicious_ips'][0]['ip'] == '192.168.0.10'


def test_rejects_invalid_extension(tmp_path: Path):
    path = tmp_path / 'payload.py'
    path.write_text('print("bad")', encoding='utf-8')
    with pytest.raises(ValueError):
        validate_log_path(path)

def test_repository_sample_log_is_supported():
    path = Path(__file__).resolve().parents[1] / 'data' / 'sample_auth.log'
    result = analyze_events(parse_log_file(path), brute_force_threshold=5)
    assert result['summary']['total_events'] == 18
    assert result['summary']['failed_logins'] == 14
    assert len(result['suspicious_ips']) == 2
