from __future__ import annotations

from pathlib import Path

import pytest

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def sample_log(tmp_path: Path) -> Path:
    content = '''2026-05-01 10:00:00 IP=192.168.0.10 USER=admin ACTION=login STATUS=failed
2026-05-01 10:00:02 IP=192.168.0.10 USER=admin ACTION=login STATUS=failed
2026-05-01 10:00:04 IP=192.168.0.10 USER=admin ACTION=login STATUS=failed
2026-05-01 10:00:06 IP=192.168.0.10 USER=admin ACTION=login STATUS=failed
2026-05-01 10:00:08 IP=192.168.0.10 USER=admin ACTION=login STATUS=failed
2026-05-01 10:00:10 IP=192.168.0.10 USER=admin ACTION=login STATUS=success
2026-05-01 10:01:10 IP=10.0.0.5 USER=guest ACTION=login STATUS=failed
'''
    path = tmp_path / 'sample.log'
    path.write_text(content, encoding='utf-8')
    return path
