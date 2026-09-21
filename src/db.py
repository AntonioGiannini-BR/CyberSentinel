from __future__ import annotations
import json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA='''
CREATE TABLE IF NOT EXISTS analyses (
 id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT NOT NULL, stored_path TEXT NOT NULL,
 report_path TEXT NOT NULL, total_events INTEGER NOT NULL, failed_logins INTEGER NOT NULL,
 successful_logins INTEGER NOT NULL, suspicious_ips INTEGER NOT NULL, created_at TEXT NOT NULL,
 result_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);
'''
def connect(db_path: Path):
    db_path.parent.mkdir(parents=True,exist_ok=True); c=sqlite3.connect(db_path); c.row_factory=sqlite3.Row; return c
def init_db(db_path: Path):
    with connect(db_path) as c: c.executescript(SCHEMA); c.commit()
def save_analysis(db_path: Path, filename: str, stored_path: Path, report_path: Path, result: dict[str,Any])->int:
    s=result.get('summary',{}); created=datetime.now(timezone.utc).isoformat()
    with connect(db_path) as c:
        cur=c.execute('''INSERT INTO analyses(filename,stored_path,report_path,total_events,failed_logins,successful_logins,suspicious_ips,created_at,result_json) VALUES(?,?,?,?,?,?,?,?,?)''',(filename,str(stored_path),str(report_path),int(s.get('total_events',0)),int(s.get('failed_logins',0)),int(s.get('successful_logins',0)),len(result.get('suspicious_ips',[])),created,json.dumps(result,ensure_ascii=False))); c.commit(); return int(cur.lastrowid)
def list_analyses(db_path: Path, limit:int=50, query:str=''):
    with connect(db_path) as c:
        if query:
            return list(c.execute('SELECT * FROM analyses WHERE filename LIKE ? ORDER BY created_at DESC LIMIT ?', (f'%{query}%',limit)))
        return list(c.execute('SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?',(limit,)))
def get_analysis(db_path: Path, analysis_id:int):
    with connect(db_path) as c: return c.execute('SELECT * FROM analyses WHERE id=?',(analysis_id,)).fetchone()
def delete_analysis(db_path: Path, analysis_id:int)->bool:
    with connect(db_path) as c:
        cur=c.execute('DELETE FROM analyses WHERE id=?',(analysis_id,)); c.commit(); return cur.rowcount>0
def dashboard_stats(db_path: Path)->dict[str,Any]:
    rows=list_analyses(db_path,limit=500)
    totals={'analyses':len(rows),'events':0,'failed':0,'success':0,'alerts':0}
    risk={'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
    categories={'Brute force':0,'Falhas de login':0,'Usuários alvo':0,'IPs únicos':0}
    days={}
    for r in rows:
        totals['events']+=r['total_events']; totals['failed']+=r['failed_logins']; totals['success']+=r['successful_logins']; totals['alerts']+=r['suspicious_ips']
        day=r['created_at'][:10]; d=days.setdefault(day,{'analyses':0,'alerts':0}); d['analyses']+=1; d['alerts']+=r['suspicious_ips']
        try: result=json.loads(r['result_json'])
        except Exception: result={}
        sus=result.get('suspicious_ips',[])
        for item in sus: risk[item.get('risk','MEDIUM') if item.get('risk') in risk else 'MEDIUM']+=1
        categories['Brute force']+=len(sus); categories['Falhas de login']+=r['failed_logins']; categories['Usuários alvo']+=len(result.get('targeted_users',[])); categories['IPs únicos']+=result.get('summary',{}).get('unique_ips',0)
    timeline=[{'day':k,'analyses':v['analyses'],'alerts':v['alerts']} for k,v in sorted(days.items())[-7:]]
    denom=max(totals['events'],1); risk_score=min(100,round((totals['failed']/denom)*55 + min(totals['alerts']*8,45)))
    return {'totals':totals,'risk':risk,'categories':categories,'timeline':timeline,'risk_score':risk_score}
