"""Unified Access SOC v2: local fictional access monitoring and case investigation.

Enable with ENABLE_ACCESS_SOC=1. ACCESS_LAB_DB selects an existing Access Lab
SQLite database. Uses the password hash in the sibling login.json for operator
login. Correlation signals are computed, not saved as new Access Lab cases.
"""
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import abort, g, jsonify, make_response, render_template_string, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash

VERSION = '2.0.0'
COOKIE = 'sentinel_access_soc_v2'
STATUSES = {'open', 'investigating', 'resolved'}


@contextmanager
def connect(path, writable=False):
    uri = Path(path).resolve().as_uri() + ('?mode=rw' if writable else '?mode=ro')
    db = sqlite3.connect(uri, uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    if not writable:
        db.execute('PRAGMA query_only=ON')
    try:
        with db:
            yield db
    finally:
        db.close()


def epoch(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(value) and 0 <= value <= 4102444800 else None
    if isinstance(value, str):
        try:
            return epoch(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())
        except (ValueError, OverflowError, OSError):
            return None
    return None


def correlations(events):
    """Two bounded, explainable rules over the sampled access events."""
    ordered = sorted((e for e in events if epoch(e.get('ts')) is not None),
                     key=lambda e: (e['ts'], e['id']))
    badge_windows, door_windows = defaultdict(deque), defaultdict(deque)
    signals = {}

    def add(rule, badge, door, evidence, summary, severity):
        ids = [e['id'] for e in evidence]
        key_data = [rule, badge, door, ids]
        key = hashlib.sha256(json.dumps(key_data).encode()).hexdigest()[:24]
        return {'id': key, 'rule': rule, 'badge_id': badge, 'door_id': door,
                'severity': severity, 'summary': summary, 'event_ids': ids,
                'first_seen': evidence[0]['ts'], 'last_seen': evidence[-1]['ts'],
                'simulation': True, 'events': evidence}

    for event in ordered:
        now = event['ts']
        if event.get('kind') == 'swipe' and event.get('result') == 'DENIED' and event.get('badge_id'):
            badge = event['badge_id']
            recent = badge_windows[badge]
            recent.append(event)
            while recent and now - recent[0]['ts'] > 120:
                recent.popleft()
            if len({item['door_id'] for item in recent}) >= 3:
                signals[('MULTI_DOOR_DENIALS', badge)] = add(
                    'MULTI_DOOR_DENIALS', badge, 'Multiple doors', list(recent),
                    'The same simulated badge was denied at three or more doors within 120 seconds.', 'medium')
            door_windows[event['door_id']].append(event)
        if event.get('kind') == 'forced':
            recent = door_windows[event['door_id']]
            while recent and now - recent[0]['ts'] > 120:
                recent.popleft()
            per_badge = defaultdict(list)
            for item in recent:
                per_badge[item['badge_id']].append(item)
            for badge, denied in per_badge.items():
                if len(denied) >= 5:
                    signals[('DENIAL_THEN_FORCED_DOOR', event['id'], badge)] = add(
                        'DENIAL_THEN_FORCED_DOOR', badge, event['door_id'], denied + [event],
                        'Five or more denials by one badge preceded a forced-door signal at this door '
                        'within 120 seconds. Timing does not establish who opened the door.', 'high')
    return sorted(signals.values(), key=lambda signal: signal['last_seen'], reverse=True)[:40]


def register_access_soc(app):
    if os.environ.get('ENABLE_ACCESS_SOC') != '1' or 'unified_access_soc_v2' in app.extensions:
        return
    db_path = Path(os.environ.get('ACCESS_LAB_DB', str(Path.home() / '.sentinel-access-lab/access.db'))).expanduser()
    state_dir = Path(app.config.get('ACCESS_SOC_STATE_DIR', Path(app.root_path) / '.access_soc'))
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    secret_file = state_dir / 'session.key'
    if not secret_file.exists():
        fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write(secrets.token_hex(32))
    signer = URLSafeTimedSerializer(secret_file.read_text().strip(), salt='unified-access-soc-v2')
    security_path = state_dir / 'security.db'
    with sqlite3.connect(security_path) as security:
        security.execute('CREATE TABLE IF NOT EXISTS login_failures(ts REAL NOT NULL)')
    app.extensions['unified_access_soc_v2'] = {'database': db_path, 'version': VERSION}

    def credential():
        try:
            value = json.loads(db_path.with_name('login.json').read_text())['password_hash']
            if not isinstance(value, str) or not value:
                raise ValueError()
            return value
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def signed_state():
        try:
            value = signer.loads(request.cookies.get(COOKIE, ''), max_age=4 * 60 * 60)
            return value if isinstance(value, dict) else {}
        except (BadSignature, SignatureExpired):
            return {}

    def is_operator(value=None):
        value = signed_state() if value is None else value
        stored = credential()
        return bool(stored and value.get('kind') == 'operator' and
                    hmac.compare_digest(str(value.get('credential', '')).encode(),
                                        hashlib.sha256(stored.encode()).hexdigest().encode()))

    def need_operator(write=False):
        value = signed_state()
        if not is_operator(value):
            abort(401, 'Sign in with your Access Lab password')
        if write:
            actual = request.headers.get('X-CSRF-Token', '')
            expected = value.get('csrf', '')
            if not expected or not actual or not hmac.compare_digest(actual.encode(), str(expected).encode()):
                abort(403, 'Invalid request token. Refresh the dashboard.')
        return value

    def set_cookie(response, value):
        response.set_cookie(COOKIE, signer.dumps(value), max_age=4 * 60 * 60,
                            httponly=True, samesite='Strict', secure=False, path='/')
        return response

    def related_path():
        return request.path == '/access-monitor' or request.path.startswith(('/access-soc/', '/api/access-soc/')) or request.path == '/api/unified-events'

    @app.before_request
    def access_soc_boundary():
        g.access_soc_nonce = secrets.token_urlsafe(18)
        if related_path():
            request.max_content_length = 16384
            if request.remote_addr not in ('127.0.0.1', '::1') or request.host.split(':')[0] not in ('127.0.0.1', 'localhost'):
                abort(403, 'Unified Access SOC is local-only')

    @app.after_request
    def access_soc_headers(response):
        if related_path():
            response.headers['Cache-Control'] = 'no-store'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['Referrer-Policy'] = 'no-referrer'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; script-src 'nonce-" + g.access_soc_nonce + "'; "
                "style-src 'nonce-" + g.access_soc_nonce + "'; connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        if request.path == '/' and response.status_code == 200 and response.mimetype == 'text/html' and not response.direct_passthrough:
            html = response.get_data(as_text=True)
            if 'href="/access-monitor"' not in html:
                link = '<a class="nav" href="/access-monitor">▣ Unified Access SOC</a>'
                needle = '</aside>' if '</aside>' in html else '</body>'
                if needle in html:
                    response.set_data(html.replace(needle, link + needle, 1))
        return response

    def api_error(message, status):
        return jsonify(error=message), status

    def read_network():
        module = sys.modules.get(app.import_name)
        network = getattr(module, 'events', [])
        lock = getattr(module, 'lock', None)
        provider = app.config.get('ACCESS_SOC_NETWORK_PROVIDER')
        if provider:
            sample = list(provider())[:70]
        elif lock:
            with lock:
                sample = list(network[:70])
        else:
            sample = list(network[:70])
        normalized = []
        for item in sample:
            if not isinstance(item, dict) or item.get('source') == 'access_lab':
                continue
            ts = epoch(item.get('timestamp'))
            normalized.append({'id': 'network:' + str(item.get('id', '')), 'ts': ts,
                               'source': 'Offline IDS' if item.get('source') == 'ids' else 'Network demo',
                               'event': str(item.get('type', 'Event')), 'subject': str(item.get('ip', '')),
                               'location': str(item.get('destination_ip') or item.get('country', '')),
                               'severity': str(item.get('severity', 'low'))})
        return normalized

    def snapshot():
        network = read_network()
        access, cases, signals = [], [], []
        counts = {'total_events': 0, 'denied': 0, 'forced': 0, 'open_cases': 0}
        if db_path.is_file():
            with connect(db_path) as db:
                db.execute('BEGIN')
                access = [dict(row) for row in db.execute('SELECT * FROM events ORDER BY id DESC LIMIT 2000')]
                cases = [dict(row) for row in db.execute('SELECT c.*, (SELECT count(*) FROM case_events ce '
                         'WHERE ce.case_id=c.id) AS evidence_count FROM cases c ORDER BY id DESC LIMIT 200')]
                counts = dict(db.execute("SELECT count(*) AS total_events,coalesce(sum(result='DENIED'),0) AS denied,"
                                         "coalesce(sum(kind='forced'),0) AS forced FROM events").fetchone())
                counts['open_cases'] = db.execute("SELECT count(*) FROM cases WHERE status!='resolved'").fetchone()[0]
            signals = correlations(access)
        physical = [{'id': 'access:' + str(e['id']), 'ts': e['ts'], 'source': 'RFID simulation',
                     'event': e['result'], 'subject': e['badge_id'] or 'Unattributed sensor',
                     'location': e['door_id'], 'severity': 'high' if e['kind'] == 'forced' else
                     'medium' if e['result'] == 'DENIED' else 'low'} for e in access[:120]]
        timeline = sorted(network + physical, key=lambda e: e['ts'] if e['ts'] is not None else -1, reverse=True)[:140]
        return {'version': VERSION, 'simulation': True, 'access_connected': db_path.is_file(),
                'sampled_access_events': len(access), 'counts': counts, 'events': timeline,
                'cases': cases, 'correlations': signals, 'refreshed_at': time.time()}

    @app.get('/access-monitor')
    def access_monitor():
        operator = signed_state()
        if is_operator(operator):
            return render_template_string(PAGE, nonce=g.access_soc_nonce, operator=True,
                                          csrf=operator['csrf'], error=None, available=True)
        preauth = {'kind': 'preauth', 'csrf': secrets.token_urlsafe(24)}
        response = make_response(render_template_string(PAGE, nonce=g.access_soc_nonce, operator=False,
                                 csrf=preauth['csrf'], error=None, available=bool(credential())))
        return set_cookie(response, preauth)

    @app.post('/access-soc/login')
    def operator_login():
        value = signed_state()
        actual = request.form.get('csrf', '')
        expected = value.get('csrf', '')
        if value.get('kind') != 'preauth' or not actual or not expected or not hmac.compare_digest(actual.encode(), str(expected).encode()):
            abort(403, 'Refresh the login page')
        stored = credential()
        if stored is None:
            return api_error('Access Lab login.json is unavailable. Start Access Lab first.', 503)
        now = time.time()
        with sqlite3.connect(security_path) as db:
            db.execute('DELETE FROM login_failures WHERE ts<?', (now - 60,))
            failures = db.execute('SELECT count(*) FROM login_failures').fetchone()[0]
        if failures >= 10:
            return api_error('Too many attempts. Wait one minute.', 429)
        password = request.form.get('password', '')
        if len(password) > 200 or not check_password_hash(stored, password):
            with sqlite3.connect(security_path) as db:
                db.execute('INSERT INTO login_failures VALUES(?)', (now,))
            return render_template_string(PAGE, nonce=g.access_soc_nonce, operator=False, csrf=expected,
                                          error='Incorrect Access Lab password.', available=True), 401
        with sqlite3.connect(security_path) as db:
            db.execute('DELETE FROM login_failures')
        operator = {'kind': 'operator', 'csrf': secrets.token_urlsafe(24),
                    'credential': hashlib.sha256(stored.encode()).hexdigest()}
        response = make_response('', 303)
        response.headers['Location'] = '/access-monitor'
        return set_cookie(response, operator)

    @app.post('/access-soc/logout')
    def operator_logout():
        need_operator(True)
        response = jsonify(ok=True)
        response.delete_cookie(COOKIE, path='/', httponly=True, samesite='Strict')
        return response

    @app.get('/api/unified-events')
    def unified_events():
        value = need_operator()
        try:
            data = snapshot()
            data['csrf'] = value['csrf']
            return jsonify(data)
        except (sqlite3.Error, OSError, ValueError):
            return api_error('Access Lab schema or database could not be read', 503)

    @app.get('/api/access-soc/cases/<int:case_id>')
    def case_detail(case_id):
        need_operator()
        if not db_path.is_file():
            return api_error('Access Lab database not found', 503)
        try:
            with connect(db_path) as db:
                db.execute('BEGIN')
                case = db.execute('SELECT * FROM cases WHERE id=?', (case_id,)).fetchone()
                if case is None:
                    return api_error('Case not found', 404)
                events = [dict(row) for row in db.execute('SELECT e.* FROM case_events ce '
                          'JOIN events e ON e.id=ce.event_id WHERE ce.case_id=? ORDER BY e.id DESC LIMIT 200', (case_id,))]
                notes = [dict(row) for row in db.execute('SELECT * FROM notes WHERE case_id=? ORDER BY id DESC LIMIT 100', (case_id,))]
                total = db.execute('SELECT count(*) FROM case_events WHERE case_id=?', (case_id,)).fetchone()[0]
                note_total = db.execute('SELECT count(*) FROM notes WHERE case_id=?', (case_id,)).fetchone()[0]
            return jsonify(case=dict(case), events=list(reversed(events)), notes=list(reversed(notes)),
                           evidence_total=total, notes_total=note_total)
        except (sqlite3.Error, OSError):
            return api_error('Case database could not be read', 503)

    @app.post('/api/access-soc/cases/<int:case_id>')
    def case_update(case_id):
        need_operator(True)
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return api_error('Expected a JSON object', 400)
        status, note = body.get('status'), body.get('note', '')
        if not isinstance(status, str) or status not in STATUSES or not isinstance(note, str) or len(note) > 2000:
            return api_error('Choose a valid status and a note up to 2000 characters', 400)
        if not db_path.is_file():
            return api_error('Access Lab database not found', 503)
        try:
            with connect(db_path, writable=True) as db:
                db.execute('BEGIN IMMEDIATE')
                before = db.execute('SELECT status FROM cases WHERE id=?', (case_id,)).fetchone()
                if before is None:
                    return api_error('Case not found', 404)
                db.execute('UPDATE cases SET status=? WHERE id=?', (status, case_id))
                if note.strip():
                    db.execute('INSERT INTO notes(case_id,ts,author,note) VALUES(?,?,?,?)',
                               (case_id, time.time(), 'unified-soc-admin', note.strip()))
                detail = {'case_id': case_id, 'before': before['status'], 'after': status,
                          'note_added': bool(note.strip()), 'origin': 'Sentinel Unified Access SOC'}
                db.execute('INSERT INTO audit(ts,actor,action,details) VALUES(?,?,?,?)',
                           (time.time(), 'unified-soc-admin', 'case_update', json.dumps(detail, sort_keys=True)))
            return jsonify(ok=True)
        except (sqlite3.Error, OSError):
            return api_error('Case update could not be saved; transaction was rolled back', 503)

    @app.get('/api/access-soc/export')
    def export():
        need_operator()
        try:
            data = snapshot()
            data['exported_at'] = datetime.now(timezone.utc).isoformat()
            response = jsonify(data)
            response.headers['Content-Disposition'] = 'attachment; filename="unified_soc_snapshot.json"'
            return response
        except (sqlite3.Error, OSError, ValueError):
            return api_error('Snapshot could not be exported', 503)


PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel 2.0 · Unified Access SOC</title>
<style nonce="{{ nonce }}">
:root{color-scheme:dark;--bg:#09111d;--panel:#111f31;--line:#2a4058;--text:#e2ebf7;--muted:#92a9c2;--cyan:#75e6d4;--red:#ff9aab;--gold:#f1cf91}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}main{max-width:1350px;margin:auto;padding:26px}h1{font-size:28px;letter-spacing:-.8px;margin:5px 0}h2{font-size:17px;margin:0 0 12px}.muted,small{color:var(--muted)}a{color:var(--cyan)}button,input,select,textarea,.button{font:inherit;border:1px solid #405a75;border-radius:7px;padding:8px 11px}button,.button{background:#20374b;color:var(--text);cursor:pointer;text-decoration:none;display:inline-block}button:hover,.button:hover{border-color:var(--cyan)}input,select,textarea{background:#0a1625;color:var(--text);max-width:100%}button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,a:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}.primary{background:var(--cyan);color:#08241e;font-weight:700}.top,.row,.tools{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}.eyebrow{font-size:11px;letter-spacing:2px;color:var(--cyan)}.panel,.stat{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:18px;margin:16px 0}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.stat{margin:0}.stat b{font-size:29px;display:block;color:var(--cyan)}.banner{background:#15322f;border:1px solid #365d52;padding:11px 14px;border-radius:8px;margin:18px 0}.alert{border-color:#916449;background:#3c2b24;color:#ffdbb0}.bad{color:var(--red)}.good{color:var(--cyan)}.gold{color:var(--gold)}.scroll{overflow:auto;max-height:430px}table{width:100%;border-collapse:collapse;white-space:nowrap;text-align:left}th{color:var(--muted);font-size:11px;letter-spacing:.6px}td,th{padding:11px 9px;border-bottom:1px solid var(--line)}td{font-size:12px}.signal{padding:13px 0;border-top:1px solid var(--line)}.signal:first-child{border:0}.pill{font-size:11px;border:1px solid #476175;padding:2px 8px;border-radius:20px;display:inline-block}.empty{color:var(--muted);padding:14px 0}.login{max-width:480px;margin:10vh auto}.login input,.login button{width:100%;margin-top:10px}.label{display:block;color:var(--muted);margin:12px 0 6px}dialog{background:var(--panel);color:var(--text);border:1px solid #46647f;border-radius:12px;width:min(880px,96vw);max-height:90vh;padding:24px}dialog::backdrop{background:#000b}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;background:#091525;border-radius:8px;padding:12px}textarea,dialog select{width:100%}textarea{min-height:90px;margin-bottom:12px}.footer{text-align:center;color:var(--muted);font-size:11px;margin:25px 0}#search{width:300px}#status{min-height:22px;margin:8px 0}details{margin:12px 0}.hidden{display:none}
@media(max-width:760px){main{padding:15px}.stats{grid-template-columns:1fr 1fr}h1{font-size:23px}.panel{padding:14px}}
</style></head><body>
{% if not operator %}<main class="login"><div class="panel"><div class="eyebrow">SENTINEL / UNIFIED ACCESS SOC V2</div><h1>Open the investigation desk.</h1><p class="muted">Sign in with your existing Access Lab password to monitor fictional events and investigate cases.</p>
{% if not available %}<p class="bad">Access Lab login configuration was not found. Start Access Lab once, then reload.</p>{% endif %}
<form method="post" action="/access-soc/login"><input type="hidden" name="csrf" value="{{ csrf }}"><label class="label" for="password">Access Lab password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="200"><button class="primary" type="submit">Sign in</button></form>{% if error %}<p class="bad">{{ error }}</p>{% endif %}<p><a href="/">Back to Sentinel 2.0</a></p></div></main>
{% else %}<main><header class="top"><div><div class="eyebrow">SENTINEL 2.0 / UNIFIED ACCESS SOC V2</div><h1>Monitor. Connect the evidence. Respond.</h1><div class="muted" id="refreshStatus">Connecting to the local database…</div></div><div class="row"><a class="button" href="/">Sentinel overview</a><a class="button" href="http://127.0.0.1:5002/" target="_blank" rel="noopener">Access Lab controls</a><a class="button" href="/api/access-soc/export">Export snapshot</a><button id="logout">Sign out</button></div></header>
<div class="banner">FICTIONAL LAB · Badge and door data stay on this device. Refreshes about every 2 seconds while this page is active.</div><div id="newAlert" class="banner alert hidden" role="status" aria-live="polite"></div><div id="status" role="status" aria-live="polite"></div>
<div class="stats"><div class="stat"><small>ACCESS EVENTS / ALL TIME</small><b id="total">0</b></div><div class="stat"><small>DENIED / ALL TIME</small><b id="denied">0</b></div><div class="stat"><small>OPEN CASES / ALL TIME</small><b id="openCases">0</b></div><div class="stat"><small>CORRELATION SIGNALS / SAMPLE</small><b id="signalCount">0</b></div></div>
<section class="panel"><div class="tools"><h2>Related activity</h2><button id="refresh">Refresh now</button></div><div id="signals"></div><details><summary class="muted">Rules and how to test them</summary><p class="muted">MULTI_DOOR_DENIALS: one badge denied at 3 different doors in 120 seconds. DENIAL_THEN_FORCED_DOOR: at least 5 denials by one badge, followed by a forced-door signal at the same door within 120 seconds. The sensor event does not identify who opened the door.</p><p class="muted">Try the first rule: in Access Lab, present SIM-UNKNOWN at three different doors within two minutes. Signals are computed from the latest 2,000 access events and remain visible as historical findings in that sample. They are separate from saved Access Lab cases.</p></details></section>
<section class="panel"><h2>Central investigation queue</h2><div class="scroll"><table><thead><tr><th>CASE</th><th>RULE</th><th>BADGE</th><th>DOOR</th><th>SEVERITY</th><th>STATUS</th><th>REVIEW</th></tr></thead><tbody id="caseRows"></tbody></table></div><p class="muted">Newest 200 cases. Evidence, notes and case-status edits use the same Access Lab database. Badge and door controls remain in Access Lab.</p></section>
<section class="panel"><div class="tools"><h2>Combined event timeline</h2><input id="search" placeholder="Filter source, badge, IP, door…" aria-label="Filter timeline"></div><div class="scroll"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>EVENT</th><th>SUBJECT</th><th>LOCATION</th><th>SEVERITY</th></tr></thead><tbody id="eventRows"></tbody></table></div><p class="muted">Latest 140 events from sampled access activity and Sentinel's retained network feed. IDS events are labeled when present. Shared timestamps alone do not establish a badge-to-IP identity.</p></section><p class="footer">LOCAL SIMULATION · V2.0 · POLLING STOPS WHEN THIS PAGE IS CLOSED</p></main>
<dialog id="investigation"><div class="row"><h2 id="caseTitle">Investigation</h2><button id="closeCase">Close</button></div><p id="caseSummary"></p><div id="caseEvidence"></div><h3>Analyst notes</h3><div id="caseNotes"></div><form id="caseForm"><label class="label" for="caseStatus">Status</label><select id="caseStatus"><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select><label class="label" for="caseNote">Add a note</label><textarea id="caseNote" maxlength="2000" placeholder="Record your assessment and supporting evidence…"></textarea><button class="primary" type="submit">Save to Access Lab</button></form></dialog>
<dialog id="signalDialog"><div class="row"><h2 id="signalTitle">Correlation evidence</h2><button id="closeSignal">Close</button></div><p id="signalSummary"></p><pre id="signalEvidence"></pre></dialog>
<script nonce="{{ nonce }}">
(()=>{const $=id=>document.getElementById(id),el=(tag,text)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e};let csrf={{ csrf|tojson }},state=null,busy=false,activeCase=null,seenCases=null,seenSignals=new Set();
const when=ts=>ts===null?'Unknown time':new Date(ts*1000).toLocaleString();
function message(text,error=false){$('status').textContent=text;$('status').className=error?'bad':'good'}
async function api(path,body){const options={cache:'no-store',credentials:'same-origin',headers:{}};if(body!==undefined){options.method='POST';options.headers={'Content-Type':'application/json','X-CSRF-Token':csrf};options.body=JSON.stringify(body)}const r=await fetch(path,options);if(r.status===401){location.href='/access-monitor';throw Error('Please sign in again')}if(!r.ok){let text='Request failed: '+r.status;try{text=(await r.json()).error||text}catch{}throw Error(text)}return r.json()}
function empty(root,text,columns){const row=el('tr'),td=el('td',text);td.colSpan=columns;td.className='empty';row.append(td);root.append(row)}
function renderEvents(){if(!state)return;const term=$('search').value.toLowerCase(),root=$('eventRows');root.replaceChildren();for(const e of state.events.filter(e=>[e.source,e.event,e.subject,e.location,e.severity].join(' ').toLowerCase().includes(term))){const row=el('tr');for(const v of [when(e.ts),e.source,e.event,e.subject,e.location,e.severity])row.append(el('td',v));root.append(row)}if(!root.children.length)empty(root,'No matching events.',6)}
function renderCases(){const root=$('caseRows');root.replaceChildren();for(const c of state.cases){const row=el('tr');for(const v of ['#'+c.id,c.rule,c.badge_id||'Unattributed',c.door_id,c.severity,c.status])row.append(el('td',v));const td=el('td'),b=el('button','Investigate · '+c.evidence_count);b.addEventListener('click',()=>openCase(c.id));td.append(b);row.append(td);root.append(row)}if(!root.children.length)empty(root,'No saved cases. Run Repeated denials in Access Lab.',7)}
function renderSignals(){const root=$('signals');root.replaceChildren();for(const s of state.correlations){const item=el('div');item.className='signal';const top=el('div');top.className='row';const title=el('strong',s.rule+' · '+s.severity);const b=el('button','Inspect '+s.event_ids.length+' events');b.addEventListener('click',()=>{$('signalTitle').textContent=s.rule;$('signalSummary').textContent=s.summary;$('signalEvidence').textContent=JSON.stringify(s,null,2);$('signalDialog').showModal()});top.append(title,b);item.append(top,el('p',s.badge_id+' → '+s.door_id),el('p',s.summary));root.append(item)}if(!state.correlations.length){const p=el('p','No related-activity patterns detected in the current sample.');p.className='empty';root.append(p)}}
async function refresh(){if(busy)return;busy=true;try{const next=await api('/api/unified-events');csrf=next.csrf;if(seenCases!==null){const fresh=next.cases.filter(c=>!seenCases.has(c.id)),signals=next.correlations.filter(s=>!seenSignals.has(s.id));if(fresh.length||signals.length){$('newAlert').textContent='New findings: '+fresh.length+' case(s), '+signals.length+' correlation signal(s). Review the evidence below.';$('newAlert').classList.remove('hidden')}}seenCases=new Set(next.cases.map(c=>c.id));seenSignals=new Set(next.correlations.map(s=>s.id));state=next;$('total').textContent=next.counts.total_events;$('denied').textContent=next.counts.denied;$('openCases').textContent=next.counts.open_cases;$('signalCount').textContent=next.correlations.length;$('refreshStatus').textContent=(next.access_connected?'Access Lab connected':'Access Lab database not found')+' · Updated '+when(next.refreshed_at);renderCases();renderSignals();renderEvents()}catch(e){message(e.message,true)}finally{busy=false}}
async function openCase(id){try{const data=await api('/api/access-soc/cases/'+id);activeCase=id;$('caseTitle').textContent='Case #'+id+' · '+data.case.rule;$('caseSummary').textContent=data.case.summary;$('caseStatus').value=data.case.status;$('caseNote').value='';const evidence=$('caseEvidence');evidence.replaceChildren(el('p','Showing '+data.events.length+' / '+data.evidence_total+' evidence events.'));for(const e of data.events)evidence.append(el('pre',JSON.stringify(e,null,2)));const notes=$('caseNotes');notes.replaceChildren(el('p','Showing '+data.notes.length+' / '+data.notes_total+' notes.'));for(const n of data.notes)notes.append(el('p',when(n.ts)+' · '+n.author+': '+n.note));if(!$('investigation').open)$('investigation').showModal()}catch(e){message(e.message,true)}}
$('caseForm').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/access-soc/cases/'+activeCase,{status:$('caseStatus').value,note:$('caseNote').value});message('Case saved. The same update is visible in Access Lab.');await openCase(activeCase);await refresh()}catch(error){message(error.message,true)}});
$('search').addEventListener('input',renderEvents);$('refresh').addEventListener('click',refresh);$('closeCase').addEventListener('click',()=>$('investigation').close());$('closeSignal').addEventListener('click',()=>$('signalDialog').close());$('logout').addEventListener('click',async()=>{try{await api('/access-soc/logout',{});location.href='/access-monitor'}catch(e){message(e.message,true)}});refresh();setInterval(refresh,2000);
})();
</script>{% endif %}</body></html>'''
