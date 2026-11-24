#!/usr/bin/env python3
"""PisoNet Milestone 1 prototype server. Python stdlib only; LAN prototype, not production hardened."""
from __future__ import annotations
import json, os, secrets, sqlite3, threading, time, uuid, hashlib, hmac, base64, mimetypes, socket, shutil, subprocess, sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote
from coin_signal_engine import CoinSignalEngine, DecoderConfig, SignalError
from serial_coin_adapter import SerialCoinAdapter

ROOT = Path(__file__).resolve().parent
SERVER_VERSION = '2.0.0-dev3'
SERVER_BUILD = '0.22'
SERVER_GITHUB_REPOSITORY = 'kenpachi1315/shutdowntimer-release'
SERVER_GITHUB_BRANCH = 'release/server'
SERVER_GITHUB_RAW = f'https://raw.githubusercontent.com/{SERVER_GITHUB_REPOSITORY}/{SERVER_GITHUB_BRANCH}'
SERVER_UPDATE_ALLOWED_FILES = {
    'server.py':'server.py',
    'coin_signal_engine.py':'coin_signal_engine.py',
    'serial_coin_adapter.py':'serial_coin_adapter.py',
    'server_update_worker.py':'server_update_worker.py',
    'web/admin_v2.html':'web/admin_v2.html',
}
SERVER_UPDATE_LOCK = threading.Lock()
SERVER_UPDATE_STATUS_PATH = ROOT / 'server_update_status.json'
SERVER_UPDATE_STALE_AFTER_SECONDS = 180


def server_update_status_is_active(status):
    if not isinstance(status,dict) or status.get('state') not in ('queued','starting','stopping','installing','rollback'):
        return False
    try: updated=float(status.get('updated_at',0))
    except (TypeError,ValueError): updated=0
    return updated>0 and time.time()-updated < SERVER_UPDATE_STALE_AFTER_SECONDS


def resolve_timezone(name='Asia/Manila'):
    """Resolve a configured IANA timezone, with a Windows-safe Manila fallback.

    Windows Python installations often lack the system IANA timezone database.
    Manila is UTC+8 year-round, so its fixed-offset fallback is exact.
    """
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    try:
        return ZoneInfo(name or 'Asia/Manila')
    except ZoneInfoNotFoundError:
        if (name or 'Asia/Manila') == 'Asia/Manila':
            from datetime import timezone, timedelta
            return timezone(timedelta(hours=8), name='PHT')
        raise


def load_pisonet_environment():
    """Load local PisoNet env files for manual and service-wrapper startup.

    Existing process environment variables take precedence. If both files are
    present, server_service.env overrides .env for values not set by the process.
    Only PISONET_* keys are imported.
    """
    parsed = {}
    sources = []
    for env_path in (ROOT / '.env', ROOT / 'server_service.env'):
        if not env_path.is_file():
            continue
        sources.append(env_path.name)
        for raw in env_path.read_text(encoding='utf-8-sig').splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('export '):
                line = line[7:].lstrip()
            if '=' not in line:
                continue
            key, value = (part.strip() for part in line.split('=', 1))
            if not key.startswith('PISONET_'):
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            elif ' #' in value:
                value = value.split(' #', 1)[0].rstrip()
            parsed[key] = value
    for key, value in parsed.items():
        os.environ.setdefault(key, value)
    if sources:
        print('Loaded PisoNet configuration from: ' + ', '.join(sources))
    return sources


load_pisonet_environment()
DB_PATH = Path(os.environ.get('PISONET_DB', ROOT / 'pisonet.db'))
HOST = os.environ.get('PISONET_HOST', '0.0.0.0')
PORT = int(os.environ.get('PISONET_PORT', '3210'))
INACTIVITY_SECONDS = int(os.environ.get('PISONET_INACTIVITY_SECONDS', '30'))
MAX_INSERT_SECONDS = int(os.environ.get('PISONET_MAX_INSERT_SECONDS', '180'))
LOCK = threading.RLock()
SPECTATE = {}
LOGIN_GUARD_LOCK = threading.Lock()
LOGIN_FAILURES = {}  # per-source-IP in-memory throttling; reset on server restart
COIN_EVENT_DIR = ROOT / 'logs'
COIN_EVENT_LOCK = threading.Lock()


def connect():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA journal_mode=WAL')
    return db


def github_ssl_context():
    """Use verified TLS with Windows trust stores, matching Telegram delivery."""
    import ssl
    if os.name == 'nt' and hasattr(ssl,'enum_certificates'):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode=ssl.CERT_REQUIRED;context.check_hostname=True
        certs=[]
        for store in ('ROOT','CA'):
            for cert,encoding,_trust in ssl.enum_certificates(store):
                if encoding=='x509_asn': certs.append(ssl.DER_cert_to_PEM_cert(cert))
        if certs: context.load_verify_locations(cadata=''.join(certs))
    else:
        context=ssl.create_default_context()
    ca_bundle=os.environ.get('PISONET_TLS_CA_BUNDLE','').strip()
    if ca_bundle: context.load_verify_locations(cafile=ca_bundle)
    return context


def server_build_tuple(value):
    import re
    match=re.fullmatch(r'\d+(?:\.\d+){1,3}',str(value or ''))
    if not match: raise ValueError('INVALID_SERVER_BUILD')
    return tuple(int(part) for part in str(value).split('.'))


def fetch_server_release_manifest():
    request=urllib.request.Request(SERVER_GITHUB_RAW+'/manifest.json',headers={'User-Agent':'PisoNet-Server-Updater/1','Accept':'application/json'})
    with urllib.request.urlopen(request,timeout=20,context=github_ssl_context()) as response:
        raw=response.read(512*1024+1)
    if len(raw)>512*1024: raise ValueError('SERVER_RELEASE_MANIFEST_TOO_LARGE')
    manifest=json.loads(raw.decode('utf-8'))
    build=str(manifest.get('build',''))
    server_build_tuple(build)
    entries=manifest.get('files')
    if not isinstance(entries,dict): raise ValueError('SERVER_RELEASE_FILES_INVALID')
    required=set(SERVER_UPDATE_ALLOWED_FILES)
    if set(entries)!=required: raise ValueError('SERVER_RELEASE_FILE_SET_MISMATCH')
    for source,entry in entries.items():
        if not isinstance(entry,dict) or entry.get('destination')!=SERVER_UPDATE_ALLOWED_FILES[source]:
            raise ValueError('SERVER_RELEASE_DESTINATION_INVALID')
        digest=str(entry.get('sha256',''))
        if len(digest)!=64 or any(c not in '0123456789abcdefABCDEF' for c in digest):
            raise ValueError('SERVER_RELEASE_CHECKSUM_INVALID')
    return manifest,raw


def server_release_status(manifest):
    remote_build=str(manifest['build'])
    remote_tuple=server_build_tuple(remote_build)
    current_tuple=server_build_tuple(SERVER_BUILD)
    changed=[]
    for source,entry in manifest['files'].items():
        local_path=ROOT/SERVER_UPDATE_ALLOWED_FILES[source]
        local_hash=hashlib.sha256(local_path.read_bytes()).hexdigest() if local_path.is_file() else ''
        if not hmac.compare_digest(local_hash.lower(),str(entry['sha256']).lower()): changed.append(source)
    # A release is installable only when its declared build increases. This
    # prevents a republished/same-version manifest from trapping the UI in an
    # update loop when byte-level differences are present.
    available=remote_tuple>current_tuple
    return {'repository':SERVER_GITHUB_REPOSITORY,'branch':SERVER_GITHUB_BRANCH,
            'current_build':SERVER_BUILD,'latest_build':remote_build,'update_available':available,
            'changed_files':changed,'checked_at':time.time(),
            'message':('Server update available.' if available else 'Server is up to date.')}


def read_server_update_status():
    try:
        status=json.loads(SERVER_UPDATE_STATUS_PATH.read_text(encoding='utf-8'))
        return status if isinstance(status,dict) else None
    except (OSError,ValueError):
        return None


def download_server_release(stage: Path, manifest: dict):
    payload=stage/'payload';payload.mkdir(parents=True,exist_ok=False)
    total=0
    for source,entry in manifest['files'].items():
        destination=SERVER_UPDATE_ALLOWED_FILES[source]
        request=urllib.request.Request(SERVER_GITHUB_RAW+'/'+quote(source,safe='/'),headers={'User-Agent':'PisoNet-Server-Updater/1','Accept':'application/octet-stream'})
        with urllib.request.urlopen(request,timeout=30,context=github_ssl_context()) as response:
            content=response.read(8*1024*1024+1)
        if len(content)>8*1024*1024: raise ValueError('SERVER_RELEASE_FILE_TOO_LARGE: '+source)
        total+=len(content)
        if total>20*1024*1024: raise ValueError('SERVER_RELEASE_PACKAGE_TOO_LARGE')
        digest=hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(digest.lower(),str(entry['sha256']).lower()):
            raise ValueError('SERVER_RELEASE_CHECKSUM_MISMATCH: '+source)
        target=payload/destination;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
    (stage/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return payload


def init_db():
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS pcs(id TEXT PRIMARY KEY, name TEXT NOT NULL, token TEXT NOT NULL UNIQUE, created_at REAL NOT NULL, last_seen REAL, online INTEGER NOT NULL DEFAULT 0, device_uuid TEXT, archived INTEGER NOT NULL DEFAULT 0, admin_locked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS rate_rules(denomination_centavos INTEGER PRIMARY KEY, seconds INTEGER NOT NULL CHECK(seconds >= 0));
        CREATE TABLE IF NOT EXISTS coin_sessions(id TEXT PRIMARY KEY, pc_id TEXT NOT NULL REFERENCES pcs(id), status TEXT NOT NULL, amount_centavos INTEGER NOT NULL DEFAULT 0, started_at REAL NOT NULL, last_coin_at REAL, finalized_at REAL, transaction_id TEXT UNIQUE, error TEXT);
        CREATE TABLE IF NOT EXISTS coin_batches(id INTEGER PRIMARY KEY AUTOINCREMENT, coin_session_id TEXT NOT NULL REFERENCES coin_sessions(id), denomination_centavos INTEGER NOT NULL, received_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS transactions(id TEXT PRIMARY KEY, coin_session_id TEXT NOT NULL UNIQUE REFERENCES coin_sessions(id), pc_id TEXT NOT NULL REFERENCES pcs(id), amount_centavos INTEGER NOT NULL, purchased_seconds INTEGER NOT NULL, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS active_sessions(id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL UNIQUE REFERENCES transactions(id), pc_id TEXT NOT NULL REFERENCES pcs(id), started_at REAL NOT NULL, expires_at REAL NOT NULL, status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS shutdown_completions(pc_id TEXT NOT NULL REFERENCES pcs(id) ON DELETE CASCADE, expired_at REAL NOT NULL, completed_at REAL NOT NULL, PRIMARY KEY(pc_id,expired_at));
        CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS connection_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, pc_id TEXT, hostname TEXT NOT NULL DEFAULT '', source_ip TEXT NOT NULL DEFAULT '', event TEXT NOT NULL, outcome TEXT NOT NULL, details TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS maintenance_sessions(pc_id TEXT PRIMARY KEY REFERENCES pcs(id), enabled INTEGER NOT NULL DEFAULT 0, changed_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS admin_users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS admin_sessions(token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS security_global(id INTEGER PRIMARY KEY CHECK(id=1), policy_json TEXT NOT NULL, updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS security_pc_overrides(pc_id TEXT PRIMARY KEY REFERENCES pcs(id) ON DELETE CASCADE, policy_json TEXT NOT NULL, updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS client_health(pc_id TEXT PRIMARY KEY REFERENCES pcs(id) ON DELETE CASCADE, at REAL NOT NULL, service_state TEXT NOT NULL, guard_state TEXT NOT NULL, client_state TEXT NOT NULL, service_pid INTEGER, guard_pid INTEGER, client_pid INTEGER, session_id INTEGER, network_connected INTEGER NOT NULL DEFAULT 0, version TEXT NOT NULL DEFAULT '3D');
        CREATE TABLE IF NOT EXISTS component_heartbeats(pc_id TEXT NOT NULL REFERENCES pcs(id) ON DELETE CASCADE, component TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY(pc_id,component));
        CREATE TABLE IF NOT EXISTS wallpapers(id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, filename TEXT NOT NULL, content_type TEXT NOT NULL, file_path TEXT NOT NULL, lockscreen_enabled INTEGER NOT NULL DEFAULT 1, desktop_enabled INTEGER NOT NULL DEFAULT 0, fit_mode TEXT NOT NULL DEFAULT 'fill', created_at REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS client_builds(id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL, filename TEXT NOT NULL, file_path TEXT NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, created_at REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS telegram_config(id INTEGER PRIMARY KEY CHECK(id=1), bot_token TEXT NOT NULL DEFAULT '', chat_id TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 0, coin_alerts INTEGER NOT NULL DEFAULT 1, daily_report INTEGER NOT NULL DEFAULT 1, report_time TEXT NOT NULL DEFAULT '23:59', timezone TEXT NOT NULL DEFAULT 'Asia/Manila', updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS telegram_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL, created_at REAL NOT NULL, last_error TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS v2_audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS workstation_commands(id INTEGER PRIMARY KEY AUTOINCREMENT, pc_id TEXT NOT NULL REFERENCES pcs(id) ON DELETE CASCADE, command TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at REAL NOT NULL, expires_at REAL NOT NULL, completed_at REAL, result TEXT NOT NULL DEFAULT '');
        ''')
        # Backward-compatible migration for existing PisoNet databases.
        cols = {r['name'] for r in db.execute('PRAGMA table_info(pcs)')}
        if 'device_uuid' not in cols: db.execute('ALTER TABLE pcs ADD COLUMN device_uuid TEXT')
        if 'archived' not in cols: db.execute('ALTER TABLE pcs ADD COLUMN archived INTEGER NOT NULL DEFAULT 0')
        if 'mac_address' not in cols: db.execute('ALTER TABLE pcs ADD COLUMN mac_address TEXT')
        if 'client_disabled' not in cols: db.execute('ALTER TABLE pcs ADD COLUMN client_disabled INTEGER NOT NULL DEFAULT 0')
        # Retire the old client disable switch so previously disabled PCs recover.
        db.execute('UPDATE pcs SET client_disabled=0 WHERE client_disabled<>0')
        if 'client_shutdown_reset_at' not in cols: db.execute('ALTER TABLE pcs ADD COLUMN client_shutdown_reset_at REAL NOT NULL DEFAULT 0')
        if 'client_shutdown_reset_until' not in cols: db.execute('ALTER TABLE pcs ADD COLUMN client_shutdown_reset_until REAL NOT NULL DEFAULT 0')
        if 'client_boot_id' not in cols: db.execute("ALTER TABLE pcs ADD COLUMN client_boot_id TEXT NOT NULL DEFAULT ''")
        if 'admin_locked' not in cols: db.execute('ALTER TABLE pcs ADD COLUMN admin_locked INTEGER NOT NULL DEFAULT 0')
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_pcs_device_uuid ON pcs(device_uuid) WHERE device_uuid IS NOT NULL')
        defaults = {100:180, 500:900, 1000:1800, 2000:3600}
        for denom, secs in defaults.items():
            db.execute('INSERT OR IGNORE INTO rate_rules VALUES (?,?)', (denom, secs))
        db.execute("INSERT OR IGNORE INTO settings VALUES ('schema_version','1')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('shutdown_countdown_minutes','5')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('insert_countdown_seconds','60')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('offline_session_timeout_minutes','5')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('maintenance_password_hash','')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('uninstall_password_hash','')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('shop_name','PisoNet')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('shop_subtext','PisoNet Internet Cafe')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('shop_name_font','system')")
        db.execute("INSERT OR IGNORE INTO settings VALUES ('shop_name_size','28')")
        default_policy = {'cmd': True, 'task_manager': True, 'registry_editor': True, 'windows_settings': True,
                          'control_panel': True, 'mmc': True, 'terminal': True, 'run_dialog': True,
                          'lock_directory': False, 'hide_app_directory': False, 'hidden_drives': [], 'service_management': True}
        db.execute('INSERT OR IGNORE INTO security_global(id,policy_json,updated_at) VALUES (1,?,?)',
                   (json.dumps(default_policy), time.time()))
        # Backfill the new Services Management policy without overwriting existing admin choices.
        current_policy_row = db.execute('SELECT policy_json FROM security_global WHERE id=1').fetchone()
        if current_policy_row:
            try:
                current_policy = json.loads(current_policy_row['policy_json'] or '{}')
                if 'service_management' not in current_policy:
                    current_policy['service_management'] = True
                    db.execute('UPDATE security_global SET policy_json=?,updated_at=? WHERE id=1',
                               (json.dumps(current_policy), time.time()))
            except Exception:
                pass
        db.execute("INSERT OR IGNORE INTO telegram_config(id,updated_at) VALUES (1,?)", (time.time(),))
        if not db.execute('SELECT 1 FROM admin_users LIMIT 1').fetchone():
            initial_password = secrets.token_urlsafe(12)
            salt = secrets.token_bytes(16)
            digest = hashlib.pbkdf2_hmac('sha256', initial_password.encode(), salt, 310000).hex()
            db.execute('INSERT INTO admin_users(username,password_salt,password_hash,must_change_password,created_at) VALUES (?,?,?,?,?)',
                       ('admin', salt.hex(), digest, 1, time.time()))
            try:
                (ROOT / 'admin.initial-credentials.txt').write_text(
                    'PisoNet V2 initial administrator login\nUsername: admin\nTemporary password: ' + initial_password +
                    '\nChange this password immediately after first login.\n', encoding='utf-8')
                os.chmod(ROOT / 'admin.initial-credentials.txt', 0o600)
            except OSError:
                pass


def get_admin_token():
    token_file = ROOT / 'admin.token'
    if token_file.exists():
        return token_file.read_text().strip()
    token = secrets.token_urlsafe(24)
    token_file.write_text(token + '\n')
    try: os.chmod(token_file, 0o600)
    except OSError: pass
    return token
ADMIN_TOKEN = get_admin_token()


def audit(db, actor, action, details):
    db.execute('INSERT INTO audit_logs(at,actor,action,details) VALUES (?,?,?,?)', (time.time(), actor, action, json.dumps(details, separators=(',', ':'))))

def spectate_state(pcid):
    return SPECTATE.setdefault(pcid, {'active':False,'approved':False,'control_requested':False,'control_enabled':False,'frame_base64':'','frame_at':0,'commands':[],'control_expires_at':0,'last_admin_at':0})

def send_wol(mac):
    raw=bytes.fromhex(str(mac).replace(':','').replace('-','').replace('.',''))
    if len(raw)!=6: raise ValueError('INVALID_MAC_ADDRESS')
    packet=b'\xff'*6+raw*16
    sent=[]
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        for port in (9,7):
            try: sock.sendto(packet,('255.255.255.255',port)); sent.append(port)
            except OSError: pass
    if not sent: raise OSError('WOL_BROADCAST_FAILED')
    return sent


def connection_log(db, pc_id, hostname, source_ip, event, outcome, details=''):
    db.execute('INSERT INTO connection_logs(at,pc_id,hostname,source_ip,event,outcome,details) VALUES (?,?,?,?,?,?,?)',
               (time.time(), pc_id, hostname or '', source_ip or '', event, outcome, str(details)[:1000]))


def write_coin_event(event, status, pc_id='', pc_name='', session_id='', transaction_id='', amount_centavos=0, pulse_count=0, details=''):
    """Append one durable, dashboard-readable coin lifecycle event per line."""
    from datetime import datetime
    at=time.time()
    record={'at':at,'time':datetime.fromtimestamp(at,resolve_timezone()).isoformat(timespec='seconds'),
            'pc_id':str(pc_id or ''),'pc_name':str(pc_name or pc_id or ''),'event':str(event),
            'status':str(status),'session_id':str(session_id or ''),'transaction_id':str(transaction_id or ''),
            'amount_centavos':int(amount_centavos or 0),'pulse_count':int(pulse_count or 0),'details':str(details or '')[:300]}
    try:
        COIN_EVENT_DIR.mkdir(parents=True,exist_ok=True)
        target=COIN_EVENT_DIR/('coin-events-'+datetime.fromtimestamp(at,resolve_timezone()).strftime('%Y%m%d')+'.txt')
        with COIN_EVENT_LOCK, target.open('a',encoding='utf-8') as log:
            log.write(json.dumps(record,ensure_ascii=False,separators=(',',':'))+'\n')
    except OSError as exc:
        print('Could not append coin event log: '+str(exc))
    return record


def recent_coin_events(limit=20):
    COIN_EVENT_DIR.mkdir(parents=True,exist_ok=True)
    files=sorted(COIN_EVENT_DIR.glob('coin-events-*.txt'),reverse=True)[:3]
    rows=[]
    with COIN_EVENT_LOCK:
        for path in files:
            try:
                for line in path.read_text(encoding='utf-8').splitlines():
                    try: rows.append(json.loads(line))
                    except (ValueError,TypeError): continue
            except OSError: continue
    rows.sort(key=lambda item:float(item.get('at',0)),reverse=True)
    return rows[:max(1,min(100,int(limit)))]


def session_view(row):
    now = time.time()
    return {"id":row['id'],"pc_id":row['pc_id'],"status":row['status'],"amount_centavos":row['amount_centavos'],"amount_pesos":row['amount_centavos']/100,"started_at":row['started_at'],"last_coin_at":row['last_coin_at'],"inactivity_deadline": (row['last_coin_at'] or row['started_at'])+INACTIVITY_SECONDS,"max_deadline":row['started_at']+MAX_INSERT_SECONDS}


def finalize(session_id, reason='done'):
    """Idempotent transaction commit. Persist transaction and credit in one DB transaction."""
    with LOCK, connect() as db:
        row = db.execute('SELECT * FROM coin_sessions WHERE id=?', (session_id,)).fetchone()
        if not row: raise ValueError('COIN_SESSION_NOT_FOUND')
        if row['status'] == 'finalized':
            tx = db.execute('SELECT * FROM transactions WHERE coin_session_id=?', (session_id,)).fetchone()
            return transaction_view(db, tx)
        if row['status'] != 'inserting': raise ValueError('COIN_SESSION_NOT_ACTIVE')
        if row['amount_centavos'] <= 0:
            db.execute("UPDATE coin_sessions SET status='cancelled', finalized_at=? WHERE id=?", (time.time(),session_id))
            audit(db,row['pc_id'],'coin_session_cancelled',{'session_id':session_id,'reason':reason})
            pc=db.execute('SELECT name FROM pcs WHERE id=?',(row['pc_id'],)).fetchone()
            write_coin_event('insertion_ended','no_coin' if reason!='user_cancelled' else 'cancelled',row['pc_id'],pc['name'] if pc else row['pc_id'],session_id,details=reason)
            return {'status':'cancelled','session_id':session_id}
        rates = {r['denomination_centavos']:r['seconds'] for r in db.execute('SELECT * FROM rate_rules')}
        total_seconds = 0
        for batch in db.execute('SELECT denomination_centavos, COUNT(*) n FROM coin_batches WHERE coin_session_id=? GROUP BY denomination_centavos',(session_id,)):
            if batch['denomination_centavos'] not in rates: raise ValueError('RATE_MISSING_FOR_COIN')
            total_seconds += rates[batch['denomination_centavos']] * batch['n']
        txid = str(uuid.uuid4()); now = time.time()
        db.execute('INSERT INTO transactions VALUES (?,?,?,?,?,?)',(txid,session_id,row['pc_id'],row['amount_centavos'],total_seconds,now))
        current = db.execute("SELECT * FROM active_sessions WHERE pc_id=? AND status='active' AND expires_at>? ORDER BY expires_at DESC LIMIT 1",(row['pc_id'],now)).fetchone()
        # Add-on purchases extend the latest active expiry; expired sessions restart from now.
        new_expiry = (current['expires_at'] if current else now) + total_seconds
        active_id = str(uuid.uuid4())
        db.execute('INSERT INTO active_sessions VALUES (?,?,?,?,?,?)',(active_id,txid,row['pc_id'],now,new_expiry,'active'))
        db.execute('UPDATE pcs SET client_shutdown_reset_at=0,client_shutdown_reset_until=0,admin_locked=0 WHERE id=?',(row['pc_id'],))
        db.execute("UPDATE coin_sessions SET status='finalized', finalized_at=?, transaction_id=? WHERE id=?",(now,txid,session_id))
        audit(db,row['pc_id'],'coin_transaction_finalized',{'session_id':session_id,'transaction_id':txid,'amount_centavos':row['amount_centavos'],'seconds':total_seconds,'reason':reason})
        pc=db.execute('SELECT name FROM pcs WHERE id=?',(row['pc_id'],)).fetchone()
        write_coin_event('credited','success',row['pc_id'],pc['name'] if pc else row['pc_id'],session_id,txid,row['amount_centavos'],details=f'{total_seconds} seconds credited')
        tx = db.execute('SELECT * FROM transactions WHERE id=?',(txid,)).fetchone()
        cfg=db.execute('SELECT enabled,coin_alerts,timezone FROM telegram_config WHERE id=1').fetchone()
        if cfg and cfg['enabled'] and cfg['coin_alerts']:
            pc=db.execute('SELECT name FROM pcs WHERE id=?',(row['pc_id'],)).fetchone()
            pc_name=pc['name'] if pc else row['pc_id']
            minutes,remainder=divmod(total_seconds,60)
            if remainder:
                credited=f"{minutes} minute{'s' if minutes!=1 else ''} {remainder} second{'s' if remainder!=1 else ''}" if minutes else f"{remainder} second{'s' if remainder!=1 else ''}"
            else:
                credited=f"{minutes} minute{'s' if minutes!=1 else ''}"
            from datetime import datetime
            credited_at=datetime.fromtimestamp(now,resolve_timezone(cfg['timezone'] or 'Asia/Manila')).strftime('%I:%M:%S %p').lstrip('0')
            message='🪙 PisoNet — Coin Credit\nPC: %s\nAmount: ₱%.2f\nTime credited: %s\nTime: %s\nTransaction: %s'%(pc_name,row['amount_centavos']/100,credited,credited_at,txid)
            enqueue_telegram(db,'coin-credit:'+txid,{'text':message})
        return transaction_view(db,tx)


def transaction_view(db, tx):
    if tx is None: return None
    active = db.execute('SELECT * FROM active_sessions WHERE transaction_id=?',(tx['id'],)).fetchone()
    pc = db.execute('SELECT name FROM pcs WHERE id=?',(tx['pc_id'],)).fetchone()
    remaining = max(0, int(active['expires_at']-time.time())) if active else 0
    return {'id':tx['id'],'pc_id':tx['pc_id'],'pc_name':pc['name'] if pc else tx['pc_id'],'amount_centavos':tx['amount_centavos'],'amount_pesos':tx['amount_centavos']/100,'purchased_seconds':tx['purchased_seconds'],'created_at':tx['created_at'],'remaining_seconds':remaining,'expires_at':active['expires_at'] if active else None}


def expire_offline_sessions(db, now, pc_id=None):
    setting=db.execute("SELECT value FROM settings WHERE key='offline_session_timeout_minutes'").fetchone()
    timeout_minutes=max(1,min(1440,int(setting['value']) if setting else 5))
    cutoff=now-timeout_minutes*60
    query="SELECT a.id,a.pc_id,a.expires_at,p.name,p.last_seen FROM active_sessions a JOIN pcs p ON p.id=a.pc_id WHERE a.status='active' AND a.expires_at>? AND (p.last_seen IS NULL OR p.last_seen<=? )"
    args=[now,cutoff]
    if pc_id is not None:
        query+=' AND a.pc_id=?'; args.append(pc_id)
    stale=db.execute(query,args).fetchall()
    for session in stale:
        offline_seconds=timeout_minutes*60 if session['last_seen'] is None else max(0,int(now-float(session['last_seen'])))
        remaining=max(0,int(float(session['expires_at'])-now))
        changed=db.execute("UPDATE active_sessions SET status='expired',expires_at=? WHERE id=? AND status='active'",(now,session['id'])).rowcount
        if not changed: continue
        details={'offline_seconds':offline_seconds,'timeout_minutes':timeout_minutes,'remaining_seconds_reset':remaining}
        audit(db,session['pc_id'],'session_expired_after_offline',details)
        connection_log(db,session['pc_id'],session['name'],'','OFFLINE_SESSION_RESET','EXPIRED',f"Session reset after {offline_seconds} seconds offline; {remaining} remaining seconds cleared")


def timer_loop():
    while True:
        now=time.time()
        with LOCK, connect() as db:
            db.execute("UPDATE active_sessions SET status='expired' WHERE status='active' AND expires_at<=?",(now,))
            expire_offline_sessions(db,now)
            # Recover insertion sessions after restart; preserve collected batches and finalize once deadline reached.
            due = [r['id'] for r in db.execute("SELECT id, started_at, last_coin_at FROM coin_sessions WHERE status='inserting'") if now >= min((r['last_coin_at'] or r['started_at'])+INACTIVITY_SECONDS, r['started_at']+MAX_INSERT_SECONDS)]
        for sid in due:
            try:
                finalize(sid,'timeout')
                if COIN_ENGINE.session_id == sid: COIN_ENGINE.release(sid)
            except Exception: pass
        time.sleep(1)


def pc_by_token(db, token):
    return db.execute('SELECT * FROM pcs WHERE token=?',(token,)).fetchone()


# Server-side decoded coin callback. Workstations can submit only simulated
# signal edges; they cannot submit denomination values.
def record_decoded_coin(session_id, denomination_centavos, pulse_count):
    with LOCK, connect() as db:
        row=db.execute("SELECT * FROM coin_sessions WHERE id=? AND status='inserting'",(session_id,)).fetchone()
        if row is None: raise SignalError("COIN_SESSION_NOT_ACTIVE")
        now=time.time()
        if now >= row['started_at']+MAX_INSERT_SECONDS: raise SignalError("MAX_INSERT_TIME_REACHED")
        if not db.execute("SELECT 1 FROM rate_rules WHERE denomination_centavos=?",(denomination_centavos,)).fetchone():
            raise SignalError("UNSUPPORTED_DENOMINATION")
        cur=db.execute("INSERT INTO coin_batches(coin_session_id,denomination_centavos,received_at) VALUES (?,?,?)",(session_id,denomination_centavos,now))
        db.execute("UPDATE coin_sessions SET amount_centavos=amount_centavos+?,last_coin_at=? WHERE id=?",(denomination_centavos,now,session_id))
        audit(db,row['pc_id'],'coin_pulse_decoded',{'session_id':session_id,'denomination_centavos':denomination_centavos,'pulse_count':pulse_count})
        pc=db.execute('SELECT name FROM pcs WHERE id=?',(row['pc_id'],)).fetchone()
        write_coin_event('pulse_detected','success',row['pc_id'],pc['name'] if pc else row['pc_id'],session_id,amount_centavos=denomination_centavos,pulse_count=pulse_count)

PULSE_WIDTH_MS=int(os.environ.get('PISONET_PULSE_WIDTH_MS','50'))
COIN_ENGINE=CoinSignalEngine(record_decoded_coin,DecoderConfig(expected_pulse_width_ms=PULSE_WIDTH_MS))
COIN_HARDWARE=SerialCoinAdapter(COIN_ENGINE)

def discovery_loop():
    """LAN UDP discovery responder. Clients broadcast PISONET_DISCOVER_V1 to UDP 3211."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 3211))
        while True:
            try:
                payload, addr = sock.recvfrom(512)
                if payload.strip() == b'PISONET_DISCOVER_V1':
                    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        probe.connect((addr[0], addr[1])); server_ip = probe.getsockname()[0]
                    finally: probe.close()
                    response = json.dumps({'service':'PisoNet','host':server_ip, 'port':PORT, 'url':f'http://{server_ip}:{PORT}'}).encode()
                    sock.sendto(response, addr)
            except OSError:
                time.sleep(.2)
    finally:
        sock.close()


WALLPAPER_DIR = ROOT / 'wallpapers'
WALLPAPER_DIR.mkdir(exist_ok=True)
INSERT_SOUND_DIR = ROOT / 'insert_sounds'
INSERT_SOUND_DIR.mkdir(exist_ok=True)
CLIENT_BUILD_DIR = ROOT / 'client_builds'
CLIENT_BUILD_DIR.mkdir(exist_ok=True)
TELEGRAM_LOCK = threading.Lock()

def enqueue_telegram(db, event_key, payload):
    db.execute('INSERT OR IGNORE INTO telegram_outbox(event_key,payload,status,attempts,next_attempt_at,created_at) VALUES (?,?,\'pending\',0,?,?)',
               (event_key, json.dumps(payload, ensure_ascii=False), time.time(), time.time()))

def zerotier_cli(*args):
    """Run the installed ZeroTier CLI against the local service only."""
    candidates=[]
    configured=os.environ.get('PISONET_ZEROTIER_CLI','').strip().replace('\\"','"')
    if len(configured)>=2 and configured[0]==configured[-1] and configured[0] in ('"',"'"):
        configured=configured[1:-1].strip()
    if configured:
        configured_path=Path(configured)
        if configured_path.is_dir():
            candidates.extend(str(configured_path/name) for name in ('zerotier-cli.bat','zerotier-cli.exe','zerotier-cli'))
        else: candidates.append(configured)
    for name in ('zerotier-cli','zerotier-cli.bat','zerotier-cli.exe'):
        found=shutil.which(name)
        if found: candidates.append(found)
    if os.name=='nt':
        install_dirs=[]
        for base in (os.environ.get('ProgramFiles(x86)'),os.environ.get('ProgramFiles'),os.environ.get('ProgramW6432')):
            if base:
                install_dirs.append(Path(base)/'ZeroTier'/'One')
        # Services may run with a trimmed PATH or nonstandard install folder.
        # Read the service executable and installer registry paths as fallbacks.
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Services\ZeroTierOneService') as key:
                image,_=winreg.QueryValueEx(key,'ImagePath')
                import re
                match=re.match(r'\s*"?(.+?\.exe)',str(image),re.IGNORECASE)
                if match: install_dirs.append(Path(match.group(1)).parent)
            for hive in (winreg.HKEY_LOCAL_MACHINE,winreg.HKEY_CURRENT_USER):
                for root in (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'):
                    try:
                        with winreg.OpenKey(hive,root) as key:
                            for i in range(winreg.QueryInfoKey(key)[0]):
                                try:
                                    sub=winreg.EnumKey(key,i)
                                    with winreg.OpenKey(key,sub) as entry:
                                        display=str(winreg.QueryValueEx(entry,'DisplayName')[0])
                                        if 'zerotier' not in display.lower(): continue
                                        location=winreg.QueryValueEx(entry,'InstallLocation')[0]
                                        if location: install_dirs.append(Path(str(location)))
                                except OSError: continue
                    except OSError: continue
        except (ImportError,OSError): pass
        seen=set()
        for folder in install_dirs:
            key=str(folder).casefold()
            if key in seen: continue
            seen.add(key)
            candidates.extend(str(folder/name) for name in ('zerotier-cli.bat','zerotier-cli.exe','zerotier-cli'))
    cli=next((p for p in candidates if Path(p).is_file()),None)
    if not cli:
        raise RuntimeError('ZeroTier CLI was not found in PATH, the ZeroTier service install folder, or the standard install folders. Set PISONET_ZEROTIER_CLI to the full path of zerotier-cli.bat if it is installed elsewhere.')
    if os.name=='nt' and Path(cli).suffix.lower() in ('.bat','.cmd'):
        # Run batch files through PowerShell's call operator. cmd.exe's /s /c
        # quoting rules corrupt quoted paths with spaces in some service launches.
        ps_quote=lambda value:"'"+str(value).replace("'","''")+"'"
        script='& '+ps_quote(cli)+' '+' '.join(ps_quote(arg) for arg in args)
        script+='; if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }'
        encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
        command=[shutil.which('powershell.exe') or 'powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',encoded]
    else:
        command=[cli,*args]
    result=subprocess.run(command,capture_output=True,text=True,timeout=8,check=False)
    output=(result.stdout or result.stderr or '').strip()
    if result.returncode:
        raise RuntimeError(output[-500:] or 'ZeroTier CLI failed with exit code '+str(result.returncode))
    return output

def zerotier_status():
    """Return local node and membership state without contacting ZeroTier Central."""
    info=json.loads(zerotier_cli('-j','info'))
    networks=json.loads(zerotier_cli('-j','listnetworks'))
    if not isinstance(networks,list): networks=[]
    return {
        'service_online':True,
        'node_online':bool(info.get('online')),
        'node_id':str(info.get('address','')),
        'version':str(info.get('version','')),
        'networks':[{
            'network_id':str(n.get('nwid') or n.get('id') or ''),
            'name':str(n.get('name') or n.get('nwid') or n.get('id') or 'ZeroTier network'),
            'status':str(n.get('status') or 'UNKNOWN'),
            'type':str(n.get('type') or ''),
            'assigned_addresses':n.get('assignedAddresses') if isinstance(n.get('assignedAddresses'),list) else [],
        } for n in networks],
        'checked_at':time.time(),
    }

def telegram_send(token, chat_id, message):
    import ssl, urllib.request
    body=json.dumps({'chat_id':chat_id,'text':message,'disable_web_page_preview':True}).encode()
    req=urllib.request.Request('https://api.telegram.org/bot'+token+'/sendMessage',data=body,headers={'Content-Type':'application/json'},method='POST')
    # Keep TLS verification enabled. On Windows, explicitly load the native
    # ROOT and CA certificate stores: Python's bundled OpenSSL CA file may not
    # contain certificates trusted by Windows/curl on the same machine.
    if os.name == 'nt' and hasattr(ssl, 'enum_certificates'):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode=ssl.CERT_REQUIRED
        context.check_hostname=True
        windows_certs=[]
        for store in ('ROOT','CA'):
            for cert, encoding, _trust in ssl.enum_certificates(store):
                if encoding == 'x509_asn':
                    windows_certs.append(ssl.DER_cert_to_PEM_cert(cert))
        if windows_certs:
            context.load_verify_locations(cadata=''.join(windows_certs))
    else:
        context=ssl.create_default_context()
    ca_bundle=os.environ.get('PISONET_TLS_CA_BUNDLE','').strip()
    if ca_bundle:
        context.load_verify_locations(cafile=ca_bundle)
    with urllib.request.urlopen(req,timeout=12,context=context) as resp:
        result=json.loads(resp.read().decode())
    if not result.get('ok'): raise RuntimeError('Telegram API rejected the message')
    return result


def telegram_send_document(token, chat_id, path, caption=''):
    import ssl, urllib.request, uuid as uuid_module
    path=Path(path).resolve()
    boundary='----PisoNet'+uuid_module.uuid4().hex
    chunks=[]
    def field(name,value):
        chunks.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n').encode())
    field('chat_id',chat_id)
    if caption: field('caption',caption)
    chunks.append((f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{path.name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode())
    chunks.append(path.read_bytes()); chunks.append(f'\r\n--{boundary}--\r\n'.encode())
    req=urllib.request.Request('https://api.telegram.org/bot'+token+'/sendDocument',data=b''.join(chunks),headers={'Content-Type':'multipart/form-data; boundary='+boundary},method='POST')
    if os.name=='nt' and hasattr(ssl,'enum_certificates'):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.verify_mode=ssl.CERT_REQUIRED;context.check_hostname=True
        certs=[]
        for store in ('ROOT','CA'):
            for cert,encoding,_trust in ssl.enum_certificates(store):
                if encoding=='x509_asn': certs.append(ssl.DER_cert_to_PEM_cert(cert))
        if certs: context.load_verify_locations(cadata=''.join(certs))
    else: context=ssl.create_default_context()
    ca_bundle=os.environ.get('PISONET_TLS_CA_BUNDLE','').strip()
    if ca_bundle: context.load_verify_locations(cafile=ca_bundle)
    with urllib.request.urlopen(req,timeout=60,context=context) as resp: result=json.loads(resp.read().decode())
    if not result.get('ok'): raise RuntimeError('Telegram API rejected the document')
    return result

def daily_sales_text(db, day, timezone='Asia/Manila'):
    from datetime import datetime, date, time as dt_time, timedelta
    zone=resolve_timezone(timezone or 'Asia/Manila')
    local_day=date.fromisoformat(day)
    start=datetime.combine(local_day,dt_time.min,tzinfo=zone).timestamp()
    end=datetime.combine(local_day+timedelta(days=1),dt_time.min,tzinfo=zone).timestamp()
    rows=list(db.execute('SELECT p.name,COUNT(*) n,SUM(t.amount_centavos) total FROM transactions t JOIN pcs p ON p.id=t.pc_id WHERE t.created_at>=? AND t.created_at<? GROUP BY p.id ORDER BY p.name',(start,end)))
    total=sum(int(r['total'] or 0) for r in rows); count=sum(int(r['n']) for r in rows)
    lines=['PisoNet daily sales — '+day,'Transactions: '+str(count),'Total sales: ₱%.2f'%(total/100),'Per workstation:']
    lines += ['• %s: %d txn(s), ₱%.2f'%(r['name'],r['n'],(r['total'] or 0)/100) for r in rows] or ['• No sales recorded']
    return '\n'.join(lines)

def telegram_process_once():
    """Queue the local-day report if due and deliver at most one durable outbox item."""
    with TELEGRAM_LOCK, connect() as db:
        cfg=db.execute('SELECT * FROM telegram_config WHERE id=1').fetchone()
        if not cfg or not cfg['bot_token'] or not cfg['chat_id']:
            return 'disabled'
        enabled=bool(cfg['enabled'])
        if enabled:
            try:
                from datetime import datetime
                local=datetime.now(resolve_timezone(cfg['timezone'] or 'Asia/Manila'))
                day=local.strftime('%Y-%m-%d')
                if cfg['daily_report'] and local.strftime('%H:%M') >= str(cfg['report_time']):
                    enqueue_telegram(db,'daily-report:'+day,{'text':daily_sales_text(db,day,cfg['timezone'])})
                    backup_dir=ROOT/'backups';backup_dir.mkdir(parents=True,exist_ok=True)
                    backup_path=backup_dir/f'pisonet-database-{day}.sqlite3'
                    if not backup_path.exists():
                        with sqlite3.connect(DB_PATH,timeout=30) as source, sqlite3.connect(backup_path) as destination:
                            source.backup(destination)
                    enqueue_telegram(db,'daily-db-backup:'+day,{'document_path':str(backup_path),'caption':'PisoNet database backup — '+day})
            except Exception as e:
                db.execute("INSERT INTO v2_audit_logs(at,actor,action,details) VALUES (?,?,?,?)",(time.time(),'system','telegram_schedule_error',str(e)[:500]))
        if enabled:
            item=db.execute("SELECT * FROM telegram_outbox WHERE status IN ('pending','retry') AND next_attempt_at<=? ORDER BY id LIMIT 1",(time.time(),)).fetchone()
        else:
            # A manually requested Test message is explicit and may be delivered
            # even while routine coin alerts and daily reports are switched off.
            item=db.execute("SELECT * FROM telegram_outbox WHERE event_key LIKE 'test:%' AND status IN ('pending','retry') AND next_attempt_at<=? ORDER BY id LIMIT 1",(time.time(),)).fetchone()
        if not item:
            return 'idle' if enabled else 'disabled'
        try:
            payload=json.loads(item['payload'])
            document=payload.get('document_path')
            if document:
                backup_dir=(ROOT/'backups').resolve(); document_path=Path(document).resolve()
                if document_path.parent!=backup_dir or not document_path.is_file(): raise RuntimeError('DATABASE_BACKUP_FILE_MISSING_OR_INVALID')
                telegram_send_document(cfg['bot_token'],cfg['chat_id'],document_path,payload.get('caption',''))
            else: telegram_send(cfg['bot_token'],cfg['chat_id'],payload['text'])
            db.execute("UPDATE telegram_outbox SET status='sent',attempts=attempts+1,last_error='' WHERE id=?",(item['id'],))
            return 'sent'
        except Exception as e:
            attempts=int(item['attempts'])+1
            delay=min(3600,5*(2**min(attempts,9)))
            error=str(e)
            try:
                import ssl
                if isinstance(e,ssl.SSLCertVerificationError):
                    error+='; configure PISONET_TLS_CA_BUNDLE with the PEM file for your trusted network root CA'
            except Exception: pass
            db.execute("UPDATE telegram_outbox SET status='retry',attempts=?,next_attempt_at=?,last_error=? WHERE id=?",(attempts,time.time()+delay,error[:500],item['id']))
            return 'retry'


def telegram_worker():
    """Background sender with durable retry queue and timezone-aware daily reports."""
    while True:
        try: telegram_process_once()
        except Exception as e: print('Telegram worker warning:',str(e),flush=True)
        time.sleep(3)

class Handler(BaseHTTPRequestHandler):
    server_version=f'PisoNetV2-PHASE3/{SERVER_BUILD}'
    def log_message(self, fmt, *args): print('%s - %s' % (self.address_string(),fmt%args))
    def send_json(self, code, data):
        body=json.dumps(data,ensure_ascii=False).encode('utf-8'); self.send_response(code)
        self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Referrer-Policy','no-referrer')
        origin=self.headers.get('Origin','')
        allowed={'tauri://localhost','http://tauri.localhost','https://tauri.localhost','http://localhost:'+str(PORT),'http://127.0.0.1:'+str(PORT)}
        if origin in allowed:
            self.send_header('Access-Control-Allow-Origin',origin); self.send_header('Vary','Origin')
        self.send_header('Access-Control-Allow-Headers','Content-Type, Authorization, X-Admin-Token'); self.send_header('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS')
        self.end_headers(); self.wfile.write(body)
    def body(self):
        try: n=int(self.headers.get('Content-Length','0'))
        except ValueError: raise ValueError('INVALID_CONTENT_LENGTH')
        if n<0 or n>12*1024*1024: raise ValueError('REQUEST_TOO_LARGE')
        return json.loads(self.rfile.read(n) or b'{}')
    def admin(self):
        if os.environ.get('PISONET_ALLOW_LEGACY_ADMIN_TOKEN','0') == '1' and secrets.compare_digest(self.headers.get('X-Admin-Token',''), ADMIN_TOKEN):
            return True
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return False
        token_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
        with connect() as db:
            row = db.execute('SELECT 1 FROM admin_sessions WHERE token_hash=? AND expires_at>?', (token_hash, time.time())).fetchone()
        return bool(row)
    def client(self, db):
        h=self.headers.get('Authorization','')
        if not h.startswith('Bearer '): return None
        return pc_by_token(db,h[7:])
    def do_OPTIONS(self): self.send_json(200,{'ok':True})
    def do_GET(self):
        path=urlparse(self.path).path
        if path=='/api/v2/spectate/frame':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            pcid=parse_qs(urlparse(self.path).query).get('pc_id',[''])[0]
            state=SPECTATE.get(pcid,{})
            now=time.time()
            if state.get('active') and now-float(state.get('last_admin_at',0))>15:
                state.update({'active':False,'approved':False,'control_requested':False,'control_enabled':False,'commands':[]})
            elif state.get('active'):
                state['last_admin_at']=now
            return self.send_json(200,{'active':bool(state.get('active')),'approved':bool(state.get('approved')),'control_requested':bool(state.get('control_requested')),'control_enabled':bool(state.get('control_enabled') and state.get('control_expires_at',0)>now),'frame_base64':state.get('frame_base64',''),'frame_at':state.get('frame_at',0)})
        if path=='/api/v2/coin-events':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            limit=parse_qs(urlparse(self.path).query).get('limit',['20'])[0]
            try: events=recent_coin_events(int(limit))
            except ValueError: return self.send_json(400,{'error':'INVALID_LIMIT'})
            return self.send_json(200,{'events':events})
        if path=='/api/v2/server-update':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            try:
                manifest,_raw=fetch_server_release_manifest()
                return self.send_json(200,{**server_release_status(manifest),'last_install':read_server_update_status()})
            except Exception as exc:
                return self.send_json(502,{'error':'GITHUB_RELEASE_CHECK_FAILED','detail':str(exc)[:300],'current_build':SERVER_BUILD,'repository':SERVER_GITHUB_REPOSITORY,'branch':SERVER_GITHUB_BRANCH})
        if path=='/api/v2/server-update/status':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            return self.send_json(200,{'current_build':SERVER_BUILD,'last_install':read_server_update_status()})
        if path == '/' or path == '/admin':
            # V2 dashboard filename; fall back to the legacy filename for compatibility.
            admin_v2 = ROOT / 'web' / 'admin_v2.html'
            admin_legacy = ROOT / 'web' / 'admin.html'
            if admin_v2.is_file():
                return self.serve_file(admin_v2)
            return self.serve_file(admin_legacy)
        if path=='/client': return self.serve_file(ROOT/'web'/'client.html')
        if path.startswith('/api/wallpapers/'):
            with connect() as db:
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                wid=path.rsplit('/',1)[-1]
                row=db.execute('SELECT * FROM wallpapers WHERE id=? AND active=1',(wid,)).fetchone()
                if not row: return self.send_json(404,{'error':'WALLPAPER_NOT_FOUND'})
                try: payload=Path(row['file_path']).read_bytes()
                except OSError: return self.send_json(404,{'error':'WALLPAPER_FILE_MISSING'})
                self.send_response(200); self.send_header('Content-Type',row['content_type']); self.send_header('Content-Length',str(len(payload))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(payload); return
        if path == '/api/client/insert-sound':
            with connect() as db:
                if not self.client(db): return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                values={r['key']:r['value'] for r in db.execute("SELECT key,value FROM settings WHERE key IN ('insert_sound_id','insert_sound_filename','insert_sound_content_type','insert_sound_file_path')")}
                sound_id=values.get('insert_sound_id','')
                if not sound_id: return self.send_json(404,{'error':'INSERT_SOUND_NOT_CONFIGURED'})
                sound_path=Path(values.get('insert_sound_file_path',''))
                if sound_path.resolve().parent!=INSERT_SOUND_DIR.resolve(): return self.send_json(404,{'error':'INSERT_SOUND_FILE_MISSING'})
                try: payload=sound_path.read_bytes()
                except OSError: return self.send_json(404,{'error':'INSERT_SOUND_FILE_MISSING'})
                return self.send_json(200,{'id':sound_id,'filename':values.get('insert_sound_filename',''),'content_type':values.get('insert_sound_content_type','audio/mpeg'),'data_base64':base64.b64encode(payload).decode('ascii')})
        if path == '/api/client/updates/latest':
            with connect() as db:
                pc=self.client(db)
                if not pc: return self.send_json(401, {'error':'CLIENT_AUTH_REQUIRED'})
                query=parse_qs(urlparse(self.path).query)
                requested_type=(query.get('package_type',[''])[0] or '').lower()
                if requested_type=='client':
                    # Automatic startup updates must compare like-for-like with
                    # the client executable. Keep using the latest client-only
                    # build even when a newer full setup was uploaded later.
                    row=db.execute("SELECT id,version,filename,sha256,size_bytes FROM client_builds WHERE lower(filename) NOT LIKE 'pisonet-setup-%' ORDER BY id DESC LIMIT 1").fetchone()
                else:
                    row=db.execute('SELECT id,version,filename,sha256,size_bytes FROM client_builds WHERE active=1 ORDER BY id DESC LIMIT 1').fetchone()
                if row:
                    package_type='setup' if str(row['filename']).lower().startswith('pisonet-setup-') else 'client'
                    download='/api/client/updates/'+str(row['id'])+'/download'+('?package_type=client' if requested_type=='client' else '')
                    update={**dict(row),'package_type':package_type,'url':download}
                else:
                    update=None
                return self.send_json(200, {'update':update})
        if path.startswith('/api/client/updates/') and path.endswith('/download'):
            with connect() as db:
                pc=self.client(db)
                if not pc: return self.send_json(401, {'error':'CLIENT_AUTH_REQUIRED'})
                build_id=path.split('/')[-2]
                query=parse_qs(urlparse(self.path).query)
                if (query.get('package_type',[''])[0] or '').lower()=='client':
                    row=db.execute("SELECT filename,file_path FROM client_builds WHERE id=? AND id=(SELECT id FROM client_builds WHERE lower(filename) NOT LIKE 'pisonet-setup-%' ORDER BY id DESC LIMIT 1)",(build_id,)).fetchone()
                else:
                    row=db.execute('SELECT filename,file_path FROM client_builds WHERE id=? AND active=1',(build_id,)).fetchone()
                if not row: return self.send_json(404,{'error':'CLIENT_BUILD_NOT_FOUND'})
                try: payload=Path(row['file_path']).read_bytes()
                except OSError: return self.send_json(404,{'error':'CLIENT_BUILD_FILE_MISSING'})
                self.send_response(200); self.send_header('Content-Type','application/vnd.microsoft.portable-executable'); self.send_header('Content-Length',str(len(payload))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(payload); return
        if path=='/api/health': return self.send_json(200,{'ok':True,'service':'PisoNet','version':SERVER_VERSION,'build':SERVER_BUILD,'coin_engine':COIN_ENGINE.status(),'coin_hardware':COIN_HARDWARE.status()})
        with connect() as db:
            if path == '/api/settings':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_AUTH_REQUIRED'})
                values={r['key']:r['value'] for r in db.execute("SELECT key,value FROM settings WHERE key IN ('shutdown_countdown_minutes','insert_countdown_seconds','offline_session_timeout_minutes','maintenance_password_hash','uninstall_password_hash','shop_name','shop_subtext','shop_name_font','shop_name_size','insert_sound_id','insert_sound_filename')")}
                sound={'id':values['insert_sound_id'],'filename':values.get('insert_sound_filename','')} if values.get('insert_sound_id') else None
                return self.send_json(200,{'shutdown_countdown_minutes':int(values.get('shutdown_countdown_minutes','5')),'insert_countdown_seconds':int(values.get('insert_countdown_seconds','60')),'offline_session_timeout_minutes':int(values.get('offline_session_timeout_minutes','5')),'maintenance_password_configured':bool(values.get('maintenance_password_hash','')),'uninstall_password_configured':bool(values.get('uninstall_password_hash','')),'shop_name':values.get('shop_name',''),'shop_subtext':values.get('shop_subtext',''),'shop_name_font':values.get('shop_name_font','system'),'shop_name_size':int(values.get('shop_name_size','28')),'insert_sound':sound})
            if path == '/api/v2/admin/me':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                auth = self.headers.get('Authorization','')
                username = 'admin'
                if auth.startswith('Bearer '):
                    th = hashlib.sha256(auth[7:].encode()).hexdigest()
                    row = db.execute('SELECT username FROM admin_sessions WHERE token_hash=? AND expires_at>?',(th,time.time())).fetchone()
                    if row: username = row['username']
                u = db.execute('SELECT must_change_password FROM admin_users WHERE username=?',(username,)).fetchone()
                return self.send_json(200, {'ok':True,'username':username,'must_change_password':bool(u['must_change_password']) if u else False})
            if path == '/api/v2/dashboard/stats':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                today=time.localtime(); start=time.mktime((today.tm_year,today.tm_mon,today.tm_mday,0,0,0,0,0,-1))
                total=db.execute('SELECT COUNT(*) n FROM pcs WHERE archived=0').fetchone()['n']
                online=db.execute('SELECT COUNT(*) n FROM pcs WHERE archived=0 AND last_seen>?',(time.time()-15,)).fetchone()['n']
                sales=db.execute('SELECT COALESCE(SUM(amount_centavos),0) n FROM transactions WHERE created_at>=?',(start,)).fetchone()['n']
                active=db.execute("SELECT COUNT(*) n FROM active_sessions WHERE status='active' AND expires_at>?",(time.time(),)).fetchone()['n']
                recent=[dict(r) for r in db.execute('SELECT l.at,l.pc_id,COALESCE(p.name,l.hostname) AS pc_name,l.hostname,l.event,l.outcome,l.details FROM connection_logs l LEFT JOIN pcs p ON p.id=l.pc_id ORDER BY l.at DESC LIMIT 6')]
                denom=[dict(r) for r in db.execute('SELECT b.denomination_centavos,COUNT(*) AS coin_count,COALESCE(SUM(b.denomination_centavos),0) AS total_centavos FROM coin_batches b JOIN coin_sessions c ON c.id=b.coin_session_id JOIN transactions t ON t.coin_session_id=c.id WHERE t.created_at>=? GROUP BY b.denomination_centavos ORDER BY b.denomination_centavos',(start,))]
                return self.send_json(200,{'workstations':total,'online':online,'sales_centavos':sales,'active_sessions':active,'recent_activity':recent,'today_by_denomination':denom})
            if path == '/api/v2/workstations/commands':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
                raw_ids=parse_qs(urlparse(self.path).query).get('ids',[''])[0]
                try: command_ids=list(dict.fromkeys(int(value) for value in raw_ids.split(',') if value.strip()))
                except ValueError: return self.send_json(400,{'error':'INVALID_COMMAND_IDS'})
                if not command_ids or len(command_ids)>100: return self.send_json(400,{'error':'COMMAND_IDS_REQUIRED'})
                marks=','.join('?' for _ in command_ids); now=time.time()
                rows=db.execute(f'SELECT id,pc_id,command,status,result,expires_at FROM workstation_commands WHERE id IN ({marks})',command_ids).fetchall()
                statuses=[]
                for row in rows:
                    status=row['status']
                    if status=='pending' and float(row['expires_at'])<=now: status='expired'
                    statuses.append({'id':row['id'],'pc_id':row['pc_id'],'command':row['command'],'status':status,'result':row['result']})
                return self.send_json(200,{'commands':statuses})
            if path == '/api/v2/admin/users':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                return self.send_json(200, {'users':[{'username':r['username'],'must_change_password':bool(r['must_change_password']),'created_at':r['created_at']} for r in db.execute('SELECT username,must_change_password,created_at FROM admin_users ORDER BY username')]})
            if path == '/api/v2/wallpapers':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                return self.send_json(200, {'wallpapers':[dict(r) for r in db.execute('SELECT id,scope,filename,content_type,lockscreen_enabled,desktop_enabled,fit_mode,created_at,active FROM wallpapers ORDER BY id DESC')]})
            if path == '/api/v2/client-builds':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                rows=[dict(r)|{'package_type':'setup' if str(r['filename']).lower().startswith('pisonet-setup-') else 'client'} for r in db.execute('SELECT id,version,filename,sha256,size_bytes,created_at,active FROM client_builds ORDER BY id DESC')]
                return self.send_json(200,{'builds':rows})
            if path == '/api/v2/zerotier/status':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
                try: return self.send_json(200,zerotier_status())
                except Exception as exc: return self.send_json(200,{'service_online':False,'node_online':False,'node_id':'','version':'','networks':[],'checked_at':time.time(),'error':str(exc)[:300]})
            if path.startswith('/api/v2/client-builds/') and path.endswith('/download'):
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                build_id=path.split('/')[-2]
                row=db.execute('SELECT filename,file_path FROM client_builds WHERE id=?',(build_id,)).fetchone()
                if not row: return self.send_json(404,{'error':'CLIENT_BUILD_NOT_FOUND'})
                try: payload=Path(row['file_path']).read_bytes()
                except OSError: return self.send_json(404,{'error':'CLIENT_BUILD_FILE_MISSING'})
                safe_name=Path(row['filename']).name.replace('"','')
                self.send_response(200); self.send_header('Content-Type','application/vnd.microsoft.portable-executable'); self.send_header('Content-Length',str(len(payload))); self.send_header('Content-Disposition','attachment; filename="'+safe_name+'"'); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(payload); return
            if path == '/api/v2/security':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                glob = db.execute('SELECT policy_json,updated_at FROM security_global WHERE id=1').fetchone()
                overrides = {r['pc_id']:json.loads(r['policy_json']) for r in db.execute('SELECT pc_id,policy_json FROM security_pc_overrides')}
                workstations=[dict(r) for r in db.execute('SELECT p.id,p.name,p.last_seen,h.at AS health_at,h.guard_state,m.enabled AS maintenance FROM pcs p LEFT JOIN client_health h ON h.pc_id=p.id LEFT JOIN maintenance_sessions m ON m.pc_id=p.id WHERE p.archived=0 ORDER BY p.name')]
                return self.send_json(200, {'global':json.loads(glob['policy_json']) if glob else {},'updated_at':glob['updated_at'] if glob else None,'overrides':overrides,'workstations':workstations,'offline_behavior':'retain','maintenance_behavior':'lift_all'})
            if path == '/api/v2/telegram/outbox':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                rows=[dict(r) for r in db.execute('SELECT id,event_key,status,attempts,next_attempt_at,created_at,last_error FROM telegram_outbox ORDER BY id DESC LIMIT 100')]
                return self.send_json(200,{'items':rows})
            if path == '/api/v2/telegram':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                t = db.execute('SELECT enabled,coin_alerts,daily_report,report_time,timezone,chat_id,CASE WHEN bot_token!="" THEN 1 ELSE 0 END AS token_configured,updated_at FROM telegram_config WHERE id=1').fetchone()
                return self.send_json(200, dict(t) if t else {})
            if path == '/api/v2/reports/sales':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                q = parse_qs(urlparse(self.path).query)
                start = q.get('from',['1970-01-01'])[0]; end = q.get('to',['2999-12-31'])[0]
                pcid = q.get('pc_id',['all'])[0]
                denomination = q.get('denomination',['all'])[0]
                try:
                    start_ts = time.mktime(time.strptime(start,'%Y-%m-%d'))
                    end_ts = time.mktime(time.strptime(end,'%Y-%m-%d')) + 86400
                except Exception: return self.send_json(400, {'error':'INVALID_DATE_RANGE'})
                where = 't.created_at>=? AND t.created_at<?'; args = [start_ts,end_ts]
                if pcid != 'all': where += ' AND t.pc_id=?'; args.append(pcid)
                rows = [dict(r) for r in db.execute('SELECT t.id,t.pc_id,p.name AS pc_name,t.amount_centavos,t.purchased_seconds,t.created_at FROM transactions t JOIN pcs p ON p.id=t.pc_id WHERE '+where+' ORDER BY t.created_at DESC',args)]
                selected_denom=int(denomination)*100 if denomination.isdigit() else 0
                filtered=[]
                for r in rows:
                    counts={str(b['denomination_centavos']//100):int(b['n']) for b in db.execute('SELECT denomination_centavos,COUNT(*) n FROM coin_batches WHERE coin_session_id=(SELECT coin_session_id FROM transactions WHERE id=?) GROUP BY denomination_centavos',(r['id'],))}
                    r['coin_counts']=counts
                    if selected_denom:
                        count=counts.get(str(selected_denom//100),0)
                        if not count: continue
                        r['amount_centavos']=selected_denom*count
                    filtered.append(r)
                rows=filtered
                total = sum(r['amount_centavos'] for r in rows)
                by_pc = {}
                for r in rows:
                    item = by_pc.setdefault(r['pc_id'], {'pc_id':r['pc_id'],'pc_name':r['pc_name'],'transactions':0,'sales_centavos':0,'coin_counts':{}})
                    item['transactions'] += 1; item['sales_centavos'] += r['amount_centavos']
                    for denom,count in r['coin_counts'].items(): item['coin_counts'][denom]=item['coin_counts'].get(denom,0)+count
                return self.send_json(200, {'from':start,'to':end,'total_centavos':total,'transaction_count':len(rows),'average_centavos':round(total/len(rows)) if rows else 0,'by_pc':list(by_pc.values()),'transactions':rows})
            if path=='/api/connection-logs':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
                rows=[]
                for r in db.execute('SELECT l.*, COALESCE(p.name,l.hostname) AS pc_name FROM connection_logs l LEFT JOIN pcs p ON p.id=l.pc_id ORDER BY l.at DESC LIMIT 200'):
                    item=dict(r); item['time']=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(item['at'])); rows.append(item)
                return self.send_json(200,{'logs':rows})
            if path=='/api/pcs':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
                pcs=[]
                now=time.time()
                for p in db.execute('SELECT p.id,p.name,p.created_at,p.last_seen,p.online,p.mac_address,p.client_disabled,COALESCE(m.enabled,0) AS maintenance FROM pcs p LEFT JOIN maintenance_sessions m ON m.pc_id=p.id WHERE p.archived=0 ORDER BY p.name'):
                    active=db.execute("SELECT a.*,t.amount_centavos FROM active_sessions a LEFT JOIN transactions t ON t.id=a.transaction_id WHERE a.pc_id=? AND a.status='active' ORDER BY a.expires_at DESC LIMIT 1",(p['id'],)).fetchone()
                    is_online=bool(p['last_seen'] is not None and now-float(p['last_seen'])<15)
                    if bool(p['online']) and not is_online:
                        db.execute('UPDATE pcs SET online=0 WHERE id=?',(p['id'],))
                        connection_log(db,p['id'],p['name'],'','CLIENT_STATUS','DISCONNECTED','No authenticated heartbeat for 15 seconds')
                    health_row=db.execute('SELECT * FROM client_health WHERE pc_id=?',(p['id'],)).fetchone()
                    health=None
                    if health_row:
                        service_age=max(0,int(now-float(health_row['at'])))
                        service_fresh=service_age<15
                        guard_hb=db.execute("SELECT at FROM component_heartbeats WHERE pc_id=? AND component=?",(p['id'],'guard')).fetchone()
                        client_hb=db.execute("SELECT at FROM component_heartbeats WHERE pc_id=? AND component=?",(p['id'],'client')).fetchone()
                        guard_age=max(0,int(now-float(guard_hb['at']))) if guard_hb else None
                        client_age=max(0,int(now-float(client_hb['at']))) if client_hb else None
                        disabled_applied=bool(p['client_disabled']) and service_fresh and health_row['client_state']=='disabled'
                        health={'last_seen':health_row['at'],'age_seconds':service_age,'online':service_fresh,
                                'service':'online' if service_fresh and health_row['service_state']=='running' else 'offline',
                                'guard':'disabled' if service_fresh and health_row['guard_state']=='disabled' else ('online' if guard_age is not None and guard_age<15 else 'offline'),
                                'client':'disabled' if disabled_applied else ('online' if client_age is not None and client_age<15 else 'offline'),
                                'client_disabled_applied':disabled_applied,
                                'guard_age_seconds':guard_age,'client_age_seconds':client_age,
                                'network_connected':bool(health_row['network_connected']),
                                'service_pid':health_row['service_pid'],'guard_pid':health_row['guard_pid'],
                                'client_pid':health_row['client_pid'],'version':health_row['version']}
                    pcs.append(dict(p)|{'online':is_online,'client_disabled_applied':bool(health and health.get('client_disabled_applied')),'remaining_seconds':max(0,int(active['expires_at']-now)) if active else 0,'expires_at':float(active['expires_at']) if active else None,'credit_centavos':int(active['amount_centavos'] or 0) if active else 0,'maintenance':bool(p['maintenance']),'health':health})
                return self.send_json(200,{'server_time':now,'pcs':pcs})
            if path=='/api/rates':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
                return self.send_json(200,{'rates':[dict(r) for r in db.execute('SELECT * FROM rate_rules ORDER BY denomination_centavos')]})
            if path=='/api/settings/insert-countdown':
                row=db.execute("SELECT value FROM settings WHERE key='insert_countdown_seconds'").fetchone()
                return self.send_json(200,{'insert_countdown_seconds':int(row['value']) if row else 60})
            if path=='/api/settings/shutdown-countdown':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
                row=db.execute("SELECT value FROM settings WHERE key='shutdown_countdown_minutes'").fetchone()
                return self.send_json(200,{'shutdown_countdown_minutes':int(row['value']) if row else 5})
            if path=='/api/transactions':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
                rows=[]
                for tx in db.execute('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100'): rows.append(transaction_view(db,tx))
                return self.send_json(200,{'transactions':rows})
            if path.startswith('/api/coin-sessions/') and path.endswith('/status'):
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                sid=path.split('/')[-2]; row=db.execute('SELECT * FROM coin_sessions WHERE id=? AND pc_id=?',(sid,pc['id'])).fetchone()
                if not row: return self.send_json(404,{'error':'COIN_SESSION_NOT_FOUND'})
                return self.send_json(200,session_view(row))
            if path=='/api/coin-engine/status':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                state=COIN_ENGINE.status()
                if state['owner'] != pc['id']: state={'owner':state['owner'],'inhibited':state['inhibited'],'healthy':state['healthy']}
                return self.send_json(200,state)
            if path=='/api/client/spectate/commands':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                state=SPECTATE.get(pc['id'],{})
                enabled=bool(state.get('active') and state.get('approved') and state.get('control_enabled') and state.get('control_expires_at',0)>time.time())
                commands=state.get('commands',[]) if enabled else []
                if enabled: state['commands']=[]
                return self.send_json(200,{'active':bool(state.get('active') and state.get('approved')),'control_enabled':enabled,'commands':commands})
            if path=='/api/client/status':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                now=time.time()
                query=parse_qs(urlparse(self.path).query)
                component=(query.get('component',[''])[0] or '').lower()
                boot_id=(query.get('boot_id',[''])[0] or '').strip()
                if component=='client' and boot_id.isdigit() and len(boot_id)<=16 and boot_id!=str(pc['client_boot_id'] or ''):
                    shutdown_cfg=db.execute("SELECT value FROM settings WHERE key='shutdown_countdown_minutes'").fetchone()
                    shutdown_minutes=max(1,min(60,int(shutdown_cfg['value']) if shutdown_cfg else 5))
                    db.execute('UPDATE pcs SET client_boot_id=?,client_shutdown_reset_at=?,client_shutdown_reset_until=? WHERE id=?',(boot_id,now,now+shutdown_minutes*60,pc['id']))
                    db.execute('DELETE FROM shutdown_completions WHERE pc_id=?',(pc['id'],))
                    audit(db,pc['id'],'workstation_boot_detected',{'boot_id':boot_id,'previous_boot_id':str(pc['client_boot_id'] or ''),'shutdown_countdown_minutes':shutdown_minutes})
                    pc=db.execute('SELECT * FROM pcs WHERE id=?',(pc['id'],)).fetchone()
                reported_name=(query.get('hostname',[''])[0] or '').strip()
                if component=='client' and reported_name and len(reported_name)<=120 and reported_name!=pc['name']:
                    old_name=pc['name']
                    db.execute('UPDATE pcs SET name=? WHERE id=?',(reported_name,pc['id']))
                    audit(db,pc['id'],'workstation_hostname_changed',{'old_name':old_name,'new_name':reported_name})
                    connection_log(db,pc['id'],reported_name,self.client_address[0] if self.client_address else '', 'HOSTNAME_CHANGED','UPDATED',f'Workstation name updated from {old_name} to {reported_name}')
                    pc=db.execute('SELECT * FROM pcs WHERE id=?',(pc['id'],)).fetchone()
                if component in ('guard','client'):
                    db.execute('INSERT INTO component_heartbeats(pc_id,component,at) VALUES (?,?,?) ON CONFLICT(pc_id,component) DO UPDATE SET at=excluded.at',(pc['id'],component,now))
                was_online=bool(pc['online']) and pc['last_seen'] is not None and (now-float(pc['last_seen'])<15)
                expire_offline_sessions(db,now,pc['id'])
                db.execute('UPDATE pcs SET online=1,last_seen=? WHERE id=?',(now,pc['id']))
                last_status_log=db.execute("SELECT at FROM connection_logs WHERE pc_id=? AND event='CLIENT_STATUS' AND outcome='CONNECTED' ORDER BY at DESC LIMIT 1",(pc['id'],)).fetchone()
                if not was_online or not last_status_log or now-float(last_status_log['at'])>=60:
                    connection_log(db,pc['id'],pc['name'],self.client_address[0] if self.client_address else '', 'CLIENT_STATUS','CONNECTED','Authenticated status request succeeded')
                db.execute("UPDATE active_sessions SET status='expired' WHERE pc_id=? AND status='active' AND expires_at<=?",(pc['id'],now))
                active=db.execute("SELECT a.*,t.amount_centavos,t.purchased_seconds FROM active_sessions a JOIN transactions t ON t.id=a.transaction_id WHERE a.pc_id=? AND a.status='active' ORDER BY a.expires_at DESC LIMIT 1",(pc['id'],)).fetchone()
                expired=db.execute("SELECT a.*,t.amount_centavos,t.purchased_seconds FROM active_sessions a JOIN transactions t ON t.id=a.transaction_id WHERE a.pc_id=? AND a.status='expired' ORDER BY a.expires_at DESC LIMIT 1",(pc['id'],)).fetchone()
                pending=db.execute("SELECT * FROM coin_sessions WHERE pc_id=? AND status='inserting' ORDER BY started_at DESC LIMIT 1",(pc['id'],)).fetchone()
                pending_view=session_view(pending) if pending else None
                cfg=db.execute("SELECT value FROM settings WHERE key='shutdown_countdown_minutes'").fetchone()
                shutdown_minutes=int(cfg['value']) if cfg else 5
                client_disabled=bool(pc['client_disabled'])
                client_shutdown_reset_at=float(pc['client_shutdown_reset_at'] or 0)
                client_shutdown_reset_until=float(pc['client_shutdown_reset_until'] or 0)
                shutdown_restarted_after_enable=bool(expired and not client_disabled and client_shutdown_reset_at>float(expired['expires_at']))
                completion=db.execute('SELECT completed_at FROM shutdown_completions WHERE pc_id=? AND ABS(expired_at-?)<0.01',(pc['id'],expired['expires_at'])).fetchone() if expired else None
                shutdown_done=bool(completion and (not shutdown_restarted_after_enable or float(completion['completed_at'])>=client_shutdown_reset_at))
                if expired and not active:
                    shutdown_at=expired['expires_at']+shutdown_minutes*60
                    if shutdown_restarted_after_enable:
                        shutdown_at=max(shutdown_at,client_shutdown_reset_until)
                    expired_view={
                        'amount_centavos':expired['amount_centavos'],
                        'purchased_seconds':expired['purchased_seconds'],
                        'expired_at':expired['expires_at'],
                        'shutdown_at':shutdown_at,
                        'shutdown_remaining_seconds':0 if shutdown_done else max(0,int(shutdown_at-now)),
                        'shutdown_completed':shutdown_done,
                    }
                else:
                    expired_view=None
                maintenance_verifier=(db.execute("SELECT value FROM settings WHERE key='maintenance_password_hash'").fetchone() or {'value':''})['value']
                uninstall_verifier=(db.execute("SELECT value FROM settings WHERE key='uninstall_password_hash'").fetchone() or {'value':''})['value']
                admin_locked=bool(pc['admin_locked'])
                # Execute queued workstation actions in the interactive Tauri client.
                # The client invokes the same native Windows commands as its local controls.
                admin_commands=[dict(r) for r in db.execute("SELECT id,command FROM workstation_commands WHERE pc_id=? AND status='pending' AND expires_at>? ORDER BY id LIMIT 20",(pc['id'],now))] if component=='client' else []
                sp=SPECTATE.get(pc['id'],{})
                insert_sound=(lambda s: ({'id':s.get('insert_sound_id',''),'filename':s.get('insert_sound_filename','')} if s.get('insert_sound_id') else None))({r['key']:r['value'] for r in db.execute("SELECT key,value FROM settings WHERE key IN ('insert_sound_id','insert_sound_filename')")})
                if sp.get('active') and now-float(sp.get('last_admin_at',0))>15:
                    sp.update({'active':False,'approved':False,'control_requested':False,'control_enabled':False,'commands':[]})
                return self.send_json(200,{'pc_id':pc['id'],'name':pc['name'],'server_time':now,'client_disabled':client_disabled,'client_shutdown_reset_at':client_shutdown_reset_at,'admin_locked':admin_locked,'admin_commands':admin_commands,'shop_name':(db.execute("SELECT value FROM settings WHERE key='shop_name'").fetchone() or {'value':''})['value'],'shop_subtext':(db.execute("SELECT value FROM settings WHERE key='shop_subtext'").fetchone() or {'value':''})['value'],'shop_name_font':(db.execute("SELECT value FROM settings WHERE key='shop_name_font'").fetchone() or {'value':'system'})['value'],'shop_name_size':int((db.execute("SELECT value FROM settings WHERE key='shop_name_size'").fetchone() or {'value':'28'})['value']),'insert_sound':insert_sound,'spectate_requested':bool(sp.get('active') and not sp.get('approved')),'spectate_active':bool(sp.get('active') and sp.get('approved')),'spectate_control_requested':bool(sp.get('control_requested')),'spectate_control_enabled':bool(sp.get('control_enabled') and sp.get('control_expires_at',0)>now),'maintenance_password_verifier':maintenance_verifier,'uninstall_password_verifier':uninstall_verifier,'session':({'remaining_seconds':max(0,int(active['expires_at']-now)),'expires_at':active['expires_at'],'purchased_seconds':active['purchased_seconds'],'amount_centavos':active['amount_centavos']} if active else None),'expired_session':expired_view,'shutdown_countdown_minutes':shutdown_minutes,'insert_countdown_seconds':int((db.execute("SELECT value FROM settings WHERE key='insert_countdown_seconds'").fetchone() or {'value':'60'})['value']),'pending_coin_session':pending_view,'server_recovery_required':bool(pending_view and COIN_ENGINE.inhibited),'maintenance_mode':bool((db.execute('SELECT enabled FROM maintenance_sessions WHERE pc_id=?',(pc['id'],)).fetchone() or {'enabled':0})['enabled']),
                    'wallpaper': (lambda w: ({'id':w['id'],'filename':w['filename'],'content_type':w['content_type'],'lockscreen_enabled':bool(w['lockscreen_enabled']),'desktop_enabled':bool(w['desktop_enabled']),'fit_mode':w['fit_mode'],'url':'/api/wallpapers/'+str(w['id'])} if w else None))(db.execute("SELECT * FROM wallpapers WHERE scope IN ('lockscreen','global') AND active=1 AND lockscreen_enabled=1 ORDER BY CASE scope WHEN 'lockscreen' THEN 0 ELSE 1 END,id DESC LIMIT 1").fetchone()),
                    'desktop_wallpaper': (lambda w: ({'id':w['id'],'filename':w['filename'],'content_type':w['content_type'],'fit_mode':w['fit_mode'],'url':'/api/wallpapers/'+str(w['id'])} if w else None))(db.execute("SELECT * FROM wallpapers WHERE scope IN ('desktop','global') AND active=1 AND desktop_enabled=1 ORDER BY CASE scope WHEN 'desktop' THEN 0 ELSE 1 END,id DESC LIMIT 1").fetchone()),
                    'client_update': (lambda b: ({'id':b['id'],'version':b['version'],'package_type':'setup' if str(b['filename']).lower().startswith('pisonet-setup-') else 'client','sha256':b['sha256'],'size_bytes':b['size_bytes'],'url':'/api/client/updates/'+str(b['id'])+'/download'} if b else None))(db.execute('SELECT id,version,filename,sha256,size_bytes FROM client_builds WHERE active=1 ORDER BY id DESC LIMIT 1').fetchone()),
                    'security_policy': (lambda policy, maintenance: ({k: (False if maintenance and isinstance(v,bool) else ([] if maintenance and k=='hidden_drives' else v)) for k,v in policy.items()} if maintenance else policy))(
                        (lambda g, o: (g | o))(
                            json.loads((db.execute('SELECT policy_json FROM security_global WHERE id=1').fetchone() or {'policy_json':'{}'})['policy_json']),
                            json.loads((db.execute('SELECT policy_json FROM security_pc_overrides WHERE pc_id=?',(pc['id'],)).fetchone() or {'policy_json':'{}'})['policy_json'])
                        ),
                        bool((db.execute('SELECT enabled FROM maintenance_sessions WHERE pc_id=?',(pc['id'],)).fetchone() or {'enabled':0})['enabled'])
                    )})
        return self.send_json(404,{'error':'NOT_FOUND'})
    def do_POST(self):
        path=urlparse(self.path).path
        if path=='/api/v2/client-builds/upload':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            version=str(self.headers.get('X-Client-Version','')).strip()
            package_type=str(self.headers.get('X-Client-Package-Type','client')).strip().lower()
            if not __import__('re').fullmatch(r'\d+\.\d+\.\d+',version): return self.send_json(400,{'error':'CLIENT_VERSION_REQUIRED'})
            if package_type not in ('client','setup'): return self.send_json(400,{'error':'INVALID_CLIENT_PACKAGE_TYPE'})
            try: length=int(self.headers.get('Content-Length','0'))
            except ValueError: return self.send_json(400,{'error':'INVALID_CONTENT_LENGTH'})
            if length<2 or length>200*1024*1024: return self.send_json(413,{'error':'CLIENT_BUILD_SIZE_LIMIT_200MB'})
            raw=self.rfile.read(length)
            if len(raw)!=length or raw[:2]!=b'MZ': return self.send_json(400,{'error':'INVALID_WINDOWS_EXE'})
            digest=hashlib.sha256(raw).hexdigest(); filename=('pisonet-setup-' if package_type=='setup' else 'pisonet-client-')+version+'-'+digest[:10]+'.exe'
            target=CLIENT_BUILD_DIR/filename; tmp=target.with_suffix('.exe.upload')
            try:
                tmp.write_bytes(raw); tmp.replace(target)
            except OSError as exc:
                try: tmp.unlink(missing_ok=True)
                except OSError: pass
                return self.send_json(500,{'error':'CLIENT_BUILD_STORAGE_FAILED','detail':str(exc)[:160]})
            with LOCK, connect() as db:
                db.execute('UPDATE client_builds SET active=0')
                cur=db.execute('INSERT INTO client_builds(version,filename,file_path,sha256,size_bytes,created_at,active) VALUES (?,?,?,?,?,?,1)',(version,filename,str(target),digest,len(raw),time.time()))
                audit(db,'admin','client_build_uploaded',{'version':version,'package_type':package_type,'sha256':digest,'size_bytes':len(raw)})
                build_id=cur.lastrowid
            return self.send_json(201,{'ok':True,'id':build_id,'version':version,'filename':filename,'package_type':package_type,'sha256':digest,'size_bytes':len(raw)})
        try: data=self.body()
        except Exception: return self.send_json(400,{'error':'INVALID_JSON'})
        if path=='/api/client/coin-event':
            with connect() as db:
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                event=str(data.get('event',''))
                if event not in ('insert_clicked','slot_open_failed'): return self.send_json(400,{'error':'INVALID_COIN_EVENT'})
                status='attempting' if event=='insert_clicked' else 'failed'
                write_coin_event(event,status,pc['id'],pc['name'],details=str(data.get('details','Client requested coin slot reservation'))[:300])
                return self.send_json(202,{'logged':True})
        if path=='/api/v2/server-update/install':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            if not SERVER_UPDATE_LOCK.acquire(blocking=False): return self.send_json(409,{'error':'SERVER_UPDATE_ALREADY_RUNNING'})
            previous_status=read_server_update_status() or {}
            if server_update_status_is_active(previous_status):
                SERVER_UPDATE_LOCK.release()
                return self.send_json(409,{'error':'SERVER_UPDATE_ALREADY_RUNNING','status':previous_status})
            if previous_status.get('state') in ('queued','starting','stopping','installing','rollback'):
                previous_status.update({'state':'stale','message':'Previous server update worker stopped reporting progress; retry is allowed.','updated_at':time.time()})
                temporary=SERVER_UPDATE_STATUS_PATH.with_suffix('.json.tmp')
                temporary.write_text(json.dumps(previous_status,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');os.replace(temporary,SERVER_UPDATE_STATUS_PATH)
            stage=ROOT/'server_ota_staging'/str(uuid.uuid4())
            process=None
            try:
                manifest,_raw=fetch_server_release_manifest()
                status=server_release_status(manifest)
                if not status['update_available']:
                    SERVER_UPDATE_LOCK.release()
                    return self.send_json(409,{'error':'SERVER_ALREADY_UP_TO_DATE','current_build':SERVER_BUILD,'latest_build':manifest['build']})
                if server_build_tuple(manifest['build'])<=server_build_tuple(SERVER_BUILD):
                    SERVER_UPDATE_LOCK.release()
                    return self.send_json(409,{'error':'SERVER_RELEASE_BUILD_MUST_INCREASE','current_build':SERVER_BUILD,'latest_build':manifest['build']})
                download_server_release(stage,manifest)
                worker=stage/'payload'/'server_update_worker.py'
                if not worker.is_file(): raise ValueError('SERVER_UPDATE_WORKER_MISSING')
                state={'build':manifest['build'],'state':'queued','message':'Verified update queued; server will restart.','updated_at':time.time(),'backup':''}
                temporary=SERVER_UPDATE_STATUS_PATH.with_suffix('.json.tmp')
                temporary.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');os.replace(temporary,SERVER_UPDATE_STATUS_PATH)
                flags=getattr(subprocess,'DETACHED_PROCESS',0)|getattr(subprocess,'CREATE_NEW_PROCESS_GROUP',0)
                if os.name=='nt': flags|=getattr(subprocess,'CREATE_NO_WINDOW',0)
                worker_log=ROOT/'logs'/'server-update-worker.log';worker_log.parent.mkdir(parents=True,exist_ok=True)
                with worker_log.open('a',encoding='utf-8') as output:
                    process=subprocess.Popen([sys.executable,str(worker),'--root',str(ROOT),'--stage',str(stage),'--build',str(manifest['build']),'--previous-build',SERVER_BUILD,'--parent-pid',str(os.getpid())],cwd=str(ROOT),stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,close_fds=True,creationflags=flags,start_new_session=(os.name!='nt'))
                try: audit(db,'admin','server_update_queued',{'build':manifest['build'],'repository':SERVER_GITHUB_REPOSITORY,'branch':SERVER_GITHUB_BRANCH,'files':status['changed_files'],'worker_pid':process.pid})
                except Exception as audit_error: print('Server OTA audit log failed after worker launch: '+str(audit_error))
                SERVER_UPDATE_LOCK.release()
                return self.send_json(202,{'queued':True,'current_build':SERVER_BUILD,'target_build':manifest['build'],'files':status['changed_files'],'message':'Verified server update queued. The API will restart while the update is applied.'})
            except Exception as exc:
                if process is None:
                    try: shutil.rmtree(stage,ignore_errors=True)
                    except Exception: pass
                    failed={'build':str(manifest.get('build','unknown')) if 'manifest' in locals() else 'unknown','state':'failed','message':'Server update preparation failed: '+str(exc)[:300],'updated_at':time.time(),'backup':''}
                    temporary=SERVER_UPDATE_STATUS_PATH.with_suffix('.json.tmp')
                    temporary.write_text(json.dumps(failed,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');os.replace(temporary,SERVER_UPDATE_STATUS_PATH)
                if SERVER_UPDATE_LOCK.locked(): SERVER_UPDATE_LOCK.release()
                return self.send_json(502,{'error':'SERVER_UPDATE_PREPARATION_FAILED','detail':str(exc)[:300]})
        if path == '/api/settings/insert-sound':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            filename=os.path.basename(str(data.get('filename','insert-sound')))
            ext=Path(filename).suffix.lower()
            allowed={'.mp3':('audio/mpeg',lambda b:b.startswith(b'ID3') or (len(b)>1 and b[0]==0xff and (b[1]&0xe0)==0xe0)),'.wav':('audio/wav',lambda b:len(b)>=12 and b[:4]==b'RIFF' and b[8:12]==b'WAVE')}
            if ext not in allowed: return self.send_json(400,{'error':'INSERT_SOUND_MUST_BE_MP3_OR_WAV'})
            try: raw=base64.b64decode(str(data.get('data_base64','')),validate=True)
            except Exception: return self.send_json(400,{'error':'INVALID_BASE64'})
            if not raw or len(raw)>5*1024*1024: return self.send_json(413,{'error':'INSERT_SOUND_MAX_5MB'})
            content_type,signature_check=allowed[ext]
            if not signature_check(raw): return self.send_json(400,{'error':'INSERT_SOUND_SIGNATURE_MISMATCH'})
            sound_id=str(uuid.uuid4()); target=INSERT_SOUND_DIR/(sound_id+ext)
            try: target.write_bytes(raw)
            except OSError as exc: return self.send_json(500,{'error':'INSERT_SOUND_STORAGE_FAILED','detail':str(exc)[:160]})
            old_path=''
            try:
                with LOCK, connect() as db:
                    old_path=(db.execute("SELECT value FROM settings WHERE key='insert_sound_file_path'").fetchone() or {'value':''})['value']
                    for key,value in (('insert_sound_id',sound_id),('insert_sound_filename',filename),('insert_sound_content_type',content_type),('insert_sound_file_path',str(target))):
                        db.execute('INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(key,value))
                    audit(db,'admin','insert_sound_uploaded',{'filename':filename,'size_bytes':len(raw),'format':ext[1:]})
            except Exception:
                target.unlink(missing_ok=True)
                raise
            if old_path and Path(old_path)!=target:
                try: Path(old_path).unlink(missing_ok=True)
                except OSError: pass
            return self.send_json(201,{'ok':True,'id':sound_id,'filename':filename,'content_type':content_type})
        if path in ('/api/v2/zerotier/join','/api/v2/zerotier/leave'):
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            network_id=str(data.get('network_id','')).strip().lower()
            if not __import__('re').fullmatch(r'[0-9a-f]{16}',network_id): return self.send_json(400,{'error':'INVALID_ZEROTIER_NETWORK_ID'})
            operation='join' if path.endswith('/join') else 'leave'
            try:
                output=zerotier_cli(operation,network_id)
                with connect() as audit_db: audit(audit_db,'admin','zerotier_local_'+operation,{'network_id':network_id})
                return self.send_json(200,{'ok':True,'network_id':network_id,'operation':operation,'message':output})
            except Exception as exc:
                return self.send_json(502,{'error':'ZEROTIER_LOCAL_SERVICE_ERROR','detail':str(exc)[:300]})
        with LOCK, connect() as db:
            if path=='/api/client/shutdown-completed':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                try: expired_at=float(data.get('expired_at'))
                except (TypeError,ValueError): return self.send_json(400,{'error':'EXPIRED_AT_REQUIRED'})
                session=db.execute("SELECT 1 FROM active_sessions WHERE pc_id=? AND status='expired' AND ABS(expires_at-?)<0.01",(pc['id'],expired_at)).fetchone()
                if not session: return self.send_json(404,{'error':'EXPIRED_SESSION_NOT_FOUND'})
                db.execute('INSERT INTO shutdown_completions(pc_id,expired_at,completed_at) VALUES (?,?,?) ON CONFLICT(pc_id,expired_at) DO UPDATE SET completed_at=excluded.completed_at',(pc['id'],expired_at,time.time()))
                return self.send_json(200,{'ok':True,'expired_at':expired_at})
            if path=='/api/v2/workstations/wol':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
                requested=data.get('pc_ids')
                if requested is not None and (not isinstance(requested,list) or len(requested)>500): return self.send_json(400,{'error':'INVALID_WORKSTATION_LIST'})
                rows=db.execute('SELECT id,name,mac_address FROM pcs WHERE archived=0'+('' if requested is None else ' AND id IN ('+','.join('?' for _ in requested)+')'),tuple(requested or [])).fetchall()
                results=[]
                for row in rows:
                    if not row['mac_address']:
                        results.append({'pc_id':row['id'],'name':row['name'],'status':'missing_mac'}); continue
                    try:
                        ports=send_wol(row['mac_address']); results.append({'pc_id':row['id'],'name':row['name'],'status':'sent','ports':ports})
                    except Exception as exc: results.append({'pc_id':row['id'],'name':row['name'],'status':'failed','error':str(exc)[:100]})
                audit(db,'admin','workstation_wol_sent',{'count':sum(1 for x in results if x['status']=='sent'),'workstations':[x['pc_id'] for x in results]})
                return self.send_json(200,{'ok':True,'results':results,'sent':sum(1 for x in results if x['status']=='sent'),'missing_mac':sum(1 for x in results if x['status']=='missing_mac')})
            if path in ('/api/v2/spectate/start','/api/v2/spectate/stop','/api/v2/spectate/control-request'):
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
                pcid=str(data.get('pc_id','')).strip(); row=db.execute('SELECT name,last_seen FROM pcs WHERE id=? AND archived=0',(pcid,)).fetchone()
                if not row: return self.send_json(404,{'error':'WORKSTATION_NOT_FOUND'})
                state=spectate_state(pcid)
                if path.endswith('/start'):
                    if row['last_seen'] is None or time.time()-float(row['last_seen'])>=15: return self.send_json(409,{'error':'WORKSTATION_OFFLINE'})
                    now=time.time()
                    state.update({'active':True,'approved':True,'control_requested':False,'control_enabled':True,'frame_base64':'','frame_at':0,'commands':[],'control_expires_at':now+600,'last_admin_at':now})
                    audit(db,'admin','spectate_started',{'pc_id':pcid,'control_enabled':True})
                    return self.send_json(200,{'ok':True,'state':'live','control_enabled':True})
                if path.endswith('/stop'):
                    state.update({'active':False,'approved':False,'control_requested':False,'control_enabled':False,'commands':[],'control_expires_at':0})
                    audit(db,'admin','spectate_ended',{'pc_id':pcid})
                    return self.send_json(200,{'ok':True})
                if not state.get('active') or not state.get('approved'): return self.send_json(409,{'error':'SPECTATE_NOT_ACTIVE'})
                state.update({'control_requested':False,'control_enabled':True,'control_expires_at':time.time()+600,'commands':[]})
                audit(db,'admin','spectate_control_enabled',{'pc_id':pcid})
                return self.send_json(200,{'ok':True,'state':'control_enabled'})
            if path=='/api/v2/spectate/input':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
                pcid=str(data.get('pc_id','')).strip(); state=SPECTATE.get(pcid,{})
                if not (state.get('active') and state.get('approved') and state.get('control_enabled') and state.get('control_expires_at',0)>time.time()): return self.send_json(403,{'error':'REMOTE_CONTROL_NOT_APPROVED'})
                event=data.get('event')
                if not isinstance(event,dict) or event.get('type') not in ('move','click','key'): return self.send_json(400,{'error':'INVALID_REMOTE_INPUT'})
                if event['type']=='move':
                    try: x=float(event.get('x')); y=float(event.get('y'))
                    except (TypeError,ValueError): return self.send_json(400,{'error':'INVALID_REMOTE_INPUT'})
                    if not (0<=x<=1 and 0<=y<=1): return self.send_json(400,{'error':'INVALID_REMOTE_INPUT'})
                    event={'type':'move','x':x,'y':y}
                elif event['type']=='click':
                    if event.get('button','left') not in ('left','right'): return self.send_json(400,{'error':'INVALID_REMOTE_INPUT'})
                    try: x=float(event.get('x')); y=float(event.get('y'))
                    except (TypeError,ValueError): return self.send_json(400,{'error':'INVALID_REMOTE_INPUT'})
                    if not (0<=x<=1 and 0<=y<=1): return self.send_json(400,{'error':'INVALID_REMOTE_INPUT'})
                    event={'type':'click','button':event.get('button','left'),'x':x,'y':y}
                else:
                    key=str(event.get('key',''))[:12]
                    if not key: return self.send_json(400,{'error':'INVALID_REMOTE_INPUT'})
                    event={'type':'key','key':key,'ctrl':event.get('ctrl') is True,'shift':event.get('shift') is True}
                state['commands'].append(event); state['commands']=state['commands'][-100:]
                return self.send_json(200,{'ok':True})
            if path=='/api/client/spectate/frame':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                state=SPECTATE.get(pc['id'])
                frame=str(data.get('frame_base64',''))
                if not state or not state.get('active') or not state.get('approved'): return self.send_json(403,{'error':'SPECTATE_NOT_APPROVED'})
                if len(frame)>9*1024*1024 or not frame.startswith('Qk'): return self.send_json(400,{'error':'INVALID_SPECTATE_FRAME'})
                state['frame_base64']=frame; state['frame_at']=time.time()
                return self.send_json(200,{'ok':True})
            if path=='/api/client/spectate/respond':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                state=SPECTATE.get(pc['id'])
                if not state or not state.get('active'): return self.send_json(409,{'error':'SPECTATE_REQUEST_EXPIRED'})
                allow=data.get('allow'); control=data.get('control') is True
                if type(allow) is not bool: return self.send_json(400,{'error':'INVALID_SPECTATE_RESPONSE'})
                if control:
                    if not state.get('approved') or not state.get('control_requested'): return self.send_json(409,{'error':'CONTROL_REQUEST_EXPIRED'})
                    state.update({'control_requested':False,'control_enabled':allow,'control_expires_at':time.time()+600 if allow else 0})
                    audit(db,'client:'+pc['id'],'spectate_control_consent',{'allowed':allow})
                elif allow:
                    state.update({'approved':True,'control_enabled':False})
                    audit(db,'client:'+pc['id'],'spectate_view_consent',{'allowed':True})
                else:
                    state.update({'active':False,'approved':False,'control_enabled':False,'control_requested':False,'commands':[]})
                    audit(db,'client:'+pc['id'],'spectate_view_consent',{'allowed':False})
                return self.send_json(200,{'ok':True,'active':bool(state.get('active') and state.get('approved')),'control_enabled':bool(state.get('control_enabled'))})
            if path == '/api/client/recovery-heartbeat':
                pc=self.client(db)
                if not pc: return self.send_json(401, {'error':'CLIENT_AUTH_REQUIRED'})
                def safe_state(key):
                    value=str(data.get(key,'unknown')).lower()
                    return value if value in ('running','missing','disabled','unknown') else 'unknown'
                try:
                    db.execute('''INSERT INTO client_health(pc_id,at,service_state,guard_state,client_state,service_pid,guard_pid,client_pid,session_id,network_connected,version)
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?)
                                  ON CONFLICT(pc_id) DO UPDATE SET at=excluded.at,service_state=excluded.service_state,guard_state=excluded.guard_state,client_state=excluded.client_state,service_pid=excluded.service_pid,guard_pid=excluded.guard_pid,client_pid=excluded.client_pid,session_id=excluded.session_id,network_connected=excluded.network_connected,version=excluded.version''',
                               (pc['id'],time.time(),safe_state('service_state'),safe_state('guard_state'),safe_state('client_state'),
                                int(data.get('service_pid') or 0),int(data.get('guard_pid') or 0),int(data.get('client_pid') or 0),
                                int(data.get('session_id') or 0),1 if data.get('network_connected') else 0,str(data.get('version','3D'))[:20]))
                    return self.send_json(200, {'ok':True,'server_time':time.time()})
                except Exception as exc: return self.send_json(400, {'error':'INVALID_RECOVERY_HEARTBEAT','detail':str(exc)[:200]})
            if path == '/api/client/admin-command-result':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                try: command_id=int(data.get('command_id'))
                except (TypeError,ValueError): return self.send_json(400,{'error':'COMMAND_ID_REQUIRED'})
                result=str(data.get('result','completed'))[:120]
                command_row=db.execute("SELECT command FROM workstation_commands WHERE id=? AND pc_id=? AND status='pending'",(command_id,pc['id'])).fetchone()
                if not command_row: return self.send_json(200,{'ok':True,'acknowledged':False})
                now=time.time()
                cur=db.execute("UPDATE workstation_commands SET status='completed',completed_at=?,result=? WHERE id=? AND pc_id=? AND status='pending'",(now,result,command_id,pc['id']))
                if cur.rowcount and command_row['command']=='reboot' and result=='reboot_scheduled':
                    shutdown_cfg=db.execute("SELECT value FROM settings WHERE key='shutdown_countdown_minutes'").fetchone()
                    shutdown_minutes=max(1,min(60,int(shutdown_cfg['value']) if shutdown_cfg else 5))
                    db.execute('UPDATE pcs SET client_shutdown_reset_at=?,client_shutdown_reset_until=? WHERE id=?',(now,now+shutdown_minutes*60,pc['id']))
                    db.execute('DELETE FROM shutdown_completions WHERE pc_id=?',(pc['id'],))
                return self.send_json(200,{'ok':True,'acknowledged':bool(cur.rowcount)})
            if path == '/api/v2/admin/login':
                username = str(data.get('username','')).strip()
                password = str(data.get('password',''))
                source_ip=self.client_address[0] if self.client_address else 'unknown'
                now=time.time()
                with LOGIN_GUARD_LOCK:
                    record=LOGIN_FAILURES.get(source_ip,{'count':0,'window':now,'blocked_until':0})
                    if now-record['window']>300: record={'count':0,'window':now,'blocked_until':0}
                    if now<record['blocked_until']:
                        return self.send_json(429,{'error':'LOGIN_RATE_LIMITED','retry_after_seconds':int(record['blocked_until']-now)})
                user = db.execute('SELECT * FROM admin_users WHERE username=?',(username,)).fetchone()
                valid = False
                if user:
                    actual = hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(user['password_salt']),310000).hex()
                    valid = secrets.compare_digest(actual,user['password_hash'])
                if not valid:
                    with LOGIN_GUARD_LOCK:
                        record['count']+=1
                        if record['count']>=5: record['blocked_until']=now+60
                        LOGIN_FAILURES[source_ip]=record
                    audit(db,'admin','admin_login_failed',{'username':username[:80],'source_ip':source_ip})
                    return self.send_json(401, {'error':'INVALID_CREDENTIALS'})
                with LOGIN_GUARD_LOCK: LOGIN_FAILURES.pop(source_ip,None)
                token = secrets.token_urlsafe(40)
                db.execute('INSERT INTO admin_sessions(token_hash,username,created_at,expires_at) VALUES (?,?,?,?)',
                           (hashlib.sha256(token.encode()).hexdigest(),username,time.time(),time.time()+8*3600))
                audit(db,username,'admin_login',{})
                db.commit()  # persist session before returning the bearer token
                return self.send_json(200, {'ok':True,'token':token,'username':username,'must_change_password':bool(user['must_change_password']),'expires_in':28800})
            if path == '/api/v2/admin/logout':
                auth = self.headers.get('Authorization','')
                if auth.startswith('Bearer '):
                    db.execute('DELETE FROM admin_sessions WHERE token_hash=?',(hashlib.sha256(auth[7:].encode()).hexdigest(),))
                return self.send_json(200, {'ok':True})
            if path == '/api/v2/admin/password':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                auth=self.headers.get('Authorization','')
                if not auth.startswith('Bearer '): return self.send_json(401, {'error':'ADMIN_SESSION_REQUIRED'})
                session=db.execute('SELECT username FROM admin_sessions WHERE token_hash=? AND expires_at>?',(hashlib.sha256(auth[7:].encode()).hexdigest(),time.time())).fetchone()
                if not session: return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                username = session['username']
                new_password = str(data.get('new_password',''))
                if len(new_password)<12 or len(new_password)>128: return self.send_json(400, {'error':'PASSWORD_MUST_BE_12_TO_128_CHARACTERS'})
                salt=secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',new_password.encode(),salt,310000).hex()
                db.execute('UPDATE admin_users SET password_salt=?,password_hash=?,must_change_password=0 WHERE username=?',(salt.hex(),digest,username))
                audit(db,username,'admin_password_changed',{})
                if username=='admin':
                    try: (ROOT/'admin.initial-credentials.txt').unlink(missing_ok=True)
                    except OSError: pass
                return self.send_json(200, {'ok':True})
            if path == '/api/v2/admin/users':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                username=str(data.get('username','')).strip(); password=str(data.get('password',''))
                if not __import__('re').fullmatch(r'[A-Za-z0-9_.-]{1,64}',username) or len(password)<12 or len(password)>128: return self.send_json(400,{'error':'USERNAME_OR_PASSWORD_INVALID'})
                salt=secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,310000).hex()
                try: db.execute('INSERT INTO admin_users(username,password_salt,password_hash,must_change_password,created_at) VALUES (?,?,?,?,?)',(username,salt.hex(),digest,0,time.time()))
                except sqlite3.IntegrityError: return self.send_json(409,{'error':'USERNAME_ALREADY_EXISTS'})
                audit(db,'admin','admin_user_created',{'username':username}); return self.send_json(201,{'ok':True,'username':username})
            if path == '/api/v2/admin/users/reset-password':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                username=str(data.get('username','')).strip(); password=str(data.get('new_password',''))
                if len(password)<12 or len(password)>128: return self.send_json(400,{'error':'PASSWORD_MUST_BE_12_TO_128_CHARACTERS'})
                if not db.execute('SELECT 1 FROM admin_users WHERE username=?',(username,)).fetchone(): return self.send_json(404,{'error':'ADMIN_USER_NOT_FOUND'})
                salt=secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,310000).hex()
                db.execute('UPDATE admin_users SET password_salt=?,password_hash=?,must_change_password=1 WHERE username=?',(salt.hex(),digest,username)); db.execute('DELETE FROM admin_sessions WHERE username=?',(username,)); audit(db,'admin','admin_password_reset',{'username':username}); return self.send_json(200,{'ok':True})
            if path == '/api/v2/admin/users/delete':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                username=str(data.get('username','')).strip(); auth=self.headers.get('Authorization',''); current=''
                if auth.startswith('Bearer '):
                    cur=db.execute('SELECT username FROM admin_sessions WHERE token_hash=?',(hashlib.sha256(auth[7:].encode()).hexdigest(),)).fetchone(); current=cur['username'] if cur else ''
                if username==current: return self.send_json(400,{'error':'CANNOT_DELETE_CURRENT_ADMIN'})
                if db.execute('SELECT COUNT(*) n FROM admin_users').fetchone()['n']<=1: return self.send_json(400,{'error':'LAST_ADMIN_CANNOT_BE_DELETED'})
                db.execute('DELETE FROM admin_sessions WHERE username=?',(username,)); cur=db.execute('DELETE FROM admin_users WHERE username=?',(username,)); audit(db,'admin','admin_user_deleted',{'username':username}); return self.send_json(200,{'ok':bool(cur.rowcount)})
            if path == '/api/v2/workstations/control':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                pcids=data.get('pc_ids'); command=str(data.get('command','')).strip().lower()
                allowed={'lock','unlock','shutdown','reboot','restart_app','wol'}
                if not isinstance(pcids,list) or not pcids or len(pcids)>500 or command not in allowed:
                    return self.send_json(400,{'error':'WORKSTATION_IDS_AND_VALID_COMMAND_REQUIRED'})
                pcids=list(dict.fromkeys(str(x).strip() for x in pcids if str(x).strip()))
                results=[]; now=time.time()
                for pcid in pcids:
                    row=db.execute('SELECT id,name,last_seen,mac_address FROM pcs WHERE id=? AND archived=0',(pcid,)).fetchone()
                    if not row:
                        results.append({'pc_id':pcid,'status':'not_found'}); continue
                    if command=='wol':
                        if not row['mac_address']:
                            results.append({'pc_id':pcid,'name':row['name'],'status':'missing_mac'}); continue
                        try: results.append({'pc_id':pcid,'name':row['name'],'status':'sent','ports':send_wol(row['mac_address'])})
                        except Exception as exc: results.append({'pc_id':pcid,'name':row['name'],'status':'failed','error':str(exc)[:100]})
                        continue
                    online=row['last_seen'] is not None and now-float(row['last_seen'])<15
                    if command in ('lock','unlock'):
                        maintenance_enabled=1 if command=='unlock' else 0
                        db.execute('INSERT INTO maintenance_sessions(pc_id,enabled,changed_at) VALUES (?,?,?) ON CONFLICT(pc_id) DO UPDATE SET enabled=excluded.enabled,changed_at=excluded.changed_at',(pcid,maintenance_enabled,now))
                        # A Lock returns the client to its insert screen; it does not block coin insertion.
                        db.execute('UPDATE pcs SET admin_locked=? WHERE id=?',(0 if command=='unlock' else 1,pcid))
                        results.append({'pc_id':pcid,'name':row['name'],'status':('maintenance_enabled' if maintenance_enabled else 'locked_to_insert_screen') if online else 'saved_for_reconnect'})
                        continue
                    if not online:
                        results.append({'pc_id':pcid,'name':row['name'],'status':'offline'}); continue
                    cur=db.execute('INSERT INTO workstation_commands(pc_id,command,status,created_at,expires_at) VALUES (?,?,\'pending\',?,?)',(pcid,command,now,now+30))
                    results.append({'pc_id':pcid,'name':row['name'],'status':'queued','command_id':cur.lastrowid})
                audit(db,'admin','workstation_bulk_'+command,{'pc_ids':pcids,'results':results})
                return self.send_json(200,{'ok':True,'command':command,'results':results})
            if path == '/api/v2/workstations/remove':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                pcid=str(data.get('pc_id','')).strip()
                row=db.execute('SELECT id,name,last_seen FROM pcs WHERE id=? AND archived=0',(pcid,)).fetchone()
                if not row: return self.send_json(404,{'error':'WORKSTATION_NOT_FOUND'})
                if row['last_seen'] is not None and time.time()-float(row['last_seen'])<15:
                    return self.send_json(409,{'error':'WORKSTATION_ONLINE','message':'This workstation is currently connected. Remove it after it disconnects.'})
                db.execute('UPDATE pcs SET archived=1,online=0 WHERE id=?',(pcid,))
                db.execute('DELETE FROM security_pc_overrides WHERE pc_id=?',(pcid,))
                audit(db,'admin','workstation_archived',{'pc_id':pcid,'name':row['name']})
                return self.send_json(200,{'ok':True,'archived':True})
            if path == '/api/v2/sales/clear':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                if str(data.get('confirmation',''))!='CLEAR SALES': return self.send_json(400,{'error':'CONFIRMATION_REQUIRED'})
                auth=self.headers.get('Authorization',''); token=auth[7:] if auth.startswith('Bearer ') else ''
                session=db.execute('SELECT username FROM admin_sessions WHERE token_hash=? AND expires_at>?',(hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone()
                user=db.execute('SELECT password_salt,password_hash FROM admin_users WHERE username=?',(session['username'],)).fetchone() if session else None
                password=str(data.get('password',''))
                if not user: return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
                actual=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(user['password_salt']),310000).hex()
                if not hmac.compare_digest(actual,user['password_hash']): return self.send_json(403,{'error':'ADMIN_PASSWORD_INVALID'})
                tx_rows=[dict(r) for r in db.execute('SELECT * FROM transactions ORDER BY created_at')]
                batch_rows=[dict(r) for r in db.execute('SELECT b.* FROM coin_batches b JOIN transactions t ON t.coin_session_id=b.coin_session_id ORDER BY b.id')]
                backup_dir=ROOT/'backups'; backup_dir.mkdir(exist_ok=True)
                backup_path=backup_dir/('sales-before-clear-'+time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)+'.json')
                backup_path.write_text(json.dumps({'transactions':tx_rows,'coin_batches':batch_rows},indent=2),encoding='utf-8')
                ids=[r['coin_session_id'] for r in tx_rows]
                if ids:
                    placeholders=','.join('?' for _ in ids)
                    db.execute('DELETE FROM active_sessions WHERE transaction_id IN (SELECT id FROM transactions)')
                    db.execute('UPDATE coin_sessions SET transaction_id=NULL WHERE id IN ('+placeholders+')',ids)
                    db.execute('DELETE FROM coin_batches WHERE coin_session_id IN ('+placeholders+')',ids)
                    db.execute('DELETE FROM coin_sessions WHERE id IN ('+placeholders+')',ids)
                    db.execute('DELETE FROM transactions')
                audit(db,'admin','sales_cleared',{'transaction_count':len(tx_rows),'backup_file':backup_path.name})
                return self.send_json(200,{'ok':True,'deleted_transactions':len(tx_rows),'backup_file':backup_path.name})
            if path == '/api/v2/telegram/test':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                cfg=db.execute('SELECT * FROM telegram_config WHERE id=1').fetchone()
                if not cfg or not cfg['bot_token'] or not cfg['chat_id']: return self.send_json(400,{'error':'TELEGRAM_TOKEN_AND_CHAT_REQUIRED'})
                enqueue_telegram(db,'test:'+str(uuid.uuid4()),{'text':'PisoNet Telegram test message — connection successful.'}); return self.send_json(202,{'ok':True,'queued':True})
            if path == '/api/v2/wallpapers/upload':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                filename=os.path.basename(str(data.get('filename','wallpaper'))); ctype=str(data.get('content_type',''))
                if ctype not in ('image/jpeg','image/png','image/webp'): return self.send_json(400,{'error':'IMAGE_TYPE_NOT_ALLOWED'})
                try: raw=base64.b64decode(str(data.get('data_base64','')),validate=True)
                except Exception: return self.send_json(400,{'error':'INVALID_BASE64'})
                if not raw or len(raw)>8*1024*1024: return self.send_json(413,{'error':'WALLPAPER_MAX_8MB'})
                # Verify file signature; do not trust the supplied MIME type.
                valid=(ctype=='image/jpeg' and raw.startswith(b'\xff\xd8\xff')) or (ctype=='image/png' and raw.startswith(b'\x89PNG\r\n\x1a\n')) or (ctype=='image/webp' and raw[:4]==b'RIFF' and raw[8:12]==b'WEBP')
                if not valid: return self.send_json(400,{'error':'IMAGE_SIGNATURE_MISMATCH'})
                wid=str(uuid.uuid4()); ext={'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp'}[ctype]; target=WALLPAPER_DIR/(wid+ext); target.write_bytes(raw)
                scope=str(data.get('wallpaper_type','')).strip().lower()
                if scope not in ('lockscreen','desktop'): return self.send_json(400,{'error':'WALLPAPER_TYPE_REQUIRED'})
                lock=scope=='lockscreen'; desktop=scope=='desktop'; fit=str(data.get('fit_mode','cover'))
                if fit not in ('cover','contain','stretch','center'): target.unlink(missing_ok=True); return self.send_json(400,{'error':'INVALID_FIT_MODE'})
                db.execute('UPDATE wallpapers SET active=0 WHERE scope=?',(scope,)); db.execute('INSERT INTO wallpapers(scope,filename,content_type,file_path,lockscreen_enabled,desktop_enabled,fit_mode,created_at,active) VALUES (?,?,?,?,?,?,?,?,1)',(scope,filename,ctype,str(target),int(lock),int(desktop),fit,time.time()))
                db.execute('UPDATE wallpapers SET lockscreen_enabled=0 WHERE scope=\'global\'') if lock else None
                db.execute('UPDATE wallpapers SET desktop_enabled=0 WHERE scope=\'global\'') if desktop else None
                audit(db,'admin','wallpaper_uploaded',{'id':wid,'filename':filename,'lockscreen':lock,'desktop':desktop}); return self.send_json(201,{'ok':True,'id':db.execute('SELECT id FROM wallpapers WHERE file_path=?',(str(target),)).fetchone()['id']})
            if path == '/api/v2/security/pc/delete':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                pcid=str(data.get('pc_id','')); db.execute('DELETE FROM security_pc_overrides WHERE pc_id=?',(pcid,)); audit(db,'admin','security_pc_override_deleted',{'pc_id':pcid}); return self.send_json(200,{'ok':True})
            if path == '/api/v2/security/global':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                policy = data.get('policy')
                if not isinstance(policy,dict): return self.send_json(400, {'error':'POLICY_OBJECT_REQUIRED'})
                allowed = {'cmd','task_manager','registry_editor','windows_settings','control_panel','mmc','terminal','run_dialog','lock_directory','hide_app_directory','hidden_drives','task_scheduler_protection','service_management'}
                if set(policy)-allowed: return self.send_json(400, {'error':'UNKNOWN_POLICY_KEYS'})
                if any(k!='hidden_drives' and type(v) is not bool for k,v in policy.items()): return self.send_json(400, {'error':'POLICY_VALUES_MUST_BE_BOOLEAN'})
                policy.setdefault('hidden_drives',[])
                if not isinstance(policy['hidden_drives'],list) or any(x not in list('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for x in policy['hidden_drives']):
                    return self.send_json(400, {'error':'INVALID_HIDDEN_DRIVES'})
                db.execute('UPDATE security_global SET policy_json=?,updated_at=? WHERE id=1',(json.dumps(policy),time.time()))
                audit(db,'admin','security_global_updated',policy)
                return self.send_json(200, {'ok':True,'policy':policy})
            if path == '/api/v2/security/pc':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                pcid=str(data.get('pc_id','')); policy=data.get('policy')
                if not db.execute('SELECT 1 FROM pcs WHERE id=?',(pcid,)).fetchone(): return self.send_json(404, {'error':'PC_NOT_FOUND'})
                if not isinstance(policy,dict): return self.send_json(400, {'error':'POLICY_OBJECT_REQUIRED'})
                allowed={'cmd','task_manager','registry_editor','windows_settings','control_panel','mmc','terminal','run_dialog','lock_directory','hide_app_directory','hidden_drives','task_scheduler_protection','service_management'}
                if set(policy)-allowed: return self.send_json(400,{'error':'UNKNOWN_POLICY_KEYS'})
                if any(k!='hidden_drives' and type(v) is not bool for k,v in policy.items()): return self.send_json(400,{'error':'POLICY_VALUES_MUST_BE_BOOLEAN'})
                policy.setdefault('hidden_drives',[])
                if not isinstance(policy['hidden_drives'],list) or any(x not in list('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for x in policy['hidden_drives']): return self.send_json(400,{'error':'INVALID_HIDDEN_DRIVES'})
                db.execute('INSERT INTO security_pc_overrides(pc_id,policy_json,updated_at) VALUES (?,?,?) ON CONFLICT(pc_id) DO UPDATE SET policy_json=excluded.policy_json,updated_at=excluded.updated_at',(pcid,json.dumps(policy),time.time()))
                audit(db,'admin','security_pc_override_updated',{'pc_id':pcid,'policy':policy})
                return self.send_json(200, {'ok':True})
            if path == '/api/v2/telegram/outbox':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                rows=[dict(r) for r in db.execute('SELECT id,event_key,status,attempts,next_attempt_at,created_at,last_error FROM telegram_outbox ORDER BY id DESC LIMIT 100')]
                return self.send_json(200,{'items':rows})
            if path == '/api/v2/telegram':
                if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
                token=str(data.get('bot_token','')).strip(); chat=str(data.get('chat_id','')).strip()
                if not token: token=db.execute('SELECT bot_token FROM telegram_config WHERE id=1').fetchone()['bot_token']
                report_time=str(data.get('report_time','23:59')); timezone=str(data.get('timezone','Asia/Manila'))
                if len(token)>256 or len(chat)>128 or not __import__('re').fullmatch(r'\d{2}:\d{2}',report_time): return self.send_json(400, {'error':'INVALID_TELEGRAM_CONFIG'})
                try:
                    resolve_timezone(timezone)
                except Exception: return self.send_json(400,{'error':'INVALID_TIMEZONE'})
                db.execute('UPDATE telegram_config SET bot_token=?,chat_id=?,enabled=?,coin_alerts=?,daily_report=?,report_time=?,timezone=?,updated_at=? WHERE id=1',
                    (token,chat,int(bool(data.get('enabled'))),int(bool(data.get('coin_alerts',True))),int(bool(data.get('daily_report',True))),report_time,timezone,time.time()))
                audit(db,'admin','telegram_config_updated',{'enabled':bool(data.get('enabled')),'chat_id_set':bool(chat),'token_set':bool(token)})
                return self.send_json(200, {'ok':True,'token_configured':bool(token)})
            if path=='/api/maintenance/unlock':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                row=db.execute("SELECT value FROM settings WHERE key='maintenance_password_hash'").fetchone()
                stored=row['value'] if row else ''
                password=str(data.get('password',''))
                try:
                    salt, expected = stored.split('$',1)
                    actual=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),240000).hex()
                    valid=bool(password) and hmac.compare_digest(actual,expected)
                except Exception: valid=False
                if not valid:
                    audit(db,pc['id'],'maintenance_unlock_failed',{})
                    return self.send_json(403,{'error':'MAINTENANCE_PASSWORD_INVALID'})
                db.execute('INSERT INTO maintenance_sessions(pc_id,enabled,changed_at) VALUES (?,1,?) ON CONFLICT(pc_id) DO UPDATE SET enabled=1,changed_at=excluded.changed_at',(pc['id'],time.time()))
                db.execute('UPDATE pcs SET admin_locked=0 WHERE id=?',(pc['id'],))
                audit(db,pc['id'],'maintenance_unlocked',{})
                return self.send_json(200,{'ok':True,'maintenance_mode':True})
            if path=='/api/maintenance/lock':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                db.execute('INSERT INTO maintenance_sessions(pc_id,enabled,changed_at) VALUES (?,0,?) ON CONFLICT(pc_id) DO UPDATE SET enabled=0,changed_at=excluded.changed_at',(pc['id'],time.time()))
                db.execute('UPDATE pcs SET admin_locked=1 WHERE id=?',(pc['id'],))
                audit(db,pc['id'],'maintenance_locked',{})
                return self.send_json(200,{'ok':True,'maintenance_mode':False})
            if path=='/api/pcs/auto-register':
                # LAN-trust onboarding: no shared password. Every attempt is visible in Admin > Connection logs.
                device_uuid=str(data.get('device_uuid','')).strip()
                name=str(data.get('hostname','')).strip()
                raw_mac=str(data.get('mac_address','')).strip().upper().replace(':','').replace('-','').replace('.','')
                mac_address=':'.join(raw_mac[i:i+2] for i in range(0,12,2)) if len(raw_mac)==12 and all(c in '0123456789ABCDEF' for c in raw_mac) else ''
                source_ip=self.client_address[0] if self.client_address else ''
                if not device_uuid or len(device_uuid)>80 or not name or len(name)>120:
                    connection_log(db,None,name,source_ip,'AUTO_REGISTER','FAILED','DEVICE_ID_AND_HOSTNAME_REQUIRED')
                    return self.send_json(400,{'error':'DEVICE_ID_AND_HOSTNAME_REQUIRED'})
                now=time.time()
                row=db.execute('SELECT * FROM pcs WHERE device_uuid=?',(device_uuid,)).fetchone()
                if row:
                    db.execute("UPDATE pcs SET name=?,online=1,last_seen=?,archived=0,mac_address=CASE WHEN COALESCE(mac_address,'')='' THEN ? ELSE mac_address END WHERE id=?",(name,now,mac_address,row['id']))
                    pcid=row['id']; token=row['token']; outcome='RECONNECTED'; event='AUTO_RECONNECT'
                    audit(db,pcid,'pc_auto_reconnected',{'hostname':name})
                    saved_mac=row['mac_address'] or mac_address
                    mac_auto_filled=bool(mac_address and not row['mac_address'])
                else:
                    pcid='PC-'+secrets.token_hex(3).upper(); token=secrets.token_urlsafe(32)
                    db.execute('INSERT INTO pcs(id,name,token,created_at,last_seen,online,device_uuid,mac_address) VALUES (?,?,?,?,?,?,?,?)',(pcid,name,token,now,now,1,device_uuid,mac_address))
                    outcome='REGISTERED'; event='AUTO_REGISTER'
                    audit(db,pcid,'pc_auto_registered',{'hostname':name,'device_uuid':device_uuid})
                    saved_mac=mac_address
                    mac_auto_filled=bool(mac_address)
                mac_note='; MAC auto-filled' if mac_auto_filled else ('; existing MAC retained' if saved_mac else '; MAC unavailable from client')
                connection_log(db,pcid,name,source_ip,event,outcome,'Workstation registered successfully'+mac_note)
                return self.send_json(201,{'id':pcid,'name':name,'token':token,'registered':True,'mac_address':saved_mac})
            if path=='/api/pcs/register':
                if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
                name=str(data.get('name','')).strip()
                if not name: return self.send_json(400,{'error':'NAME_REQUIRED'})
                pcid='PC-'+secrets.token_hex(3).upper(); token=secrets.token_urlsafe(32); now=time.time()
                db.execute('INSERT INTO pcs(id,name,token,created_at) VALUES (?,?,?,?)',(pcid,name,token,now)); audit(db,'admin','pc_registered',{'pc_id':pcid,'name':name})
                return self.send_json(201,{'id':pcid,'name':name,'token':token})
            if path=='/api/coin-sessions/open':
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                existing=db.execute("SELECT cs.pc_id,p.name AS pc_name FROM coin_sessions cs LEFT JOIN pcs p ON p.id=cs.pc_id WHERE cs.status='inserting' LIMIT 1").fetchone()
                if existing:
                    return self.send_json(409,{'error':'COIN_SLOT_BUSY','reserved_for':existing['pc_name'] or existing['pc_id'],'reserved_for_pc_id':existing['pc_id']})
                if COIN_HARDWARE.port and not COIN_HARDWARE.connected:
                    return self.send_json(503,{'error':'COIN_SLOT_UNAVAILABLE','message':'The physical coin slot is not connected to the server.'})
                sid=str(uuid.uuid4()); now=time.time()
                db.execute("INSERT INTO coin_sessions(id,pc_id,status,started_at) VALUES (?,?,?,?)",(sid,pc['id'],'inserting',now)); audit(db,pc['id'],'coin_slot_reserved',{'session_id':sid})
                try: COIN_ENGINE.reserve(pc['id'],sid)
                except SignalError as e:
                    db.execute("UPDATE coin_sessions SET status='cancelled',finalized_at=? WHERE id=?",(time.time(),sid))
                    return self.send_json(409,{'error':str(e)})
                write_coin_event('slot_opened','success',pc['id'],pc['name'],sid)
                return self.send_json(201,{'session_id':sid,'status':'inserting','inactivity_seconds':INACTIVITY_SECONDS,'max_seconds':MAX_INSERT_SECONDS,'coin_input_mode':'serial' if COIN_HARDWARE.port else 'simulator','coin_hardware_connected':COIN_HARDWARE.connected})
            if path.startswith('/api/coin-sessions/') and path.endswith('/coin'):
                return self.send_json(410,{'error':'DENOMINATION_SHORTCUT_DISABLED','message':'Use raw pulse simulator events in Milestone 2D.'})
            if path=='/api/simulator/coin-train':
                if COIN_HARDWARE.port: return self.send_json(403,{'error':'SIMULATOR_DISABLED_WITH_COIN_HARDWARE'})
                # Deterministic simulator: one authenticated request represents a
                # complete electrical pulse train. Feed synthetic timed edges through
                # the same server decoder to avoid HTTP scheduling jitter.
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                sid=str(data.get('session_id',''))
                if COIN_ENGINE.owner != pc['id'] or COIN_ENGINE.session_id != sid:
                    return self.send_json(409,{'error':'COIN_SLOT_NOT_OWNED'})
                row=db.execute("SELECT * FROM coin_sessions WHERE id=? AND status='inserting'",(sid,)).fetchone()
                if row is None: return self.send_json(409,{'error':'COIN_SESSION_NOT_ACTIVE'})
                deadline=min((row['last_coin_at'] or row['started_at'])+INACTIVITY_SECONDS,row['started_at']+MAX_INSERT_SECONDS)
                if time.time() >= deadline: return self.send_json(409,{'error':'COIN_SESSION_DEADLINE_REACHED'})
                count=data.get('pulse_count')
                if type(count) is not int or count not in (1,5,10,20):
                    return self.send_json(400,{'error':'INVALID_SIMULATED_PULSE_COUNT','allowed':[1,5,10,20]})
                if COIN_ENGINE.high or COIN_ENGINE.last_fall is not None or COIN_ENGINE.widths:
                    return self.send_json(409,{'error':'SIMULATOR_TRAIN_IN_PROGRESS','engine':COIN_ENGINE.status()})
                try:
                    base=max(time.monotonic()*1000,(COIN_ENGINE.last_ms or 0)+1)
                    for index in range(count):
                        rise=base+index*(PULSE_WIDTH_MS+80)
                        COIN_ENGINE.edge(True,rise)
                        COIN_ENGINE.edge(False,rise+PULSE_WIDTH_MS)
                    end_ms=base+(count-1)*(PULSE_WIDTH_MS+80)+PULSE_WIDTH_MS+COIN_ENGINE.cfg.gap_ms
                    decoded=COIN_ENGINE.poll(end_ms)
                    row=db.execute('SELECT * FROM coin_sessions WHERE id=?',(sid,)).fetchone()
                    return self.send_json(200,{'decoded':decoded,'pulse_count':count,'session':session_view(row) if row else None,'engine':COIN_ENGINE.status()})
                except SignalError as e:
                    return self.send_json(409,{'error':str(e),'engine':COIN_ENGINE.status()})
            if path=='/api/simulator/poll':
                if COIN_HARDWARE.port: return self.send_json(403,{'error':'SIMULATOR_DISABLED_WITH_COIN_HARDWARE'})
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                sid=str(data.get('session_id',''))
                if COIN_ENGINE.owner != pc['id'] or COIN_ENGINE.session_id != sid:
                    return self.send_json(409,{'error':'COIN_SLOT_NOT_OWNED'})
                row=db.execute("SELECT * FROM coin_sessions WHERE id=? AND status='inserting'",(sid,)).fetchone()
                if row is None: return self.send_json(409,{'error':'COIN_SESSION_NOT_ACTIVE'})
                deadline=min((row['last_coin_at'] or row['started_at'])+INACTIVITY_SECONDS,row['started_at']+MAX_INSERT_SECONDS)
                if time.time() >= deadline: return self.send_json(409,{'error':'COIN_SESSION_DEADLINE_REACHED'})
                try:
                    decoded=COIN_ENGINE.poll(time.monotonic()*1000)
                    row=db.execute('SELECT * FROM coin_sessions WHERE id=?',(sid,)).fetchone()
                    return self.send_json(200,{'decoded':decoded,'session':session_view(row) if row else None,'engine':COIN_ENGINE.status()})
                except SignalError as e: return self.send_json(409,{'error':str(e)})
            if path=='/api/simulator/coin-edge':
                if COIN_HARDWARE.port: return self.send_json(403,{'error':'SIMULATOR_DISABLED_WITH_COIN_HARDWARE'})
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                sid=str(data.get('session_id',''))
                if COIN_ENGINE.owner != pc['id'] or COIN_ENGINE.session_id != sid:
                    return self.send_json(409,{'error':'COIN_SLOT_NOT_OWNED'})
                row=db.execute('SELECT * FROM coin_sessions WHERE id=? AND status=\'inserting\'',(sid,)).fetchone()
                if row is None: return self.send_json(409,{'error':'COIN_SESSION_NOT_ACTIVE'})
                deadline=min((row['last_coin_at'] or row['started_at'])+INACTIVITY_SECONDS,row['started_at']+MAX_INSERT_SECONDS)
                if time.time() >= deadline: return self.send_json(409,{'error':'COIN_SESSION_DEADLINE_REACHED'})
                level=data.get('high')
                if not isinstance(level,bool): return self.send_json(400,{'error':'BOOLEAN_HIGH_REQUIRED'})
                try:
                    now_ms=time.monotonic()*1000
                    edge=COIN_ENGINE.edge(level,now_ms)
                    decoded=COIN_ENGINE.poll(now_ms)
                    row=db.execute('SELECT * FROM coin_sessions WHERE id=?',(sid,)).fetchone()
                    return self.send_json(200,{'edge':edge,'decoded':decoded,'session':session_view(row) if row else None,'engine':COIN_ENGINE.status()})
                except SignalError as e: return self.send_json(409,{'error':str(e)})
            if path.startswith('/api/coin-sessions/') and path.endswith('/cancel'):
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                sid=path.split('/')[-2]
                row=db.execute('SELECT * FROM coin_sessions WHERE id=? AND pc_id=?',(sid,pc['id'])).fetchone()
                if not row: return self.send_json(404,{'error':'COIN_SESSION_NOT_FOUND'})
                if row['status']!='inserting': return self.send_json(409,{'error':'COIN_SESSION_NOT_ACTIVE'})
                if row['amount_centavos']>0:
                    return self.send_json(409,{'error':'COIN_SESSION_HAS_CREDIT','amount_centavos':row['amount_centavos']})
                try:
                    COIN_ENGINE.cancel_if_idle(sid)
                except SignalError as e:
                    return self.send_json(409,{'error':str(e)})
                # Re-read after the decoder lock is released so a pulse train
                # that completed concurrently cannot be canceled without credit.
                with LOCK, connect() as cancel_db:
                    row=cancel_db.execute('SELECT * FROM coin_sessions WHERE id=? AND pc_id=?',(sid,pc['id'])).fetchone()
                    if not row: return self.send_json(404,{'error':'COIN_SESSION_NOT_FOUND'})
                    if row['status']!='inserting': return self.send_json(409,{'error':'COIN_SESSION_NOT_ACTIVE'})
                    if row['amount_centavos']>0:
                        has_credit=True
                    else:
                        cancel_db.execute("UPDATE coin_sessions SET status='cancelled',finalized_at=? WHERE id=?",(time.time(),sid))
                        audit(cancel_db,pc['id'],'coin_session_cancelled',{'session_id':sid,'reason':'user_cancelled'})
                        has_credit=False
                if has_credit:
                    try: COIN_ENGINE.reserve(pc['id'],sid)
                    except SignalError: pass
                    return self.send_json(409,{'error':'COIN_SESSION_HAS_CREDIT','amount_centavos':row['amount_centavos']})
                pc_name=db.execute('SELECT name FROM pcs WHERE id=?',(pc['id'],)).fetchone()
                write_coin_event('insertion_ended','cancelled',pc['id'],pc_name['name'] if pc_name else pc['id'],sid)
                return self.send_json(200,{'ok':True,'status':'cancelled','session_id':sid})
            if path.startswith('/api/coin-sessions/') and path.endswith('/done'):
                pc=self.client(db)
                if not pc: return self.send_json(401,{'error':'CLIENT_AUTH_REQUIRED'})
                sid=path.split('/')[-2]; own=db.execute('SELECT 1 FROM coin_sessions WHERE id=? AND pc_id=?',(sid,pc['id'])).fetchone()
                if not own: return self.send_json(404,{'error':'COIN_SESSION_NOT_FOUND'})
        if path.startswith('/api/coin-sessions/') and path.endswith('/done'):
            try:
                # A physical coin pulse is only credited after the decoder's
                # inter-pulse gap has elapsed. Do not finalize (and release)
                # while that train is still being assembled.
                if COIN_ENGINE.session_id == sid:
                    COIN_ENGINE.poll(time.monotonic()*1000)
                    engine_state=COIN_ENGINE.status()
                    if engine_state['coin_line_high'] or engine_state['pulse_train_open']:
                        return self.send_json(409,{'error':'COIN_PULSE_IN_PROGRESS','engine':engine_state})
                result=finalize(sid,'done')
                if COIN_ENGINE.session_id == sid: COIN_ENGINE.release(sid)
                return self.send_json(200,result)
            except ValueError as e:
                with connect() as log_db:
                    pc_name=log_db.execute('SELECT p.id,p.name FROM coin_sessions c JOIN pcs p ON p.id=c.pc_id WHERE c.id=?',(sid,)).fetchone()
                    if pc_name: write_coin_event('credit_failed','failed',pc_name['id'],pc_name['name'],sid,details=str(e))
                return self.send_json(409,{'error':str(e)})
            except Exception as e:
                with connect() as log_db:
                    pc_name=log_db.execute('SELECT p.id,p.name FROM coin_sessions c JOIN pcs p ON p.id=c.pc_id WHERE c.id=?',(sid,)).fetchone()
                    if pc_name: write_coin_event('credit_failed','failed',pc_name['id'],pc_name['name'],sid,details=str(e))
                return self.send_json(500,{'error':'COIN_CREDIT_FAILED','detail':str(e)[:240]})
        return self.send_json(404,{'error':'NOT_FOUND'})
    def do_DELETE(self):
        path=urlparse(self.path).path
        if path == '/api/settings/insert-sound':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            with LOCK, connect() as db:
                values={r['key']:r['value'] for r in db.execute("SELECT key,value FROM settings WHERE key IN ('insert_sound_id','insert_sound_filename','insert_sound_file_path')")}
                db.execute("DELETE FROM settings WHERE key IN ('insert_sound_id','insert_sound_filename','insert_sound_content_type','insert_sound_file_path')")
                audit(db,'admin','insert_sound_removed',{'filename':values.get('insert_sound_filename','')})
            if values.get('insert_sound_file_path'):
                sound_path=Path(values['insert_sound_file_path'])
                if sound_path.resolve().parent==INSERT_SOUND_DIR.resolve():
                    try: sound_path.unlink(missing_ok=True)
                    except OSError: pass
            return self.send_json(200,{'ok':True})
        if path.startswith('/api/v2/client-builds/'):
            if not self.admin(): return self.send_json(401, {'error':'ADMIN_LOGIN_REQUIRED'})
            build_id=path.rsplit('/',1)[-1]
            if not build_id.isdigit(): return self.send_json(400,{'error':'INVALID_CLIENT_BUILD_ID'})
            with connect() as db:
                row=db.execute('SELECT id,version,filename,file_path,active FROM client_builds WHERE id=?',(int(build_id),)).fetchone()
                if not row: return self.send_json(404,{'error':'CLIENT_BUILD_NOT_FOUND'})
                if row['active']: return self.send_json(409,{'error':'CANNOT_DELETE_ACTIVE_CLIENT_BUILD','message':'Upload another build or deactivate this one before removing it.'})
                db.execute('DELETE FROM client_builds WHERE id=?',(int(build_id),))
                audit(db,'admin','client_build_deleted',{'id':row['id'],'version':row['version'],'filename':row['filename']})
                file_path=row['file_path']
            try: Path(file_path).unlink(missing_ok=True)
            except OSError: pass
            return self.send_json(200,{'ok':True,'id':int(build_id)})
        if path.startswith('/api/v2/wallpapers/'):
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            wid=path.rsplit('/',1)[-1]
            with connect() as db:
                row=db.execute('SELECT file_path FROM wallpapers WHERE id=?',(wid,)).fetchone()
                if not row: return self.send_json(404,{'error':'WALLPAPER_NOT_FOUND'})
                db.execute('UPDATE wallpapers SET active=0 WHERE id=?',(wid,)); audit(db,'admin','wallpaper_deactivated',{'id':wid})
                try: Path(row['file_path']).unlink(missing_ok=True)
                except OSError: pass
            return self.send_json(200,{'ok':True})
        return self.send_json(404,{'error':'NOT_FOUND'})

    def do_PUT(self):
        path=urlparse(self.path).path
        if path=='/api/v2/workstations/mac-address':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_LOGIN_REQUIRED'})
            try: data=self.body()
            except Exception: return self.send_json(400,{'error':'INVALID_JSON'})
            pcid=str(data.get('pc_id','')).strip(); raw=str(data.get('mac_address','')).strip().upper().replace(':','').replace('-','').replace('.','')
            if len(raw)!=12 or any(c not in '0123456789ABCDEF' for c in raw): return self.send_json(400,{'error':'INVALID_MAC_ADDRESS'})
            mac=':'.join(raw[i:i+2] for i in range(0,12,2))
            with LOCK, connect() as db:
                if not db.execute('SELECT 1 FROM pcs WHERE id=? AND archived=0',(pcid,)).fetchone(): return self.send_json(404,{'error':'WORKSTATION_NOT_FOUND'})
                db.execute('UPDATE pcs SET mac_address=? WHERE id=?',(mac,pcid)); audit(db,'admin','workstation_mac_updated',{'pc_id':pcid,'mac_address':mac})
            return self.send_json(200,{'ok':True,'pc_id':pcid,'mac_address':mac})
        if path=='/api/settings/shop-branding':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
            try: data=self.body()
            except Exception: return self.send_json(400,{'error':'INVALID_JSON'})
            shop_name=data.get('shop_name','')
            shop_subtext=data.get('shop_subtext','')
            font=str(data.get('shop_name_font','system')).strip().lower()
            size=data.get('shop_name_size',28)
            allowed_fonts={'system','arial','verdana','tahoma','trebuchet','georgia','times'}
            if not isinstance(shop_name,str) or len(shop_name.strip())>60 or any(ord(c)<32 for c in shop_name):
                return self.send_json(400,{'error':'SHOP_NAME_MUST_BE_0_TO_60_PRINTABLE_CHARACTERS'})
            if not isinstance(shop_subtext,str) or len(shop_subtext.strip())>100 or any(ord(c)<32 for c in shop_subtext):
                return self.send_json(400,{'error':'SHOP_SUBTEXT_MUST_BE_0_TO_100_PRINTABLE_CHARACTERS'})
            if font not in allowed_fonts: return self.send_json(400,{'error':'INVALID_SHOP_NAME_FONT'})
            if not isinstance(size,int) or isinstance(size,bool) or not 12<=size<=56:
                return self.send_json(400,{'error':'SHOP_NAME_SIZE_MUST_BE_12_TO_56'})
            shop_name=shop_name.strip()
            shop_subtext=shop_subtext.strip()
            with LOCK, connect() as db:
                for key,value in (('shop_name',shop_name),('shop_subtext',shop_subtext),('shop_name_font',font),('shop_name_size',str(size))):
                    db.execute('INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(key,value))
                audit(db,'admin','shop_branding_updated',{'shop_name':shop_name,'shop_subtext':shop_subtext,'font':font,'size':size})
            return self.send_json(200,{'ok':True,'shop_name':shop_name,'shop_subtext':shop_subtext,'shop_name_font':font,'shop_name_size':size})
        if path=='/api/settings/maintenance-password':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
            try: password=str(self.body().get('password',''))
            except Exception: return self.send_json(400,{'error':'INVALID_JSON'})
            if len(password)<8 or len(password)>128: return self.send_json(400,{'error':'MAINTENANCE_PASSWORD_LENGTH_8_TO_128'})
            salt=secrets.token_bytes(16)
            digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,240000).hex()
            with connect() as db:
                db.execute("INSERT INTO settings(key,value) VALUES ('maintenance_password_hash',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(salt.hex()+'$'+digest,))
                audit(db,'admin','maintenance_password_updated',{})
            return self.send_json(200,{'ok':True})
        if path=='/api/settings/uninstall-password':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
            try: password=str(self.body().get('password',''))
            except Exception: return self.send_json(400,{'error':'INVALID_JSON'})
            if len(password)<8 or len(password)>128: return self.send_json(400,{'error':'UNINSTALL_PASSWORD_LENGTH_8_TO_128'})
            salt=secrets.token_bytes(16)
            digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,240000).hex()
            with connect() as db:
                db.execute("INSERT INTO settings(key,value) VALUES ('uninstall_password_hash',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(salt.hex()+'$'+digest,))
                audit(db,'admin','uninstall_password_updated',{})
            return self.send_json(200,{'ok':True})
        if path=='/api/settings/insert-countdown':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
            try: seconds=self.body().get('insert_countdown_seconds')
            except Exception: return self.send_json(400,{'error':'INVALID_JSON'})
            if not isinstance(seconds,int) or not 15<=seconds<=600:
                return self.send_json(400,{'error':'INVALID_INSERT_COUNTDOWN','message':'Use 15 to 600 seconds.'})
            with connect() as db:
                db.execute("INSERT INTO settings(key,value) VALUES ('insert_countdown_seconds',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(str(seconds),))
                audit(db,'admin','insert_countdown_updated',{'seconds':seconds})
            return self.send_json(200,{'ok':True,'insert_countdown_seconds':seconds})
        if path=='/api/settings/shutdown-countdown':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
            try: minutes=self.body().get('shutdown_countdown_minutes')
            except Exception: return self.send_json(400,{'error':'INVALID_JSON'})
            if not isinstance(minutes,int) or isinstance(minutes,bool) or not 1<=minutes<=60:
                return self.send_json(400,{'error':'SHUTDOWN_COUNTDOWN_MUST_BE_1_TO_60'})
            with connect() as db:
                db.execute("INSERT INTO settings(key,value) VALUES ('shutdown_countdown_minutes',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(str(minutes),))
                audit(db,'admin','shutdown_countdown_updated',{'minutes':minutes})
            return self.send_json(200,{'ok':True,'shutdown_countdown_minutes':minutes})
        if path=='/api/settings/offline-session-timeout':
            if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
            try: minutes=self.body().get('offline_session_timeout_minutes')
            except Exception: return self.send_json(400,{'error':'INVALID_JSON'})
            if not isinstance(minutes,int) or isinstance(minutes,bool) or not 1<=minutes<=1440:
                return self.send_json(400,{'error':'OFFLINE_SESSION_TIMEOUT_MUST_BE_1_TO_1440'})
            with connect() as db:
                db.execute("INSERT INTO settings(key,value) VALUES ('offline_session_timeout_minutes',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(str(minutes),))
                audit(db,'admin','offline_session_timeout_updated',{'minutes':minutes})
            return self.send_json(200,{'ok':True,'offline_session_timeout_minutes':minutes})
        if path!='/api/rates': return self.send_json(404,{'error':'NOT_FOUND'})
        if not self.admin(): return self.send_json(401,{'error':'ADMIN_AUTH_REQUIRED'})
        try: rates=self.body().get('rates',[])
        except Exception: return self.send_json(400,{'error':'INVALID_JSON'})
        if not rates or any(not isinstance(x.get('denomination_centavos'),int) or not isinstance(x.get('seconds'),int) or x['denomination_centavos']<=0 or x['seconds']<0 for x in rates): return self.send_json(400,{'error':'INVALID_RATES'})
        with connect() as db:
            db.execute('DELETE FROM rate_rules')
            db.executemany('INSERT INTO rate_rules VALUES (?,?)',[(x['denomination_centavos'],x['seconds']) for x in rates]); audit(db,'admin','rates_updated',{'rates':rates})
        return self.send_json(200,{'ok':True,'rates':rates})
    def serve_file(self,path):
        try: body=path.read_bytes()
        except OSError: return self.send_json(404,{'error':'UI_NOT_FOUND'})
        self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.send_header('Pragma','no-cache'); self.send_header('Expires','0'); self.end_headers(); self.wfile.write(body)

def restore_engine_reservation():
    # A persisted insertion reservation remains exclusive after process restart.
    with connect() as db:
        row=db.execute("SELECT id,pc_id FROM coin_sessions WHERE status='inserting' ORDER BY started_at LIMIT 1").fetchone()
    if row:
        try: COIN_ENGINE.restore_reservation_inhibited(row['pc_id'],row['id'])
        except SignalError: pass


if __name__=='__main__':
    init_db(); restore_engine_reservation(); COIN_HARDWARE.start(); threading.Thread(target=timer_loop,daemon=True).start(); threading.Thread(target=discovery_loop,daemon=True).start(); threading.Thread(target=telegram_worker,daemon=True).start()
    print(f'PisoNet server listening on http://{HOST}:{PORT} (LAN discovery UDP 3211)')
    if COIN_HARDWARE.port:
        print(f'Coin slot serial input configured on {COIN_HARDWARE.port} ({COIN_HARDWARE.input_line}); hardware status: {COIN_HARDWARE.status()}')
    else:
        print('Coin slot hardware not configured; server is in simulator-only coin input mode.')
    print('Admin access: use the V2 username/password login at /admin. Legacy X-Admin-Token compatibility is disabled by default.')
    print('Startup recovery: any pending coin session is restored with coin input INHIBITED until its owner finalizes it.')
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
