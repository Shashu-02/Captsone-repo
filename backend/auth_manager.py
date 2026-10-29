"""SQLite auth and approval helpers for the local capstone demo."""
import hashlib, hmac, os, secrets, sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "backend" / "users.sqlite3"
ITERATIONS = 310_000

def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def initialize():
    with _connect() as con:
        con.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY COLLATE NOCASE, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','sender','receiver')), status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','revoked')), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_by TEXT, reviewed_at TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        con.execute("CREATE TABLE IF NOT EXISTS receiver_public_keys (username TEXT PRIMARY KEY COLLATE NOCASE, ecdh_public_pem TEXT NOT NULL, fingerprint TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE)")

def _hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), ITERATIONS).hex()

def _event(con, username, action, details=''):
    con.execute('INSERT INTO events(username, action, details) VALUES(?,?,?)', (username, action, details[:500]))

def create_admin(username, password):
    initialize()
    username = username.strip()
    if len(username) < 3 or len(password) < 12:
        raise ValueError('Admin username must be at least 3 characters and password at least 12 characters.')
    salt = secrets.token_hex(16)
    with _connect() as con:
        count = con.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        if count:
            raise ValueError('An admin already exists. Do not recreate or overwrite it.')
        con.execute('INSERT INTO users(username,password_salt,password_hash,role,status) VALUES(?,?,?,?,?)', (username,salt,_hash(password,salt),'admin','approved'))
        _event(con, username, 'admin_created', 'Initial administrator provisioned')

def register_user(username, password, role):
    initialize()
    username = username.strip()
    if role not in ('sender','receiver'):
        raise ValueError('Invalid client role.')
    if len(username) < 3 or len(username) > 64 or not all(c.isalnum() or c in '._-' for c in username):
        raise ValueError('Username must be 3–64 characters and use letters, numbers, dot, underscore or hyphen.')
    if len(password) < 10:
        raise ValueError('Password must be at least 10 characters.')
    salt = secrets.token_hex(16)
    try:
        with _connect() as con:
            con.execute('INSERT INTO users(username,password_salt,password_hash,role,status) VALUES(?,?,?,?,?)', (username,salt,_hash(password,salt),role,'pending'))
            _event(con, username, 'registration', f'Role={role}; status=pending')
    except sqlite3.IntegrityError:
        raise ValueError('That username is already registered.')

def authenticate(username, password):
    initialize()
    with _connect() as con:
        row = con.execute('SELECT * FROM users WHERE username=?', (username.strip(),)).fetchone()
        if not row or not hmac.compare_digest(row['password_hash'], _hash(password, row['password_salt'])):
            _event(con, username.strip(), 'login_failed', 'Invalid credentials')
            return None
        _event(con, row['username'], 'login', f"status={row['status']}")
        return dict(row)

def get_user(username):
    initialize()
    with _connect() as con:
        row=con.execute('SELECT username,role,status,created_at,reviewed_by,reviewed_at FROM users WHERE username=?',(username,)).fetchone()
        return dict(row) if row else None

def list_users():
    initialize()
    with _connect() as con:
        return [dict(r) for r in con.execute('SELECT username,role,status,created_at,reviewed_by,reviewed_at FROM users ORDER BY created_at DESC')]

def review_user(username, status, admin_username):
    if status not in ('approved','rejected','revoked'):
        raise ValueError('Invalid review action.')
    with _connect() as con:
        row=con.execute('SELECT role,status FROM users WHERE username=?',(username,)).fetchone()
        if not row or row['role']=='admin':
            raise ValueError('Client not found or cannot modify administrator account.')
        con.execute('UPDATE users SET status=?, reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP WHERE username=?',(status,admin_username,username))
        _event(con, username, f'account_{status}', f'Reviewed by {admin_username}')

def list_events(limit=300):
    initialize()
    with _connect() as con:
        return [dict(r) for r in con.execute('SELECT id,username,action,details,created_at FROM events ORDER BY id DESC LIMIT ?', (int(limit),))]

def log_event(username, action, details=''):
    with _connect() as con: _event(con, username, action, details)

def ensure_identity(role, key_dir, generator):
    """Create an identity only if incomplete; never overwrite keys automatically."""
    key_dir=Path(key_dir)
    names = [f'{role}_ecdh_private.pem', f'{role}_ecdh_public.pem', f'{role}_sign_private.pem', f'{role}_sign_public.pem']
    if not all((key_dir/n).exists() for n in names):
        generator(role)
        log_event(None, 'identity_provisioned', f'role={role}; key_dir={key_dir.name}')

if __name__ == '__main__':
    import getpass
    import sys
    if len(sys.argv) != 2 or sys.argv[1] != 'create-admin':
        print('Usage: python backend/auth_manager.py create-admin'); raise SystemExit(2)
    username=input('Admin username: ').strip()
    password=getpass.getpass('Admin password (minimum 12 characters): ')
    create_admin(username,password)
    print('Administrator created. Keep the password secure.')


def publish_receiver_public_key(username, public_pem):
    """Register a receiver's public ECDH key for approved senders to discover."""
    initialize()
    pem = public_pem.decode("utf-8") if isinstance(public_pem, bytes) else str(public_pem)
    fingerprint = hashlib.sha256(pem.encode("utf-8")).hexdigest()
    with _connect() as con:
        row = con.execute("SELECT role,status FROM users WHERE username=?", (username,)).fetchone()
        if not row or row["role"] != "receiver" or row["status"] != "approved":
            raise ValueError("Only approved receiver accounts can publish a public key.")
        con.execute("INSERT INTO receiver_public_keys(username,ecdh_public_pem,fingerprint,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(username) DO UPDATE SET ecdh_public_pem=excluded.ecdh_public_pem,fingerprint=excluded.fingerprint,updated_at=CURRENT_TIMESTAMP", (username,pem,fingerprint))
        _event(con, username, "receiver_public_key_published", f"fingerprint={fingerprint}")

def list_approved_receiver_public_keys():
    initialize()
    with _connect() as con:
        rows = con.execute("SELECT u.username, r.ecdh_public_pem, r.fingerprint FROM users u JOIN receiver_public_keys r ON r.username=u.username WHERE u.role='receiver' AND u.status='approved' ORDER BY u.username COLLATE NOCASE").fetchall()
        return [dict(r) for r in rows]
