#!/usr/bin/env python3
"""STRIKER PACKS online server — Python stdlib only (no pip install needed).
Run:  python3 server.py      (env: PORT=8000  DB_PATH=./game.db  TRUST_PROXY=1 behind a proxy)"""
import json, os, re, sqlite3, secrets, hashlib, hmac, time, threading, queue
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote, parse_qs

ROOT = os.path.dirname(os.path.abspath(__file__))
DBP = os.environ.get('DB_PATH', os.path.join(ROOT, 'game.db'))
PORT = int(os.environ.get('PORT', '8000'))
PROXY = os.environ.get('TRUST_PROXY') == '1'
NAME = re.compile(r'^[\w\u0E00-\u0E7F]{2,12}$')
COOLDOWN, DAILY_CAP, GAIN = 1800, 30, {'w': 3, 'd': 1, 'l': 0}

lock = threading.Lock()
con = sqlite3.connect(DBP, check_same_thread=False)
con.row_factory = sqlite3.Row
con.executescript('''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, lc TEXT UNIQUE, salt TEXT, pw TEXT, av TEXT DEFAULT '😎',
  lv INT DEFAULT 1, power INT DEFAULT 0, points INT DEFAULT 0, created REAL);
CREATE TABLE IF NOT EXISTS sess(tok TEXT PRIMARY KEY, uid INT, exp REAL);
CREATE TABLE IF NOT EXISTS saves(uid INT PRIMARY KEY, data TEXT, n INT, lineup TEXT, upd REAL);
CREATE TABLE IF NOT EXISTS friends(uid INT, fid INT, PRIMARY KEY(uid, fid));
CREATE TABLE IF NOT EXISTS ch(uid INT, tid INT, t REAL);
''')
hits = {}  # ip -> [timestamps] for login/register throttling
streams, invites, matches, chat, lastmsg, paired = {}, {}, {}, [], {}, {}

def cleanav(a):
    return re.sub(r'[<>&"\'`\\]', '', str(a))[:8] or '😎'

def hashpw(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(salt), 200000).hex()

def throttle(ip, limit, window):
    now = time.time(); l = [t for t in hits.get(ip, []) if now - t < window]
    hits[ip] = l
    if len(l) >= limit: return False
    l.append(now); return True

class H(BaseHTTPRequestHandler):
    server_version = 'Striker/1'
    def log_message(self, *a): pass
    def ip(self):
        if PROXY: return (self.headers.get('X-Forwarded-For', '') or self.client_address[0]).split(',')[0].strip()
        return self.client_address[0]
    def out(self, o, c=200):
        b = json.dumps(o, ensure_ascii=False).encode()
        self.send_response(c)
        for k, v in (('Content-Type', 'application/json; charset=utf-8'), ('Content-Length', str(len(b))),
                     ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff')): self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)
    def err(self, msg, c=400): self.out({'ok': 0, 'err': msg}, c)
    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > 400000: raise ValueError('too big')
        return json.loads(self.rfile.read(n) or b'{}')
    def user(self):
        a = self.headers.get('Authorization', '')
        tok = a[7:] if a.startswith('Bearer ') else (parse_qs(urlparse(self.path).query).get('token') or [''])[0]
        if not tok: return None
        with lock:
            return con.execute('SELECT u.* FROM sess s JOIN users u ON u.id=s.uid WHERE s.tok=? AND s.exp>?', (tok, time.time())).fetchone()
    def newsess(self, uid):
        tok = secrets.token_urlsafe(32)
        with lock:
            con.execute('DELETE FROM sess WHERE exp<?', (time.time(),))
            con.execute('INSERT INTO sess VALUES(?,?,?)', (tok, uid, time.time() + 30 * 864e2)); con.commit()
        return tok
    def find(self, name):
        with lock: return con.execute('SELECT * FROM users WHERE lc=?', (str(name).strip().lower(),)).fetchone()
    def pub(self, r): return {k: r[k] for k in ('name', 'av', 'lv', 'power', 'points')}

    def do_GET(self): self.route('GET')
    def do_POST(self): self.route('POST')
    def do_PUT(self): self.route('PUT')

    def route(self, m):
        p = urlparse(self.path).path
        try:
            if m == 'GET' and p in ('/', '/index.html'):
                b = open(os.path.join(ROOT, 'index.html'), 'rb').read()
                self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(b))); self.end_headers(); return self.wfile.write(b)
            if p == '/api/ping': return self.out({'ok': 1})
            if p == '/api/register' and m == 'POST': return self.register()
            if p == '/api/login' and m == 'POST': return self.login()
            u = self.user()
            if not u: return self.err('กรุณาเข้าสู่ระบบ', 401)
            if p == '/api/me': return self.me(u)
            if p == '/api/save' and m == 'PUT': return self.save(u)
            if p == '/api/board': return self.board()
            if p.startswith('/api/user/'):
                r = self.find(unquote(p[10:]))
                return self.out({'ok': 1, 'user': self.pub(r)}) if r else self.err('ไม่พบผู้เล่นชื่อนี้', 404)
            if p == '/api/friends' and m == 'GET': return self.friends(u)
            if p == '/api/friends/add' and m == 'POST': return self.addfriend(u)
            if p.startswith('/api/lineup/'): return self.lineup(u, unquote(p[12:]))
            if p == '/api/challenge' and m == 'POST': return self.challenge(u)
            if p == '/api/rename' and m == 'POST': return self.rename(u)
            if p == '/api/logout' and m == 'POST':
                with lock: con.execute('DELETE FROM sess WHERE tok=?', (self.headers['Authorization'][7:],)); con.commit()
                return self.out({'ok': 1})
            if p == '/api/rt/stream': return self.stream(u)
            if p == '/api/rt/online': return self.online()
            if p == '/api/rt/chat' and m == 'GET': return self.out({'ok': 1, 'rows': chat[-50:]})
            if p == '/api/rt/chat' and m == 'POST': return self.chatpost(u)
            if p == '/api/rt/invite' and m == 'POST': return self.invite(u)
            if p == '/api/rt/answer' and m == 'POST': return self.answer(u)
            if p == '/api/rt/result' and m == 'POST': return self.result(u)
            self.err('ไม่พบหน้านี้', 404)
        except Exception:
            self.err('คำขอไม่ถูกต้อง')

    def register(self):
        if not throttle('r' + self.ip(), 8, 3600): return self.err('สมัครบ่อยเกินไป ลองใหม่ภายหลัง', 429)
        d = self.body(); name = str(d.get('name', '')).strip(); pw = str(d.get('pw', '')); av = cleanav(d.get('av', '😎'))
        if not NAME.match(name): return self.err('ชื่อต้อง 2-12 ตัว (ตัวอักษร/เลข/_)')
        if not 6 <= len(pw) <= 100: return self.err('รหัสผ่านต้อง 6 ตัวขึ้นไป')
        salt = secrets.token_hex(16)
        try:
            with lock:
                c = con.execute('INSERT INTO users(name,lc,salt,pw,av,created) VALUES(?,?,?,?,?,?)', (name, name.lower(), salt, hashpw(pw, salt), av, time.time()))
                uid = c.lastrowid; con.commit()
        except sqlite3.IntegrityError:
            return self.err('ชื่อนี้ถูกใช้แล้ว')
        self.out({'ok': 1, 'token': self.newsess(uid), 'name': name, 'av': av, 'save': None})

    def login(self):
        if not throttle('l' + self.ip(), 10, 300): return self.err('ลองบ่อยเกินไป รอสักครู่', 429)
        d = self.body(); r = self.find(d.get('name', ''))
        if not r or not hmac.compare_digest(hashpw(str(d.get('pw', '')), r['salt']), r['pw']): return self.err('ชื่อหรือรหัสผ่านไม่ถูกต้อง', 401)
        self.me(r, self.newsess(r['id']))

    def me(self, u, tok=None):
        with lock: s = con.execute('SELECT data FROM saves WHERE uid=?', (u['id'],)).fetchone()
        o = {'ok': 1, 'name': u['name'], 'av': u['av'], 'save': json.loads(s['data']) if s else None}
        if tok: o['token'] = tok
        self.out(o)

    def save(self, u):
        d = self.body(); data = d.get('data')
        if not isinstance(data, dict): return self.err('ข้อมูลไม่ถูกต้อง')
        own = data.get('own') if isinstance(data.get('own'), dict) else {}
        lu = d.get('lineup') or {}
        ids = [i for i in (lu.get('ids') or []) if isinstance(i, int) and own.get(str(i), 0) > 0][:11]
        up = {k: v for k, v in (lu.get('up') or {}).items() if k in own and isinstance(v, int) and 0 <= v <= 5}
        fo = {k: v for k, v in (lu.get('fo') or {}).items() if k in own and isinstance(v, int) and -3 <= v <= 3}
        lineup = json.dumps({'fm': str(lu.get('fm', '4-3-3'))[:8], 'ids': ids, 'up': up, 'fo': fo})
        power = max(0, min(1100, int(d.get('power') or 0))); lv = max(1, min(999, int(d.get('lv') or 1)))
        with lock:
            con.execute('INSERT INTO saves VALUES(?,?,?,?,?) ON CONFLICT(uid) DO UPDATE SET data=?,n=?,lineup=?,upd=?',
                        (u['id'], json.dumps(data), int(d.get('n') or 0), lineup, time.time(), json.dumps(data), int(d.get('n') or 0), lineup, time.time()))
            con.execute('UPDATE users SET lv=?,power=?,av=? WHERE id=?', (lv, power, cleanav(d.get('av', u['av'])), u['id'])); con.commit()
        self.out({'ok': 1})

    def board(self):
        by = 'points' if 'by=points' in (self.path or '') else 'power'
        with lock: rows = con.execute(f'SELECT name,av,lv,power,points FROM users ORDER BY {by} DESC LIMIT 20').fetchall()
        self.out({'ok': 1, 'rows': [self.pub(r) for r in rows]})

    def friends(self, u):
        with lock: rows = con.execute('SELECT x.* FROM friends f JOIN users x ON x.id=f.fid WHERE f.uid=? ORDER BY x.power DESC', (u['id'],)).fetchall()
        self.out({'ok': 1, 'points': u['points'], 'rows': [self.pub(r) for r in rows]})

    def addfriend(self, u):
        r = self.find(self.body().get('name', ''))
        if not r: return self.err('ไม่พบผู้เล่นชื่อนี้')
        if r['id'] == u['id']: return self.err('เพิ่มตัวเองไม่ได้')
        with lock: con.execute('INSERT OR IGNORE INTO friends VALUES(?,?)', (u['id'], r['id'])); con.commit()
        self.out({'ok': 1})

    def lineup(self, u, name):
        r = self.find(name)
        if not r: return self.err('ไม่พบผู้เล่นชื่อนี้', 404)
        with lock:
            s = con.execute('SELECT lineup FROM saves WHERE uid=?', (r['id'],)).fetchone()
            c = con.execute('SELECT MAX(t) t FROM ch WHERE uid=? AND tid=?', (u['id'], r['id'])).fetchone()
        L = json.loads(s['lineup']) if s and s['lineup'] else None
        if not L or len(L['ids']) < 11: return self.err('ทีมของผู้เล่นคนนี้ยังไม่พร้อม')
        wait = max(0, int((c['t'] or 0) + COOLDOWN - time.time()))
        self.out({'ok': 1, 'lineup': L, 'wait': wait, 'user': self.pub(r)})

    def challenge(self, u):
        d = self.body(); r = self.find(d.get('target', '')); res = d.get('res')
        if not r or r['id'] == u['id'] or res not in GAIN: return self.err('ท้าไม่ได้')
        now = time.time()
        with lock:
            last = con.execute('SELECT MAX(t) t FROM ch WHERE uid=? AND tid=?', (u['id'], r['id'])).fetchone()['t'] or 0
            cnt = con.execute('SELECT COUNT(*) c FROM ch WHERE uid=? AND t>?', (u['id'], now - 864e2)).fetchone()['c']
            if now - last < COOLDOWN: return self.err('ท้าคนนี้ได้อีกครั้งในอีกสักพัก')
            if cnt >= DAILY_CAP: return self.err('ท้าครบโควตารายวันแล้ว')
            con.execute('INSERT INTO ch VALUES(?,?,?)', (u['id'], r['id'], now))
            con.execute('UPDATE users SET points=points+? WHERE id=?', (GAIN[res], u['id'])); con.commit()
            pts = con.execute('SELECT points FROM users WHERE id=?', (u['id'],)).fetchone()['points']
        self.out({'ok': 1, 'gain': GAIN[res], 'points': pts})

    # ---------- realtime (Server-Sent Events) ----------
    def push(self, uid, ev, data):
        for q in list(streams.get(uid, [])): q.put((ev, data))

    def stream(self, u):
        q = queue.Queue()
        with lock: streams.setdefault(u['id'], []).append(q)
        self.send_response(200)
        for k, v in (('Content-Type', 'text/event-stream'), ('Cache-Control', 'no-cache'), ('X-Accel-Buffering', 'no'), ('Connection', 'keep-alive')): self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(b': hi\n\n'); self.wfile.flush()
            while True:
                try:
                    ev, data = q.get(timeout=15)
                    self.wfile.write(f'event: {ev}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n'.encode())
                except queue.Empty:
                    self.wfile.write(b': ping\n\n')
                self.wfile.flush()
        except Exception:
            pass
        finally:
            with lock:
                l = streams.get(u['id'], [])
                if q in l: l.remove(q)
                if not l: streams.pop(u['id'], None)

    def online(self):
        with lock:
            rows = [con.execute('SELECT * FROM users WHERE id=?', (i,)).fetchone() for i in list(streams.keys())[:60]]
        self.out({'ok': 1, 'rows': [self.pub(r) for r in rows if r]})

    def chatpost(self, u):
        t = str(self.body().get('text', '')).strip()[:120]; now = time.time()
        if not t: return self.err('ข้อความว่าง')
        if now - lastmsg.get(u['id'], 0) < 1: return self.err('ส่งเร็วเกินไป', 429)
        lastmsg[u['id']] = now
        m = {'name': u['name'], 'av': u['av'], 'text': t, 't': int(now)}
        with lock:
            chat.append(m); del chat[:-50]; ids = list(streams.keys())
        for i in ids: self.push(i, 'chat', m)
        self.out({'ok': 1})

    def invite(self, u):
        r = self.find(self.body().get('target', ''))
        if not r or r['id'] == u['id']: return self.err('ท้าไม่ได้')
        if r['id'] not in streams: return self.err('ผู้เล่นคนนี้ไม่ได้ออนไลน์อยู่')
        iid = secrets.token_hex(6); invites[iid] = {'from': u['id'], 'to': r['id'], 't': time.time()}
        self.push(r['id'], 'invite', {'id': iid, 'from': u['name'], 'av': u['av']})
        self.out({'ok': 1})

    def lineup_of(self, uid):
        with lock: s = con.execute('SELECT lineup FROM saves WHERE uid=?', (uid,)).fetchone()
        L = json.loads(s['lineup']) if s and s['lineup'] else None
        return L if L and len(L['ids']) >= 11 else None

    def answer(self, u):
        d = self.body(); v = invites.pop(d.get('id'), None)
        if not v or v['to'] != u['id'] or time.time() - v['t'] > 60: return self.err('คำเชิญหมดอายุแล้ว')
        if not d.get('accept'):
            self.push(v['from'], 'decline', {'by': u['name']}); return self.out({'ok': 1})
        La, Lb = self.lineup_of(v['from']), self.lineup_of(u['id'])
        if not La or not Lb: return self.err('ทีมของฝ่ายใดฝ่ายหนึ่งยังไม่พร้อม')
        with lock: ra = con.execute('SELECT * FROM users WHERE id=?', (v['from'],)).fetchone()
        mid, seed = secrets.token_hex(6), secrets.randbits(32)
        matches[mid] = {'a': v['from'], 'b': u['id'], 'res': {}, 'done': False}
        A = {'name': ra['name'], 'av': ra['av'], 'lineup': La}; B = {'name': u['name'], 'av': u['av'], 'lineup': Lb}
        self.push(v['from'], 'match', {'mid': mid, 'seed': seed, 'me': 0, 'a': A, 'b': B, 'delay': 3000})
        self.push(u['id'], 'match', {'mid': mid, 'seed': seed, 'me': 1, 'a': A, 'b': B, 'delay': 3000})
        self.out({'ok': 1})

    def result(self, u):
        d = self.body(); m = matches.get(d.get('mid')); res = d.get('res')
        if not m or u['id'] not in (m['a'], m['b']) or res not in GAIN or m['done']: return self.err('ผลไม่ถูกต้อง')
        m['res'][u['id']] = res
        if len(m['res']) < 2: return self.out({'ok': 1, 'pending': 1})
        m['done'] = True; ra, rb = m['res'][m['a']], m['res'][m['b']]
        if (ra, rb) in {('w', 'l'), ('l', 'w'), ('d', 'd')}:
            pts = {'w': 4, 'd': 2, 'l': 1}; now = time.time(); key = tuple(sorted((m['a'], m['b'])))
            if now - paired.get(key, 0) < 600: gains = {m['a']: 0, m['b']: 0}
            else:
                paired[key] = now; gains = {m['a']: pts[ra], m['b']: pts[rb]}
            with lock:
                for uid, g in gains.items(): con.execute('UPDATE users SET points=points+? WHERE id=?', (g, uid))
                con.commit()
            for uid, g in gains.items(): self.push(uid, 'points', {'gain': g})
        else:
            for uid in (m['a'], m['b']): self.push(uid, 'points', {'gain': 0, 'err': 'ผลของสองฝั่งไม่ตรงกัน ไม่นับแต้ม'})
        matches.pop(d.get('mid'), None)
        self.out({'ok': 1})

    def rename(self, u):
        name = str(self.body().get('name', '')).strip()
        if not NAME.match(name): return self.err('ชื่อต้อง 2-12 ตัว')
        with lock:
            s = con.execute('SELECT data FROM saves WHERE uid=?', (u['id'],)).fetchone()
        if not s or json.loads(s['data']).get('c', 0) < 10000: return self.err('ต้องมีเหรียญอย่างน้อย 10,000')
        try:
            with lock: con.execute('UPDATE users SET name=?,lc=? WHERE id=?', (name, name.lower(), u['id'])); con.commit()
        except sqlite3.IntegrityError:
            return self.err('ชื่อนี้ถูกใช้แล้ว')
        self.out({'ok': 1, 'name': name})

if __name__ == '__main__':
    print(f'STRIKER PACKS server on http://0.0.0.0:{PORT}  (db: {DBP})')
    ThreadingHTTPServer(('0.0.0.0', PORT), H).serve_forever()
