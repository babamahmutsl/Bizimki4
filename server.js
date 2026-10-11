const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const INVITE_CODE = process.env.INVITE_CODE || 'arkadaslar';
const SESSION_DAYS = 36500; // pratikte süresiz oturum
const MAX_MESSAGE_LENGTH = 2000;
const MAX_VOICE = 6; // sesli odada aynı anda en fazla kişi

if (!process.env.INVITE_CODE) {
  console.warn(
    'UYARI: INVITE_CODE ayarlanmadı, varsayılan davet kodu "arkadaslar" kullanılıyor. ' +
      'Yayına almadan önce kendi davet kodunu belirle.'
  );
}

// Sesli görüşme için ICE sunucuları. Varsayılan: Google STUN.
// Bağlantı kurulamayan ağlar için ICE_SERVERS ortam değişkenine TURN sunucusu ekleyebilirsin (JSON dizisi).
let ICE_SERVERS = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
if (process.env.ICE_SERVERS) {
  try {
    const parsed = JSON.parse(process.env.ICE_SERVERS);
    if (Array.isArray(parsed) && parsed.length) ICE_SERVERS = parsed;
    else console.warn('UYARI: ICE_SERVERS boş veya dizi değil, varsayılan STUN kullanılıyor.');
  } catch (_) {
    console.warn('UYARI: ICE_SERVERS geçerli JSON değil, varsayılan STUN kullanılıyor.');
  }
}

// ---------- Veritabanı ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'chat.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pass_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  insertUser: db.prepare('INSERT INTO users (username, pass_hash, created_at) VALUES (?, ?, ?)'),
  insertSession: db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  userByToken: db.prepare(`
    SELECT u.id, u.username FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ? AND s.created_at > ?
  `),
  insertMessage: db.prepare('INSERT INTO messages (user_id, body, created_at) VALUES (?, ?, ?)'),
  latest: db.prepare(`
    SELECT m.id, m.user_id AS userId, u.username, m.body, m.created_at AS createdAt
    FROM messages m JOIN users u ON u.id = m.user_id
    ORDER BY m.id DESC LIMIT 100
  `),
  before: db.prepare(`
    SELECT m.id, m.user_id AS userId, u.username, m.body, m.created_at AS createdAt
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.id < ? ORDER BY m.id DESC LIMIT 100
  `),
  after: db.prepare(`
    SELECT m.id, m.user_id AS userId, u.username, m.body, m.created_at AS createdAt
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.id > ? ORDER BY m.id ASC LIMIT 200
  `),
};

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  q.insertSession.run(token, userId, Date.now());
  return token;
}

function userForToken(token) {
  if (typeof token !== 'string' || token.length !== 64) return null;
  const minTime = Date.now() - SESSION_DAYS * 24 * 60 * 60 * 1000;
  return q.userByToken.get(token, minTime) || null;
}

// ---------- Basit deneme sınırlayıcı (giriş/kayıt) ----------
const attempts = new Map();
function tooManyAttempts(ip) {
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || entry.reset < now) {
    attempts.set(ip, { count: 1, reset: now + 10 * 60 * 1000 });
    return false;
  }
  entry.count += 1;
  return entry.count > 15;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of attempts) if (e.reset < now) attempts.delete(ip);
}, 60 * 1000).unref();

// ---------- Express ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});
// Sadece bu dosyalar dışarıya açılır (server.js ve veritabanı asla servis edilmez).
const PUBLIC_FILES = ['index.html', 'sw.js', 'manifest.json', 'icon.svg', 'icon-192.png', 'icon-512.png'];
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
for (const file of PUBLIC_FILES) {
  app.get('/' + file, (req, res) => res.sendFile(path.join(__dirname, file)));
}

function auth(req, res, next) {
  const header = req.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const user = userForToken(token);
  if (!user) return res.status(401).json({ error: 'Oturum geçersiz, tekrar giriş yap.' });
  req.user = user;
  req.token = token;
  next();
}

const USERNAME_RE = /^[\p{L}\p{N}_.-]{3,20}$/u;

app.post('/api/register', (req, res) => {
  if (tooManyAttempts(req.ip)) {
    return res.status(429).json({ error: 'Çok fazla deneme yaptın. Birkaç dakika sonra tekrar dene.' });
  }
  const { username, password, invite } = req.body || {};
  if (typeof username !== 'string' || !USERNAME_RE.test(username.trim())) {
    return res.status(400).json({
      error: 'Kullanıcı adı 3-20 karakter olmalı; harf, rakam, nokta, tire ve alt çizgi kullanabilirsin.',
    });
  }
  if (typeof password !== 'string' || password.length < 6 || password.length > 100) {
    return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı.' });
  }
  if (typeof invite !== 'string' || invite.trim() !== INVITE_CODE) {
    return res.status(403).json({ error: 'Davet kodu yanlış.' });
  }
  const name = username.trim();
  if (q.userByName.get(name)) {
    return res.status(409).json({ error: 'Bu kullanıcı adı alınmış.' });
  }
  const hash = bcrypt.hashSync(password, 10);
  const info = q.insertUser.run(name, hash, Date.now());
  const token = createSession(info.lastInsertRowid);
  res.json({ token, user: { id: Number(info.lastInsertRowid), username: name } });
});

app.post('/api/login', (req, res) => {
  if (tooManyAttempts(req.ip)) {
    return res.status(429).json({ error: 'Çok fazla deneme yaptın. Birkaç dakika sonra tekrar dene.' });
  }
  const { username, password } = req.body || {};
  const user = typeof username === 'string' ? q.userByName.get(username.trim()) : null;
  if (!user || typeof password !== 'string' || !bcrypt.compareSync(password, user.pass_hash)) {
    return res.status(401).json({ error: 'Kullanıcı adı veya şifre yanlış.' });
  }
  const token = createSession(user.id);
  res.json({ token, user: { id: user.id, username: user.username } });
});

app.post('/api/logout', auth, (req, res) => {
  q.deleteSession.run(req.token);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/ice', auth, (req, res) => {
  res.json({ iceServers: ICE_SERVERS });
});

app.get('/api/history', auth, (req, res) => {
  const before = parseInt(req.query.before, 10);
  const after = parseInt(req.query.after, 10);
  let rows;
  if (Number.isInteger(after)) rows = q.after.all(after);
  else if (Number.isInteger(before)) rows = q.before.all(before).reverse();
  else rows = q.latest.all().reverse();
  res.json({ messages: rows });
});

// ---------- Socket.io ----------
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e5 });

const online = new Map(); // userId -> { username, count }
function broadcastPresence() {
  io.emit(
    'presence',
    [...online.values()].map((u) => u.username)
  );
}

// Sesli oda: socket.id -> { username }
const voice = new Map();
function voiceNames() {
  return [...voice.values()].map((v) => v.username);
}
function broadcastVoice() {
  io.emit('voice:members', voiceNames());
}
function leaveVoice(socket) {
  if (!voice.has(socket.id)) return;
  voice.delete(socket.id);
  socket.leave('voice');
  socket.to('voice').emit('voice:peer-left', socket.id);
  broadcastVoice();
}

io.use((socket, next) => {
  const user = userForToken(socket.handshake.auth && socket.handshake.auth.token);
  if (!user) return next(new Error('auth'));
  socket.user = user;
  next();
});

io.on('connection', (socket) => {
  const { id, username } = socket.user;
  const entry = online.get(id) || { username, count: 0 };
  entry.count += 1;
  online.set(id, entry);
  broadcastPresence();
  socket.emit('voice:members', voiceNames());

  const recent = [];

  socket.on('message', (text, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    if (typeof text !== 'string') return reply({ error: 'Geçersiz mesaj.' });
    const body = text.trim();
    if (!body) return reply({ error: 'Mesaj boş.' });
    if (body.length > MAX_MESSAGE_LENGTH) {
      return reply({ error: `Mesaj en fazla ${MAX_MESSAGE_LENGTH} karakter olabilir.` });
    }
    const now = Date.now();
    while (recent.length && recent[0] < now - 10000) recent.shift();
    if (recent.length >= 8) return reply({ error: 'Çok hızlı yazıyorsun, biraz bekle.' });
    recent.push(now);

    const info = q.insertMessage.run(id, body, now);
    io.emit('message', {
      id: Number(info.lastInsertRowid),
      userId: id,
      username,
      body,
      createdAt: now,
    });
    reply({ ok: true });
  });

  socket.on('typing', () => {
    socket.broadcast.emit('typing', username);
  });

  // ---- Sesli görüşme (WebRTC sinyalleşmesi) ----
  socket.on('voice:join', (ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    const already = voice.has(socket.id);
    if (!already && voice.size >= MAX_VOICE) {
      return reply({ error: `Sesli oda dolu (en fazla ${MAX_VOICE} kişi).` });
    }
    const peers = [...voice.entries()]
      .filter(([sid]) => sid !== socket.id)
      .map(([sid, v]) => ({ id: sid, username: v.username }));
    if (!already) {
      voice.set(socket.id, { username });
      socket.join('voice');
      broadcastVoice();
    }
    reply({ ok: true, peers });
  });

  socket.on('voice:signal', (msg) => {
    if (!voice.has(socket.id) || !msg || typeof msg.to !== 'string' || !voice.has(msg.to)) return;
    io.to(msg.to).emit('voice:signal', { from: socket.id, username, data: msg.data });
  });

  socket.on('voice:leave', () => leaveVoice(socket));

  socket.on('disconnect', () => {
    leaveVoice(socket);
    const e = online.get(id);
    if (e) {
      e.count -= 1;
      if (e.count <= 0) online.delete(id);
    }
    broadcastPresence();
  });
});

server.listen(PORT, () => {
  console.log(`Bizimki http://localhost:${PORT} adresinde çalışıyor`);
});
