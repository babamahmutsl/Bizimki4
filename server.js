'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const { Server } = require('socket.io');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');

// ---------- Ayarlar ----------
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const INVITE_CODE = process.env.INVITE_CODE || 'arkadaslar';
const SESSION_DAYS = 36500; // pratikte süresiz oturum
const MAX_MESSAGE_LENGTH = 2000;
const MAX_FILE_BYTES = 3 * 1024 * 1024;
const MAX_VOICE = 6; // sesli odada aynı anda en fazla kişi
const MAX_PINS = 20;
const MAX_GROUP_MEMBERS = 50;
const BOT_NAME = 'Bizimki-Bot';
const REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🙏', '🔥', '👎'];
// Başkan hesabı: tüm mesajları silebilir/düzenleyebilir, herkesin etiketini değiştirebilir,
// "/bot mesaj" ile botun adından yazabilir. Render'da ADMIN_USERNAME ile değiştirilebilir.
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'Ömer_Rıza_Bolukbas').toLocaleLowerCase('tr-TR');

if (!process.env.INVITE_CODE) {
  console.warn(
    'UYARI: INVITE_CODE ayarlanmadı, varsayılan davet kodu "arkadaslar" kullanılıyor. ' +
      'Yayına almadan önce kendi davet kodunu belirle.'
  );
}

// Sesli görüşme için ICE sunucuları. Varsayılan: Google STUN.
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

// ---------- Veritabanı (Turso / libSQL) ----------
let dbUrl = (process.env.TURSO_DATABASE_URL || '').trim();
if (dbUrl) {
  // WebSocket yerine HTTPS kullan: uyuyan/uyanan sunucuda daha az kopma yaşanır.
  dbUrl = dbUrl.replace(/^libsql:\/\//, 'https://');
} else {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  dbUrl = 'file:' + path.join(DATA_DIR, 'bizimki.db');
  console.warn(
    'UYARI: TURSO_DATABASE_URL ayarlanmadı. Veriler bu sunucunun diskinde tutuluyor; ' +
      'ücretsiz Render yeniden başlayınca silinir. Kalıcı olması için Turso bilgilerini ekle.'
  );
}
const db = createClient({ url: dbUrl, authToken: (process.env.TURSO_AUTH_TOKEN || '').trim() || undefined });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function withRetry(fn) {
  try {
    return await fn();
  } catch (e) {
    if (!/fetch failed|ECONN|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|network|socket hang|STREAM|\b50[234]\b/i.test(String((e && e.message) || e))) {
      throw e;
    }
    await sleep(300);
    return fn();
  }
}
const q = {
  all: async (sql, args = []) => (await withRetry(() => db.execute({ sql, args }))).rows,
  one: async (sql, args = []) => (await q.all(sql, args))[0] || null,
  run: (sql, args = []) => db.execute({ sql, args }),
  batch: (stmts) => db.batch(stmts.map(([sql, args = []]) => ({ sql, args })), 'write'),
};
const int = (v) => {
  const n = Number(v);
  return Number.isInteger(n) ? n : null;
};

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pass_hash TEXT NOT NULL,
    tag TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    dm_key TEXT UNIQUE,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS members (
    conv_id INTEGER NOT NULL REFERENCES conversations(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    last_read_id INTEGER NOT NULL DEFAULT 0,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (conv_id, user_id)
  );
  CREATE INDEX IF NOT EXISTS idx_members_user ON members(user_id);
  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    conv_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    data BLOB NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conv_id INTEGER NOT NULL REFERENCES conversations(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL DEFAULT 'text',
    body TEXT NOT NULL DEFAULT '',
    file_id INTEGER,
    reply_to INTEGER,
    created_at INTEGER NOT NULL,
    edited_at INTEGER,
    edited_by_admin INTEGER NOT NULL DEFAULT 0,
    deleted_at INTEGER,
    pinned_at INTEGER,
    pinned_by INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conv_id, id);
  CREATE TABLE IF NOT EXISTS reactions (
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    emoji TEXT NOT NULL,
    PRIMARY KEY (message_id, user_id)
  );
`;

let bot = null; // { id, username }
let defaultConvId = null;

async function initDb() {
  await db.executeMultiple(SCHEMA);

  let b = await q.one('SELECT id, username FROM users WHERE username = ?', [BOT_NAME]);
  if (!b) {
    // Geçerli bir bcrypt özeti olmayan rastgele değer: bu hesaba kimse giriş yapamaz.
    const info = await q.run('INSERT INTO users (username, pass_hash, tag, created_at) VALUES (?, ?, ?, ?)', [
      BOT_NAME,
      'x:' + crypto.randomBytes(24).toString('hex'),
      '',
      Date.now(),
    ]);
    b = { id: Number(info.lastInsertRowid), username: BOT_NAME };
  }
  bot = { id: Number(b.id), username: b.username };

  let def = await q.one('SELECT id FROM conversations WHERE is_default = 1');
  if (!def) {
    const info = await q.run(
      "INSERT INTO conversations (type, name, is_default, created_at) VALUES ('group', 'Genel', 1, ?)",
      [Date.now()]
    );
    def = { id: Number(info.lastInsertRowid) };
  }
  defaultConvId = Number(def.id);
  await q.run(
    `INSERT OR IGNORE INTO members (conv_id, user_id, last_read_id, joined_at)
     SELECT ?, id, (SELECT COALESCE(MAX(id), 0) FROM messages WHERE conv_id = ?), ? FROM users WHERE id <> ?`,
    [defaultConvId, defaultConvId, Date.now(), bot.id]
  );
}

// ---------- Yardımcılar ----------
const isAdminName = (name) => String(name || '').toLocaleLowerCase('tr-TR') === ADMIN_USERNAME;
const publicUser = (u) => ({ id: Number(u.id), username: u.username, tag: u.tag || '', isAdmin: isAdminName(u.username) });

function cleanTag(raw) {
  return String(raw == null ? '' : raw)
    .replace(/[\p{C}\u2028\u2029]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 24);
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await q.run('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)', [token, userId, Date.now()]);
  return token;
}

async function userForToken(token) {
  if (typeof token !== 'string' || token.length !== 64) return null;
  const minTime = Date.now() - SESSION_DAYS * 24 * 60 * 60 * 1000;
  const r = await q.one(
    `SELECT u.id, u.username, u.tag FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.created_at > ?`,
    [token, minTime]
  );
  return r ? { id: Number(r.id), username: r.username, tag: r.tag || '' } : null;
}

// Basit deneme sınırlayıcı (giriş/kayıt)
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

// Genel hız sınırı: key -> zaman damgaları
function makeLimiter(max, windowMs) {
  const map = new Map();
  return (key) => {
    const now = Date.now();
    const arr = (map.get(key) || []).filter((t) => t > now - windowMs);
    if (arr.length >= max) {
      map.set(key, arr);
      return false;
    }
    arr.push(now);
    map.set(key, arr);
    return true;
  };
}
const uploadLimit = makeLimiter(12, 60 * 1000);
const msgLimit = makeLimiter(8, 10 * 1000);
const opLimit = makeLimiter(40, 10 * 1000);

// ---------- Üyelik önbelleği ----------
const memberCache = new Map(); // convId -> Set(userId)
async function getMembers(convId) {
  let s = memberCache.get(convId);
  if (!s) {
    const rows = await q.all('SELECT user_id FROM members WHERE conv_id = ?', [convId]);
    s = new Set(rows.map((r) => Number(r.user_id)));
    memberCache.set(convId, s);
  }
  return s;
}
const isMember = async (convId, userId) => (await getMembers(convId)).has(userId);
const dropMemberCache = (convId) => memberCache.delete(convId);

async function addMember(convId, userId) {
  await q.run(
    `INSERT OR IGNORE INTO members (conv_id, user_id, last_read_id, joined_at)
     VALUES (?, ?, (SELECT COALESCE(MAX(id), 0) FROM messages WHERE conv_id = ?), ?)`,
    [convId, userId, convId, Date.now()]
  );
  dropMemberCache(convId);
}

// ---------- Mesajlar ----------
const MSG_SELECT = `
  SELECT m.id, m.conv_id, m.user_id, u.username, u.tag, m.kind, m.body, m.file_id,
         f.name AS file_name, f.mime AS file_mime, f.size AS file_size,
         m.reply_to, m.created_at, m.edited_at, m.edited_by_admin, m.deleted_at, m.pinned_at,
         r.id AS r_id, ru.username AS r_user, r.body AS r_body, r.kind AS r_kind,
         r.deleted_at AS r_deleted, rf.name AS r_file_name
  FROM messages m
  JOIN users u ON u.id = m.user_id
  LEFT JOIN files f ON f.id = m.file_id
  LEFT JOIN messages r ON r.id = m.reply_to
  LEFT JOIN users ru ON ru.id = r.user_id
  LEFT JOIN files rf ON rf.id = r.file_id`;

function toMessage(r, reactionMap) {
  const deleted = r.deleted_at != null;
  const id = Number(r.id);
  const msg = {
    id,
    convId: Number(r.conv_id),
    userId: Number(r.user_id),
    username: r.username,
    tag: r.tag || '',
    kind: deleted ? 'text' : r.kind,
    body: deleted ? '' : r.body,
    createdAt: Number(r.created_at),
    editedAt: r.edited_at != null ? Number(r.edited_at) : null,
    editedByAdmin: !!Number(r.edited_by_admin),
    deleted,
    pinnedAt: r.pinned_at != null && !deleted ? Number(r.pinned_at) : null,
    reactions: deleted ? {} : reactionMap.get(id) || {},
    file: null,
    replyTo: null,
  };
  if (!deleted && r.file_id != null) {
    msg.file = { id: Number(r.file_id), name: r.file_name, mime: r.file_mime, size: Number(r.file_size) };
  }
  if (r.reply_to != null) {
    const gone = r.r_id == null || r.r_deleted != null;
    msg.replyTo = {
      id: Number(r.reply_to),
      username: r.r_user || '',
      deleted: gone,
      kind: gone ? 'text' : r.r_kind,
      body: gone ? '' : String(r.r_body || '').slice(0, 160),
      fileName: gone ? '' : r.r_file_name || '',
    };
  }
  return msg;
}

async function hydrate(rows) {
  const ids = rows.map((r) => Number(r.id));
  const rmap = new Map();
  if (ids.length) {
    const rx = await q.all(
      `SELECT message_id, user_id, emoji FROM reactions WHERE message_id IN (${ids.map(() => '?').join(',')})`,
      ids
    );
    for (const x of rx) {
      const mid = Number(x.message_id);
      if (!rmap.has(mid)) rmap.set(mid, {});
      const o = rmap.get(mid);
      (o[x.emoji] ||= []).push(Number(x.user_id));
    }
  }
  return rows.map((r) => toMessage(r, rmap));
}

async function fetchMessages(where, args, { order = 'm.id ASC', limit = 200 } = {}) {
  const rows = await q.all(`${MSG_SELECT} WHERE ${where} ORDER BY ${order} LIMIT ${Number(limit)}`, args);
  return hydrate(rows);
}
const getMessage = async (id) => (await fetchMessages('m.id = ?', [id], { limit: 1 }))[0] || null;

let io; // aşağıda oluşturulur

async function createMessage({ convId, userId, kind = 'text', body = '', fileId = null, replyTo = null }) {
  let replyId = null;
  if (replyTo != null) {
    const ok = await q.one('SELECT id FROM messages WHERE id = ? AND conv_id = ?', [replyTo, convId]);
    if (ok) replyId = Number(ok.id);
  }
  const info = await q.run(
    'INSERT INTO messages (conv_id, user_id, kind, body, file_id, reply_to, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [convId, userId, kind, body, fileId, replyId, Date.now()]
  );
  const msg = await getMessage(Number(info.lastInsertRowid));
  io.to('conv:' + convId).emit('message', msg);
  return msg;
}

async function emitUpdate(id) {
  const msg = await getMessage(id);
  if (msg) io.to('conv:' + msg.convId).emit('message:update', msg);
  return msg;
}

const sysMessage = (convId, actorId, text) =>
  createMessage({ convId, userId: actorId, kind: 'system', body: text.slice(0, MAX_MESSAGE_LENGTH) });

// ---------- Sohbetler ----------
async function listConversations(userId, onlyId = null) {
  const args = [userId, userId];
  let where = '';
  if (onlyId != null) {
    where = ' WHERE c.id = ?';
    args.push(onlyId);
  }
  const rows = await q.all(
    `SELECT c.id, c.type, c.name, c.is_default, c.created_by, c.created_at, mm.last_read_id,
       (SELECT COUNT(*) FROM messages x WHERE x.conv_id = c.id AND x.id > mm.last_read_id
          AND x.user_id <> ? AND x.deleted_at IS NULL AND x.kind <> 'system') AS unread,
       (SELECT MAX(x.id) FROM messages x WHERE x.conv_id = c.id) AS last_id
     FROM conversations c
     JOIN members mm ON mm.conv_id = c.id AND mm.user_id = ?${where}`,
    args
  );
  if (!rows.length) return [];
  const convIds = rows.map((r) => Number(r.id));
  const memRows = await q.all(
    `SELECT mem.conv_id, u.id, u.username, u.tag, mem.last_read_id
     FROM members mem JOIN users u ON u.id = mem.user_id
     WHERE mem.conv_id IN (${convIds.map(() => '?').join(',')})
     ORDER BY u.username COLLATE NOCASE`,
    convIds
  );
  const membersBy = new Map();
  for (const m of memRows) {
    const cid = Number(m.conv_id);
    if (!membersBy.has(cid)) membersBy.set(cid, []);
    membersBy.get(cid).push({ id: Number(m.id), username: m.username, tag: m.tag || '', lastReadId: Number(m.last_read_id) });
  }
  const lastIds = rows.map((r) => r.last_id).filter((v) => v != null).map(Number);
  let lastMessages = [];
  if (lastIds.length) {
    lastMessages = await fetchMessages(`m.id IN (${lastIds.map(() => '?').join(',')})`, lastIds, { limit: lastIds.length });
  }
  const lastBy = new Map(lastMessages.map((m) => [m.convId, m]));
  return rows.map((r) => ({
    id: Number(r.id),
    type: r.type,
    name: r.name,
    isDefault: !!Number(r.is_default),
    createdBy: r.created_by != null ? Number(r.created_by) : null,
    createdAt: Number(r.created_at),
    unread: Number(r.unread || 0),
    members: membersBy.get(Number(r.id)) || [],
    lastMessage: lastBy.get(Number(r.id)) || null,
  }));
}

async function userConvIds(userId) {
  const rows = await q.all('SELECT conv_id FROM members WHERE user_id = ?', [userId]);
  return rows.map((r) => Number(r.conv_id));
}

function notifyConvChanged(userIds) {
  for (const uid of userIds) io.to('user:' + uid).emit('conversations:changed');
}
function joinUsersToConv(userIds, convId) {
  for (const uid of userIds) io.in('user:' + uid).socketsJoin('conv:' + convId);
}

// ---------- Express ----------
const app = express();
const server = http.createServer(app);
io = new Server(server, { maxHttpBufferSize: 1e5 });

app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});

const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Sadece bu dosyalar dışarıya açılır (server.js ve veritabanı asla servis edilmez).
const PUBLIC_FILES = ['index.html', 'sw.js', 'manifest.json', 'icon.svg', 'icon-192.png', 'icon-512.png'];
const sendPublic = (file) => (req, res) => {
  if (file === 'index.html' || file === 'sw.js') res.set('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, file));
};
app.get('/', sendPublic('index.html'));
for (const file of PUBLIC_FILES) app.get('/' + file, sendPublic(file));

const auth = ah(async (req, res, next) => {
  const header = req.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const user = await userForToken(token);
  if (!user) return res.status(401).json({ error: 'Oturum geçersiz, tekrar giriş yap.' });
  req.user = user;
  req.token = token;
  next();
});

const USERNAME_RE = /^[\p{L}\p{N}_.-]{3,20}$/u;

app.post(
  '/api/register',
  ah(async (req, res) => {
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
    if (await q.one('SELECT id FROM users WHERE username = ?', [name])) {
      return res.status(409).json({ error: 'Bu kullanıcı adı alınmış.' });
    }
    const hash = bcrypt.hashSync(password, 10);
    let info;
    try {
      info = await q.run('INSERT INTO users (username, pass_hash, tag, created_at) VALUES (?, ?, ?, ?)', [name, hash, '', Date.now()]);
    } catch (e) {
      if (/UNIQUE/i.test(String(e && e.message))) return res.status(409).json({ error: 'Bu kullanıcı adı alınmış.' });
      throw e;
    }
    const userId = Number(info.lastInsertRowid);
    await addMember(defaultConvId, userId);
    const token = await createSession(userId);
    const user = publicUser({ id: userId, username: name, tag: '' });
    io.emit('users:changed', { id: userId, username: name, tag: '' });
    res.json({ token, user });
  })
);

app.post(
  '/api/login',
  ah(async (req, res) => {
    if (tooManyAttempts(req.ip)) {
      return res.status(429).json({ error: 'Çok fazla deneme yaptın. Birkaç dakika sonra tekrar dene.' });
    }
    const { username, password } = req.body || {};
    const user = typeof username === 'string' ? await q.one('SELECT * FROM users WHERE username = ?', [username.trim()]) : null;
    if (!user || user.id === bot.id || typeof password !== 'string' || !bcrypt.compareSync(password, user.pass_hash)) {
      return res.status(401).json({ error: 'Kullanıcı adı veya şifre yanlış.' });
    }
    const token = await createSession(Number(user.id));
    res.json({ token, user: publicUser(user) });
  })
);

app.post(
  '/api/logout',
  auth,
  ah(async (req, res) => {
    await q.run('DELETE FROM sessions WHERE token = ?', [req.token]);
    res.json({ ok: true });
  })
);

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));
app.get('/api/ice', auth, (req, res) => res.json({ iceServers: ICE_SERVERS }));

app.get(
  '/api/users',
  auth,
  ah(async (req, res) => {
    const rows = await q.all('SELECT id, username, tag FROM users WHERE id <> ? ORDER BY username COLLATE NOCASE', [bot.id]);
    res.json({ users: rows.map((r) => ({ id: Number(r.id), username: r.username, tag: r.tag || '' })) });
  })
);

app.patch(
  '/api/users/:id/tag',
  auth,
  ah(async (req, res) => {
    const target = int(req.params.id);
    if (target == null || target === bot.id) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    if (target !== req.user.id && !isAdminName(req.user.username)) {
      return res.status(403).json({ error: 'Sadece kendi etiketini değiştirebilirsin.' });
    }
    const u = await q.one('SELECT id, username FROM users WHERE id = ?', [target]);
    if (!u) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    const tag = cleanTag((req.body || {}).tag);
    await q.run('UPDATE users SET tag = ? WHERE id = ?', [tag, target]);
    io.emit('users:changed', { id: target, username: u.username, tag });
    res.json({ ok: true, tag });
  })
);

// ----- Sohbet listesi / oluşturma -----
app.get(
  '/api/conversations',
  auth,
  ah(async (req, res) => {
    res.json({ conversations: await listConversations(req.user.id) });
  })
);

app.post(
  '/api/conversations',
  auth,
  ah(async (req, res) => {
    const body = req.body || {};
    const me = req.user;
    if (!opLimit('conv:' + me.id)) return res.status(429).json({ error: 'Çok hızlı işlem yapıyorsun.' });

    if (body.type === 'dm') {
      const other = int(body.userId);
      if (other == null || other === me.id || other === bot.id) return res.status(400).json({ error: 'Geçersiz kişi.' });
      if (!(await q.one('SELECT id FROM users WHERE id = ?', [other]))) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
      const key = [me.id, other].sort((a, b) => a - b).join(':');
      let c = await q.one('SELECT id FROM conversations WHERE dm_key = ?', [key]);
      if (!c) {
        try {
          const info = await q.run("INSERT INTO conversations (type, name, dm_key, created_by, created_at) VALUES ('dm', '', ?, ?, ?)", [key, me.id, Date.now()]);
          c = { id: Number(info.lastInsertRowid) };
        } catch (_) {
          c = await q.one('SELECT id FROM conversations WHERE dm_key = ?', [key]);
        }
      }
      const convId = Number(c.id);
      await addMember(convId, me.id);
      await addMember(convId, other);
      joinUsersToConv([me.id, other], convId);
      notifyConvChanged([me.id, other]);
      const [conv] = await listConversations(me.id, convId);
      return res.json({ conversation: conv });
    }

    if (body.type === 'group') {
      const name = String(body.name || '').replace(/\s+/g, ' ').trim().slice(0, 40);
      if (!name) return res.status(400).json({ error: 'Grup adı yaz.' });
      const ids = [...new Set((Array.isArray(body.memberIds) ? body.memberIds : []).map(int).filter((n) => n != null && n !== me.id && n !== bot.id))].slice(0, MAX_GROUP_MEMBERS);
      if (!ids.length) return res.status(400).json({ error: 'En az bir kişi seç.' });
      const found = await q.all(`SELECT id FROM users WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
      const members = [me.id, ...found.map((r) => Number(r.id))];
      if (members.length < 2) return res.status(400).json({ error: 'Seçilen kişiler bulunamadı.' });
      const info = await q.run("INSERT INTO conversations (type, name, created_by, created_at) VALUES ('group', ?, ?, ?)", [name, me.id, Date.now()]);
      const convId = Number(info.lastInsertRowid);
      for (const uid of members) await addMember(convId, uid);
      joinUsersToConv(members, convId);
      notifyConvChanged(members);
      await sysMessage(convId, me.id, `${me.username} "${name}" grubunu oluşturdu`);
      const [conv] = await listConversations(me.id, convId);
      return res.json({ conversation: conv });
    }

    res.status(400).json({ error: 'Geçersiz istek.' });
  })
);

async function loadConvForUser(req, res) {
  const convId = int(req.params.id);
  if (convId == null || !(await isMember(convId, req.user.id))) {
    res.status(404).json({ error: 'Sohbet bulunamadı.' });
    return null;
  }
  const c = await q.one('SELECT id, type, name, is_default, created_by FROM conversations WHERE id = ?', [convId]);
  if (!c) {
    res.status(404).json({ error: 'Sohbet bulunamadı.' });
    return null;
  }
  return { id: convId, type: c.type, name: c.name, isDefault: !!Number(c.is_default), createdBy: c.created_by != null ? Number(c.created_by) : null };
}

app.patch(
  '/api/conversations/:id',
  auth,
  ah(async (req, res) => {
    const c = await loadConvForUser(req, res);
    if (!c) return;
    if (c.type !== 'group' || c.isDefault) return res.status(400).json({ error: 'Bu sohbetin adı değiştirilemez.' });
    if (c.createdBy !== req.user.id && !isAdminName(req.user.username)) {
      return res.status(403).json({ error: 'Grup adını sadece kurucusu veya başkan değiştirebilir.' });
    }
    const name = String((req.body || {}).name || '').replace(/\s+/g, ' ').trim().slice(0, 40);
    if (!name) return res.status(400).json({ error: 'Grup adı yaz.' });
    await q.run('UPDATE conversations SET name = ? WHERE id = ?', [name, c.id]);
    const members = [...(await getMembers(c.id))];
    notifyConvChanged(members);
    await sysMessage(c.id, req.user.id, `${req.user.username} grubun adını "${name}" yaptı`);
    res.json({ ok: true, name });
  })
);

app.post(
  '/api/conversations/:id/members',
  auth,
  ah(async (req, res) => {
    const c = await loadConvForUser(req, res);
    if (!c) return;
    if (c.type !== 'group' || c.isDefault) return res.status(400).json({ error: 'Bu sohbete kişi eklenemez.' });
    const current = await getMembers(c.id);
    const ids = [...new Set((Array.isArray((req.body || {}).userIds) ? req.body.userIds : []).map(int).filter((n) => n != null && n !== bot.id && !current.has(n)))];
    if (!ids.length) return res.status(400).json({ error: 'Eklenecek kişi seç.' });
    if (current.size + ids.length > MAX_GROUP_MEMBERS) return res.status(400).json({ error: 'Grup çok kalabalık.' });
    const found = await q.all(`SELECT id, username FROM users WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
    if (!found.length) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    for (const u of found) await addMember(c.id, Number(u.id));
    const all = [...(await getMembers(c.id))];
    joinUsersToConv(found.map((u) => Number(u.id)), c.id);
    notifyConvChanged(all);
    await sysMessage(c.id, req.user.id, `${req.user.username}, ${found.map((u) => u.username).join(', ')} kişisini ekledi`);
    res.json({ ok: true });
  })
);

app.delete(
  '/api/conversations/:id/members/me',
  auth,
  ah(async (req, res) => {
    const c = await loadConvForUser(req, res);
    if (!c) return;
    if (c.type !== 'group' || c.isDefault) return res.status(400).json({ error: 'Bu sohbetten ayrılamazsın.' });
    const before = [...(await getMembers(c.id))];
    await q.run('DELETE FROM members WHERE conv_id = ? AND user_id = ?', [c.id, req.user.id]);
    dropMemberCache(c.id);
    await sysMessage(c.id, req.user.id, `${req.user.username} gruptan ayrıldı`);
    io.in('user:' + req.user.id).socketsLeave('conv:' + c.id);
    notifyConvChanged(before);
    res.json({ ok: true });
  })
);

app.get(
  '/api/conversations/:id/messages',
  auth,
  ah(async (req, res) => {
    const c = await loadConvForUser(req, res);
    if (!c) return;
    const before = int(req.query.before);
    const after = int(req.query.after);
    let limit = int(req.query.limit);
    if (limit == null || limit < 1 || limit > 100) limit = 60;
    let messages;
    if (after != null) {
      messages = await fetchMessages('m.conv_id = ? AND m.id > ?', [c.id, after], { order: 'm.id ASC', limit: 200 });
    } else if (before != null) {
      messages = (await fetchMessages('m.conv_id = ? AND m.id < ?', [c.id, before], { order: 'm.id DESC', limit })).reverse();
    } else {
      messages = (await fetchMessages('m.conv_id = ?', [c.id], { order: 'm.id DESC', limit })).reverse();
    }
    res.json({ messages, hasMore: after == null && messages.length === limit });
  })
);

app.get(
  '/api/conversations/:id/pins',
  auth,
  ah(async (req, res) => {
    const c = await loadConvForUser(req, res);
    if (!c) return;
    const pins = await fetchMessages('m.conv_id = ? AND m.pinned_at IS NOT NULL AND m.deleted_at IS NULL', [c.id], {
      order: 'm.pinned_at DESC',
      limit: MAX_PINS,
    });
    res.json({ pins });
  })
);

// ----- Dosya yükleme / indirme -----
function sniffImage(b) {
  if (b.length > 12) {
    if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'image/png';
    if (b.toString('latin1', 0, 4) === 'GIF8') return 'image/gif';
    if (b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP') return 'image/webp';
  }
  return null;
}
function cleanFileName(raw) {
  let name = String(raw || '');
  try {
    name = decodeURIComponent(name);
  } catch (_) {}
  name = name.replace(/[\u0000-\u001f\u007f\\/:*?"<>|]+/g, '_').trim().slice(0, 100);
  return name || 'dosya';
}

app.post(
  '/api/upload',
  auth,
  express.raw({ type: () => true, limit: MAX_FILE_BYTES }),
  ah(async (req, res) => {
    const convId = int(req.query.conv);
    if (convId == null || !(await isMember(convId, req.user.id))) {
      return res.status(403).json({ error: 'Bu sohbete erişimin yok.' });
    }
    if (!uploadLimit(req.user.id)) return res.status(429).json({ error: 'Çok fazla dosya gönderdin, biraz bekle.' });
    const buf = req.body;
    if (!Buffer.isBuffer(buf) || buf.length === 0) return res.status(400).json({ error: 'Dosya boş.' });
    if (buf.length > MAX_FILE_BYTES) return res.status(413).json({ error: 'Dosya en fazla 3 MB olabilir.' });
    const name = cleanFileName(req.get('X-File-Name'));
    const imgMime = sniffImage(buf);
    const kind = imgMime ? 'image' : 'file';
    const mime = imgMime || 'application/octet-stream';
    const info = await q.run('INSERT INTO files (user_id, conv_id, name, mime, size, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', [
      req.user.id,
      convId,
      name,
      mime,
      buf.length,
      buf,
      Date.now(),
    ]);
    const msg = await createMessage({
      convId,
      userId: req.user.id,
      kind,
      fileId: Number(info.lastInsertRowid),
      replyTo: req.query.reply != null ? int(req.query.reply) : null,
    });
    res.json({ ok: true, message: msg });
  })
);

app.get(
  '/api/files/:id',
  auth,
  ah(async (req, res) => {
    const id = int(req.params.id);
    const f = id == null ? null : await q.one('SELECT id, conv_id, name, mime, size, data FROM files WHERE id = ?', [id]);
    if (!f || !(await isMember(Number(f.conv_id), req.user.id))) return res.status(404).json({ error: 'Dosya bulunamadı.' });
    const data = Buffer.from(f.data);
    const image = String(f.mime).startsWith('image/');
    res.set({
      'Content-Type': image ? f.mime : 'application/octet-stream',
      'Content-Length': String(data.length),
      'Content-Disposition': (image ? 'inline' : 'attachment') + `; filename*=UTF-8''${encodeURIComponent(f.name)}`,
      'Cache-Control': 'private, max-age=31536000, immutable',
      'Content-Security-Policy': "default-src 'none'; sandbox",
    });
    res.send(data);
  })
);

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Dosya en fazla 3 MB olabilir.' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Geçersiz istek.' });
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Sunucuda bir hata oluştu. Tekrar dene.' });
});

// ---------- Bot ----------
const botSay = (convId, text) => createMessage({ convId, userId: bot.id, body: String(text).slice(0, MAX_MESSAGE_LENGTH) });

// Komut adlarını Türkçe karakterlerden bağımsız karşılaştırmak için sadeleştirir.
const norm = (s) =>
  String(s)
    .toLocaleLowerCase('tr-TR')
    .replace(/ı/g, 'i')
    .replace(/ş/g, 's')
    .replace(/ö/g, 'o')
    .replace(/ü/g, 'u')
    .replace(/ç/g, 'c')
    .replace(/ğ/g, 'g');

const WMO = {
  0: 'Açık', 1: 'Çoğunlukla açık', 2: 'Parçalı bulutlu', 3: 'Kapalı', 45: 'Sisli', 48: 'Kırağılı sis',
  51: 'Hafif çisenti', 53: 'Çisenti', 55: 'Yoğun çisenti', 56: 'Dondurucu çisenti', 57: 'Yoğun dondurucu çisenti',
  61: 'Hafif yağmurlu', 63: 'Yağmurlu', 65: 'Şiddetli yağmurlu', 66: 'Dondurucu yağmur', 67: 'Şiddetli dondurucu yağmur',
  71: 'Hafif karlı', 73: 'Karlı', 75: 'Yoğun karlı', 77: 'Kar taneleri',
  80: 'Hafif sağanak', 81: 'Sağanak', 82: 'Şiddetli sağanak', 85: 'Hafif kar sağanağı', 86: 'Yoğun kar sağanağı',
  95: 'Gök gürültülü fırtına', 96: 'Dolulu fırtına', 99: 'Şiddetli dolulu fırtına',
};

const weatherCache = new Map(); // şehir -> { t, text }
async function getWeather(city) {
  const key = norm(city);
  const hit = weatherCache.get(key);
  if (hit && hit.t > Date.now() - 10 * 60 * 1000) return hit.text;

  const geoRes = await fetch(
    'https://geocoding-api.open-meteo.com/v1/search?count=1&language=tr&format=json&name=' + encodeURIComponent(city),
    { signal: AbortSignal.timeout(6000) }
  );
  const geo = await geoRes.json();
  const place = geo && geo.results && geo.results[0];
  if (!place) return `"${city}" adında bir yer bulamadım. Şehir adını kontrol et.`;

  const url =
    `https://api.open-meteo.com/v1/forecast?latitude=${place.latitude}&longitude=${place.longitude}` +
    '&current=temperature_2m,apparent_temperature,relative_humidity_2m,weather_code,wind_speed_10m' +
    '&daily=temperature_2m_max,temperature_2m_min,precipitation_probability_max&forecast_days=1&timezone=auto';
  const res = await fetch(url, { signal: AbortSignal.timeout(6000) });
  const w = await res.json();
  const cur = w && w.current;
  if (!cur) throw new Error('no weather');

  const round = (n) => Math.round(n);
  const daily = w.daily || {};
  const min = daily.temperature_2m_min && daily.temperature_2m_min[0];
  const max = daily.temperature_2m_max && daily.temperature_2m_max[0];
  const rain = daily.precipitation_probability_max && daily.precipitation_probability_max[0];
  const where = [place.name, place.admin1 && place.admin1 !== place.name ? place.admin1 : null, place.country].filter(Boolean).join(', ');

  let text = `${where}\n${WMO[cur.weather_code] || 'Hava durumu bilinmiyor'}, ${round(cur.temperature_2m)}°C`;
  text += ` (hissedilen ${round(cur.apparent_temperature)}°C)`;
  text += `\nNem %${round(cur.relative_humidity_2m)}, rüzgar ${round(cur.wind_speed_10m)} km/sa`;
  if (typeof min === 'number' && typeof max === 'number') text += `\nBugün en düşük ${round(min)}°C, en yüksek ${round(max)}°C`;
  if (typeof rain === 'number') text += `, yağış ihtimali %${round(rain)}`;

  weatherCache.set(key, { t: Date.now(), text });
  return text;
}

const JOKES = [
  'Bilgisayar neden doktora gitmiş? Virüs kapmış.',
  'Matematik kitabı neden üzgünmüş? Çünkü çok problemi varmış.',
  'Telefon neden hiç yalan söylemez? Çünkü her şeyi kayda alıyor.',
  'Ağaç neden internete giremiyormuş? Çünkü hep dalgın olduğu için şifreyi unutuyormuş.',
  'Saat neden mutluymuş? Çünkü hep zamanında geliyormuş.',
];

const HELP =
  'Komutlar:\n' +
  '/hava [şehir] - hava durumu (şehir yazmazsan İstanbul)\n' +
  '/zar [yüz sayısı] - zar at\n' +
  '/yazıtura - yazı tura at\n' +
  '/seç a, b, c - birini seçerim\n' +
  '/saat - saat kaç\n' +
  '/şaka - bir şaka\n' +
  '/yardım - bu liste';

async function handleCommand(convId, body) {
  const [rawCmd, ...rest] = body.split(/\s+/);
  const cmd = norm(rawCmd.slice(1));
  const arg = rest.join(' ').trim();
  const say = (t) => botSay(convId, t);

  switch (cmd) {
    case 'yardim':
    case 'help':
      return say(HELP);
    case 'hava': {
      const city = (arg || 'İstanbul').slice(0, 60);
      try {
        return say(await getWeather(city));
      } catch (_) {
        return say('Hava durumunu şu an alamadım, biraz sonra tekrar dene.');
      }
    }
    case 'zar': {
      let sides = parseInt(arg, 10);
      if (!Number.isInteger(sides) || sides < 2) sides = 6;
      if (sides > 1000) sides = 1000;
      return say(`${sides} yüzlü zar: ${crypto.randomInt(1, sides + 1)}`);
    }
    case 'yazitura':
      return say(crypto.randomInt(0, 2) === 0 ? 'Yazı!' : 'Tura!');
    case 'sec': {
      const options = arg.split(/,|\sveya\s/i).map((s) => s.trim()).filter(Boolean).slice(0, 20);
      if (options.length < 2) return say('Örnek: /seç pizza, hamburger, kebap');
      return say('Ben şunu seçtim: ' + options[crypto.randomInt(0, options.length)]);
    }
    case 'saat':
      return say(
        'Saat ' +
          new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' })
      );
    case 'saka':
      return say(JOKES[crypto.randomInt(0, JOKES.length)]);
    default:
      return say('Bu komutu bilmiyorum. Komutları görmek için /yardım yaz.');
  }
}

// ---------- Socket.io ----------
const online = new Map(); // userId -> { username, count }
function broadcastPresence() {
  io.emit('presence', [...online.values()].map((u) => u.username));
}

// Sesli oda: socket.id -> { username }
const voice = new Map();
const voiceNames = () => [...voice.values()].map((v) => v.username);
const broadcastVoice = () => io.emit('voice:members', voiceNames());
function leaveVoice(socket) {
  if (!voice.has(socket.id)) return;
  voice.delete(socket.id);
  socket.leave('voice');
  socket.to('voice').emit('voice:peer-left', socket.id);
  broadcastVoice();
}

io.use(async (socket, next) => {
  try {
    const user = await userForToken(socket.handshake.auth && socket.handshake.auth.token);
    if (!user) return next(new Error('auth'));
    socket.user = user;
    next();
  } catch (e) {
    console.error(e);
    next(new Error('server'));
  }
});

io.on('connection', (socket) => {
  const { id, username } = socket.user;
  const isAdmin = isAdminName(username);
  const entry = online.get(id) || { username, count: 0 };
  entry.count += 1;
  online.set(id, entry);
  broadcastPresence();
  socket.join('user:' + id);
  userConvIds(id)
    .then((ids) => ids.forEach((cid) => socket.join('conv:' + cid)))
    .catch((e) => console.error(e));
  socket.emit('voice:members', voiceNames());

  // Her olayda aynı kalıp: hata yakala, sınırla, ack ile cevap ver.
  const on = (event, handler, { limited = true } = {}) =>
    socket.on(event, async (payload, ack) => {
      const reply = typeof ack === 'function' ? ack : () => {};
      try {
        if (limited && !opLimit('sock:' + socket.id)) return reply({ error: 'Çok hızlı işlem yapıyorsun, biraz bekle.' });
        await handler(payload && typeof payload === 'object' ? payload : {}, reply);
      } catch (e) {
        console.error(event, e);
        reply({ error: 'Bir hata oluştu, tekrar dene.' });
      }
    });

  on(
    'message',
    async (p, reply) => {
      const convId = int(p.convId);
      if (convId == null || typeof p.text !== 'string') return reply({ error: 'Geçersiz mesaj.' });
      if (!(await isMember(convId, id))) return reply({ error: 'Bu sohbete erişimin yok.' });
      const body = p.text.trim();
      if (!body) return reply({ error: 'Mesaj boş.' });
      if (body.length > MAX_MESSAGE_LENGTH) return reply({ error: `Mesaj en fazla ${MAX_MESSAGE_LENGTH} karakter olabilir.` });
      if (!msgLimit(socket.id)) return reply({ error: 'Çok hızlı yazıyorsun, biraz bekle.' });

      // Başkan "/bot mesaj" yazarak botun hesabından mesaj gönderebilir.
      if (isAdmin && /^\/bot(\s|$)/i.test(body)) {
        const botText = body.slice(4).trim();
        if (!botText) return reply({ error: 'Örnek: /bot Herkese merhaba' });
        await botSay(convId, botText);
        return reply({ ok: true });
      }

      await createMessage({ convId, userId: id, body, replyTo: p.replyTo != null ? int(p.replyTo) : null });
      reply({ ok: true });
      if (body.startsWith('/') && body.length > 1) handleCommand(convId, body).catch((e) => console.error(e));
    },
    { limited: false }
  );

  on('message:edit', async (p, reply) => {
    const mid = int(p.id);
    const text = typeof p.text === 'string' ? p.text.trim() : '';
    const m = mid == null ? null : await q.one('SELECT id, conv_id, user_id, kind, deleted_at, body FROM messages WHERE id = ?', [mid]);
    if (!m || m.deleted_at != null || !(await isMember(Number(m.conv_id), id))) return reply({ error: 'Mesaj bulunamadı.' });
    if (m.kind !== 'text') return reply({ error: 'Bu mesaj düzenlenemez.' });
    const mine = Number(m.user_id) === id;
    if (!mine && !isAdmin) return reply({ error: 'Sadece kendi mesajını düzenleyebilirsin.' });
    if (!text) return reply({ error: 'Mesaj boş olamaz.' });
    if (text.length > MAX_MESSAGE_LENGTH) return reply({ error: `Mesaj en fazla ${MAX_MESSAGE_LENGTH} karakter olabilir.` });
    if (text === m.body) return reply({ ok: true });
    await q.run('UPDATE messages SET body = ?, edited_at = ?, edited_by_admin = ? WHERE id = ?', [text, Date.now(), mine ? 0 : 1, mid]);
    await emitUpdate(mid);
    reply({ ok: true });
  });

  on('message:delete', async (p, reply) => {
    const mid = int(p.id);
    const m = mid == null ? null : await q.one('SELECT id, conv_id, user_id, kind, file_id, deleted_at FROM messages WHERE id = ?', [mid]);
    if (!m || m.deleted_at != null || !(await isMember(Number(m.conv_id), id))) return reply({ error: 'Mesaj bulunamadı.' });
    if (m.kind === 'system') return reply({ error: 'Bu mesaj silinemez.' });
    if (Number(m.user_id) !== id && !isAdmin) return reply({ error: 'Sadece kendi mesajını silebilirsin.' });
    const stmts = [
      ["UPDATE messages SET deleted_at = ?, body = '', file_id = NULL, pinned_at = NULL, pinned_by = NULL WHERE id = ?", [Date.now(), mid]],
      ['DELETE FROM reactions WHERE message_id = ?', [mid]],
    ];
    if (m.file_id != null) stmts.push(['DELETE FROM files WHERE id = ?', [Number(m.file_id)]]);
    await q.batch(stmts);
    await emitUpdate(mid);
    reply({ ok: true });
  });

  on('message:react', async (p, reply) => {
    const mid = int(p.id);
    const emoji = typeof p.emoji === 'string' ? p.emoji : '';
    if (!REACTIONS.includes(emoji)) return reply({ error: 'Geçersiz tepki.' });
    const m = mid == null ? null : await q.one('SELECT id, conv_id, kind, deleted_at FROM messages WHERE id = ?', [mid]);
    if (!m || m.deleted_at != null || m.kind === 'system' || !(await isMember(Number(m.conv_id), id))) return reply({ error: 'Mesaj bulunamadı.' });
    const cur = await q.one('SELECT emoji FROM reactions WHERE message_id = ? AND user_id = ?', [mid, id]);
    if (cur && cur.emoji === emoji) {
      await q.run('DELETE FROM reactions WHERE message_id = ? AND user_id = ?', [mid, id]);
    } else {
      await q.run(
        'INSERT INTO reactions (message_id, user_id, emoji) VALUES (?, ?, ?) ON CONFLICT(message_id, user_id) DO UPDATE SET emoji = excluded.emoji',
        [mid, id, emoji]
      );
    }
    await emitUpdate(mid);
    reply({ ok: true });
  });

  on('message:pin', async (p, reply) => {
    const mid = int(p.id);
    const m = mid == null ? null : await q.one('SELECT id, conv_id, kind, deleted_at, pinned_at FROM messages WHERE id = ?', [mid]);
    if (!m || m.deleted_at != null || m.kind === 'system' || !(await isMember(Number(m.conv_id), id))) return reply({ error: 'Mesaj bulunamadı.' });
    if (p.pinned) {
      if (m.pinned_at == null) {
        const cnt = await q.one('SELECT COUNT(*) AS n FROM messages WHERE conv_id = ? AND pinned_at IS NOT NULL', [Number(m.conv_id)]);
        if (Number(cnt.n) >= MAX_PINS) return reply({ error: `En fazla ${MAX_PINS} mesaj sabitlenebilir.` });
        await q.run('UPDATE messages SET pinned_at = ?, pinned_by = ? WHERE id = ?', [Date.now(), id, mid]);
      }
    } else {
      await q.run('UPDATE messages SET pinned_at = NULL, pinned_by = NULL WHERE id = ?', [mid]);
    }
    await emitUpdate(mid);
    reply({ ok: true });
  });

  on(
    'read',
    async (p) => {
      const convId = int(p.convId);
      const upTo = int(p.upTo);
      if (convId == null || upTo == null || upTo < 0 || !(await isMember(convId, id))) return;
      const r = await q.run(
        `UPDATE members
         SET last_read_id = MAX(last_read_id, MIN(?, COALESCE((SELECT MAX(id) FROM messages WHERE conv_id = ?), 0)))
         WHERE conv_id = ? AND user_id = ? RETURNING last_read_id`,
        [upTo, convId, convId, id]
      );
      const row = r.rows[0];
      if (row) io.to('conv:' + convId).emit('read:update', { convId, userId: id, lastReadId: Number(row.last_read_id) });
    },
    { limited: false }
  );

  on(
    'typing',
    async (p) => {
      const convId = int(p.convId);
      if (convId == null || !(await isMember(convId, id))) return;
      socket.to('conv:' + convId).emit('typing', { convId, username });
    },
    { limited: false }
  );

  // ---- Sesli görüşme (WebRTC sinyalleşmesi) ----
  on('voice:join', async (p, reply) => {
    const already = voice.has(socket.id);
    if (!already && voice.size >= MAX_VOICE) return reply({ error: `Sesli oda dolu (en fazla ${MAX_VOICE} kişi).` });
    const peers = [...voice.entries()].filter(([sid]) => sid !== socket.id).map(([sid, v]) => ({ id: sid, username: v.username }));
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

initDb()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Bizimki http://localhost:${PORT} adresinde çalışıyor`);
    });
  })
  .catch((e) => {
    console.error('Veritabanı başlatılamadı:', e);
    process.exit(1);
  });
