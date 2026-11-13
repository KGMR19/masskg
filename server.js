const express = require('express');
const http = require('http');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const { createClient } = require('@libsql/client');

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me';

// Подключение к Turso
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Инициализация таблиц при запуске
async function initDB() {
  try {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        passwordHash TEXT NOT NULL,
        avatar TEXT,
        publicKey TEXT,
        contacts TEXT DEFAULT '[]',
        createdAt INTEGER NOT NULL
      )
    `);
    await db.execute(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fromId INTEGER NOT NULL,
        toId INTEGER NOT NULL,
        body TEXT NOT NULL,
        iv TEXT,
        type TEXT DEFAULT 'text',
        read INTEGER DEFAULT 0,
        createdAt INTEGER NOT NULL
      )
    `);
    console.log('✅ Таблицы Turso готовы');
  } catch (e) {
    console.error('❌ Ошибка инициализации Turso:', e);
  }
}
initDB();

/* ---------- HTTP ---------- */
const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const loginAttempts = new Map();
setInterval(() => loginAttempts.clear(), 15 * 60 * 1000);

app.get('/api/health', async (_, res) => {
  try {
    const users = await db.execute('SELECT COUNT(*) as c FROM users');
    res.json({ ok: true, users: users.rows[0].c });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Нужны логин и пароль' });
    const u = username.trim();
    if (u.length < 3) return res.status(400).json({ error: 'Логин — минимум 3 символа' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль — минимум 6 символов' });

    const hash = bcrypt.hashSync(password, 10);
    const result = await db.execute({
      sql: 'INSERT INTO users (username, passwordHash, createdAt) VALUES (?, ?, ?)',
      args: [u, hash, Date.now()]
    });

    const user = { id: Number(result.lastInsertRowid), username: u, avatar: null, publicKey: null };
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Логин занят' });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const ip = req.ip;
    if ((loginAttempts.get(ip) || 0) > 10) return res.status(429).json({ error: 'Слишком много попыток.' });

    const result = await db.execute({
      sql: 'SELECT * FROM users WHERE username = ?',
      args: [String(username || '').trim()]
    });
    
    const user = result.rows[0];
    if (!user || !bcrypt.compareSync(String(password || ''), user.passwordHash)) {
      loginAttempts.set(ip, (loginAttempts.get(ip) || 0) + 1);
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    loginAttempts.delete(ip);
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar, publicKey: user.publicKey } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/change-password', async (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    const userRes = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [payload.id] });
    const user = userRes.rows[0];
    
    if (!user || !bcrypt.compareSync(req.body.oldPassword, user.passwordHash))
      return res.status(400).json({ error: 'Неверный текущий пароль' });

    const newHash = bcrypt.hashSync(req.body.newPassword, 10);
    await db.execute({ sql: 'UPDATE users SET passwordHash = ? WHERE id = ?', args: [newHash, payload.id] });
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
});

app.post('/api/public-key', async (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    await db.execute({ sql: 'UPDATE users SET publicKey = ? WHERE id = ?', args: [req.body.publicKey, payload.id] });
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
});

app.post('/api/avatar', async (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    await db.execute({ sql: 'UPDATE users SET avatar = ? WHERE id = ?', args: [req.body.avatar, payload.id] });
    res.json({ ok: true, avatar: req.body.avatar });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
});

/* ---------- Socket.io ---------- */
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 2e7 });

io.use(async (socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token || '', JWT_SECRET);
    const res = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [payload.id] });
    if (!res.rows[0]) return next(new Error('unauthorized'));
    socket.user = { id: res.rows[0].id, username: res.rows[0].username };
    next();
  } catch { next(new Error('unauthorized')); }
});

const online = new Map();

const getContactsList = async (userId) => {
  const res = await db.execute({ sql: 'SELECT contacts FROM users WHERE id = ?', args: [userId] });
  if (!res.rows[0]) return [];
  const contactIds = JSON.parse(res.rows[0].contacts || '[]');
  if (contactIds.length === 0) return [];

  const placeholders = contactIds.map(() => '?').join(',');
  const usersRes = await db.execute({ sql: `SELECT id, username, avatar, publicKey FROM users WHERE id IN (${placeholders})`, args: contactIds });
  return usersRes.rows;
};

io.on('connection', async (socket) => {
  const me = socket.user;
  if (!online.has(me.id)) online.set(me.id, new Set());
  online.get(me.id).add(socket.id);
  io.emit('online', [...online.keys()]);

  const sendUsers = async () => {
    const list = await getContactsList(me.id);
    socket.emit('users', list);
  };
  sendUsers();

  socket.on('users', async (cb) => { cb(await getContactsList(me.id)); });

  socket.on('add-contact', async ({ username }, cb) => {
    try {
      const targetRes = await db.execute({ sql: 'SELECT * FROM users WHERE LOWER(username) = LOWER(?)', args: [String(username || '').trim()] });
      const target = targetRes.rows[0];
      const meRes = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [me.id] });
      const meUser = meRes.rows[0];

      if (!target) return cb({ error: 'Пользователь не найден' });
      if (target.id === me.id) return cb({ error: 'Это вы' });
      
      const myContacts = JSON.parse(meUser.contacts || '[]');
      if (myContacts.includes(target.id)) return cb({ error: 'Уже в контактах' });

      myContacts.push(target.id);
      await db.execute({ sql: 'UPDATE users SET contacts = ? WHERE id = ?', args: [JSON.stringify(myContacts), me.id] });

      const targetContacts = JSON.parse(target.contacts || '[]');
      if (!targetContacts.includes(me.id)) {
        targetContacts.push(me.id);
        await db.execute({ sql: 'UPDATE users SET contacts = ? WHERE id = ?', args: [JSON.stringify(targetContacts), target.id] });
      }

      cb({ ok: true });
      io.to([...online.get(me.id) || []]).emit('users', await getContactsList(me.id));
      io.to([...online.get(target.id) || []]).emit('users', await getContactsList(target.id));
    } catch (e) { cb({ error: e.message }); }
  });

  socket.on('history', async ({ withId }, cb) => {
    try {
      const res = await db.execute({
        sql: `SELECT * FROM messages WHERE (fromId = ? AND toId = ?) OR (fromId = ? AND toId = ?) ORDER BY createdAt ASC LIMIT 200`,
        args: [me.id, withId, withId, me.id]
      });
      
      await db.execute({
        sql: `UPDATE messages SET read = 1 WHERE fromId = ? AND toId = ? AND read = 0`,
        args: [withId, me.id]
      });
      
      const targetSockets = online.get(withId);
      if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('messages-read');

      cb(res.rows.map(r => ({ ...r, read: r.read === 1 })));
    } catch (e) { cb([]); }
  });

  socket.on('typing', ({ toId, isTyping }) => {
    const targetSockets = online.get(toId);
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('typing', { fromId: me.id, isTyping });
  });

  socket.on('message', async ({ toId, body, type, iv }, ack) => {
    try {
      const result = await db.execute({
        sql: 'INSERT INTO messages (fromId, toId, body, iv, type, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
        args: [me.id, toId, body, iv, type || 'text', Date.now()]
      });
      
      const msg = {
        id: Number(result.lastInsertRowid), fromId: me.id, toId: Number(toId),
        body, iv, type: type || 'text', read: false, createdAt: Date.now()
      };

      const deliver = (uid, message) => {
        const set = online.get(uid);
        if (set) for (const sid of set) io.to(sid).emit('message', message);
      };
      deliver(toId, msg);
      for (const sid of online.get(me.id) || []) { if (sid !== socket.id) io.to(sid).emit('message', msg); }
      if (ack) ack({ ok: true, msg });
    } catch (e) { if (ack) ack({ error: e.message }); }
  });

  socket.on('mark-read', async ({ toId }) => {
    await db.execute({ sql: 'UPDATE messages SET read = 1 WHERE fromId = ? AND toId = ?', args: [toId, me.id] });
    const targetSockets = online.get(toId);
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('messages-read');
  });

  // Звонки (без изменений)
  socket.on('call-user', ({ toId, offer, type }) => { const t = online.get(Number(toId)); if (t) for (const sid of t) io.to(sid).emit('incoming-call', { fromId: me.id, fromName: me.username, offer, type }); });
  socket.on('answer-call', ({ toId, answer }) => { const t = online.get(Number(toId)); if (t) for (const sid of t) io.to(sid).emit('call-answered', { answer }); });
  socket.on('ice-candidate', ({ toId, candidate }) => { const t = online.get(Number(toId)); if (t) for (const sid of t) io.to(sid).emit('ice-candidate', { candidate }); });
  socket.on('end-call', ({ toId }) => { const t = online.get(Number(toId)); if (t) for (const sid of t) io.to(sid).emit('call-ended'); });

  socket.on('disconnect', () => {
    const set = online.get(me.id);
    if (set) { set.delete(socket.id); if (!set.size) online.delete(me.id); }
    io.emit('online', [...online.keys()]);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ Сервер с Turso запущен на порту ${PORT}\n`);
});
