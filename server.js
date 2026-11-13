const express = require('express');
const http = require('http');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me';

const TURSO_URL = (process.env.TURSO_DATABASE_URL || '').replace('libsql://', 'https://').replace(/\/$/, '');
const TURSO_TOKEN = (process.env.TURSO_AUTH_TOKEN || '').trim(); 
const DB_ENDPOINT = `${TURSO_URL}/v2/pipeline`;

async function dbQuery(sql, args = []) {
  const formattedArgs = args.map(arg => {
    if (typeof arg === 'number') return { type: 'integer', value: String(arg) }; 
    if (typeof arg === 'string') return { type: 'text', value: arg };
    if (arg === null) return { type: 'null' };
    return { type: 'text', value: String(arg) };
  });

  const response = await fetch(DB_ENDPOINT, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${TURSO_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requests: [{ type: 'execute', stmt: { sql, args: formattedArgs } }, { type: 'close' }] })
  });

  if (!response.ok) throw new Error(`Turso Error: ${await response.text()}`);

  const data = await response.json();
  const result = data.results[0];
  if (result.type === 'error') throw new Error(result.error.message);
  
  const resData = result.response.result;
  const cols = resData.cols.map(c => c.name);
  const rows = resData.rows.map(row => {
    const obj = {};
    row.forEach((cell, i) => {
      obj[cols[i]] = cell.type === 'integer' ? Number(cell.value) : (cell.type === 'null' ? null : cell.value);
    });
    return obj;
  });

  return { rows, lastInsertRowid: resData.last_insert_rowid ? Number(resData.last_insert_rowid) : null };
}

async function initDB() {
  try {
    await dbQuery(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, passwordHash TEXT NOT NULL,
        avatar TEXT, publicKey TEXT, contacts TEXT DEFAULT '[]', createdAt INTEGER NOT NULL
    )`);
    await dbQuery(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, fromId INTEGER NOT NULL, toId INTEGER, groupId INTEGER,
        body TEXT NOT NULL, iv TEXT, type TEXT DEFAULT 'text', read INTEGER DEFAULT 0, createdAt INTEGER NOT NULL
    )`);
    await dbQuery(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, type TEXT DEFAULT 'group',
        avatar TEXT, members TEXT DEFAULT '[]', admins TEXT DEFAULT '[]', createdAt INTEGER NOT NULL
    )`);
    console.log('✅ Таблицы Turso готовы');
  } catch (e) { console.error('❌ Ошибка БД:', e.message); }
}
initDB();

const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Нужны логин и пароль' });
    const hash = bcrypt.hashSync(password, 10);
    const result = await dbQuery('INSERT INTO users (username, passwordHash, createdAt) VALUES (?, ?, ?)', [username.trim(), hash, Date.now()]);
    const user = { id: result.lastInsertRowid, username: username.trim(), avatar: null, publicKey: null };
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const result = await dbQuery('SELECT * FROM users WHERE username = ?', [String(username || '').trim()]);
    const user = result.rows[0];
    if (!user || !bcrypt.compareSync(String(password || ''), user.passwordHash)) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar, publicKey: user.publicKey } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/public-key', async (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    await dbQuery('UPDATE users SET publicKey = ? WHERE id = ?', [req.body.publicKey, payload.id]);
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
});

app.post('/api/avatar', async (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    await dbQuery('UPDATE users SET avatar = ? WHERE id = ?', [req.body.avatar, payload.id]);
    res.json({ ok: true, avatar: req.body.avatar });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
});

app.post('/api/change-password', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Нет токена' });
    const payload = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    const userRes = await dbQuery('SELECT * FROM users WHERE id = ?', [payload.id]);
    const user = userRes.rows[0];
    
    if (!user) return res.status(404).json({ error: 'Пользователь не найден. Выйдите и зарегистрируйтесь заново.' });
    if (!bcrypt.compareSync(req.body.oldPassword, user.passwordHash))
      return res.status(400).json({ error: 'Неверный текущий пароль' });

    const newHash = bcrypt.hashSync(req.body.newPassword, 10);
    await dbQuery('UPDATE users SET passwordHash = ? WHERE id = ?', [newHash, payload.id]);
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка сессии: ' + e.message }); }
});

const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 2e7 });

io.use(async (socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token || '', JWT_SECRET);
    const res = await dbQuery('SELECT * FROM users WHERE id = ?', [payload.id]);
    if (!res.rows[0]) return next(new Error('unauthorized'));
    socket.user = { id: res.rows[0].id, username: res.rows[0].username };
    next();
  } catch { next(new Error('unauthorized')); }
});

const online = new Map();

const getContactsList = async (userId) => {
  const res = await dbQuery('SELECT contacts FROM users WHERE id = ?', [userId]);
  if (!res.rows[0]) return [];
  const ids = JSON.parse(res.rows[0].contacts || '[]');
  if (ids.length === 0) return [];
  const placeholders = ids.map(() => '?').join(',');
  const usersRes = await dbQuery(`SELECT id, username, avatar, publicKey FROM users WHERE id IN (${placeholders})`, ids);
  return usersRes.rows;
};

const getGroupsList = async (userId) => {
  const res = await dbQuery(`SELECT * FROM groups WHERE members LIKE ?`, [`%${userId}%`]);
  return res.rows.map(g => ({ ...g, members: JSON.parse(g.members), admins: JSON.parse(g.admins) }));
};

io.on('connection', async (socket) => {
  const me = socket.user;
  if (!online.has(me.id)) online.set(me.id, new Set());
  online.get(me.id).add(socket.id);
  io.emit('online', [...online.keys()]);

  socket.on('get-data', async (cb) => {
    cb({ contacts: await getContactsList(me.id), groups: await getGroupsList(me.id) });
  });

  socket.on('create-group', async ({ name, type, memberIds }, cb) => {
    try {
      const members = [...new Set([me.id, ...memberIds])];
      const result = await dbQuery('INSERT INTO groups (name, type, members, admins, createdAt) VALUES (?, ?, ?, ?, ?)',
        [name, type, JSON.stringify(members), JSON.stringify([me.id]), Date.now()]);
      cb({ ok: true, groupId: result.lastInsertRowid });
      io.emit('refresh-data'); 
    } catch (e) { cb({ error: e.message }); }
  });

  socket.on('add-contact', async ({ username }, cb) => {
    try {
      const targetRes = await dbQuery('SELECT * FROM users WHERE LOWER(username) = LOWER(?)', [String(username || '').trim()]);
      const target = targetRes.rows[0];
      const meRes = await dbQuery('SELECT * FROM users WHERE id = ?', [me.id]);
      const meUser = meRes.rows[0];

      if (!target) return cb({ error: 'Пользователь не найден' });
      if (target.id === me.id) return cb({ error: 'Это вы' });
      
      const myContacts = JSON.parse(meUser.contacts || '[]');
      if (myContacts.includes(target.id)) return cb({ error: 'Уже в контактах' });

      myContacts.push(target.id);
      await dbQuery('UPDATE users SET contacts = ? WHERE id = ?', [JSON.stringify(myContacts), me.id]);

      const targetContacts = JSON.parse(target.contacts || '[]');
      if (!targetContacts.includes(me.id)) {
        targetContacts.push(me.id);
        await dbQuery('UPDATE users SET contacts = ? WHERE id = ?', [JSON.stringify(targetContacts), target.id]);
      }
      cb({ ok: true });
      io.emit('refresh-data');
    } catch (e) { cb({ error: e.message }); }
  });

  socket.on('history', async ({ withId, isGroup }, cb) => {
    try {
      const sql = isGroup 
        ? `SELECT * FROM messages WHERE groupId = ? ORDER BY createdAt ASC LIMIT 200`
        : `SELECT * FROM messages WHERE (fromId = ? AND toId = ?) OR (fromId = ? AND toId = ?) ORDER BY createdAt ASC LIMIT 200`;
      const args = isGroup ? [withId] : [me.id, withId, withId, me.id];
      
      const res = await dbQuery(sql, args);
      cb(res.rows.map(r => ({ ...r, read: r.read === 1 })));
    } catch (e) { cb([]); }
  });

  socket.on('message', async ({ toId, groupId, body, type, iv }, ack) => {
    try {
      const isGroup = !!groupId;
      const result = await dbQuery(
        'INSERT INTO messages (fromId, toId, groupId, body, iv, type, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [me.id, toId || null, groupId || null, body, iv, type || 'text', Date.now()]
      );
      
      const msg = { id: result.lastInsertRowid, fromId: me.id, username: me.username, toId, groupId, body, iv, type: type || 'text', read: false, createdAt: Date.now() };

      if (isGroup) {
        const groupRes = await dbQuery('SELECT members FROM groups WHERE id = ?', [groupId]);
        const members = JSON.parse(groupRes.rows[0].members);
        members.forEach(uid => {
          const set = online.get(uid);
          if (set) for (const sid of set) io.to(sid).emit('message', msg);
        });
      } else {
        const deliver = (uid, message) => {
          const set = online.get(uid);
          if (set) for (const sid of set) io.to(sid).emit('message', message);
        };
        deliver(toId, msg);
        for (const sid of online.get(me.id) || []) { if (sid !== socket.id) io.to(sid).emit('message', msg); }
      }
      if (ack) ack({ ok: true, msg });
    } catch (e) { if (ack) ack({ error: e.message }); }
  });

  // ГРУППОВЫЕ ЗВОНКИ
  const activeCalls = new Map(); 
  socket.on('join-call', async ({ groupId }) => {
    if (!activeCalls.has(groupId)) activeCalls.set(groupId, new Set());
    const callPeers = activeCalls.get(groupId);
    socket.emit('call-peers', { peers: [...callPeers] });
    callPeers.forEach(uid => {
      const set = online.get(uid);
      if (set) for (const sid of set) io.to(sid).emit('peer-joined', { peerId: me.id, username: me.username });
    });
    callPeers.add(me.id);
    socket.join(`call-${groupId}`);
  });
  socket.on('call-signal', ({ toId, signal }) => {
    const set = online.get(toId);
    if (set) for (const sid of set) io.to(sid).emit('call-signal', { fromId: me.id, signal });
  });
  socket.on('leave-call', ({ groupId }) => {
    if (activeCalls.has(groupId)) {
      const callPeers = activeCalls.get(groupId);
      callPeers.delete(me.id);
      socket.leave(`call-${groupId}`);
      callPeers.forEach(uid => {
        const set = online.get(uid);
        if (set) for (const sid of set) io.to(sid).emit('peer-left', { peerId: me.id });
      });
    }
  });

  socket.on('disconnect', () => {
    const set = online.get(me.id);
    if (set) { set.delete(socket.id); if (!set.size) online.delete(me.id); }
    io.emit('online', [...online.keys()]);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ Сервер запущен на порту ${PORT}\n`);
});
