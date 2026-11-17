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
        avatar TEXT, bio TEXT, lastSeen INTEGER, contacts TEXT DEFAULT '[]', createdAt INTEGER NOT NULL
    )`);
    await dbQuery(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, fromId INTEGER NOT NULL, toId INTEGER,
        body TEXT NOT NULL, type TEXT DEFAULT 'text', read INTEGER DEFAULT 0, createdAt INTEGER NOT NULL
    )`);
    await dbQuery(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, type TEXT DEFAULT 'group',
        avatar TEXT, members TEXT DEFAULT '[]', admins TEXT DEFAULT '[]', createdAt INTEGER NOT NULL
    )`);
    
    try { await dbQuery(`ALTER TABLE messages ADD COLUMN groupId INTEGER`); } catch (e) {}
    try { await dbQuery(`ALTER TABLE messages ADD COLUMN reactions TEXT DEFAULT '[]'`); } catch (e) {}
    try { await dbQuery(`ALTER TABLE messages ADD COLUMN replyTo INTEGER`); } catch (e) {}
    try { await dbQuery(`ALTER TABLE messages ADD COLUMN selfDestruct INTEGER`); } catch (e) {}
    try { await dbQuery(`ALTER TABLE users ADD COLUMN bio TEXT`); } catch (e) {}
    try { await dbQuery(`ALTER TABLE users ADD COLUMN lastSeen INTEGER`); } catch (e) {}
    try { await dbQuery(`ALTER TABLE users ADD COLUMN settings TEXT DEFAULT '{}'`); } catch (e) {}

    console.log('✅ Таблицы GhoFlux готовы');
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
    const user = { id: result.lastInsertRowid, username: username.trim(), avatar: null, bio: null, settings: '{}' };
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
    res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar, bio: user.bio, settings: user.settings || '{}' } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/profile', async (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    await dbQuery('UPDATE users SET avatar = ?, bio = ?, settings = ? WHERE id = ?', [req.body.avatar, req.body.bio, req.body.settings || '{}', payload.id]);
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
});

app.post('/api/change-password', async (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    const userRes = await dbQuery('SELECT * FROM users WHERE id = ?', [payload.id]);
    const user = userRes.rows[0];
    if (!user || !bcrypt.compareSync(req.body.oldPassword, user.passwordHash))
      return res.status(400).json({ error: 'Неверный пароль' });
    const newHash = bcrypt.hashSync(req.body.newPassword, 10);
    await dbQuery('UPDATE users SET passwordHash = ? WHERE id = ?', [newHash, payload.id]);
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
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
  const usersRes = await dbQuery(`SELECT id, username, avatar, bio, lastSeen FROM users WHERE id IN (${placeholders})`, ids);
  return usersRes.rows;
};

const getGroupsList = async (userId) => {
  const res = await dbQuery(`SELECT * FROM groups WHERE members LIKE ?`, [`%${userId}%`]);
  return res.rows.map(g => ({ ...g, members: JSON.parse(g.members), admins: JSON.parse(g.admins) }));
};

const parseMsg = (r) => ({
  ...r, 
  read: r.read === 1,
  reactions: JSON.parse(r.reactions || '[]')
});

io.on('connection', async (socket) => {
  const me = socket.user;
  if (!online.has(me.id)) online.set(me.id, new Set());
  online.get(me.id).add(socket.id);
  io.emit('online', [...online.keys()]);
  await dbQuery('UPDATE users SET lastSeen = ? WHERE id = ?', [Date.now(), me.id]);

  socket.on('get-data', async (cb) => {
    const userRes = await dbQuery('SELECT settings FROM users WHERE id = ?', [me.id]);
    cb({ contacts: await getContactsList(me.id), groups: await getGroupsList(me.id), settings: userRes.rows[0]?.settings || '{}' });
  });

  socket.on('force-refresh', () => { io.emit('refresh-data'); });

  socket.on('save-settings', async ({ settings }, cb) => {
    try {
      await dbQuery('UPDATE users SET settings = ? WHERE id = ?', [JSON.stringify(settings), me.id]);
      if (cb) cb({ ok: true });
    } catch(e) { if (cb) cb({ error: e.message }); }
  });

  socket.on('typing', ({ toId, groupId, isTyping }) => {
    if (groupId) {
      dbQuery('SELECT members FROM groups WHERE id = ?', [groupId]).then(res => {
        if (!res.rows[0]) return;
        const members = JSON.parse(res.rows[0].members).filter(id => id !== me.id);
        members.forEach(uid => {
          const set = online.get(uid);
          if (set) for (const sid of set) io.to(sid).emit('typing', { fromId: me.id, isTyping });
        });
      });
    } else {
      const set = online.get(toId);
      if (set) for (const sid of set) io.to(sid).emit('typing', { fromId: me.id, isTyping });
    }
  });

  socket.on('toggle-reaction', async ({ msgId, emoji }) => {
    try {
      const msgRes = await dbQuery('SELECT * FROM messages WHERE id = ?', [msgId]);
      const msg = msgRes.rows[0];
      if (!msg) return;
      let reactions = JSON.parse(msg.reactions || '[]');
      const existing = reactions.find(r => r.userId === me.id);
      if (existing && existing.emoji === emoji) {
        reactions = reactions.filter(r => r.userId !== me.id);
      } else {
        reactions = reactions.filter(r => r.userId !== me.id);
        reactions.push({ userId: me.id, emoji });
      }
      await dbQuery('UPDATE messages SET reactions = ? WHERE id = ?', [JSON.stringify(reactions), msgId]);
      
      const payload = { msgId, reactions };
      if (msg.groupId) {
        const g = await dbQuery('SELECT members FROM groups WHERE id = ?', [msg.groupId]);
        if (g.rows[0]) JSON.parse(g.rows[0].members).forEach(uid => {
          const set = online.get(uid);
          if (set) for (const sid of set) io.to(sid).emit('reaction-updated', payload);
        });
      } else {
        const deliver = (uid) => {
          const set = online.get(uid);
          if (set) for (const sid of set) io.to(sid).emit('reaction-updated', payload);
        };
        deliver(msg.fromId); deliver(msg.toId);
      }
    } catch(e) {}
  });

  socket.on('delete-message', async ({ msgId, toId, groupId }) => {
    try {
      await dbQuery('DELETE FROM messages WHERE id = ?', [msgId]);
      const deliver = (uid) => {
        const set = online.get(uid);
        if (set) for (const sid of set) io.to(sid).emit('msg-deleted', { msgId });
      };
      if (groupId) {
        const res = await dbQuery('SELECT members FROM groups WHERE id = ?', [groupId]);
        if (res.rows[0]) JSON.parse(res.rows[0].members).forEach(deliver);
      } else { deliver(toId); deliver(me.id); }
    } catch(e) {}
  });

  socket.on('search-messages', async ({ query }, cb) => {
    try {
      const rows = await dbQuery(
        `SELECT m.*, u.username as fromUsername FROM messages m 
         LEFT JOIN users u ON m.fromId = u.id
         WHERE m.body LIKE ? AND (m.toId = ? OR m.fromId = ? OR m.groupId IN (
           SELECT id FROM groups WHERE members LIKE ?
         )) ORDER BY m.createdAt DESC LIMIT 50`,
        [`%${query}%`, me.id, me.id, `%${me.id}%`]
      );
      cb(rows.rows.map(parseMsg));
    } catch (e) { cb([]); }
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

  socket.on('delete-chat', async ({ id, isGroup }, cb) => {
    try {
      if (isGroup) {
        const groupRes = await dbQuery('SELECT admins FROM groups WHERE id = ?', [id]);
        if (!groupRes.rows[0]) return cb({ error: 'Группа не найдена' });
        const admins = JSON.parse(groupRes.rows[0].admins);
        if (!admins.includes(me.id)) return cb({ error: 'Только создатель' });
        await dbQuery('DELETE FROM groups WHERE id = ?', [id]);
        await dbQuery('DELETE FROM messages WHERE groupId = ?', [id]);
        io.emit('chat-deleted', { id, isGroup });
      } else {
        const idToDelete = Number(id);
        await dbQuery('DELETE FROM messages WHERE (fromId = ? AND toId = ?) OR (fromId = ? AND toId = ?)', [me.id, idToDelete, idToDelete, me.id]);
        
        const meRes = await dbQuery('SELECT contacts FROM users WHERE id = ?', [me.id]);
        if (meRes.rows[0]) {
          let contacts = JSON.parse(meRes.rows[0].contacts || '[]').filter(c => c !== idToDelete);
          await dbQuery('UPDATE users SET contacts = ? WHERE id = ?', [JSON.stringify(contacts), me.id]);
        }
        const targetRes = await dbQuery('SELECT contacts FROM users WHERE id = ?', [idToDelete]);
        if (targetRes.rows[0]) {
          let targetContacts = JSON.parse(targetRes.rows[0].contacts || '[]').filter(c => c !== me.id);
          await dbQuery('UPDATE users SET contacts = ? WHERE id = ?', [JSON.stringify(targetContacts), idToDelete]);
        }
        const targetSockets = online.get(idToDelete);
        if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('chat-deleted', { id: me.id, isGroup: false });
        socket.emit('chat-deleted', { id: idToDelete, isGroup: false });
      }
      cb({ ok: true });
      io.emit('refresh-data');
    } catch (e) { cb({ error: e.message }); }
  });

  socket.on('clear-all-chats', async (cb) => {
    try {
      await dbQuery('DELETE FROM messages WHERE fromId = ? OR toId = ?', [me.id, me.id]);
      const meRes = await dbQuery('SELECT contacts FROM users WHERE id = ?', [me.id]);
      if (meRes.rows[0]) {
        let contacts = JSON.parse(meRes.rows[0].contacts || '[]');
        for (const cid of contacts) {
          const targetRes = await dbQuery('SELECT contacts FROM users WHERE id = ?', [cid]);
          if (targetRes.rows[0]) {
            let tc = JSON.parse(targetRes.rows[0].contacts || '[]').filter(c => c !== me.id);
            await dbQuery('UPDATE users SET contacts = ? WHERE id = ?', [JSON.stringify(tc), cid]);
          }
        }
        await dbQuery('UPDATE users SET contacts = ? WHERE id = ?', [JSON.stringify([]), me.id]);
      }
      socket.emit('all-chats-cleared');
      cb({ ok: true });
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
        ? `SELECT * FROM messages WHERE groupId = ? ORDER BY createdAt ASC LIMIT 300`
        : `SELECT * FROM messages WHERE (fromId = ? AND toId = ?) OR (fromId = ? AND toId = ?) ORDER BY createdAt ASC LIMIT 300`;
      const args = isGroup ? [withId] : [me.id, withId, withId, me.id];
      const res = await dbQuery(sql, args);
      cb(res.rows.map(parseMsg));
    } catch (e) { cb([]); }
  });

  socket.on('message', async ({ toId, groupId, body, type, replyTo, selfDestruct }, ack) => {
    try {
      const isGroup = !!groupId;
      const result = await dbQuery(
        'INSERT INTO messages (fromId, toId, groupId, body, type, replyTo, selfDestruct, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [me.id, toId || null, groupId || null, body, type || 'text', replyTo || null, selfDestruct || null, Date.now()]
      );
      
      const msg = { id: result.lastInsertRowid, fromId: me.id, username: me.username, toId, groupId, body, type: type || 'text', read: false, replyTo, selfDestruct, reactions: [], createdAt: Date.now() };
      if (replyTo) {
        const r = await dbQuery('SELECT m.*, u.username as fromUsername FROM messages m LEFT JOIN users u ON m.fromId = u.id WHERE m.id = ?', [replyTo]);
        if (r.rows[0]) msg.replyData = { body: r.rows[0].body, username: r.rows[0].fromUsername, type: r.rows[0].type };
      }

      const deliver = (uid, message) => {
        const set = online.get(uid);
        if (set) for (const sid of set) io.to(sid).emit('message', message);
      };
      if (isGroup) {
        const g = await dbQuery('SELECT members FROM groups WHERE id = ?', [groupId]);
        if (g.rows[0]) JSON.parse(g.rows[0].members).forEach(uid => deliver(uid, msg));
      } else {
        deliver(toId, msg);
        for (const sid of online.get(me.id) || []) { if (sid !== socket.id) io.to(sid).emit('message', msg); }
      }
      if (ack) ack({ ok: true, msg });
    } catch (e) { if (ack) ack({ error: e.message }); }
  });

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

  socket.on('disconnect', async () => {
    const set = online.get(me.id);
    if (set) { 
      set.delete(socket.id); 
      if (!set.size) { 
        online.delete(me.id); 
        await dbQuery('UPDATE users SET lastSeen = ? WHERE id = ?', [Date.now(), me.id]);
      } 
    }
    io.emit('online', [...online.keys()]);
  });
});

// Автоудаление сообщений с таймером
setInterval(async () => {
  try {
    const now = Date.now();
    const expired = await dbQuery('SELECT id, fromId, toId, groupId FROM messages WHERE selfDestruct IS NOT NULL AND selfDestruct < ?', [now]);
    for (const m of expired.rows) {
      await dbQuery('DELETE FROM messages WHERE id = ?', [m.id]);
      const deliver = (uid) => {
        const set = online.get(uid);
        if (set) for (const sid of set) io.to(sid).emit('msg-deleted', { msgId: m.id });
      };
      if (m.groupId) {
        const g = await dbQuery('SELECT members FROM groups WHERE id = ?', [m.groupId]);
        if (g.rows[0]) JSON.parse(g.rows[0].members).forEach(deliver);
      } else { deliver(m.fromId); deliver(m.toId); }
    }
  } catch(e) {}
}, 10000);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 GhoFlux v6.0 (MAX) запущен на порту ${PORT}\n`);
});
