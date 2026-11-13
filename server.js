const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me';
const DATA_FILE = path.join(__dirname, 'data.json');

/* ---------- Хранилище ---------- */
let state = { nextUserId: 1, nextMsgId: 1, users: [], messages: [] };
if (fs.existsSync(DATA_FILE)) {
  try { state = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (e) { console.error('⚠ data.json повреждён, начинаю с пустой БД:', e.message); }
}

// Гарантируем наличие массивов
if (!state.users) state.users = [];
if (!state.messages) state.messages = [];

let saveTimer = null;
function persist() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try { fs.writeFileSync(DATA_FILE, JSON.stringify(state)); }
    catch (e) { console.error('Ошибка записи в файл:', e); }
  }, 100);
}

// УМНЫЙ ПОИСК (без учета регистра и пробелов)
const findUserByName = (u) => {
  if (!u) return null;
  return state.users.find(x => x.username.toLowerCase() === u.toLowerCase().trim());
};
const findUserById = (id) => state.users.find(x => x.id === Number(id));

/* ---------- HTTP ---------- */
const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (_, res) => res.json({ ok: true, users: state.users.length }));

app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Нужны логин и пароль' });
  
  const u = username.trim();
  if (u.length < 3) return res.status(400).json({ error: 'Логин — минимум 3 символа' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль — минимум 6 символов' });
  if (findUserByName(u)) return res.status(409).json({ error: 'Такой логин уже занят' });

  const user = { 
    id: state.nextUserId++, username: u, passwordHash: bcrypt.hashSync(password, 10), 
    createdAt: Date.now(), contacts: [], avatar: null, publicKey: null
  };
  state.users.push(user);
  persist();

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar, publicKey: user.publicKey } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = findUserByName(String(username || ''));
  if (!user || !bcrypt.compareSync(String(password || ''), user.passwordHash))
    return res.status(401).json({ error: 'Неверный логин или пароль' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar, publicKey: user.publicKey } });
});

app.post('/api/change-password', (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    const user = findUserById(payload.id);
    if (!user || !bcrypt.compareSync(req.body.oldPassword, user.passwordHash))
      return res.status(400).json({ error: 'Неверный текущий пароль' });
    
    user.passwordHash = bcrypt.hashSync(req.body.newPassword, 10);
    persist();
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка авторизации' }); }
});

app.post('/api/public-key', (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    const user = findUserById(payload.id);
    if (user) { user.publicKey = req.body.publicKey; persist(); }
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
});

app.post('/api/avatar', (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET);
    const user = findUserById(payload.id);
    if (user) { user.avatar = req.body.avatar; persist(); res.json({ ok: true, avatar: user.avatar }); }
    else res.status(404).json({ error: 'Не найден' });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
});

/* ---------- Socket.io ---------- */
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 2e7 });

io.use((socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token || '', JWT_SECRET);
    const u = findUserById(payload.id);
    if (!u) return next(new Error('unauthorized'));
    socket.user = { id: u.id, username: u.username };
    next();
  } catch { next(new Error('unauthorized')); }
});

const online = new Map();

const getContactsList = (userId) => {
  const user = findUserById(userId);
  if (!user || !user.contacts) return [];
  return state.users
    .filter(u => user.contacts.includes(u.id))
    .map(u => ({ id: u.id, username: u.username, avatar: u.avatar, publicKey: u.publicKey }));
};

io.on('connection', (socket) => {
  const me = socket.user;
  if (!online.has(me.id)) online.set(me.id, new Set());
  online.get(me.id).add(socket.id);
  io.emit('online', [...online.keys()]);

  const sendUsers = () => {
    socket.emit('users', getContactsList(me.id));
  };
  sendUsers();

  socket.on('users', (cb) => { cb(getContactsList(me.id)); });

  socket.on('add-contact', ({ username }, cb) => {
    try {
      const target = findUserByName(String(username || ''));
      const meUser = findUserById(me.id);

      console.log(`[LOG] ${me.username} добавляет ${username}. Найден: ${target ? target.username : 'НЕТ'}`);

      if (!target) return cb({ error: 'Пользователь не найден. (Помните: на бесплатном Render все аккаунты стираются после 15 мин бездействия)' });
      if (target.id === me.id) return cb({ error: 'Нельзя добавить самого себя' });
      if (meUser.contacts.includes(target.id)) return cb({ error: 'Уже в контактах' });

      meUser.contacts.push(target.id);
      if (!target.contacts) target.contacts = [];
      if (!target.contacts.includes(me.id)) target.contacts.push(me.id);
      persist();

      cb({ ok: true });
      
      // Обновляем списки у обоих
      const meList = getContactsList(me.id);
      for (const sid of online.get(me.id) || []) io.to(sid).emit('users', meList);
      const targetList = getContactsList(target.id);
      for (const sid of online.get(target.id) || []) io.to(sid).emit('users', targetList);
    } catch (e) { cb({ error: 'Ошибка сервера: ' + e.message }); }
  });

  socket.on('history', ({ withId }, cb) => {
    const rows = state.messages
      .filter(m => (m.fromId === me.id && m.toId === withId) || (m.fromId === withId && m.toId === me.id))
      .slice(-200);
    
    let updated = false;
    rows.forEach(m => { if (m.toId === me.id && !m.read) { m.read = true; updated = true; } });
    if (updated) {
      persist();
      const targetSockets = online.get(withId);
      if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('messages-read');
    }
    cb(rows);
  });

  socket.on('typing', ({ toId, isTyping }) => {
    const targetSockets = online.get(Number(toId));
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('typing', { fromId: me.id, isTyping });
  });

  socket.on('message', ({ toId, body, type, iv }, ack) => {
    const target = findUserById(toId);
    if (!target || !body.trim()) return ack && ack({ error: 'Ошибка' });

    const msg = { id: state.nextMsgId++, fromId: me.id, toId: target.id, body, type: type || 'text', iv, read: false, createdAt: Date.now() };
    state.messages.push(msg);
    persist();

    const deliver = (uid, message) => {
      const set = online.get(uid);
      if (set) for (const sid of set) io.to(sid).emit('message', message);
    };
    deliver(target.id, msg);
    for (const sid of online.get(me.id) || []) { if (sid !== socket.id) io.to(sid).emit('message', msg); }
    if (ack) ack({ ok: true, msg });
  });

  socket.on('mark-read', ({ toId }) => {
    let updated = false;
    state.messages.forEach(m => { if (m.fromId === Number(toId) && m.toId === me.id && !m.read) { m.read = true; updated = true; } });
    if (updated) {
      persist();
      const targetSockets = online.get(Number(toId));
      if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('messages-read');
    }
  });

  socket.on('call-user', ({ toId, offer, type }) => {
    const targetSockets = online.get(Number(toId));
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('incoming-call', { fromId: me.id, fromName: me.username, offer, type });
  });
  socket.on('answer-call', ({ toId, answer }) => {
    const targetSockets = online.get(Number(toId));
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('call-answered', { answer });
  });
  socket.on('ice-candidate', ({ toId, candidate }) => {
    const targetSockets = online.get(Number(toId));
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('ice-candidate', { candidate });
  });
  socket.on('end-call', ({ toId }) => {
    const targetSockets = online.get(Number(toId));
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('call-ended');
  });

  socket.on('disconnect', () => {
    const set = online.get(me.id);
    if (set) { set.delete(socket.id); if (!set.size) online.delete(me.id); }
    io.emit('online', [...online.keys()]);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ Сервер с E2EE запущен на порту ${PORT}\n`);
});
