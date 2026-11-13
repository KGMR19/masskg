const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const DATA_FILE = path.join(__dirname, 'data.json');

/* ---------- Хранилище ---------- */
let state = { nextUserId: 1, nextMsgId: 1, users: [], messages: [] };
if (fs.existsSync(DATA_FILE)) {
  try { state = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (e) { console.error('⚠ data.json повреждён, начинаю с пустой БД:', e.message); }
}

state.users.forEach(u => { 
  if (!u.contacts) u.contacts = []; 
  if (u.avatar === undefined) u.avatar = null;
});
state.users = state.users.filter(u => u.id !== -1);
state.messages = state.messages.filter(m => m.fromId !== -1 && m.toId !== -1);

let saveTimer = null;
function persist() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    fs.writeFileSync(DATA_FILE, JSON.stringify(state));
  }, 100);
}
const findUserByName = (u) => state.users.find(x => x.username === u);
const findUserById   = (id) => state.users.find(x => x.id === id);

/* ---------- HTTP ---------- */
const app = express();
// Увеличиваем лимит, так как аудио в Base64 весит прилично
app.use(express.json({ limit: '20mb' })); 
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (_, res) =>
  res.json({ ok: true, users: state.users.length, messages: state.messages.length }));

app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string')
    return res.status(400).json({ error: 'Нужны username и password' });
  const u = username.trim();
  if (u.length < 3) return res.status(400).json({ error: 'Логин — минимум 3 символа' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль — минимум 6 символов' });
  if (findUserByName(u))   return res.status(409).json({ error: 'Такой логин уже занят' });

  const user = { 
    id: state.nextUserId++, 
    username: u, 
    passwordHash: bcrypt.hashSync(password, 10), 
    createdAt: Date.now(),
    contacts: [],
    avatar: null
  };
  state.users.push(user);
  persist();

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = findUserByName(String(username || '').trim());
  if (!user || !bcrypt.compareSync(String(password || ''), user.passwordHash))
    return res.status(401).json({ error: 'Неверный логин или пароль' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

app.post('/api/avatar', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Нет токена' });
  
  try {
    const token = authHeader.split(' ')[1];
    const payload = jwt.verify(token, JWT_SECRET);
    const user = findUserById(payload.id);
    
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    
    user.avatar = req.body.avatar;
    persist();
    
    res.json({ ok: true, avatar: user.avatar });
  } catch (e) {
    res.status(401).json({ error: 'Неверный токен' });
  }
});

/* ---------- Socket.io ---------- */
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 2e7 }); // 20 MB для аудио

io.use((socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token || '', JWT_SECRET);
    const u = findUserById(payload.id);
    if (!u) return next(new Error('Пользователь не найден'));
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
    .map(u => ({ id: u.id, username: u.username, avatar: u.avatar }));
};

io.on('connection', (socket) => {
  const me = socket.user;
  if (!online.has(me.id)) online.set(me.id, new Set());
  online.get(me.id).add(socket.id);
  io.emit('online', [...online.keys()]);

  const sendUsers = (cb) => {
    const list = getContactsList(me.id);
    cb ? cb(list) : socket.emit('users', list);
  };
  sendUsers();

  socket.on('users', sendUsers);

  socket.on('add-contact', ({ username }, cb) => {
    const target = findUserByName(String(username || '').trim());
    const meUser = findUserById(me.id);

    if (!target) return cb({ error: 'Пользователь с таким логином не найден' });
    if (target.id === me.id) return cb({ error: 'Нельзя добавить самого себя' });
    if (meUser.contacts.includes(target.id)) return cb({ error: 'Этот пользователь уже в ваших контактах' });

    meUser.contacts.push(target.id);
    if (!target.contacts) target.contacts = [];
    target.contacts.push(me.id);
    persist();

    cb({ ok: true });

    const meList = getContactsList(me.id);
    for (const sid of online.get(me.id) || []) io.to(sid).emit('users', meList);

    const targetList = getContactsList(target.id);
    for (const sid of online.get(target.id) || []) io.to(sid).emit('users', targetList);
  });

  socket.on('history', ({ withId }, cb) => {
    const rows = state.messages.filter(m =>
      (m.fromId === me.id && m.toId === withId) || (m.fromId === withId && m.toId === me.id)
    ).slice(-200);
    
    // Помечаем сообщения от собеседника как прочитанные
    let updated = false;
    rows.forEach(m => {
      if (m.toId === me.id && !m.read) {
        m.read = true;
        updated = true;
      }
    });
    if (updated) {
      persist();
      const targetSockets = online.get(withId);
      if (targetSockets) {
        for (const sid of targetSockets) io.to(sid).emit('messages-read');
      }
    }

    if (cb) cb(rows);
  });

  socket.on('typing', ({ toId, isTyping }) => {
    const targetSockets = online.get(Number(toId));
    if (targetSockets) {
      for (const sid of targetSockets) {
        io.to(sid).emit('typing', { fromId: me.id, isTyping });
      }
    }
  });

  socket.on('message', ({ toId, body, type }, ack) => {
    body = String(body || '').slice(0, 4000000); // Лимит на размер аудио
    const target = findUserById(Number(toId));
    if (!target || !body.trim()) return ack && ack({ error: 'Некорректное сообщение' });

    const msg = { id: state.nextMsgId++, fromId: me.id, toId: target.id, body, type: type || 'text', createdAt: Date.now(), read: false };
    state.messages.push(msg);
    persist();

    const deliver = (uid, message) => {
      const set = online.get(uid);
      if (!set) return;
      for (const sid of set) io.to(sid).emit('message', message);
    };
    deliver(target.id, msg);
    for (const sid of online.get(me.id) || []) {
      if (sid !== socket.id) io.to(sid).emit('message', msg);
    }
    if (ack) ack({ ok: true, msg });
  });

  socket.on('mark-read', ({ toId }) => {
    let updated = false;
    state.messages.forEach(m => {
      if (m.fromId === Number(toId) && m.toId === me.id && !m.read) {
        m.read = true;
        updated = true;
      }
    });
    if (updated) {
      persist();
      const targetSockets = online.get(Number(toId));
      if (targetSockets) {
        for (const sid of targetSockets) io.to(sid).emit('messages-read');
      }
    }
  });

  /* ================= ЗВОНКИ ================= */
  socket.on('call-user', ({ toId, offer, type }) => {
    const targetSockets = online.get(Number(toId));
    if (targetSockets) {
      for (const sid of targetSockets) io.to(sid).emit('incoming-call', { fromId: me.id, fromName: me.username, offer, type });
    }
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
  /* ========================================== */

  socket.on('disconnect', () => {
    const set = online.get(me.id);
    if (set) { set.delete(socket.id); if (!set.size) online.delete(me.id); }
    io.emit('online', [...online.keys()]);
  });
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') console.error(`\n❌ Порт ${PORT} занят.\n`);
  else console.error('❌ Ошибка сервера:', e);
  process.exit(1);
});

server.listen(PORT, () => {
  console.log(`\n✅ Готово. Открой в браузере: http://localhost:${PORT}`);
  console.log(`   База: ${DATA_FILE}\n`);
});
