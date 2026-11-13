require('dotenv').config(); // В Render переменные окружения подтягиваются автоматически

const express = require('express');
const http = require('http');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const mongoose = require('mongoose');

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me';
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ Не задана переменная окружения MONGODB_URI');
  process.exit(1);
}

/* ---------- Схемы MongoDB ---------- */
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  avatar: { type: String, default: null },
  contacts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  publicKey: { type: String, default: null },
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  fromId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  toId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  body: { type: String, required: true },
  iv: { type: String, default: null },
  type: { type: String, default: 'text' },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);

/* ---------- Подключение к MongoDB ---------- */
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Подключено к MongoDB Atlas'))
  .catch(err => { 
    console.error('❌ Ошибка подключения к MongoDB:', err.message); 
    process.exit(1); 
  });

/* ---------- HTTP ---------- */
const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const loginAttempts = new Map();
setInterval(() => loginAttempts.clear(), 15 * 60 * 1000);

app.get('/api/health', async (_, res) => {
  try {
    const users = await User.countDocuments();
    const messages = await Message.countDocuments();
    res.json({ ok: true, users, messages });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Нужны логин и пароль' });
    const u = username.trim();
    if (u.length < 3) return res.status(400).json({ error: 'Логин — минимум 3 символа' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль — минимум 6 символов' });
    
    const exists = await User.findOne({ username: u });
    if (exists) return res.status(409).json({ error: 'Такой логин уже занят' });

    const user = await User.create({ username: u, passwordHash: bcrypt.hashSync(password, 10) });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, username: user.username, avatar: user.avatar, publicKey: user.publicKey } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const ip = req.ip;
    
    if ((loginAttempts.get(ip) || 0) > 10) return res.status(429).json({ error: 'Слишком много попыток. Подождите 15 минут.' });

    const user = await User.findOne({ username: String(username || '').trim() });
    if (!user || !bcrypt.compareSync(String(password || ''), user.passwordHash)) {
      loginAttempts.set(ip, (loginAttempts.get(ip) || 0) + 1);
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    loginAttempts.delete(ip);
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, username: user.username, avatar: user.avatar, publicKey: user.publicKey } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/change-password', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Нет токена' });
    const payload = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    const user = await User.findById(payload.id);
    
    if (!bcrypt.compareSync(req.body.oldPassword, user.passwordHash)) {
      return res.status(400).json({ error: 'Неверный текущий пароль' });
    }
    
    user.passwordHash = bcrypt.hashSync(req.body.newPassword, 10);
    await user.save();
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка авторизации' }); }
});

app.post('/api/public-key', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Нет токена' });
    const payload = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    
    await User.findByIdAndUpdate(payload.id, { publicKey: req.body.publicKey });
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: 'Ошибка' }); }
});

app.post('/api/avatar', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Нет токена' });
    const payload = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    const user = await User.findById(payload.id);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    user.avatar = req.body.avatar;
    await user.save();
    res.json({ ok: true, avatar: user.avatar });
  } catch (e) { res.status(401).json({ error: 'Неверный токен' }); }
});

/* ---------- Socket.io ---------- */
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 2e7 });

io.use(async (socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token || '', JWT_SECRET);
    const user = await User.findById(payload.id);
    if (!user) return next(new Error('unauthorized'));
    socket.user = { id: user._id.toString(), username: user.username };
    next();
  } catch { next(new Error('unauthorized')); }
});

const online = new Map();

const getContactsList = async (userId) => {
  const user = await User.findById(userId).populate('contacts', 'username avatar publicKey');
  if (!user) return [];
  return user.contacts.map(c => ({ id: c._id.toString(), username: c.username, avatar: c.avatar, publicKey: c.publicKey }));
};

io.on('connection', (socket) => {
  const me = socket.user;
  if (!online.has(me.id)) online.set(me.id, new Set());
  online.get(me.id).add(socket.id);
  io.emit('online', [...online.keys()]);

  const sendUsers = async (cb) => {
    const list = await getContactsList(me.id);
    cb ? cb(list) : socket.emit('users', list);
  };
  sendUsers();

  socket.on('users', async (cb) => { cb(await getContactsList(me.id)); });

  socket.on('add-contact', async ({ username }, cb) => {
    try {
      const target = await User.findOne({ username: String(username || '').trim() });
      const meUser = await User.findById(me.id);
      if (!target) return cb({ error: 'Пользователь не найден' });
      if (target._id.equals(meUser._id)) return cb({ error: 'Нельзя добавить самого себя' });
      if (meUser.contacts.some(c => c.equals(target._id))) return cb({ error: 'Уже в контактах' });

      meUser.contacts.push(target._id);
      if (!target.contacts.includes(meUser._id)) target.contacts.push(meUser._id);
      await meUser.save(); await target.save();

      cb({ ok: true });
      const meList = await getContactsList(me.id);
      for (const sid of online.get(me.id) || []) io.to(sid).emit('users', meList);
      const targetList = await getContactsList(target._id.toString());
      for (const sid of online.get(target._id.toString()) || []) io.to(sid).emit('users', targetList);
    } catch (e) { cb({ error: e.message }); }
  });

  socket.on('history', async ({ withId }, cb) => {
    try {
      const rows = await Message.find({
        $or: [{ fromId: me.id, toId: withId }, { fromId: withId, toId: me.id }]
      }).sort({ createdAt: 1 }).limit(200);

      await Message.updateMany({ fromId: withId, toId: me.id, read: false }, { $set: { read: true } });
      const targetSockets = online.get(withId);
      if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('messages-read');

      cb(rows.map(r => ({
        id: r._id.toString(),
        fromId: r.fromId.toString(),
        toId: r.toId.toString(),
        body: r.body,
        iv: r.iv,
        type: r.type,
        read: r.read,
        createdAt: r.createdAt.getTime()
      })));
    } catch (e) { cb([]); }
  });

  socket.on('typing', ({ toId, isTyping }) => {
    const targetSockets = online.get(toId);
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('typing', { fromId: me.id, isTyping });
  });

  socket.on('message', async ({ toId, body, type, iv }, ack) => {
    try {
      const target = await User.findById(toId);
      if (!target || !body.trim()) return ack && ack({ error: 'Некорректное сообщение' });

      const msg = await Message.create({ fromId: me.id, toId: target._id, body, type: type || 'text', iv, read: false });
      const msgData = {
        id: msg._id.toString(), fromId: me.id, toId: target._id.toString(),
        body: msg.body, type: msg.type, iv: msg.iv, read: msg.read, createdAt: msg.createdAt.getTime()
      };

      const deliver = (uid, message) => {
        const set = online.get(uid);
        if (set) for (const sid of set) io.to(sid).emit('message', message);
      };
      deliver(target._id.toString(), msgData);
      for (const sid of online.get(me.id) || []) { if (sid !== socket.id) io.to(sid).emit('message', msgData); }
      
      if (ack) ack({ ok: true, msg: msgData });
    } catch (e) { if (ack) ack({ error: e.message }); }
  });

  socket.on('mark-read', async ({ toId }) => {
    try {
      await Message.updateMany({ fromId: toId, toId: me.id, read: false }, { $set: { read: true } });
      const targetSockets = online.get(toId);
      if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('messages-read');
    } catch (e) { /* ignore */ }
  });

  socket.on('call-user', ({ toId, offer, type }) => {
    const targetSockets = online.get(toId);
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('incoming-call', { fromId: me.id, fromName: me.username, offer, type });
  });
  socket.on('answer-call', ({ toId, answer }) => {
    const targetSockets = online.get(toId);
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('call-answered', { answer });
  });
  socket.on('ice-candidate', ({ toId, candidate }) => {
    const targetSockets = online.get(toId);
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('ice-candidate', { candidate });
  });
  socket.on('end-call', ({ toId }) => {
    const targetSockets = online.get(toId);
    if (targetSockets) for (const sid of targetSockets) io.to(sid).emit('call-ended');
  });

  socket.on('disconnect', () => {
    const set = online.get(me.id);
    if (set) { set.delete(socket.id); if (!set.size) online.delete(me.id); }
    io.emit('online', [...online.keys()]);
  });
});

server.listen(PORT, () => {
  console.log(`\n✅ Сервер с E2EE запущен на порту ${PORT}\n`);
});
