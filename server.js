const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-this-secret-before-deployment';
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 15);
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'bytechat.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, avatar_color TEXT NOT NULL DEFAULT '#16a085',
 bio TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rooms (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('dm','group')),
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
 room_id TEXT NOT NULL, user_id TEXT NOT NULL, joined_at INTEGER NOT NULL,
 PRIMARY KEY(room_id,user_id), FOREIGN KEY(room_id) REFERENCES rooms(id), FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY, room_id TEXT NOT NULL, sender_id TEXT NOT NULL,
 payload TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'text', created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_room_time ON messages(room_id,created_at);
CREATE TABLE IF NOT EXISTS statuses (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, payload TEXT NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
`);

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: false } });
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false })); // Inline client script in this starter; tighten CSP for production.
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR, { fallthrough: false, index: false }));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false });
const now = () => Date.now();
const id = () => crypto.randomUUID();
const publicUser = u => ({ id:u.id, username:u.username, displayName:u.display_name, avatarColor:u.avatar_color, bio:u.bio });
function tokenFor(user) { return jwt.sign({ sub:user.id }, JWT_SECRET, { expiresIn:'7d', issuer:'bytechat' }); }
function auth(req,res,next) {
  const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  try {
    const decoded = jwt.verify(raw, JWT_SECRET, { issuer:'bytechat' });
    req.user = db.prepare('SELECT * FROM users WHERE id=?').get(decoded.sub);
    if (!req.user) return res.status(401).json({ error:'Account not found' });
    next();
  } catch { return res.status(401).json({ error:'Please sign in again' }); }
}
function roomForUser(roomId, userId) {
  return db.prepare('SELECT r.* FROM rooms r JOIN members m ON m.room_id=r.id WHERE r.id=? AND m.user_id=?').get(roomId,userId);
}
function roomSummary(room, userId) {
  const members = db.prepare('SELECT u.id,u.username,u.display_name,u.avatar_color,u.bio FROM members m JOIN users u ON u.id=m.user_id WHERE m.room_id=?').all(room.id).map(publicUser);
  let name = room.name;
  if (room.kind === 'dm') name = (members.find(u => u.id !== userId) || members[0] || {}).displayName || 'Direct message';
  const last = db.prepare('SELECT payload,kind,created_at FROM messages WHERE room_id=? ORDER BY created_at DESC LIMIT 1').get(room.id);
  return { id:room.id, name, kind:room.kind, members, lastMessage:last ? { preview:last.kind === 'text' ? safePreview(last.payload) : '['+last.kind+']', createdAt:last.created_at } : null };
}
function safePreview(payload) { try { const p=JSON.parse(payload); return p.ciphertext ? '🔒 Encrypted message' : String(p.text || '').slice(0,80); } catch { return 'Message'; } }

app.get('/api/health', (_req,res) => res.json({ ok:true, service:'BYTECHAT', time:now() }));
app.post('/api/auth/register', authLimiter, async (req,res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const displayName = String(req.body.displayName || '').trim().slice(0,40);
  const password = String(req.body.password || '');
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({error:'Username must be 3–24 letters, numbers, or underscores'});
  if (displayName.length < 1) return res.status(400).json({error:'Display name is required'});
  if (password.length < 10 || password.length > 200) return res.status(400).json({error:'Password must be 10–200 characters'});
  if (db.prepare('SELECT id FROM users WHERE username=?').get(username)) return res.status(409).json({error:'Username is already taken'});
  const user = { id:id(), username, display_name:displayName, password_hash:await bcrypt.hash(password,12), avatar_color:['#16a085','#6c5ce7','#e17055','#0984e3'][Math.floor(Math.random()*4)], bio:'', created_at:now() };
  db.prepare('INSERT INTO users (id,username,display_name,password_hash,avatar_color,bio,created_at) VALUES (@id,@username,@display_name,@password_hash,@avatar_color,@bio,@created_at)').run(user);
  res.status(201).json({ token:tokenFor(user), user:publicUser(user) });
});
app.post('/api/auth/login', authLimiter, async (req,res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || !(await bcrypt.compare(String(req.body.password || ''),user.password_hash))) return res.status(401).json({error:'Invalid username or password'});
  res.json({ token:tokenFor(user), user:publicUser(user) });
});
app.get('/api/me', auth, (req,res) => res.json({ user:publicUser(req.user) }));
app.patch('/api/me', auth, (req,res) => {
  const displayName = String(req.body.displayName || req.user.display_name).trim().slice(0,40);
  const bio = String(req.body.bio ?? req.user.bio).trim().slice(0,160);
  db.prepare('UPDATE users SET display_name=?,bio=? WHERE id=?').run(displayName,bio,req.user.id);
  res.json({user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id))});
});
app.get('/api/users', auth, (req,res) => {
  const q = String(req.query.q || '').trim().toLowerCase().slice(0,40);
  const users = db.prepare(`SELECT id,username,display_name,avatar_color,bio FROM users WHERE id<>? AND (username LIKE ? OR lower(display_name) LIKE ?) ORDER BY display_name LIMIT 30`)
    .all(req.user.id, `%${q}%`, `%${q}%`).map(publicUser);
  res.json({users});
});
app.get('/api/rooms', auth, (req,res) => {
  const rooms = db.prepare('SELECT r.* FROM rooms r JOIN members m ON m.room_id=r.id WHERE m.user_id=? ORDER BY r.created_at DESC').all(req.user.id);
  res.json({rooms:rooms.map(r=>roomSummary(r,req.user.id))});
});
app.post('/api/rooms/dm', auth, (req,res) => {
  const otherId = String(req.body.userId || '');
  const other = db.prepare('SELECT id FROM users WHERE id=?').get(otherId);
  if (!other || otherId === req.user.id) return res.status(400).json({error:'Choose another valid user'});
  const existing = db.prepare(`SELECT r.id FROM rooms r JOIN members a ON a.room_id=r.id JOIN members b ON b.room_id=r.id
    WHERE r.kind='dm' AND a.user_id=? AND b.user_id=? AND (SELECT COUNT(*) FROM members x WHERE x.room_id=r.id)=2 LIMIT 1`).get(req.user.id,otherId);
  if (existing) return res.json({room:roomSummary(db.prepare('SELECT * FROM rooms WHERE id=?').get(existing.id),req.user.id)});
  const room = {id:id(),name:'Direct message',kind:'dm',created_by:req.user.id,created_at:now()};
  const insertRoom=db.prepare('INSERT INTO rooms (id,name,kind,created_by,created_at) VALUES (@id,@name,@kind,@created_by,@created_at)');
  const insertMember=db.prepare('INSERT INTO members (room_id,user_id,joined_at) VALUES (?,?,?)');
  db.transaction(()=>{insertRoom.run(room);insertMember.run(room.id,req.user.id,now());insertMember.run(room.id,otherId,now());})();
  io.to(`user:${otherId}`).emit('rooms:changed');
  res.status(201).json({room:roomSummary(room,req.user.id)});
});
app.post('/api/rooms/group', auth, (req,res) => {
  const name = String(req.body.name || '').trim().slice(0,60);
  const userIds = [...new Set([req.user.id,...(Array.isArray(req.body.userIds)?req.body.userIds:[]).map(String)])].slice(0,51);
  if (name.length < 2) return res.status(400).json({error:'Group name must be at least 2 characters'});
  if (userIds.length < 2) return res.status(400).json({error:'Select at least one other member'});
  const valid = db.prepare(`SELECT id FROM users WHERE id IN (${userIds.map(()=>'?').join(',')})`).all(...userIds);
  if (valid.length !== userIds.length) return res.status(400).json({error:'One or more members are invalid'});
  const room={id:id(),name,kind:'group',created_by:req.user.id,created_at:now()};
  db.transaction(()=>{db.prepare('INSERT INTO rooms (id,name,kind,created_by,created_at) VALUES (@id,@name,@kind,@created_by,@created_at)').run(room);
    const st=db.prepare('INSERT INTO members (room_id,user_id,joined_at) VALUES (?,?,?)'); userIds.forEach(uid=>st.run(room.id,uid,now()));})();
  userIds.filter(uid=>uid!==req.user.id).forEach(uid=>io.to(`user:${uid}`).emit('rooms:changed'));
  res.status(201).json({room:roomSummary(room,req.user.id)});
});
app.get('/api/rooms/:id/messages', auth, (req,res) => {
  if (!roomForUser(req.params.id,req.user.id)) return res.status(403).json({error:'Not a member of this chat'});
  const rows=db.prepare(`SELECT m.id,m.room_id,m.sender_id,m.payload,m.kind,m.created_at,u.username,u.display_name
    FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.room_id=? ORDER BY m.created_at DESC LIMIT 100`).all(req.params.id).reverse();
  res.json({messages:rows.map(m=>({id:m.id,roomId:m.room_id,senderId:m.sender_id,username:m.username,displayName:m.display_name,payload:JSON.parse(m.payload),kind:m.kind,createdAt:m.created_at}))});
});
const storage=multer.diskStorage({destination:UPLOAD_DIR,filename:(_req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).slice(0,12))});
const upload=multer({storage,limits:{fileSize:MAX_UPLOAD_MB*1024*1024,files:1}});
app.post('/api/upload', auth, upload.single('file'), (req,res) => {
  if (!req.file) return res.status(400).json({error:'Choose a file'});
  res.status(201).json({file:{url:'/uploads/'+req.file.filename, name:path.basename(req.file.originalname).slice(0,180), size:req.file.size, mime:req.file.mimetype}});
});
app.post('/api/status', auth, (req,res) => {
  const text=String(req.body.text || '').trim().slice(0,500);
  if (!text) return res.status(400).json({error:'Status cannot be empty'});
  const s={id:id(),user_id:req.user.id,payload:JSON.stringify({text}),created_at:now(),expires_at:now()+24*60*60*1000};
  db.prepare('INSERT INTO statuses (id,user_id,payload,created_at,expires_at) VALUES (@id,@user_id,@payload,@created_at,@expires_at)').run(s);
  io.emit('status:changed');
  res.status(201).json({status:{id:s.id,text,createdAt:s.created_at,expiresAt:s.expires_at}});
});
app.get('/api/status', auth, (_req,res) => {
  db.prepare('DELETE FROM statuses WHERE expires_at < ?').run(now());
  const statuses=db.prepare(`SELECT s.id,s.user_id,s.payload,s.created_at,s.expires_at,u.username,u.display_name,u.avatar_color
    FROM statuses s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC LIMIT 100`).all()
    .map(s=>({id:s.id,userId:s.user_id,username:s.username,displayName:s.display_name,avatarColor:s.avatar_color,...JSON.parse(s.payload),createdAt:s.created_at,expiresAt:s.expires_at}));
  res.json({statuses});
});

const sockets = new Map();
io.use((socket,next)=>{
  try { const token=socket.handshake.auth?.token; const d=jwt.verify(token,JWT_SECRET,{issuer:'bytechat'}); const u=db.prepare('SELECT * FROM users WHERE id=?').get(d.sub); if(!u) throw Error(); socket.user=u; next(); }
  catch { next(new Error('unauthorized')); }
});
io.on('connection', socket => {
  const uid=socket.user.id; sockets.set(socket.id,uid); socket.join(`user:${uid}`);
  db.prepare('SELECT room_id FROM members WHERE user_id=?').all(uid).forEach(r=>socket.join(`room:${r.room_id}`));
  socket.on('room:join', roomId => { if (typeof roomId==='string' && roomForUser(roomId,uid)) socket.join(`room:${roomId}`); });
  socket.on('message:send', data => {
    if (!data || typeof data.roomId!=='string' || !roomForUser(data.roomId,uid)) return socket.emit('app:error',{message:'You are not a member of that chat'});
    const kind=['text','image','file'].includes(data.kind)?data.kind:'text';
    let payload;
    try { payload=JSON.stringify(data.payload); if (!payload || payload.length>20000) throw Error(); } catch { return socket.emit('app:error',{message:'Invalid or oversized message'}); }
    let parsed; try { parsed=JSON.parse(payload); } catch { return; }
    if (kind==='text' && typeof parsed.text!=='string' && typeof parsed.ciphertext!=='string') return;
    const m={id:id(),room_id:data.roomId,sender_id:uid,payload,kind,created_at:now()};
    db.prepare('INSERT INTO messages (id,room_id,sender_id,payload,kind,created_at) VALUES (@id,@room_id,@sender_id,@payload,@kind,@created_at)').run(m);
    const out={id:m.id,roomId:m.room_id,senderId:uid,username:socket.user.username,displayName:socket.user.display_name,payload:parsed,kind,createdAt:m.created_at};
    io.to(`room:${m.room_id}`).emit('message:new',out);
    const members=db.prepare('SELECT user_id FROM members WHERE room_id=?').all(m.room_id);
    members.forEach(mem=>{ if(mem.user_id!==uid) io.to(`user:${mem.user_id}`).emit('rooms:changed'); });
  });
  // WebRTC signaling only. Media is peer-to-peer; this server does not record calls.
  socket.on('call:signal', data => {
    if (!data || typeof data.targetId!=='string' || !data.signal || !data.roomId || !roomForUser(data.roomId,uid) || !roomForUser(data.roomId,data.targetId)) return;
    io.to(`user:${data.targetId}`).emit('call:signal',{fromId:uid,fromName:socket.user.display_name,roomId:data.roomId,signal:data.signal});
  });
  socket.on('disconnect',()=>sockets.delete(socket.id));
});

server.listen(PORT,()=>console.log(`BYTECHAT running at http://localhost:${PORT}`));
