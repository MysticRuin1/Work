require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const http = require('http');
const path = require('path');

const app = express();
app.set('trust proxy', 1); // for Render/Proxies
const server = http.createServer(app);
const io = require('socket.io')(server, {
  cors: { origin: true, methods: ['GET','POST'], credentials: true }
});

function CHECK_ENV() {
  const errs = [];
  if (!process.env.JWT_SECRET) errs.push('JWT_SECRET not set');
  if (!process.env.DATABASE_URL) errs.push('DATABASE_URL not set');
  if (errs.length) {
    console.warn('[Config] Missing variables:', errs.join(', '));
  }
}
CHECK_ENV();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com') ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "wss:", "ws:"],
    },
  },
}));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Util helpers
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
function authRequired(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.status(401).json({ error: 'auth_required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

async function query(q, params) {
  const client = await pool.connect();
  try {
    const res = await client.query(q, params);
    return res;
  } finally {
    client.release();
  }
}

// --- Migrations helper (runs at boot if needed) ---
async function ensureMigrations() {
  await query(`
    CREATE TABLE IF NOT EXISTS schema_migrations(
      id serial PRIMARY KEY,
      name text UNIQUE,
      run_at timestamptz DEFAULT now()
    );
  `);
  const { rows } = await query(`SELECT name FROM schema_migrations`);
  const ran = new Set(rows.map(r => r.name));

  const steps = [
    {
      name: '001_init',
      sql: `
        CREATE TABLE IF NOT EXISTS users(
          id bigserial PRIMARY KEY,
          handle text NOT NULL,
          number integer NOT NULL,
          handle_number text UNIQUE NOT NULL,
          email text UNIQUE,
          password_hash text NOT NULL,
          creed text,
          role text DEFAULT 'member', -- member|mod|security|admin
          field_cred integer DEFAULT 0,
          status text DEFAULT 'active', -- active|memorialized|banned
          created_at timestamptz DEFAULT now()
        );
        CREATE UNIQUE INDEX IF NOT EXISTS users_handle_number_idx ON users(handle_number);
        CREATE TABLE IF NOT EXISTS counters(
          key text PRIMARY KEY,
          value integer NOT NULL
        );
        INSERT INTO counters(key,value) VALUES('user_number',0) ON CONFLICT(key) DO NOTHING;

        CREATE TABLE IF NOT EXISTS boards(
          id serial PRIMARY KEY,
          key text UNIQUE NOT NULL,
          title text NOT NULL,
          description text
        );

        CREATE TABLE IF NOT EXISTS threads(
          id bigserial PRIMARY KEY,
          board_id integer REFERENCES boards(id) ON DELETE CASCADE,
          author_id bigint REFERENCES users(id) ON DELETE SET NULL,
          title text NOT NULL,
          body_md text NOT NULL,
          signal text, -- sighting|intel|request-aid|after-action|caution
          tags text[] DEFAULT '{}',
          sticky boolean DEFAULT false,
          locked boolean DEFAULT false,
          created_at timestamptz DEFAULT now(),
          updated_at timestamptz DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS posts(
          id bigserial PRIMARY KEY,
          thread_id bigint REFERENCES threads(id) ON DELETE CASCADE,
          author_id bigint REFERENCES users(id) ON DELETE SET NULL,
          body_md text NOT NULL,
          created_at timestamptz DEFAULT now(),
          edited_at timestamptz
        );

        CREATE TABLE IF NOT EXISTS chat_rooms(
          id serial PRIMARY KEY,
          key text UNIQUE NOT NULL, -- global|firelight|judgment-day|...
          title text NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages(
          id bigserial PRIMARY KEY,
          room_id integer REFERENCES chat_rooms(id) ON DELETE CASCADE,
          author_id bigint REFERENCES users(id) ON DELETE SET NULL,
          body text NOT NULL,
          created_at timestamptz DEFAULT now()
        );
      `
    },
    {
      name: '002_seed_boards_rooms',
      sql: `
        INSERT INTO boards(key,title,description) VALUES
          ('main','Main List','Global intelligence and coordination'),
          ('firelight','Firelight','Avengers'),
          ('judgment-day','Judgment Day','Judges'),
          ('triage','Triage','Redeemers'),
          ('unity','Unity','Visionaries'),
          ('vigil','Vigil','Defenders'),
          ('vitalis','Vitalis','Innocents')
        ON CONFLICT(key) DO NOTHING;

        INSERT INTO chat_rooms(key,title) VALUES
          ('global','Global'),
          ('firelight','Firelight'),
          ('judgment-day','Judgment Day'),
          ('triage','Triage'),
          ('unity','Unity'),
          ('vigil','Vigil'),
          ('vitalis','Vitalis')
        ON CONFLICT(key) DO NOTHING;
      `
    }
  ];

  for (const step of steps) {
    if (!ran.has(step.name)) {
      await query(step.sql);
      await query(`INSERT INTO schema_migrations(name) VALUES($1)`, [step.name]);
      console.log('Ran migration', step.name);
    }
  }
}

// Generate next user number (never recycled)
async function nextUserNumber() {
  const res = await query(`UPDATE counters SET value = value + 1 WHERE key='user_number' RETURNING value`);
  return res.rows[0].value;
}

// --- Auth routes ---
app.post('/api/register', async (req, res) => {
  try {
    const { handle, email, password, creed } = req.body;
    if (!handle || !password) return res.status(400).json({ error: 'missing_fields' });
    const number = await nextUserNumber();
    const handle_number = `${handle}${number}`;
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await query(
      `INSERT INTO users(handle,number,handle_number,email,password_hash,creed) 
       VALUES($1,$2,$3,$4,$5,$6) RETURNING id,handle,number,handle_number,creed,role,status,field_cred`,
       [handle, number, handle_number, email || null, hash, creed || null]
    );
    const user = rows[0];
    const token = signToken({ id: user.id, handle_number: user.handle_number, role: user.role });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.json({ user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'register_failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { handle_number, password } = req.body;
    const { rows } = await query(`SELECT * FROM users WHERE handle_number=$1`, [handle_number]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'invalid_credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
    const token = signToken({ id: user.id, handle_number: user.handle_number, role: user.role });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.json({ user: { id: user.id, handle_number: user.handle_number, creed: user.creed, role: user.role, status: user.status, field_cred: user.field_cred } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'login_failed' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', authRequired, async (req, res) => {
  const { rows } = await query(`SELECT id,handle_number,creed,role,status,field_cred FROM users WHERE id=$1`, [req.user.id]);
  res.json({ user: rows[0] });
});

// --- Boards & Threads ---
app.get('/api/boards', authRequired, async (req, res) => {
  const { rows } = await query(`SELECT * FROM boards ORDER BY id ASC`);
  res.json(rows);
});

app.get('/api/boards/:key/threads', authRequired, async (req, res) => {
  const { key } = req.params;
  const { rows: b } = await query(`SELECT id FROM boards WHERE key=$1`, [key]);
  if (!b[0]) return res.status(404).json({ error: 'board_not_found' });
  const { rows } = await query(
    `SELECT t.*, u.handle_number as author FROM threads t
     LEFT JOIN users u ON u.id=t.author_id
     WHERE t.board_id=$1 ORDER BY sticky DESC, updated_at DESC`, [b[0].id]);
  res.json(rows);
});

app.post('/api/boards/:key/threads', authRequired, async (req, res) => {
  const { key } = req.params;
  const { title, body_md, signal, tags } = req.body;
  const { rows: b } = await query(`SELECT id FROM boards WHERE key=$1`, [key]);
  if (!b[0]) return res.status(404).json({ error: 'board_not_found' });
  const { rows } = await query(
    `INSERT INTO threads(board_id, author_id, title, body_md, signal, tags)
     VALUES($1,$2,$3,$4,$5,$6)
     RETURNING *`, [b[0].id, req.user.id, title, body_md, signal || null, tags || []]);
  res.json(rows[0]);
});

app.get('/api/threads/:id', authRequired, async (req, res) => {
  const { id } = req.params;
  const { rows } = await query(
    `SELECT t.*, u.handle_number as author FROM threads t
     LEFT JOIN users u ON u.id=t.author_id
     WHERE t.id=$1`, [id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  const { rows: posts } = await query(
    `SELECT p.*, u.handle_number as author FROM posts p
     LEFT JOIN users u ON u.id=p.author_id
     WHERE p.thread_id=$1 ORDER BY p.created_at ASC`, [id]);
  res.json({ thread: rows[0], posts });
});

app.post('/api/threads/:id/posts', authRequired, async (req, res) => {
  const { id } = req.params;
  const { body_md } = req.body;
  const { rows } = await query(
    `INSERT INTO posts(thread_id, author_id, body_md) VALUES($1,$2,$3) RETURNING *`,
    [id, req.user.id, body_md]);
  await query(`UPDATE threads SET updated_at=now() WHERE id=$1`, [id]);
  res.json(rows[0]);
});

// --- Admin lite: sticky/lock (role: mod|admin|security) ---
function requireMod(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'auth_required' });
  if (!['mod','admin','security'].includes(req.user.role)) return res.status(403).json({ error: 'forbidden' });
  next();
}
app.patch('/api/threads/:id', authRequired, requireMod, async (req, res) => {
  const { id } = req.params;
  const { sticky, locked } = req.body;
  const { rows } = await query(
    `UPDATE threads SET sticky=COALESCE($1,sticky), locked=COALESCE($2,locked), updated_at=now() WHERE id=$3 RETURNING *`,
    [sticky, locked, id]);
  res.json(rows[0]);
});

// --- Chat via Socket.IO ---
function parseCookie(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach(p => {
    const idx = p.indexOf('=');
    if (idx > -1) {
      const k = p.slice(0, idx).trim();
      const v = decodeURIComponent(p.slice(idx+1).trim());
      out[k] = v;
    }
  });
  return out;
}

io.use(async (socket, next) => {
  try {
    let token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) {
      const cookies = parseCookie(socket.handshake.headers.cookie || '');
      token = cookies.token;
    }
    if (!token) return next(new Error('auth_required'));
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (e) {
    next(new Error('invalid_token'));
  }
});

io.on('connection', (socket) => {
  socket.join('global');
  socket.on('join', (roomKey) => {
    Object.keys(socket.rooms).forEach(r => {
      if (r !== socket.id) socket.leave(r);
    });
    socket.join(roomKey);
  });
  socket.on('message', async ({ roomKey, body }) => {
    const { rows: roomRows } = await query(`SELECT id FROM chat_rooms WHERE key=$1`, [roomKey]);
    const room = roomRows[0];
    if (!room) return;
    await query(`INSERT INTO messages(room_id, author_id, body) VALUES($1,$2,$3)`, [room.id, socket.user.id, body]);
    io.to(roomKey).emit('message', { author: socket.user.handle_number, body, created_at: new Date().toISOString() });
  });
});

// Health check
app.get('/healthz', (req, res) => res.json({ ok: true }));

// Serve index at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// SPA-style fallback for non-API routes (avoids 'Cannot GET /')
app.get(/^\/(?!api|healthz|socket\.io).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start
ensureMigrations().then(() => {
  server.listen(PORT, () => {
    console.log('Hunter-Net server running on port', PORT);
  });
}).catch(err => {
  console.error('Migration error:', err);
  process.exit(1);
});
