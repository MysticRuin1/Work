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
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = require('socket.io')(server, {
  cors: { origin: "*", methods: ['GET','POST'], credentials: true }
});

// --- ENV check ---
function CHECK_ENV() {
  const errs = [];
  if (!process.env.JWT_SECRET) errs.push('JWT_SECRET not set');
  if (!process.env.DATABASE_URL) errs.push('DATABASE_URL not set');
  if (errs.length) {
    console.warn('[Config] Missing variables:', errs.join(', '));
  }
}
CHECK_ENV();

const PORT = process.env.PORT; // must use Render-provided port
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

// --- Middleware ---
app.use(helmet({
  contentSecurityPolicy: false // disable CSP so socket.io + inline scripts work
}));
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- Utilities ---
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
    return await client.query(q, params);
  } finally {
    client.release();
  }
}

// --- Migration helper ---
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
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          handle_number TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at TIMESTAMPTZ DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS chat_rooms (
          id SERIAL PRIMARY KEY,
          key TEXT UNIQUE NOT NULL,
          created_at TIMESTAMPTZ DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS messages (
          id SERIAL PRIMARY KEY,
          room_id INT REFERENCES chat_rooms(id) ON DELETE CASCADE,
          author_id INT REFERENCES users(id) ON DELETE CASCADE,
          body TEXT NOT NULL,
          created_at TIMESTAMPTZ DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS boards (
          id SERIAL PRIMARY KEY,
          name TEXT UNIQUE NOT NULL,
          description TEXT,
          created_at TIMESTAMPTZ DEFAULT now()
        );

        CREATE TABLE IF NOT EXISTS threads (
          id SERIAL PRIMARY KEY,
          board_id INT REFERENCES boards(id) ON DELETE CASCADE,
          author_id INT REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL,
          body TEXT,
          created_at TIMESTAMPTZ DEFAULT now()
        );
      `
    },
    {
      name: '002_seed_boards_rooms',
      sql: `
        INSERT INTO chat_rooms (key) VALUES ('global')
        ON CONFLICT (key) DO NOTHING;

        INSERT INTO boards (name, description) VALUES
          ('Firelight', 'Discussion about cryptids and monsters'),
          ('Judgment Day', 'Hunter tactics and survival'),
          ('Triage', 'Medical and psychological support'),
          ('Unity', 'Organizing hunters together'),
          ('Vigil', 'Field reports and sightings'),
          ('Vitalis', 'Research and lore')
        ON CONFLICT (name) DO NOTHING;
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

// --- Auth + Boards + Threads routes (unchanged) ---
// keep your API endpoints here

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

io.use((socket, next) => {
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

// --- Health check + SPA fallback ---
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get(/^\/(?!api|healthz|socket\.io).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Start ---
ensureMigrations().then(() => {
  server.listen(PORT, () => {
    console.log('Hunter-Net server running on port', PORT);
  });
}).catch(err => {
  console.error('Migration error:', err);
  process.exit(1);
});


