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
  if (!process.env.PORT) errs.push('PORT not set');
  if (errs.length) {
    console.warn('[Config] Missing variables:', errs.join(', '));
  }
}
CHECK_ENV();

const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

// --- Middleware ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- Utils ---
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
function authRequired(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.status(401).json({ error: 'auth_required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'invalid_token' });
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

// --- Migrations & Seeding ---
async function ensureMigrations() {
  await query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE,
      run_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  const { rows } = await query(`SELECT name FROM schema_migrations;`);
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
      name: '002_seed_initial',
      sql: `
        INSERT INTO chat_rooms (key) VALUES ('global') ON CONFLICT (key) DO NOTHING;
        INSERT INTO boards (name, description) VALUES
          ('Firelight', 'Cryptid & monster discussions'),
          ('Judgment Day', 'Tactics & survival'),
          ('Triage', 'Medical & support'),
          ('Unity', 'Coordination & organization'),
          ('Vigil', 'Field reports & logs'),
          ('Vitalis', 'Research & lore')
        ON CONFLICT (name) DO NOTHING;
      `
    }
  ];

  for (const step of steps) {
    if (!ran.has(step.name)) {
      await query(step.sql);
      await query(`INSERT INTO schema_migrations (name) VALUES ($1);`, [step.name]);
      console.log('Migration ran:', step.name);
    }
  }
}

// --- Routes & Socket.IO (unchanged from your setup) ---
// [Include your API endpoints and chat logic here exactly as before]

app.get('/healthz', (req, res) => res.json({ ok: true }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get(/^\/(?!api|healthz|socket\\.io).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Start server ---
ensureMigrations().then(() => {
  server.listen(PORT, () => {
    console.log('Server is live on port', PORT);
  });
}).catch(err => {
  console.error('Migration error:', err);
  process.exit(1);
});
