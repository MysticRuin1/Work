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

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

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
  } catch {
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
  try {
    console.log('Starting migrations...');
    // Create migrations table
    await query(`
      CREATE TABLE IF NOT EXISTS schema_migrations(
        id serial PRIMARY KEY,
        name text UNIQUE,
        run_at timestamptz DEFAULT now()
      );
    `);

    const { rows } = await query(`SELECT name FROM schema_migrations`);
    const ran = new Set(rows.map(r => r.name));

    console.log('Previously run migrations:', Array.from(ran));
    
    const steps = [
      {
        name: '001_init',
        sql: `
          -- Create sequence first
          CREATE SEQUENCE IF NOT EXISTS user_number_seq START 1;
          
          -- Create users table to match actual database schema
          CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            handle TEXT,
            number INT NOT NULL,
            handle_number TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            creed TEXT,
            member TEXT DEFAULT 'member',
            field_cred INT DEFAULT 0,
            active TEXT DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT now(),
            is_admin BOOLEAN DEFAULT false
          );

          CREATE TABLE IF NOT EXISTS chat_rooms (
            id SERIAL PRIMARY KEY,
            key TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
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
            name TEXT,
            description TEXT,
            key TEXT UNIQUE NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
          );

          CREATE TABLE IF NOT EXISTS threads (
            id SERIAL PRIMARY KEY,
            board_id INT REFERENCES boards(id) ON DELETE CASCADE,
            author_id INT REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            body_md TEXT,
            signal_type TEXT,
            tags TEXT,
            sticky BOOLEAN DEFAULT false,
            locked BOOLEAN DEFAULT false,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
          );

          CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            thread_id INT REFERENCES threads(id) ON DELETE CASCADE,
            author_id INT REFERENCES users(id) ON DELETE CASCADE,
            body_md TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
          );
        `
      },
      {
        name: '002_seed_boards_rooms',
        sql: `
          INSERT INTO chat_rooms (key, title) VALUES
            ('global', 'Global Chat'),
            ('firelight', 'Firelight'),
            ('judgment-day', 'Judgment Day'),
            ('triage', 'Triage'),
            ('unity', 'Unity'),
            ('vigil', 'Vigil'),
            ('vitalis', 'Vitalis')
          ON CONFLICT (key) DO NOTHING;

          INSERT INTO boards (name, description, key) VALUES
            ('Firelight', 'Discussion about cryptids and monsters', 'firelight'),
            ('Judgment Day', 'Hunter tactics and survival', 'judgment-day'),
            ('Triage', 'Medical and psychological support', 'triage'),
            ('Unity', 'Organizing hunters together', 'unity'),
            ('Vigil', 'Field reports and sightings', 'vigil'),
            ('Vitalis', 'Research and lore', 'vitalis')
          ON CONFLICT (key) DO NOTHING;
        `
      },
      {
        name: '003_fix_existing_schema',
        sql: `
          -- Add missing columns if they don't exist
          ALTER TABLE users ADD COLUMN IF NOT EXISTS handle TEXT;
          ALTER TABLE users ADD COLUMN IF NOT EXISTS number INT;
          ALTER TABLE users ADD COLUMN IF NOT EXISTS member TEXT DEFAULT 'member';
          ALTER TABLE users ADD COLUMN IF NOT EXISTS active TEXT DEFAULT 'active';
          ALTER TABLE boards ADD COLUMN IF NOT EXISTS name TEXT;
          ALTER TABLE threads ADD COLUMN IF NOT EXISTS signal_type TEXT;
          
          -- Update existing users to have proper values if they're missing
          UPDATE users SET
            handle = CASE
              WHEN handle IS NULL THEN split_part(handle_number, regexp_replace(handle_number, '[^0-9].*$', '', 'g'), 1)
              ELSE handle
            END,
            number = CASE
              WHEN number IS NULL THEN COALESCE(CAST(regexp_replace(handle_number, '^[^0-9]*', '', 'g') AS INT), 1)
              ELSE number
            END,
            member = COALESCE(member, 'member'),
            active = COALESCE(active, 'active')
          WHERE handle IS NULL OR number IS NULL OR member IS NULL OR active IS NULL;

          -- Update boards to have names if they're missing
          UPDATE boards SET name = CASE 
            WHEN name IS NULL THEN 
              CASE key
                WHEN 'firelight' THEN 'Firelight'
                WHEN 'judgment-day' THEN 'Judgment Day'
                WHEN 'triage' THEN 'Triage'
                WHEN 'unity' THEN 'Unity'
                WHEN 'vigil' THEN 'Vigil'
                WHEN 'vitalis' THEN 'Vitalis'
                ELSE initcap(replace(key, '-', ' '))
              END
            ELSE name
          END
          WHERE name IS NULL;

          -- Ensure sequence exists
          CREATE SEQUENCE IF NOT EXISTS user_number_seq START 1;
          
          -- Update sequence to be higher than existing numbers
          SELECT setval('user_number_seq', COALESCE((SELECT MAX(number) FROM users), 0) + 1, false);
        `
      },
      {
        name: '004_complete_setup',
        sql: `
          -- Ensure all constraints are in place
          SELECT 1 as setup_complete;
        `
      }
    ];

    for (const step of steps) {
      if (!ran.has(step.name)) {
        console.log(`Running migration: ${step.name}`);
        await query(step.sql);
        await query(`INSERT INTO schema_migrations(name) VALUES($1)`, [step.name]);
        console.log(`Completed migration: ${step.name}`);
      }
    }

    console.log('Migrations completed successfully');
  } catch (error) {
    console.error('Migration error:', error);
    throw error;
  }
}

// --- API Routes ---

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { handle, email, password, creed } = req.body;
    
    if (!handle || !password) {
      return res.status(400).json({ error: 'Handle and password required' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Generate unique handle number
    const { rows: [{ nextval }] } = await query('SELECT nextval(\'user_number_seq\')');
    const handle_number = `${handle}${nextval}`;

    // Hash password
    const password_hash = await bcrypt.hash(password, 12);

    // Create user with correct schema
    const { rows: [user] } = await query(`
      INSERT INTO users (handle, number, handle_number, password_hash, email, creed, member, active) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
      RETURNING id, handle_number, field_cred, is_admin
    `, [handle, nextval, handle_number, password_hash, email || null, creed || null, 'member', 'active']);

    // Sign JWT
    const token = signToken({
      id: user.id,
      handle_number: user.handle_number,
      is_admin: user.is_admin
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      user: {
        handle_number: user.handle_number,
        field_cred: user.field_cred,
        is_admin: user.is_admin
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === '23505') { // Unique violation
      res.status(400).json({ error: 'Handle already taken' });
    } else {
      res.status(500).json({ error: 'Registration failed' });
    }
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { handle_number, password } = req.body;
    
    if (!handle_number || !password) {
      return res.status(400).json({ error: 'Handle and password required' });
    }

    // Find user
    const { rows: [user] } = await query(
      'SELECT id, handle_number, password_hash, field_cred, is_admin FROM users WHERE handle_number = $1',
      [handle_number]
    );

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Sign JWT
    const token = signToken({
      id: user.id,
      handle_number: user.handle_number,
      is_admin: user.is_admin
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      user: {
        handle_number: user.handle_number,
        field_cred: user.field_cred,
        is_admin: user.is_admin
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/me', authRequired, async (req, res) => {
  try {
    const { rows: [user] } = await query(
      'SELECT handle_number, field_cred, is_admin FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// Get boards - Fixed version with error handling
app.get('/api/boards', async (req, res) => {
  try {
    const { rows: boards } = await query(
      'SELECT id, name, description, key FROM boards ORDER BY name'
    );
    res.json({ boards });
  } catch (error) {
    console.error('Get boards error:', error);
    // If the name column doesn't exist, try a fallback query
    if (error.code === '42703' && error.message.includes('name')) {
      try {
        console.log('Attempting fallback query for boards...');
        const { rows: boards } = await query('SELECT id, key, description FROM boards ORDER BY key');
        const fixedBoards = boards.map(board => ({
          ...board,
          name: board.key || 'Unnamed Board'
        }));
        res.json({ boards: fixedBoards });
      } catch (fallbackError) {
        console.error('Fallback query also failed:', fallbackError);
        res.status(500).json({ error: 'Failed to get boards' });
      }
    } else {
      res.status(500).json({ error: 'Failed to get boards' });
    }
  }
});

// Get threads for a board - Fixed version
app.get('/api/boards/:key/threads', async (req, res) => {
  try {
    const { key } = req.params;
    
    // Try with signal_type column first
    try {
      const { rows: threads } = await query(`
        SELECT t.id, t.title, t.signal_type, t.tags, t.sticky, t.locked,
               t.created_at, t.updated_at, u.handle_number as author,
               (SELECT COUNT(*) FROM posts WHERE thread_id = t.id) as post_count
        FROM threads t
        JOIN boards b ON t.board_id = b.id
        JOIN users u ON t.author_id = u.id
        WHERE b.key = $1
        ORDER BY t.sticky DESC, t.updated_at DESC
      `, [key]);
      
      res.json({ threads });
    } catch (columnError) {
      // Fallback without signal_type column
      if (columnError.code === '42703' && columnError.message.includes('signal_type')) {
        console.log('Fallback: getting threads without signal_type column');
        const { rows: threads } = await query(`
          SELECT t.id, t.title, t.tags, t.sticky, t.locked,
                 t.created_at, t.updated_at, u.handle_number as author,
                 (SELECT COUNT(*) FROM posts WHERE thread_id = t.id) as post_count
          FROM threads t
          JOIN boards b ON t.board_id = b.id
          JOIN users u ON t.author_id = u.id
          WHERE b.key = $1
          ORDER BY t.sticky DESC, t.updated_at DESC
        `, [key]);
        
        // Add signal_type as null for consistency
        const threadsWithSignal = threads.map(thread => ({
          ...thread,
          signal_type: null
        }));
        
        res.json({ threads: threadsWithSignal });
      } else {
        throw columnError;
      }
    }
  } catch (error) {
    console.error('Get threads error:', error);
    res.status(500).json({ error: 'Failed to get threads' });
  }
});

// Create thread - Fixed version
app.post('/api/boards/:key/threads', authRequired, async (req, res) => {
  try {
    const { key } = req.params;
    const { title, body_md, signal, tags } = req.body;
    
    if (!title || !body_md) {
      return res.status(400).json({ error: 'Title and body required' });
    }

    // Get board
    const { rows: [board] } = await query('SELECT id FROM boards WHERE key = $1', [key]);
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    // Try creating thread with signal_type column first
    try {
      const { rows: [thread] } = await query(`
        INSERT INTO threads (board_id, author_id, title, body_md, signal_type, tags)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, title, signal_type, tags, created_at
      `, [board.id, req.user.id, title, body_md, signal || null, tags || null]);
      
      res.json({ thread });
    } catch (columnError) {
      // If signal_type column doesn't exist, create without it
      if (columnError.code === '42703' && columnError.message.includes('signal_type')) {
        console.log('Fallback: creating thread without signal_type column');
        const { rows: [thread] } = await query(`
          INSERT INTO threads (board_id, author_id, title, body_md, tags)
          VALUES ($1, $2, $3, $4, $5)
          RETURNING id, title, tags, created_at
        `, [board.id, req.user.id, title, body_md, tags || null]);
        
        // Add signal_type to response for consistency
        thread.signal_type = signal || null;
        res.json({ thread });
      } else {
        throw columnError;
      }
    }
  } catch (error) {
    console.error('Create thread error:', error);
    res.status(500).json({ error: 'Failed to create thread' });
  }
});

// Get thread with posts - Fixed version
app.get('/api/threads/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get thread - try with signal_type first, fallback without
    let thread;
    try {
      const { rows: [threadData] } = await query(`
        SELECT t.id, t.title, t.body_md, t.signal_type, t.tags, t.sticky, t.locked,
               t.created_at, u.handle_number as author, b.name as board_name, b.key as board_key
        FROM threads t
        JOIN users u ON t.author_id = u.id
        JOIN boards b ON t.board_id = b.id
        WHERE t.id = $1
      `, [id]);
      thread = threadData;
    } catch (columnError) {
      if (columnError.code === '42703') {
        console.log('Fallback: getting thread without signal_type or board name');
        const { rows: [threadData] } = await query(`
          SELECT t.id, t.title, t.body_md, t.tags, t.sticky, t.locked,
                 t.created_at, u.handle_number as author, b.key as board_key
          FROM threads t
          JOIN users u ON t.author_id = u.id
          JOIN boards b ON t.board_id = b.id
          WHERE t.id = $1
        `, [id]);
        thread = { ...threadData, signal_type: null, board_name: threadData.board_key };
      } else {
        throw columnError;
      }
    }

    if (!thread) {
      return res.status(404).json({ error: 'Thread not found' });
    }

    // Get posts
    const { rows: posts } = await query(`
      SELECT p.id, p.body_md, p.created_at, u.handle_number as author
      FROM posts p
      JOIN users u ON p.author_id = u.id
      WHERE p.thread_id = $1
      ORDER BY p.created_at ASC
    `, [id]);

    res.json({ thread, posts });
  } catch (error) {
    console.error('Get thread error:', error);
    res.status(500).json({ error: 'Failed to get thread' });
  }
});

// Create post in thread
app.post('/api/threads/:id/posts', authRequired, async (req, res) => {
  try {
    const { id } = req.params;
    const { body_md } = req.body;
    
    if (!body_md) {
      return res.status(400).json({ error: 'Post body required' });
    }

    // Check if thread exists and isn't locked
    const { rows: [thread] } = await query(
      'SELECT id, locked FROM threads WHERE id = $1',
      [id]
    );

    if (!thread) {
      return res.status(404).json({ error: 'Thread not found' });
    }

    if (thread.locked) {
      return res.status(403).json({ error: 'Thread is locked' });
    }

    // Create post
    const { rows: [post] } = await query(`
      INSERT INTO posts (thread_id, author_id, body_md)
      VALUES ($1, $2, $3)
      RETURNING id, body_md, created_at
    `, [id, req.user.id, body_md]);

    // Update thread timestamp
    await query('UPDATE threads SET updated_at = now() WHERE id = $1', [id]);

    res.json({
      post: {
        ...post,
        author: req.user.handle_number
      }
    });

  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Moderate thread (sticky/lock)
app.patch('/api/threads/:id', authRequired, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ error: 'Admin required' });
    }

    const { id } = req.params;
    const { sticky, locked } = req.body;

    const updates = [];
    const values = [];
    let paramCount = 1;

    if (typeof sticky === 'boolean') {
      updates.push(`sticky = $${paramCount++}`);
      values.push(sticky);
    }

    if (typeof locked === 'boolean') {
      updates.push(`locked = $${paramCount++}`);
      values.push(locked);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No valid updates provided' });
    }

    values.push(id);

    const { rows: [thread] } = await query(`
      UPDATE threads SET ${updates.join(', ')}, updated_at = now()
      WHERE id = $${paramCount}
      RETURNING id, sticky, locked
    `, values);

    if (!thread) {
      return res.status(404).json({ error: 'Thread not found' });
    }

    res.json({ thread });

  } catch (error) {
    console.error('Moderate thread error:', error);
    res.status(500).json({ error: 'Failed to moderate thread' });
  }
});

// Get chat rooms
app.get('/api/chat/rooms', authRequired, async (req, res) => {
  try {
    const { rows: rooms } = await query('SELECT key, title FROM chat_rooms ORDER BY title');
    res.json({ rooms });
  } catch (error) {
    console.error('Get rooms error:', error);
    res.status(500).json({ error: 'Failed to get rooms' });
  }
});

// Get chat messages for a room
app.get('/api/chat/rooms/:key/messages', authRequired, async (req, res) => {
  try {
    const { key } = req.params;
    const limit = parseInt(req.query.limit) || 50;

    const { rows: messages } = await query(`
      SELECT m.body, m.created_at, u.handle_number as author
      FROM messages m
      JOIN chat_rooms r ON m.room_id = r.id
      JOIN users u ON m.author_id = u.id
      WHERE r.key = $1
      ORDER BY m.created_at DESC
      LIMIT $2
    `, [key, limit]);

    res.json({ messages: messages.reverse() });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

// Debug route (remove in production)
app.get('/api/debug/schema', async (req, res) => {
  try {
    const threadsSchema = await query(`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'threads' 
      ORDER BY ordinal_position
    `);
    
    const boardsSchema = await query(`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'boards' 
      ORDER BY ordinal_position
    `);
    
    res.json({ 
      threads: threadsSchema.rows,
      boards: boardsSchema.rows 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
    try {
      const { rows: roomRows } = await query(`SELECT id FROM chat_rooms WHERE key=$1`, [roomKey]);
      const room = roomRows[0];
      if (!room) return;

      await query(`INSERT INTO messages(room_id, author_id, body) VALUES($1,$2,$3)`, [room.id, socket.user.id, body]);

      io.to(roomKey).emit('message', {
        author: socket.user.handle_number,
        body,
        created_at: new Date().toISOString()
      });
    } catch (error) {
      console.error('Socket message error:', error);
    }
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
