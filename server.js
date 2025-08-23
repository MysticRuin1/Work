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
const multer = require('multer');
const fs = require('fs').promises;
const crypto = require('crypto');
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

// Configure multer for image uploads
const storage = multer.diskStorage({
destination: async (req, file, cb) => {
const uploadDir = path.join(__dirname, 'public', 'uploads');
try {
await fs.mkdir(uploadDir, { recursive: true });
cb(null, uploadDir);
} catch (error) {
cb(error);
}
},
filename: (req, file, cb) => {
const uniqueSuffix = crypto.randomBytes(16).toString('hex');
const ext = path.extname(file.originalname);
cb(null, `${Date.now()}-${uniqueSuffix}${ext}`);
}
});

const fileFilter = (req, file, cb) => {
if (file.mimetype.startsWith('image/')) {
cb(null, true);
} else {
cb(new Error('Only image files are allowed'), false);
}
};

const upload = multer({
storage,
fileFilter,
limits: {
fileSize: 5 * 1024 * 1024, // 5MB limit
}
});

// --- Middleware ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

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

function adminRequired(req, res, next) {
if (!req.user || !req.user.is_admin || req.user.handle_number !== 'Witness1') {
return res.status(403).json({ error: 'Witness1 admin access required' });
}
next();
}

async function query(q, params) {
const client = await pool.connect();
try {
return await client.query(q, params);
} finally {
client.release();
}
}

// Field Cred system based on voting
async function updateFieldCredForVote(targetUserId, voteType, targetType) {
try {
let credChange = 0;
if (voteType === 'up') {
switch (targetType) {
case 'thread': credChange = 3; break;
case 'post': credChange = 2; break;
case 'message': credChange = 1; break;
}
} else if (voteType === 'down') {
switch (targetType) {
case 'thread': credChange = -2; break;
case 'post': credChange = -1; break;
case 'message': credChange = -1; break;
}
}

if (credChange !== 0) {
const { rows: [user] } = await query(`
UPDATE users
SET field_cred = GREATEST(0, field_cred + $1)
WHERE id = $2
RETURNING field_cred, handle_number
`, [credChange, targetUserId]);
console.log(`Field Cred: ${user.handle_number} ${credChange > 0 ? '+' : ''}${credChange} (${voteType}vote on ${targetType}) -> ${user.field_cred}`);
}
} catch (error) {
console.error('Field Cred update error:', error);
}
}

// --- Migration helper ---
async function ensureMigrations() {
try {
console.log('Starting migrations...');
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
CREATE SEQUENCE IF NOT EXISTS user_number_seq START 1;
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
is_admin BOOLEAN DEFAULT false,
deleted_at TIMESTAMPTZ,
deletion_reason TEXT
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
image_path TEXT,
upvotes INT DEFAULT 0,
downvotes INT DEFAULT 0,
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
image_path TEXT,
sticky BOOLEAN DEFAULT false,
locked BOOLEAN DEFAULT false,
upvotes INT DEFAULT 0,
downvotes INT DEFAULT 0,
created_at TIMESTAMPTZ DEFAULT now(),
updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS posts (
id SERIAL PRIMARY KEY,
thread_id INT REFERENCES threads(id) ON DELETE CASCADE,
author_id INT REFERENCES users(id) ON DELETE CASCADE,
body_md TEXT NOT NULL,
image_path TEXT,
upvotes INT DEFAULT 0,
downvotes INT DEFAULT 0,
created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS votes (
id SERIAL PRIMARY KEY,
voter_id INT REFERENCES users(id) ON DELETE CASCADE,
target_type TEXT NOT NULL,
target_id INT NOT NULL,
vote_type TEXT NOT NULL CHECK (vote_type IN ('up', 'down')),
created_at TIMESTAMPTZ DEFAULT now(),
UNIQUE(voter_id, target_type, target_id)
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
name: '003_witness1_admin',
sql: `
INSERT INTO users (handle, number, handle_number, password_hash, creed, member, active, is_admin, field_cred)
VALUES ('Witness', 1, 'Witness1',
'$2b$12$8K1p/a0dclxU/1SUPiYmy.WsaRm0CXqJXwzYzk3Ywq7kBNRJC7cqG', 'vigil', 'admin',
'active', true, 999)
ON CONFLICT (handle_number)
DO UPDATE SET
is_admin = true,
member = 'admin',
active = 'active',
field_cred = 999,
password_hash = '$2b$12$8K1p/a0dclxU/1SUPiYmy.WsaRm0CXqJXwzYzk3Ywq7kBNRJC7cqG';
`
},
{
name: '004_fix_missing_columns',
sql: `
-- Add missing name column to boards if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'boards' AND column_name = 'name') THEN
        ALTER TABLE boards ADD COLUMN name TEXT;
    END IF;
END $$;

-- Add missing image_path column to messages if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'messages' AND column_name = 'image_path') THEN
        ALTER TABLE messages ADD COLUMN image_path TEXT;
    END IF;
END $$;

-- Update boards with names if they don't have them
UPDATE boards SET name = 'Firelight' WHERE key = 'firelight' AND name IS NULL;
UPDATE boards SET name = 'Judgment Day' WHERE key = 'judgment-day' AND name IS NULL;
UPDATE boards SET name = 'Triage' WHERE key = 'triage' AND name IS NULL;
UPDATE boards SET name = 'Unity' WHERE key = 'unity' AND name IS NULL;
UPDATE boards SET name = 'Vigil' WHERE key = 'vigil' AND name IS NULL;
UPDATE boards SET name = 'Vitalis' WHERE key = 'vitalis' AND name IS NULL;
`
},
{
name: '005_fix_witness1_password',
sql: `
-- Update Witness1 password to the correct hash for 'AdminHunter2024!'
UPDATE users 
SET password_hash = '$2b$12$8K1p/a0dclxU/1SUPiYmy.WsaRm0CXqJXwzYzk3Ywq7kBNRJC7cqG'
WHERE handle_number = 'Witness1';
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

// Ensure sequence is properly set
await query(`SELECT setval('user_number_seq', COALESCE((SELECT MAX(number) FROM users), 1), true)`);
console.log('Migrations completed successfully');
} catch (error) {
console.error('Migration error:', error);
throw error;
}
}

// --- API Routes ---

// Upload image
app.post('/api/upload', authRequired, upload.single('image'), (req, res) => {
try {
if (!req.file) {
return res.status(400).json({ error: 'No image file provided' });
}
const imagePath = `/uploads/${req.file.filename}`;
res.json({ image_path: imagePath });
} catch (error) {
console.error('Upload error:', error);
res.status(500).json({ error: 'Upload failed' });
}
});

// Vote on content
app.post('/api/vote', authRequired, async (req, res) => {
try {
const { target_type, target_id, vote_type } = req.body;
if (!['thread', 'post', 'message'].includes(target_type)) {
return res.status(400).json({ error: 'Invalid target type' });
}
if (!['up', 'down'].includes(vote_type)) {
return res.status(400).json({ error: 'Invalid vote type' });
}

// Get target author
let authorQuery;
switch (target_type) {
case 'thread':
authorQuery = 'SELECT author_id FROM threads WHERE id = $1';
break;
case 'post':
authorQuery = 'SELECT author_id FROM posts WHERE id = $1';
break;
case 'message':
authorQuery = 'SELECT author_id FROM messages WHERE id = $1';
break;
}

const { rows: [targetData] } = await query(authorQuery, [target_id]);
if (!targetData) {
return res.status(404).json({ error: 'Target not found' });
}

// Can't vote on your own content
if (targetData.author_id === req.user.id) {
return res.status(400).json({ error: 'Cannot vote on your own content' });
}

// Insert or update vote
await query(`
INSERT INTO votes (voter_id, target_type, target_id, vote_type)
VALUES ($1, $2, $3, $4)
ON CONFLICT (voter_id, target_type, target_id)
DO UPDATE SET vote_type = $4, created_at = now()
`, [req.user.id, target_type, target_id, vote_type]);

// Update vote counts
const { rows: [voteCounts] } = await query(`
SELECT
COUNT(CASE WHEN vote_type = 'up' THEN 1 END) as upvotes,
COUNT(CASE WHEN vote_type = 'down' THEN 1 END) as downvotes
FROM votes
WHERE target_type = $1 AND target_id = $2
`, [target_type, target_id]);

// Update the target table with new vote counts
const updateQuery = `UPDATE ${target_type}s SET upvotes = $1, downvotes = $2 WHERE id = $3`;
await query(updateQuery, [voteCounts.upvotes, voteCounts.downvotes, target_id]);

// Update field cred for the content author
await updateFieldCredForVote(targetData.author_id, vote_type, target_type);

res.json({
upvotes: parseInt(voteCounts.upvotes),
downvotes: parseInt(voteCounts.downvotes)
});
} catch (error) {
console.error('Vote error:', error);
res.status(500).json({ error: 'Failed to vote' });
}
});

// Get vote status for content
app.get('/api/votes/:target_type/:target_id', authRequired, async (req, res) => {
try {
const { target_type, target_id } = req.params;

// Get vote counts
const { rows: [voteCounts] } = await query(`
SELECT upvotes, downvotes FROM ${target_type}s WHERE id = $1
`, [target_id]);

// Get user's vote
const { rows: [userVote] } = await query(`
SELECT vote_type FROM votes
WHERE voter_id = $1 AND target_type = $2 AND target_id = $3
`, [req.user.id, target_type, target_id]);

res.json({
upvotes: voteCounts?.upvotes || 0,
downvotes: voteCounts?.downvotes || 0,
user_vote: userVote?.vote_type || null
});
} catch (error) {
console.error('Get votes error:', error);
res.status(500).json({ error: 'Failed to get votes' });
}
});

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

// Create user
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
maxAge: 7 * 24 * 60 * 60 * 1000
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
if (error.code === '23505') {
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

let user = null;
// Try exact match first
const { rows: exactMatch } = await query(
'SELECT id, handle_number, password_hash, field_cred, is_admin, active FROM users WHERE handle_number = $1',
[handle_number]
);

if (exactMatch.length > 0) {
user = exactMatch[0];
} else {
// Try handle without number
const { rows: handleMatches } = await query(
'SELECT id, handle_number, password_hash, field_cred, is_admin, active FROM users WHERE handle = $1 ORDER BY number ASC',
[handle_number]
);
if (handleMatches.length > 0) {
user = handleMatches[0];
}
}

if (!user) {
return res.status(401).json({ error: 'Invalid credentials' });
}

// Check if account is deleted
if (user.active === 'deleted') {
return res.status(401).json({ error: 'Account has been deleted' });
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
maxAge: 7 * 24 * 60 * 60 * 1000
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
'SELECT handle_number, field_cred, is_admin FROM users WHERE id = $1 AND active != \'deleted\'',
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

// Delete account
app.delete('/api/account', authRequired, async (req, res) => {
try {
const { password, reason } = req.body;
if (!password) {
return res.status(400).json({ error: 'Password required for account deletion' });
}

// Verify password
const { rows: [user] } = await query(
'SELECT password_hash FROM users WHERE id = $1',
[req.user.id]
);

const validPassword = await bcrypt.compare(password, user.password_hash);
if (!validPassword) {
return res.status(401).json({ error: 'Invalid password' });
}

// Soft delete
await query(`
UPDATE users
SET deleted_at = now(), deletion_reason = $1, active = 'deleted'
WHERE id = $2
`, [reason || 'User requested deletion', req.user.id]);

res.clearCookie('token');
res.json({ success: true, message: 'Account deleted successfully' });
} catch (error) {
console.error('Delete account error:', error);
res.status(500).json({ error: 'Failed to delete account' });
}
});

// Get boards
app.get('/api/boards', async (req, res) => {
try {
const { rows: boards } = await query(
'SELECT id, name, description, key FROM boards ORDER BY name'
);
res.json({ boards });
} catch (error) {
console.error('Get boards error:', error);
res.status(500).json({ error: 'Failed to get boards' });
}
});

// Get threads for a board
app.get('/api/boards/:key/threads', async (req, res) => {
try {
const { key } = req.params;
const { rows: threads } = await query(`
SELECT t.id, t.title, t.signal_type, t.tags, t.sticky, t.locked,
t.upvotes, t.downvotes, t.created_at, t.updated_at,
u.handle_number as author,
(SELECT COUNT(*) FROM posts WHERE thread_id = t.id) as post_count
FROM threads t
JOIN boards b ON t.board_id = b.id
JOIN users u ON t.author_id = u.id
WHERE b.key = $1
ORDER BY t.sticky DESC, t.updated_at DESC
`, [key]);

res.json({ threads });
} catch (error) {
console.error('Get threads error:', error);
res.status(500).json({ error: 'Failed to get threads' });
}
});

// Create thread
app.post('/api/boards/:key/threads', authRequired, async (req, res) => {
try {
const { key } = req.params;
const { title, body_md, signal, tags, image_path } = req.body;

if (!title || !body_md) {
return res.status(400).json({ error: 'Title and body required' });
}

// Get board
const { rows: [board] } = await query('SELECT id FROM boards WHERE key = $1', [key]);
if (!board) {
return res.status(404).json({ error: 'Board not found' });
}

// Process tags
let processedTags = null;
if (tags) {
if (Array.isArray(tags)) {
processedTags = tags.join(', ');
} else if (typeof tags === 'string') {
processedTags = tags;
}
}

// Create thread
const { rows: [thread] } = await query(`
INSERT INTO threads (board_id, author_id, title, body_md, signal_type, tags, image_path)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, title, signal_type, tags, image_path, created_at
`, [board.id, req.user.id, title, body_md, signal || null, processedTags, image_path || null]);

// Award field cred
let credChange = 2;
if (signal === 'after-action') credChange = 4;
if (signal === 'intel' || signal === 'sighting') credChange = 3;
if (image_path) credChange += 1;

await query('UPDATE users SET field_cred = field_cred + $1 WHERE id = $2', [credChange, req.user.id]);

res.json({ thread });
} catch (error) {
console.error('Create thread error:', error);
res.status(500).json({ error: 'Failed to create thread' });
}
});

// Get thread with posts
app.get('/api/threads/:id', async (req, res) => {
try {
const { id } = req.params;

// Get thread
const { rows: [thread] } = await query(`
SELECT t.id, t.title, t.body_md, t.signal_type, t.tags, t.sticky, t.locked,
t.image_path, t.upvotes, t.downvotes, t.created_at,
u.handle_number as author, b.name as board_name, b.key as board_key
FROM threads t
JOIN users u ON t.author_id = u.id
JOIN boards b ON t.board_id = b.id
WHERE t.id = $1
`, [id]);

if (!thread) {
return res.status(404).json({ error: 'Thread not found' });
}

// Get posts
const { rows: posts } = await query(`
SELECT p.id, p.body_md, p.image_path, p.upvotes, p.downvotes, p.created_at,
u.handle_number as author
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
const { body_md, image_path } = req.body;

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
INSERT INTO posts (thread_id, author_id, body_md, image_path)
VALUES ($1, $2, $3, $4)
RETURNING id, body_md, image_path, created_at
`, [id, req.user.id, body_md, image_path || null]);

// Update thread timestamp
await query('UPDATE threads SET updated_at = now() WHERE id = $1', [id]);

// Award field cred
let credChange = 1;
if (image_path) credChange += 1;
await query('UPDATE users SET field_cred = field_cred + $1 WHERE id = $2', [credChange, req.user.id]);

res.json({
post: {
...post,
author: req.user.handle_number,
upvotes: 0,
downvotes: 0
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
SELECT m.id, m.body, m.image_path, m.upvotes, m.downvotes, m.created_at,
u.handle_number as author
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

// --- ADMIN ROUTES (Witness1 only) ---

// Admin: Get user list
app.get('/api/admin/users', adminRequired, async (req, res) => {
try {
const { rows: users } = await query(`
SELECT
id, handle_number, email, creed, field_cred,
active, created_at, deleted_at, deletion_reason,
(SELECT COUNT(*) FROM threads WHERE author_id = users.id) as thread_count,
(SELECT COUNT(*) FROM posts WHERE author_id = users.id) as post_count
FROM users
ORDER BY created_at DESC
`);

res.json({ users });
} catch (error) {
console.error('Admin get users error:', error);
res.status(500).json({ error: 'Failed to get users' });
}
});

// Admin: Update user field cred
app.patch('/api/admin/users/:id/field-cred', adminRequired, async (req, res) => {
try {
const { id } = req.params;
const { field_cred, reason } = req.body;

const { rows: [user] } = await query(`
UPDATE users
SET field_cred = $1
WHERE id = $2
RETURNING handle_number, field_cred
`, [field_cred, id]);

if (!user) {
return res.status(404).json({ error: 'User not found' });
}

console.log(`Admin Field Cred Update: ${user.handle_number} set to ${field_cred} (${reason || 'Admin adjustment'})`);

res.json({
success: true,
user: {
handle_number: user.handle_number,
field_cred: user.field_cred
}
});
} catch (error) {
console.error('Admin field cred update error:', error);
res.status(500).json({ error: 'Failed to update field cred' });
}
});

// Admin: Force delete user
app.delete('/api/admin/users/:id', adminRequired, async (req, res) => {
try {
const { id } = req.params;
const { reason } = req.body;

if (parseInt(id) === req.user.id) {
return res.status(400).json({ error: 'Cannot delete your own admin account' });
}

const { rows: [user] } = await query(`
UPDATE users
SET deleted_at = now(), deletion_reason = $1, active = 'deleted'
WHERE id = $2
RETURNING handle_number
`, [reason || 'Admin deletion', id]);

if (!user) {
return res.status(404).json({ error: 'User not found' });
}

console.log(`Admin deletion: ${user.handle_number} deleted by Witness1 (${reason})`);

res.json({
success: true,
message: `User ${user.handle_number} deleted by admin`
});
} catch (error) {
console.error('Admin delete user error:', error);
res.status(500).json({ error: 'Failed to delete user' });
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

socket.on('message', async ({ roomKey, body, image_path }) => {
try {
const { rows: roomRows } = await query(`SELECT id FROM chat_rooms WHERE key=$1`, [roomKey]);
const room = roomRows[0];
if (!room) return;

const { rows: [message] } = await query(`
INSERT INTO messages(room_id, author_id, body, image_path)
VALUES($1,$2,$3,$4)
RETURNING id, created_at
`, [room.id, socket.user.id, body, image_path || null]);

// Award small field cred for chat participation
await query('UPDATE users SET field_cred = field_cred + 1 WHERE id = $1', [socket.user.id]);

io.to(roomKey).emit('message', {
id: message.id,
author: socket.user.handle_number,
body,
image_path,
created_at: message.created_at,
upvotes: 0,
downvotes: 0
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

app.get(/^\/(?!api|healthz|socket\.io|uploads).*/, (req, res) => {
res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Start ---

ensureMigrations().then(() => {
server.listen(PORT, () => {
console.log('Enhanced Hunter-Net server running on port', PORT);
console.log('Default Witness1 password: AdminHunter2024! - CHANGE THIS IMMEDIATELY!');
});
}).catch(err => {
console.error('Migration error:', err);
process.exit(1);
});
