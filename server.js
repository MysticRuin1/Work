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

// Enhanced connection with better error handling
const pool = new Pool({
connectionString: process.env.DATABASE_URL,
ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
? { rejectUnauthorized: false }
: false,
max: 20,
idleTimeoutMillis: 30000,
connectionTimeoutMillis: 10000,
});

// Configure multer for image uploads
const storage = multer.diskStorage({
destination: async (req, file, cb) => {
const uploadDir = path.join(__dirname, 'public', 'uploads');
try {
await fs.mkdir(uploadDir, { recursive: true });
cb(null, uploadDir);
} catch (error) {
console.error('Upload directory creation failed:', error);
cb(error);
}
},
filename: (req, file, cb) => {
const uniqueSuffix = crypto.randomBytes(16).toString('hex');
const ext = path.extname(file.originalname).toLowerCase();
const safeName = `${Date.now()}-${uniqueSuffix}${ext}`;
cb(null, safeName);
}
});

const fileFilter = (req, file, cb) => {
const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
if (allowedTypes.includes(file.mimetype)) {
cb(null, true);
} else {
cb(new Error('Only JPEG, PNG, GIF, and WebP images are allowed'), false);
}
};

const upload = multer({
storage,
fileFilter,
limits: {
fileSize: 5 * 1024 * 1024, // 5MB limit
files: 1 // Only one file at a time
}
});

// --- Middleware ---
app.use(helmet({
contentSecurityPolicy: false,
crossOriginEmbedderPolicy: false
}));
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
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
if (!req.user || !req.user.is_admin) {
return res.status(403).json({ error: 'Admin access required' });
}
next();
}

async function query(q, params) {
const client = await pool.connect();
try {
const result = await client.query(q, params);
return result;
} catch (error) {
console.error('Database query error:', error);
throw error;
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
name: '001_init_tables',
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
name TEXT NOT NULL,
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
pinned BOOLEAN DEFAULT false,
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

CREATE TABLE IF NOT EXISTS private_messages (
id SERIAL PRIMARY KEY,
sender_id INT REFERENCES users(id) ON DELETE CASCADE,
recipient_id INT REFERENCES users(id) ON DELETE CASCADE,
subject TEXT NOT NULL,
content TEXT NOT NULL,
read_at TIMESTAMPTZ,
created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS server_messages (
id SERIAL PRIMARY KEY,
content TEXT NOT NULL,
message_type TEXT DEFAULT 'info',
active BOOLEAN DEFAULT true,
created_at TIMESTAMPTZ DEFAULT now(),
expires_at TIMESTAMPTZ
);
`
},
{
name: '002_add_moderator_column',
sql: `
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_moderator BOOLEAN DEFAULT false;
`
},
{
name: '003_seed_boards_rooms',
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
('General Discussion', 'General hunter communications', 'general'),
('Creature Sightings', 'Report supernatural encounters', 'sightings'),
('Intelligence Reports', 'Share gathered intelligence', 'intel'),
('Aid Requests', 'Request assistance from other hunters', 'requests'),
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
name: '004_witness1_admin_correct_password',
sql: `
DELETE FROM users WHERE handle_number = 'Witness1';

INSERT INTO users (handle, number, handle_number, password_hash, creed, member, active, is_admin, is_moderator, field_cred)
VALUES ('Witness', 1, 'Witness1', '${await bcrypt.hash('Witness1Pass2024!', 12)}', 'vigil', 'admin', 'active', true, true, 999);
`
},
{
name: '005_demo_users',
sql: `
INSERT INTO users (handle, number, handle_number, password_hash, creed, member, active, is_admin, is_moderator, field_cred)
VALUES
('hunter', 1, 'hunter001', '${await bcrypt.hash('test123', 12)}', 'vigil', 'member', 'active', false, false, 250),
('tracker', 7, 'tracker007', '${await bcrypt.hash('password123', 12)}', 'firelight', 'moderator', 'active', false, true, 1500)
ON CONFLICT (handle_number) DO NOTHING;
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
console.log('Demo Accounts:');
console.log('Admin: Witness1 / Witness1Pass2024!');
console.log('User: hunter001 / test123');
console.log('Mod: tracker007 / password123');
} catch (error) {
console.error('Migration error:', error);
throw error;
}
}

// --- API Routes ---

// Upload image
app.post('/api/upload', authRequired, (req, res) => {
upload.single('image')(req, res, (err) => {
if (err) {
console.error('Multer error:', err);
if (err instanceof multer.MulterError) {
if (err.code === 'LIMIT_FILE_SIZE') {
return res.status(400).json({ error: 'File too large. Maximum 5MB allowed.' });
}
return res.status(400).json({ error: `Upload error: ${err.message}` });
}
return res.status(400).json({ error: err.message });
}

if (!req.file) {
return res.status(400).json({ error: 'No image file provided' });
}

const imagePath = `/uploads/${req.file.filename}`;
console.log(`Image uploaded: ${imagePath} by ${req.user.handle_number}`);
res.json({
image_path: imagePath,
filename: req.file.filename,
size: req.file.size
});
});
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
let tableName;
switch (target_type) {
case 'thread':
authorQuery = 'SELECT author_id FROM threads WHERE id = $1';
tableName = 'threads';
break;
case 'post':
authorQuery = 'SELECT author_id FROM posts WHERE id = $1';
tableName = 'posts';
break;
case 'message':
authorQuery = 'SELECT author_id FROM messages WHERE id = $1';
tableName = 'messages';
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
const updateQuery = `UPDATE ${tableName} SET upvotes = $1, downvotes = $2 WHERE id = $3`;
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
let tableName;
switch (target_type) {
case 'thread': tableName = 'threads'; break;
case 'post': tableName = 'posts'; break;
case 'message': tableName = 'messages'; break;
default: return res.status(400).json({ error: 'Invalid target type' });
}

// Get vote counts
const { rows: [voteCounts] } = await query(`
SELECT upvotes, downvotes FROM ${tableName} WHERE id = $1
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
RETURNING id, handle_number, field_cred, creed, is_admin, is_moderator, created_at
`, [handle, nextval, handle_number, password_hash, email || null, creed || null, 'member', 'active']);

// Sign JWT
const token = signToken({
id: user.id,
handle_number: user.handle_number,
is_admin: user.is_admin,
is_moderator: user.is_moderator
});

res.cookie('token', token, {
httpOnly: true,
secure: process.env.NODE_ENV === 'production',
maxAge: 7 * 24 * 60 * 60 * 1000,
sameSite: 'lax'
});

res.json({
user: {
id: user.id,
handle_number: user.handle_number,
field_cred: user.field_cred,
creed: user.creed,
is_admin: user.is_admin,
is_moderator: user.is_moderator,
created_at: user.created_at
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

console.log(`Login attempt for: ${handle_number}`);

// Try exact match first
const { rows: exactMatch } = await query(
'SELECT id, handle_number, password_hash, field_cred, creed, is_admin, is_moderator, active, created_at FROM users WHERE handle_number = $1',
[handle_number]
);

let user = null;
if (exactMatch.length > 0) {
user = exactMatch[0];
console.log(`Found exact match for ${handle_number}`);
} else {
// Try handle without number
const handlePart = handle_number.replace(/\d+$/, '');
const { rows: handleMatches } = await query(
'SELECT id, handle_number, password_hash, field_cred, creed, is_admin, is_moderator, active, created_at FROM users WHERE handle = $1 ORDER BY number ASC',
[handlePart]
);

if (handleMatches.length > 0) {
user = handleMatches[0];
console.log(`Found handle match for ${handlePart} -> ${user.handle_number}`);
}
}

if (!user) {
console.log(`No user found for ${handle_number}`);
return res.status(401).json({ error: 'Invalid credentials' });
}

// Check if account is deleted
if (user.active === 'deleted') {
return res.status(401).json({ error: 'Account has been deleted' });
}

// Check password
const valid = await bcrypt.compare(password, user.password_hash);
if (!valid) {
console.log(`Invalid password for ${user.handle_number}`);
return res.status(401).json({ error: 'Invalid credentials' });
}

console.log(`Successful login for ${user.handle_number} (admin: ${user.is_admin})`);

// Sign JWT
const token = signToken({
id: user.id,
handle_number: user.handle_number,
is_admin: user.is_admin,
is_moderator: user.is_moderator
});

res.cookie('token', token, {
httpOnly: true,
secure: process.env.NODE_ENV === 'production',
maxAge: 7 * 24 * 60 * 60 * 1000,
sameSite: 'lax'
});

res.json({
user: {
id: user.id,
handle_number: user.handle_number,
field_cred: user.field_cred,
creed: user.creed,
is_admin: user.is_admin,
is_moderator: user.is_moderator,
created_at: user.created_at
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
'SELECT id, handle_number, field_cred, creed, is_admin, is_moderator, created_at FROM users WHERE id = $1 AND active != \'deleted\'',
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

// Change password
app.patch('/api/account/password', authRequired, async (req, res) => {
try {
const { current_password, new_password } = req.body;

if (!current_password || !new_password) {
return res.status(400).json({ error: 'Current and new password required' });
}
if (new_password.length < 8) {
return res.status(400).json({ error: 'New password must be at least 8 characters' });
}

// Verify current password
const { rows: [user] } = await query(
'SELECT password_hash FROM users WHERE id = $1',
[req.user.id]
);

const validPassword = await bcrypt.compare(current_password, user.password_hash);
if (!validPassword) {
return res.status(401).json({ error: 'Invalid current password' });
}

// Hash new password
const new_password_hash = await bcrypt.hash(new_password, 12);

// Update password
await query(
'UPDATE users SET password_hash = $1 WHERE id = $2',
[new_password_hash, req.user.id]
);

res.json({ success: true });
} catch (error) {
console.error('Change password error:', error);
res.status(500).json({ error: 'Failed to change password' });
}
});

// Change affiliation
app.patch('/api/account/affiliation', authRequired, async (req, res) => {
try {
const { affiliation } = req.body;
const { rows: [user] } = await query(
'UPDATE users SET creed = $1 WHERE id = $2 RETURNING creed',
[affiliation || null, req.user.id]
);

res.json({ creed: user.creed });
} catch (error) {
console.error('Change affiliation error:', error);
res.status(500).json({ error: 'Failed to change affiliation' });
}
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
SELECT t.id, t.title, t.signal_type, t.tags, t.sticky, t.locked, t.pinned,
t.upvotes, t.downvotes, t.created_at, t.updated_at,
u.handle_number as author,
(SELECT COUNT(*) FROM posts WHERE thread_id = t.id) as post_count
FROM threads t
JOIN boards b ON t.board_id = b.id
JOIN users u ON t.author_id = u.id
WHERE b.key = $1 AND u.active != 'deleted'
ORDER BY t.pinned DESC, t.sticky DESC, t.updated_at DESC
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

await query('UPDATE users SET field_cred = field_cred + $1 WHERE id = $2',
[credChange, req.user.id]);

console.log(`Thread created: "${title}" by ${req.user.handle_number} (+${credChange} cred)`);

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
SELECT t.id, t.title, t.body_md, t.signal_type, t.tags, t.sticky, t.locked, t.pinned,
t.image_path, t.upvotes, t.downvotes, t.created_at,
u.handle_number as author, b.name as board_name, b.key as board_key
FROM threads t
JOIN users u ON t.author_id = u.id
JOIN boards b ON t.board_id = b.id
WHERE t.id = $1 AND u.active != 'deleted'
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
WHERE p.thread_id = $1 AND u.active != 'deleted'
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

if (thread.locked && !req.user.is_admin) {
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
await query('UPDATE users SET field_cred = field_cred + $1 WHERE id = $2',
[credChange, req.user.id]);

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

// Delete thread
app.delete('/api/threads/:id', authRequired, async (req, res) => {
try {
const { id } = req.params;

// Check if user can delete (admin or author)
const { rows: [thread] } = await query(
'SELECT author_id FROM threads WHERE id = $1',
[id]
);

if (!thread) {
return res.status(404).json({ error: 'Thread not found' });
}

if (!req.user.is_admin && thread.author_id !== req.user.id) {
return res.status(403).json({ error: 'Permission denied' });
}

await query('DELETE FROM threads WHERE id = $1', [id]);
res.json({ success: true });
} catch (error) {
console.error('Delete thread error:', error);
res.status(500).json({ error: 'Failed to delete thread' });
}
});

// Delete post
app.delete('/api/posts/:id', authRequired, async (req, res) => {
try {
const { id } = req.params;

// Check if user can delete (admin or author)
const { rows: [post] } = await query(
'SELECT author_id, thread_id FROM posts WHERE id = $1',
[id]
);

if (!post) {
return res.status(404).json({ error: 'Post not found' });
}

if (!req.user.is_admin && post.author_id !== req.user.id) {
return res.status(403).json({ error: 'Permission denied' });
}

await query('DELETE FROM posts WHERE id = $1', [id]);

// Update thread timestamp
await query('UPDATE threads SET updated_at = now() WHERE id = $1', [post.thread_id]);

res.json({ success: true });
} catch (error) {
console.error('Delete post error:', error);
res.status(500).json({ error: 'Failed to delete post' });
}
});

// Moderate thread (sticky/lock/pin)
app.patch('/api/threads/:id', authRequired, async (req, res) => {
try {
if (!req.user.is_admin) {
return res.status(403).json({ error: 'Admin required' });
}

const { id } = req.params;
const { sticky, locked, pinned } = req.body;

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
if (typeof pinned === 'boolean') {
updates.push(`pinned = $${paramCount++}`);
values.push(pinned);
}

if (updates.length === 0) {
return res.status(400).json({ error: 'No valid updates provided' });
}

values.push(id);
const { rows: [thread] } = await query(`
UPDATE threads SET ${updates.join(', ')}, updated_at = now()
WHERE id = $${paramCount}
RETURNING id, sticky, locked, pinned
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

// Get members
app.get('/api/members', authRequired, async (req, res) => {
try {
const { rows: members } = await query(`
SELECT handle_number, field_cred, creed, is_admin, is_moderator, created_at,
(SELECT COUNT(*) FROM threads WHERE author_id = users.id) as active_threads,
(SELECT COUNT(*) FROM posts WHERE author_id = users.id) as post_count,
(SELECT COUNT(*) FROM messages WHERE author_id = users.id) as message_count,
true as is_online
FROM users
WHERE active = 'active'
ORDER BY is_admin DESC, is_moderator DESC, created_at ASC
`);

res.json({ members });
} catch (error) {
console.error('Get members error:', error);
res.status(500).json({ error: 'Failed to get members' });
}
});

// Get member profile
app.get('/api/members/:handle', authRequired, async (req, res) => {
try {
const { handle } = req.params;
const { rows: [member] } = await query(`
SELECT handle_number, field_cred, creed, is_admin, is_moderator, created_at,
(SELECT COUNT(*) FROM threads WHERE author_id = users.id) as active_threads,
(SELECT COUNT(*) FROM posts WHERE author_id = users.id) as post_count,
(SELECT COUNT(*) FROM messages WHERE author_id = users.id) as message_count,
true as is_online
FROM users
WHERE handle_number = $1 AND active = 'active'
`, [handle]);

if (!member) {
return res.status(404).json({ error: 'Member not found' });
}

res.json({ member });
} catch (error) {
console.error('Get member error:', error);
res.status(500).json({ error: 'Failed to get member' });
}
});

// Get private messages
app.get('/api/private-messages', authRequired, async (req, res) => {
try {
const { rows: conversations } = await query(`
SELECT DISTINCT
CASE
WHEN sender_id = $1 THEN recipient_id
ELSE sender_id
END as other_user_id,
(SELECT handle_number FROM users WHERE id =
CASE
WHEN sender_id = $1 THEN recipient_id
ELSE sender_id
END
) as other_participant,
subject,
MAX(created_at) as last_message_at,
COUNT(CASE WHEN recipient_id = $1 AND read_at IS NULL THEN 1 END) as unread_count,
MIN(id) as id
FROM private_messages
WHERE sender_id = $1 OR recipient_id = $1
GROUP BY other_user_id, subject
ORDER BY last_message_at DESC
`, [req.user.id]);

res.json({ conversations });
} catch (error) {
console.error('Get private messages error:', error);
res.status(500).json({ error: 'Failed to get private messages' });
}
});

// Get private conversation
app.get('/api/private-messages/:id', authRequired, async (req, res) => {
try {
const { id } = req.params;

// First get the conversation details to find the other participant
const { rows: [conversation] } = await query(`
SELECT subject, sender_id, recipient_id FROM private_messages WHERE id = $1
`, [id]);

if (!conversation) {
return res.status(404).json({ error: 'Conversation not found' });
}

// Determine the other participant
const otherUserId = conversation.sender_id === req.user.id ?
conversation.recipient_id : conversation.sender_id;

// Get all messages in this conversation thread
const { rows: messages } = await query(`
SELECT pm.id, pm.content, pm.created_at, u.handle_number as sender
FROM private_messages pm
JOIN users u ON pm.sender_id = u.id
WHERE pm.subject = $1
AND ((pm.sender_id = $2 AND pm.recipient_id = $3)
OR (pm.sender_id = $3 AND pm.recipient_id = $2))
ORDER BY pm.created_at ASC
`, [conversation.subject, req.user.id, otherUserId]);

res.json({ messages });
} catch (error) {
console.error('Get conversation error:', error);
res.status(500).json({ error: 'Failed to get conversation' });
}
});

// Send private message
app.post('/api/private-messages', authRequired, async (req, res) => {
try {
const { recipient, subject, content } = req.body;

if (!recipient || !subject || !content) {
return res.status(400).json({ error: 'Recipient, subject, and content required' });
}

// Get recipient ID
const { rows: [recipientUser] } = await query(
'SELECT id FROM users WHERE handle_number = $1 AND active = \'active\'',
[recipient]
);

if (!recipientUser) {
return res.status(404).json({ error: 'Recipient not found' });
}

if (recipientUser.id === req.user.id) {
return res.status(400).json({ error: 'Cannot send message to yourself' });
}

// Create message
const { rows: [message] } = await query(`
INSERT INTO private_messages (sender_id, recipient_id, subject, content)
VALUES ($1, $2, $3, $4)
RETURNING id, created_at
`, [req.user.id, recipientUser.id, subject, content]);

res.json({
id: message.id,
created_at: message.created_at,
success: true
});
} catch (error) {
console.error('Send private message error:', error);
res.status(500).json({ error: 'Failed to send private message' });
}
});

// Reply to private message
app.post('/api/private-messages/:id/reply', authRequired, async (req, res) => {
try {
const { id } = req.params;
const { content } = req.body;

if (!content) {
return res.status(400).json({ error: 'Content required' });
}

// Get original message to determine subject and participants
const { rows: [original] } = await query(`
SELECT subject, sender_id, recipient_id FROM private_messages WHERE id = $1
`, [id]);

if (!original) {
return res.status(404).json({ error: 'Original message not found' });
}

// Determine recipient (the other person in the conversation)
const recipientId = original.sender_id === req.user.id ?
original.recipient_id : original.sender_id;

// Create reply
const { rows: [reply] } = await query(`
INSERT INTO private_messages (sender_id, recipient_id, subject, content)
VALUES ($1, $2, $3, $4)
RETURNING id, created_at
`, [req.user.id, recipientId, original.subject, content]);

res.json({
id: reply.id,
created_at: reply.created_at,
success: true
});
} catch (error) {
console.error('Reply to private message error:', error);
res.status(500).json({ error: 'Failed to reply to private message' });
}
});

// Mark private message as read
app.post('/api/private-messages/:id/read', authRequired, async (req, res) => {
try {
const { id } = req.params;

// Mark all messages in this conversation as read
const { rows: [original] } = await query(`
SELECT subject, sender_id, recipient_id FROM private_messages WHERE id = $1
`, [id]);

if (!original) {
return res.status(404).json({ error: 'Message not found' });
}

const otherUserId = original.sender_id === req.user.id ?
original.recipient_id : original.sender_id;

await query(`
UPDATE private_messages
SET read_at = now()
WHERE subject = $1
AND recipient_id = $2
AND sender_id = $3
AND read_at IS NULL
`, [original.subject, req.user.id, otherUserId]);

res.json({ success: true });
} catch (error) {
console.error('Mark as read error:', error);
res.status(500).json({ error: 'Failed to mark as read' });
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
WHERE r.key = $1 AND u.active != 'deleted'
ORDER BY m.created_at DESC
LIMIT $2
`, [key, limit]);

res.json({ messages: messages.reverse() });
} catch (error) {
console.error('Get messages error:', error);
res.status(500).json({ error: 'Failed to get messages' });
}
});

// Get chat room members
app.get('/api/chat/rooms/:key/members', authRequired, async (req, res) => {
try {
// For demo purposes, return all active members
// In a real app, you'd track who's actually in each room
const { rows: members } = await query(`
SELECT handle_number, is_admin, is_moderator
FROM users
WHERE active = 'active'
ORDER BY is_admin DESC, is_moderator DESC, handle_number ASC
LIMIT 20
`);

res.json({ members });
} catch (error) {
console.error('Get chat members error:', error);
res.status(500).json({ error: 'Failed to get chat members' });
}
});

// Delete chat message
app.delete('/api/chat/messages/:id', authRequired, async (req, res) => {
try {
const { id } = req.params;

// Check if user can delete (admin, moderator, or author)
const { rows: [message] } = await query(
'SELECT author_id FROM messages WHERE id = $1',
[id]
);

if (!message) {
return res.status(404).json({ error: 'Message not found' });
}

if (!req.user.is_admin && !req.user.is_moderator && message.author_id !== req.user.id) {
return res.status(403).json({ error: 'Permission denied' });
}

await query('DELETE FROM messages WHERE id = $1', [id]);
res.json({ success: true });
} catch (error) {
console.error('Delete message error:', error);
res.status(500).json({ error: 'Failed to delete message' });
}
});

// Get server messages
app.get('/api/server-messages', authRequired, async (req, res) => {
try {
const { rows: messages } = await query(`
SELECT content, message_type as type
FROM server_messages
WHERE active = true
AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at DESC
LIMIT 5
`);

res.json({ messages });
} catch (error) {
console.error('Get server messages error:', error);
res.status(500).json({ error: 'Failed to get server messages' });
}
});

// --- ADMIN ROUTES ---

// Admin: Get user list
app.get('/api/admin/users', adminRequired, async (req, res) => {
try {
const { rows: users } = await query(`
SELECT
id, handle_number, email, creed, field_cred,
active, created_at, deleted_at, deletion_reason, is_moderator,
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

// Admin: Toggle moderator status
app.patch('/api/admin/users/:id/moderator', adminRequired, async (req, res) => {
try {
const { id } = req.params;
const { is_moderator } = req.body;

const { rows: [user] } = await query(`
UPDATE users
SET is_moderator = $1
WHERE id = $2
RETURNING handle_number, is_moderator
`, [is_moderator, id]);

if (!user) {
return res.status(404).json({ error: 'User not found' });
}

console.log(`Admin Moderator Update: ${user.handle_number} moderator = ${is_moderator}`);

res.json({
success: true,
user: {
handle_number: user.handle_number,
is_moderator: user.is_moderator
}
});
} catch (error) {
console.error('Admin moderator update error:', error);
res.status(500).json({ error: 'Failed to update moderator status' });
}
});

// Admin: Delete user
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

console.log(`Admin deletion: ${user.handle_number} deleted by ${req.user.handle_number} (${reason})`);

res.json({
success: true,
message: `User ${user.handle_number} deleted by admin`
});
} catch (error) {
console.error('Admin delete user error:', error);
res.status(500).json({ error: 'Failed to delete user' });
}
});

// Admin: Send server message
app.post('/api/admin/server-message', adminRequired, async (req, res) => {
try {
const { content, type } = req.body;

if (!content) {
return res.status(400).json({ error: 'Message content required' });
}

const { rows: [message] } = await query(`
INSERT INTO server_messages (content, message_type)
VALUES ($1, $2)
RETURNING id, created_at
`, [content, type || 'info']);

console.log(`Server message sent by ${req.user.handle_number}: ${content}`);

res.json({
success: true,
message: {
id: message.id,
content,
type: type || 'info',
created_at: message.created_at
}
});
} catch (error) {
console.error('Send server message error:', error);
res.status(500).json({ error: 'Failed to send server message' });
}
});

// Admin: Get private conversations
app.get('/api/admin/private-messages', adminRequired, async (req, res) => {
try {
const { rows: conversations } = await query(`
SELECT DISTINCT
pm.subject,
u1.handle_number as participant1,
u2.handle_number as participant2,
COUNT(*) as message_count,
MAX(pm.created_at) as last_message_at,
MIN(pm.id) as id
FROM private_messages pm
JOIN users u1 ON pm.sender_id = u1.id
JOIN users u2 ON pm.recipient_id = u2.id
GROUP BY pm.subject, u1.handle_number, u2.handle_number
ORDER BY last_message_at DESC
LIMIT 50
`);

res.json({ conversations });
} catch (error) {
console.error('Admin get private messages error:', error);
res.status(500).json({ error: 'Failed to get private conversations' });
}
});

// Admin: View private conversation
app.get('/api/admin/private-messages/:id', adminRequired, async (req, res) => {
try {
const { id } = req.params;

// Get the subject from the message ID
const { rows: [original] } = await query(`
SELECT subject FROM private_messages WHERE id = $1
`, [id]);

if (!original) {
return res.status(404).json({ error: 'Conversation not found' });
}

// Get all messages in this conversation
const { rows: messages } = await query(`
SELECT pm.content, pm.created_at, u.handle_number as sender
FROM private_messages pm
JOIN users u ON pm.sender_id = u.id
WHERE pm.subject = $1
ORDER BY pm.created_at ASC
`, [original.subject]);

res.json({ messages });
} catch (error) {
console.error('Admin get conversation error:', error);
res.status(500).json({ error: 'Failed to get conversation' });
}
});

// Admin: Delete private conversation
app.delete('/api/admin/private-messages/:id', adminRequired, async (req, res) => {
try {
const { id } = req.params;

// Get the subject from the message ID
const { rows: [original] } = await query(`
SELECT subject FROM private_messages WHERE id = $1
`, [id]);

if (!original) {
return res.status(404).json({ error: 'Conversation not found' });
}

// Delete all messages in this conversation
await query(`
DELETE FROM private_messages WHERE subject = $1
`, [original.subject]);

console.log(`Admin deleted private conversation: ${original.subject} by ${req.user.handle_number}`);

res.json({ success: true });
} catch (error) {
console.error('Admin delete conversation error:', error);
res.status(500).json({ error: 'Failed to delete conversation' });
}
});

// --- Socket.IO Chat Implementation ---

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
console.log(`Socket auth success: ${decoded.handle_number}`);
next();
} catch (e) {
console.log('Socket auth failed:', e.message);
next(new Error('invalid_token'));
}
});

io.on('connection', (socket) => {
console.log(`Socket connected: ${socket.user.handle_number}`);
socket.join('global');

socket.on('join', (roomKey) => {
console.log(`${socket.user.handle_number} joined room: ${roomKey}`);
Object.keys(socket.rooms).forEach(r => {
if (r !== socket.id) socket.leave(r);
});
socket.join(roomKey);
});

socket.on('message', async ({ roomKey, body, image_path }) => {
try {
if (!body || body.trim() === '') {
return socket.emit('error', { message: 'Message body required' });
}

const { rows: roomRows } = await query(`SELECT id FROM chat_rooms WHERE key=$1`, [roomKey]);
const room = roomRows[0];

if (!room) {
return socket.emit('error', { message: 'Room not found' });
}

const { rows: [message] } = await query(`
INSERT INTO messages(room_id, author_id, body, image_path)
VALUES($1,$2,$3,$4)
RETURNING id, created_at
`, [room.id, socket.user.id, body.trim(), image_path || null]);

// Award small field cred for chat participation
await query('UPDATE users SET field_cred = field_cred + 1 WHERE id = $1', [socket.user.id]);

const messageData = {
id: message.id,
author: socket.user.handle_number,
body: body.trim(),
image_path,
created_at: message.created_at,
upvotes: 0,
downvotes: 0
};

console.log(`Chat message: [${roomKey}] ${socket.user.handle_number}: ${body.substring(0, 50)}...`);

// Broadcast to all users in the room
io.to(roomKey).emit('message', messageData);
} catch (error) {
console.error('Socket message error:', error);
socket.emit('error', { message: 'Failed to send message' });
}
});

socket.on('disconnect', () => {
console.log(`Socket disconnected: ${socket.user.handle_number}`);
});
});

// --- Health check + SPA fallback ---

app.get('/healthz', (req, res) => res.json({ ok: true, timestamp: new Date().toISOString() }));

app.get('/', (req, res) => {
res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get(/^\/(?!api|healthz|socket\.io|uploads).*/, (req, res) => {
res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
console.error('Express error:', error);
if (error instanceof multer.MulterError) {
if (error.code === 'LIMIT_FILE_SIZE') {
return res.status(400).json({ error: 'File too large. Maximum 5MB allowed.' });
}
return res.status(400).json({ error: `Upload error: ${error.message}` });
}
res.status(500).json({ error: 'Internal server error' });
});

// --- Start Server ---

ensureMigrations().then(() => {
server.listen(PORT, () => {
console.log('Enhanced Hunter-Net server running on port', PORT);
console.log('═══════════════════════════════════════════');
console.log('DEMO ACCOUNTS:');
console.log('Admin: Witness1 / Witness1Pass2024!');
console.log('User: hunter001 / test123');
console.log('Mod: tracker007 / password123');
console.log('═══════════════════════════════════════════');
console.log('Ready for connections...');
});
}).catch(err => {
console.error('Migration error:', err);
process.exit(1);
});
