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
await fs.mkdir(path.join(__dirname, 'public'), { recursive: true });
await fs.mkdir(uploadDir, { recursive: true });
console.log(`Upload directory ready: ${uploadDir}`);
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
files: 1
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
console.log(`Field Cred: ${user.handle_number} ${credChange > 0 ? '+' :
''}${credChange} (${voteType}vote on ${targetType}) -> ${user.field_cred}`);
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
CREATE TABLE IF NOT EXISTS private_chats (
id SERIAL PRIMARY KEY,
user1_id INT REFERENCES users(id) ON DELETE CASCADE,
user2_id INT REFERENCES users(id) ON DELETE CASCADE,
created_at TIMESTAMPTZ DEFAULT now(),
UNIQUE(user1_id, user2_id)
);
CREATE TABLE IF NOT EXISTS private_messages (
id SERIAL PRIMARY KEY,
chat_id INT REFERENCES private_chats(id) ON DELETE CASCADE,
sender_id INT REFERENCES users(id) ON DELETE CASCADE,
body TEXT NOT NULL,
image_path TEXT,
created_at TIMESTAMPTZ DEFAULT now()
);
`
},
{
name: '002_seed_boards_rooms',
sql: `
INSERT INTO chat_rooms (key, title) VALUES
('global', 'Global Chat'),
('tactical', 'Tactical Discussion'),
('social', 'Social Hour')
ON CONFLICT (key) DO NOTHING;
INSERT INTO boards (name, description, key) VALUES
('General Discussion', 'Open discussion for all hunters', 'general'),
('Creature Sightings', 'Report and discuss supernatural encounters', 'sightings'),
('Intelligence Sharing', 'Share tactical information and research', 'intel'),
('Hunter Support', 'Request and offer assistance to fellow hunters', 'support')
ON CONFLICT (key) DO NOTHING;
`
},
{

name: '003_reset_users_and_create_witness1',
sql: `
-- Remove ALL users first
DELETE FROM users;
-- Reset user number sequence to start from 1
SELECT setval('user_number_seq', 1, false);
-- Create fresh witness1 admin account with proper password hash
-- Password: witness1pass (hashed with bcrypt rounds 12)
INSERT INTO users (handle, number, handle_number, password_hash, creed,
member, active, is_admin, field_cred)
VALUES ('witness', 1, 'witness1',
'$2b$12$8K9wjJpKhXjzqX7Z5YoRF.B8mKP6GJH4WXqN9vL3rS2tE5dC7aI1u', 'vigil', 'admin',
'active', true, 999);
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
console.log('Witness1 account ready - Handle: witness1, Password: witness1pass');
} catch (error) {
console.error('Migration error:', error);
throw error;
}
}
// --- API Routes ---
// Upload image - Fixed for proper error handling

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

const updateQuery = `UPDATE ${tableName} SET upvotes = $1, downvotes = $2 WHERE
id = $3`;
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
// Register - Fixed to ensure proper handle generation
app.post('/api/register', async (req, res) => {
try {
const { handle, email, password, creed } = req.body;
if (!handle || !password) {
return res.status(400).json({ error: 'Handle and password required' });
}
if (password.length < 8) {
return res.status(400).json({ error: 'Password must be at least 8 characters' });
}
// Clean handle input
const cleanHandle = handle.toLowerCase().trim();
if (cleanHandle.length < 1) {
return res.status(400).json({ error: 'Handle cannot be empty' });
}
// Generate unique handle number
const { rows: [{ nextval }] } = await query('SELECT nextval(\'user_number_seq\')');
const handle_number = `${cleanHandle}${nextval}`;
// Hash password with same settings as witness1
const password_hash = await bcrypt.hash(password, 12);
console.log(`Registering user: ${handle_number} with hash: ${password_hash.substring(0, 20)}...`);
// Create user
const { rows: [user] } = await query(`
INSERT INTO users (handle, number, handle_number, password_hash, email, creed,
member, active)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, handle_number, field_cred, is_admin, creed

`, [cleanHandle, nextval, handle_number, password_hash, email || null, creed ||
null, 'member', 'active']);
console.log(`User registered successfully: ${handle_number}`);
// Sign JWT
const token = signToken({
id: user.id,
handle_number: user.handle_number,
is_admin: user.is_admin
});
res.cookie('token', token, {
httpOnly: true,
secure: process.env.NODE_ENV === 'production',
maxAge: 7 * 24 * 60 * 60 * 1000,
sameSite: 'lax'
});
res.json({
user: {
handle_number: user.handle_number,
field_cred: user.field_cred,
is_admin: user.is_admin,
creed: user.creed
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
// Login - Simplified and fixed
app.post('/api/login', async (req, res) => {
try {
const { handle_number, password } = req.body;
if (!handle_number || !password) {
return res.status(400).json({ error: 'Handle and password required' });
}

const cleanHandleNumber = handle_number.toLowerCase().trim();
console.log(`Login attempt for: ${cleanHandleNumber}`);
// Get user by handle_number
const { rows: users } = await query(
'SELECT id, handle_number, password_hash, field_cred, is_admin, active, creed FROM users WHERE LOWER(handle_number) = $1',
[cleanHandleNumber]
);
if (users.length === 0) {
console.log(`No user found for ${cleanHandleNumber}`);
return res.status(401).json({ error: 'Invalid credentials' });
}
const user = users[0];
// Check if account is deleted
if (user.active === 'deleted') {
console.log(`Deleted account login attempt: ${user.handle_number}`);
return res.status(401).json({ error: 'Account has been deleted' });
}
console.log(`Found user: ${user.handle_number}, checking password...`);
console.log(`Stored hash: ${user.password_hash.substring(0, 20)}...`);
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
is_admin: user.is_admin
});
res.cookie('token', token, {
httpOnly: true,
secure: process.env.NODE_ENV === 'production',
maxAge: 7 * 24 * 60 * 60 * 1000,
sameSite: 'lax'
});
res.json({
user: {
handle_number: user.handle_number,
field_cred: user.field_cred,
is_admin: user.is_admin,
creed: user.creed
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
'SELECT handle_number, field_cred, is_admin, creed FROM users WHERE id = $1 AND active != $2',
[req.user.id, 'deleted']
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
// Account management routes
app.patch('/api/account/password', authRequired, async (req, res) => {
try {
const { current_password, new_password } = req.body;
// Get current password hash
const { rows: [user] } = await query('SELECT password_hash FROM users WHERE id =
$1', [req.user.id]);
if (!await bcrypt.compare(current_password, user.password_hash)) {
return res.status(400).json({ error: 'Current password is incorrect' });
}
if (new_password.length < 8) {
return res.status(400).json({ error: 'New password must be at least 8 characters' });
}
const password_hash = await bcrypt.hash(new_password, 12);
await query('UPDATE users SET password_hash = $1 WHERE id = $2', [password_hash,
req.user.id]);
res.json({ message: 'Password updated successfully' });
} catch (error) {
console.error('Password change error:', error);
res.status(500).json({ error: 'Password change failed' });
}
});
app.patch('/api/account/affiliation', authRequired, async (req, res) => {
try {
const { creed } = req.body;

await query('UPDATE users SET creed = $1 WHERE id = $2', [creed || null, req.user.id]);
res.json({ creed: creed || null });
} catch (error) {
console.error('Affiliation change error:', error);
res.status(500).json({ error: 'Affiliation change failed' });
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
const { rows: [user] } = await query('SELECT password_hash FROM users WHERE id =
$1', [req.user.id]);
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
WHERE b.key = $1 AND u.active != 'deleted'
ORDER BY t.sticky DESC, t.updated_at DESC
`, [key]);
res.json({ threads });
} catch (error) {
console.error('Get threads error:', error);
res.status(500).json({ error: 'Failed to get threads' });
}
});
// Create thread - Fixed image handling
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
INSERT INTO threads (board_id, author_id, title, body_md, signal_type, tags,
image_path)
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
console.log(`Thread created: "${title}" by ${req.user.handle_number} (+${credChange}
cred)`);
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
// Create post in thread - Fixed image handling
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

// Moderate thread (admin only)
app.patch('/api/threads/:id', authRequired, adminRequired, async (req, res) => {
try {
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

// Delete thread
app.delete('/api/threads/:threadId', authRequired, async (req, res) => {
try {
const threadId = parseInt(req.params.threadId);
// Get thread to check ownership
const { rows: [thread] } = await query(`
SELECT t.*, u.handle_number as author
FROM threads t
JOIN users u ON t.author_id = u.id
WHERE t.id = $1
`, [threadId]);
if (!thread) {
return res.status(404).json({ error: 'Thread not found' });
}
// Check if user can delete (author or admin)
if (thread.author !== req.user.handle_number && !req.user.is_admin) {
return res.status(403).json({ error: 'Permission denied' });
}
// Delete thread (posts will cascade)
await query('DELETE FROM threads WHERE id = $1', [threadId]);
res.json({ message: 'Thread deleted successfully' });
} catch (error) {
console.error('Delete thread error:', error);
res.status(500).json({ error: 'Thread deletion failed' });
}
});
// Delete post
app.delete('/api/posts/:postId', authRequired, async (req, res) => {
try {
const postId = parseInt(req.params.postId);
// Get post to check ownership
const { rows: [post] } = await query(`
SELECT p.*, u.handle_number as author
FROM posts p
JOIN users u ON p.author_id = u.id
WHERE p.id = $1

`, [postId]);
if (!post) {
return res.status(404).json({ error: 'Post not found' });
}
// Check if user can delete (author or admin)
if (post.author !== req.user.handle_number && !req.user.is_admin) {
return res.status(403).json({ error: 'Permission denied' });
}
// Delete post
await query('DELETE FROM posts WHERE id = $1', [postId]);
res.json({ message: 'Post deleted successfully' });
} catch (error) {
console.error('Delete post error:', error);
res.status(500).json({ error: 'Post deletion failed' });
}
});
// Get chat rooms
app.get('/api/chat/rooms', authRequired, async (req, res) => {
try {
const { rows: rooms } = await query('SELECT key, title FROM chat_rooms ORDER BY
title');
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
// Delete chat message
app.delete('/api/chat-messages/:messageId', authRequired, async (req, res) => {
try {
const messageId = parseInt(req.params.messageId);
// Get message to check ownership
const { rows: [message] } = await query(`
SELECT m.*, u.handle_number as author
FROM messages m
JOIN users u ON m.author_id = u.id
WHERE m.id = $1
`, [messageId]);
if (!message) {
return res.status(404).json({ error: 'Message not found' });
}
// Check if user can delete (author or admin)
if (message.author !== req.user.handle_number && !req.user.is_admin) {
return res.status(403).json({ error: 'Permission denied' });
}
// Delete message
await query('DELETE FROM messages WHERE id = $1', [messageId]);
res.json({ message: 'Message deleted successfully' });
} catch (error) {
console.error('Delete chat message error:', error);
res.status(500).json({ error: 'Message deletion failed' });
}
});

// Get members
app.get('/api/members', authRequired, async (req, res) => {
try {
const { rows: members } = await query(`
SELECT
u.id, u.handle_number, u.field_cred, u.is_admin, u.creed, u.created_at,
(SELECT COUNT(*) FROM threads WHERE author_id = u.id) as thread_count,
(SELECT COUNT(*) FROM posts WHERE author_id = u.id) as post_count
FROM users u
WHERE u.active = 'active'
ORDER BY u.is_admin DESC, u.created_at ASC
`);
res.json({ members });
} catch (error) {
console.error('Get members error:', error);
res.status(500).json({ error: 'Failed to get members' });
}
});
// Get member profile
app.get('/api/members/:handleNumber', authRequired, async (req, res) => {
try {
const { handleNumber } = req.params;
const { rows: [member] } = await query(`
SELECT
u.id, u.handle_number, u.field_cred, u.is_admin, u.creed, u.created_at,
(SELECT COUNT(*) FROM threads WHERE author_id = u.id) as thread_count,
(SELECT COUNT(*) FROM posts WHERE author_id = u.id) as post_count
FROM users u
WHERE u.handle_number = $1 AND u.active = 'active'
`, [handleNumber]);
if (!member) {
return res.status(404).json({ error: 'Member not found' });
}
res.json({ member });
} catch (error) {
console.error('Get member error:', error);
res.status(500).json({ error: 'Failed to get member' });
}

});
// Private chat routes
app.get('/api/private-chats', authRequired, async (req, res) => {
try {
const { rows: chats } = await query(`
SELECT DISTINCT
pc.id,
CASE
WHEN u1.handle_number = $1 THEN u2.handle_number
ELSE u1.handle_number
END as other_user,
0 as unread_count
FROM private_chats pc
JOIN users u1 ON pc.user1_id = u1.id
JOIN users u2 ON pc.user2_id = u2.id
WHERE (u1.handle_number = $1 OR u2.handle_number = $1)
AND u1.active != 'deleted' AND u2.active != 'deleted'
ORDER BY pc.id DESC
`, [req.user.handle_number]);
res.json({ chats });
} catch (error) {
console.error('Get private chats error:', error);
res.status(500).json({ error: 'Failed to get private chats' });
}
});
app.post('/api/private-chats', authRequired, async (req, res) => {
try {
const { recipient, message } = req.body;
if (!recipient || !message) {
return res.status(400).json({ error: 'Recipient and message required' });
}
// Get recipient user
const { rows: [recipientUser] } = await query(
'SELECT id FROM users WHERE handle_number = $1 AND active = \'active\'',
[recipient]
);
if (!recipientUser) {
return res.status(404).json({ error: 'Recipient not found' });

}
// Check if chat already exists
let { rows: [chat] } = await query(`
SELECT id FROM private_chats
WHERE (user1_id = $1 AND user2_id = $2) OR (user1_id = $2 AND user2_id = $1)
`, [req.user.id, recipientUser.id]);
if (!chat) {
// Create new chat
const { rows: [newChat] } = await query(`
INSERT INTO private_chats (user1_id, user2_id)
VALUES ($1, $2)
RETURNING id
`, [req.user.id, recipientUser.id]);
chat = newChat;
}
// Add initial message
await query(`
INSERT INTO private_messages (chat_id, sender_id, body)
VALUES ($1, $2, $3)
`, [chat.id, req.user.id, message]);
res.json({ chat });
} catch (error) {
console.error('Create private chat error:', error);
res.status(500).json({ error: 'Failed to create private chat' });
}
});
app.get('/api/private-chats/:chatId/messages', authRequired, async (req, res) => {
try {
const chatId = parseInt(req.params.chatId);
// Verify user has access to this chat
const { rows: [chat] } = await query(`
SELECT pc.id FROM private_chats pc
JOIN users u1 ON pc.user1_id = u1.id
JOIN users u2 ON pc.user2_id = u2.id
WHERE pc.id = $1 AND (u1.handle_number = $2 OR u2.handle_number = $2)
`, [chatId, req.user.handle_number]);
if (!chat) {

return res.status(404).json({ error: 'Chat not found or access denied' });
}
const { rows: messages } = await query(`
SELECT pm.id, pm.body, pm.image_path, pm.created_at,
u.handle_number as sender
FROM private_messages pm
JOIN users u ON pm.sender_id = u.id
WHERE pm.chat_id = $1 AND u.active != 'deleted'
ORDER BY pm.created_at ASC
`, [chatId]);
res.json({ messages });
} catch (error) {
console.error('Get private messages error:', error);
res.status(500).json({ error: 'Failed to get messages' });
}
});
app.post('/api/private-chats/:chatId/messages', authRequired, async (req, res) => {
try {
const chatId = parseInt(req.params.chatId);
const { body } = req.body;
if (!body) {
return res.status(400).json({ error: 'Message body required' });
}
// Verify user has access to this chat
const { rows: [chat] } = await query(`
SELECT pc.id FROM private_chats pc
JOIN users u1 ON pc.user1_id = u1.id
JOIN users u2 ON pc.user2_id = u2.id
WHERE pc.id = $1 AND (u1.handle_number = $2 OR u2.handle_number = $2)
`, [chatId, req.user.handle_number]);
if (!chat) {
return res.status(404).json({ error: 'Chat not found or access denied' });
}
const { rows: [message] } = await query(`
INSERT INTO private_messages (chat_id, sender_id, body)
VALUES ($1, $2, $3)
RETURNING id, body, created_at

`, [chatId, req.user.id, body]);
res.json({
message: {
...message,
sender: req.user.handle_number
}
});
} catch (error) {
console.error('Send private message error:', error);
res.status(500).json({ error: 'Failed to send message' });
}
});
app.delete('/api/private-messages/:messageId', authRequired, async (req, res) => {
try {
const messageId = parseInt(req.params.messageId);
// Get message to check ownership
const { rows: [message] } = await query(`
SELECT pm.*, u.handle_number as sender
FROM private_messages pm
JOIN users u ON pm.sender_id = u.id
WHERE pm.id = $1
`, [messageId]);
if (!message) {
return res.status(404).json({ error: 'Message not found' });
}
// Check if user can delete (only sender can delete their own messages)
if (message.sender !== req.user.handle_number) {
return res.status(403).json({ error: 'Permission denied' });
}
// Delete message
await query('DELETE FROM private_messages WHERE id = $1', [messageId]);
res.json({ message: 'Message deleted successfully' });
} catch (error) {
console.error('Delete private message error:', error);
res.status(500).json({ error: 'Message deletion failed' });
}
});

// --- ADMIN ROUTES ---
app.post('/api/admin/server-message', authRequired, adminRequired, async (req, res) => {
try {
const { message, type } = req.body;
// In a real implementation, this would send notifications to all users
console.log(`[${type.toUpperCase()}] Server message from ${req.user.handle_number}:
${message}`);
res.json({ message: 'Server message sent successfully' });
} catch (error) {
console.error('Server message error:', error);
res.status(500).json({ error: 'Server message failed' });
}
});
app.get('/api/admin/users', authRequired, adminRequired, async (req, res) => {
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
app.patch('/api/admin/users/:userId/field-cred', authRequired, adminRequired, async (req, res)
=> {
try {
const userId = parseInt(req.params.userId);
const { field_cred, reason } = req.body;
const { rows: [user] } = await query(`
UPDATE users

SET field_cred = $1
WHERE id = $2
RETURNING handle_number, field_cred
`, [field_cred, userId]);
if (!user) {
return res.status(404).json({ error: 'User not found' });
}
console.log(`Admin Field Cred Update: ${user.handle_number} set to ${field_cred}
(${reason || 'Admin adjustment'})`);
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
app.delete('/api/admin/users/:userId', authRequired, adminRequired, async (req, res) => {
try {
const userId = parseInt(req.params.userId);
const { reason } = req.body;
if (userId === req.user.id) {
return res.status(400).json({ error: 'Cannot delete your own admin account' });
}
const { rows: [user] } = await query(`
UPDATE users
SET deleted_at = now(), deletion_reason = $1, active = 'deleted'
WHERE id = $2
RETURNING handle_number
`, [reason || 'Admin deletion', userId]);
if (!user) {
return res.status(404).json({ error: 'User not found' });
}

console.log(`Admin deletion: ${user.handle_number} deleted by
${req.user.handle_number} (${reason})`);
res.json({
success: true,
message: `User ${user.handle_number} deleted by admin`
});
} catch (error) {
console.error('Admin delete user error:', error);
res.status(500).json({ error: 'Failed to delete user' });
}
});
app.post('/api/admin/users/:userId/strike', authRequired, adminRequired, async (req, res) => {
try {
const userId = parseInt(req.params.userId);
const { reason } = req.body;
const { rows: [user] } = await query('SELECT handle_number FROM users WHERE id =
$1', [userId]);
if (!user) {
return res.status(404).json({ error: 'User not found' });
}
// In a real implementation, you'd track strikes in a separate table
console.log(`Admin ${req.user.handle_number} issued strike to ${user.handle_number}.
Reason: ${reason}`);
res.json({ message: 'Strike issued successfully' });
} catch (error) {
console.error('Strike issuance error:', error);
res.status(500).json({ error: 'Strike issuance failed' });
}
});
app.get('/api/admin/private-chats', authRequired, adminRequired, async (req, res) => {
try {
const { rows: chats } = await query(`
SELECT
pc.id,
u1.handle_number as user1,
u2.handle_number as user2,

(SELECT COUNT(*) FROM private_messages WHERE chat_id = pc.id) as
message_count,
COALESCE(
(SELECT MAX(created_at) FROM private_messages WHERE chat_id = pc.id),
pc.created_at
) as last_message_at
FROM private_chats pc
JOIN users u1 ON pc.user1_id = u1.id
JOIN users u2 ON pc.user2_id = u2.id
WHERE u1.active != 'deleted' AND u2.active != 'deleted'
ORDER BY last_message_at DESC
`);
res.json({ chats });
} catch (error) {
console.error('Admin get private chats error:', error);
res.status(500).json({ error: 'Failed to get private chats' });
}
});
app.get('/api/admin/private-chats/:chatId/messages', authRequired, adminRequired, async (req,
res) => {
try {
const chatId = parseInt(req.params.chatId);
const { rows: messages } = await query(`
SELECT pm.id, pm.body, pm.image_path, pm.created_at,
u.handle_number as sender
FROM private_messages pm
JOIN users u ON pm.sender_id = u.id
WHERE pm.chat_id = $1 AND u.active != 'deleted'
ORDER BY pm.created_at ASC
`, [chatId]);
res.json({ messages });
} catch (error) {
console.error('Admin get private chat messages error:', error);
res.status(500).json({ error: 'Failed to get messages' });
}
});
app.post('/api/admin/private-chats/:chatId/join', authRequired, adminRequired, async (req, res)
=> {
try {

const chatId = parseInt(req.params.chatId);
// Verify chat exists
const { rows: [chat] } = await query('SELECT id FROM private_chats WHERE id = $1',
[chatId]);
if (!chat) {
return res.status(404).json({ error: 'Chat not found' });
}
// Add notification message
await query(`
INSERT INTO private_messages (chat_id, sender_id, body)
VALUES ($1, $2, $3)
`, [chatId, req.user.id, `Admin ${req.user.handle_number} has joined this conversation for
monitoring purposes.`]);
res.json({ message: 'Joined chat successfully' });
} catch (error) {
console.error('Admin chat join error:', error);
res.status(500).json({ error: 'Failed to join chat' });
}
});
// --- Socket.IO Chat with better message persistence ---
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
const { rows: roomRows } = await query(`SELECT id FROM chat_rooms WHERE
key=$1`, [roomKey]);
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
await query('UPDATE users SET field_cred = field_cred + 1 WHERE id = $1',
[socket.user.id]);
const messageData = {
id: message.id,
author: socket.user.handle_number,
body: body.trim(),
image_path,
created_at: message.created_at,
upvotes: 0,
downvotes: 0
};
console.log(`Chat message: [${roomKey}] ${socket.user.handle_number}:
${body.substring(0, 50)}...`);
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
// Create required directories at startup
async function ensureDirectories() {
try {
const publicDir = path.join(__dirname, 'public');
const uploadsDir = path.join(__dirname, 'public', 'uploads');
await fs.mkdir(publicDir, { recursive: true });
await fs.mkdir(uploadsDir, { recursive: true });
console.log('Required directories created successfully');
console.log(`Public directory: ${publicDir}`);
console.log(`Uploads directory: ${uploadsDir}`);
} catch (error) {
console.error('Directory creation failed:', error);
// Try synchronous creation as fallback
try {
const fsSync = require('fs');
const publicDir = path.join(__dirname, 'public');
const uploadsDir = path.join(__dirname, 'public', 'uploads');
fsSync.mkdirSync(publicDir, { recursive: true });
fsSync.mkdirSync(uploadsDir, { recursive: true });
console.log('Directories created successfully (sync fallback)');
} catch (syncError) {
console.error('Both async and sync directory creation failed:', syncError);
}
}
}
// Generate a fresh password hash for witness1 at startup
async function generateWitness1Hash() {
const password = 'witness1pass';
const hash = await bcrypt.hash(password, 12);
console.log('Fresh witness1 password hash:', hash);
return hash;
}
// --- Start ---

Promise.all([ensureMigrations(), ensureDirectories()]).then(() => {
server.listen(PORT, () => {
console.log('Enhanced Hunter-Net server running on port', PORT);
console.log('═══════════════════════════════════════════');
console.log('WITNESS1 ADMIN ACCOUNT:');
console.log('Handle: witness1');
console.log('Password: witness1pass');
console.log('═══════════════════════════════════════════');
console.log('Ready for connections...');
});
}).catch(err => {
console.error('Startup error:', err);
process.exit(1);
});
