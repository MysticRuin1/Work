# Hunter-Net (Reckoning-style) – Full-Stack App

A functional, lore-flavored Hunter-Net clone with:
- Decoy gateway
- Registration/login (non-recycled numbered handles)
- Boards, threads, posts
- Socket.IO chat rooms (global + creed)
- Minimal admin (sticky/lock)
- PostgreSQL database
- Ready for Render deployment

## Local Setup
1) `cp .env.example .env` and fill `DATABASE_URL` + `JWT_SECRET`.
2) `npm install`
3) `npm start`
4) Visit `http://localhost:10000`

## Render Deployment
- Create a **Web Service** from this repo.
- Add a **PostgreSQL** database on Render and copy its `External Connection` string to `DATABASE_URL` env var.
- Add `JWT_SECRET` env var.
- Set Start Command: `npm start`
- Enable WebSockets in service settings (default supported).

## API (quick)
- POST /api/register { handle, email?, password, creed? }
- POST /api/login { handle_number, password }
- GET  /api/me
- GET  /api/boards
- GET  /api/boards/:key/threads
- POST /api/boards/:key/threads { title, body_md, signal?, tags? }
- GET  /api/threads/:id
- POST /api/threads/:id/posts { body_md }
- PATCH /api/threads/:id { sticky?, locked? }  // mod/admin

## Notes
- User numbers are never recycled (monotonic counter).
- Initial boards/rooms seeded per lore.
- Frontend is in `/public` and uses fetch() + Socket.IO to talk to the backend.

## Deploy to Render
1. Push this repo to GitHub.
2. In Render, create a **Blueprint** and point it to the repo (using `render.yaml`).
3. Render will provision a free **PostgreSQL** (`hunternet-db`) and wire `DATABASE_URL`.
4. `JWT_SECRET` will be auto-generated. You can rotate it any time.
5. The service will start and expose `/healthz` for health checks.
6. Visit the URL; the decoy gateway (index) should load instead of `Cannot GET /`.

## Features
- **Decoy Site**: Looks like "Anonymous Liberty" privacy advocacy portal
- **Hunter-Net Interface**: Revealed after authentication
- **Forum System**: Boards organized by Creed, threads with signal types
- **Real-time Chat**: Multiple secure channels
- **User System**: Handle + auto-assigned numbers (never recycled)
- **Security**: JWT auth, password hashing, SQL injection protection
- **Mobile Responsive**: Works on all devices

## Hunter: The Reckoning Lore Integration
- Boards named after Creeds (Firelight, Judgment Day, etc.)
- Signal types: Sighting, Intel, Request Aid, After Action, Caution
- Hunter-Net theming with appropriate glyphs and terminology
- Field Credibility system ready for expansion
- Secure "underground network" aesthetic