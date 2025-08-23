# Enhanced Hunter-Net Deployment Guide

## 🚀 Quick Deployment to Render

### 1. Push to GitHub
```bash
git add .
git commit -m "Enhanced Hunter-Net with voting, images, and admin"
git push origin main
```

### 2. Deploy on Render
1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click "New" → "Blueprint"
3. Connect your GitHub repo
4. Select the repo with your Hunter-Net code
5. Render will automatically use `render.yaml` to provision:
   - PostgreSQL database (`hunternet-db`)
   - Web service (`hunternet-app`)
   - All environment variables

### 3. Important Post-Deployment Steps

#### 🔐 CRITICAL: Change Witness1 Password
**Default password:** `AdminHunter2024!`

**You MUST change this immediately after deployment!**

Options to change it:
1. **Via psql (recommended):**
   ```bash
   # Generate new hash (use Node.js or online bcrypt tool)
   const bcrypt = require('bcrypt');
   const newHash = await bcrypt.hash('YourNewSecurePassword', 12);
   
   # Connect to your Render database and run:
   UPDATE users 
   SET password_hash = 'YOUR_NEW_BCRYPT_HASH_HERE'
   WHERE handle_number = 'Witness1';
   ```

2. **Via database dashboard:**
   - Go to your Render PostgreSQL dashboard
   - Use the Query tab to run the UPDATE command above

#### 📁 Create Uploads Directory
Render needs the uploads directory to exist:
```bash
# This should already be handled by the .gitkeep file
# but verify the /public/uploads/ directory exists
```

## 🛠 Local Development Setup

### Prerequisites
- Node.js 18+
- PostgreSQL database

### Setup Steps
```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit .env with your local database details
# DATABASE_URL=postgresql://username:password@localhost:5432/hunternet
# JWT_SECRET=your-secret-key-here
# PORT=10000

# Create local database
createdb hunternet

# Start the server (migrations run automatically)
npm start

# For development with auto-restart:
npm run dev  # (requires nodemon: npm install -g nodemon)
```

## 🔧 Environment Variables

### Required Variables
- `DATABASE_URL`: PostgreSQL connection string
- `JWT_SECRET`: Secret for JWT token signing (auto-generated on Render)
- `PORT`: Server port (default: 10000)

### Render Auto-Configuration
The `render.yaml` handles:
- Database provisioning and URL injection
- JWT secret generation
- Environment setup
- Build and start commands

## 📊 System Features

### 🗳️ Voting System
- Upvote/downvote on threads, posts, and chat messages
- Automatic Field Credibility adjustments
- Vote counts displayed in real-time

### 🖼️ Image Upload System
- 5MB file size limit
- Images stored in `/public/uploads/`
- Supported in threads, posts, and chat
- Click images to view full-size

### ⭐ Field Credibility System
**Automatic Awards:**
- Thread creation: +2 (+1 bonus with image)
- Post creation: +1 (+1 bonus with image)
- Chat participation: +1 per message
- Received upvotes: +3 (threads), +2 (posts), +1 (messages)
- Received downvotes: -2 (threads), -1 (posts), -1 (messages)

**Special Bonuses:**
- After Action reports: +4 base
- Intel/Sighting threads: +3 base

### 👑 Admin System (Witness1 Only)
- View all users and statistics
- Manually adjust Field Credibility
- Delete user accounts with reason tracking
- Enhanced thread moderation (sticky/lock)

### 🗑️ Account Management
- Users can delete their own accounts
- Soft deletion preserves data integrity
- Password confirmation required

## 🔍 Monitoring & Logs

### Server Logs to Watch
```bash
# Field Credibility changes
Field Cred: username +/-amount (reason) -> total

# Admin actions
Admin Field Cred Update: username set to X (reason)
Admin deletion: username deleted by Witness1 (reason)

# System health
Enhanced Hunter-Net server running on port X
Default Witness1 password: AdminHunter2024! - CHANGE THIS IMMEDIATELY!
```

### Database Monitoring
Monitor these key tables:
- `users` - User accounts and field cred
- `votes` - All voting activity
- `messages/posts/threads` - Content with vote counts
- `schema_migrations` - Migration status

## 🚨 Security Checklist

### Immediate Actions
- [ ] Change Witness1 password from default
- [ ] Verify uploads directory permissions
- [ ] Check database connection security
- [ ] Test admin access restriction

### Ongoing Security
- [ ] Monitor user uploads for inappropriate content
- [ ] Watch for vote manipulation patterns
- [ ] Regular database backups
- [ ] Monitor server resource usage

## 🛡️ Backup Strategy

### Database Backup
```bash
# Manual backup (adjust connection details)
pg_dump $DATABASE_URL > hunternet_backup_$(date +%Y%m%d).sql

# Restore from backup
psql $DATABASE_URL < hunternet_backup_YYYYMMDD.sql
```

### File Uploads Backup
- Regularly backup `/public/uploads/` directory
- Consider cloud storage for uploaded images
- Monitor disk usage on Render

## 🔄 Updates & Migrations

The system includes automatic migrations:
- New migrations added to `ensureMigrations()` function
- Automatically run on server start
- Track completed migrations in `schema_migrations` table

### Adding New Migrations
```javascript
// Add to the steps array in ensureMigrations()
{
    name: '004_your_migration_name',
    sql: `
        -- Your SQL commands here
        ALTER TABLE users ADD COLUMN new_field TEXT;
    `
}
```

## 📱 Mobile Responsiveness

The interface adapts to mobile devices:
- Responsive voting controls
- Collapsible chat interface
- Touch-friendly image viewing
- Mobile-optimized forms

## 🎯 Performance Tips

### Database Optimization
- Indexes on frequently queried columns
- Vote count caching in content tables
- Efficient pagination for large datasets

### File Upload Optimization
- Image compression before upload
- CDN integration for uploaded files
- Regular cleanup of orphaned uploads

### Caching Strategy
- JWT token caching
- Vote count aggregation
- Message history caching

## 📈 Scaling Considerations

### Horizontal Scaling
- Stateless server design
- Database connection pooling
- Session management via JWT

### Vertical Scaling
- Monitor memory usage for image uploads
- Database performance tuning
- Consider Redis for session caching

---

## 🆘 Troubleshooting

### Common Issues

**"Upload failed" errors:**
- Check uploads directory exists and is writable
- Verify file size under 5MB limit
- Check disk space on server

**Voting not working:**
- Verify vote tables exist in database
- Check user authentication
- Confirm target content exists

**Admin access denied:**
- Must be logged in as exactly "Witness1"
- Check is_admin flag in database
- Verify JWT token includes admin status

**Migration errors:**
- Check database connection
- Verify table permissions
- Review migration SQL syntax

### Support Resources
- Check server logs for specific error messages
- Test API endpoints directly with curl/Postman
- Verify database schema matches expected structure
- Monitor network connectivity and timeouts
