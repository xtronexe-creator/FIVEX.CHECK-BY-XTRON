# FiveX.check - Complete Deployment Guide

## Overview

FiveX.check is a professional FiveM and PC security scanning system consisting of:

1. **Admin Panel Website** - Manage scan codes, view results, monitor scans in real-time
2. **Desktop Scanner Application** - Windows-based application that scans PCs for suspicious files
3. **Backend API Server** - Node.js/Express server with database integration
4. **Real-time Monitoring** - Live scan progress and results display

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Admin Panel (Web)                         │
│  - Generate Scan Codes                                      │
│  - View Scan Results                                        │
│  - Monitor Live Scans                                       │
│  - Manage Users & Settings                                  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ HTTPS/API
                     │
┌────────────────────▼────────────────────────────────────────┐
│            Backend API Server (Node.js)                     │
│  - tRPC API Endpoints                                       │
│  - Database Integration (MySQL)                             │
│  - Authentication & Authorization                           │
│  - Real-time WebSocket Updates                              │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ REST API
                     │
┌────────────────────▼────────────────────────────────────────┐
│         Desktop Scanner Application (Python/Windows)        │
│  - Scan for suspicious FiveM files                          │
│  - Detect cheats, mods, malware                             │
│  - Submit results to server                                 │
│  - Real-time progress reporting                             │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Server Requirements

- **OS**: Windows Server 2019+ or Linux (Ubuntu 20.04+)
- **Node.js**: v18.0.0 or higher
- **MySQL**: v8.0 or higher (or compatible database)
- **RAM**: Minimum 2GB, recommended 4GB+
- **Storage**: Minimum 10GB for database and logs

### Client Requirements (Scanner)

- **OS**: Windows 10/11 (64-bit)
- **Python**: 3.8+ (included in standalone build)
- **RAM**: Minimum 512MB
- **Network**: Internet connection for API communication

## Installation & Setup

### Step 1: Database Setup

#### Option A: Local MySQL Setup

```bash
# Install MySQL Server
# Windows: Download from https://dev.mysql.com/downloads/mysql/
# Linux: sudo apt-get install mysql-server

# Create database
mysql -u root -p
> CREATE DATABASE fivex_check CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
> CREATE USER 'fivex_user'@'localhost' IDENTIFIED BY 'strong_password_here';
> GRANT ALL PRIVILEGES ON fivex_check.* TO 'fivex_user'@'localhost';
> FLUSH PRIVILEGES;
> EXIT;
```

#### Option B: Cloud Database (Recommended for Production)

- **AWS RDS**: Create MySQL instance
- **Google Cloud SQL**: Create MySQL instance
- **DigitalOcean Managed Database**: Create MySQL cluster
- **TiDB Cloud**: Create TiDB cluster (MySQL compatible)

### Step 2: Environment Configuration

Create `.env` file in project root:

```env
# Database
DATABASE_URL="mysql://fivex_user:strong_password_here@localhost:3306/fivex_check"

# Server
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# OAuth (Manus)
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_REDIRECT_URI=http://your-domain.com/auth/callback

# Admin User
OWNER_OPEN_ID=your_admin_user_id

# Session
SESSION_SECRET=generate_random_secret_here

# API Keys
API_KEY=your_api_key_here
```

### Step 3: Install Dependencies

```bash
# Navigate to project directory
cd fivex-check-web

# Install Node.js dependencies
pnpm install

# Or using npm
npm install
```

### Step 4: Database Migration

```bash
# Run Drizzle migrations
pnpm run db:push

# Or manually
drizzle-kit generate
drizzle-kit migrate
```

### Step 5: Build Project

```bash
# Build frontend and backend
pnpm run build

# Or using npm
npm run build
```

### Step 6: Start Server

```bash
# Development mode
pnpm run dev

# Production mode
pnpm run start

# Or using npm
npm start
```

The server will start on `http://localhost:3000`

## Desktop Scanner Deployment

### Option 1: Standalone Executable

Build a standalone Windows executable:

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
pyinstaller --onefile --windowed FiveXCheck_Scanner_Enhanced.py

# Output: dist/FiveXCheck_Scanner_Enhanced.exe
```

### Option 2: Python Distribution

Create a distribution package:

```bash
# Install required packages
pip install -r requirements.txt

# Create installer script
# Use NSIS or Inno Setup for professional installer
```

### Option 3: Direct Python Execution

Users can run directly with Python:

```bash
python FiveXCheck_Scanner_Enhanced.py
```

## Configuration

### Admin Panel Settings

1. **Login**: Access `http://your-domain.com` and login with admin credentials
2. **Generate Scan Codes**:
   - Navigate to "Scan Codes" section
   - Click "Generate New Code"
   - Set expiration time (1-30 days)
   - Share code with users

3. **View Results**:
   - Navigate to "Scan Results"
   - Click on any scan to view details
   - Export results as PDF/CSV

### Scanner Configuration

Edit `FiveXCheck_Scanner_Enhanced.py`:

```python
# API Configuration
API_BASE_URL = "http://your-domain.com/api/trpc"

# Scan Locations (modify as needed)
FIVEM_COMMON_LOCATIONS = [
    Path.home() / "AppData" / "Local" / "FiveM",
    # Add custom paths here
]

# Detection Patterns
FIVEM_SUSPICIOUS_PATTERNS = {
    "cheats": [r"cheat", r"hack", ...],
    # Add custom patterns here
}
```

## Deployment Options

### Option 1: Self-Hosted (Recommended for Testing)

**Local Machine**:
```bash
# Install all dependencies
# Configure .env
# Run: pnpm run dev
# Access: http://localhost:3000
```

**VPS/Dedicated Server**:
```bash
# Rent VPS from: DigitalOcean, Linode, AWS, etc.
# SSH into server
# Clone repository
# Follow installation steps above
# Use PM2 for process management

npm install -g pm2
pm2 start dist/index.js --name "fivex-check"
pm2 save
pm2 startup
```

### Option 2: Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY dist ./dist

EXPOSE 3000

CMD ["node", "dist/index.js"]
```

Build and run:

```bash
docker build -t fivex-check .
docker run -p 3000:3000 --env-file .env fivex-check
```

### Option 3: Cloud Platforms

**Vercel** (Frontend only):
```bash
npm install -g vercel
vercel deploy
```

**Heroku** (Full stack):
```bash
heroku create fivex-check
git push heroku main
```

**AWS EC2**:
- Launch EC2 instance
- Install Node.js and MySQL
- Clone repository
- Configure security groups
- Start application

## Security Considerations

### 1. SSL/TLS Certificate

```bash
# Using Let's Encrypt (free)
sudo apt-get install certbot
sudo certbot certonly --standalone -d your-domain.com

# Configure in server
HTTPS_KEY=/etc/letsencrypt/live/your-domain.com/privkey.pem
HTTPS_CERT=/etc/letsencrypt/live/your-domain.com/fullchain.pem
```

### 2. Database Security

```sql
-- Create strong password
-- Use SSL connections
-- Backup database regularly
-- Monitor access logs
```

### 3. API Security

```env
# Strong API keys
API_KEY=generate_random_64_char_string

# Rate limiting
RATE_LIMIT=100 requests per minute

# CORS configuration
CORS_ORIGIN=https://your-domain.com
```

### 4. User Authentication

- Implement OAuth2 with Manus
- Enable two-factor authentication
- Regular password rotation
- IP whitelisting for admin panel

## Monitoring & Maintenance

### Health Checks

```bash
# Check server status
curl http://localhost:3000/health

# Monitor logs
tail -f logs/app.log
```

### Database Maintenance

```bash
# Backup database
mysqldump -u fivex_user -p fivex_check > backup.sql

# Restore database
mysql -u fivex_user -p fivex_check < backup.sql

# Optimize tables
mysql -u fivex_user -p -e "OPTIMIZE TABLE scan_results, scan_files, scan_logs;"
```

### Performance Optimization

```bash
# Enable caching
# Configure CDN for static assets
# Use database indexes
# Monitor query performance
```

## Troubleshooting

### Scanner Cannot Connect to Server

**Problem**: Scanner shows "Connection failed"

**Solution**:
1. Check server is running: `curl http://localhost:3000`
2. Verify API URL in scanner configuration
3. Check firewall rules
4. Verify network connectivity

### Database Connection Error

**Problem**: "Database not available"

**Solution**:
1. Verify DATABASE_URL in .env
2. Check MySQL is running: `mysql -u root -p`
3. Test connection: `mysql -u fivex_user -p -h localhost fivex_check`
4. Check database credentials

### Scan Code Validation Fails

**Problem**: "Invalid or expired scan code"

**Solution**:
1. Generate new code from admin panel
2. Check code hasn't expired
3. Verify code is active (not used)
4. Check server time synchronization

### High Memory Usage

**Problem**: Server using too much RAM

**Solution**:
1. Increase server RAM
2. Optimize database queries
3. Implement pagination for results
4. Clear old logs: `DELETE FROM scan_logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY);`

## Performance Tuning

### Database Optimization

```sql
-- Add indexes for faster queries
CREATE INDEX idx_scan_code ON scan_codes(code);
CREATE INDEX idx_scan_result_status ON scan_results(scanStatus);
CREATE INDEX idx_scan_file_risk ON scan_files(riskLevel);

-- Archive old data
CREATE TABLE scan_results_archive LIKE scan_results;
INSERT INTO scan_results_archive SELECT * FROM scan_results WHERE scanStartTime < DATE_SUB(NOW(), INTERVAL 90 DAY);
DELETE FROM scan_results WHERE scanStartTime < DATE_SUB(NOW(), INTERVAL 90 DAY);
```

### Server Optimization

```bash
# Increase Node.js memory limit
NODE_OPTIONS="--max-old-space-size=4096" npm start

# Enable compression
# Configure reverse proxy (Nginx)
# Use load balancer for multiple instances
```

## Scaling for Production

### Horizontal Scaling

```bash
# Run multiple instances
pm2 start dist/index.js -i max

# Use load balancer (Nginx)
# Configure sticky sessions for WebSocket
```

### Vertical Scaling

```bash
# Increase server resources
# Upgrade CPU, RAM, storage
# Use SSD for database
```

### Database Scaling

```bash
# Read replicas for scaling reads
# Sharding for large datasets
# Connection pooling
```

## Backup & Recovery

### Automated Backups

```bash
# Create backup script
#!/bin/bash
BACKUP_DIR="/backups/fivex-check"
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u fivex_user -p fivex_check > $BACKUP_DIR/backup_$DATE.sql
gzip $BACKUP_DIR/backup_$DATE.sql

# Schedule with cron
0 2 * * * /path/to/backup.sh  # Daily at 2 AM
```

### Disaster Recovery

```bash
# Test restore procedure
mysql -u fivex_user -p fivex_check < backup.sql

# Verify data integrity
SELECT COUNT(*) FROM scan_results;
SELECT COUNT(*) FROM scan_files;
```

## Support & Documentation

- **Documentation**: See README.md
- **Issues**: Report bugs on GitHub
- **Community**: Join Discord server
- **Email Support**: support@fivex-check.com

## License

FiveX.check is proprietary software. All rights reserved.

## Version History

- **v1.0.0** (2024) - Initial release
- **v1.1.0** (2024) - Enhanced scanner with WebSocket support
- **v1.2.0** (2024) - Admin dashboard improvements

---

**Last Updated**: March 2024
**Maintained By**: FiveX.check Team
