# FiveX.check - Complete Installation Guide

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
3. [Step-by-Step Setup](#step-by-step-setup)
4. [Configuration](#configuration)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

## System Requirements

### Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows Server 2016 / Ubuntu 18.04 | Windows Server 2022 / Ubuntu 22.04 |
| CPU | 2 cores | 4 cores |
| RAM | 2 GB | 4 GB |
| Storage | 10 GB | 50 GB |
| Node.js | 16.0.0 | 18.0.0+ |
| MySQL | 5.7 | 8.0+ |
| Network | 100 Mbps | 1 Gbps |

### Client Requirements (Scanner)

| Component | Requirement |
|-----------|------------|
| OS | Windows 10/11 (64-bit) |
| RAM | 512 MB minimum |
| Storage | 100 MB for application |
| .NET Framework | 4.5+ (for some features) |
| Network | Internet connection |

## Installation Methods

### Method 1: Docker (Recommended)

**Easiest and most reliable for production**

#### Prerequisites
- Docker Desktop or Docker Engine
- Docker Compose

#### Steps

```bash
# 1. Clone repository
git clone https://github.com/fivex-check/fivex-check-web.git
cd fivex-check-web

# 2. Create .env file
cp .env.example .env
# Edit .env with your configuration

# 3. Create docker-compose.override.yml for local development
cat > docker-compose.override.yml << EOF
version: '3.8'
services:
  app:
    environment:
      NODE_ENV: development
    command: npm run dev
    volumes:
      - .:/app
      - /app/node_modules
EOF

# 4. Start services
docker-compose up -d

# 5. Run migrations
docker-compose exec app pnpm run db:push

# 6. Access application
# Web: http://localhost:3000
# Database: localhost:3306
```

### Method 2: Manual Installation (Linux/Ubuntu)

**For full control and customization**

#### Prerequisites
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install MySQL
sudo apt install -y mysql-server

# Install Git
sudo apt install -y git

# Install Nginx (optional, for reverse proxy)
sudo apt install -y nginx
```

#### Installation Steps

```bash
# 1. Create application directory
sudo mkdir -p /opt/fivex-check
sudo chown $USER:$USER /opt/fivex-check
cd /opt/fivex-check

# 2. Clone repository
git clone https://github.com/fivex-check/fivex-check-web.git .

# 3. Install dependencies
npm install -g pnpm
pnpm install

# 4. Setup database
sudo mysql -u root << EOF
CREATE DATABASE fivex_check CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'fivex_user'@'localhost' IDENTIFIED BY 'strong_password_here';
GRANT ALL PRIVILEGES ON fivex_check.* TO 'fivex_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# 5. Configure environment
cp .env.example .env
nano .env
# Edit with your settings

# 6. Run migrations
pnpm run db:push

# 7. Build application
pnpm run build

# 8. Start with PM2
npm install -g pm2
pm2 start dist/index.js --name "fivex-check"
pm2 save
pm2 startup
```

### Method 3: Manual Installation (Windows)

**For Windows Server deployment**

#### Prerequisites

1. **Install Node.js**
   - Download from https://nodejs.org/ (LTS version)
   - Run installer and follow prompts
   - Verify: `node --version`

2. **Install MySQL**
   - Download from https://dev.mysql.com/downloads/mysql/
   - Run installer
   - Configure MySQL Server
   - Create root password

3. **Install Git**
   - Download from https://git-scm.com/
   - Run installer

#### Installation Steps

```batch
REM 1. Clone repository
git clone https://github.com/fivex-check/fivex-check-web.git
cd fivex-check-web

REM 2. Install dependencies
npm install -g pnpm
pnpm install

REM 3. Setup database
mysql -u root -p << EOF
CREATE DATABASE fivex_check CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'fivex_user'@'localhost' IDENTIFIED BY 'strong_password_here';
GRANT ALL PRIVILEGES ON fivex_check.* TO 'fivex_user'@'localhost';
FLUSH PRIVILEGES;
EOF

REM 4. Configure environment
copy .env.example .env
REM Edit .env with Notepad

REM 5. Run migrations
pnpm run db:push

REM 6. Build application
pnpm run build

REM 7. Start with PM2
npm install -g pm2
pm2 start dist/index.js --name "fivex-check"
pm2 save
pm2 startup
```

### Method 4: Cloud Deployment

#### AWS EC2

```bash
# 1. Launch EC2 instance (Ubuntu 22.04)
# 2. Connect via SSH

# 3. Install dependencies
sudo apt update && sudo apt upgrade -y
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs mysql-server git nginx

# 4. Clone and setup (same as Method 2)
```

#### Heroku

```bash
# 1. Install Heroku CLI
npm install -g heroku

# 2. Login
heroku login

# 3. Create app
heroku create fivex-check

# 4. Add MySQL add-on
heroku addons:create cleardb:ignite

# 5. Set environment variables
heroku config:set NODE_ENV=production
heroku config:set OAUTH_CLIENT_ID=your_id
# ... set other variables

# 6. Deploy
git push heroku main

# 7. Run migrations
heroku run pnpm run db:push
```

#### DigitalOcean App Platform

```bash
# 1. Create app.yaml
cat > app.yaml << EOF
name: fivex-check
services:
- name: web
  github:
    repo: fivex-check/fivex-check-web
    branch: main
  build_command: pnpm install && pnpm run build
  run_command: pnpm start
  http_port: 3000
databases:
- name: mysql
  engine: MYSQL
  version: "8"
EOF

# 2. Deploy
doctl apps create --spec app.yaml
```

## Step-by-Step Setup

### 1. Database Setup

#### Create Database
```sql
CREATE DATABASE fivex_check CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

#### Create User
```sql
CREATE USER 'fivex_user'@'localhost' IDENTIFIED BY 'your_strong_password';
GRANT ALL PRIVILEGES ON fivex_check.* TO 'fivex_user'@'localhost';
FLUSH PRIVILEGES;
```

#### Verify Connection
```bash
mysql -u fivex_user -p -h localhost fivex_check
> SHOW TABLES;
> EXIT;
```

### 2. Environment Configuration

Create `.env` file:

```env
# Database
DATABASE_URL="mysql://fivex_user:your_password@localhost:3306/fivex_check"

# Server
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# OAuth (Get from Manus)
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_REDIRECT_URI=https://your-domain.com/auth/callback

# Admin
OWNER_OPEN_ID=your_admin_id

# Security
SESSION_SECRET=$(openssl rand -base64 32)
API_KEY=$(openssl rand -base64 32)
```

### 3. Install Dependencies

```bash
# Using pnpm (recommended)
pnpm install

# Or using npm
npm install

# Or using yarn
yarn install
```

### 4. Database Migrations

```bash
# Generate migrations
drizzle-kit generate

# Run migrations
drizzle-kit migrate

# Or using npm script
pnpm run db:push
```

### 5. Build Application

```bash
# Development build
pnpm run build

# Production build with optimization
NODE_ENV=production pnpm run build
```

### 6. Start Application

```bash
# Development mode
pnpm run dev

# Production mode
pnpm run start

# With PM2
pm2 start dist/index.js --name "fivex-check"
```

## Configuration

### OAuth Setup (Manus)

1. **Register Application**
   - Visit https://manus.im/developers
   - Create new application
   - Set redirect URI: `https://your-domain.com/auth/callback`

2. **Get Credentials**
   - Copy Client ID
   - Copy Client Secret
   - Add to `.env`

### SSL/TLS Certificate

```bash
# Using Let's Encrypt
sudo apt install certbot python3-certbot-nginx
sudo certbot certonly --standalone -d your-domain.com

# Configure in Nginx
# See nginx.conf example
```

### Reverse Proxy (Nginx)

Create `/etc/nginx/sites-available/fivex-check`:

```nginx
upstream fivex_backend {
    server localhost:3000;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://fivex_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/fivex-check /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Verification

### Check Application Status

```bash
# Check if running
curl http://localhost:3000

# Check health endpoint
curl http://localhost:3000/health

# View logs
tail -f logs/app.log

# Check database connection
mysql -u fivex_user -p -h localhost fivex_check -e "SELECT 1;"
```

### Test Scanner Connection

```bash
# From scanner machine
python FiveXCheck_Scanner_Enhanced.py

# Should connect to server successfully
```

### Verify Admin Access

1. Open http://your-domain.com
2. Click "Login to Admin Panel"
3. Authenticate with OAuth
4. Should see admin dashboard

## Troubleshooting

### Port Already in Use

```bash
# Find process using port 3000
lsof -i :3000

# Kill process
kill -9 <PID>

# Or use different port
PORT=3001 npm start
```

### Database Connection Failed

```bash
# Check MySQL is running
sudo systemctl status mysql

# Test connection
mysql -u fivex_user -p -h localhost

# Check .env DATABASE_URL
cat .env | grep DATABASE_URL

# Verify credentials
mysql -u fivex_user -p fivex_check -e "SELECT 1;"
```

### Build Errors

```bash
# Clear cache
rm -rf node_modules pnpm-lock.yaml
pnpm install

# Check Node version
node --version  # Should be 18.0.0+

# Check TypeScript errors
pnpm run check
```

### Memory Issues

```bash
# Increase Node.js memory
NODE_OPTIONS="--max-old-space-size=4096" npm start

# Check available memory
free -h

# Monitor memory usage
watch -n 1 'free -h'
```

### Permission Denied

```bash
# Fix ownership
sudo chown -R $USER:$USER /opt/fivex-check

# Fix permissions
chmod -R 755 /opt/fivex-check
chmod -R 644 /opt/fivex-check/.env
```

## Next Steps

1. **Generate Scan Codes**
   - Login to admin panel
   - Navigate to "Scan Codes"
   - Generate codes for distribution

2. **Download Scanner**
   - Build Windows executable: `python build_scanner_exe.py`
   - Distribute `dist/FiveXCheck_Scanner.exe`

3. **Monitor Scans**
   - Check "Live Logs" for real-time progress
   - Review "Scan Results" for completed scans

4. **Backup Data**
   - Setup automated backups
   - Test restore procedure

## Support

- **Documentation**: See README_COMPLETE.md
- **Issues**: Report on GitHub
- **Email**: support@fivex-check.com
- **Discord**: Join our community

---

**Last Updated**: March 2024
**Version**: 1.1.0
