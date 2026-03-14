# FiveX.check - Professional FiveM & PC Security Scanner

![Version](https://img.shields.io/badge/version-1.1.0-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Web-brightgreen)

## 📋 Overview

**FiveX.check** is a professional-grade security scanning system designed specifically for FiveM gaming communities. It provides comprehensive detection of cheats, suspicious files, and malware on player PCs, with real-time monitoring and detailed reporting capabilities.

### Key Features

✅ **Advanced FiveM Detection** - Identifies FiveM cheats, mods, and suspicious modifications
✅ **Comprehensive File Scanning** - Scans AppData, Downloads, FiveM directories, and custom paths
✅ **Real-time Monitoring** - Live progress tracking and result submission
✅ **Professional Admin Panel** - Manage scan codes, view results, monitor active scans
✅ **Detailed Threat Analysis** - Categorized threats (Suspicious, Warning, Moderate, Safe)
✅ **Windows Metadata** - Extracts file properties, creation dates, modification times
✅ **Secure Code System** - Time-limited, single-use scan codes for device authentication
✅ **Database Integration** - MySQL/TiDB backend for persistent storage
✅ **User Authentication** - OAuth2 integration with admin role management
✅ **Scalable Architecture** - Designed for production deployment

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Admin Panel (Web)                         │
│  React + TypeScript + TailwindCSS                           │
│  - Generate & manage scan codes                             │
│  - View detailed scan results                               │
│  - Monitor live scans in real-time                          │
│  - Export reports                                           │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTPS/tRPC
                     │
┌────────────────────▼────────────────────────────────────────┐
│            Backend API Server (Node.js)                     │
│  Express + tRPC + Drizzle ORM                               │
│  - Scan code generation & validation                        │
│  - Result storage & retrieval                               │
│  - Real-time log streaming                                  │
│  - User authentication                                      │
└────────────────────┬────────────────────────────────────────┘
                     │ REST API
                     │
┌────────────────────▼────────────────────────────────────────┐
│         Desktop Scanner (Python/Windows)                    │
│  Tkinter GUI + Advanced File Analysis                       │
│  - Scan for suspicious files                                │
│  - Detect cheats & malware                                  │
│  - Submit results to server                                 │
│  - Real-time progress reporting                             │
└─────────────────────────────────────────────────────────────┘
```

## 📦 Project Structure

```
fivex-check-web/
├── client/                          # React frontend
│   ├── src/
│   │   ├── pages/                  # Page components
│   │   │   ├── Home.tsx            # Landing page & admin dashboard
│   │   │   ├── ScanCodes.tsx       # Code generation & management
│   │   │   ├── ScanResults.tsx     # Results viewer
│   │   │   └── LiveLogs.tsx        # Real-time log monitoring
│   │   ├── components/             # Reusable components
│   │   └── styles/                 # TailwindCSS styles
│   └── index.html
├── server/                          # Node.js backend
│   ├── _core/
│   │   ├── trpc.ts                 # tRPC setup
│   │   ├── context.ts              # Request context
│   │   └── oauth.ts                # Authentication
│   ├── routers.ts                  # API endpoints
│   ├── db.ts                       # Database functions
│   └── index.ts                    # Server entry point
├── drizzle/                         # Database schema
│   ├── schema.ts                   # Table definitions
│   └── migrations/                 # Database migrations
├── FiveXCheck_Scanner_Enhanced.py  # Enhanced desktop scanner
├── build_scanner_exe.py            # Build script for Windows .exe
├── DEPLOYMENT_GUIDE.md             # Complete deployment instructions
└── package.json
```

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18.0.0+
- **MySQL** 8.0+ or compatible database
- **Python** 3.8+ (for scanner)
- **Windows 10/11** (for running scanner)

### Installation

1. **Clone and Setup**
```bash
cd fivex-check-web
pnpm install
```

2. **Configure Environment**
```bash
cp .env.example .env
# Edit .env with your database credentials
```

3. **Setup Database**
```bash
pnpm run db:push
```

4. **Start Development Server**
```bash
pnpm run dev
# Access at http://localhost:3000
```

5. **Build for Production**
```bash
pnpm run build
pnpm run start
```

### 🚀 Free Hosting (Railway, Neon, etc.)

See **FREE_HOSTING_GUIDE_BANGLA.txt** for step-by-step guide in Bengali.  
Quick: GitHub → Neon (DB) → Railway (deploy) → set `DATABASE_URL`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` in env.

## 📱 Desktop Scanner Usage

### For End Users

1. **Download Scanner**
   - Get `FiveXCheck_Scanner.exe` from your admin
   - No installation required - just run the executable

2. **Enter Scan Code**
   - Paste the 12-character code provided by admin
   - Device name auto-fills (can be customized)

3. **Configure Scan**
   - Select which directories to scan
   - Check "Deep Analysis" for thorough scan (slower)

4. **Start Scan**
   - Click "Start Scan"
   - Monitor progress in real-time
   - Results automatically submitted to server

### For Administrators

1. **Generate Scan Codes**
   - Login to admin panel
   - Navigate to "Scan Codes"
   - Click "Generate New Code"
   - Set expiration (1-30 days)
   - Share code with players

2. **Monitor Scans**
   - View "Live Logs" for real-time progress
   - Check "Scan Results" for completed scans
   - Export detailed reports

3. **Analyze Results**
   - View threat categorization
   - Check file paths and metadata
   - Identify FiveM-related files
   - Take action on suspicious files

## 🔍 Threat Detection

### Risk Levels

| Level | Color | Description | Action |
|-------|-------|-------------|--------|
| **Suspicious** | 🔴 Red | Likely malware or cheat | Immediate action required |
| **Warning** | 🟠 Orange | Suspicious executable | Review and investigate |
| **Moderate** | 🟡 Yellow | Potentially risky file | Monitor and log |
| **Safe** | 🟢 Green | Legitimate file | No action needed |

### Detection Patterns

The scanner detects:

- **Cheats**: Files with keywords like "cheat", "hack", "mod", "trainer", "exploit"
- **Malware**: Keywords like "malware", "trojan", "virus", "ransomware", "spyware"
- **Tools**: "keylogger", "backdoor", "hook", "proxy", "interceptor"
- **Scripts**: Lua, JavaScript, Python files in suspicious locations
- **Executables**: .exe, .dll, .scr, .bat, .cmd, .ps1, .vbs files

### File Analysis

For each detected file, the scanner extracts:

- **File Metadata**: Size, creation date, modification date, permissions
- **Hash**: MD5 hash for file identification
- **Windows Details**: Digital signature, version info
- **Content Analysis**: Suspicious strings in scripts
- **Location**: Full file path and directory analysis
- **FiveM Relation**: Whether file is FiveM-related

## 🔐 Security Features

### Authentication
- OAuth2 integration with Manus
- Role-based access control (Admin/User)
- Session management with secure cookies
- Protected API endpoints

### Scan Code System
- Unique 12-character alphanumeric codes
- Configurable expiration (1-30 days)
- Single-use validation
- Device tracking

### Data Protection
- Encrypted database connections
- Secure API communication (HTTPS)
- Input validation and sanitization
- SQL injection prevention via ORM
- CORS protection

### Privacy
- Minimal data collection
- Automatic log rotation
- Data retention policies
- User consent management

## 📊 Database Schema

### Tables

**users** - Admin and user accounts
- id, openId, name, email, role, createdAt, updatedAt

**scan_codes** - Generated scan codes
- id, code, status, createdAt, expiresAt, usedAt, usedByDevice

**scan_results** - Scan sessions
- id, scanCodeId, deviceName, osVersion, scanStartTime, scanEndTime
- totalFilesScanned, suspiciousCount, warningCount, moderateCount
- overallRiskLevel, scanStatus

**scan_files** - Detected files
- id, scanResultId, filePath, fileName, fileType, fileSize
- riskLevel, detectionReason, fileHash, isFiveMMod, isSystemFile
- windowsDetails

**scan_logs** - Real-time logs
- id, scanResultId, logLevel, message, timestamp, filePath, progress

## 🛠️ API Endpoints

### Authentication
- `POST /api/trpc/auth.me` - Get current user
- `POST /api/trpc/auth.logout` - Logout

### Scan Codes
- `POST /api/trpc/scanCode.generate` - Generate new code (Admin)
- `POST /api/trpc/scanCode.list` - List all codes (Admin)
- `POST /api/trpc/scanCode.validate` - Validate code (Public)

### Scan Results
- `POST /api/trpc/scanResult.create` - Create scan result
- `POST /api/trpc/scanResult.list` - List all results (Admin)
- `POST /api/trpc/scanResult.getWithFiles` - Get result with files (Admin)
- `POST /api/trpc/scanResult.updateStatus` - Update scan status
- `POST /api/trpc/scanResult.addFiles` - Add detected files

### Scan Logs
- `POST /api/trpc/scanLog.add` - Add log entry
- `POST /api/trpc/scanLog.getAll` - Get all logs (Admin)
- `POST /api/trpc/scanLog.getRecent` - Get recent logs (Admin)

## 📈 Performance

### Optimization Tips

1. **Database**
   - Use indexes on frequently queried columns
   - Archive old scan data
   - Regular maintenance and optimization

2. **Server**
   - Enable gzip compression
   - Use CDN for static assets
   - Implement caching strategies
   - Load balancing for multiple instances

3. **Scanner**
   - Exclude system directories when possible
   - Use deep analysis only when needed
   - Optimize file pattern matching

## 🐛 Troubleshooting

### Scanner Connection Issues
```
Problem: "Connection failed"
Solution: 
1. Verify server is running
2. Check API URL configuration
3. Verify firewall rules
4. Test network connectivity
```

### Database Errors
```
Problem: "Database not available"
Solution:
1. Check DATABASE_URL in .env
2. Verify MySQL is running
3. Check credentials
4. Test connection: mysql -u user -p
```

### Scan Code Validation
```
Problem: "Invalid or expired scan code"
Solution:
1. Generate new code from admin panel
2. Check code hasn't expired
3. Verify code is active (not used)
4. Check server time synchronization
```

## 📚 Documentation

- **[DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)** - Complete deployment instructions
- **[SETUP_GUIDE.md](./SETUP_GUIDE.md)** - Initial setup guide
- **[SCANNER_QUICKSTART.md](./SCANNER_QUICKSTART.md)** - Scanner usage guide

## 🔄 Development

### Running in Development Mode

```bash
# Start dev server with hot reload
pnpm run dev

# Run tests
pnpm run test

# Type checking
pnpm run check

# Format code
pnpm run format
```

### Building Scanner Executable

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
python build_scanner_exe.py

# Output: dist/FiveXCheck_Scanner.exe
```

## 🚢 Deployment

### Local Development
```bash
pnpm run dev
```

### Production Build
```bash
pnpm run build
pnpm run start
```

### Docker
```bash
docker build -t fivex-check .
docker run -p 3000:3000 --env-file .env fivex-check
```

### Cloud Platforms
- **Vercel**: `vercel deploy`
- **Heroku**: `git push heroku main`
- **AWS**: EC2 instance with Node.js
- **DigitalOcean**: App Platform or Droplet

## 📋 Environment Variables

```env
# Database
DATABASE_URL=mysql://user:password@host:3306/database

# Server
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# OAuth
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_REDIRECT_URI=https://your-domain.com/auth/callback

# Admin
OWNER_OPEN_ID=admin_user_id

# Security
SESSION_SECRET=random_secret_string
API_KEY=random_api_key
```

## 📝 License

FiveX.check is proprietary software. All rights reserved.

Unauthorized copying, distribution, or modification is prohibited.

## 🤝 Support

For issues, feature requests, or support:
- Email: support@fivex-check.com
- Discord: [Join our server](https://discord.gg/fivex-check)
- GitHub Issues: [Report a bug](https://github.com/fivex-check/issues)

## 🎯 Roadmap

- [ ] WebSocket real-time updates
- [ ] Advanced threat intelligence
- [ ] Machine learning detection
- [ ] Mobile app for iOS/Android
- [ ] API for third-party integrations
- [ ] Custom detection rules
- [ ] Automated remediation
- [ ] Community threat database

## 👥 Contributors

- **FiveX.check Team** - Core development
- **Community** - Feedback and suggestions

## 🔔 Version History

### v1.1.0 (March 2024)
- Enhanced scanner with advanced file analysis
- Improved UI with tabs and better organization
- Better FiveM detection patterns
- Windows metadata extraction
- File hash calculation

### v1.0.0 (February 2024)
- Initial release
- Basic scanning functionality
- Admin panel
- Database integration

---

**Last Updated**: March 2024
**Maintained By**: FiveX.check Team
**Status**: Active Development
