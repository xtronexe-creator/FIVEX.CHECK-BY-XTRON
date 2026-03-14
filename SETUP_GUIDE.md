# FiveX.check - Complete Setup & Deployment Guide

## Overview

FiveX.check is a professional FiveM and PC suspicious file detection system. It consists of three main components:

1. **Admin Panel Website** - React frontend for code generation and scan result viewing
2. **Backend API** - Node.js/Express with tRPC for secure communication
3. **Desktop Scanner** - Python application for PC scanning

---

## Part 1: Backend Setup

### Prerequisites

- Node.js 18+ and pnpm
- MySQL/MariaDB database
- Python 3.8+ (for desktop app)

### Installation Steps

1. **Install Dependencies**
   ```bash
   cd /home/ubuntu/fivex-check-web
   pnpm install
   ```

2. **Configure Database**
   - Create a MySQL database
   - Update `DATABASE_URL` in environment variables
   - Run migrations:
   ```bash
   pnpm db:push
   ```

3. **Start Development Server**
   ```bash
   pnpm dev
   ```

   The server will run on `http://localhost:3000`

4. **Build for Production**
   ```bash
   pnpm build
   pnpm start
   ```

---

## Part 2: Admin Panel Usage

### Accessing the Panel

1. Navigate to `http://localhost:3000` in your browser
2. Click "Login to Admin Panel"
3. Authenticate using Manus OAuth
4. You'll be promoted to admin if you're the owner

### Generating Scan Codes

1. Go to **Scan Codes** section
2. Set expiration time (1-720 hours)
3. Click **Generate Code**
4. Copy the code and share with users
5. Track code status: Active, Used, or Expired

### Viewing Scan Results

1. Go to **Scan Results** section
2. Select a device from the list
3. View detailed file information:
   - File path and name
   - Risk level (Suspicious, Warning, Moderate, Safe)
   - Detection reason
   - File metadata

### File Risk Levels

- **Suspicious** (Critical): Malware indicators, dangerous keywords
- **Warning** (High): Executable files, system modifications
- **Moderate** (Medium): Large executables, unusual locations
- **Safe** (Low): Normal system files

---

## Part 3: Desktop Scanner Application

### System Requirements

- Windows 10/11 (64-bit recommended)
- Python 3.8+ with tkinter
- Internet connection
- 100MB free disk space

### Installation

1. **Install Python Dependencies**
   ```bash
   pip install requests psutil
   ```

2. **Run the Scanner**
   ```bash
   python FiveXCheck_Scanner.py
   ```

### Using the Scanner

1. **Enter Scan Code**
   - Paste the code generated from admin panel
   - Device name auto-fills with computer name

2. **Select Scan Locations**
   - AppData & Local: Scans user profile
   - Downloads: Scans Downloads folder
   - FiveM Directory: Scans FiveM installation
   - System Folders: Scans Windows system directories

3. **Start Scan**
   - Click "Start Scan" button
   - Monitor progress in real-time
   - Results display with file details

4. **View Results**
   - Files are categorized by risk level
   - Details include path, size, and detection reason
   - Results automatically submitted to server

### Scanner Features

- **Real-time Scanning**: Progress bar shows scan status
- **Automatic Detection**: Identifies suspicious files
- **FiveM Analysis**: Special detection for FiveM mods
- **System Integration**: Scans AppData, Downloads, and FiveM folders
- **Secure Submission**: Results encrypted and sent to server

---

## Part 4: API Endpoints

### Authentication

```
POST /api/trpc/scanCode.validate
Body: { code: string, deviceName: string }
Response: { valid: boolean, codeId?: number }
```

### Code Generation (Admin Only)

```
POST /api/trpc/scanCode.generate
Body: { expirationHours: number }
Response: { code: string, success: boolean }
```

### Scan Results

```
POST /api/trpc/scanResult.create
Body: { scanCodeId: number, deviceName: string, osVersion?: string }
Response: { id: number, ... }

POST /api/trpc/scanResult.addFiles
Body: { scanResultId: number, files: Array<FileData> }
Response: { success: boolean }

GET /api/trpc/scanResult.list
Response: Array<ScanResult>

GET /api/trpc/scanResult.getWithFiles
Body: { scanResultId: number }
Response: { ...ScanResult, files: Array<ScanFile> }
```

---

## Part 5: Database Schema

### Tables

**scan_codes**
- id: Primary key
- code: Unique scan code
- status: active | used | expired
- createdAt: Timestamp
- expiresAt: Expiration timestamp
- usedAt: When code was used
- usedByDevice: Device name
- createdByUserId: Admin user ID

**scan_results**
- id: Primary key
- scanCodeId: Foreign key to scan_codes
- deviceName: Computer name
- osVersion: Operating system
- scanStartTime: Scan start timestamp
- scanEndTime: Scan end timestamp
- totalFilesScanned: Number of files
- suspiciousCount: Suspicious files
- warningCount: Warning files
- moderateCount: Moderate files
- safeCount: Safe files
- overallRiskLevel: critical | high | medium | low | safe
- scanStatus: in_progress | completed | failed

**scan_files**
- id: Primary key
- scanResultId: Foreign key to scan_results
- filePath: Full file path
- fileName: File name
- fileType: File extension
- fileSize: File size in bytes
- riskLevel: suspicious | warning | moderate | safe
- detectionReason: Why file was flagged
- fileHash: MD5/SHA hash
- isFiveMMod: Boolean
- isSystemFile: Boolean
- windowsDetails: JSON metadata

---

## Part 6: Deployment

### Docker Deployment

Create `Dockerfile`:
```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY . .

RUN pnpm install
RUN pnpm build

EXPOSE 3000
CMD ["pnpm", "start"]
```

Build and run:
```bash
docker build -t fivex-check .
docker run -p 3000:3000 -e DATABASE_URL=<your_db_url> fivex-check
```

### Environment Variables

```
DATABASE_URL=mysql://user:password@host:3306/fivex_check
JWT_SECRET=your_secret_key
VITE_APP_ID=your_manus_app_id
OAUTH_SERVER_URL=https://api.manus.im
VITE_OAUTH_PORTAL_URL=https://manus.im
```

### Production Checklist

- [ ] Database backed up
- [ ] Environment variables configured
- [ ] SSL certificate installed
- [ ] Rate limiting enabled
- [ ] Logging configured
- [ ] Monitoring set up
- [ ] Admin credentials secured
- [ ] Firewall rules configured

---

## Part 7: Troubleshooting

### Scanner Won't Connect

1. Check internet connection
2. Verify API URL in scanner code
3. Ensure backend is running
4. Check firewall settings

### Code Validation Fails

1. Verify code is correct (case-sensitive)
2. Check code hasn't expired
3. Ensure code hasn't been used
4. Regenerate new code if needed

### Database Connection Error

1. Verify MySQL is running
2. Check DATABASE_URL format
3. Verify credentials
4. Check firewall for port 3306

### Scanner Crashes

1. Update Python to latest version
2. Reinstall dependencies: `pip install --upgrade requests psutil`
3. Run with admin privileges
4. Check system disk space

---

## Part 8: Security Considerations

### Best Practices

1. **Code Generation**: Codes expire after set time
2. **API Authentication**: Use JWT tokens
3. **Database**: Encrypt sensitive data
4. **Transmission**: Use HTTPS/TLS
5. **Validation**: Server-side validation for all inputs
6. **Logging**: Audit trail of all scans
7. **Access Control**: Admin-only operations

### Admin Panel Security

- Only admins can generate codes
- Only admins can view results
- Session tokens expire after inactivity
- All API calls require authentication

### Scanner Security

- Codes validated before scan
- Results encrypted in transit
- No sensitive data stored locally
- Automatic cleanup of temporary files

---

## Part 9: Maintenance

### Regular Tasks

- Monitor database size
- Review scan logs weekly
- Update threat detection patterns
- Backup database daily
- Check server logs for errors

### Performance Optimization

- Index frequently queried columns
- Archive old scan results
- Optimize database queries
- Cache common results
- Monitor API response times

---

## Support & Documentation

For issues or questions:
1. Check logs in `.manus-logs/` directory
2. Review error messages in browser console
3. Verify all prerequisites are installed
4. Test API endpoints with curl/Postman

---

## Version Information

- **FiveX.check**: 1.0.0
- **Node.js**: 18+
- **Python**: 3.8+
- **React**: 19
- **tRPC**: 11
- **Drizzle ORM**: 0.44+

---

Last Updated: March 2026
