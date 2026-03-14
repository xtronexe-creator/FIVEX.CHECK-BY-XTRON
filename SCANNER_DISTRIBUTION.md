# FiveX.check Desktop Scanner - Distribution Guide

## Overview

The FiveX.check Scanner is available in multiple formats for different user needs:

1. **Standalone Executable (.exe)** - Recommended for end users
2. **Python Script** - For developers and advanced users
3. **Batch File Launcher** - Quick installation helper
4. **PyInstaller Build** - Custom builds

---

## Method 1: Standalone Executable (Recommended)

### For End Users

**Requirements:**
- Windows 10/11 (64-bit)
- 100MB free disk space
- Internet connection

**Installation:**
1. Download `FiveXCheck.exe`
2. Double-click to run (no installation needed)
3. Enter your scan code
4. Start scanning

**Advantages:**
- No Python installation required
- Single file distribution
- Instant execution
- Professional appearance

### Building the Executable

**Prerequisites:**
```bash
pip install PyInstaller requests psutil
```

**Build Process:**
```bash
python build_scanner.py
```

This will create:
- `dist/FiveXCheck.exe` - Standalone executable
- `FiveXCheck_Scanner.bat` - Quick launcher
- `README_SCANNER.txt` - User guide

**Distribution:**
1. Copy `dist/FiveXCheck.exe` to users
2. Users run the file directly
3. No additional setup needed

---

## Method 2: Python Script

### For Developers

**Requirements:**
- Python 3.8+
- pip package manager

**Installation:**
```bash
pip install requests psutil
python FiveXCheck_Scanner.py
```

**Advantages:**
- Easy to modify and customize
- Cross-platform compatible
- Source code visible
- No compilation needed

---

## Method 3: Batch File Launcher

### For Windows Users

**File:** `FiveXCheck_Scanner.bat`

**Usage:**
1. Double-click `FiveXCheck_Scanner.bat`
2. Script checks for Python
3. Installs dependencies automatically
4. Launches scanner

**Advantages:**
- Automatic dependency installation
- Error handling
- User-friendly prompts
- No manual pip commands

---

## Distribution Checklist

### Pre-Distribution
- [ ] Test scanner on Windows 10
- [ ] Test scanner on Windows 11
- [ ] Verify code generation works
- [ ] Verify scan results submission
- [ ] Test with different user accounts
- [ ] Check file permissions
- [ ] Verify internet connectivity handling

### Packaging
- [ ] Include README_SCANNER.txt
- [ ] Include FiveXCheck.exe
- [ ] Include FiveXCheck_Scanner.bat (optional)
- [ ] Include FiveXCheck_Scanner.py (optional)
- [ ] Create ZIP archive
- [ ] Add version number to filename

### Distribution Methods

**Option A: Direct Download**
```
FiveXCheck_v1.0.0.zip
├── FiveXCheck.exe
├── README_SCANNER.txt
└── FiveXCheck_Scanner.bat
```

**Option B: GitHub Release**
1. Create GitHub repository
2. Upload FiveXCheck.exe to releases
3. Include release notes
4. Add download link to admin panel

**Option C: Cloud Storage**
1. Upload to Google Drive
2. Create shareable link
3. Share link with users
4. Track downloads

---

## User Installation Instructions

### Quick Start (Recommended)

1. **Download the Scanner**
   - Download `FiveXCheck.exe` from your admin

2. **Run the Scanner**
   - Double-click `FiveXCheck.exe`
   - No installation needed

3. **Enter Scan Code**
   - Get code from admin panel
   - Paste into scanner
   - Device name auto-fills

4. **Select Scan Locations**
   - AppData & Local (recommended)
   - Downloads (recommended)
   - FiveM Directory (if installed)
   - System Folders (optional)

5. **Start Scanning**
   - Click "Start Scan"
   - Monitor progress
   - Wait for completion

6. **View Results**
   - Results automatically submitted
   - Check admin panel for details

### Troubleshooting

**Scanner Won't Start**
- Ensure Windows Defender isn't blocking it
- Run as Administrator
- Check internet connection
- Verify code is correct

**Code Validation Fails**
- Copy code exactly (case-sensitive)
- Check code hasn't expired
- Ask admin for new code

**Scan Won't Complete**
- Check available disk space
- Disable antivirus temporarily
- Run with administrator privileges
- Check internet connection

---

## Technical Details

### Executable Specifications

**File:** FiveXCheck.exe
- **Size:** ~50-80 MB (includes Python runtime)
- **Architecture:** 64-bit
- **Runtime:** Embedded Python 3.11
- **Dependencies:** Bundled (requests, psutil, tkinter)
- **Signature:** Unsigned (can be self-signed)

### Security Considerations

**Code Signing:**
```bash
# Optional: Self-sign the executable
signtool sign /f certificate.pfx /p password /t http://timestamp.server FiveXCheck.exe
```

**Antivirus Compatibility:**
- Executable may trigger antivirus warnings initially
- This is normal for new applications
- Can be whitelisted by users
- Consider code signing to reduce warnings

**Data Privacy:**
- No data stored locally
- All results sent to secure server
- Logs encrypted in transit
- No personal information collected

---

## Advanced Distribution

### Custom Branding

**Modify build_scanner.py:**
```python
# Add custom icon
"--icon=path/to/icon.ico",

# Add custom version info
"--version-file=version_info.txt",

# Add splash screen
"--splash=path/to/splash.png",
```

### Silent Installation

**For IT Departments:**
```batch
REM Deploy scanner silently
FiveXCheck.exe --headless --code=XXXXX --scan-all
```

### Deployment Scripts

**GPO Deployment (Windows Domain):**
```batch
REM Deploy via Group Policy
copy FiveXCheck.exe \\server\share\software\
```

**SCCM Deployment:**
```
Application Name: FiveX.check Scanner
Installation Program: FiveXCheck.exe
Detection Method: File exists at C:\Program Files\FiveXCheck\FiveXCheck.exe
```

---

## Version Management

### Versioning Scheme

```
FiveXCheck_v1.0.0.exe
                ↓
         Major.Minor.Patch
```

### Update Process

1. Build new executable
2. Update version number
3. Create release notes
4. Upload to distribution channel
5. Notify users
6. Track adoption

### Rollback Plan

- Keep previous version available
- Document breaking changes
- Provide rollback instructions
- Test updates before release

---

## Monitoring & Support

### User Support

**Common Issues:**
1. Python not installed → Use .exe version
2. Code expired → Request new code
3. Scan fails → Check internet connection
4. Results not submitted → Verify API endpoint

**Support Channels:**
- Email support
- Discord/Slack channel
- Help documentation
- FAQ page

### Analytics

**Track:**
- Download counts
- Scan completion rates
- Error rates
- User feedback

**Dashboard:**
- Admin panel shows scan statistics
- Real-time monitoring available
- Historical data archived

---

## Compliance & Legal

### Terms of Service
- Users must accept terms before scanning
- Data usage policies
- Privacy statement
- Liability disclaimer

### GDPR Compliance
- Inform users about data collection
- Provide data deletion option
- Document consent
- Maintain audit logs

### Antivirus Compatibility
- Test with major antivirus software
- Provide whitelist instructions
- Document any known issues
- Update compatibility list

---

## FAQ

**Q: Do users need Python installed?**
A: No, use the .exe version. It includes Python runtime.

**Q: Can I modify the scanner?**
A: Yes, edit FiveXCheck_Scanner.py and rebuild with build_scanner.py

**Q: Is the scanner safe?**
A: Yes, it only scans local files and sends results to your server.

**Q: How large is the .exe file?**
A: Approximately 50-80 MB (includes Python runtime)

**Q: Can I distribute the .exe freely?**
A: Yes, it's self-contained and portable.

**Q: What if antivirus blocks it?**
A: Users can whitelist it or use the Python version.

**Q: How do I update users?**
A: Provide new .exe version, users download and run.

**Q: Can I customize the UI?**
A: Yes, edit FiveXCheck_Scanner.py and rebuild.

---

## Support & Documentation

For more information:
- See SETUP_GUIDE.md for backend setup
- See README_FIVEX.md for project overview
- Check admin panel for user management
- Review logs for troubleshooting

---

**FiveX.check v1.0.0 | Distribution Guide**
Last Updated: March 2026
