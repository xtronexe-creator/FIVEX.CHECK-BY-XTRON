# FiveX.check Scanner - Quick Start Guide

## 🚀 Installation (2 Minutes)

### Option 1: Standalone Executable (Easiest)
1. Download `FiveXCheck.exe`
2. Double-click the file
3. Done! Scanner starts immediately

### Option 2: Batch File (Auto-Install)
1. Download `FiveXCheck_Scanner.bat`
2. Double-click the file
3. Dependencies install automatically
4. Scanner starts

### Option 3: Python Script
1. Install Python 3.8+ from python.org
2. Download `FiveXCheck_Scanner.py`
3. Run: `python FiveXCheck_Scanner.py`

---

## 📋 First Time Setup

### Step 1: Get Your Scan Code
- Ask your administrator for a scan code
- Codes look like: `ABC123XYZ789`
- Each code is unique and expires after a set time

### Step 2: Enter Code in Scanner
1. Open FiveXCheck scanner
2. Paste your code in the "Scan Code" field
3. Device name auto-fills (you can change it)
4. Click "Validate Code"

### Step 3: Select Scan Locations
Choose which folders to scan:
- ✅ **AppData & Local** - User profile data (recommended)
- ✅ **Downloads** - Download folder (recommended)
- ✅ **FiveM Directory** - FiveM game folder (if installed)
- ❌ **System Folders** - Windows system (optional, requires admin)

---

## 🔍 Running a Scan

### Quick Scan (5-10 minutes)
1. Check only "AppData & Local" and "Downloads"
2. Click "Start Scan"
3. Wait for completion
4. Results auto-submit

### Full Scan (15-30 minutes)
1. Check all locations
2. Click "Start Scan"
3. Monitor progress bar
4. Results auto-submit

### Custom Folder Scan
1. Click "Browse Folder"
2. Select custom folder
3. Click "Start Scan"
4. Results auto-submit

---

## 📊 Understanding Results

### Risk Levels

| Level | Icon | Meaning | Action |
|-------|------|---------|--------|
| **Suspicious** | 🔴 | Likely malware | Delete/Quarantine |
| **Warning** | 🟠 | Suspicious activity | Review carefully |
| **Moderate** | 🟡 | Unusual file | Monitor |
| **Safe** | 🟢 | Normal file | No action |

### File Information Shown
- **File Path**: Location on your computer
- **File Name**: Name of the file
- **File Type**: File extension (.exe, .dll, etc.)
- **File Size**: Size in bytes
- **Detection Reason**: Why it was flagged
- **Risk Level**: Threat classification

---

## ⚙️ Scanner Interface

### Main Window

```
┌─────────────────────────────────────────┐
│  FiveX.check Scanner                    │
├─────────────────────────────────────────┤
│                                         │
│  Scan Code: [________________]          │
│  Device Name: [________________]        │
│                                         │
│  Scan Locations:                        │
│  ☑ AppData & Local                      │
│  ☑ Downloads                            │
│  ☑ FiveM Directory                      │
│  ☐ System Folders                       │
│                                         │
│  [Start Scan]  [Browse Folder]          │
│                                         │
│  Progress: [████████░░░░░░░░] 50%       │
│  Status: Scanning: file.exe             │
│                                         │
│  Logs:                                  │
│  [INFO] Scan started                    │
│  [WARN] Detected: malware.exe           │
│  [INFO] Scan complete                   │
│                                         │
└─────────────────────────────────────────┘
```

### Progress Bar
- Shows percentage of scan completion
- Updates in real-time
- Indicates active file being scanned

### Log Display
- Shows all scan events
- Color-coded by severity
- Scrolls automatically to latest entry

---

## 🛡️ Common Scenarios

### Scenario 1: First Time Scan
1. Open scanner
2. Enter code from admin
3. Select "AppData & Local" and "Downloads"
4. Click "Start Scan"
5. Wait 5-10 minutes
6. Results appear in admin panel

### Scenario 2: Suspicious File Detected
1. Scan completes
2. File marked as "Suspicious"
3. Admin reviews in Live Logs
4. Admin takes action (delete/quarantine)
5. You receive notification

### Scenario 3: Code Expired
1. Click "Start Scan"
2. See "Code validation failed"
3. Ask admin for new code
4. Enter new code
5. Try again

### Scenario 4: Scan Interrupted
1. Close scanner window
2. Reopen scanner
3. Enter same code
4. Click "Start Scan" again
5. Scan restarts from beginning

---

## 🔧 Troubleshooting

### Scanner Won't Start
**Problem:** Double-clicking .exe does nothing
**Solution:**
- Run as Administrator (right-click → Run as administrator)
- Check Windows Defender isn't blocking it
- Disable antivirus temporarily
- Try the .bat file instead

### Code Validation Fails
**Problem:** "Code validation failed" error
**Solution:**
- Copy code exactly (case-sensitive)
- Check code hasn't expired
- Verify internet connection
- Ask admin for new code

### Scan Won't Complete
**Problem:** Scan stops or hangs
**Solution:**
- Check available disk space (need 1GB minimum)
- Disable antivirus temporarily
- Run with administrator privileges
- Restart computer and try again

### Results Not Submitted
**Problem:** Scan completes but results don't appear
**Solution:**
- Check internet connection
- Verify API endpoint is reachable
- Check firewall isn't blocking
- Contact administrator

### Antivirus Blocking Scanner
**Problem:** Windows Defender or antivirus blocks scanner
**Solution:**
- Add FiveXCheck.exe to antivirus whitelist
- Temporarily disable antivirus
- Use Python version instead
- Contact administrator

---

## 📱 System Requirements

### Minimum
- Windows 10 or later
- 100MB free disk space
- Internet connection
- 2GB RAM

### Recommended
- Windows 11
- 500MB free disk space
- Stable internet
- 4GB+ RAM

### Not Supported
- Windows 7 or earlier
- Mac OS
- Linux
- Offline systems

---

## 🔐 Privacy & Security

### What the Scanner Does
✅ Scans local files only
✅ Checks for suspicious patterns
✅ Detects FiveM modifications
✅ Sends results to secure server

### What the Scanner Does NOT Do
❌ Access internet files
❌ Modify your files
❌ Collect personal information
❌ Store data locally
❌ Run in background

### Data Handling
- All scans encrypted in transit
- Results stored securely on server
- Only admin can view results
- Data deleted after retention period

---

## 📞 Getting Help

### Before Contacting Support
1. Check this guide
2. Verify code is valid
3. Check internet connection
4. Try restarting scanner
5. Check admin panel status

### Contact Administrator
- Email: [admin email]
- Discord: [discord link]
- Slack: [slack channel]
- Phone: [phone number]

### Provide Information
- Scanner version
- Error message (if any)
- Scan code used
- Device name
- Windows version

---

## 📚 Additional Resources

- **SETUP_GUIDE.md** - Complete setup instructions
- **README_FIVEX.md** - Project overview
- **SCANNER_DISTRIBUTION.md** - Distribution guide
- **Admin Panel** - View scan results and manage codes

---

## ✅ Checklist Before First Scan

- [ ] Downloaded FiveXCheck.exe or .bat file
- [ ] Have valid scan code from admin
- [ ] Internet connection working
- [ ] At least 100MB free disk space
- [ ] Windows 10 or later
- [ ] Not in Safe Mode
- [ ] Antivirus not blocking scanner

---

## 🎯 Tips for Best Results

1. **Run as Administrator** - Allows scanning system folders
2. **Close Other Programs** - Speeds up scanning
3. **Disable Antivirus** - Prevents false positives
4. **Use Wired Internet** - More stable connection
5. **Scan During Off-Hours** - Doesn't slow down computer
6. **Keep Scanner Updated** - Download latest version
7. **Review Results Carefully** - Check admin panel

---

**FiveX.check Scanner v1.0.0**
Quick Start Guide | March 2026

For detailed information, see full documentation.
