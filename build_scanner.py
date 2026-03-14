#!/usr/bin/env python3
"""
Build script to create standalone FiveX.check Scanner executable
Requires: PyInstaller, requests, psutil
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def install_dependencies():
    """Install required packages"""
    print("[*] Installing dependencies...")
    packages = ["PyInstaller", "requests", "psutil"]
    for package in packages:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package, "-q"])
    print("[✓] Dependencies installed")

def build_executable():
    """Build standalone executable using PyInstaller"""
    print("[*] Building standalone executable...")
    
    script_path = Path("FiveXCheck_Scanner.py")
    if not script_path.exists():
        print("[✗] FiveXCheck_Scanner.py not found")
        return False
    
    # PyInstaller command
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",  # Single executable file
        "--windowed",  # No console window
        "--name=FiveXCheck",  # Output name
        "--icon=NONE",  # No icon (can add later)
        "--add-data=.",  # Include current directory
        "--hidden-import=tkinter",
        "--hidden-import=requests",
        "--hidden-import=psutil",
        "--distpath=./dist",
        "--buildpath=./build",
        "--specpath=./build",
        str(script_path),
    ]
    
    try:
        subprocess.check_call(cmd)
        print("[✓] Executable built successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[✗] Build failed: {e}")
        return False

def cleanup():
    """Clean up build artifacts"""
    print("[*] Cleaning up build artifacts...")
    dirs_to_remove = ["build", "__pycache__"]
    for dir_name in dirs_to_remove:
        if Path(dir_name).exists():
            shutil.rmtree(dir_name)
    
    # Remove .spec file
    spec_file = Path("FiveXCheck.spec")
    if spec_file.exists():
        spec_file.unlink()
    
    print("[✓] Cleanup complete")

def create_installer_batch():
    """Create a batch file for easy installation"""
    batch_content = """@echo off
REM FiveX.check Scanner Installer
REM This script installs Python dependencies and runs the scanner

echo Installing FiveX.check Scanner...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
python -m pip install requests psutil -q

REM Run the scanner
echo Starting FiveX.check Scanner...
python FiveXCheck_Scanner.py

pause
"""
    
    with open("FiveXCheck_Scanner.bat", "w") as f:
        f.write(batch_content)
    
    print("[✓] Created FiveXCheck_Scanner.bat")

def create_readme():
    """Create README for distribution"""
    readme_content = """# FiveX.check Desktop Scanner

Professional FiveM and PC suspicious file detection application.

## Quick Start

### Option 1: Standalone Executable (Recommended)
1. Download `FiveXCheck.exe` from the dist folder
2. Double-click to run (no installation needed)
3. Enter your scan code and start scanning

### Option 2: Python Script
1. Ensure Python 3.8+ is installed
2. Run: `python FiveXCheck_Scanner.py`
3. Enter your scan code and start scanning

### Option 3: Batch File
1. Double-click `FiveXCheck_Scanner.bat`
2. Dependencies will be installed automatically
3. Scanner will start

## System Requirements

- Windows 10/11 (64-bit recommended)
- 100MB free disk space
- Internet connection
- For Python version: Python 3.8+

## Features

✓ Real-time file scanning
✓ FiveM mod detection
✓ Suspicious file identification
✓ Progress tracking
✓ Automatic result submission
✓ Professional gaming UI

## How to Use

1. **Get Scan Code**: Ask admin to generate a code from the admin panel
2. **Enter Code**: Paste the code into the scanner
3. **Select Locations**: Choose which folders to scan
4. **Start Scan**: Click "Start Scan" button
5. **Monitor Progress**: Watch real-time scanning progress
6. **View Results**: Results are automatically submitted to the server

## Scan Locations

- **AppData & Local**: User profile data and applications
- **Downloads**: Download folder
- **FiveM Directory**: FiveM game installation
- **System Folders**: Windows system directories

## Risk Levels

- **Suspicious** (🔴): Malware indicators, dangerous keywords
- **Warning** (🟠): Executable files, system modifications
- **Moderate** (🟡): Large files, unusual locations
- **Safe** (🟢): Normal system files

## Troubleshooting

### Scanner Won't Start
- Ensure you have administrator privileges
- Check internet connection
- Verify Python is installed (for Python version)

### Code Validation Fails
- Verify code is correct (case-sensitive)
- Check code hasn't expired
- Ask admin to generate a new code

### Scan Won't Complete
- Check available disk space
- Disable antivirus temporarily
- Run with administrator privileges

## Support

For issues or questions:
1. Check the admin panel for status
2. Verify your internet connection
3. Contact your administrator

## Version

FiveX.check Scanner v1.0.0
Release: March 2026

---

**Professional Gaming Security | FiveM Protection**
"""
    
    with open("README_SCANNER.txt", "w") as f:
        f.write(readme_content)
    
    print("[✓] Created README_SCANNER.txt")

def main():
    """Main build process"""
    print("=" * 60)
    print("FiveX.check Scanner - Standalone Build")
    print("=" * 60)
    print()
    
    try:
        # Install dependencies
        install_dependencies()
        print()
        
        # Build executable
        if not build_executable():
            sys.exit(1)
        print()
        
        # Create helper files
        create_installer_batch()
        create_readme()
        print()
        
        # Cleanup
        cleanup()
        print()
        
        print("=" * 60)
        print("[✓] Build Complete!")
        print("=" * 60)
        print()
        print("Distribution files:")
        print("  - dist/FiveXCheck.exe (Standalone executable)")
        print("  - FiveXCheck_Scanner.bat (Quick launcher)")
        print("  - FiveXCheck_Scanner.py (Python script)")
        print("  - README_SCANNER.txt (User guide)")
        print()
        print("Next steps:")
        print("1. Test FiveXCheck.exe on your system")
        print("2. Distribute to users")
        print("3. Users run the .exe file directly")
        print()
        
    except Exception as e:
        print(f"[✗] Build failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
