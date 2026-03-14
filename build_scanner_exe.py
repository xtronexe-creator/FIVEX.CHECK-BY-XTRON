#!/usr/bin/env python3
"""
Enhanced build script for FiveX.check Scanner Windows executable
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def main():
    print("=" * 60)
    print("FiveX.check Scanner - Windows Executable Builder")
    print("=" * 60)

    # Check if PyInstaller is available
    try:
        # Try running PyInstaller as a module (more reliable)
        subprocess.run([sys.executable, "-m", "PyInstaller", "--version"],
                       capture_output=True, check=True)
        pyinstaller_cmd = [sys.executable, "-m", "PyInstaller"]
        print("[OK] PyInstaller found.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[ERROR] PyInstaller not found. Please install it with:")
        print("        pip install pyinstaller")
        sys.exit(1)

    # Define paths
    scanner_file = Path("FiveXCheck_Scanner_Enhanced.py")
    output_dir = Path("dist")
    build_dir = Path("build")
    spec_file = Path("FiveXCheck_Scanner.spec")

    if not scanner_file.exists():
        print(f"\n[ERROR] Scanner file not found: {scanner_file}")
        sys.exit(1)

    print(f"\n[INFO] Building executable from: {scanner_file}")
    print(f"[INFO] Output directory: {output_dir}")

    # Clean previous builds
    print("\n[INFO] Cleaning previous builds...")
    for dir_to_clean in [output_dir, build_dir]:
        if dir_to_clean.exists():
            shutil.rmtree(dir_to_clean)
            print(f"[INFO] Removed: {dir_to_clean}")

    if spec_file.exists():
        spec_file.unlink()
        print(f"[INFO] Removed: {spec_file}")

    # Prepare PyInstaller command
    cmd = pyinstaller_cmd + [
        "--onefile",
        "--windowed",
        "--name", "FiveXCheck_Scanner",
        "--add-data", f"{scanner_file.parent}{os.pathsep}.",
        "--collect-all", "tkinter",
        "--hidden-import=requests",
        "--hidden-import=psutil",
        "--hidden-import=winreg",
        "--hidden-import=wmi",
        str(scanner_file)
    ]

    # Add icon if exists
    icon_path = Path("icon.ico")
    if icon_path.exists():
        cmd.extend(["--icon", str(icon_path)])
        print("[INFO] Using custom icon: icon.ico")
    else:
        print("[INFO] No icon file found, using default icon.")

    # Build executable
    print("\n[INFO] Building executable (this may take a few minutes)...")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        if result.returncode == 0:
            exe_path = output_dir / "FiveXCheck_Scanner.exe"
            if exe_path.exists():
                size_mb = exe_path.stat().st_size / (1024 * 1024)
                print(f"\n[SUCCESS] Executable created successfully!")
                print(f"[SUCCESS] Location: {exe_path.absolute()}")
                print(f"[SUCCESS] Size: {size_mb:.2f} MB")

                # Create distribution package
                print("\n[INFO] Creating distribution package...")
                dist_dir = Path("FiveXCheck_Distribution")
                if dist_dir.exists():
                    shutil.rmtree(dist_dir)
                dist_dir.mkdir()

                # Copy executable
                shutil.copy(exe_path, dist_dir / "FiveXCheck_Scanner.exe")

                # Create README
                readme_content = """# FiveX.check Scanner - Windows Executable

## Installation

1. Download FiveXCheck_Scanner.exe
2. Double-click to run
3. Enter your scan code (provided by admin)
4. Click "Start Scan"

## Requirements

- Windows 10/11 (64-bit)
- Internet connection
- Administrator privileges (recommended)

## Features

- Scan for FiveM cheats and suspicious files
- Real-time progress reporting
- Detailed threat analysis
- Automatic result submission

## Support

For issues or questions, contact your administrator.
"""
                (dist_dir / "README.txt").write_text(readme_content)

                print(f"[SUCCESS] Distribution package created: {dist_dir}")
                print("[INFO] Ready to distribute!")
            else:
                print(f"\n[ERROR] Executable not found at expected location")
                sys.exit(1)
        else:
            print(f"\n[ERROR] Build failed with return code: {result.returncode}")
            print(f"STDERR: {result.stderr}")
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Build failed: {e}")
        print(f"STDERR: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Build completed successfully!")
    print("=" * 60)

if __name__ == "__main__":
    main()