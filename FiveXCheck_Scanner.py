#!/usr/bin/env python3
"""
FiveX.check Desktop Scanner Application
Professional FiveM and PC suspicious file detection system
"""

import os
import sys
import json
import hashlib
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from datetime import datetime
from threading import Thread
import platform
import subprocess
import psutil
from typing import List, Dict, Tuple

# Configuration
API_BASE_URL = "http://localhost:3000/api/trpc"
SUSPICIOUS_PATTERNS = [
    r"\.exe$", r"\.dll$", r"\.scr$", r"\.bat$", r"\.cmd$", r"\.ps1$",
    r"\.vbs$", r"\.js$", r"\.jar$", r"\.zip$", r"\.rar$"
]
FIVEM_PATHS = [
    "FiveM",
    "GTA V",
    "Grand Theft Auto V",
    "Rockstar Games",
]
DANGEROUS_KEYWORDS = [
    "malware", "trojan", "virus", "ransomware", "spyware", "adware",
    "keylogger", "backdoor", "exploit", "injection", "hook", "mod",
    "cheat", "trainer", "hack", "crack", "serial", "keygen"
]

class FiveXCheckScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("FiveX.check Scanner")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        
        # Apply dark theme
        self.root.configure(bg="#0a0f1e")
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        bg_color = "#0a0f1e"
        card_color = "#0f1932"
        accent_color = "#8b5cf6"
        text_color = "#f0faff"
        
        style.configure("TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=text_color)
        style.configure("TButton", background=card_color, foreground=text_color)
        style.configure("Accent.TButton", background=accent_color, foreground=bg_color)
        
        self.bg_color = bg_color
        self.card_color = card_color
        self.accent_color = accent_color
        self.text_color = text_color
        
        # State variables
        self.scan_code = tk.StringVar()
        self.device_name = tk.StringVar(value=platform.node())
        self.scan_running = False
        self.scan_results = []
        self.scan_result_id = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tk.Label(
            main_frame,
            text="FiveX.check Scanner",
            font=("Arial", 24, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title_label.pack(pady=10)
        
        # Authentication Section
        auth_frame = tk.LabelFrame(
            main_frame,
            text="Authentication",
            font=("Arial", 12, "bold"),
            bg=self.card_color,
            fg=self.text_color,
            padx=15,
            pady=15
        )
        auth_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(auth_frame, text="Scan Code:", bg=self.card_color, fg=self.text_color).grid(row=0, column=0, sticky=tk.W, pady=5)
        tk.Entry(auth_frame, textvariable=self.scan_code, width=40, font=("Courier", 12)).grid(row=0, column=1, padx=10, sticky=tk.EW)
        
        tk.Label(auth_frame, text="Device Name:", bg=self.card_color, fg=self.text_color).grid(row=1, column=0, sticky=tk.W, pady=5)
        tk.Entry(auth_frame, textvariable=self.device_name, width=40, font=("Courier", 12)).grid(row=1, column=1, padx=10, sticky=tk.EW)
        
        auth_frame.columnconfigure(1, weight=1)
        
        # Scan Section
        scan_frame = tk.LabelFrame(
            main_frame,
            text="Scan Settings",
            font=("Arial", 12, "bold"),
            bg=self.card_color,
            fg=self.text_color,
            padx=15,
            pady=15
        )
        scan_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(scan_frame, text="Scan Locations:", bg=self.card_color, fg=self.text_color).pack(anchor=tk.W, pady=5)
        
        # Checkboxes for scan locations
        self.scan_appdata = tk.BooleanVar(value=True)
        self.scan_downloads = tk.BooleanVar(value=True)
        self.scan_fivem = tk.BooleanVar(value=True)
        self.scan_system = tk.BooleanVar(value=False)
        
        tk.Checkbutton(scan_frame, text="AppData & Local", variable=self.scan_appdata, bg=self.card_color, fg=self.text_color, selectcolor=self.accent_color).pack(anchor=tk.W)
        tk.Checkbutton(scan_frame, text="Downloads", variable=self.scan_downloads, bg=self.card_color, fg=self.text_color, selectcolor=self.accent_color).pack(anchor=tk.W)
        tk.Checkbutton(scan_frame, text="FiveM Directory", variable=self.scan_fivem, bg=self.card_color, fg=self.text_color, selectcolor=self.accent_color).pack(anchor=tk.W)
        tk.Checkbutton(scan_frame, text="System Folders", variable=self.scan_system, bg=self.card_color, fg=self.text_color, selectcolor=self.accent_color).pack(anchor=tk.W)
        
        # Control Buttons
        button_frame = tk.Frame(main_frame, bg=self.bg_color)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = tk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_scan,
            font=("Arial", 12, "bold"),
            bg=self.accent_color,
            fg=self.bg_color,
            padx=20,
            pady=10
        )
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            button_frame,
            text="Browse Folder",
            command=self.browse_folder,
            font=("Arial", 10),
            bg=self.card_color,
            fg=self.text_color,
            padx=15,
            pady=8
        ).pack(side=tk.LEFT, padx=5)
        
        # Progress Section
        progress_frame = tk.LabelFrame(
            main_frame,
            text="Scan Progress",
            font=("Arial", 12, "bold"),
            bg=self.card_color,
            fg=self.text_color,
            padx=15,
            pady=15
        )
        progress_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            length=400,
            mode='determinate'
        )
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.status_label = tk.Label(
            progress_frame,
            text="Ready to scan",
            bg=self.card_color,
            fg=self.text_color,
            font=("Arial", 10)
        )
        self.status_label.pack(anchor=tk.W, pady=5)
        
        # Results Text Area
        self.results_text = tk.Text(
            progress_frame,
            height=10,
            bg="#0f1932",
            fg="#00ff00",
            font=("Courier", 9),
            insertbackground=self.accent_color
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        scrollbar = ttk.Scrollbar(self.results_text)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.results_text.yview)
        
    def log_message(self, message: str, level: str = "INFO", file_path: str = None, progress: int = None):
        """Log message to results text area and send to server"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.results_text.insert(tk.END, f"[{timestamp}] {level}: {message}\n")
        self.results_text.see(tk.END)
        self.root.update()
        
        # Send log to server
        if self.scan_result_id:
            try:
                payload = {
                    "scanResultId": self.scan_result_id,
                    "logLevel": level,
                    "message": message,
                    "filePath": file_path,
                    "progress": progress,
                }
                requests.post(
                    f"{API_BASE_URL}/scanLog.add",
                    json=payload,
                    timeout=5
                )
            except:
                pass  # Silently fail if log submission fails
        
    def start_scan(self):
        """Start the scanning process"""
        if not self.scan_code.get():
            messagebox.showerror("Error", "Please enter a scan code")
            return
            
        if self.scan_running:
            messagebox.showwarning("Warning", "Scan already running")
            return
            
        self.scan_running = True
        self.start_button.config(state=tk.DISABLED)
        self.results_text.delete(1.0, tk.END)
        self.scan_results = []
        
        # Run scan in separate thread
        thread = Thread(target=self.run_scan, daemon=True)
        thread.start()
        
    def run_scan(self):
        """Execute the scan process"""
        try:
            self.log_message("Initializing scan...", "INFO")
            
            # Validate code
            if not self.validate_code():
                self.log_message("Code validation failed", "ERROR")
                return
                
            self.log_message("Code validated successfully", "SUCCESS")
            
            # Create scan result
            if not self.create_scan_result():
                self.log_message("Failed to create scan result", "ERROR")
                return
                
            # Perform scan
            self.perform_scan()
            
            # Submit results
            if self.submit_results():
                self.log_message("Scan completed and submitted successfully", "SUCCESS")
                messagebox.showinfo("Success", "Scan completed and results submitted!")
            else:
                self.log_message("Failed to submit results", "ERROR")
                
        except Exception as e:
            self.log_message(f"Scan error: {str(e)}", "ERROR")
        finally:
            self.scan_running = False
            self.start_button.config(state=tk.NORMAL)
            
    def validate_code(self) -> bool:
        """Validate scan code with server"""
        try:
            self.log_message("Validating scan code...", "INFO")
            
            payload = {
                "code": self.scan_code.get(),
                "deviceName": self.device_name.get()
            }
            
            response = requests.post(
                f"{API_BASE_URL}/scanCode.validate",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("result", {}).get("data", {}).get("valid"):
                    return True
                    
            return False
        except Exception as e:
            self.log_message(f"Validation error: {str(e)}", "ERROR")
            return False
            
    def create_scan_result(self) -> bool:
        """Create scan result on server"""
        try:
            self.log_message("Creating scan result...", "INFO")
            
            payload = {
                "scanCodeId": 1,  # Will be updated
                "deviceName": self.device_name.get(),
                "osVersion": platform.platform()
            }
            
            response = requests.post(
                f"{API_BASE_URL}/scanResult.create",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.scan_result_id = data.get("result", {}).get("data", {}).get("id")
                return self.scan_result_id is not None
                
            return False
        except Exception as e:
            self.log_message(f"Create result error: {str(e)}", "ERROR")
            return False
            
    def perform_scan(self):
        """Perform the actual file scanning"""
        self.log_message("Starting file scan...", "INFO")
        
        paths_to_scan = []
        
        if self.scan_appdata.get():
            appdata = Path.home() / "AppData"
            if appdata.exists():
                paths_to_scan.append(appdata)
                
        if self.scan_downloads.get():
            downloads = Path.home() / "Downloads"
            if downloads.exists():
                paths_to_scan.append(downloads)
                
        if self.scan_fivem.get():
            fivem_path = self.find_fivem_path()
            if fivem_path:
                paths_to_scan.append(fivem_path)
                
        total_files = 0
        for path in paths_to_scan:
            total_files += len(list(path.rglob("*")))
            
        scanned = 0
        for path in paths_to_scan:
            for file_path in path.rglob("*"):
                if file_path.is_file():
                    scanned += 1
                    progress_pct = int((scanned / max(total_files, 1)) * 100)
                    self.progress_var.set(progress_pct)
                    self.status_label.config(text=f"Scanned: {scanned} files")
                    
                    # Check file
                    risk_level = self.check_file(file_path)
                    if risk_level != "safe":
                        self.scan_results.append({
                            "filePath": str(file_path),
                            "fileName": file_path.name,
                            "fileType": file_path.suffix,
                            "fileSize": file_path.stat().st_size,
                            "riskLevel": risk_level,
                            "detectionReason": self.get_detection_reason(file_path),
                            "isFiveMMod": self.is_fivem_related(file_path),
                            "isSystemFile": self.is_system_file(file_path),
                            "createdDate": datetime.fromtimestamp(file_path.stat().st_ctime),
                            "modifiedDate": datetime.fromtimestamp(file_path.stat().st_mtime)
                        })
                        
                        self.log_message(f"Detected: {file_path.name} ({risk_level})", "WARN", str(file_path), progress_pct)
                    else:
                        # Send progress update
                        self.log_message(f"Scanning: {file_path.name}", "DEBUG", str(file_path), progress_pct)
                        
        self.progress_var.set(100)
        self.log_message(f"Scan complete. Found {len(self.scan_results)} suspicious files", "INFO")
        
    def check_file(self, file_path: Path) -> str:
        """Check file for suspicious characteristics"""
        try:
            name_lower = file_path.name.lower()
            
            # Check for dangerous keywords
            for keyword in DANGEROUS_KEYWORDS:
                if keyword in name_lower:
                    return "suspicious"
                    
            # Check file extension
            if file_path.suffix.lower() in [".exe", ".dll", ".scr", ".bat"]:
                return "warning"
                
            # Check file size (unusually large executables)
            if file_path.suffix.lower() in [".exe", ".dll"]:
                if file_path.stat().st_size > 50 * 1024 * 1024:  # 50MB
                    return "moderate"
                    
            return "safe"
        except:
            return "safe"
            
    def get_detection_reason(self, file_path: Path) -> str:
        """Get reason for detection"""
        name_lower = file_path.name.lower()
        
        for keyword in DANGEROUS_KEYWORDS:
            if keyword in name_lower:
                return f"Detected keyword: {keyword}"
                
        if file_path.suffix.lower() in [".exe", ".dll"]:
            return "Suspicious executable file"
            
        return "Unknown reason"
        
    def is_fivem_related(self, file_path: Path) -> bool:
        """Check if file is FiveM related"""
        path_str = str(file_path).lower()
        return any(pattern.lower() in path_str for pattern in FIVEM_PATHS)
        
    def is_system_file(self, file_path: Path) -> bool:
        """Check if file is system file"""
        system_dirs = ["windows", "system32", "syswow64", "program files"]
        return any(d in str(file_path).lower() for d in system_dirs)
        
    def find_fivem_path(self) -> Path:
        """Find FiveM installation path"""
        possible_paths = [
            Path.home() / "AppData" / "Local" / "FiveM",
            Path("C:/Program Files/FiveM"),
            Path("C:/Program Files (x86)/FiveM"),
        ]
        
        for path in possible_paths:
            if path.exists():
                return path
                
        return None
        
    def submit_results(self) -> bool:
        """Submit scan results to server"""
        try:
            if not self.scan_result_id:
                return False
                
            self.log_message("Submitting results...", "INFO")
            
            payload = {
                "scanResultId": self.scan_result_id,
                "files": self.scan_results
            }
            
            response = requests.post(
                f"{API_BASE_URL}/scanResult.addFiles",
                json=payload,
                timeout=30
            )
            
            return response.status_code == 200
        except Exception as e:
            self.log_message(f"Submit error: {str(e)}", "ERROR")
            return False
            
    def browse_folder(self):
        """Browse and select folder to scan"""
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self.log_message(f"Added custom folder: {folder}", "INFO")

def main():
    root = tk.Tk()
    app = FiveXCheckScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()
