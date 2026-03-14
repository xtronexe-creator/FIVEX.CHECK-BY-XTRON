#!/usr/bin/env python3
"""
FIVEX.CHECK SCANNER PRO - Professional FiveM Cheat Detection
Enhanced Version with Advanced Patterns & UI
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
import winreg
import socket
import time
import re
import math
import sqlite3
import shutil
import tempfile
from typing import List, Dict, Tuple, Optional
from collections import Counter

# Optional imports (graceful fallback)
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

API_BASE_URL = "http://localhost:3000/api/trpc"  # Change to your hosted URL when deploying (e.g. https://your-app.up.railway.app/api/trpc)

# If True: user will NOT see detailed logs / file paths in the app.
# All details stay on the backend (website). For now we want
# players to see live file details while scanning, so keep this False.
HIDE_LOCAL_DETAILS = False

# ==============================================================================
# PROFESSIONAL CHEAT SIGNATURE DATABASE
# ==============================================================================

# 1. Regex patterns - ONLY known cheat names (detect.ac style, minimal false positives)
CHEAT_PATTERNS = {
    "cheat_engines": [
        r"eulen", r"red[\s_-]*engine", r"phaze", r"keyser", r"tzx", r"exterium",
        r"project[\s_-]*[xX]", r"aimstar", r"phantom", r"unknowncheat", r"fate",
        r"infinity", r"titan", r"void", r"nano", r"synapse[\s_-]*[xX]", r"krnl",
        r"fluxus", r"script[\s_-]*ware", r"easyexploits", r"oxygen[\s_-]*u",
        r"cheatengine", r"artmoney", r"gameguardian", r"bruteforce", r"memory[\s_-]*hack",
        r"injector", r"bypass", r"spoofer", r"unban", r"crack",
        r"xforce", r"redengine", r"evolution", r"nemesis", r"predator", r"hydra",
    ],
    "cheat_dlls": [
        r"injector\.dll", r"loader\.dll", r"menu\.dll", r"bypass\.dll", r"spoofer\.dll",
        r"unknowncheat\.dll", r"phantom\.dll", r"susano\.dll", r"phaze\.dll",
        r"eulen\.dll", r"keyser\.dll", r"tzx\.dll", r"redengine\.dll", r"exterium\.dll",
        r"projectx\.dll", r"aimstar\.dll", r"fate\.dll", r"infinity\.dll", r"titan\.dll",
        r"void\.dll", r"nano\.dll", r"synapse\.dll", r"krnl\.dll", r"fluxus\.dll",
    ],
    "cheat_exes": [
        r"injector\.exe", r"loader\.exe", r"menu\.exe", r"bypass\.exe", r"spoofer\.exe",
        r"eulen\.exe", r"keyser\.exe", r"tzx\.exe", r"phaze\.exe", r"redengine\.exe",
        r"exterium\.exe", r"projectx\.exe", r"aimstar\.exe", r"phantom\.exe",
        r"unknowncheat\.exe", r"fate\.exe", r"infinity\.exe", r"titan\.exe", r"void\.exe",
        r"nano\.exe", r"synapse\.exe", r"krnl\.exe", r"fluxus\.exe", r"artmoney\.exe",
        r"cheatengine\.exe", r"gameguardian\.exe",
    ],
    "generic_hack": [
        r"fivem[\s_-]*hack", r"fivem[\s_-]*cheat", r"fivem[\s_-]*mod[\s_-]*menu",
        r"fivem[\s_-]*injector", r"fivem[\s_-]*bypass", r"fivem[\s_-]*spoofer", r"fivem[\s_-]*unban",
        r"gta[\s_-]*mod[\s_-]*menu", r"gta[\s_-]*trainer", r"aimbot", r"wallhack", r"triggerbot",
        r"noclip", r"godmode", r"infinite[\s_-]*ammo", r"no[\s_-]*recoil",
        r"speed[\s_-]*hack", r"super[\s_-]*jump", r"money[\s_-]*drop", r"rpx[\s_-]*cheat",
    ]
}

# Normal game file extensions - SKIP these (avoid false positives)
SKIP_EXTENSIONS = {".lua", ".json", ".ymf", ".ytd", ".yft", ".ydr", ".ybn", ".ytyp", ".ymap",
                   ".awc", ".dat", ".cfg", ".txt", ".xml", ".meta", ".cache", ".log",
                   ".png", ".jpg", ".dds", ".ttf", ".otf", ".mp3", ".wav", ".ogg"}

# Folders to skip when scanning (non-cheat, speeds up full PC scan)
SKIP_DIRS = {"node_modules", "__pycache__", ".git", ".svn", "cache", "Cache", "Caches",
             "CodeCache", "GPUCache", "ShaderCache", "Logs", "logs", "Temp", "tmp",
             "Microsoft", "Windows", "WindowsApps", "WinSxS", "assembly", "winsxs"}

# 2. Known cheat file hashes (MD5) – extend as needed
KNOWN_CHEAT_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "Example empty file",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Example SHA256 placeholder",
    # Add real cheat hashes here from public databases
}

# 3. Suspicious registry keys/values
SUSPICIOUS_REGISTRY = [
    (winreg.HKEY_CURRENT_USER, r"Software\EulenCheat"),
    (winreg.HKEY_CURRENT_USER, r"Software\RedEngine"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\EulenCheat"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\RedEngine"),
    (winreg.HKEY_CURRENT_USER, r"Software\CheatEngine"),
]

# 4. Safe FiveM / official files (never flag these)
SAFE_FIVEM_FILES = [
    "citizen-mod-loader-five.dll",
    "citizen-level-loader-five.dll",
    "handling-loader-five.dll",
    "CitizenFX.FiveM.dll",
    "CitizenFX.FiveM.Native.dll",
    "CitizenFX.FiveM.NativeImpl.dll",
    "CitizenFX.FiveM.Server.dll",
    "CitizenFX.FiveM.Shared.dll",
    "CitizenFX.Core.dll",
    "CitizenFX.Core.Native.dll",
    "CitizenFX.Core.Vehicle.dll",
    "CitizenFX.Core.UI.dll",
    "CitizenFX.Core.Entity.dll",
    "CitizenFX.Core.Player.dll",
    "CitizenFX.Core.Ped.dll",
    "CitizenFX.Core.Pool.dll",
    "CitizenFX.Core.Task.dll",
    "CitizenFX.Core.Weapon.dll",
    "CitizenFX.Core.World.dll",
    "CitizenFX.Core.Blip.dll",
    "CitizenFX.Core.Checkpoint.dll",
    "CitizenFX.Core.Pickup.dll",
    "CitizenFX.Core.Rope.dll",
    "CitizenFX.Core.Scaleform.dll",
    "CitizenFX.Core.Timer.dll",
    "CitizenFX.Core.Zone.dll",
    "CitizenFX.Core.Weather.dll",
    "CitizenFX.Core.Timecycle.dll",
    "CitizenFX.Core.Audio.dll",
    "CitizenFX.Core.Cam.dll",
    "CitizenFX.Core.Control.dll",
    "CitizenFX.Core.Cutscene.dll",
    "CitizenFX.Core.Decorator.dll",
    "CitizenFX.Core.Fire.dll",
    "CitizenFX.Core.Force.dll",
    "CitizenFX.Core.GameEvent.dll",
    "CitizenFX.Core.GtaFx.dll",
    "CitizenFX.Core.Misc.dll",
    "CitizenFX.Core.Model.dll",
    "CitizenFX.Core.Network.dll",
    "CitizenFX.Core.Object.dll",
    "CitizenFX.Core.Ptfx.dll",
    "CitizenFX.Core.Ragdoll.dll",
    "CitizenFX.Core.Script.dll",
    "CitizenFX.Core.ShapeTest.dll",
    "CitizenFX.Core.Streaming.dll",
    "CitizenFX.Core.Text.dll",
    "CitizenFX.Core.Txd.dll",
    "CitizenFX.Core.Vehicle.dll",
    "CitizenFX.Core.Weapon.dll",
    "CitizenFX.Core.Zone.dll",
    "CitizenFX.Server.dll",
    "CitizenFX.Shared.dll",
    "CitizenFX.Subprocess.dll",
    "CitizenFX.Subprocess.Broker.dll",
    "CitizenFX.Subprocess.Channel.dll",
    "CitizenFX.Subprocess.Shared.dll"
]

# 5. Important directories to scan
SCAN_LOCATIONS = [
    # FiveM paths
    Path.home() / "AppData" / "Local" / "FiveM",
    Path.home() / "AppData" / "Roaming" / "FiveM",
    Path("C:/Program Files/FiveM"),
    Path("C:/Program Files (x86)/FiveM"),
    Path.home() / "Documents" / "FiveM",
    # Common cheat folders
    Path.home() / "AppData" / "Local" / "Temp",
    Path.home() / "AppData" / "Roaming",
    Path.home() / "AppData" / "Local",
    Path.home() / "Downloads",
    Path.home() / "Desktop",
    Path("C:/Windows/Temp"),
]

# Keywords/domains in browser history that suggest cheat/hack site visits or login attempts
BROWSER_CHEAT_KEYWORDS = [
    "unknowncheats", "unknown-cheats", "cheatengine", "eulen", "redengine", "phaze", "aimstar",
    "fivem cheat", "fivem hack", "fivem injector", "fivem mod menu", "fivem bypass",
    "gta cheat", "gta mod menu", "synapse", "krnl", "fluxus", "script-ware",
    "elite cheats", "aimbot", "wallhack", "triggerbot", "cheat", "hack", "injector",
    "bypass", "spoofer", "unban", "crack", "keygen", "trainer",
]

# ==============================================================================
# FILE ANALYSIS UTILITIES
# ==============================================================================

class FileAnalyzer:
    @staticmethod
    def calculate_hash(file_path: Path, algorithm: str = "md5") -> str:
        """Calculate file hash (MD5 by default)."""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception:
            return "N/A"

    @staticmethod
    def get_file_metadata(file_path: Path) -> Dict:
        """Get basic file metadata."""
        try:
            stat = file_path.stat()
            return {
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat()
            }
        except Exception:
            return {}

    @staticmethod
    def get_windows_file_details(file_path: Path) -> Dict:
        """Get digital signature and version info (Windows only)."""
        details = {"signed": False, "product_name": "", "company_name": "", "description": ""}
        if platform.system() == "Windows":
            try:
                # Check signature (use argv form to avoid quoting issues)
                cmd = [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(Get-AuthenticodeSignature -FilePath '{str(file_path)}').Status",
                ]
                result = subprocess.check_output(cmd, text=True, timeout=5).strip()
                details["signed"] = (result == "Valid")
                # Get version info
                cmd2 = [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(Get-Item -LiteralPath '{str(file_path)}').VersionInfo | Select-Object ProductName, CompanyName, FileDescription | ConvertTo-Json",
                ]
                result2 = subprocess.check_output(cmd2, text=True, timeout=5).strip()
                if result2:
                    info = json.loads(result2)
                    details["product_name"] = info.get("ProductName", "")
                    details["company_name"] = info.get("CompanyName", "")
                    details["description"] = info.get("FileDescription", "")
            except Exception:
                pass
        return details

    @staticmethod
    def calculate_entropy(file_path: Path) -> Optional[float]:
        """Calculate Shannon entropy of file (high entropy may indicate packed/encrypted code)."""
        try:
            total = 0
            counts = Counter()
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    counts.update(chunk)
            if total == 0:
                return 0.0
            entropy = 0.0
            for c in counts.values():
                p = c / total
                entropy += -p * math.log2(p)
            return entropy
        except Exception:
            return None

    @staticmethod
    def is_dotnet_assembly(file_path: Path) -> bool:
        """Check if file is a .NET assembly (optional, requires pefile)."""
        if not HAS_PEFILE:
            return False
        try:
            pe = pefile.PE(str(file_path))
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll.decode().lower() == "mscoree.dll":
                    return True
            return False
        except Exception:
            return False

# ==============================================================================
# MAIN SCANNER CLASS (ENHANCED UI)
# ==============================================================================

class FiveXCheckScannerPro:
    def __init__(self, root):
        self.root = root
        self.root.title("FIVEX.CHECK SCANNER BY XTRON")
        self.root.geometry("1240x780")
        self.root.configure(bg="#0e0e12")
        self.root.minsize(1000, 650)
        # Remove OS title bar; we use custom top bar with close button
        self.root.overrideredirect(True)
        self._drag_start_x = 0
        self._drag_start_y = 0

        # Color scheme
        self.colors = {
            "bg": "#0e0e12",
            "card": "#1a1a24",
            "accent": "#00ccff",
            "accent_dark": "#0099cc",
            "text": "#ffffff",
            "text_light": "#a0a0b0",
            "danger": "#ff5555",
            "warning": "#ffaa00",
            "moderate": "#ff8800",
            "success": "#55ff55",
            "border": "#2a2a3a",
            "entry_bg": "#222230",
        }

        # Variables
        self.scan_code = tk.StringVar()
        self.device_name = tk.StringVar(value=platform.node())
        self.scan_running = False
        self.scan_results = []          # List of result dicts
        self.scan_result_id = None
        self.code_id = None
        self.overall_risk_level = "safe"
        self.start_time = None
        self.timer_id = None
        self.total_files_scanned = 0

        # Scan options (boolean vars) - default modules ON
        self.scan_fivem = tk.BooleanVar(value=True)
        self.scan_appdata = tk.BooleanVar(value=True)
        self.scan_forensics = tk.BooleanVar(value=True)
        self.scan_memory = tk.BooleanVar(value=True)
        self.scan_registry = tk.BooleanVar(value=True)
        self.scan_hashes = tk.BooleanVar(value=True)   # Enable hash checking
        self.scan_entropy = tk.BooleanVar(value=True)  # Enable entropy analysis
        self.scan_browser = tk.BooleanVar(value=True)  # Browser history (cheat/hack sites)

        self.system_info = self._get_system_info()
        self.setup_ui()
        self.apply_styles()

    def _get_system_info(self) -> dict:
        """Gather detailed system hardware / OS info for the website."""
        info: Dict[str, Any] = {
            "os": platform.platform(),
            "processor": platform.processor(),
            "machine": platform.machine(),
            "hostname": platform.node(),
            "boot_time": None,
            "uptime_seconds": None,
            "cpu": {},
            "memory": {},
            "disks": [],
            "network": [],
            "gpu": [],
            "motherboard": {},
            "bios": {},
            "software": {
                "python_version": platform.python_version(),
                "os_version": getattr(platform, "version", lambda: "")(),
                "os_release": platform.release(),
            },
            "windows_install_date": None,
            "is_vm": False,
            "vm_name": None,
            "location": None,
            "timezone": None,
        }

        try:
            info["timezone"] = f"{time.tzname[0] or 'UTC'}/{time.tzname[1] or 'UTC'}"
        except Exception:
            pass

        try:
            # Boot / uptime
            bt = psutil.boot_time()
            info["boot_time"] = datetime.fromtimestamp(bt).isoformat()
            info["uptime_seconds"] = int(time.time() - bt)

            # CPU
            info["cpu"] = {
                "physical_cores": psutil.cpu_count(logical=False) or 0,
                "logical_cores": psutil.cpu_count(logical=True) or 0,
                "max_frequency": getattr(psutil.cpu_freq(), "max", 0) if hasattr(psutil, "cpu_freq") else 0,
                "current_frequency": getattr(psutil.cpu_freq(), "current", 0) if hasattr(psutil, "cpu_freq") else 0,
                "usage_percent": psutil.cpu_percent(interval=0.1),
            }

            # Memory
            vm = psutil.virtual_memory()
            info["memory"] = {
                "total": vm.total,
                "available": vm.available,
                "used": vm.used,
                "percent": vm.percent,
            }

            # Disks
            disks = []
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent,
                    })
                except Exception:
                    continue
            info["disks"] = disks

            # Network (IPv4 only)
            addrs = psutil.net_if_addrs()
            net_list = []
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if getattr(socket, "AF_INET", None) and addr.family == socket.AF_INET:
                        net_list.append({
                            "interface": iface,
                            "ip": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": addr.broadcast,
                        })
            info["network"] = net_list
        except Exception:
            pass

        # Extra Windows-specific info via WMI (if available)
        try:
            if HAS_WMI:
                c = wmi.WMI()
                for gpu in c.Win32_VideoController():
                    info["gpu"].append({
                        "name": gpu.Name,
                        "adapter_ram": getattr(gpu, "AdapterRAM", None),
                        "driver_version": getattr(gpu, "DriverVersion", None),
                        "video_processor": getattr(gpu, "VideoProcessor", None),
                    })
                for board in c.Win32_BaseBoard():
                    info["motherboard"] = {
                        "manufacturer": getattr(board, "Manufacturer", None),
                        "product": getattr(board, "Product", None),
                        "serial": getattr(board, "SerialNumber", None),
                    }
                    break
                for bios in c.Win32_BIOS():
                    info["bios"] = {"version": getattr(bios, "SMBIOSBIOSVersion", None)}
                    break
                for os_obj in c.Win32_OperatingSystem():
                    raw = getattr(os_obj, "InstallDate", None)
                    if raw:
                        try:
                            dt = datetime.strptime(str(raw).split(".")[0], "%Y%m%d%H%M%S")
                            info["windows_install_date"] = dt.isoformat()
                        except Exception:
                            info["windows_install_date"] = str(raw)
                    break
                # VM detection
                for cs in c.Win32_ComputerSystem():
                    model = (getattr(cs, "Model", None) or "").lower()
                    manufacturer = (getattr(cs, "Manufacturer", None) or "").lower()
                    vm_indicators = ("virtual", "vmware", "vbox", "virtualbox", "hyper-v", "qemu", "xen", "kvm", "parallels")
                    if any(v in model for v in vm_indicators) or any(v in manufacturer for v in vm_indicators):
                        info["is_vm"] = True
                        info["vm_name"] = model or manufacturer or "Virtual Machine"
                    break
        except Exception:
            pass

        return info

    def _on_drag_start(self, event):
        self._drag_start_x = event.x_root - self.root.winfo_x()
        self._drag_start_y = event.y_root - self.root.winfo_y()

    def _on_drag_motion(self, event):
        x = event.x_root - self._drag_start_x
        y = event.y_root - self._drag_start_y
        self.root.geometry(f"+{x}+{y}")

    def setup_ui(self):
        """Build the main UI with tabs."""
        _script_dir = Path(__file__).parent.resolve()

        # Professional border: accent frame (thicker for quality look)
        border_frame = tk.Frame(self.root, bg=self.colors["accent"], padx=4, pady=4)
        border_frame.pack(fill=tk.BOTH, expand=True)
        inner = tk.Frame(border_frame, bg=self.colors["bg"])
        inner.pack(fill=tk.BOTH, expand=True)
        inner.bind("<Button-1>", self._on_drag_start)
        inner.bind("<B1-Motion>", self._on_drag_motion)

        # Top bar (no OS title bar): no logo inside window; close button top-right
        top_bar = tk.Frame(inner, bg=self.colors["bg"], height=44)
        top_bar.pack(fill=tk.X, side=tk.TOP)
        top_bar.pack_propagate(False)
        top_bar.bind("<Button-1>", self._on_drag_start)
        top_bar.bind("<B1-Motion>", self._on_drag_motion)
        # Window icon only (taskbar); logo not shown inside app
        for logo_name in ["xtron-logo.png", "logo.png"]:
            logo_path = _script_dir / logo_name
            if logo_path.exists():
                try:
                    from tkinter import PhotoImage
                    self._logo_img = PhotoImage(file=str(logo_path))
                    self.root.iconphoto(True, self._logo_img)
                    break
                except Exception:
                    pass
        else:
            for ico_name in ["icon.ico", "logo.ico"]:
                ico_path = _script_dir / ico_name
                if ico_path.exists():
                    try:
                        self.root.iconbitmap(default=str(ico_path))
                        break
                    except Exception:
                        pass

        # Close button – top-right corner
        close_btn = tk.Button(
            top_bar,
            text="✕",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors["text_light"],
            bg=self.colors["bg"],
            activeforeground="#fff",
            activebackground="#ff5555",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            width=3,
            command=self.root.destroy,
        )
        close_btn.pack(side=tk.RIGHT, padx=8, pady=6)
        close_btn.bind("<Enter>", lambda e: e.widget.config(fg="#fff", bg="#ff5555"))
        close_btn.bind("<Leave>", lambda e: e.widget.config(fg=self.colors["text_light"], bg=self.colors["bg"]))

        # Footer at bottom (pack first so it stays at bottom)
        footer = tk.Frame(inner, bg=self.colors["bg"], height=28)
        footer.pack(side=tk.BOTTOM, fill=tk.X)
        footer.pack_propagate(False)
        tk.Label(footer, text="© 2026 All rights reserved XTRON", font=("Segoe UI", 9),
                 fg=self.colors["text_light"], bg=self.colors["bg"]).pack(pady=4)

        # Main container
        main_frame = tk.Frame(inner, bg=self.colors["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 8))

        # Header (title inside app, not OS bar)
        header = tk.Frame(main_frame, bg=self.colors["bg"])
        header.pack(fill=tk.X, pady=(0, 15))

        title_frame = tk.Frame(header, bg=self.colors["bg"])
        title_frame.pack(side=tk.LEFT)

        tk.Label(title_frame, text="FIVEX.CHECK", font=("Segoe UI", 36, "bold"),
                 fg=self.colors["accent"], bg=self.colors["bg"]).pack(side=tk.LEFT)
        tk.Label(title_frame, text="SCANNER BY XTRON", font=("Segoe UI", 14, "bold"),
                 fg=self.colors["warning"], bg=self.colors["bg"]).pack(side=tk.LEFT, padx=(8, 0))

        self.status_label = tk.Label(header, text="● READY", font=("Segoe UI", 10, "bold"),
                                      fg=self.colors["success"], bg=self.colors["bg"])
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # Notebook (tabs)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Scan Configuration
        self.tab_config = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_config, text=" SCAN CONFIGURATION ")
        self.setup_config_tab()

        # Tab 2: Live Logs
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text=" LIVE LOGS ")
        self.setup_logs_tab()

    def apply_styles(self):
        """Apply ttk styles for modern look."""
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.colors["card"], foreground=self.colors["text_light"],
                        padding=[20, 8], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", self.colors["accent"])],
                  foreground=[("selected", self.colors["bg"])])
        style.configure("Neon.Horizontal.TProgressbar", thickness=20,
                        troughcolor=self.colors["card"], background=self.colors["accent"],
                        borderwidth=0)
        style.configure("Treeview", background=self.colors["entry_bg"], foreground=self.colors["text"],
                        fieldbackground=self.colors["entry_bg"], borderwidth=0, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=self.colors["card"], foreground=self.colors["accent"],
                        font=("Segoe UI", 10, "bold"))
        style.map("Treeview.Heading", background=[("active", self.colors["accent_dark"])])

    def setup_config_tab(self):
        """Tab for scan options and code entry."""
        container = tk.Frame(self.tab_config, bg=self.colors["bg"])
        container.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Top: Scan Code + System Info (compact, side-by-side)
        top_row = tk.Frame(container, bg=self.colors["bg"])
        top_row.pack(fill=tk.X, pady=(0, 12))

        # Scan Code card (left)
        code_card = self.create_card(top_row, "🔑 SCAN CODE")
        code_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(20, 10))
        tk.Label(code_card, text="Enter your scan code:", fg=self.colors["text_light"],
                 bg=self.colors["card"], font=("Segoe UI", 10)).pack(anchor=tk.W, padx=15, pady=(5,0))
        code_entry = tk.Entry(code_card, textvariable=self.scan_code, bg=self.colors["entry_bg"],
                              fg=self.colors["text"], insertbackground=self.colors["accent"],
                              font=("Consolas", 14), bd=0, highlightthickness=1,
                              highlightbackground=self.colors["border"], highlightcolor=self.colors["accent"])
        code_entry.pack(fill=tk.X, padx=15, pady=(0,10), ipady=8)

        # Scan button inside the code card (right side)
        btn_frame = tk.Frame(code_card, bg=self.colors["card"])
        btn_frame.pack(fill=tk.X, padx=15, pady=(0, 10))
        self.start_btn = tk.Button(
            btn_frame,
            text="▶ START SECURITY SCAN",
            font=("Segoe UI", 12, "bold"),
            bg=self.colors["accent"],
            fg=self.colors["bg"],
            activebackground=self.colors["accent_dark"],
            bd=0,
            padx=20,
            pady=8,
            cursor="hand2",
            command=self.start_scan,
        )
        self.start_btn.pack(side=tk.RIGHT)

        # System Info card (right)
        sys_card = self.create_card(top_row, "🖥️ SYSTEM INFO")
        sys_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 20))
        sys_inner = tk.Frame(sys_card, bg=self.colors["card"])
        sys_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))

        si = self.system_info or {}
        os_label = tk.Label(sys_inner, text=f"OS: {si.get('os', 'Unknown')}",
                            fg=self.colors["text"], bg=self.colors["card"],
                            font=("Segoe UI", 9))
        os_label.pack(anchor=tk.W)

        host_label = tk.Label(sys_inner, text=f"Device: {si.get('hostname', platform.node())}",
                              fg=self.colors["text_light"], bg=self.colors["card"],
                              font=("Segoe UI", 9))
        host_label.pack(anchor=tk.W)

        cpu = si.get("cpu", {}) or {}
        cores = cpu.get("logical_cores") or si.get("cpu_cores")
        ram_total = si.get("memory", {}).get("total") or si.get("ram_total")
        if cores:
            tk.Label(sys_inner, text=f"CPU Cores: {cores}",
                     fg=self.colors["text_light"], bg=self.colors["card"],
                     font=("Segoe UI", 9)).pack(anchor=tk.W)
        if ram_total:
            gb = ram_total / (1024 ** 3)
            tk.Label(sys_inner, text=f"RAM: {gb:.1f} GB",
                     fg=self.colors["text_light"], bg=self.colors["card"],
                     font=("Segoe UI", 9)).pack(anchor=tk.W)

        # Windows install date is collected for the website only (shown in web panel)

        # Scan Modules card
        opt_card = self.create_card(container, "⚙️ SCAN MODULES")
        opt_card.pack(fill=tk.X, pady=(0, 12))
        options_frame = tk.Frame(opt_card, bg=self.colors["card"])
        options_frame.pack(fill=tk.X, padx=15, pady=10)
        row1 = tk.Frame(options_frame, bg=self.colors["card"])
        row1.pack(fill=tk.X, pady=4)
        self.add_option_checkbox(row1, "FiveM Directories", "All drives - FiveM/GTA/CFX related folders only", self.scan_fivem)
        self.add_option_checkbox(row1, "AppData & User Folders", "User folders for cheat loaders", self.scan_appdata)
        self.add_option_checkbox(row1, "Registry", "Known cheat registry keys", self.scan_registry)
        row2 = tk.Frame(options_frame, bg=self.colors["card"])
        row2.pack(fill=tk.X, pady=4)
        self.add_option_checkbox(row2, "Memory Scan", "Running cheat processes", self.scan_memory)
        self.add_option_checkbox(row2, "Forensics", "Prefetch & system traces", self.scan_forensics)
        self.add_option_checkbox(row2, "Hash Matching", "Known cheat file hashes", self.scan_hashes)
        self.add_option_checkbox(row2, "Browser History", "Cheat/hack site visits or login attempts", self.scan_browser)

    def create_card(self, parent, title):
        """Helper to create a styled card frame (caller is responsible for pack/placement)."""
        card = tk.Frame(parent, bg=self.colors["card"], bd=1, relief=tk.SOLID,
                        highlightbackground=self.colors["border"], highlightthickness=1)
        tk.Label(card, text=title, fg=self.colors["accent"], bg=self.colors["card"],
                 font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=15, pady=(10,5))
        return card

    def add_option_checkbox(self, parent, label, desc, var):
        """Create a styled checkbox for scan options."""
        frame = tk.Frame(parent, bg=self.colors["entry_bg"], bd=1, relief=tk.SOLID,
                         highlightbackground=self.colors["border"])
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        cb = tk.Checkbutton(frame, text=label, variable=var, bg=self.colors["entry_bg"],
                            fg=self.colors["text"], selectcolor=self.colors["entry_bg"],
                            activebackground=self.colors["entry_bg"], font=("Segoe UI", 10, "bold"))
        cb.pack(anchor=tk.W, padx=10, pady=(5,0))

        tk.Label(frame, text=desc, fg=self.colors["text_light"], bg=self.colors["entry_bg"],
                 font=("Segoe UI", 8), wraplength=180, justify=tk.LEFT).pack(anchor=tk.W, padx=25, pady=(0,5))
        return frame

    def setup_logs_tab(self):
        """Tab with live logs and results table."""
        # Progress bar frame
        progress_frame = tk.Frame(self.tab_logs, bg=self.colors["card"], bd=1,
                                  highlightbackground=self.colors["border"])
        progress_frame.pack(fill=tk.X, pady=(10,5), padx=10)

        tk.Label(progress_frame, text="SCAN PROGRESS", fg=self.colors["accent"],
                 bg=self.colors["card"], font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(5,0))

        progress_container = tk.Frame(progress_frame, bg=self.colors["card"])
        progress_container.pack(fill=tk.X, padx=10, pady=10)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_container, variable=self.progress_var,
                                             maximum=100, mode='determinate',
                                             style="Neon.Horizontal.TProgressbar")
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.percent_label = tk.Label(progress_container, text="0%", fg=self.colors["accent"],
                                       bg=self.colors["card"], font=("Consolas", 14, "bold"))
        self.percent_label.pack(side=tk.RIGHT, padx=(10,0))

        # Stats frame
        stats_frame = tk.Frame(self.tab_logs, bg=self.colors["card"], bd=1,
                               highlightbackground=self.colors["border"])
        stats_frame.pack(fill=tk.X, pady=5, padx=10)

        self.timer_label = tk.Label(stats_frame, text="⏱️ Time: 00:00:00", fg=self.colors["accent"],
                                    bg=self.colors["card"], font=("Consolas", 12, "bold"), anchor=tk.W)
        self.timer_label.pack(side=tk.LEFT, padx=10, pady=8)

        self.file_count_label = tk.Label(stats_frame, text="📁 Files: 0", fg=self.colors["text_light"],
                                         bg=self.colors["card"], font=("Consolas", 12), anchor=tk.E)
        self.file_count_label.pack(side=tk.RIGHT, padx=10, pady=8)

        # Live Logs only (no count labels - just logs)
        if not HIDE_LOCAL_DETAILS:
            log_label = tk.Label(self.tab_logs, text="LIVE LOGS (scroll for more)", fg=self.colors["accent"],
                                 bg=self.colors["bg"], font=("Segoe UI", 10, "bold"), anchor=tk.W)
            log_label.pack(fill=tk.X, padx=10, pady=(5,0))

            log_frame = tk.Frame(self.tab_logs, bg=self.colors["bg"])
            log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))

            self.log_area = tk.Text(log_frame, bg=self.colors["entry_bg"], fg=self.colors["text"],
                                    font=("Consolas", 9), borderwidth=0, height=10, wrap=tk.WORD,
                                    highlightbackground=self.colors["border"], highlightthickness=1)
            log_scroll = tk.Scrollbar(log_frame, orient="vertical", command=self.log_area.yview)
            self.log_area.configure(yscrollcommand=log_scroll.set)
            self.log_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

            self.log_area.tag_config("INFO", foreground=self.colors["accent"])
            self.log_area.tag_config("WARN", foreground=self.colors["warning"])
            self.log_area.tag_config("ERROR", foreground=self.colors["danger"])
            self.log_area.tag_config("SUCCESS", foreground=self.colors["success"])

            self.tree = None
        else:
            self.tree = None
            self.log_area = None
            info = tk.Label(
                self.tab_logs,
                text="This scan is managed by the server.\nDetailed results will be visible on the website.",
                fg=self.colors["text_light"],
                bg=self.colors["bg"],
                font=("Segoe UI", 11),
                justify=tk.CENTER,
            )
            info.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def setup_settings_tab(self):
        """Settings tab (placeholder)."""
        frame = tk.Frame(self.tab_settings, bg=self.colors["bg"])
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        tk.Label(frame, text="Settings will be available in the next update.",
                 fg=self.colors["text_light"], bg=self.colors["bg"], font=("Segoe UI", 12)).pack()

    # ==========================================================================
    # SCANNING LOGIC
    # ==========================================================================

    def log_message(self, msg, level="INFO", file_path=None):
        """Add a message to the log area."""
        ts = datetime.now().strftime("%H:%M:%S")
        if not HIDE_LOCAL_DETAILS and hasattr(self, "log_area") and self.log_area is not None:
            self.log_area.insert(tk.END, f"[{ts}] [{level}] {msg}\n", level)
            self.log_area.see(tk.END)
            self.root.update_idletasks()

        # Update status label
        if level == "ERROR":
            self.status_label.config(text="● ERROR", fg=self.colors["danger"])
        elif level == "SUCCESS":
            self.status_label.config(text="● SUCCESS", fg=self.colors["success"])
        elif level == "WARN":
            self.status_label.config(text="● WARNING", fg=self.colors["warning"])
        else:
            self.status_label.config(text="● SCANNING", fg=self.colors["accent"])

        # Optional API call (always send to backend, even if UI is hidden)
        if self.scan_result_id:
            try:
                payload = {"json": {"scanResultId": self.scan_result_id, "logLevel": level,
                                    "message": msg, "filePath": file_path}}
                requests.post(f"{API_BASE_URL}/scanLog.add", json=payload, timeout=2)
            except:
                pass

    def update_progress(self, value):
        self.progress_var.set(value)
        self.percent_label.config(text=f"{int(value)}%")
        self.root.update_idletasks()

    def update_timer(self):
        if self.scan_running and self.start_time:
            elapsed = int(time.time() - self.start_time)
            h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
            self.timer_label.config(text=f"⏱️ Time: {h:02d}:{m:02d}:{s:02d}")
            self.timer_id = self.root.after(1000, self.update_timer)

    def update_file_count(self):
        self.file_count_label.config(text=f"📁 Files: {self.total_files_scanned}")

    def start_scan(self):
        if not self.scan_code.get():
            messagebox.showerror("Error", "Please enter a scan code.")
            return
        if self.scan_running:
            return
        self.notebook.select(1)  # Switch to logs tab
        self.scan_running = True
        self.scan_results.clear()
        if self.tree is not None:
            self.tree.delete(*self.tree.get_children())
        if hasattr(self, "log_area") and self.log_area is not None:
            self.log_area.delete(1.0, tk.END)

        self.start_btn.config(state=tk.DISABLED, text="⏳ SCANNING...")
        self.update_progress(0)
        self.total_files_scanned = 0
        self.safe_files_count = 0
        self.update_file_count()
        self.start_time = time.time()
        self.update_timer()
        Thread(target=self.run_scan, daemon=True).start()

    def _show_error_popup(self, title: str, message: str):
        """Show a custom popup with XTRON logo (like success popup style)."""
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=self.colors["bg"])
        win.transient(self.root)
        win.grab_set()
        _script_dir = Path(__file__).parent.resolve()
        # Logo
        for logo_name in ["xtron-logo.png", "logo.png"]:
            logo_path = _script_dir / logo_name
            if logo_path.exists():
                try:
                    from tkinter import PhotoImage
                    img = PhotoImage(file=str(logo_path)).subsample(4, 4)
                    tk.Label(win, image=img, bg=self.colors["bg"]).pack(pady=(16, 8))
                    win._img_ref = img
                    break
                except Exception:
                    pass
        tk.Label(win, text=message, font=("Segoe UI", 11), fg=self.colors["text_light"],
                 bg=self.colors["bg"], wraplength=320, justify=tk.CENTER).pack(padx=24, pady=(0, 16))
        tk.Button(win, text="OK", font=("Segoe UI", 10, "bold"), fg=self.colors["bg"], bg=self.colors["danger"],
                  activebackground="#cc4444", bd=0, padx=24, pady=8, cursor="hand2",
                  command=win.destroy).pack(pady=(0, 16))
        win.update_idletasks()
        win.geometry(f"+{self.root.winfo_x() + (self.root.winfo_width() - win.winfo_reqwidth()) // 2}+{self.root.winfo_y() + 80}")
        win.wait_window()

    def run_scan(self):
        try:
            self.log_message("🔑 Validating scan code...", "INFO")
            if not self.validate_code():
                self.log_message("❌ Invalid or expired scan code", "ERROR")
                self.root.after(0, lambda: self._show_error_popup("Invalid Scan Code", "Invalid or expired scan code.\nPlease enter a valid scan code from the dashboard."))
                self.scan_cleanup()
                return

            self.log_message("📝 Creating scan session...", "INFO")
            if not self.create_scan_result():
                self.log_message("❌ Failed to create scan session", "ERROR")
                self.scan_cleanup()
                return

            self.log_message("✅ Scan session created", "SUCCESS")
            self.perform_scan()
        except Exception as e:
            self.log_message(f"💥 Fatal error: {str(e)}", "ERROR")
        finally:
            self.scan_cleanup()

    def scan_cleanup(self):
        self.scan_running = False
        self.start_btn.config(state=tk.NORMAL, text="▶ START SECURITY SCAN")
        if self.timer_id:
            self.root.after_cancel(self.timer_id)
        self.update_progress(100)
        self.status_label.config(text="● READY", fg=self.colors["success"])

    def validate_code(self) -> bool:
        try:
            payload = {"json": {"code": self.scan_code.get(), "deviceName": self.device_name.get()}}
            r = requests.post(f"{API_BASE_URL}/scanCode.validate", json=payload, timeout=10)
            if r.status_code == 200:
                data = r.json()
                res = data.get("result", {}).get("data", {}).get("json", {})
                if res.get("valid"):
                    self.code_id = res.get("codeId")
                    return True
            return False
        except Exception:
            return False

    def create_scan_result(self) -> bool:
        try:
            payload = {"json": {"scanCodeId": self.code_id or 1, "deviceName": self.device_name.get(),
                                "osVersion": platform.platform(), "systemInfo": self.system_info}}
            r = requests.post(f"{API_BASE_URL}/scanResult.create", json=payload, timeout=10)
            if r.status_code == 200:
                data = r.json()
                self.scan_result_id = data.get("result", {}).get("data", {}).get("json", {}).get("id")
                return bool(self.scan_result_id)
            return False
        except Exception:
            return False

    def perform_scan(self):
        """Main scanning routine."""
        # Determine phases and weight
        phases = []
        if self.scan_fivem.get():
            phases.append(("FiveM Directories", self.scan_fivem_dirs, 30))
        if self.scan_appdata.get():
            phases.append(("User Folders", self.scan_user_folders, 15))
            phases.append(("PC EXE (Program Files)", self.scan_pc_exe_locations, 15))
        if self.scan_registry.get():
            phases.append(("Registry", self.scan_registry_keys, 10))
        if self.scan_memory.get():
            phases.append(("Memory", self.scan_memory_processes, 20))
        if self.scan_forensics.get():
            phases.append(("Forensics", self.scan_forensic_artifacts, 10))
        if self.scan_browser.get():
            phases.append(("Browser History", self.scan_browser_history, 10))

        total_weight = sum(w for _, _, w in phases)
        completed_weight = 0

        for name, func, weight in phases:
            if not self.scan_running:
                return
            self.log_message(f"🔍 Starting {name} scan...", "INFO")
            try:
                func()
            except Exception as e:
                self.log_message(f"   Error in {name}: {str(e)}", "WARN")
            completed_weight += weight
            self.update_progress(completed_weight * 100 / total_weight)

        self.submit_results()

    # --------------------------------------------------------------------------
    # Scanning Modules
    # --------------------------------------------------------------------------

    def _find_fivem_folders_on_drive(self, root: Path, markers: tuple, seen: set, max_depth: int = 5, depth: int = 0) -> None:
        """Recursively find FiveM-related folders anywhere on a drive (e.g. P:\\, C:\\) up to max_depth."""
        if depth >= max_depth or not self.scan_running:
            return
        try:
            for child in root.iterdir():
                if not child.is_dir():
                    continue
                try:
                    name = child.name.lower()
                    if any(m in name for m in markers):
                        p = child.resolve()
                        if str(p) not in seen:
                            seen.add(str(p))
                            self.scan_directory(p, "FiveM (drive)")
                    # Recurse into subdirs to find FiveM folders anywhere on drive
                    self._find_fivem_folders_on_drive(child, markers, seen, max_depth, depth + 1)
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError) as e:
            if depth == 0:
                self.log_message(f"   Drive scan error on {root}: {str(e)[:50]}", "WARN")

    def scan_fivem_dirs(self):
        """Scan FiveM-related folders on ALL drives (any depth). P drive or any drive - find all FiveM/GTA/CFX folders."""
        markers = ("fivem", "citizenfx", "cfx", "fivem application data")
        extra_paths = [
            Path("C:/Program Files/FiveM"),
            Path("C:/Program Files (x86)/FiveM"),
            Path.home() / "AppData" / "Local" / "FiveM",
            Path.home() / "AppData" / "Roaming" / "FiveM",
            Path.home() / "Documents" / "FiveM",
        ]
        seen = set()

        for p in extra_paths:
            if p.exists() and str(p) not in seen:
                seen.add(str(p))
                self.scan_directory(p, "FiveM")

        try:
            for part in psutil.disk_partitions():
                root = Path(part.mountpoint)
                if not root.exists():
                    continue
                self._find_fivem_folders_on_drive(root, markers, seen)
        except Exception as e:
            self.log_message(f"   Drive enumeration error: {e}", "WARN")

    def scan_user_folders(self):
        """Scan common user folders for cheat files."""
        for base in SCAN_LOCATIONS[5:]:  # User folders
            if base.exists():
                self.scan_directory(base, "User")

    def scan_pc_exe_locations(self):
        """Scan Program Files and Program Files (x86) for EXE so more safe exes are reported."""
        for base in [
            Path("C:/Program Files"),
            Path("C:/Program Files (x86)"),
        ]:
            if base.exists():
                self.log_message(f"   Scanning EXE in {base}...", "INFO")
                self.scan_directory(base, "PC EXE")

    def scan_browser_history(self):
        """Check browser history (Chrome, Edge) for visits to cheat/hack sites or login attempts."""
        if platform.system() != "Windows":
            return
        home = Path.home()
        browsers = [
            ("Chrome", home / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History"),
            ("Edge", home / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "History"),
        ]
        for browser_name, history_path in browsers:
            if not history_path.exists():
                continue
            try:
                # Copy to temp to avoid lock when browser is open
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                    tmp_path = tmp.name
                try:
                    shutil.copy2(history_path, tmp_path)
                    conn = sqlite3.connect(tmp_path)
                    conn.row_factory = sqlite3.Row
                    cur = conn.execute(
                        "SELECT url, title, visit_count FROM urls WHERE url IS NOT NULL OR title IS NOT NULL"
                    )
                    found_urls = []
                    for row in cur.fetchall():
                        url = (row["url"] or "").lower()
                        title = (row["title"] or "").lower()
                        combined = f"{url} {title}"
                        for kw in BROWSER_CHEAT_KEYWORDS:
                            if kw.lower() in combined:
                                found_urls.append((url[:150], kw))
                                break
                    if found_urls:
                        keywords_found = ", ".join(sorted(set(k for _, k in found_urls)))
                        self.log_message(
                            f"WARNING: {browser_name} history - {len(found_urls)} cheat/hack-related visit(s) or login attempt(s) | {keywords_found}",
                            "WARN",
                            found_urls[0][0] if found_urls else None,
                        )
                        self.add_artifact_result(
                            f"{browser_name} history: {len(found_urls)} cheat/hack-related URL(s)",
                            f"{browser_name} browser history",
                            "warning",
                            f"User visited or attempted login to cheat/hack-related site(s). Keywords: {keywords_found}",
                            f"browser_{browser_name.lower()}",
                        )
                    else:
                        self.log_message(f"   {browser_name}: No cheat/hack-related history found", "INFO")
                    conn.close()
                finally:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
            except Exception as e:
                self.log_message(f"   Browser ({browser_name}) history check failed: {str(e)[:60]}", "WARN")

    @staticmethod
    def _is_windows_system_path(file_path: Path) -> bool:
        """True if path is under Windows/system locations (official EXEs, not third-party)."""
        path_str = str(file_path).lower()
        return any(
            x in path_str
            for x in (
                "\\windows\\", "\\program files\\", "\\program files (x86)\\",
                "\\winsxs\\", "\\system32\\", "\\syswow64\\", "\\winxs\\",
            )
        )

    def scan_directory(self, path: Path, context: str):
        """Recursively scan a directory for cheat files (skips non-cheat folders for speed)."""
        try:
            for root, dirs, files in os.walk(path, topdown=True):
                if not self.scan_running:
                    return
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in files:
                    file_path = Path(root) / f
                    self.total_files_scanned += 1
                    if self.total_files_scanned % 50 == 0:
                        self.update_file_count()
                    risk, reason = self.analyze_file(file_path)
                    if risk != "safe":
                        self.add_result(file_path, risk, reason, context, is_system_file=False)
                    else:
                        self.safe_files_count += 1
                        self.log_message(f"SAFE: {file_path.name} - {reason}", "INFO", str(file_path))
                        # Include safe .exe in results so they appear in Scanned Files and View details
                        if file_path.suffix.lower() == ".exe":
                            is_sys = self._is_windows_system_path(file_path)
                            self.add_result(file_path, "safe", reason, context, is_system_file=is_sys)
        except Exception as e:
            self.log_message(f"   Error scanning {path}: {str(e)[:50]}", "WARN")

    def analyze_file(self, file_path: Path) -> Tuple[str, str]:
        """Determine if a file is a cheat (detect.ac style - minimal false positives)."""
        name = file_path.name.lower()
        path_str = str(file_path).lower()
        ext = file_path.suffix.lower()

        # 1. Skip normal game asset extensions
        if ext in SKIP_EXTENSIONS:
            return "safe", "Normal game file"

        # 2. Skip safe FiveM/CitizenFX files
        if any(safe.lower() in name for safe in SAFE_FIVEM_FILES):
            return "safe", "Official FiveM file"

        # 3. Trusted Windows / system DLLs (never flag)
        if ext == ".dll":
            if "windows" in path_str or "program files" in path_str or "winsxs" in path_str:
                safe_win = (
                    "api-ms-win-", "vcruntime", "msvcp", "msvcr", "ntdll",
                    "kernel32", "ucrtbase", "wow64", "d3d", "dxgi", "dx11", "dx12",
                    "libraryloader", "clr", "mscorlib", "coreclr",
                )
                if any(name.startswith(p) for p in safe_win):
                    return "safe", "Trusted system DLL"
            # Official FiveM/CitizenFX loaders (any path)
            if "loader-five" in name and ("citizen" in name or "handling" in name or "level" in name):
                return "safe", "Official FiveM loader"

        # 4. Only analyze executables and DLLs for cheat detection
        if ext not in (".exe", ".dll", ".sys"):
            return "safe", "Not executable"

        # 5. Check file hash if enabled
        if self.scan_hashes.get():
            file_hash = FileAnalyzer.calculate_hash(file_path, "md5")
            if file_hash in KNOWN_CHEAT_HASHES:
                return "suspicious", f"Known cheat hash: {KNOWN_CHEAT_HASHES[file_hash]}"

        # 6. SUSPICIOUS only: exact known cheat filename (full match so normal DLLs not flagged)
        for pattern in CHEAT_PATTERNS.get("cheat_exes", []) + CHEAT_PATTERNS.get("cheat_dlls", []):
            if re.fullmatch(pattern, name):
                return "suspicious", f"Known cheat file | {file_path.name}"
        for pattern in CHEAT_PATTERNS.get("cheat_engines", []):
            if re.search(pattern, name) and len(name) < 50:  # avoid long official names
                return "suspicious", f"Known cheat file | {file_path.name}"

        # 7. MODERATE: packed/obfuscated (high entropy) or unsigned-looking exe in Temp only
        path_lower = path_str
        if ext in (".exe", ".dll"):
            if self.scan_entropy.get():
                ent = FileAnalyzer.calculate_entropy(file_path)
                if ent and ent > 7.0:
                    return "moderate", f"Packed/obfuscated file | {file_path.name}"
            if "\\temp\\" in path_lower or "\\tmp\\" in path_lower or path_lower.endswith("\\temp") or path_lower.endswith("\\tmp"):
                return "moderate", f"Executable in temp path | {file_path.name}"

        # 8. WARNING: generic hack-related name only
        for pattern in CHEAT_PATTERNS.get("generic_hack", []):
            if re.search(pattern, name, re.IGNORECASE):
                return "warning", f"Hack-related name | {file_path.name}"

        return "safe", "No threats detected"

    def scan_registry_keys(self):
        """Check for known cheat registry keys."""
        for hkey, subkey in SUSPICIOUS_REGISTRY:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    # Key exists -> cheat trace
                    self.add_registry_result(subkey, "suspicious", "Known cheat registry key")
            except FileNotFoundError:
                pass
            except Exception as e:
                self.log_message(f"   Registry error: {e}", "WARN")

    def scan_memory_processes(self):
        """Scan running processes for cheat names."""
        for proc in psutil.process_iter(['name', 'exe', 'pid']):
            try:
                name = proc.info['name'].lower() if proc.info['name'] else ""
                exe = proc.info['exe'] or ""
                # Check process name against patterns
                for category, patterns in CHEAT_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, name, re.IGNORECASE) or re.search(pattern, exe, re.IGNORECASE):
                            risk = "suspicious" if category in ["cheat_engines", "cheat_exes"] else "warning"
                            self.add_process_result(proc.info, risk, f"Running process matches {pattern}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def scan_forensic_artifacts(self):
        """Prefetch, PowerShell history (detect.ac style detection methods)."""
        prefetch = Path("C:/Windows/Prefetch")
        if prefetch.exists():
            for pf in prefetch.glob("*.pf"):
                name_lower = pf.name.lower()
                if any(x in name_lower for x in ["injector", "loader", "eulen", "cheatengine", "bypass", "spoofer"]):
                    if not any(s in name_lower for s in ["fivem", "citizenfx", "gta5"]):
                        self.add_result(pf, "moderate", "Prefetch entry for cheat-related executable", "Forensics", is_system_file=False)

        ps_hist = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
        if ps_hist.exists():
            try:
                if ps_hist.stat().st_size > 0:
                    self.add_artifact_result(str(ps_hist), "ConsoleHost_history.txt", "warning",
                        "PowerShell history not empty", "PowerShell")
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # Result Handling
    # --------------------------------------------------------------------------

    def add_result(self, file_path: Path, risk: str, reason: str, context: str = "", is_system_file: bool = False):
        """Add a file result to the list and treeview."""
        meta = FileAnalyzer.get_file_metadata(file_path)
        win_details = FileAnalyzer.get_windows_file_details(file_path)
        file_hash = FileAnalyzer.calculate_hash(file_path)
        entropy = FileAnalyzer.calculate_entropy(file_path)

        result = {
            "filePath": str(file_path),
            "fileName": file_path.name,
            "fileType": file_path.suffix,
            "fileSize": meta.get("size", 0),
            "createdDate": meta.get("created"),
            "modifiedDate": meta.get("modified"),
            "riskLevel": risk,
            "detectionReason": reason,
            "fileHash": file_hash,
            "entropy": entropy,
            "windowsDetails": json.dumps(win_details) if isinstance(win_details, dict) else str(win_details),
            "context": context,
            "isSystemFile": is_system_file,
        }
        self.scan_results.append(result)

        if self.tree is not None:
            tag = risk
            self.tree.insert("", tk.END, values=(risk.upper(), file_path.name, str(file_path), reason), tags=(tag,))

        # Log with level matched to risk
        if risk == "suspicious":
            level = "ERROR"
        elif risk in ("warning", "moderate"):
            level = "WARN"
        else:
            level = "INFO"
        self.log_message(f"{risk.upper()}: {file_path.name} - {reason}", level, str(file_path))

    def add_artifact_result(self, file_path: str, file_name: str, risk: str, reason: str, context: str = ""):
        """Add an artifact (e.g. prefetch, PowerShell history) as a result."""
        result = {
            "filePath": file_path,
            "fileName": file_name,
            "fileType": "artifact",
            "fileSize": 0,
            "createdDate": None,
            "modifiedDate": None,
            "riskLevel": risk,
            "detectionReason": reason,
            "fileHash": "",
            "windowsDetails": json.dumps({"type": "artifact", "context": context}),
            "context": context,
            "isSystemFile": False,
        }
        self.scan_results.append(result)
        if self.tree is not None:
            self.tree.insert("", tk.END, values=(risk.upper(), file_name, file_path, reason), tags=(risk,))
        level = "ERROR" if risk == "suspicious" else "WARN"
        self.log_message(f"{risk.upper()}: {reason} | {file_name}", level, file_path)

    def add_registry_result(self, key: str, risk: str, reason: str):
        """Add a registry detection."""
        display_path = f"REGISTRY::{key}"
        result = {
            "filePath": display_path,
            "fileName": key.split("\\")[-1] or key,
            "fileType": "registry",
            "fileSize": 0,
            "riskLevel": risk,
            "detectionReason": reason,
            "fileHash": "",
            "windowsDetails": json.dumps({"type": "registry", "key": key}),
            "isSystemFile": False,
        }
        self.scan_results.append(result)
        if self.tree is not None:
            self.tree.insert("", tk.END, values=(risk.upper(), "[Registry]", key, reason), tags=(risk,))
        # Log with level matched to risk
        if risk == "suspicious":
            level = "ERROR"
        elif risk in ("warning", "moderate"):
            level = "WARN"
        else:
            level = "INFO"
        self.log_message(f"{risk.upper()}: Registry {key} - {reason}", level)

    def add_process_result(self, proc_info: dict, risk: str, reason: str):
        """Add a running process detection."""
        name = proc_info.get('name', '') or 'Unknown'
        pid = proc_info.get('pid', '')
        exe = proc_info.get('exe', '') or ''
        display = f"{name} (PID: {pid})"
        pseudo_path = exe or f"PROCESS::{name}"
        result = {
            "filePath": pseudo_path,
            "fileName": name,
            "fileType": "process",
            "fileSize": 0,
            "riskLevel": risk,
            "detectionReason": reason,
            "fileHash": "",
            "windowsDetails": json.dumps({"type": "process", "exe": exe, "pid": pid}),
            "isSystemFile": False,
        }
        self.scan_results.append(result)
        if self.tree is not None:
            self.tree.insert("", tk.END, values=(risk.upper(), display, exe, reason), tags=(risk,))
        # Log with level matched to risk
        if risk == "suspicious":
            level = "ERROR"
        elif risk in ("warning", "moderate"):
            level = "WARN"
        else:
            level = "INFO"
        self.log_message(f"{risk.upper()}: Process {display} - {reason}", level)

    def submit_results(self):
        """Upload results to backend (if available) and show summary."""
        if not self.scan_result_id:
            return
        try:
            self.log_message("📤 Submitting results...", "INFO")
            all_results = list(self.scan_results)

            # Derive folder-level detections (suspicious folders) based on file results
            folder_stats: Dict[str, Dict[str, int]] = {}
            for res in self.scan_results:
                fp = res.get("filePath")
                risk = res.get("riskLevel", "safe")
                ftype = res.get("fileType")
                if not fp or risk == "safe" or ftype in ("folder", "registry", "process", "artifact"):
                    continue
                try:
                    folder = str(Path(fp).parent)
                except Exception:
                    continue
                if folder not in folder_stats:
                    folder_stats[folder] = {"suspicious": 0, "warning": 0, "moderate": 0}
                if risk in folder_stats[folder]:
                    folder_stats[folder][risk] += 1

            folder_results = []
            for folder, stats in folder_stats.items():
                sus = stats["suspicious"]
                warn = stats["warning"]
                mod = stats["moderate"]
                total_flags = sus + warn + mod
                if total_flags == 0:
                    continue
                # Decide folder risk level
                if sus >= 2 or (sus >= 1 and warn >= 1):
                    folder_risk = "suspicious"
                elif sus == 1 or warn >= 3:
                    folder_risk = "moderate"
                else:
                    folder_risk = "warning"

                reason = f"Folder contains {sus} suspicious, {warn} warning, {mod} moderate detections"
                folder_result = {
                    "filePath": folder,
                    "fileName": Path(folder).name or folder,
                    "fileType": "folder",
                    "fileSize": 0,
                    "createdDate": None,
                    "modifiedDate": None,
                    "riskLevel": folder_risk,
                    "detectionReason": reason,
                    "fileHash": "",
                    "entropy": None,
                    "windowsDetails": json.dumps({"type": "folder_summary", "stats": stats}),
                    "context": "Folder summary",
                    "isSystemFile": False,
                }
                folder_results.append(folder_result)
                # Also log folder-level detection
                log_level = "ERROR" if folder_risk == "suspicious" else "WARN"
                self.log_message(f"{folder_risk.upper()}: Folder {folder} - {reason}", log_level, folder)

            if folder_results:
                all_results.extend(folder_results)

            if all_results:
                batch_size = 50
                for i in range(0, len(all_results), batch_size):
                    batch = all_results[i:i+batch_size]
                    payload = {"json": {"scanResultId": self.scan_result_id, "files": batch}}
                    requests.post(f"{API_BASE_URL}/scanResult.addFiles", json=payload, timeout=30)

            risk_counts = {"suspicious": 0, "warning": 0, "moderate": 0, "safe": getattr(self, "safe_files_count", 0)}
            for res in all_results:
                risk_counts[res.get("riskLevel", "safe")] += 1
            risk_counts["safe"] = getattr(self, "safe_files_count", 0)

            # So backend shows correct safe count and total (scanner does not submit safe file rows)
            set_counts_payload = {
                "json": {
                    "scanResultId": self.scan_result_id,
                    "totalFilesScanned": self.total_files_scanned,
                    "suspiciousCount": risk_counts["suspicious"],
                    "warningCount": risk_counts["warning"],
                    "moderateCount": risk_counts["moderate"],
                    "safeCount": risk_counts["safe"],
                }
            }
            try:
                requests.post(f"{API_BASE_URL}/scanResult.setCounts", json=set_counts_payload, timeout=10)
            except Exception:
                pass

            if risk_counts["suspicious"] > 0:
                self.overall_risk_level = "suspicious"
            elif risk_counts["warning"] > 0:
                self.overall_risk_level = "warning"
            elif risk_counts["moderate"] > 0:
                self.overall_risk_level = "moderate"
            else:
                self.overall_risk_level = "safe"

            # Update status on backend
            payload = {"json": {"scanResultId": self.scan_result_id, "status": "completed",
                                "overallRiskLevel": self.overall_risk_level}}
            requests.post(f"{API_BASE_URL}/scanResult.updateStatus", json=payload, timeout=10)

            # Show simple completion message and close app
            self.log_message("✅ Scan Successfully Completed", "SUCCESS")
            messagebox.showinfo("Scan Complete", "Scan Successfully Completed")
            try:
                # Close the scanner automatically after a short delay
                self.root.after(500, self.root.destroy)
            except Exception:
                pass
        except Exception as e:
            self.log_message(f"❌ Upload error: {e}", "ERROR")

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.iconbitmap(default='icon.ico')
    except:
        pass
    app = FiveXCheckScannerPro(root)
    root.mainloop()