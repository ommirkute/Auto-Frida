#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     █████╗ ██╗   ██╗████████╗ ██████╗     ███████╗██████╗ ██╗██████╗  █████╗  ║
║    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗ ║
║    ███████║██║   ██║   ██║   ██║   ██║    █████╗  ██████╔╝██║██║  ██║███████║ ║
║    ██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║ ║
║    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║     ██║  ██║██║██████╔╝██║  ██║ ║
║    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝ ║
║                                                                               ║
║                    AUTO FRIDA v1.0 - Android Security Toolkit                 ║
║                         Created by: Omkar Mirkute                             ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Auto Frida v1.0 - Complete Android Security Testing Automation for Windows
Created by: Omkar Mirkute

Description:
    Auto Frida is a powerful, all-in-one automation toolkit that handles everything
    from Frida installation to script injection. Zero manual setup required – just
    connect your device and start testing.

Key Features:
    • Auto Installation    - Installs Frida on Windows & Android automatically
    • SSL Pinning Bypass   - Universal SSL/TLS certificate pinning bypass
    • Root Detection Bypass- Bypass root detection in banking/security apps
    • Flutter SSL Bypass   - Specialized bypass for Flutter/Dart applications
    • Custom Scripts       - Load and execute your own Frida scripts
    • Frida CodeShare      - Run scripts directly from Frida CodeShare
    • 3-Layer Validation   - Robust Frida server management
    • PID-based Attach     - Reliable attachment using process ID
    • Smart Lifecycle      - Idempotent server management

Usage:
    python auto_frida.py

Requirements:
    - Python 3.8+
    - Windows OS
    - ADB (Android Debug Bridge)
    - USB Debugging enabled on Android device
    - Rooted device (for Spawn mode) or non-rooted (Attach mode only)

License: MIT
Repository: https://github.com/omkarmirkute/auto-frida
"""

__title__ = "Auto Frida"
__version__ = "1.0"
__author__ = "Omkar Mirkute"
__license__ = "MIT"
__copyright__ = "Copyright 2024 Omkar Mirkute"

import subprocess
import sys
import os
import re
import json
import time
import lzma
import shutil
import logging
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Union
from dataclasses import dataclass
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

LOG_DIR = Path('logs')
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'auto_frida.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# ANSI COLORS FOR WINDOWS TERMINAL
# ═══════════════════════════════════════════════════════════════════════════════

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


# Enable ANSI colors on Windows
os.system('')


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DeviceInfo:
    """Information about connected Android device"""
    serial: str
    state: str
    model: str = ""
    architecture: str = ""
    is_rooted: bool = False
    selinux_enforcing: bool = True


@dataclass
class AppInfo:
    """Information about an Android application"""
    pid: Optional[int]
    name: str           # Display name
    identifier: str     # Package identifier (used for spawning)


@dataclass
class FridaServerStatus:
    """Detailed status of Frida server with 3-layer validation"""
    process_running: bool = False
    process_pid: Optional[int] = None
    port_bound: bool = False
    protocol_ok: bool = False
    error_message: str = ""
    
    @property
    def is_fully_operational(self) -> bool:
        """Server is fully operational only if all 3 layers pass"""
        return self.process_running and self.port_bound and self.protocol_ok
    
    @property
    def needs_restart(self) -> bool:
        """Server needs restart if process exists but port/protocol fails"""
        return self.process_running and (not self.port_bound or not self.protocol_ok)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN AUTO FRIDA CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class AutoFrida:
    """
    Auto Frida - Complete Android Security Testing Automation
    
    Created by: Omkar Mirkute
    Version: 1.0
    
    This class orchestrates the entire Frida automation workflow:
    1. Environment validation (Python, pip, Frida)
    2. ADB & device detection
    3. Architecture detection + root/SELinux analysis
    4. Smart Frida server lifecycle with 3-layer validation
    5. App enumeration
    6. Target selection
    7. Script management (local + CodeShare)
    8. Script execution (Spawn/Attach modes)
    """
    
    # Architecture mapping for Frida server download
    ARCH_MAP = {
        'arm64-v8a': 'android-arm64',
        'armeabi-v7a': 'android-arm',
        'x86': 'android-x86',
        'x86_64': 'android-x86_64'
    }
    
    # Frida server configuration
    FRIDA_SERVER_PATH = '/data/local/tmp/fridaserver'
    FRIDA_DEFAULT_PORT = 27042
    
    # Directory configuration
    SCRIPTS_DIR = Path('scripts')
    LOGS_DIR = Path('logs')
    
    # Navigation constants
    GO_BACK = "GO_BACK"
    EXIT_PROGRAM = "EXIT_PROGRAM"
    CODESHARE_PREFIX = "codeshare:"
    
    def __init__(self):
        """Initialize Auto Frida"""
        self.frida_version: str = ""
        self.device: Optional[DeviceInfo] = None
        self.apps: List[AppInfo] = []
        self._ensure_directories()
        
        # Log startup
        logger.info(f"Auto Frida v{__version__} initialized")
        logger.info(f"Created by: {__author__}")
    
    def _exit_program(self):
        """Exit the program gracefully"""
        print(f"\n{Colors.GREEN}{'═' * 60}{Colors.END}")
        print(f"{Colors.GREEN}  Auto Frida Session Complete - Goodbye!{Colors.END}")
        print(f"{Colors.GREEN}  Created by: {__author__}{Colors.END}")
        print(f"{Colors.GREEN}{'═' * 60}{Colors.END}")
        sys.exit(0)
    
    def _ensure_directories(self):
        """Create necessary directories"""
        self.SCRIPTS_DIR.mkdir(exist_ok=True)
        self.LOGS_DIR.mkdir(exist_ok=True)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # INPUT HANDLING UTILITIES
    # ═══════════════════════════════════════════════════════════════════════════
    
    def safe_input(self, prompt: str) -> str:
        """Safely get user input, handling any exceptions"""
        try:
            return input(prompt).strip()
        except EOFError:
            return ""
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Operation cancelled by user{Colors.END}")
            return ""
    
    def get_valid_input(self, prompt: str, valid_options: List[str], 
                        case_sensitive: bool = False,
                        allow_empty: bool = False) -> str:
        """
        Get validated input from user with retry on invalid input
        
        Args:
            prompt: The prompt to display
            valid_options: List of valid options
            case_sensitive: Whether to check case-sensitively
            allow_empty: Whether to allow empty input
            
        Returns:
            Valid user input
        """
        while True:
            user_input = self.safe_input(prompt)
            
            if not user_input and not allow_empty:
                print(f"{Colors.RED}[!] Invalid option. Please enter a valid option{Colors.END}")
                continue
            
            check_input = user_input if case_sensitive else user_input.lower()
            check_options = valid_options if case_sensitive else [o.lower() for o in valid_options]
            
            if check_input in check_options:
                return user_input
            
            print(f"{Colors.RED}[!] Invalid option. Valid options: {', '.join(valid_options)}{Colors.END}")
    
    def get_numeric_input(self, prompt: str, min_val: int, max_val: int, 
                          allow_special: List[str] = None) -> Tuple[bool, any]:
        """
        Get a numeric input within range or special string commands
        
        Args:
            prompt: The prompt to display
            min_val: Minimum valid number
            max_val: Maximum valid number
            allow_special: List of special string commands to accept (e.g., ['b', 'c'])
            
        Returns:
            Tuple of (is_number, value) - if is_number is True, value is int; else it's the special string
        """
        allow_special = allow_special or []
        
        while True:
            user_input = self.safe_input(prompt)
            
            if not user_input:
                print(f"{Colors.RED}[!] Invalid option. Please enter a valid option{Colors.END}")
                continue
            
            # Check for special commands first
            if allow_special:
                if user_input.lower() in [s.lower() for s in allow_special]:
                    return (False, user_input.lower())
            
            # Try to parse as number
            try:
                num = int(user_input)
                if min_val <= num <= max_val:
                    return (True, num)
                else:
                    if allow_special:
                        print(f"{Colors.RED}[!] Invalid option. Enter {min_val}-{max_val} or {'/'.join(allow_special)}{Colors.END}")
                    else:
                        print(f"{Colors.RED}[!] Invalid option. Enter a number between {min_val} and {max_val}{Colors.END}")
            except ValueError:
                if allow_special:
                    print(f"{Colors.RED}[!] Invalid option. Enter {min_val}-{max_val} or {'/'.join(allow_special)}{Colors.END}")
                else:
                    print(f"{Colors.RED}[!] Invalid option. Please enter a valid number{Colors.END}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # BANNER & UI
    # ═══════════════════════════════════════════════════════════════════════════
    
    def print_banner(self):
        """Display Auto Frida banner"""
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   {Colors.GREEN}█████╗ ██╗   ██╗████████╗ ██████╗     ███████╗██████╗ ██╗██████╗  █████╗{Colors.CYAN} ║
║  {Colors.GREEN}██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗{Colors.CYAN}║
║  {Colors.GREEN}███████║██║   ██║   ██║   ██║   ██║    █████╗  ██████╔╝██║██║  ██║███████║{Colors.CYAN}║
║  {Colors.GREEN}██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║{Colors.CYAN}║
║  {Colors.GREEN}██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║     ██║  ██║██║██████╔╝██║  ██║{Colors.CYAN}║
║  {Colors.GREEN}╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝{Colors.CYAN}║
║                                                                          ║
║        {Colors.WHITE}AUTO FRIDA v{__version__} - Android Security Testing Automation{Colors.CYAN}        ║
║                    {Colors.YELLOW}Created by: {__author__}{Colors.CYAN}                          ║
║                                                                          ║
║   {Colors.PURPLE}▸ Auto Frida Installation    ▸ SSL Pinning Bypass{Colors.CYAN}                    ║
║   {Colors.PURPLE}▸ Root Detection Bypass      ▸ Flutter SSL Bypass{Colors.CYAN}                    ║
║   {Colors.PURPLE}▸ Frida CodeShare Support    ▸ Custom Script Support{Colors.CYAN}                 ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.END}
"""
        print(banner)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # COMMAND EXECUTION UTILITIES
    # ═══════════════════════════════════════════════════════════════════════════
    
    def run_command(self, cmd: List[str], check: bool = True, capture: bool = True, 
                    timeout: int = 30) -> subprocess.CompletedProcess:
        """Execute a command and return result"""
        try:
            # On Windows, we need shell=True for some commands
            use_shell = sys.platform == 'win32'
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                check=check,
                shell=use_shell,
                timeout=timeout
            )
            return result
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {' '.join(cmd)}")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)}")
            logger.error(f"Error: {e.stderr}")
            raise
    
    def adb_command(self, args: List[str], check: bool = True, 
                    timeout: int = 30) -> subprocess.CompletedProcess:
        """Run ADB command with device serial"""
        cmd = ['adb']
        if self.device:
            cmd.extend(['-s', self.device.serial])
        cmd.extend(args)
        return self.run_command(cmd, check=check, timeout=timeout)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1: ENVIRONMENT VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def check_python(self) -> bool:
        """Verify Python version >= 3.8"""
        print(f"\n{Colors.BLUE}[*] Checking Python version...{Colors.END}")
        
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print(f"{Colors.RED}[!] Python 3.8+ required. Current: {version.major}.{version.minor}{Colors.END}")
            return False
        
        print(f"{Colors.GREEN}[✓] Python {version.major}.{version.minor}.{version.micro}{Colors.END}")
        return True
    
    def check_pip(self) -> bool:
        """Verify pip is available"""
        print(f"{Colors.BLUE}[*] Checking pip...{Colors.END}")
        
        try:
            result = self.run_command(['pip', '--version'])
            print(f"{Colors.GREEN}[✓] pip available{Colors.END}")
            return True
        except Exception:
            print(f"{Colors.RED}[!] pip not found{Colors.END}")
            return False
    
    def check_frida(self) -> bool:
        """Check and install Frida & Frida-tools"""
        print(f"\n{Colors.BLUE}[*] Checking Frida installation...{Colors.END}")
        
        try:
            result = self.run_command(['frida', '--version'])
            self.frida_version = result.stdout.strip()
            print(f"{Colors.GREEN}[✓] Frida {self.frida_version}{Colors.END}")
            
            # Check Frida version for compatibility warnings
            try:
                major_version = int(self.frida_version.split('.')[0])
                if major_version >= 16:
                    print(f"{Colors.CYAN}    ℹ Frida 16+ detected - using compatible syntax{Colors.END}")
            except (ValueError, IndexError):
                pass
            
            # Also check frida-ps
            self.run_command(['frida-ps', '--version'])
            print(f"{Colors.GREEN}[✓] Frida-tools available{Colors.END}")
            return True
            
        except Exception:
            print(f"{Colors.YELLOW}[!] Frida not found. Installing...{Colors.END}")
            return self._install_frida()
    
    def _install_frida(self) -> bool:
        """Install Frida and Frida-tools via pip"""
        try:
            print(f"{Colors.BLUE}[*] Installing frida and frida-tools...{Colors.END}")
            self.run_command(['pip', 'install', 'frida', 'frida-tools'], timeout=120)
            
            # Get version after install
            result = self.run_command(['frida', '--version'])
            self.frida_version = result.stdout.strip()
            print(f"{Colors.GREEN}[✓] Installed Frida {self.frida_version}{Colors.END}")
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to install Frida: {e}{Colors.END}")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2: ADB & DEVICE DETECTION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def check_adb(self) -> bool:
        """Verify ADB is available"""
        print(f"\n{Colors.BLUE}[*] Checking ADB...{Colors.END}")
        
        try:
            result = self.run_command(['adb', 'version'])
            version_line = result.stdout.split('\n')[0]
            print(f"{Colors.GREEN}[✓] {version_line}{Colors.END}")
            return True
        except Exception:
            print(f"{Colors.RED}[!] ADB not found. Please install Android SDK Platform Tools{Colors.END}")
            print(f"{Colors.YELLOW}    Download: https://developer.android.com/studio/releases/platform-tools{Colors.END}")
            return False
    
    def detect_device(self) -> bool:
        """Detect connected Android devices"""
        print(f"\n{Colors.BLUE}[*] Detecting devices...{Colors.END}")
        
        result = self.run_command(['adb', 'devices', '-l'])
        lines = result.stdout.strip().split('\n')[1:]  # Skip header
        
        devices = []
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    serial = parts[0]
                    state = parts[1]
                    model = ""
                    for part in parts:
                        if part.startswith('model:'):
                            model = part.split(':')[1]
                    devices.append(DeviceInfo(serial=serial, state=state, model=model))
        
        if not devices:
            print(f"{Colors.RED}[!] No devices connected{Colors.END}")
            print(f"{Colors.YELLOW}    • Connect device via USB{Colors.END}")
            print(f"{Colors.YELLOW}    • Enable USB debugging in Developer Options{Colors.END}")
            return False
        
        # Check for unauthorized devices
        unauthorized = [d for d in devices if d.state == 'unauthorized']
        if unauthorized:
            print(f"{Colors.YELLOW}[!] Device {unauthorized[0].serial} is unauthorized{Colors.END}")
            print(f"{Colors.YELLOW}    Please accept the RSA key prompt on the device{Colors.END}")
            self.safe_input(f"{Colors.CYAN}    Press Enter after accepting...{Colors.END}")
            return self.detect_device()  # Retry
        
        # Filter to only connected devices
        connected = [d for d in devices if d.state == 'device']
        
        if not connected:
            print(f"{Colors.RED}[!] No authorized devices found{Colors.END}")
            return False
        
        if len(connected) == 1:
            self.device = connected[0]
        else:
            # Multiple devices - prompt selection with validation
            print(f"\n{Colors.CYAN}Multiple devices found:{Colors.END}")
            for i, dev in enumerate(connected, 1):
                print(f"  {i}. {dev.serial} ({dev.model or 'Unknown model'})")
            
            is_num, value = self.get_numeric_input(
                f"\n{Colors.CYAN}Select device (1-{len(connected)}): {Colors.END}",
                1, len(connected)
            )
            self.device = connected[value - 1]
        
        print(f"{Colors.GREEN}[✓] Using device: {self.device.serial} ({self.device.model or 'Unknown'}){Colors.END}")
        return True
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3: ARCHITECTURE DETECTION + ROOT/SELINUX CHECK
    # ═══════════════════════════════════════════════════════════════════════════
    
    def detect_architecture(self) -> bool:
        """Detect device CPU architecture"""
        print(f"\n{Colors.BLUE}[*] Detecting CPU architecture...{Colors.END}")
        
        result = self.adb_command(['shell', 'getprop', 'ro.product.cpu.abi'])
        abi = result.stdout.strip()
        
        if abi not in self.ARCH_MAP:
            print(f"{Colors.RED}[!] Unknown architecture: {abi}{Colors.END}")
            return False
        
        self.device.architecture = self.ARCH_MAP[abi]
        print(f"{Colors.GREEN}[✓] Architecture: {abi} → {self.device.architecture}{Colors.END}")
        return True
    
    def check_root_access(self) -> bool:
        """Check if device has root access"""
        print(f"\n{Colors.BLUE}[*] Checking root access...{Colors.END}")
        
        # Method 1: Check if 'su' binary exists
        try:
            result = self.adb_command(['shell', 'which su'], check=False)
            if result.returncode == 0 and result.stdout.strip():
                print(f"{Colors.GREEN}[✓] Root binary found: {result.stdout.strip()}{Colors.END}")
                
                # Method 2: Try to actually get root
                result = self.adb_command(['shell', 'su -c id'], check=False)
                if result.returncode == 0 and 'uid=0' in result.stdout:
                    print(f"{Colors.GREEN}[✓] Root access confirmed{Colors.END}")
                    self.device.is_rooted = True
                    return True
                else:
                    print(f"{Colors.YELLOW}[!] Root binary exists but access denied{Colors.END}")
                    print(f"{Colors.YELLOW}    Grant root access in Magisk/SuperSU{Colors.END}")
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[!] Root check timed out - may need manual approval{Colors.END}")
        except Exception as e:
            logger.debug(f"Root check failed: {e}")
        
        print(f"{Colors.YELLOW}[!] Device may not be rooted - Spawn mode may fail{Colors.END}")
        print(f"{Colors.YELLOW}    Attach mode will still work for running apps{Colors.END}")
        self.device.is_rooted = False
        return True  # Continue anyway, let user decide
    
    def check_selinux(self) -> bool:
        """Check and handle SELinux status"""
        print(f"\n{Colors.BLUE}[*] Checking SELinux status...{Colors.END}")
        
        try:
            result = self.adb_command(['shell', 'getenforce'], check=False)
            selinux_status = result.stdout.strip().lower()
            
            if selinux_status == 'enforcing':
                print(f"{Colors.YELLOW}[!] SELinux is Enforcing - may block Frida{Colors.END}")
                self.device.selinux_enforcing = True
                
                if self.device.is_rooted:
                    print(f"{Colors.BLUE}[*] Attempting to set SELinux to Permissive...{Colors.END}")
                    result = self.adb_command(['shell', 'su -c setenforce 0'], check=False)
                    
                    # Verify
                    result = self.adb_command(['shell', 'getenforce'], check=False)
                    if result.stdout.strip().lower() == 'permissive':
                        print(f"{Colors.GREEN}[✓] SELinux set to Permissive{Colors.END}")
                        self.device.selinux_enforcing = False
                    else:
                        print(f"{Colors.YELLOW}[!] Could not change SELinux mode{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}    Tip: Use Magisk to manage SELinux{Colors.END}")
            
            elif selinux_status == 'permissive':
                print(f"{Colors.GREEN}[✓] SELinux is Permissive{Colors.END}")
                self.device.selinux_enforcing = False
            
            elif selinux_status == 'disabled':
                print(f"{Colors.GREEN}[✓] SELinux is Disabled{Colors.END}")
                self.device.selinux_enforcing = False
            
            else:
                print(f"{Colors.YELLOW}[?] SELinux status: {selinux_status}{Colors.END}")
            
            return True
            
        except Exception as e:
            logger.warning(f"SELinux check failed: {e}")
            return True  # Continue anyway
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4: SMART FRIDA SERVER LIFECYCLE (3-LAYER VALIDATION)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _check_frida_process_on_device(self) -> Tuple[bool, Optional[int]]:
        """
        Layer 1: Check if fridaserver process is running on device
        
        Returns:
            Tuple of (is_running, pid or None)
        """
        print(f"{Colors.CYAN}    [Layer 1] Checking fridaserver process...{Colors.END}")
        
        # Method 1: Try pidof (more reliable, available on Android 5.0+)
        try:
            result = self.adb_command(
                ['shell', 'pidof', 'fridaserver'],
                check=False,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                pid_str = result.stdout.strip().split()[0]
                try:
                    pid = int(pid_str)
                    print(f"{Colors.GREEN}    [✓] Layer 1 PASS: fridaserver running (PID: {pid}){Colors.END}")
                    return (True, pid)
                except ValueError:
                    pass
        except subprocess.TimeoutExpired:
            logger.debug("pidof command timed out")
        except Exception as e:
            logger.debug(f"pidof failed: {e}")
        
        # Method 2: Fallback to ps + grep
        try:
            result = self.adb_command(
                ['shell', 'ps -A 2>/dev/null | grep -E "fridaserver|frida-server" | grep -v grep'],
                check=False,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[1])
                            print(f"{Colors.GREEN}    [✓] Layer 1 PASS: fridaserver running (PID: {pid}){Colors.END}")
                            return (True, pid)
                        except ValueError:
                            try:
                                pid = int(parts[0])
                                print(f"{Colors.GREEN}    [✓] Layer 1 PASS: fridaserver running (PID: {pid}){Colors.END}")
                                return (True, pid)
                            except ValueError:
                                continue
        except subprocess.TimeoutExpired:
            logger.debug("ps command timed out")
        except Exception as e:
            logger.debug(f"ps fallback failed: {e}")
        
        # Method 3: Try ps without -A flag (legacy Android)
        try:
            result = self.adb_command(
                ['shell', 'ps | grep -E "fridaserver|frida-server" | grep -v grep'],
                check=False,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[1])
                            print(f"{Colors.GREEN}    [✓] Layer 1 PASS: fridaserver running (PID: {pid}){Colors.END}")
                            return (True, pid)
                        except ValueError:
                            continue
        except Exception as e:
            logger.debug(f"Legacy ps failed: {e}")
        
        print(f"{Colors.YELLOW}    [✗] Layer 1 FAIL: fridaserver process not found{Colors.END}")
        return (False, None)
    
    def _check_frida_port_binding(self) -> bool:
        """
        Layer 2: Check if Frida server port (27042) is bound and listening
        
        Returns:
            True if port 27042 is listening, False otherwise
        """
        print(f"{Colors.CYAN}    [Layer 2] Checking port {self.FRIDA_DEFAULT_PORT} binding...{Colors.END}")
        
        # Method 1: Try ss command (modern Linux/Android)
        try:
            result = self.adb_command(
                ['shell', f'ss -lntp 2>/dev/null | grep ":{self.FRIDA_DEFAULT_PORT}"'],
                check=False,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                if str(self.FRIDA_DEFAULT_PORT) in result.stdout:
                    print(f"{Colors.GREEN}    [✓] Layer 2 PASS: Port {self.FRIDA_DEFAULT_PORT} is listening{Colors.END}")
                    return True
        except subprocess.TimeoutExpired:
            logger.debug("ss command timed out")
        except Exception as e:
            logger.debug(f"ss command failed: {e}")
        
        # Method 2: Try netstat
        try:
            result = self.adb_command(
                ['shell', f'netstat -tlnp 2>/dev/null | grep ":{self.FRIDA_DEFAULT_PORT}"'],
                check=False,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                if str(self.FRIDA_DEFAULT_PORT) in result.stdout:
                    print(f"{Colors.GREEN}    [✓] Layer 2 PASS: Port {self.FRIDA_DEFAULT_PORT} is listening{Colors.END}")
                    return True
        except subprocess.TimeoutExpired:
            logger.debug("netstat command timed out")
        except Exception as e:
            logger.debug(f"netstat command failed: {e}")
        
        # Method 3: Try netstat without -p flag
        try:
            result = self.adb_command(
                ['shell', f'netstat -tln 2>/dev/null | grep ":{self.FRIDA_DEFAULT_PORT}"'],
                check=False,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                if str(self.FRIDA_DEFAULT_PORT) in result.stdout:
                    print(f"{Colors.GREEN}    [✓] Layer 2 PASS: Port {self.FRIDA_DEFAULT_PORT} is listening{Colors.END}")
                    return True
        except Exception as e:
            logger.debug(f"netstat -tln failed: {e}")
        
        # Method 4: Try cat /proc/net/tcp
        try:
            hex_port = format(self.FRIDA_DEFAULT_PORT, 'X').upper()
            result = self.adb_command(
                ['shell', f'cat /proc/net/tcp 2>/dev/null | grep ":{hex_port}"'],
                check=False,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                print(f"{Colors.GREEN}    [✓] Layer 2 PASS: Port {self.FRIDA_DEFAULT_PORT} found in /proc/net/tcp{Colors.END}")
                return True
        except Exception as e:
            logger.debug(f"/proc/net/tcp check failed: {e}")
        
        print(f"{Colors.YELLOW}    [✗] Layer 2 FAIL: Port {self.FRIDA_DEFAULT_PORT} not listening{Colors.END}")
        return False
    
    def _check_frida_protocol_handshake(self) -> bool:
        """
        Layer 3: Verify Frida protocol handshake via frida-ps --json
        
        Returns:
            True if protocol handshake succeeds, False otherwise
        """
        print(f"{Colors.CYAN}    [Layer 3] Checking Frida protocol handshake...{Colors.END}")
        
        try:
            result = self.run_command(
                ['frida-ps', '-U', '--json'],
                check=False,
                timeout=10
            )
            
            if result.returncode != 0:
                print(f"{Colors.YELLOW}    [✗] Layer 3 FAIL: frida-ps returned error{Colors.END}")
                if result.stderr:
                    logger.debug(f"frida-ps stderr: {result.stderr}")
                return False
            
            output = result.stdout.strip()
            
            if not output:
                print(f"{Colors.YELLOW}    [✗] Layer 3 FAIL: Empty response from frida-ps{Colors.END}")
                return False
            
            if not (output.startswith('[') or output.startswith('{')):
                print(f"{Colors.YELLOW}    [✗] Layer 3 FAIL: Invalid JSON response{Colors.END}")
                return False
            
            try:
                parsed = json.loads(output)
                
                if isinstance(parsed, list):
                    process_count = len(parsed)
                    print(f"{Colors.GREEN}    [✓] Layer 3 PASS: Protocol OK ({process_count} processes){Colors.END}")
                    return True
                elif isinstance(parsed, dict):
                    print(f"{Colors.GREEN}    [✓] Layer 3 PASS: Protocol OK (valid response){Colors.END}")
                    return True
                else:
                    print(f"{Colors.YELLOW}    [✗] Layer 3 FAIL: Unexpected JSON structure{Colors.END}")
                    return False
                    
            except json.JSONDecodeError as e:
                print(f"{Colors.YELLOW}    [✗] Layer 3 FAIL: JSON parse error - {e}{Colors.END}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}    [✗] Layer 3 FAIL: Protocol handshake timed out{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.YELLOW}    [✗] Layer 3 FAIL: {e}{Colors.END}")
            return False
    
    def get_frida_server_status(self) -> FridaServerStatus:
        """
        Perform comprehensive 3-layer Frida server validation
        
        Returns:
            FridaServerStatus with detailed state information
        """
        print(f"\n{Colors.BLUE}[*] Performing 3-layer Frida server validation...{Colors.END}")
        
        status = FridaServerStatus()
        
        # Layer 1: Process check
        process_running, pid = self._check_frida_process_on_device()
        status.process_running = process_running
        status.process_pid = pid
        
        if not process_running:
            status.error_message = "Frida server process not running on device"
            return status
        
        # Layer 2: Port binding check
        status.port_bound = self._check_frida_port_binding()
        
        if not status.port_bound:
            status.error_message = f"Frida server running but port {self.FRIDA_DEFAULT_PORT} not bound"
            return status
        
        # Layer 3: Protocol handshake
        status.protocol_ok = self._check_frida_protocol_handshake()
        
        if not status.protocol_ok:
            status.error_message = "Frida server running but protocol handshake failed"
            return status
        
        return status
    
    def is_frida_server_running(self) -> bool:
        """Check if Frida server is fully operational using 3-layer validation"""
        print(f"\n{Colors.BLUE}[*] Checking Frida server status...{Colors.END}")
        
        status = self.get_frida_server_status()
        
        if status.is_fully_operational:
            print(f"{Colors.GREEN}[✓] Frida server is fully operational!{Colors.END}")
            return True
        
        print(f"\n{Colors.YELLOW}[!] Frida server validation failed{Colors.END}")
        print(f"{Colors.CYAN}    Status Summary:{Colors.END}")
        print(f"      • Process running: {'✓' if status.process_running else '✗'} {f'(PID: {status.process_pid})' if status.process_pid else ''}")
        print(f"      • Port bound:      {'✓' if status.port_bound else '✗'}")
        print(f"      • Protocol OK:     {'✓' if status.protocol_ok else '✗'}")
        
        if status.error_message:
            print(f"{Colors.YELLOW}    Issue: {status.error_message}{Colors.END}")
        
        if status.needs_restart:
            print(f"{Colors.YELLOW}    → Server needs restart{Colors.END}")
        
        return False
    
    def kill_frida_server(self) -> bool:
        """Kill any existing Frida server processes on device"""
        print(f"{Colors.CYAN}    Killing existing Frida server processes...{Colors.END}")
        
        try:
            if self.device.is_rooted:
                self.adb_command(['shell', 'su -c "pkill -9 -f fridaserver"'], check=False, timeout=5)
                self.adb_command(['shell', 'su -c "pkill -9 -f frida-server"'], check=False, timeout=5)
                self.adb_command(['shell', f'su -c "pkill -9 -f {self.FRIDA_SERVER_PATH}"'], check=False, timeout=5)
            else:
                self.adb_command(['shell', 'pkill -9 -f fridaserver'], check=False, timeout=5)
                self.adb_command(['shell', 'pkill -9 -f frida-server'], check=False, timeout=5)
            
            time.sleep(1)
            
            process_running, _ = self._check_frida_process_on_device()
            if not process_running:
                print(f"{Colors.GREEN}    [✓] Frida server killed successfully{Colors.END}")
                return True
            else:
                print(f"{Colors.YELLOW}    [!] Frida server still running after kill attempt{Colors.END}")
                return False
                
        except Exception as e:
            logger.debug(f"Kill frida server error: {e}")
            return False
    
    def is_frida_server_on_device(self) -> bool:
        """Check if Frida server binary exists on device"""
        print(f"{Colors.BLUE}[*] Checking for Frida server binary on device...{Colors.END}")
        
        result = self.adb_command(['shell', f'ls -la {self.FRIDA_SERVER_PATH}'], check=False)
        if result.returncode == 0 and 'No such file' not in result.stdout:
            print(f"{Colors.GREEN}[✓] Frida server binary found on device{Colors.END}")
            return True
        
        print(f"{Colors.YELLOW}[!] Frida server not found on device{Colors.END}")
        return False
    
    def get_local_server_path(self) -> Optional[Path]:
        """Get path to local Frida server if exists"""
        for f in Path('.').glob(f'frida-server-*'):
            if f.is_file() and not f.suffix == '.xz':
                print(f"{Colors.GREEN}[✓] Found local Frida server: {f}{Colors.END}")
                return f
        return None
    
    def download_frida_server(self) -> Optional[Path]:
        """Download matching Frida server from GitHub with retry"""
        print(f"\n{Colors.BLUE}[*] Downloading Frida server...{Colors.END}")
        
        filename = f"frida-server-{self.frida_version}-{self.device.architecture}.xz"
        url = f"https://github.com/frida/frida/releases/download/{self.frida_version}/{filename}"
        
        print(f"{Colors.CYAN}    URL: {url}{Colors.END}")
        
        xz_path = Path(filename)
        server_path = Path(f"frida-server-{self.frida_version}-{self.device.architecture}")
        
        if server_path.exists():
            print(f"{Colors.GREEN}[✓] Frida server already exists locally{Colors.END}")
            return server_path
        
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                print(f"{Colors.CYAN}    Downloading (attempt {attempt}/{max_retries})...{Colors.END}")
                request = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                
                with urlopen(request, timeout=60) as response:
                    total_size = int(response.headers.get('content-length', 0))
                    downloaded = 0
                    chunk_size = 8192
                    
                    with open(xz_path, 'wb') as f:
                        while True:
                            chunk = response.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            
                            if total_size:
                                percent = (downloaded / total_size) * 100
                                bar = '█' * int(percent // 2) + '░' * (50 - int(percent // 2))
                                print(f"\r    [{bar}] {percent:.1f}%", end='', flush=True)
                    
                    print()
                
                print(f"{Colors.CYAN}    Extracting...{Colors.END}")
                with lzma.open(xz_path, 'rb') as xz_file:
                    with open(server_path, 'wb') as out_file:
                        shutil.copyfileobj(xz_file, out_file)
                
                xz_path.unlink()
                
                print(f"{Colors.GREEN}[✓] Frida server downloaded{Colors.END}")
                return server_path
                
            except (URLError, HTTPError) as e:
                print(f"{Colors.YELLOW}[!] Download attempt {attempt} failed: {e}{Colors.END}")
                if attempt < max_retries:
                    print(f"{Colors.CYAN}    Retrying in 2 seconds...{Colors.END}")
                    time.sleep(2)
                else:
                    print(f"{Colors.RED}[!] Download failed after {max_retries} attempts{Colors.END}")
                    return None
            except Exception as e:
                print(f"{Colors.RED}[!] Unexpected error: {e}{Colors.END}")
                return None
        
        return None
    
    def push_frida_server(self, local_path: Path) -> bool:
        """Push Frida server to device"""
        print(f"\n{Colors.BLUE}[*] Pushing Frida server to device...{Colors.END}")
        
        try:
            self.adb_command(['push', str(local_path), self.FRIDA_SERVER_PATH])
            print(f"{Colors.GREEN}[✓] Pushed to {self.FRIDA_SERVER_PATH}{Colors.END}")
            
            print(f"{Colors.BLUE}[*] Setting permissions...{Colors.END}")
            self.adb_command(['shell', 'chmod', '755', self.FRIDA_SERVER_PATH])
            print(f"{Colors.GREEN}[✓] Permissions set (755){Colors.END}")
            
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to push Frida server: {e}{Colors.END}")
            return False
    
    def start_frida_server(self) -> bool:
        """Start Frida server on device with proper root handling and validation"""
        print(f"\n{Colors.BLUE}[*] Starting Frida server...{Colors.END}")
        
        self.kill_frida_server()
        
        try:
            if self.device.is_rooted:
                print(f"{Colors.CYAN}    Starting with root...{Colors.END}")
                subprocess.Popen(
                    ['adb', '-s', self.device.serial, 'shell', 
                     f'su -c "{self.FRIDA_SERVER_PATH} -D"'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=True if sys.platform == 'win32' else False
                )
            else:
                print(f"{Colors.CYAN}    Starting without root (may fail)...{Colors.END}")
                subprocess.Popen(
                    ['adb', '-s', self.device.serial, 'shell', 
                     f'{self.FRIDA_SERVER_PATH} -D'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=True if sys.platform == 'win32' else False
                )
            
            print(f"{Colors.CYAN}    Waiting for server to initialize...{Colors.END}")
            
            for attempt in range(1, 6):
                time.sleep(2)
                print(f"{Colors.CYAN}    Validation attempt {attempt}/5...{Colors.END}")
                
                status = self.get_frida_server_status()
                
                if status.is_fully_operational:
                    print(f"{Colors.GREEN}[✓] Frida server started and validated successfully!{Colors.END}")
                    return True
                
                if status.process_running and not status.port_bound:
                    print(f"{Colors.CYAN}    Process running, waiting for port binding...{Colors.END}")
                    continue
                
                if not status.process_running and attempt > 2:
                    break
            
            print(f"{Colors.RED}[!] Frida server failed to start properly{Colors.END}")
            
            if self.device.selinux_enforcing:
                print(f"{Colors.YELLOW}    SELinux may be blocking. Try:{Colors.END}")
                print(f"{Colors.YELLOW}    adb shell su -c setenforce 0{Colors.END}")
            
            if not self.device.is_rooted:
                print(f"{Colors.YELLOW}    Device is not rooted - server may not have required permissions{Colors.END}")
            
            return False
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error starting Frida server: {e}{Colors.END}")
            return False
    
    def ensure_frida_server(self) -> bool:
        """Smart Frida server lifecycle - idempotent with 3-layer validation"""
        print(f"\n{Colors.PURPLE}{'═' * 60}{Colors.END}")
        print(f"{Colors.PURPLE}  Smart Frida Server Lifecycle (3-Layer Validation){Colors.END}")
        print(f"{Colors.PURPLE}{'═' * 60}{Colors.END}")
        
        status = self.get_frida_server_status()
        
        if status.is_fully_operational:
            print(f"\n{Colors.GREEN}[✓] Frida server is fully operational - skipping setup{Colors.END}")
            return True
        
        if status.needs_restart:
            print(f"\n{Colors.YELLOW}[!] Frida server in bad state - restarting...{Colors.END}")
            self.kill_frida_server()
            time.sleep(1)
        
        if self.is_frida_server_on_device():
            print(f"{Colors.BLUE}[*] Server binary exists on device, attempting to start...{Colors.END}")
            if self.start_frida_server():
                return True
            print(f"{Colors.YELLOW}[!] Failed to start existing server - may need to re-push{Colors.END}")
        
        local_server = self.get_local_server_path()
        if local_server:
            print(f"{Colors.BLUE}[*] Using local server: {local_server}{Colors.END}")
        else:
            local_server = self.download_frida_server()
            if not local_server:
                return False
        
        if not self.push_frida_server(local_server):
            return False
        
        return self.start_frida_server()
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5: APP ENUMERATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def enumerate_apps(self) -> bool:
        """List installed applications with correct parsing"""
        print(f"\n{Colors.BLUE}[*] Enumerating installed apps...{Colors.END}")
        
        try:
            result = self.run_command(['frida-ps', '-Uai'])
            lines = result.stdout.strip().split('\n')
            
            self.apps = []
            
            for line in lines[2:]:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        pid_str = parts[0]
                        pid = int(pid_str) if pid_str != '-' else None
                        identifier = parts[-1]
                        name = ' '.join(parts[1:-1])
                        
                        self.apps.append(AppInfo(pid=pid, name=name, identifier=identifier))
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Failed to parse line: {line} - {e}")
                        continue
            
            print(f"{Colors.GREEN}[✓] Found {len(self.apps)} apps{Colors.END}")
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to enumerate apps: {e}{Colors.END}")
            return False
    
    def display_apps(self, filter_running: bool = False) -> List[AppInfo]:
        """Display apps in a formatted list and return the displayed list"""
        apps_to_show = self.apps
        if filter_running:
            apps_to_show = [a for a in self.apps if a.pid is not None]
        
        print(f"\n{Colors.CYAN}{'#':>4}  {'PID':>6}  {'Identifier':<45}  Name{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 90}{Colors.END}")
        
        for i, app in enumerate(apps_to_show, 1):
            pid_str = str(app.pid) if app.pid else '-'
            status = f"{Colors.GREEN}●{Colors.END}" if app.pid else f"{Colors.YELLOW}○{Colors.END}"
            identifier = app.identifier[:43] + '..' if len(app.identifier) > 45 else app.identifier
            name = app.name[:30] + '..' if len(app.name) > 32 else app.name
            print(f"{i:>4}  {pid_str:>6}  {identifier:<45}  {status} {name}")
        
        return apps_to_show
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 6: TARGET SELECTION (with back and exit options)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def select_target(self) -> Optional[AppInfo]:
        """Prompt user to select target app with input validation and back option"""
        while True:
            print(f"\n{Colors.CYAN}Filter options:{Colors.END}")
            print(f"  1. Show all apps")
            print(f"  2. Show only running apps")
            print(f"  {Colors.PURPLE}B. Go back (refresh app list){Colors.END}")
            print(f"  {Colors.RED}X. Exit{Colors.END}")
            
            filter_choice = self.get_valid_input(
                f"{Colors.YELLOW}> {Colors.END}",
                ['1', '2', 'b', 'x']
            )
            
            if filter_choice.lower() == 'b':
                print(f"{Colors.PURPLE}[←] Refreshing app list...{Colors.END}")
                self.enumerate_apps()
                continue
            
            if filter_choice.lower() == 'x':
                self._exit_program()
            
            filter_running = filter_choice == '2'
            apps_to_select = self.display_apps(filter_running=filter_running)
            
            if not apps_to_select:
                print(f"{Colors.YELLOW}[!] No apps found with current filter{Colors.END}")
                print(f"{Colors.CYAN}Returning to filter options...{Colors.END}")
                continue
            
            print(f"\n{Colors.CYAN}Enter app number (1-{len(apps_to_select)}), package identifier,{Colors.END}")
            print(f"{Colors.CYAN}'B' to go back to filter options, or 'X' to exit:{Colors.END}")
            selection = self.safe_input(f"{Colors.YELLOW}> {Colors.END}")
            
            if not selection:
                print(f"{Colors.RED}[!] Invalid option. Please enter a valid selection{Colors.END}")
                continue
            
            if selection.lower() == 'b':
                continue
            
            if selection.lower() == 'x':
                self._exit_program()
            
            try:
                idx = int(selection)
                if 1 <= idx <= len(apps_to_select):
                    app = apps_to_select[idx - 1]
                    print(f"{Colors.GREEN}[✓] Selected: {app.identifier}{Colors.END}")
                    return app
                else:
                    print(f"{Colors.RED}[!] Invalid option. Enter 1-{len(apps_to_select)}{Colors.END}")
                    continue
            except ValueError:
                pass
            
            for app in self.apps:
                if app.identifier == selection:
                    print(f"{Colors.GREEN}[✓] Selected: {app.identifier}{Colors.END}")
                    return app
            
            matches = [a for a in self.apps if selection.lower() in a.identifier.lower()]
            if len(matches) == 1:
                print(f"{Colors.GREEN}[✓] Selected: {matches[0].identifier}{Colors.END}")
                return matches[0]
            elif len(matches) > 1:
                print(f"{Colors.YELLOW}[!] Multiple matches found:{Colors.END}")
                for m in matches[:5]:
                    print(f"    - {m.identifier}")
                print(f"{Colors.YELLOW}    Please be more specific{Colors.END}")
                continue
            
            print(f"{Colors.RED}[!] App not found: {selection}{Colors.END}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 7: SCRIPT MANAGEMENT (with CodeShare and exit option)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def show_codeshare_examples(self):
        """Display popular Frida CodeShare scripts"""
        print(f"\n{Colors.CYAN}Popular Frida CodeShare Scripts:{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.END}")
        
        examples = [
            ("pcipolloni/universal-android-ssl-pinning-bypass-with-frida", "Universal SSL Pinning Bypass"),
            ("dzonerzy/fridantiroot", "Root Detection Bypass"),
            ("akabe1/frida-multiple-unpinning", "Multiple SSL Unpinning"),
            ("masbog/frida-android-unpinning-ssl", "Android SSL Unpinning"),
            ("sowdust/universal-android-ssl-pinning-bypass-2", "Universal SSL Bypass v2"),
        ]
        
        for script_id, description in examples:
            print(f"  {Colors.GREEN}•{Colors.END} {script_id}")
            print(f"    {Colors.YELLOW}{description}{Colors.END}")
        
        print(f"\n{Colors.CYAN}Browse more at: https://codeshare.frida.re/{Colors.END}")
    
    def validate_codeshare_script(self, script_name: str) -> Optional[str]:
        """
        Validate and normalize a Frida CodeShare script name
        
        Args:
            script_name: The script name in format 'author/script-name'
            
        Returns:
            Normalized script name if valid, or None if invalid format
        """
        # Normalize script name - remove @ prefix if present and trailing slashes
        script_name = script_name.strip()
        if script_name.startswith('@'):
            script_name = script_name[1:]
        script_name = script_name.rstrip('/')
        
        # Validate format: should be 'author/script-name'
        if '/' not in script_name:
            print(f"{Colors.RED}[!] Invalid format: {script_name}{Colors.END}")
            print(f"{Colors.YELLOW}    Must be in format: author/script-name{Colors.END}")
            print(f"{Colors.YELLOW}    Example: pcipolloni/universal-android-ssl-pinning-bypass-with-frida{Colors.END}")
            return None
        
        parts = script_name.split('/')
        if len(parts) < 2 or not parts[0] or not parts[1]:
            print(f"{Colors.RED}[!] Invalid format: {script_name}{Colors.END}")
            print(f"{Colors.YELLOW}    Must be in format: author/script-name{Colors.END}")
            return None
        
        print(f"{Colors.GREEN}[✓] CodeShare script: {script_name}{Colors.END}")
        return script_name
    
    def _handle_codeshare_selection(self) -> Optional[str]:
        """
        Handle Frida CodeShare script selection
        
        Returns:
            CodeShare script identifier (format: codeshare:author/script-name) or GO_BACK
        """
        self.show_codeshare_examples()
        
        while True:
            print(f"\n{Colors.CYAN}Enter CodeShare script name (e.g., author/script-name):{Colors.END}")
            print(f"{Colors.CYAN}'B' to go back, 'X' to exit{Colors.END}")
            
            script_name = self.safe_input(f"{Colors.YELLOW}> {Colors.END}")
            
            if not script_name:
                print(f"{Colors.RED}[!] Please enter a script name{Colors.END}")
                continue
            
            if script_name.lower() == 'b':
                return self.GO_BACK
            
            if script_name.lower() == 'x':
                self._exit_program()
            
            # Validate the script name format
            validated_name = self.validate_codeshare_script(script_name)
            
            if validated_name:
                # Return with codeshare prefix to identify it later
                return f"{self.CODESHARE_PREFIX}{validated_name}"
            else:
                print(f"\n{Colors.CYAN}Would you like to try another script? (Y/N):{Colors.END}")
                retry = self.get_valid_input(
                    f"{Colors.YELLOW}> {Colors.END}",
                    ['y', 'n', 'yes', 'no']
                ).lower()
                
                if retry in ['n', 'no']:
                    return self.GO_BACK
    
    def _handle_local_script(self) -> Optional[Path]:
        """
        Handle local script file selection
        
        Returns:
            Path to local script file or GO_BACK
        """
        while True:
            print(f"\n{Colors.CYAN}Enter full path to script (.js file):{Colors.END}")
            print(f"{Colors.CYAN}'B' to go back, 'X' to exit{Colors.END}")
            
            custom_path = self.safe_input(f"{Colors.YELLOW}> {Colors.END}")
            
            if not custom_path:
                print(f"{Colors.RED}[!] Please enter a valid path{Colors.END}")
                continue
            
            if custom_path.lower() == 'b':
                return self.GO_BACK
            
            if custom_path.lower() == 'x':
                self._exit_program()
            
            custom_path = Path(custom_path.strip('"').strip("'"))
            
            if custom_path.exists() and custom_path.suffix == '.js':
                print(f"{Colors.GREEN}[✓] Using script: {custom_path}{Colors.END}")
                return custom_path
            elif not custom_path.exists():
                print(f"{Colors.RED}[!] File not found: {custom_path}{Colors.END}")
            else:
                print(f"{Colors.RED}[!] Not a .js file: {custom_path}{Colors.END}")
    
    def _handle_custom_script_menu(self) -> Union[Path, str, None]:
        """
        Handle custom script submenu with CodeShare and local file options
        
        Returns:
            Path to local script, CodeShare identifier (codeshare:author/script), GO_BACK, or None
        """
        while True:
            print(f"\n{Colors.CYAN}Custom Script Options:{Colors.END}")
            print(f"{Colors.CYAN}{'─' * 50}{Colors.END}")
            print(f"  1. {Colors.GREEN}Frida CodeShare{Colors.END} - Run script from codeshare.frida.re")
            print(f"  2. {Colors.YELLOW}Local Script{Colors.END} - Enter path to local .js file")
            print(f"  {Colors.PURPLE}B. Go back to script selection{Colors.END}")
            print(f"  {Colors.RED}X. Exit{Colors.END}")
            
            choice = self.get_valid_input(
                f"\n{Colors.YELLOW}> {Colors.END}",
                ['1', '2', 'b', 'x']
            )
            
            if choice.lower() == 'b':
                return self.GO_BACK
            
            if choice.lower() == 'x':
                self._exit_program()
            
            if choice == '1':
                # Frida CodeShare
                result = self._handle_codeshare_selection()
                if result == self.GO_BACK:
                    continue
                return result
            
            elif choice == '2':
                # Local script
                result = self._handle_local_script()
                if result == self.GO_BACK:
                    continue
                return result
    
    def get_available_scripts(self) -> List[Dict]:
        """Get list of available Frida scripts"""
        scripts = []
        
        metadata_path = self.SCRIPTS_DIR / 'scripts.json'
        if metadata_path.exists():
            try:
                with open(metadata_path) as f:
                    scripts = json.load(f)
            except json.JSONDecodeError:
                logger.warning("Invalid scripts.json")
        
        if not scripts:
            for js_file in self.SCRIPTS_DIR.glob('*.js'):
                scripts.append({
                    'name': js_file.stem.replace('_', ' ').title(),
                    'file': js_file.name,
                    'type': 'general'
                })
        
        if not scripts:
            scripts = [
                {'name': 'Universal SSL Pinning Bypass', 'file': 'ssl_pinning_bypass.js'},
                {'name': 'Root Detection Bypass', 'file': 'root_bypass.js'},
                {'name': 'Flutter SSL Pinning Bypass', 'file': 'flutter_ssl_bypass.js'},
                {'name': 'Anti Debug / Emulator Bypass', 'file': 'anti_debug_bypass.js'}
            ]
        
        return scripts
    
    def select_script(self) -> Union[Path, str, None]:
        """
        Prompt user to select a Frida script
        
        Returns:
            Path to local script, CodeShare identifier (codeshare:author/script), or None for go back
        """
        scripts = self.get_available_scripts()
        
        while True:
            print(f"\n{Colors.CYAN}Available Frida Scripts:{Colors.END}")
            print(f"{Colors.CYAN}{'─' * 50}{Colors.END}")
            
            for i, script in enumerate(scripts, 1):
                script_path = self.SCRIPTS_DIR / script['file']
                exists = "✓" if script_path.exists() else "✗"
                color = Colors.GREEN if script_path.exists() else Colors.RED
                print(f"  {i}. {script['name']} {color}[{exists}]{Colors.END}")
            
            print(f"\n  {Colors.YELLOW}C. Custom script options (CodeShare / Local){Colors.END}")
            print(f"  {Colors.PURPLE}B. Go back to app selection{Colors.END}")
            print(f"  {Colors.RED}X. Exit{Colors.END}")
            
            print(f"\n{Colors.CYAN}Select script (1-{len(scripts)}), 'C' for custom, 'B' to go back, 'X' to exit:{Colors.END}")
            
            is_num, value = self.get_numeric_input(
                f"{Colors.YELLOW}> {Colors.END}",
                1, len(scripts),
                allow_special=['b', 'c', 'x']
            )
            
            if not is_num:
                if value == 'b':
                    print(f"{Colors.PURPLE}[←] Going back to app selection...{Colors.END}")
                    return None
                
                elif value == 'x':
                    self._exit_program()
                
                elif value == 'c':
                    result = self._handle_custom_script_menu()
                    if result == self.GO_BACK:
                        continue
                    return result
            else:
                script_path = self.SCRIPTS_DIR / scripts[value - 1]['file']
                if script_path.exists():
                    print(f"{Colors.GREEN}[✓] Selected: {scripts[value - 1]['name']}{Colors.END}")
                    return script_path
                else:
                    print(f"{Colors.RED}[!] Script file not found: {script_path}{Colors.END}")
                    print(f"{Colors.YELLOW}    Create the script or use custom option (C){Colors.END}")
                    continue
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 8: SCRIPT EXECUTION (with CodeShare support)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _get_app_pid(self, identifier: str) -> Optional[int]:
        """Get current PID of a running app by package identifier"""
        # Method 1: Use pidof
        try:
            result = self.adb_command(
                ['shell', f'pidof {identifier}'],
                check=False,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                pid_str = result.stdout.strip().split()[0]
                return int(pid_str)
        except (ValueError, subprocess.TimeoutExpired):
            pass
        except Exception as e:
            logger.debug(f"pidof failed for {identifier}: {e}")
        
        # Method 2: Use ps with grep
        try:
            result = self.adb_command(
                ['shell', f'ps -A 2>/dev/null | grep {identifier} | grep -v grep'],
                check=False,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            return int(parts[1])
                        except ValueError:
                            continue
        except Exception as e:
            logger.debug(f"ps grep failed for {identifier}: {e}")
        
        # Method 3: Check our cached app list
        for app in self.apps:
            if app.identifier == identifier and app.pid:
                try:
                    result = self.adb_command(
                        ['shell', f'kill -0 {app.pid} 2>/dev/null && echo "alive"'],
                        check=False,
                        timeout=3
                    )
                    if 'alive' in result.stdout:
                        return app.pid
                except:
                    pass
        
        return None
    
    def _kill_app(self, identifier: str) -> bool:
        """Force stop an app using am force-stop"""
        print(f"{Colors.CYAN}    Force stopping {identifier}...{Colors.END}")
        
        try:
            self.adb_command(
                ['shell', 'am', 'force-stop', identifier],
                check=False,
                timeout=10
            )
            
            time.sleep(1)
            
            pid = self._get_app_pid(identifier)
            if pid is None:
                print(f"{Colors.GREEN}    [✓] App stopped successfully{Colors.END}")
                return True
            else:
                print(f"{Colors.YELLOW}    [!] App still running (PID: {pid}){Colors.END}")
                
                if self.device.is_rooted:
                    self.adb_command(
                        ['shell', f'su -c "kill -9 {pid}"'],
                        check=False,
                        timeout=5
                    )
                else:
                    self.adb_command(
                        ['shell', f'kill -9 {pid}'],
                        check=False,
                        timeout=5
                    )
                
                time.sleep(1)
                return self._get_app_pid(identifier) is None
                
        except Exception as e:
            print(f"{Colors.YELLOW}    [!] Error stopping app: {e}{Colors.END}")
            return False
    
    def _launch_app(self, identifier: str) -> Optional[int]:
        """Launch an app and return its PID"""
        print(f"{Colors.CYAN}    Launching {identifier}...{Colors.END}")
        
        try:
            self.adb_command([
                'shell', 'monkey', '-p', identifier, '-c',
                'android.intent.category.LAUNCHER', '1'
            ], check=False, timeout=10)
            
            print(f"{Colors.CYAN}    Waiting for app to start...{Colors.END}")
            
            for attempt in range(1, 6):
                time.sleep(1)
                pid = self._get_app_pid(identifier)
                if pid:
                    print(f"{Colors.GREEN}    [✓] App started (PID: {pid}){Colors.END}")
                    return pid
                print(f"{Colors.CYAN}    Checking... ({attempt}/5){Colors.END}")
            
            print(f"{Colors.YELLOW}    [!] App may not have started properly{Colors.END}")
            return None
            
        except Exception as e:
            print(f"{Colors.YELLOW}    [!] Error launching app: {e}{Colors.END}")
            return None
    
    def execute_script(self, target: AppInfo, script: Union[Path, str]) -> bool:
        """
        Execute Frida script against target app
        
        Supports both local scripts (Path) and CodeShare scripts (string with codeshare: prefix)
        """
        # Check if this is a CodeShare script
        is_codeshare = isinstance(script, str) and script.startswith(self.CODESHARE_PREFIX)
        
        if is_codeshare:
            codeshare_name = script[len(self.CODESHARE_PREFIX):]
            print(f"\n{Colors.GREEN}[*] Using Frida CodeShare: {codeshare_name}{Colors.END}")
        else:
            print(f"\n{Colors.GREEN}[*] Using local script: {script}{Colors.END}")
        
        while True:
            current_pid = self._get_app_pid(target.identifier)
            
            print(f"\n{Colors.CYAN}Execution mode:{Colors.END}")
            print(f"  1. Spawn (launch app fresh with injection)")
            print(f"  2. Attach (connect to running app)")
            print(f"  {Colors.PURPLE}B. Go back to script selection{Colors.END}")
            print(f"  {Colors.RED}X. Exit{Colors.END}")
            
            if current_pid:
                print(f"\n{Colors.GREEN}    ℹ App is currently running (PID: {current_pid}){Colors.END}")
            else:
                print(f"\n{Colors.YELLOW}    ℹ App is not running - Spawn recommended{Colors.END}")
            
            if not self.device.is_rooted:
                print(f"{Colors.YELLOW}    ⚠ Device not rooted - Spawn mode may fail{Colors.END}")
                print(f"{Colors.YELLOW}      Use Attach mode for non-rooted devices{Colors.END}")
            
            is_num, value = self.get_numeric_input(
                f"{Colors.YELLOW}> {Colors.END}",
                1, 2,
                allow_special=['b', 'x']
            )
            
            if not is_num:
                if value == 'b':
                    print(f"{Colors.PURPLE}[←] Going back to script selection...{Colors.END}")
                    return False
                elif value == 'x':
                    self._exit_program()
            
            mode = str(value)
            
            # Build command based on script type
            if is_codeshare:
                codeshare_name = script[len(self.CODESHARE_PREFIX):]
                
                # SPAWN MODE with CodeShare
                if mode == '1':
                    if not self.device.is_rooted:
                        print(f"\n{Colors.YELLOW}[!] Warning: Spawn mode on non-rooted device{Colors.END}")
                        print(f"{Colors.YELLOW}    This may fail with 'need Gadget' error{Colors.END}")
                        print(f"{Colors.CYAN}    Continue anyway? (Y/N):{Colors.END}")
                        
                        confirm = self.get_valid_input(
                            f"{Colors.YELLOW}> {Colors.END}",
                            ['y', 'n', 'yes', 'no']
                        ).lower()
                        
                        if confirm in ['n', 'no']:
                            continue
                    
                    if current_pid:
                        print(f"\n{Colors.YELLOW}[!] App is already running (PID: {current_pid}){Colors.END}")
                        print(f"{Colors.BLUE}[*] Killing app before spawn...{Colors.END}")
                        
                        if not self._kill_app(target.identifier):
                            print(f"{Colors.YELLOW}[!] Could not kill app - spawn may fail{Colors.END}")
                        
                        time.sleep(2)
                    
                    cmd = [
                        'frida', '-U',
                        '--codeshare', codeshare_name,
                        '-f', target.identifier
                    ]
                    print(f"\n{Colors.CYAN}[*] Spawning {target.identifier} with CodeShare script...{Colors.END}")
                
                # ATTACH MODE with CodeShare
                else:
                    if not current_pid:
                        print(f"\n{Colors.YELLOW}[!] App not running. Starting it first...{Colors.END}")
                        current_pid = self._launch_app(target.identifier)
                        
                        if not current_pid:
                            print(f"{Colors.RED}[!] Failed to start app{Colors.END}")
                            print(f"{Colors.CYAN}    Try starting the app manually and retry{Colors.END}")
                            continue
                    
                    cmd = [
                        'frida', '-U',
                        '--codeshare', codeshare_name,
                        '-p', str(current_pid)
                    ]
                    print(f"\n{Colors.CYAN}[*] Attaching to {target.identifier} (PID: {current_pid}) with CodeShare script...{Colors.END}")
            
            else:
                # Local script execution
                script_path = script
                
                # SPAWN MODE with local script
                if mode == '1':
                    if not self.device.is_rooted:
                        print(f"\n{Colors.YELLOW}[!] Warning: Spawn mode on non-rooted device{Colors.END}")
                        print(f"{Colors.YELLOW}    This may fail with 'need Gadget' error{Colors.END}")
                        print(f"{Colors.CYAN}    Continue anyway? (Y/N):{Colors.END}")
                        
                        confirm = self.get_valid_input(
                            f"{Colors.YELLOW}> {Colors.END}",
                            ['y', 'n', 'yes', 'no']
                        ).lower()
                        
                        if confirm in ['n', 'no']:
                            continue
                    
                    if current_pid:
                        print(f"\n{Colors.YELLOW}[!] App is already running (PID: {current_pid}){Colors.END}")
                        print(f"{Colors.BLUE}[*] Killing app before spawn...{Colors.END}")
                        
                        if not self._kill_app(target.identifier):
                            print(f"{Colors.YELLOW}[!] Could not kill app - spawn may fail{Colors.END}")
                        
                        time.sleep(2)
                    
                    cmd = [
                        'frida', '-U',
                        '-f', target.identifier,
                        '-l', str(script_path)
                    ]
                    print(f"\n{Colors.CYAN}[*] Spawning {target.identifier}...{Colors.END}")
                
                # ATTACH MODE with local script
                else:
                    if not current_pid:
                        print(f"\n{Colors.YELLOW}[!] App not running. Starting it first...{Colors.END}")
                        current_pid = self._launch_app(target.identifier)
                        
                        if not current_pid:
                            print(f"{Colors.RED}[!] Failed to start app{Colors.END}")
                            print(f"{Colors.CYAN}    Try starting the app manually and retry{Colors.END}")
                            continue
                    
                    cmd = [
                        'frida', '-U',
                        '-p', str(current_pid),
                        '-l', str(script_path)
                    ]
                    print(f"\n{Colors.CYAN}[*] Attaching to {target.identifier} (PID: {current_pid})...{Colors.END}")
            
            # Execute Frida
            print(f"\n{Colors.PURPLE}[*] Command: {' '.join(cmd)}{Colors.END}")
            print(f"{Colors.CYAN}{'═' * 60}{Colors.END}")
            print(f"{Colors.GREEN}[*] Auto Frida session starting...{Colors.END}")
            print(f"{Colors.YELLOW}[*] Created by: {__author__}{Colors.END}")
            print(f"{Colors.YELLOW}[*] Press Ctrl+C to stop Frida and return{Colors.END}")
            print(f"{Colors.CYAN}{'═' * 60}{Colors.END}\n")
            
            try:
                result = subprocess.run(
                    cmd, 
                    shell=True if sys.platform == 'win32' else False
                )
                
                if result.returncode != 0:
                    print(f"\n{Colors.YELLOW}[!] Frida exited with code {result.returncode}{Colors.END}")
                
                return True
                
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Frida session terminated by user{Colors.END}")
                return True
                
            except Exception as e:
                error_msg = str(e).lower()
                
                if 'unable to find process' in error_msg:
                    print(f"\n{Colors.RED}[!] Process not found - app may have crashed{Colors.END}")
                
                elif 'timed out' in error_msg:
                    print(f"\n{Colors.RED}[!] Spawn timed out{Colors.END}")
                    print(f"{Colors.CYAN}    Try using Attach mode instead{Colors.END}")
                
                elif 'gadget' in error_msg or 'jailed' in error_msg:
                    print(f"\n{Colors.RED}[!] Spawn failed: Device is not rooted{Colors.END}")
                    print(f"{Colors.YELLOW}    Use Attach mode instead (option 2){Colors.END}")
                
                else:
                    print(f"\n{Colors.RED}[!] Frida error: {e}{Colors.END}")
                    logger.exception("Frida execution failed")
                
                print(f"\n{Colors.CYAN}Would you like to:{Colors.END}")
                print(f"  1. Try again with different mode")
                print(f"  2. Go back to script selection")
                print(f"  3. Exit")
                
                is_num, retry_choice = self.get_numeric_input(
                    f"{Colors.YELLOW}> {Colors.END}",
                    1, 3
                )
                
                if retry_choice == 1:
                    continue
                elif retry_choice == 2:
                    return False
                else:
                    self._exit_program()
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MAIN EXECUTION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def run(self) -> None:
        """Main execution flow with go back navigation"""
        self.print_banner()
        
        # Phase 1: Environment Validation
        print(f"\n{Colors.PURPLE}{'═' * 60}{Colors.END}")
        print(f"{Colors.PURPLE}  PHASE 1: Environment Validation{Colors.END}")
        print(f"{Colors.PURPLE}{'═' * 60}{Colors.END}")
        
        if not self.check_python():
            sys.exit(1)
        if not self.check_pip():
            sys.exit(1)
        if not self.check_frida():
            sys.exit(1)
        
        # Phase 2: ADB & Device Detection
        print(f"\n{Colors.PURPLE}{'═' * 60}{Colors.END}")
        print(f"{Colors.PURPLE}  PHASE 2: ADB & Device Detection{Colors.END}")
        print(f"{Colors.PURPLE}{'═' * 60}{Colors.END}")
        
        if not self.check_adb():
            sys.exit(1)
        if not self.detect_device():
            sys.exit(1)
        
        # Phase 3: Architecture + Root/SELinux
        print(f"\n{Colors.PURPLE}{'═' * 60}{Colors.END}")
        print(f"{Colors.PURPLE}  PHASE 3: Device Analysis{Colors.END}")
        print(f"{Colors.PURPLE}{'═' * 60}{Colors.END}")
        
        if not self.detect_architecture():
            sys.exit(1)
        self.check_root_access()
        self.check_selinux()
        
        # Phase 4: Smart Frida Server Lifecycle
        if not self.ensure_frida_server():
            print(f"{Colors.RED}[!] Failed to setup Frida server{Colors.END}")
            sys.exit(1)
        
        # Phase 5: App Enumeration
        print(f"\n{Colors.PURPLE}{'═' * 60}{Colors.END}")
        print(f"{Colors.PURPLE}  PHASE 5: App Enumeration{Colors.END}")
        print(f"{Colors.PURPLE}{'═' * 60}{Colors.END}")
        
        if not self.enumerate_apps():
            sys.exit(1)
        
        # Phases 6-8: Interactive loop with go back support
        while True:
            # Phase 6: Target Selection
            print(f"\n{Colors.PURPLE}{'═' * 60}{Colors.END}")
            print(f"{Colors.PURPLE}  PHASE 6: Target Selection{Colors.END}")
            print(f"{Colors.PURPLE}{'═' * 60}{Colors.END}")
            
            target = self.select_target()
            if not target:
                continue
            
            # Phase 7: Script Selection (with go back)
            while True:
                print(f"\n{Colors.PURPLE}{'═' * 60}{Colors.END}")
                print(f"{Colors.PURPLE}  PHASE 7: Script Selection{Colors.END}")
                print(f"{Colors.PURPLE}{'═' * 60}{Colors.END}")
                
                script = self.select_script()
                if script is None:
                    break
                
                # Phase 8: Execution (with go back)
                print(f"\n{Colors.PURPLE}{'═' * 60}{Colors.END}")
                print(f"{Colors.PURPLE}  PHASE 8: Script Execution{Colors.END}")
                print(f"{Colors.PURPLE}{'═' * 60}{Colors.END}")
                
                execution_complete = self.execute_script(target, script)
                
                if not execution_complete:
                    continue
                
                # Post-execution menu
                print(f"\n{Colors.CYAN}{'═' * 60}{Colors.END}")
                print(f"{Colors.CYAN}  What would you like to do next?{Colors.END}")
                print(f"{Colors.CYAN}{'═' * 60}{Colors.END}")
                print(f"  1. Run another script on the same app")
                print(f"  2. Select a different app")
                print(f"  3. Exit")
                
                is_num, next_action = self.get_numeric_input(
                    f"{Colors.YELLOW}> {Colors.END}",
                    1, 3
                )
                
                if next_action == 1:
                    continue
                elif next_action == 2:
                    break
                else:
                    self._exit_program()


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point for Auto Frida"""
    auto_frida = AutoFrida()
    try:
        auto_frida.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        logger.exception("Unexpected error")
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
        sys.exit(1)


if __name__ == '__main__':
    main()
