"""
PC Health Scanner v6.0
Complete Windows Security Scanner with ClamAV Virus Detection
Built for Simon

Features:
- Port scanning with one-click fix buttons
- Firewall check and auto-enable
- User account detection with one-click disable
- Remote Desktop check and auto-disable
- Suspicious network connections with one-click block
- USB device malware scanning
- Windows patch history
- ClamAV virus scanner with quarantine vault
- Admin-protected virus deletion from source
- Auto-updates ClamAV definitions
- Works on Windows 7, 8, 10 and 11
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess, socket, os, sys, json, platform
import threading, datetime, ctypes, hashlib, shutil, tempfile

try:
    import winreg
except ImportError:
    winreg = None

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


# ---- Colours --------------------------------------------------------------
BG       = "#1e1f26"
PANEL    = "#262833"
ACCENT   = "#58a6ff"
GREEN    = "#3fb950"
YELLOW   = "#d29922"
RED      = "#f85149"
TEXT     = "#e6edf3"
DIM      = "#8b949e"
FONT     = ("Segoe UI", 10)
BOLD     = ("Segoe UI Semibold", 11)
MONO     = ("Consolas", 9)


# ---- ClamAV paths -----------------------------------------------------------
CLAM_PATHS = [
    r"C:\Program Files\ClamAV\clamscan.exe",
    r"C:\Program Files (x86)\ClamAV\clamscan.exe",
    r"C:\ClamAV\clamscan.exe",
]

FRESHCLAM_PATHS = [
    r"C:\Program Files\ClamAV\freshclam.exe",
    r"C:\Program Files (x86)\ClamAV\freshclam.exe",
    r"C:\ClamAV\freshclam.exe",
]

# ---- Quarantine folder ------------------------------------------------------
QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])),
                               "PC_Health_Quarantine")

# ---- Port definitions -------------------------------------------------------
PORTS = {
    21:   ("FTP",        "HIGH",     "FTP sends passwords in plaintext. Block it."),
    23:   ("Telnet",     "CRITICAL", "Telnet is unencrypted. Block immediately."),
    25:   ("SMTP",       "MEDIUM",   "Mail port. Close if not running a mail server."),
    80:   ("HTTP",       "LOW",      "Web server port. Normal if running a website."),
    110:  ("POP3",       "MEDIUM",   "Email port. Close if not needed."),
    135:  ("MS RPC",     "HIGH",     "Windows RPC. Will be blocked at firewall."),
    139:  ("NetBIOS",    "HIGH",     "NetBIOS. Exploited by many attacks."),
    443:  ("HTTPS",      "LOW",      "Secure web port. Normal if running a website."),
    445:  ("SMB",        "CRITICAL", "SMB exploited by WannaCry. Block immediately."),
    1433: ("MSSQL",      "HIGH",     "SQL Server. Restrict access."),
    3306: ("MySQL",      "HIGH",     "MySQL database. Should not be public."),
    3389: ("RDP",        "HIGH",     "Remote Desktop. Restrict to VPN only."),
    4444: ("Backdoor",   "CRITICAL", "Port 4444 linked to Metasploit malware."),
    5432: ("PostgreSQL", "HIGH",     "Database port. Restrict access."),
    5900: ("VNC",        "HIGH",     "Remote control. Use SSH tunnel."),
    8080: ("HTTP-Alt",   "LOW",      "Alternate web port."),
    8443: ("HTTPS-Alt",  "LOW",      "Alternate secure web port."),
}


# ============================================================================
# Helper functions
# ============================================================================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def check_port(host, port, timeout=0.7):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((host, port))
        s.close()
        return r == 0
    except Exception:
        return False


def get_sysinfo():
    d = {}
    d["Computer Name"]   = socket.gethostname()
    d["Windows Version"] = platform.version()
    d["Windows Release"] = platform.release()
    d["Architecture"]    = platform.machine()
    try:
        d["Local IP"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        d["Local IP"] = "Unknown"
    if PSUTIL_OK:
        m = psutil.virtual_memory()
        d["RAM"] = f"{round(m.total/1024**3,1)} GB ({m.percent}% used)"
        b = datetime.datetime.fromtimestamp(psutil.boot_time())
        d["Last Boot"] = b.strftime("%d/%m/%Y %H:%M:%S")
    return d


def get_firewall():
    try:
        o = subprocess.check_output(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            stderr=subprocess.DEVNULL, text=True, timeout=10)
        profiles = {}
        cur = None
        for line in o.splitlines():
            line = line.strip()
            if "Profile Settings" in line:
                cur = line.replace("Profile Settings:", "").strip()
            elif line.startswith("State") and cur:
                profiles[cur] = "ON" in line.upper()
        return all(profiles.values()) if profiles else False
    except Exception:
        return False


def get_rdp():
    if not winreg:
        return False
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server")
        v, _ = winreg.QueryValueEx(k, "fDenyTSConnections")
        winreg.CloseKey(k)
        return v == 0   # 0 means RDP is ENABLED (deny=0)
    except Exception:
        return False


def get_accounts():
    try:
        o = subprocess.check_output(
            ["net", "user"], stderr=subprocess.DEVNULL, text=True, timeout=10)
        acc = []
        lines = o.splitlines()
        for line in lines[4:]:
            if "---" in line or "command" in line.lower() or not line.strip():
                continue
            if "completed" in line.lower():
                break
            # net user output columns are fixed-width, ~ split on whitespace
            parts = line.split()
            acc.extend(parts)
        return acc
    except Exception:
        return []


def get_patches():
    try:
        o = subprocess.check_output(
            ["powershell", "-Command",
             "Get-HotFix | Sort-Object InstalledOn -Descending | "
             "Select-Object -First 15 | Format-List HotFixID,Description,InstalledOn"],
            stderr=subprocess.DEVNULL, text=True, timeout=30)
        return o.strip()
    except Exception:
        return ("Unable to retrieve patches. Run as Administrator for full results.")


def get_connections():
    """Return suspicious / external established connections."""
    conns = []
    if not PSUTIL_OK:
        return conns
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "ESTABLISHED" and c.raddr:
                ip = c.raddr.ip
                if not (ip.startswith("127.") or ip.startswith("10.")
                        or ip.startswith("192.168.") or ip == "::1"):
                    conns.append({
                        "pid": c.pid,
                        "local": f"{c.laddr.ip}:{c.laddr.port}",
                        "remote": f"{ip}:{c.raddr.port}",
                    })
    except Exception:
        pass
    return conns


# ============================================================================
# Fix actions (require admin)
# ============================================================================

def do_block_port(port):
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name=PCHealth Block Port {port}",
                         "dir=in", "action=block", "protocol=TCP",
                         f"localport={port}"],
                        stderr=subprocess.DEVNULL, timeout=10)
        return True
    except Exception:
        return False


def do_block_ip(ip):
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name=PCHealth Block {ip}",
                         "action=block", f"remoteip={ip}", "dir=in"],
                        stderr=subprocess.DEVNULL, timeout=10)
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name=PCHealth Block {ip} OUT",
                         "action=block", f"remoteip={ip}", "dir=out"],
                        stderr=subprocess.DEVNULL, timeout=10)
        return True
    except Exception:
        return False


def do_disable_rdp():
    try:
        subprocess.run(["reg", "add",
                         r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                         "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f"],
                        stderr=subprocess.DEVNULL, timeout=10)
        return True
    except Exception:
        return False


def do_disable_account(name):
    try:
        subprocess.run(["net", "user", name, "/active:no"],
                        stderr=subprocess.DEVNULL, timeout=10)
        return True
    except Exception:
        return False


def do_enable_firewall():
    try:
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                        stderr=subprocess.DEVNULL, timeout=10)
        return True
    except Exception:
        return False


# ============================================================================
# ClamAV functions
# ============================================================================

def find_clamscan():
    """Find clamscan.exe on this PC."""
    for path in CLAM_PATHS:
        if os.path.exists(path):
            return path
    # Also try PATH
    try:
        result = subprocess.run(["where", "clamscan"],
                                 capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
    except Exception:
        pass
    return None


def find_freshclam():
    """Find freshclam.exe on this PC."""
    for path in FRESHCLAM_PATHS:
        if os.path.exists(path):
            return path
    try:
        result = subprocess.run(["where", "freshclam"],
                                 capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
    except Exception:
        pass
    return None


def is_clamav_installed():
    """Check if ClamAV is installed."""
    return find_clamscan() is not None


def install_clamav_instructions():
    """Return instructions for installing ClamAV."""
    return (
        "ClamAV is not installed on this PC.\n\n"
        "To install ClamAV:\n"
        "1. Go to https://www.clamav.net/downloads\n"
        "2. Download the Windows installer (.msi)\n"
        "3. Run the installer (default location is C:\\Program Files\\ClamAV)\n"
        "4. Re-run this scanner once installed.\n\n"
        "After installing, click 'Update Virus Definitions' before your first scan."
    )


def update_virus_definitions(log_callback=None):
    """Update ClamAV virus definitions using freshclam."""
    freshclam = find_freshclam()
    if not freshclam:
        return False, "freshclam.exe not found. Please install ClamAV first."
    try:
        if log_callback:
            log_callback("Downloading latest virus definitions...")
        result = subprocess.run(
            [freshclam, "--stdout"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0 or "is up to date" in result.stdout.lower():
            return True, "Virus definitions updated successfully."
        else:
            return False, f"Update failed: {result.stderr or result.stdout}"
    except subprocess.TimeoutExpired:
        return False, "Update timed out. Check your internet connection."
    except Exception as e:
        return False, f"Update error: {str(e)}"


def quarantine_file(filepath):
    """Move a file to the quarantine vault."""
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        filename = os.path.basename(filepath)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{timestamp}_{filename}.quarantine")

        # Take ownership and move file
        try:
            # Take ownership first
            subprocess.run(["takeown", "/f", filepath, "/a"],
                            stderr=subprocess.DEVNULL, timeout=10)
            # Grant admin full control
            subprocess.run(["icacls", filepath, "/grant", "Administrators:F"],
                            stderr=subprocess.DEVNULL, timeout=10)
        except Exception:
            pass

        shutil.move(filepath, quarantine_path)

        # Save quarantine log
        log_file = os.path.join(QUARANTINE_DIR, "quarantine_log.json")
        log_entry = {
            "original_path": filepath,
            "quarantine_path": quarantine_path,
            "timestamp": str(datetime.datetime.now()),
            "filename": filename,
        }
        try:
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    log_data = json.load(f)
            else:
                log_data = []
            log_data.append(log_entry)
            with open(log_file, "w") as f:
                json.dump(log_data, f, indent=2)
        except Exception:
            pass

        return True, quarantine_path
    except Exception as e:
        return False, str(e)


def delete_from_source(filepath):
    """Permanently delete a file from its source location, bypassing protection."""
    try:
        # Take ownership
        subprocess.run(["takeown", "/f", filepath, "/a"],
                        stderr=subprocess.DEVNULL, timeout=10)
        # Grant full control to administrators
        subprocess.run(["icacls", filepath, "/grant", "Administrators:F"],
                        stderr=subprocess.DEVNULL, timeout=10)
        os.remove(filepath)
        return True, "File permanently deleted from source."
    except Exception as e:
        return False, f"Could not delete: {str(e)}"


def delete_quarantined_file(quarantine_path):
    """Permanently delete a file from quarantine."""
    try:
        os.remove(quarantine_path)
        return True, "File permanently deleted."
    except Exception as e:
        return False, str(e)


def scan_with_clamav(scan_path, log_callback=None, progress_callback=None):
    """Run ClamAV scan on a path and return found threats."""
    clamscan = find_clamscan()
    if not clamscan:
        return False, [], "ClamAV not installed."

    threats = []
    try:
        if log_callback:
            log_callback(f"Scanning {scan_path} with ClamAV...")

        cmd = [
            clamscan,
            "--recursive",
            "--infected",
            "--no-summary",
            "--stdout",
            scan_path
        ]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            if progress_callback:
                progress_callback(line)
            if "FOUND" in line:
                # Format: /path/to/file: Virus.Name FOUND
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    fpath = parts[0].strip()
                    vname = parts[1].replace("FOUND", "").strip()
                    threats.append({"path": fpath, "virus": vname})

        process.wait(timeout=3600)
        return True, threats, f"Scan complete. {len(threats)} threat(s) found."
    except subprocess.TimeoutExpired:
        return False, threats, "Scan timed out."
    except Exception as e:
        return False, threats, f"Scan error: {str(e)}"


# ============================================================================
# Main Application
# ============================================================================

class PCHealth(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PC Health Scanner v6.0 - Built for Simon")
        self.geometry("980x680")
        self.configure(bg=BG)
        self.minsize(860, 600)

        self._results = {}
        self._drives = []

        self._build_ui()
        self._log("PC Health Scanner v6.0 ready.", "ok")
        if not is_admin():
            self._log("Not running as Administrator - some fixes/checks will be limited.", "warn")

    # ------------------------------------------------------------------
    # UI BUILD
    # ------------------------------------------------------------------
    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=TEXT,
                        padding=(14, 6), font=BOLD)
        style.map("TNotebook.Tab", background=[("selected", ACCENT)],
                  foreground=[("selected", "#0b0d12")])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=TEXT, rowheight=24, font=FONT)
        style.configure("Treeview.Heading", background=BG, foreground=ACCENT, font=BOLD)
        style.configure("TProgressbar", background=ACCENT)

        # Header
        header = tk.Frame(self, bg=PANEL)
        header.pack(fill="x")
        tk.Label(header, text="🛡  PC Health Scanner v6.0", bg=PANEL, fg=ACCENT,
                 font=("Segoe UI Semibold", 16)).pack(side="left", padx=14, pady=10)
        tk.Label(header, text="Built for Simon", bg=PANEL, fg=DIM,
                 font=FONT).pack(side="right", padx=14)

        # Notebook
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_overview = tk.Frame(self.nb, bg=BG)
        self.tab_ports    = tk.Frame(self.nb, bg=BG)
        self.tab_security = tk.Frame(self.nb, bg=BG)
        self.tab_clamav   = tk.Frame(self.nb, bg=BG)
        self.tab_usb      = tk.Frame(self.nb, bg=BG)
        self.tab_patches  = tk.Frame(self.nb, bg=BG)

        self.nb.add(self.tab_overview, text="  Overview  ")
        self.nb.add(self.tab_ports, text="  Ports & Firewall  ")
        self.nb.add(self.tab_security, text="  Accounts & RDP  ")
        self.nb.add(self.tab_clamav, text="  ClamAV Scanner  ")
        self.nb.add(self.tab_usb, text="  USB Scanner  ")
        self.nb.add(self.tab_patches, text="  Patches & Report  ")

        self._build_overview_tab()
        self._build_ports_tab()
        self._build_security_tab()
        self._build_clamav_tab()
        self._build_usb_tab()
        self._build_patches_tab()

        # Log console at bottom
        log_frame = tk.Frame(self, bg=BG)
        log_frame.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(log_frame, text="Activity Log", bg=BG, fg=DIM, font=BOLD).pack(anchor="w")
        self.log_box = scrolledtext.ScrolledText(log_frame, height=6, bg="#0d1117",
                                                   fg=TEXT, font=MONO, insertbackground=TEXT)
        self.log_box.pack(fill="x")
        self.log_box.tag_config("ok", foreground=GREEN)
        self.log_box.tag_config("warn", foreground=YELLOW)
        self.log_box.tag_config("bad", foreground=RED)
        self.log_box.tag_config("info", foreground=ACCENT)
        self.log_box.config(state="disabled")

    def _log(self, msg, tag="info"):
        self.log_box.config(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{ts}] {msg}\n", tag)
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    # ------------------------------------------------------------------
    # OVERVIEW TAB
    # ------------------------------------------------------------------
    def _build_overview_tab(self):
        f = self.tab_overview
        top = tk.Frame(f, bg=BG)
        top.pack(fill="x", padx=12, pady=12)

        tk.Button(top, text="🔄  Run Full Scan", bg=ACCENT, fg="#0b0d12",
                  font=BOLD, relief="flat", padx=16, pady=8,
                  command=self._run_full_scan).pack(side="left")

        self.admin_lbl = tk.Label(top, bg=BG, fg=(GREEN if is_admin() else YELLOW),
                                   text=("✓ Running as Administrator" if is_admin()
                                         else "⚠ Not running as Administrator"),
                                   font=BOLD)
        self.admin_lbl.pack(side="left", padx=20)

        self.sys_box = scrolledtext.ScrolledText(f, height=18, bg=PANEL, fg=TEXT,
                                                   font=MONO, insertbackground=TEXT)
        self.sys_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._refresh_sysinfo()

    def _refresh_sysinfo(self):
        info = get_sysinfo()
        self.sys_box.config(state="normal")
        self.sys_box.delete("1.0", "end")
        self.sys_box.insert("end", "SYSTEM INFORMATION\n")
        self.sys_box.insert("end", "=" * 60 + "\n")
        for k, v in info.items():
            self.sys_box.insert("end", f"{k:<20}: {v}\n")
        self.sys_box.config(state="disabled")
        self._results["sysinfo"] = info

    def _run_full_scan(self):
        self._log("Starting full scan...", "info")
        threading.Thread(target=self._full_scan_worker, daemon=True).start()

    def _full_scan_worker(self):
        self._refresh_sysinfo()
        self.after(0, self._scan_ports)
        self.after(0, self._refresh_security)
        self.after(0, self._refresh_patches)
        self._log("Full scan complete. Check each tab for results.", "ok")

    # ------------------------------------------------------------------
    # PORTS & FIREWALL TAB
    # ------------------------------------------------------------------
    def _build_ports_tab(self):
        f = self.tab_ports
        top = tk.Frame(f, bg=BG)
        top.pack(fill="x", padx=12, pady=12)

        tk.Button(top, text="🔍  Scan Ports", bg=ACCENT, fg="#0b0d12", font=BOLD,
                  relief="flat", padx=14, pady=6, command=self._scan_ports).pack(side="left")

        self.fw_lbl = tk.Label(top, bg=BG, fg=DIM, text="Firewall: not checked", font=BOLD)
        self.fw_lbl.pack(side="left", padx=20)

        tk.Button(top, text="Enable Firewall", bg=PANEL, fg=TEXT, font=FONT,
                  relief="flat", padx=10, pady=6,
                  command=self._enable_firewall).pack(side="left")

        cols = ("Port", "Service", "Status", "Risk", "Description", "Fix")
        self.port_tree = ttk.Treeview(f, columns=cols, show="headings", height=14)
        for c, w in zip(cols, (60, 90, 70, 80, 420, 80)):
            self.port_tree.heading(c, text=c)
            self.port_tree.column(c, width=w, anchor="w")
        self.port_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.port_tree.bind("<Double-1>", self._on_port_double_click)

        tk.Label(f, text="Double-click a row marked OPEN with HIGH/CRITICAL risk to block it via firewall.",
                 bg=BG, fg=DIM, font=FONT).pack(anchor="w", padx=12, pady=(0, 8))

    def _scan_ports(self):
        self._log("Scanning local ports...", "info")
        for row in self.port_tree.get_children():
            self.port_tree.delete(row)

        fw = get_firewall()
        self.fw_lbl.config(text=f"Firewall: {'ON (all profiles)' if fw else 'OFF / partial'}",
                            fg=(GREEN if fw else RED))
        self._results["firewall"] = fw

        open_ports = []
        for port, (svc, risk, desc) in PORTS.items():
            is_open = check_port("127.0.0.1", port)
            status = "OPEN" if is_open else "closed"
            tag = "open" if is_open else "closed"
            fix = "Block" if is_open else "-"
            self.port_tree.insert("", "end", values=(port, svc, status, risk, desc, fix),
                                   tags=(tag, str(port)))
            if is_open:
                open_ports.append((port, svc, risk))

        self.port_tree.tag_configure("open", foreground=RED)
        self.port_tree.tag_configure("closed", foreground=DIM)

        self._results["open_ports"] = open_ports
        if open_ports:
            self._log(f"{len(open_ports)} open port(s) found.", "warn")
        else:
            self._log("No monitored ports are open locally.", "ok")

    def _on_port_double_click(self, _event):
        sel = self.port_tree.selection()
        if not sel:
            return
        item = self.port_tree.item(sel[0])
        port, svc, status, risk, desc, fix = item["values"]
        if status != "OPEN":
            return
        if not messagebox.askyesno("Block Port",
                f"Block port {port} ({svc}) at the Windows Firewall?\n\n"
                f"Risk: {risk}\n{desc}\n\n"
                "Requires Administrator privileges."):
            return
        ok = do_block_port(port)
        if ok:
            self._log(f"Firewall rule added to block port {port} ({svc}).", "ok")
            messagebox.showinfo("Blocked", f"Port {port} has been blocked at the firewall.")
        else:
            self._log(f"Failed to block port {port}. Run as Administrator.", "bad")
            messagebox.showerror("Failed", "Could not add firewall rule. Run as Administrator.")

    def _enable_firewall(self):
        if not messagebox.askyesno("Enable Firewall",
                "Turn on Windows Firewall for all profiles?\nRequires Administrator."):
            return
        if do_enable_firewall():
            self._log("Windows Firewall enabled for all profiles.", "ok")
            self._scan_ports()
        else:
            self._log("Failed to enable firewall. Run as Administrator.", "bad")

    # ------------------------------------------------------------------
    # ACCOUNTS & RDP TAB
    # ------------------------------------------------------------------
    def _build_security_tab(self):
        f = self.tab_security
        top = tk.Frame(f, bg=BG)
        top.pack(fill="x", padx=12, pady=12)

        tk.Button(top, text="🔄  Refresh", bg=ACCENT, fg="#0b0d12", font=BOLD,
                  relief="flat", padx=14, pady=6, command=self._refresh_security).pack(side="left")

        self.rdp_lbl = tk.Label(top, bg=BG, fg=DIM, text="RDP: not checked", font=BOLD)
        self.rdp_lbl.pack(side="left", padx=20)

        tk.Button(top, text="Disable RDP", bg=PANEL, fg=TEXT, font=FONT,
                  relief="flat", padx=10, pady=6,
                  command=self._disable_rdp).pack(side="left")

        # Suspicious connections
        tk.Label(f, text="Active External Connections", bg=BG, fg=ACCENT, font=BOLD)\
            .pack(anchor="w", padx=12, pady=(8, 0))
        conn_cols = ("PID", "Local", "Remote")
        self.conn_tree = ttk.Treeview(f, columns=conn_cols, show="headings", height=6)
        for c, w in zip(conn_cols, (80, 220, 220)):
            self.conn_tree.heading(c, text=c)
            self.conn_tree.column(c, width=w, anchor="w")
        self.conn_tree.pack(fill="x", padx=12, pady=(0, 8))
        self.conn_tree.bind("<Double-1>", self._on_conn_double_click)
        tk.Label(f, text="Double-click a connection to block its remote IP at the firewall.",
                 bg=BG, fg=DIM, font=FONT).pack(anchor="w", padx=12)

        # Accounts
        tk.Label(f, text="User Accounts", bg=BG, fg=ACCENT, font=BOLD)\
            .pack(anchor="w", padx=12, pady=(12, 0))
        acc_cols = ("Account",)
        self.acc_tree = ttk.Treeview(f, columns=acc_cols, show="headings", height=6)
        self.acc_tree.heading("Account", text="Account")
        self.acc_tree.column("Account", width=300, anchor="w")
        self.acc_tree.pack(fill="x", padx=12, pady=(0, 8))
        self.acc_tree.bind("<Double-1>", self._on_account_double_click)
        tk.Label(f, text="Double-click an account to disable it.",
                 bg=BG, fg=DIM, font=FONT).pack(anchor="w", padx=12)

    def _refresh_security(self):
        self._log("Checking RDP, accounts and connections...", "info")

        rdp = get_rdp()
        self.rdp_lbl.config(text=f"RDP: {'ENABLED' if rdp else 'disabled'}",
                             fg=(RED if rdp else GREEN))
        self._results["rdp"] = rdp

        for row in self.conn_tree.get_children():
            self.conn_tree.delete(row)
        conns = get_connections()
        for c in conns:
            self.conn_tree.insert("", "end", values=(c["pid"], c["local"], c["remote"]))
        self._results["connections"] = conns

        for row in self.acc_tree.get_children():
            self.acc_tree.delete(row)
        accounts = get_accounts()
        for a in accounts:
            self.acc_tree.insert("", "end", values=(a,))
        self._results["accounts"] = accounts

        self._log(f"Found {len(conns)} external connection(s), {len(accounts)} account(s).", "ok")

    def _disable_rdp(self):
        if not messagebox.askyesno("Disable RDP",
                "Disable Remote Desktop access on this PC?\nRequires Administrator."):
            return
        if do_disable_rdp():
            self._log("RDP disabled (fDenyTSConnections=1).", "ok")
            self._refresh_security()
        else:
            self._log("Failed to disable RDP. Run as Administrator.", "bad")

    def _on_conn_double_click(self, _event):
        sel = self.conn_tree.selection()
        if not sel:
            return
        item = self.conn_tree.item(sel[0])
        pid, local, remote = item["values"]
        ip = remote.rsplit(":", 1)[0]
        if not messagebox.askyesno("Block IP",
                f"Block all traffic to/from {ip} at the firewall?\nRequires Administrator."):
            return
        if do_block_ip(ip):
            self._log(f"Firewall rules added to block {ip}.", "ok")
            messagebox.showinfo("Blocked", f"{ip} has been blocked (in and out).")
        else:
            self._log(f"Failed to block {ip}. Run as Administrator.", "bad")

    def _on_account_double_click(self, _event):
        sel = self.acc_tree.selection()
        if not sel:
            return
        name = self.acc_tree.item(sel[0])["values"][0]
        if not messagebox.askyesno("Disable Account",
                f"Disable the account '{name}'?\nThis cannot be undone easily.\n"
                "Requires Administrator."):
            return
        if do_disable_account(name):
            self._log(f"Account '{name}' disabled.", "ok")
            self._refresh_security()
        else:
            self._log(f"Failed to disable account '{name}'. Run as Administrator.", "bad")

    # ------------------------------------------------------------------
    # CLAMAV TAB
    # ------------------------------------------------------------------
    def _build_clamav_tab(self):
        f = self.tab_clamav
        top = tk.Frame(f, bg=BG)
        top.pack(fill="x", padx=12, pady=12)

        self.clam_status_lbl = tk.Label(top, bg=BG, fg=DIM, font=BOLD,
                                         text="ClamAV: checking...")
        self.clam_status_lbl.pack(side="left")

        tk.Button(top, text="Update Definitions", bg=PANEL, fg=TEXT, font=FONT,
                  relief="flat", padx=10, pady=6,
                  command=self._update_definitions).pack(side="left", padx=10)

        tk.Button(top, text="📁  Choose Folder & Scan", bg=ACCENT, fg="#0b0d12", font=BOLD,
                  relief="flat", padx=14, pady=6,
                  command=self._choose_and_scan).pack(side="left")

        self.clam_progress = ttk.Progressbar(f, mode="indeterminate")
        self.clam_progress.pack(fill="x", padx=12, pady=(0, 8))

        self.clam_out = scrolledtext.ScrolledText(f, height=12, bg=PANEL, fg=TEXT,
                                                    font=MONO, insertbackground=TEXT)
        self.clam_out.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.clam_out.tag_config("ok", foreground=GREEN)
        self.clam_out.tag_config("bad", foreground=RED)
        self.clam_out.tag_config("warn", foreground=YELLOW)

        # Threat actions
        action_frame = tk.Frame(f, bg=BG)
        action_frame.pack(fill="x", padx=12, pady=(0, 12))
        tk.Label(action_frame, text="Detected threats (double-click to act):",
                 bg=BG, fg=DIM, font=FONT).pack(anchor="w")

        self.threat_tree = ttk.Treeview(f, columns=("Path", "Virus"), show="headings", height=6)
        self.threat_tree.heading("Path", text="File")
        self.threat_tree.heading("Virus", text="Threat")
        self.threat_tree.column("Path", width=560, anchor="w")
        self.threat_tree.column("Virus", width=220, anchor="w")
        self.threat_tree.pack(fill="x", padx=12, pady=(0, 12))
        self.threat_tree.bind("<Double-1>", self._on_threat_double_click)

        self._check_clamav_status()

    def _check_clamav_status(self):
        if is_clamav_installed():
            self.clam_status_lbl.config(text="ClamAV: installed ✓", fg=GREEN)
        else:
            self.clam_status_lbl.config(text="ClamAV: not installed", fg=RED)
            self._clam_log(install_clamav_instructions(), "warn")

    def _clam_log(self, msg, tag="ok"):
        self.clam_out.insert("end", msg + "\n", tag)
        self.clam_out.see("end")

    def _update_definitions(self):
        if not is_clamav_installed():
            messagebox.showwarning("ClamAV not found", install_clamav_instructions())
            return
        self.clam_progress.start(10)
        threading.Thread(target=self._update_definitions_worker, daemon=True).start()

    def _update_definitions_worker(self):
        ok, msg = update_virus_definitions(log_callback=lambda m: self.after(0, self._clam_log, m, "ok"))
        self.after(0, self._clam_log, msg, "ok" if ok else "bad")
        self.after(0, self.clam_progress.stop)

    def _choose_and_scan(self):
        if not is_clamav_installed():
            messagebox.showwarning("ClamAV not found", install_clamav_instructions())
            return
        path = filedialog.askdirectory(title="Choose a folder to scan")
        if not path:
            return
        for row in self.threat_tree.get_children():
            self.threat_tree.delete(row)
        self._clam_log(f"\nStarting scan of {path} ...", "ok")
        self.clam_progress.start(10)
        threading.Thread(target=self._scan_worker, args=(path,), daemon=True).start()

    def _scan_worker(self, path):
        def progress(line):
            self.after(0, self._clam_log, line, "ok")

        ok, threats, msg = scan_with_clamav(
            path,
            log_callback=lambda m: self.after(0, self._clam_log, m, "ok"),
            progress_callback=progress
        )
        self.after(0, self.clam_progress.stop)
        self.after(0, self._clam_log, msg, "bad" if threats else "ok")
        self._results["clamav_threats"] = threats
        for t in threats:
            self.after(0, self.threat_tree.insert, "", "end", (t["path"], t["virus"]))

    def _on_threat_double_click(self, _event):
        sel = self.threat_tree.selection()
        if not sel:
            return
        path, virus = self.threat_tree.item(sel[0])["values"]
        choice = messagebox.askyesnocancel(
            "Threat Action",
            f"File: {path}\nThreat: {virus}\n\n"
            "Yes = Quarantine (safe, recoverable)\n"
            "No = Permanently delete from source\n"
            "Cancel = Do nothing"
        )
        if choice is None:
            return
        if choice:
            ok, result = quarantine_file(path)
            if ok:
                self._clam_log(f"Quarantined: {path} -> {result}", "ok")
                self._log(f"Quarantined {os.path.basename(path)}.", "ok")
            else:
                self._clam_log(f"Quarantine failed: {result}", "bad")
        else:
            if not messagebox.askyesno("Confirm Delete",
                    "This will permanently delete the file. Continue?\nRequires Administrator."):
                return
            ok, msg = delete_from_source(path)
            self._clam_log(msg, "ok" if ok else "bad")
            if ok:
                self._log(f"Deleted {os.path.basename(path)} from source.", "ok")
        if sel:
            self.threat_tree.delete(sel[0])

    # ------------------------------------------------------------------
    # USB SCANNER TAB
    # ------------------------------------------------------------------
    def _build_usb_tab(self):
        f = self.tab_usb
        top = tk.Frame(f, bg=BG)
        top.pack(fill="x", padx=12, pady=12)

        tk.Button(top, text="🔄  Refresh Drives", bg=PANEL, fg=TEXT, font=FONT,
                  relief="flat", padx=10, pady=6,
                  command=self._refresh_usb).pack(side="left")

        tk.Button(top, text="🔍  Scan USB", bg=ACCENT, fg="#0b0d12", font=BOLD,
                  relief="flat", padx=14, pady=6,
                  command=self._scan_usb).pack(side="left", padx=10)

        self.usb_drives_lbl = tk.Label(top, bg=BG, fg=DIM, font=BOLD,
                                        text="No removable drives found. Plug in USB and click Refresh.")
        self.usb_drives_lbl.pack(side="left", padx=10)

        self.usb_out = scrolledtext.ScrolledText(f, height=20, bg=PANEL, fg=TEXT,
                                                   font=MONO, insertbackground=TEXT)
        self.usb_out.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.usb_out.tag_config("ok", foreground=GREEN)
        self.usb_out.tag_config("bad", foreground=RED)
        self.usb_out.tag_config("warn", foreground=YELLOW)

        self._refresh_usb()

    def _refresh_usb(self):
        self._drives = []
        if PSUTIL_OK:
            try:
                for p in psutil.disk_partitions():
                    if "removable" in p.opts.lower():
                        self._drives.append(p.mountpoint)
            except Exception:
                pass
        if not self._drives:
            for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
                d = f"{letter}:\\"
                if os.path.exists(d):
                    try:
                        if ctypes.windll.kernel32.GetDriveTypeW(d) == 2:
                            self._drives.append(d)
                    except Exception:
                        pass
        if self._drives:
            self.usb_drives_lbl.config(text="Found: " + ", ".join(self._drives), fg=GREEN)
        else:
            self.usb_drives_lbl.config(
                text="No removable drives found. Plug in USB and click Refresh.", fg=YELLOW)

    def _scan_usb(self):
        if not self._drives:
            self._refresh_usb()
        if not self._drives:
            messagebox.showinfo("No USB",
                "No removable drives detected.\nPlug in your USB device and click Refresh first.")
            return

        # If ClamAV available, offer to use it for USB scan too
        if is_clamav_installed():
            if messagebox.askyesno("ClamAV USB Scan",
                    "ClamAV is installed. Use ClamAV for a thorough virus scan of the USB?\n\n"
                    "Choose 'No' for a quick built-in hash/autorun check."):
                drives = list(self._drives)
                self.usb_out.config(state="normal")
                self.usb_out.delete("1.0", "end")
                self.usb_out.insert("end", f"Running ClamAV scan on {len(drives)} drive(s)...\n", "ok")
                self.usb_out.config(state="disabled")
                self.clam_progress.start(10)
                for d in drives:
                    threading.Thread(target=self._usb_clamav_worker, args=(d,), daemon=True).start()
                return

        self.usb_out.config(state="normal")
        self.usb_out.delete("1.0", "end")
        self.usb_out.insert("end", f"Scanning {len(self._drives)} drive(s)...\n\n", "ok")
        self.usb_out.config(state="disabled")
        threading.Thread(target=self._usb_quick_scan_worker, daemon=True).start()

    def _usb_clamav_worker(self, drive):
        ok, threats, msg = scan_with_clamav(
            drive,
            log_callback=lambda m: self.after(0, self._usb_log, m, "ok"),
            progress_callback=lambda m: self.after(0, self._usb_log, m, "ok")
        )
        self.after(0, self.clam_progress.stop)
        self.after(0, self._usb_log, f"{drive}: {msg}", "bad" if threats else "ok")
        for t in threats:
            self.after(0, self._usb_log, f"  ⚠ {t['path']} -- {t['virus']}", "bad")

    def _usb_log(self, msg, tag="ok"):
        self.usb_out.config(state="normal")
        self.usb_out.insert("end", msg + "\n", tag)
        self.usb_out.see("end")
        self.usb_out.config(state="disabled")

    # Known-bad file hashes (MD5) -- EICAR test virus etc.
    BAD = {"44d88612fea8a8f36de82e1278abb02f": "EICAR Test Virus"}

    def _usb_quick_scan_worker(self):
        for drive in self._drives:
            self._usb_log(f"Scanning {drive} ...", "ok")
            threats = []
            count = 0
            try:
                for root, dirs, files in os.walk(drive):
                    dirs[:] = [d for d in dirs if d not in
                               ["System Volume Information", "$RECYCLE.BIN"]]
                    for fname in files:
                        if count >= 500:
                            break
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, "rb") as fh:
                                h = hashlib.md5(fh.read(1024 * 1024)).hexdigest()
                            count += 1
                            if h in self.BAD:
                                threats.append(f"{fpath} -- {self.BAD[h]}")
                            if fname.lower() == "autorun.inf":
                                threats.append(f"{fpath} -- Suspicious autorun file")
                        except Exception:
                            pass
            except Exception:
                pass

            if threats:
                self._usb_log(f"  ⚠ {len(threats)} THREAT(S) FOUND:", "bad")
                for t in threats:
                    self._usb_log(f"    {t}", "bad")
            else:
                self._usb_log(f"  ✓ {count} files scanned. No threats found.", "ok")

    # ------------------------------------------------------------------
    # PATCHES & REPORT TAB
    # ------------------------------------------------------------------
    def _build_patches_tab(self):
        f = self.tab_patches
        top = tk.Frame(f, bg=BG)
        top.pack(fill="x", padx=12, pady=12)

        tk.Button(top, text="🔄  Refresh Patches", bg=PANEL, fg=TEXT, font=FONT,
                  relief="flat", padx=10, pady=6,
                  command=self._refresh_patches).pack(side="left")

        tk.Button(top, text="Open Windows Update", bg=PANEL, fg=TEXT, font=FONT,
                  relief="flat", padx=10, pady=6,
                  command=self._open_updates).pack(side="left", padx=10)

        tk.Button(top, text="💾  Save Report", bg=ACCENT, fg="#0b0d12", font=BOLD,
                  relief="flat", padx=14, pady=6,
                  command=self._save_report).pack(side="left", padx=10)

        tk.Button(top, text="🖥  Create Desktop Shortcut", bg=PANEL, fg=TEXT, font=FONT,
                  relief="flat", padx=10, pady=6,
                  command=self._make_shortcut).pack(side="left")

        self.patch_out = scrolledtext.ScrolledText(f, height=24, bg=PANEL, fg=TEXT,
                                                     font=MONO, insertbackground=TEXT)
        self.patch_out.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _refresh_patches(self):
        self._log("Retrieving patch history (may take a moment)...", "info")
        threading.Thread(target=self._refresh_patches_worker, daemon=True).start()

    def _refresh_patches_worker(self):
        patches = get_patches()
        self._results["patches"] = patches

        def update():
            self.patch_out.delete("1.0", "end")
            self.patch_out.insert("end", "RECENT WINDOWS PATCHES\n")
            self.patch_out.insert("end", "=" * 60 + "\n")
            self.patch_out.insert("end", patches + "\n")
        self.after(0, update)
        self._log("Patch history updated.", "ok")

    def _open_updates(self):
        self._log("Opening Windows Update...", "info")
        try:
            subprocess.Popen(["control", "update"])
        except Exception:
            try:
                os.startfile("ms-settings:windowsupdate")
            except Exception:
                messagebox.showinfo("Windows Update",
                    "Go to Settings > Windows Update to check for patches.")

    # ---- Report ---------------------------------------------------------
    def _save_report(self):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = []
        lines.append("PC HEALTH SCANNER v6.0 - REPORT")
        lines.append(f"Generated: {ts}")
        lines.append("=" * 60)

        lines += ["", "SYSTEM INFO", "-" * 40]
        for k, v in self._results.get("sysinfo", {}).items():
            lines.append(f"{k}: {v}")

        lines += ["", "FIREWALL", "-" * 40,
                  "Enabled (all profiles)" if self._results.get("firewall") else "DISABLED or partial"]

        lines += ["", "OPEN PORTS", "-" * 40]
        ports = self._results.get("open_ports", [])
        if ports:
            for p, svc, risk in ports:
                lines.append(f"Port {p} ({svc}) - Risk: {risk}")
        else:
            lines.append("None detected.")

        lines += ["", "REMOTE DESKTOP (RDP)", "-" * 40,
                  "ENABLED" if self._results.get("rdp") else "Disabled"]

        lines += ["", "EXTERNAL CONNECTIONS", "-" * 40]
        conns = self._results.get("connections", [])
        if conns:
            for c in conns:
                lines.append(f"PID {c['pid']}: {c['local']} -> {c['remote']}")
        else:
            lines.append("None detected.")

        lines += ["", "USER ACCOUNTS", "-" * 40]
        for a in self._results.get("accounts", []):
            lines.append(a)

        lines += ["", "CLAMAV THREATS", "-" * 40]
        threats = self._results.get("clamav_threats", [])
        if threats:
            for t in threats:
                lines.append(f"{t['path']} -- {t['virus']}")
        else:
            lines.append("None found / not scanned.")

        lines += ["", "PATCH HISTORY", "-" * 40,
                  self._results.get("patches", "Not checked."),
                  "", "=" * 60]

        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".txt",
            initialfile=f"pchealth_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            filetypes=[("Text files", "*.txt")]
        )
        if not path:
            return
        with open(path, "w") as fh:
            fh.write("\n".join(lines))

        # Also save a local copy next to the script
        try:
            local = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])),
                                  f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(local, "w") as fh:
                fh.write("\n".join(lines))
        except Exception:
            pass

        messagebox.showinfo("Saved", f"Report saved to:\n{path}")
        self._log(f"Report saved -> {path}", "ok")

    # ---- Desktop shortcut -------------------------------------------------
    def _make_shortcut(self):
        try:
            desk = os.path.join(os.path.expanduser("~"), "Desktop")
            spath = os.path.abspath(sys.argv[0])
            bat = os.path.join(desk, "PC Health Scanner.bat")
            with open(bat, "w") as fh:
                fh.write(f'@echo off\npython "{spath}"\npause\n')
            messagebox.showinfo("Shortcut Created",
                f"Desktop shortcut created:\n{bat}\n\n"
                "Double-click it anytime to launch PC Health Scanner.")
            self._log(f"Shortcut created: {bat}", "ok")
        except Exception as e:
            messagebox.showerror("Error", str(e))


# ============================================================================
# Entry point
# ============================================================================
if __name__ == "__main__":
    PCHealth().mainloop()
