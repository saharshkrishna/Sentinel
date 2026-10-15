"""
desktop_app.py - Professional Cross-Platform SIEM Dashboard for Sentinel IDS.
Features a responsive, dark-themed UI with properly aligned toolbars,
live event stream, active threat table, and real-time visualization.
"""
import os
import sys
import subprocess
import threading
import queue
import datetime
from pathlib import Path

# Tkinter imports with friendly fallback guidance
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:
    print("ERROR: Tkinter is required for the Desktop UI.")
    print("On Fedora: sudo dnf install python3-tkinter")
    print("On Ubuntu/Debian: sudo apt install python3-tk")
    sys.exit(1)

# Matplotlib imports with graceful fallback
try:
    import matplotlib
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

from core.platform_adapter import IS_WINDOWS, IS_LINUX
from core.decision_engine import process_event, subscribe
from core.log_reader import LogReader
from core.alert import log_alert_to_file
from core.limitations import get_limitations_text
from core import process_control
from core.canary_sentry import get_canary_sentry
from core.process_tree import get_process_tree

# ─────────────────────────────────────────────────────────────
# Theme & Color Tokens (Modern Cybersecurity SIEM Palette)
# ─────────────────────────────────────────────────────────────
BG_DARK = "#121214"
BG_CARD = "#1a1a1e"
BG_CARD_HOVER = "#242429"
BG_INPUT = "#0d0d0f"
BORDER_COLOR = "#2e2e36"

TEXT_PRIMARY = "#f4f4f6"
TEXT_SECONDARY = "#9494a0"
TEXT_MUTED = "#646470"

COLOR_HIGH = "#ef4444"
COLOR_MEDIUM = "#f59e0b"
COLOR_LOW = "#3b82f6"
COLOR_NORMAL = "#10b981"
COLOR_FLOOD = "#dc2626"

FONT_FAMILY = "Segoe UI" if IS_WINDOWS else "Cantarell, DejaVu Sans, Sans"
FONT_MONO = "Consolas" if IS_WINDOWS else "Monospace"


class DesktopIDSApp:
    def __init__(self, root):
        self.root = root
        platform_name = "Linux" if IS_LINUX else "Windows" if IS_WINDOWS else "macOS"
        self.root.title(f"Sentinel IDS — Real-Time Threat Analysis & SIEM [{platform_name}]")
        self.root.geometry("1240x880")
        self.root.minsize(1080, 740)
        self.root.configure(bg=BG_DARK)

        self.stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
        self.total_scanned = 0
        self.log_lines = []
        self.is_processing = False
        self.is_live = False
        self.live_reader = None
        self.event_queue = queue.Queue()
        self.threat_map = {}
        self.notifications_enabled = True

        self._configure_styles()
        self.setup_ui()
        self.start_tray_detached()
        subscribe(self.on_new_event)
        self.poll_queue()

    def _configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Progressbar styling
        style.configure("Custom.Horizontal.TProgressbar",
                        background=COLOR_LOW,
                        troughcolor=BG_INPUT,
                        bordercolor=BORDER_COLOR,
                        lightcolor=COLOR_LOW,
                        darkcolor=COLOR_LOW)

        # Treeview styling
        style.configure("Custom.Treeview",
                        background=BG_CARD,
                        foreground=TEXT_PRIMARY,
                        fieldbackground=BG_CARD,
                        rowheight=26,
                        font=(FONT_FAMILY, 9),
                        borderwidth=0)
        style.configure("Custom.Treeview.Heading",
                        background=BG_INPUT,
                        foreground=TEXT_SECONDARY,
                        font=(FONT_FAMILY, 9, "bold"),
                        relief="flat",
                        borderwidth=1)
        style.map("Custom.Treeview.Heading",
                  background=[("active", BORDER_COLOR)])

    # ─────────────────────────────────────────────────────────
    #  Tray Spawner (Platform-safe)
    # ─────────────────────────────────────────────────────────
    def start_tray_detached(self):
        try:
            cmd = [sys.executable, "main.py", "--tray"]
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if sys.platform == "win32":
                DETACHED_PROCESS = 0x00000008
                CREATE_NEW_PROCESS_GROUP = 0x00000200
                subprocess.Popen(
                    cmd,
                    creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                    cwd=base_dir
                )
            else:
                subprocess.Popen(
                    cmd,
                    start_new_session=True,
                    cwd=base_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
        except Exception as e:
            print(f"Tray spawn notification: {e}")

    # ─────────────────────────────────────────────────────────
    #  UI Layout Construction
    # ─────────────────────────────────────────────────────────
    def setup_ui(self):
        # ── 1. Top Header & Control Navbar ──
        navbar = tk.Frame(self.root, bg=BG_CARD, height=64, padx=16, pady=10,
                          highlightbackground=BORDER_COLOR, highlightthickness=1)
        navbar.pack(fill=tk.X, side=tk.TOP)

        # Brand / Title (Left aligned)
        brand_frame = tk.Frame(navbar, bg=BG_CARD)
        brand_frame.pack(side=tk.LEFT, padx=(0, 24))

        lbl_logo = tk.Label(brand_frame, text="🛡️ SENTINEL", bg=BG_CARD, fg=TEXT_PRIMARY,
                            font=(FONT_FAMILY, 14, "bold"))
        lbl_logo.pack(side=tk.LEFT)

        plat_tag = "Linux (systemd)" if IS_LINUX else "Windows (Win32)"
        lbl_plat = tk.Label(brand_frame, text=f" [{plat_tag}]", bg=BG_CARD, fg=TEXT_MUTED,
                            font=(FONT_FAMILY, 9))
        lbl_plat.pack(side=tk.LEFT, padx=(4, 0), pady=(3, 0))

        # Action Buttons (Cleanly aligned in center)
        action_bar = tk.Frame(navbar, bg=BG_CARD)
        action_bar.pack(side=tk.LEFT, fill=tk.Y)

        self.btn_live_toggle = tk.Button(
            action_bar, text="▶ Start Live Monitor", command=self.toggle_live,
            bg="#15803d", fg="white", activebackground="#16a34a", activeforeground="white",
            relief="flat", font=(FONT_FAMILY, 9, "bold"), padx=12, pady=4, cursor="hand2"
        )
        self.btn_live_toggle.pack(side=tk.LEFT, padx=5)

        self.btn_upload = tk.Button(
            action_bar, text="📁 Upload Log File", command=self.upload_file,
            bg=BORDER_COLOR, fg=TEXT_PRIMARY, activebackground=BG_CARD_HOVER, activeforeground=TEXT_PRIMARY,
            relief="flat", font=(FONT_FAMILY, 9), padx=10, pady=4, cursor="hand2"
        )
        self.btn_upload.pack(side=tk.LEFT, padx=5)

        self.btn_mute = tk.Button(
            action_bar, text="🔔 Alerts: Active", command=self.toggle_mute,
            bg=BORDER_COLOR, fg=TEXT_PRIMARY, activebackground=BG_CARD_HOVER, activeforeground=TEXT_PRIMARY,
            relief="flat", font=(FONT_FAMILY, 9), padx=10, pady=4, cursor="hand2"
        )
        self.btn_mute.pack(side=tk.LEFT, padx=5)

        btn_limits = tk.Button(
            action_bar, text="ℹ Limitations", command=self.show_limitations,
            bg=BORDER_COLOR, fg=TEXT_PRIMARY, activebackground=BG_CARD_HOVER, activeforeground=TEXT_PRIMARY,
            relief="flat", font=(FONT_FAMILY, 9), padx=10, pady=4, cursor="hand2"
        )
        btn_limits.pack(side=tk.LEFT, padx=5)

        self.btn_host_isolate = tk.Button(
            action_bar, text="🛑 Isolate Host", command=self.action_toggle_host_isolation,
            bg="#451a03", fg="#fde047", activebackground="#78350f", activeforeground="#fef08a",
            relief="flat", font=(FONT_FAMILY, 9, "bold"), padx=10, pady=4, cursor="hand2"
        )
        self.btn_host_isolate.pack(side=tk.LEFT, padx=5)

        # Right-aligned Status & Exit
        right_frame = tk.Frame(navbar, bg=BG_CARD)
        right_frame.pack(side=tk.RIGHT)

        btn_exit = tk.Button(
            right_frame, text="✕ Exit", command=self.root.quit,
            bg="#991b1b", fg="white", activebackground="#b91c1c", activeforeground="white",
            relief="flat", font=(FONT_FAMILY, 9, "bold"), padx=10, pady=4, cursor="hand2"
        )
        btn_exit.pack(side=tk.RIGHT, padx=(12, 0))

        self.lbl_status_badge = tk.Label(
            right_frame, text="● READY", bg="#1e293b", fg="#38bdf8",
            font=(FONT_FAMILY, 9, "bold"), padx=10, pady=4
        )
        self.lbl_status_badge.pack(side=tk.RIGHT)

        # ── 2. Real-Time Metric Pills Bar ──
        metrics_bar = tk.Frame(self.root, bg=BG_DARK, pady=8, padx=16)
        metrics_bar.pack(fill=tk.X, side=tk.TOP)

        self.lbl_metric_high = self._create_metric_pill(metrics_bar, "CRITICAL / HIGH", "0", COLOR_HIGH)
        self.lbl_metric_med  = self._create_metric_pill(metrics_bar, "SUSPICIOUS / MED", "0", COLOR_MEDIUM)
        self.lbl_metric_low  = self._create_metric_pill(metrics_bar, "INFORMATIONAL", "0", COLOR_LOW)
        self.lbl_metric_norm = self._create_metric_pill(metrics_bar, "NORMAL EVENTS", "0", COLOR_NORMAL)
        self.lbl_metric_total = self._create_metric_pill(metrics_bar, "TOTAL SCANNED", "0", TEXT_PRIMARY)

        # Progress bar embedded cleanly
        self.progress = ttk.Progressbar(self.root, style="Custom.Horizontal.TProgressbar",
                                        orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=16, pady=(0, 6))

        # ── 3. Main Multi-Pane Dashboard ──
        self.paned = tk.PanedWindow(self.root, orient=tk.VERTICAL, bg=BORDER_COLOR,
                                    sashrelief=tk.FLAT, sashwidth=6, bd=0)
        self.paned.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 6))

        # ① Live Event Stream Pane
        log_panel = tk.LabelFrame(self.paned, text="  Live Event Stream  ", bg=BG_CARD, fg=TEXT_SECONDARY,
                                  font=(FONT_FAMILY, 9, "bold"), bd=1, relief="solid")
        
        self.text_area = tk.Text(log_panel, height=8, state=tk.DISABLED,
                                 bg=BG_INPUT, fg=TEXT_PRIMARY, font=(FONT_MONO, 9),
                                 insertbackground="white", bd=0, padx=8, pady=6)
        self.text_area.tag_config("FLOOD",  foreground="white",   background=COLOR_FLOOD, font=(FONT_MONO, 9, "bold"))
        self.text_area.tag_config("HIGH",   foreground=COLOR_HIGH, background=BG_INPUT,    font=(FONT_MONO, 9, "bold"))
        self.text_area.tag_config("MEDIUM", foreground=COLOR_MEDIUM)
        self.text_area.tag_config("LOW",    foreground=COLOR_LOW)
        self.text_area.tag_config("NORMAL", foreground=TEXT_SECONDARY)

        scroll_log = ttk.Scrollbar(log_panel, orient=tk.VERTICAL, command=self.text_area.yview)
        self.text_area.configure(yscrollcommand=scroll_log.set)
        scroll_log.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area.pack(fill=tk.BOTH, expand=True)
        self.paned.add(log_panel, minsize=140)

        # ② Active Threats Pane
        threat_panel = tk.LabelFrame(self.paned, text="  ⚠ Active Threats & Process Interceptor  ",
                                     bg=BG_CARD, fg=COLOR_HIGH, font=(FONT_FAMILY, 9, "bold"),
                                     bd=1, relief="solid")

        cols = ("severity", "app", "pid", "time", "description")
        self.threat_tree = ttk.Treeview(threat_panel, columns=cols, show="headings",
                                        style="Custom.Treeview", height=6)
        
        self.threat_tree.heading("severity",    text="Severity", anchor=tk.CENTER)
        self.threat_tree.heading("app",         text="Application / Process", anchor=tk.W)
        self.threat_tree.heading("pid",         text="PID", anchor=tk.CENTER)
        self.threat_tree.heading("time",        text="Timestamp", anchor=tk.CENTER)
        self.threat_tree.heading("description", text="Threat Description & Behavioral Payload", anchor=tk.W)

        self.threat_tree.column("severity",    width=90,  anchor=tk.CENTER, stretch=tk.NO)
        self.threat_tree.column("app",         width=180, anchor=tk.W,      stretch=tk.NO)
        self.threat_tree.column("pid",         width=75,  anchor=tk.CENTER, stretch=tk.NO)
        self.threat_tree.column("time",        width=120, anchor=tk.CENTER, stretch=tk.NO)
        self.threat_tree.column("description", width=550, anchor=tk.W,      stretch=tk.YES)

        self.threat_tree.tag_configure("HIGH",   foreground=COLOR_HIGH,   background="#2a1215")
        self.threat_tree.tag_configure("MEDIUM", foreground=COLOR_MEDIUM, background="#2a1e12")
        self.threat_tree.tag_configure("LOW",    foreground=COLOR_LOW,    background="#121e2a")

        scroll_tree = ttk.Scrollbar(threat_panel, orient=tk.VERTICAL, command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=scroll_tree.set)
        scroll_tree.pack(side=tk.RIGHT, fill=tk.Y)
        self.threat_tree.pack(fill=tk.BOTH, expand=True)

        # Action bar beneath Active Threats
        action_bar = tk.Frame(threat_panel, bg=BG_CARD, pady=4, padx=6)
        action_bar.pack(fill=tk.X)

        tk.Button(action_bar, text="📂 Open File Location", command=self.action_open_location,
                  bg="#27272a", fg="white", activebackground="#3f3f46", activeforeground="white",
                  relief="flat", font=(FONT_FAMILY, 9), padx=10, pady=3, cursor="hand2").pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(action_bar, text="⏸ Suspend Process", command=self.action_suspend,
                  bg="#78350f", fg="#fef08a", activebackground="#92400e", activeforeground="#fef08a",
                  relief="flat", font=(FONT_FAMILY, 9, "bold"), padx=10, pady=3, cursor="hand2").pack(side=tk.LEFT, padx=6)

        tk.Button(action_bar, text="📸 Snapshot (Forensics)", command=self.action_snapshot,
                  bg="#1e1b4b", fg="#c7d2fe", activebackground="#312e81", activeforeground="white",
                  relief="flat", font=(FONT_FAMILY, 9), padx=8, pady=3, cursor="hand2").pack(side=tk.LEFT, padx=5)

        tk.Button(action_bar, text="🌐 Cut Network", command=self.action_isolate_process,
                  bg="#312e81", fg="#e0e7ff", activebackground="#3730a3", activeforeground="white",
                  relief="flat", font=(FONT_FAMILY, 9), padx=8, pady=3, cursor="hand2").pack(side=tk.LEFT, padx=5)

        tk.Button(action_bar, text="❌ End Task (Kill)", command=self.action_end_task,
                  bg="#7f1d1d", fg="#fecaca", activebackground="#991b1b", activeforeground="#fecaca",
                  relief="flat", font=(FONT_FAMILY, 9, "bold"), padx=10, pady=3, cursor="hand2").pack(side=tk.LEFT, padx=6)

        tk.Button(action_bar, text="🗑 Clear Threat List", command=self.clear_threats,
                  bg=BORDER_COLOR, fg=TEXT_SECONDARY, activebackground=BG_CARD_HOVER, activeforeground=TEXT_PRIMARY,
                  relief="flat", font=(FONT_FAMILY, 9), padx=8, pady=3, cursor="hand2").pack(side=tk.RIGHT)

        self.paned.add(threat_panel, minsize=140)

        # ③ Analytics / Charts Pane
        self.chart_panel = tk.LabelFrame(self.paned, text="  Security Analytics & Threat Distribution  ",
                                         bg=BG_CARD, fg=TEXT_SECONDARY, font=(FONT_FAMILY, 9, "bold"),
                                         bd=1, relief="solid")
        self.paned.add(self.chart_panel, minsize=160)
        self.setup_charts()

        # ── 4. Bottom Information Status Bar ──
        statusbar = tk.Frame(self.root, bg=BG_INPUT, height=24, padx=16, pady=4,
                             highlightbackground=BORDER_COLOR, highlightthickness=1)
        statusbar.pack(fill=tk.X, side=tk.BOTTOM)

        lbl_engine = tk.Label(statusbar, text="Ingestion: Active System Pipeline", bg=BG_INPUT, fg=TEXT_MUTED, font=(FONT_FAMILY, 8))
        lbl_engine.pack(side=tk.LEFT)

        self.lbl_footer_status = tk.Label(statusbar, text="Idle • Waiting for triggers", bg=BG_INPUT, fg=TEXT_SECONDARY, font=(FONT_FAMILY, 8))
        self.lbl_footer_status.pack(side=tk.LEFT, padx=20)

        lbl_version = tk.Label(statusbar, text="Sentinel IDS v2.1 • Standalone EDR-Lite", bg=BG_INPUT, fg=TEXT_MUTED, font=(FONT_FAMILY, 8))
        lbl_version.pack(side=tk.RIGHT)

    def _create_metric_pill(self, parent, title, initial_val, accent_color):
        pill = tk.Frame(parent, bg=BG_CARD, padx=12, pady=6,
                        highlightbackground=BORDER_COLOR, highlightthickness=1)
        pill.pack(side=tk.LEFT, padx=(0, 10))

        lbl_title = tk.Label(pill, text=title, bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 7, "bold"))
        lbl_title.pack(anchor=tk.W)

        lbl_val = tk.Label(pill, text=initial_val, bg=BG_CARD, fg=accent_color, font=(FONT_FAMILY, 13, "bold"))
        lbl_val.pack(anchor=tk.W)
        return lbl_val

    # ─────────────────────────────────────────────────────────
    #  Process Action Handlers
    # ─────────────────────────────────────────────────────────
    def _selected_event(self):
        sel = self.threat_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Please select a threat row first.")
            return None
        return self.threat_map.get(sel[0])

    def action_open_location(self):
        ev = self._selected_event()
        if ev is None: return
        path = ev.get("exe_path", "N/A")
        ok, msg = process_control.open_file_location(path)
        if not ok:
            messagebox.showerror("Open Location", msg)

    def action_suspend(self):
        ev = self._selected_event()
        if ev is None: return
        pid = ev.get("pid")
        name = ev.get("process_name", "Unknown")
        if pid is None:
            messagebox.showwarning("Suspend", "No PID available for this event.")
            return
        if not messagebox.askyesno("Confirm Suspend",
                                    f"Suspend process '{name}' (PID {pid})?\n"
                                    "The process will pause in memory without termination."):
            return
        ok, msg = process_control.suspend_process(int(pid), name)
        messagebox.showinfo("Suspend Result", msg)

    def action_snapshot(self):
        ev = self._selected_event()
        if ev is None: return
        pid = ev.get("pid")
        name = ev.get("process_name", "Unknown")
        if pid is None:
            messagebox.showwarning("Snapshot", "No PID available for this event.")
            return
        ok, msg = process_control.capture_snapshot(int(pid), name)
        if ok:
            messagebox.showinfo("Forensics Snapshot Created",
                                f"Digital evidence captured successfully for '{name}' (PID {pid}).\n\n{msg}")
            self.lbl_footer_status.config(text=f"Forensic snapshot saved for PID {pid} ({name})")
        else:
            messagebox.showerror("Snapshot Failed", f"Could not capture forensics: {msg}")

    def action_isolate_process(self):
        ev = self._selected_event()
        if ev is None: return
        pid = ev.get("pid")
        name = ev.get("process_name", "Unknown")
        exe_path = ev.get("exe_path", "")
        if pid is None:
            messagebox.showwarning("Network Cut", "No PID available for this event.")
            return
        if not messagebox.askyesno("Confirm Process Network Isolation",
                                    f"🌐 Sever all network connectivity for '{name}' (PID {pid})?\n\n"
                                    "Active TCP/UDP sockets will be blocked via kernel firewall rules.\n"
                                    "The process will remain running locally for analysis but cannot communicate over the network.",
                                    icon="warning"):
            return
        ok, msg = process_control.isolate_process_network(int(pid), name, exe_path)
        if ok:
            messagebox.showinfo("Network Cut Applied", msg)
            self.lbl_footer_status.config(text=f"Network blocked for PID {pid} ({name})")
        else:
            messagebox.showerror("Network Cut Failed", msg)

    def action_toggle_host_isolation(self):
        if not process_control.is_host_isolated():
            if not messagebox.askyesno("🚨 EMERGENCY HOST NETWORK CONTAINMENT",
                                        "Are you sure you want to isolate this entire machine from the network?\n\n"
                                        "• All inbound and outbound traffic will be dropped immediately.\n"
                                        "• Loopback / local inter-process communication remains functional.\n"
                                        "• Lateral movement and ransomware C2 beacons will be instantly severed.\n\n"
                                        "Proceed with Host Isolation?",
                                        icon="warning"):
                return
            ok, msg = process_control.isolate_host()
            if ok:
                self.btn_host_isolate.config(text="🟢 Restore Network", bg="#14532d", fg="#86efac",
                                             activebackground="#166534", activeforeground="white")
                self.lbl_footer_status.config(text="🚨 HOST NETWORK ISOLATED — System in quarantine mode")
                messagebox.showwarning("Host Isolated", "Host is now isolated from all external network traffic.")
            else:
                messagebox.showerror("Isolation Failed", f"Failed to isolate host: {msg}")
        else:
            if not messagebox.askyesno("Confirm Network Restore",
                                        "Restore normal network connectivity to this host?\n\n"
                                        "Firewall isolation rules will be flushed and normal traffic will resume."):
                return
            ok, msg = process_control.restore_host()
            if ok:
                self.btn_host_isolate.config(text="🛑 Isolate Host", bg="#451a03", fg="#fde047",
                                             activebackground="#78350f", activeforeground="#fef08a")
                self.lbl_footer_status.config(text="Host network restored to normal operations")
                messagebox.showinfo("Network Restored", "Host network isolation rules successfully removed.")
            else:
                messagebox.showerror("Restore Failed", f"Failed to restore network: {msg}")

    def action_end_task(self):
        ev = self._selected_event()
        if ev is None: return
        pid = ev.get("pid")
        name = ev.get("process_name", "Unknown")
        if pid is None:
            messagebox.showwarning("End Task", "No PID available for this event.")
            return
        if not messagebox.askyesno("Confirm End Task",
                                    f"⚠ This will TERMINATE '{name}' (PID {pid}).\n\n"
                                    "A pre-kill digital forensics snapshot (memory dump, binary hash, sockets) "
                                    "will be automatically saved to logs/forensics/.\n\n"
                                    "Proceed with termination?",
                                    icon="warning"):
            return
        ok, msg = process_control.kill_process(int(pid), name)
        messagebox.showinfo("End Task Result", msg)

    def clear_threats(self):
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
        self.threat_map.clear()

    # ─────────────────────────────────────────────────────────
    #  Limitations Popup
    # ─────────────────────────────────────────────────────────
    def show_limitations(self):
        win = tk.Toplevel(self.root)
        win.title("Sentinel IDS — System Limitations & Constraints")
        win.geometry("640x500")
        win.configure(bg=BG_DARK)
        txt = tk.Text(win, wrap=tk.WORD, font=(FONT_MONO, 9), bg=BG_INPUT, fg=TEXT_PRIMARY,
                      padx=12, pady=12, bd=0)
        txt.insert(tk.END, get_limitations_text())
        txt.config(state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        tk.Button(win, text="Close", command=win.destroy, bg=BORDER_COLOR, fg=TEXT_PRIMARY,
                  relief="flat", padx=14, pady=4).pack(pady=(0, 10))

    # ─────────────────────────────────────────────────────────
    #  Mute Toggle
    # ─────────────────────────────────────────────────────────
    def toggle_mute(self):
        if self.notifications_enabled:
            self.notifications_enabled = False
            self.btn_mute.config(text="🔕 Alerts: Muted", bg="#7f1d1d", fg="white")
        else:
            self.notifications_enabled = True
            self.btn_mute.config(text="🔔 Alerts: Active", bg=BORDER_COLOR, fg=TEXT_PRIMARY)

    # ─────────────────────────────────────────────────────────
    #  Charts (Safe, Dark Themed, Properly Aligned)
    # ─────────────────────────────────────────────────────────
    def setup_charts(self):
        if not HAS_MATPLOTLIB:
            # Fallback frame if matplotlib is not installed
            msg_frame = tk.Frame(self.chart_panel, bg=BG_CARD)
            msg_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            tk.Label(msg_frame, text="📊 Live Charts: python3-matplotlib is not installed.",
                     bg=BG_CARD, fg=TEXT_SECONDARY, font=(FONT_FAMILY, 10, "bold")).pack(pady=4)
            tk.Label(msg_frame, text="Install via: sudo dnf install python3-matplotlib (Fedora) or pip install matplotlib",
                     bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 9)).pack()
            return

        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 2.8))
        self.fig.patch.set_facecolor(BG_CARD)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_panel)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        self.update_charts_display()

    def update_charts_display(self):
        if not HAS_MATPLOTLIB:
            return

        labels = ["HIGH", "MEDIUM", "LOW", "NORMAL"]
        values = [self.stats.get(l, 0) for l in labels]
        colors = [COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_NORMAL]

        self.ax1.clear()
        self.ax2.clear()

        # Bar chart
        bars = self.ax1.bar(labels, values, color=colors, width=0.55)
        self.ax1.set_title('Threat Categorization', color=TEXT_PRIMARY, fontsize=9, fontweight='bold', pad=8)
        self.ax1.set_ylabel('Count', color=TEXT_SECONDARY, fontsize=8)
        self.ax1.set_facecolor(BG_INPUT)
        self.ax1.tick_params(colors=TEXT_SECONDARY, labelsize=8)
        self.ax1.spines['bottom'].set_color(BORDER_COLOR)
        self.ax1.spines['top'].set_visible(False)
        self.ax1.spines['right'].set_visible(False)
        self.ax1.spines['left'].set_color(BORDER_COLOR)

        # Pie chart
        pie_labels = [l for l, v in zip(labels, values) if v > 0]
        pie_values = [v for v in values if v > 0]
        pie_colors = [c for c, v in zip(colors, values) if v > 0]

        self.ax2.set_facecolor(BG_CARD)
        if pie_values:
            wedges, texts, autotexts = self.ax2.pie(
                pie_values, labels=pie_labels, colors=pie_colors,
                autopct='%1.0f%%', startangle=90,
                textprops=dict(color=TEXT_PRIMARY, fontsize=8)
            )
            for autotext in autotexts:
                autotext.set_color("black")
                autotext.set_weight("bold")
            self.ax2.set_title('Threat Distribution', color=TEXT_PRIMARY, fontsize=9, fontweight='bold', pad=8)
        else:
            self.ax2.text(0.5, 0.5, 'No Security Events Yet', ha='center', va='center',
                          color=TEXT_MUTED, fontsize=9)
            self.ax2.axis('off')

        try:
            self.fig.tight_layout(pad=1.5)
        except Exception:
            pass

        self.canvas.draw_idle()

    # ─────────────────────────────────────────────────────────
    #  Event Queue & Background Consumer
    # ─────────────────────────────────────────────────────────
    def on_new_event(self, event_data, severity):
        self.event_queue.put((event_data, severity))

    def poll_queue(self):
        try:
            updates = 0
            while True:
                event_data, severity = self.event_queue.get_nowait()
                is_flood = severity == "HIGH_FLOOD"
                if is_flood:
                    severity = "HIGH"

                self.stats[severity] = self.stats.get(severity, 0) + 1
                self.total_scanned += 1

                # Update metric indicators
                self.lbl_metric_high.config(text=str(self.stats.get("HIGH", 0)))
                self.lbl_metric_med.config(text=str(self.stats.get("MEDIUM", 0)))
                self.lbl_metric_low.config(text=str(self.stats.get("LOW", 0)))
                self.lbl_metric_norm.config(text=str(self.stats.get("NORMAL", 0)))
                self.lbl_metric_total.config(text=str(self.total_scanned))

                clean_msg = str(event_data.get('message', '')).replace('\n', ' ').replace('\r', '')
                source_label = event_data.get('process_name') or event_data.get('source') or '?'
                msg = f"[{severity:<6}] ID:{event_data.get('event_id', 0):<4} | {source_label[:18]:<18} | {clean_msg[:120]}"

                if is_flood:
                    msg = f"⚠ FLOOD ALERT: High frequency activity detected!\n{msg}"

                # Append to Active Threats if not NORMAL
                if severity != "NORMAL":
                    ts = datetime.datetime.now().strftime("%H:%M:%S")
                    app_name = event_data.get("process_name") or event_data.get("source") or "Unknown"
                    if event_data.get("parent_name") and event_data.get("parent_name") != "Unknown":
                        app_name = f"{app_name} (PPID:{event_data.get('ppid')})"
                    pid_val = event_data.get("pid") or "—"
                    desc = clean_msg
                    if event_data.get("lotl_rule"):
                        desc = f"[{event_data['lotl_rule']}] {desc}"
                    elif event_data.get("lineage_str") and event_data.get("lineage_str") != "N/A":
                        desc = f"{desc} | Tree: {event_data['lineage_str']}"
                    desc = desc[:150]

                    iid = self.threat_tree.insert(
                        "", tk.END,
                        values=(severity, app_name, pid_val, ts, desc),
                        tags=(severity,)
                    )
                    self.threat_map[iid] = event_data
                    self.threat_tree.see(iid)

                # Send tray notification on HIGH
                if severity == "HIGH" and self.is_live and self.notifications_enabled:
                    log_alert_to_file({
                        "severity": severity,
                        "event_id": event_data.get('event_id'),
                        "source": event_data.get('source', 'Live'),
                        "message": msg
                    })

                # Stream to Live Text Console
                if severity != "NORMAL" or self.is_live:
                    self.text_area.config(state=tk.NORMAL)
                    tag = "FLOOD" if is_flood else severity
                    self.text_area.insert(tk.END, msg + "\n", tag)
                    self.text_area.see(tk.END)
                    self.text_area.config(state=tk.DISABLED)

                updates += 1
                if updates > 50:
                    break
        except queue.Empty:
            pass

        self.root.after(100, self.poll_queue)

    def periodic_chart_update(self):
        if self.is_live:
            self.update_charts_display()
            self.root.after(2000, self.periodic_chart_update)

    # ─────────────────────────────────────────────────────────
    #  Live Monitoring Toggle
    # ─────────────────────────────────────────────────────────
    def toggle_live(self):
        if not self.is_live:
            self.is_live = True
            self.btn_live_toggle.config(text="⏹ Stop Live Monitor", bg="#b91c1c", activebackground="#dc2626")
            self.lbl_status_badge.config(text="● MONITORING ACTIVE", bg="#064e3b", fg="#34d399")
            self.lbl_footer_status.config(text="Live Stream Active • Processing system events in real-time")
            self.btn_upload.config(state=tk.DISABLED)

            self.live_reader = LogReader(silent=True)
            self.proc_tree = get_process_tree()
            self.proc_tree.start()
            self.canary_sentry = get_canary_sentry()
            self.canary_sentry.start()
            self.stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
            self.total_scanned = 0
            self.text_area.config(state=tk.NORMAL)
            self.text_area.delete("1.0", tk.END)
            self.text_area.config(state=tk.DISABLED)

            threading.Thread(target=self.live_reader.start, daemon=True).start()
            self.root.after(2000, self.periodic_chart_update)
        else:
            self.is_live = False
            self.btn_live_toggle.config(text="▶ Start Live Monitor", bg="#15803d", activebackground="#16a34a")
            self.lbl_status_badge.config(text="● PAUSED", bg="#1e293b", fg="#38bdf8")
            self.lbl_footer_status.config(text="Monitoring Paused • Ready")
            self.btn_upload.config(state=tk.NORMAL)
            if self.live_reader:
                self.live_reader.stop()
            if hasattr(self, 'canary_sentry') and self.canary_sentry:
                self.canary_sentry.stop(cleanup=False)
            if hasattr(self, 'proc_tree') and self.proc_tree:
                self.proc_tree.stop()
            self.update_charts_display()

    # ─────────────────────────────────────────────────────────
    #  Offline File Analysis
    # ─────────────────────────────────────────────────────────
    def upload_file(self):
        if self.is_processing or self.is_live:
            messagebox.showwarning("Busy", "Cannot upload while processing or monitoring.")
            return

        filepath = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=(("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if not filepath:
            return

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                self.log_lines = [l.strip() for l in f if l.strip()]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{e}")
            return

        if not self.log_lines:
            messagebox.showerror("Error", "The selected file is empty.")
            return

        self.lbl_status_badge.config(text="● ANALYZING FILE", bg="#78350f", fg="#fde047")
        self.lbl_footer_status.config(text=f"Loaded: {os.path.basename(filepath)} ({len(self.log_lines)} lines)")
        self.stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
        self.total_scanned = 0
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete("1.0", tk.END)
        self.text_area.config(state=tk.DISABLED)

        threading.Thread(target=self.process_offline_logs, daemon=True).start()

    def process_offline_logs(self):
        self.is_processing = True
        self.btn_upload.config(state=tk.DISABLED)
        self.btn_live_toggle.config(state=tk.DISABLED)

        total = len(self.log_lines)
        self.progress['maximum'] = total
        self.progress['value'] = 0

        def offline_chart_updater():
            if self.is_processing:
                self.update_charts_display()
                self.root.after(2000, offline_chart_updater)
        self.root.after(2000, offline_chart_updater)

        for i, line in enumerate(self.log_lines):
            process_event({"event_id": 0, "message": line, "source": "Offline Scan"}, silent=True)
            self.root.after(0, self.update_progress, i + 1, total)

        self.root.after(0, self.finish_processing)

    def update_progress(self, current, total):
        self.progress['value'] = current
        self.lbl_footer_status.config(text=f"Analyzing... {current}/{total} ({int((current/total)*100)}%)")

    def finish_processing(self):
        self.is_processing = False
        self.btn_upload.config(state=tk.NORMAL)
        self.btn_live_toggle.config(state=tk.NORMAL)
        self.lbl_status_badge.config(text="● COMPLETED", bg="#064e3b", fg="#34d399")
        self.lbl_footer_status.config(text="Offline Analysis Complete")
        self.update_charts_display()


def run_desktop_app():
    root = tk.Tk()
    app = DesktopIDSApp(root)
    root.mainloop()


if __name__ == "__main__":
    run_desktop_app()
