import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import sys
import subprocess
import queue
import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from core.decision_engine import process_event, subscribe
from core.log_reader import LogReader
from core.alert import log_alert_to_file
from core.limitations import get_limitations_text
from core import process_control

SEVERITY_COLORS = {
    "HIGH": "#ff4444",
    "MEDIUM": "orange",
    "LOW": "yellow",
    "NORMAL": "white",
}

class DesktopIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows IDS — Professional SIEM")
        self.root.geometry("1200x860")

        self.stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
        self.log_lines = []
        self.is_processing = False
        self.is_live = False
        self.live_reader = None
        self.event_queue = queue.Queue()
        # threat_map: treeview item id -> event_data dict
        self.threat_map = {}

        self.setup_ui()
        self.start_tray_detached()
        subscribe(self.on_new_event)
        self.poll_queue()

    # ──────────────────────────────────────────
    #  Tray
    # ──────────────────────────────────────────
    def start_tray_detached(self):
        try:
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            cmd = [sys.executable, "main.py", "--tray"]
            subprocess.Popen(
                cmd,
                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
        except Exception as e:
            print(f"Failed to spawn detached tray app: {e}")

    # ──────────────────────────────────────────
    #  UI Layout
    # ──────────────────────────────────────────
    def setup_ui(self):
        # ── Top Toolbar ──
        toolbar = tk.Frame(self.root, pady=6)
        toolbar.pack(fill=tk.X)

        offline_frame = tk.LabelFrame(toolbar, text="Offline Analysis")
        offline_frame.pack(side=tk.LEFT, padx=8, fill=tk.Y)
        self.btn_upload = tk.Button(offline_frame, text="Upload Log File", command=self.upload_file, width=15)
        self.btn_upload.pack(side=tk.LEFT, padx=4, pady=4)

        live_frame = tk.LabelFrame(toolbar, text="Live Monitoring")
        live_frame.pack(side=tk.LEFT, padx=8, fill=tk.Y)
        self.btn_live_toggle = tk.Button(live_frame, text="▶ Start Live Monitor",
                                         command=self.toggle_live, width=20, fg="green")
        self.btn_live_toggle.pack(side=tk.LEFT, padx=4, pady=4)

        notify_frame = tk.LabelFrame(toolbar, text="Notifications")
        notify_frame.pack(side=tk.LEFT, padx=8, fill=tk.Y)
        self.notifications_enabled = True
        self.btn_mute = tk.Button(notify_frame, text="Mute OS Alerts",
                                   command=self.toggle_mute, width=15, fg="black")
        self.btn_mute.pack(side=tk.LEFT, padx=4, pady=4)

        info_frame = tk.LabelFrame(toolbar, text="Help")
        info_frame.pack(side=tk.LEFT, padx=8, fill=tk.Y)
        tk.Button(info_frame, text="View Limitations", command=self.show_limitations, width=15).pack(padx=4, pady=4)

        self.lbl_status = tk.Label(toolbar, text="Ready.", fg="blue", font=("Arial", 10, "bold"))
        self.lbl_status.pack(side=tk.LEFT, padx=10)

        tk.Button(toolbar, text="Exit UI", command=self.root.quit, width=8).pack(side=tk.RIGHT, padx=10)

        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=3)

        # ── Main Paned Area ──
        self.paned = tk.PanedWindow(self.root, orient=tk.VERTICAL, sashrelief=tk.RAISED)
        self.paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # ① Live Log Stream
        log_frame = tk.LabelFrame(self.paned, text="Live Event Stream")
        self.text_area = tk.Text(log_frame, height=10, state=tk.DISABLED,
                                  bg="#1e1e1e", fg="white", font=("Consolas", 10))
        self.text_area.tag_config("FLOOD",  foreground="white",  background="red",    font=("Consolas", 10, "bold"))
        self.text_area.tag_config("HIGH",   foreground="red",    background="#1e1e1e", font=("Consolas", 10, "bold"))
        self.text_area.tag_config("MEDIUM", foreground="orange")
        self.text_area.tag_config("LOW",    foreground="yellow")
        self.text_area.tag_config("NORMAL", foreground="white")
        scroll_log = ttk.Scrollbar(log_frame, command=self.text_area.yview)
        self.text_area.configure(yscrollcommand=scroll_log.set)
        scroll_log.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area.pack(fill=tk.BOTH, expand=True)
        self.paned.add(log_frame)

        # ② Active Threats Treeview
        threat_frame = tk.LabelFrame(self.paned, text="⚠ Active Threats",
                                      fg="red", font=("Arial", 10, "bold"))
        cols = ("severity", "app", "pid", "time", "description")
        self.threat_tree = ttk.Treeview(threat_frame, columns=cols, show="headings", height=7)
        self.threat_tree.heading("severity",    text="Severity")
        self.threat_tree.heading("app",         text="Application")
        self.threat_tree.heading("pid",         text="PID")
        self.threat_tree.heading("time",        text="Timestamp")
        self.threat_tree.heading("description", text="Description")
        self.threat_tree.column("severity",    width=75,  anchor=tk.CENTER)
        self.threat_tree.column("app",         width=160)
        self.threat_tree.column("pid",         width=60,  anchor=tk.CENTER)
        self.threat_tree.column("time",        width=140, anchor=tk.CENTER)
        self.threat_tree.column("description", width=450)

        # Row colour tags
        self.threat_tree.tag_configure("HIGH",   foreground="#ff4444", background="#1a0000")
        self.threat_tree.tag_configure("MEDIUM", foreground="orange",  background="#1a1000")
        self.threat_tree.tag_configure("LOW",    foreground="#cccc00", background="#111100")

        scroll_tree = ttk.Scrollbar(threat_frame, command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=scroll_tree.set)
        scroll_tree.pack(side=tk.RIGHT, fill=tk.Y)
        self.threat_tree.pack(fill=tk.BOTH, expand=True)

        # Action buttons beneath the treeview
        action_bar = tk.Frame(threat_frame)
        action_bar.pack(fill=tk.X, pady=3)
        tk.Button(action_bar, text="📂 Open Location", command=self.action_open_location,
                  bg="#2a2a2a", fg="white", width=16).pack(side=tk.LEFT, padx=6)
        tk.Button(action_bar, text="⏸  Suspend Process", command=self.action_suspend,
                  bg="#333300", fg="yellow", width=18).pack(side=tk.LEFT, padx=6)
        tk.Button(action_bar, text="❌ End Task", command=self.action_end_task,
                  bg="#330000", fg="#ff4444", width=14).pack(side=tk.LEFT, padx=6)
        tk.Button(action_bar, text="Clear Threats", command=self.clear_threats,
                  width=12).pack(side=tk.RIGHT, padx=6)

        self.paned.add(threat_frame)

        # ③ Charts
        self.chart_frame = tk.Frame(self.paned, bg="white")
        self.paned.add(self.chart_frame)
        self.setup_charts()

    # ──────────────────────────────────────────
    #  Process Action Helpers
    # ──────────────────────────────────────────
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
                                    "The process will pause but not be terminated."):
            return
        ok, msg = process_control.suspend_process(int(pid), name)
        messagebox.showinfo("Suspend Result", msg)

    def action_end_task(self):
        ev = self._selected_event()
        if ev is None: return
        pid = ev.get("pid")
        name = ev.get("process_name", "Unknown")
        if pid is None:
            messagebox.showwarning("End Task", "No PID available for this event.")
            return
        if not messagebox.askyesno("Confirm End Task",
                                    f"⚠ This will TERMINATE '{name}' (PID {pid}).\n"
                                    "Data in that process may be lost. Proceed?",
                                    icon="warning"):
            return
        ok, msg = process_control.kill_process(int(pid), name)
        messagebox.showinfo("End Task Result", msg)

    def clear_threats(self):
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
        self.threat_map.clear()

    # ──────────────────────────────────────────
    #  Limitations Popup
    # ──────────────────────────────────────────
    def show_limitations(self):
        win = tk.Toplevel(self.root)
        win.title("IDS System Limitations")
        win.geometry("620x460")
        txt = tk.Text(win, wrap=tk.WORD, font=("Consolas", 10), bg="#1e1e1e", fg="#cccccc",
                      padx=10, pady=10)
        txt.insert(tk.END, get_limitations_text())
        txt.config(state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True)
        tk.Button(win, text="Close", command=win.destroy).pack(pady=6)

    # ──────────────────────────────────────────
    #  Mute Toggle
    # ──────────────────────────────────────────
    def toggle_mute(self):
        if self.notifications_enabled:
            self.notifications_enabled = False
            self.btn_mute.config(text="Alerts Muted ✕", fg="red")
        else:
            self.notifications_enabled = True
            self.btn_mute.config(text="Mute OS Alerts", fg="black")

    # ──────────────────────────────────────────
    #  Charts
    # ──────────────────────────────────────────
    def setup_charts(self):
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.update_charts_display()

    def update_charts_display(self):
        labels = list(self.stats.keys())
        values = list(self.stats.values())
        colors = ['#ff4444', 'orange', 'yellow', '#44aa44']

        self.ax1.clear()
        self.ax2.clear()

        self.ax1.bar(labels, values, color=colors)
        self.ax1.set_title('Threat Categorization')
        self.ax1.set_ylabel('Events')
        self.ax1.set_facecolor('#1e1e1e')
        self.ax1.figure.patch.set_facecolor('#1e1e1e')
        self.ax1.tick_params(colors='white')
        self.ax1.title.set_color('white')
        self.ax1.yaxis.label.set_color('white')

        pie_labels  = [l for l, v in zip(labels, values) if v > 0]
        pie_values  = [v for v in values if v > 0]
        pie_colors  = [c for c, v in zip(colors, values) if v > 0]

        self.ax2.set_facecolor('#1e1e1e')
        self.ax2.figure.patch.set_facecolor('#1e1e1e')
        if pie_values:
            wedges, texts, autotexts = self.ax2.pie(
                pie_values, labels=pie_labels, colors=pie_colors,
                autopct='%1.1f%%', startangle=90)
            for t in texts + autotexts:
                t.set_color('white')
            self.ax2.set_title('Threat Distribution', color='white')
        else:
            self.ax2.text(0.5, 0.5, 'No Data', ha='center', va='center', color='grey')
            self.ax2.axis('off')

        self.canvas.draw()

    # ──────────────────────────────────────────
    #  Event Queue / Pub-Sub
    # ──────────────────────────────────────────
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

                self.stats[severity] += 1

                clean_msg = str(event_data.get('message', '')).replace('\n', ' ').replace('\r', '')
                msg = (f"[{severity}] ID:{event_data.get('event_id', 0)} "
                       f"| {event_data.get('process_name', event_data.get('source','?'))} "
                       f"| {clean_msg[:120]}")

                if is_flood:
                    msg = f"HIGH ALERT: Suspicious activity flood detected!\n{msg}"

                # ── Active Threats treeview (non-NORMAL only)
                if severity != "NORMAL":
                    ts = datetime.datetime.now().strftime("%H:%M:%S")
                    app_name  = event_data.get("process_name", event_data.get("source", "Unknown"))
                    pid_val   = event_data.get("pid") or "—"
                    desc      = clean_msg[:120]
                    iid = self.threat_tree.insert(
                        "", tk.END,
                        values=(severity, app_name, pid_val, ts, desc),
                        tags=(severity,)
                    )
                    self.threat_map[iid] = event_data
                    self.threat_tree.see(iid)

                # ── HIGH → tray notification
                if severity == "HIGH" and self.is_live and self.notifications_enabled:
                    log_alert_to_file({
                        "severity": severity,
                        "event_id": event_data.get('event_id'),
                        "source": event_data.get('source', 'Live'),
                        "message": msg
                    })

                # ── Live text stream
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

    # ──────────────────────────────────────────
    #  Live Monitoring Toggle
    # ──────────────────────────────────────────
    def toggle_live(self):
        if not self.is_live:
            self.is_live = True
            self.btn_live_toggle.config(text="⏹ Stop Live Monitor", fg="red")
            self.lbl_status.config(text="🔴 Live Monitoring Active...")
            self.btn_upload.config(state=tk.DISABLED)

            self.live_reader = LogReader(silent=True)
            self.stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
            self.text_area.config(state=tk.NORMAL)
            self.text_area.delete("1.0", tk.END)
            self.text_area.config(state=tk.DISABLED)

            threading.Thread(target=self.live_reader.start, daemon=True).start()
            self.root.after(2000, self.periodic_chart_update)
        else:
            self.is_live = False
            self.btn_live_toggle.config(text="▶ Start Live Monitor", fg="green")
            self.lbl_status.config(text="Monitoring Stopped.")
            self.btn_upload.config(state=tk.NORMAL)
            if self.live_reader:
                self.live_reader.stop()
            self.update_charts_display()

    # ──────────────────────────────────────────
    #  Offline File Analysis
    # ──────────────────────────────────────────
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

        self.lbl_status.config(text=f"Loaded: {os.path.basename(filepath)} ({len(self.log_lines)} lines)")
        self.stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
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
        self.lbl_status.config(text=f"Analyzing... {current}/{total}")

    def finish_processing(self):
        self.is_processing = False
        self.btn_upload.config(state=tk.NORMAL)
        self.btn_live_toggle.config(state=tk.NORMAL)
        self.lbl_status.config(text="Analysis Complete!")
        self.update_charts_display()


def run_desktop_app():
    root = tk.Tk()
    app = DesktopIDSApp(root)
    root.mainloop()
