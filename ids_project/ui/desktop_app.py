import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import sys
import subprocess
import queue
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from core.decision_engine import process_event, subscribe
from core.log_reader import LogReader
from core.alert import log_alert_to_file

class DesktopIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows IDS - Advanced SIEM")
        self.root.geometry("1100x800")

        self.stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
        
        self.log_lines = []
        self.is_processing = False
        
        self.is_live = False
        self.live_reader = None
        self.event_queue = queue.Queue()

        self.setup_ui()
        self.start_tray_detached()
        
        subscribe(self.on_new_event)
        self.poll_queue()

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

    def setup_ui(self):
        control_frame = tk.Frame(self.root, pady=10)
        control_frame.pack(fill=tk.X)

        offline_frame = tk.LabelFrame(control_frame, text="Offline Analysis")
        offline_frame.pack(side=tk.LEFT, padx=10, fill=tk.Y)

        self.btn_upload = tk.Button(offline_frame, text="Upload Log File", command=self.upload_file, width=15)
        self.btn_upload.pack(side=tk.LEFT, padx=5, pady=5)

        live_frame = tk.LabelFrame(control_frame, text="Live Monitoring")
        live_frame.pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        self.btn_live_toggle = tk.Button(live_frame, text="Start Live Monitor", command=self.toggle_live, width=18, fg="green")
        self.btn_live_toggle.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Mute control
        notify_frame = tk.LabelFrame(control_frame, text="Notifications")
        notify_frame.pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        self.notifications_enabled = True
        self.btn_mute = tk.Button(notify_frame, text="Mute OS Alerts", command=self.toggle_mute, width=15, fg="black")
        self.btn_mute.pack(side=tk.LEFT, padx=5, pady=5)
        
        status_frame = tk.Frame(control_frame)
        status_frame.pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        self.lbl_status = tk.Label(status_frame, text="Ready.", fg="blue", font=("Arial", 10, "bold"))
        self.lbl_status.pack(side=tk.LEFT, padx=5, pady=10)

        self.btn_exit = tk.Button(control_frame, text="Exit UI", command=self.root.quit, width=10)
        self.btn_exit.pack(side=tk.RIGHT, padx=10, pady=10)

        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        self.paned = tk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Standard Log Area
        self.text_area = tk.Text(self.paned, height=12, state=tk.DISABLED, bg="#1e1e1e", fg="white", font=("Consolas", 10))
        self.text_area.tag_config("FLOOD", foreground="white", background="red", font=("Consolas", 10, "bold"))
        self.text_area.tag_config("HIGH", foreground="red", background="black", font=("Consolas", 10, "bold"))
        self.text_area.tag_config("MEDIUM", foreground="orange")
        self.text_area.tag_config("LOW", foreground="yellow")
        self.text_area.tag_config("NORMAL", foreground="white")
        self.paned.add(self.text_area)

        # High Alerts Frame
        high_frame = tk.LabelFrame(self.paned, text="Recent HIGH Alerts", fg="red", font=("Arial", 10, "bold"), bg="#110000")
        self.high_listbox = tk.Listbox(high_frame, height=5, bg="#2e0000", fg="#ff4444", font=("Consolas", 10, "bold"), selectbackground="#ff0000")
        self.high_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.paned.add(high_frame)

        self.chart_frame = tk.Frame(self.paned, bg="white")
        self.paned.add(self.chart_frame)
        
        self.setup_charts()
        
    def toggle_mute(self):
        if self.notifications_enabled:
            self.notifications_enabled = False
            self.btn_mute.config(text="Alerts Muted", fg="red")
        else:
            self.notifications_enabled = True
            self.btn_mute.config(text="Mute OS Alerts", fg="black")

    def setup_charts(self):
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 3.5))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.update_charts_display()

    def update_charts_display(self):
        labels = list(self.stats.keys())
        values = list(self.stats.values())
        colors = ['red', 'orange', 'yellow', 'green']

        self.ax1.clear()
        self.ax2.clear()

        self.ax1.bar(labels, values, color=colors)
        self.ax1.set_title('Threat Categorization')
        self.ax1.set_ylabel('Events')

        pie_labels = [l for l, v in zip(labels, values) if v > 0]
        pie_values = [v for v in values if v > 0]
        pie_colors = [c for c, v in zip(colors, values) if v > 0]

        if pie_values:
            self.ax2.pie(pie_values, labels=pie_labels, colors=pie_colors, autopct='%1.1f%%', startangle=90)
            self.ax2.axis('equal')
            self.ax2.set_title('Threat Distribution')
        else:
            self.ax2.text(0.5, 0.5, 'No Data', ha='center', va='center')
            self.ax2.axis('off')

        self.canvas.draw()
        
    def on_new_event(self, event_data, severity):
        self.event_queue.put((event_data, severity))
        
    def poll_queue(self):
        try:
            updates = 0
            while True:
                event_data, severity = self.event_queue.get_nowait()
                
                is_flood = False
                if severity == "HIGH_FLOOD":
                    is_flood = True
                    severity = "HIGH"
                
                self.stats[severity] += 1
                
                msg = f"[{severity}] ID: {event_data.get('event_id', 0)} | {str(event_data.get('message', ''))[:150]}"
                
                if is_flood:
                    msg = f"HIGH ALERT: Suspicious activity flood detected!\n{msg}"
                
                # Dedicated HIGH panel routing and System Notifications
                if severity == "HIGH":
                    self.high_listbox.insert(tk.END, msg)
                    self.high_listbox.see(tk.END)
                    
                    # Trigger system tray notification safely via IPC alerts.json only if enabled
                    if self.is_live and self.notifications_enabled:
                        alert_info = {
                            "severity": severity,
                            "event_id": event_data.get('event_id'),
                            "source": event_data.get('source', 'Offline'),
                            "message": msg
                        }
                        log_alert_to_file(alert_info)
                
                if severity != "NORMAL" or self.is_live:
                    self.text_area.config(state=tk.NORMAL)
                    if is_flood:
                        self.text_area.insert(tk.END, msg + "\n\n", "FLOOD")
                    else:
                        self.text_area.insert(tk.END, msg + "\n", severity)
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

    def toggle_live(self):
        if not self.is_live:
            self.is_live = True
            self.btn_live_toggle.config(text="Stop Live Monitor", fg="red")
            self.lbl_status.config(text="Live Monitoring Active...")
            self.btn_upload.config(state=tk.DISABLED)
            
            self.live_reader = LogReader(silent=True)
            
            self.stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
            self.text_area.config(state=tk.NORMAL)
            self.text_area.delete("1.0", tk.END)
            self.text_area.config(state=tk.DISABLED)
            
            self.high_listbox.delete(0, tk.END)
            
            threading.Thread(target=self.live_reader.start, daemon=True).start()
            self.root.after(2000, self.periodic_chart_update)
        else:
            self.is_live = False
            self.btn_live_toggle.config(text="Start Live Monitor", fg="green")
            self.lbl_status.config(text="Live Monitoring Stopped.")
            self.btn_upload.config(state=tk.NORMAL)
            
            if self.live_reader:
                self.live_reader.stop()
            self.update_charts_display()

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
                self.log_lines = [line.strip() for line in f.readlines() if line.strip()]
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
        
        self.high_listbox.delete(0, tk.END)
        
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
            event_data = {
                "event_id": 0, 
                "message": line,
                "source": "Offline Scan"
            }
            process_event(event_data, silent=True)
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
