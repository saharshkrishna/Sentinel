import pystray
from PIL import Image, ImageDraw
import os
import time
import json
import threading
import sys
import tempfile
import msvcrt
import win32serviceutil
from config.settings import ALERTS_JSON_FILE, SERVICE_NAME

def create_icon_image(color1, color2):
    # Generates a basic shield icon representing security IDS
    width = 64
    height = 64
    image = Image.new('RGBA', (width, height), (255, 255, 255, 0))
    d = ImageDraw.Draw(image)
    d.polygon([(32, 5), (60, 20), (50, 50), (32, 60), (14, 50), (4, 20)], fill=color1, outline=color2)
    return image

def get_service_status():
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
        if status == 4: # SERVICE_RUNNING
            return "Running"
        elif status == 1: # SERVICE_STOPPED
            return "Stopped"
        else:
            return "Pending"
    except Exception:
        return "Not Installed"

def start_service(icon, item):
    try:
        win32serviceutil.StartService(SERVICE_NAME)
        icon.notify("IDS Service Started successfully", "Windows IDS")
    except Exception as e:
        icon.notify(f"Failed to start service. Run as Admin? ({str(e)[:50]})", "Windows IDS Error")

def stop_service(icon, item):
    try:
        win32serviceutil.StopService(SERVICE_NAME)
        icon.notify("IDS Service Stopped", "Windows IDS")
    except Exception as e:
        icon.notify(f"Failed to stop service. ({str(e)[:50]})", "Windows IDS Error")

def view_alerts(icon, item):
    if os.path.exists(ALERTS_JSON_FILE):
        os.startfile(ALERTS_JSON_FILE)
    else:
        icon.notify("No alerts recorded yet.", "Windows IDS")

def exit_action(icon, item):
    icon.stop()

def poll_alerts(icon):
    # Monitor the alerts.json file and dispatch notifications
    last_size = 0
    if os.path.exists(ALERTS_JSON_FILE):
        last_size = os.path.getsize(ALERTS_JSON_FILE)
        
    while icon.visible:
        try:
            if os.path.exists(ALERTS_JSON_FILE):
                current_size = os.path.getsize(ALERTS_JSON_FILE)
                if current_size > last_size:
                    with open(ALERTS_JSON_FILE, "r") as f:
                        f.seek(last_size)
                        new_lines = f.readlines()
                    last_size = current_size
                    
                    valid_alerts = []
                    for line in new_lines:
                        if line.strip():
                            try:
                                valid_alerts.append(json.loads(line))
                            except:
                                pass
                                
                    if valid_alerts:
                        if len(valid_alerts) > 1:
                            title = f"IDS: {len(valid_alerts)} Alerts Flagged!"
                            latest = valid_alerts[-1]
                            msg = f"System under load. Latest Event: {latest.get('event_id')} ({latest.get('severity')})"
                        else:
                            alert = valid_alerts[-1]
                            title = f"IDS Alert: {alert.get('severity', 'UNKNOWN')}"
                            msg = f"Event ID: {alert.get('event_id')}\nSource: {alert.get('source')}"
                        
                        try:
                            icon.notify(msg, title)
                        except:
                            pass
        except Exception:
            pass
        time.sleep(2)

def run_tray():
    lockfile = os.path.join(tempfile.gettempdir(), 'ids_tray_app.lock')
    try:
        lock_fd = os.open(lockfile, os.O_CREAT | os.O_WRONLY)
        msvcrt.locking(lock_fd, msvcrt.LK_NBLCK, 1)
    except IOError:
        return # Already running, perfectly exit

    image = create_icon_image("blue", "black")
    menu = pystray.Menu(
        pystray.MenuItem(lambda text: f"Status: {get_service_status()}", lambda x, y: None, enabled=False),
        pystray.MenuItem("Start Service", start_service),
        pystray.MenuItem("Stop Service", stop_service),
        pystray.MenuItem("View Recent Alerts", view_alerts),
        pystray.MenuItem("Exit", exit_action)
    )
    icon = pystray.Icon("WindowsIDS", image, "Windows IDS", menu)
    
    def setup(icon):
        icon.visible = True
        t = threading.Thread(target=poll_alerts, args=(icon,), daemon=True)
        t.start()
        
    icon.run(setup=setup)

if __name__ == "__main__":
    run_tray()
