import sys
import os
import argparse
import ctypes
from service.service_runner import IDSService
import win32serviceutil
from tray.tray_app import run_tray
from core.log_reader import LogReader

def is_admin():
    """Check if script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    parser = argparse.ArgumentParser(description="Windows IDS Manager")
    parser.add_argument("--install", action="store_true", help="Install the background service (Requires Admin)")
    parser.add_argument("--remove", action="store_true", help="Remove the background service (Requires Admin)")
    parser.add_argument("--start", action="store_true", help="Start the background service (Requires Admin)")
    parser.add_argument("--stop", action="store_true", help="Stop the background service (Requires Admin)")
    parser.add_argument("--tray", action="store_true", help="Run the system tray UI")
    parser.add_argument("--console", action="store_true", help="Run directly in console for testing")
    parser.add_argument("--desktop", action="store_true", help="Run the Tkinter Desktop Analysis UI")
    
    args = parser.parse_args()
    
    if args.install or args.remove or args.start or args.stop:
        if not is_admin():
            print("ERROR: Service management commands require Administrative privileges.")
            sys.exit(1)
            
        service_args = []
        if args.install: service_args.append("install")
        if args.remove: service_args.append("remove")
        if args.start: service_args.append("start")
        if args.stop: service_args.append("stop")
        
        try:
            sys.argv = ['service_runner.py'] + service_args
            win32serviceutil.HandleCommandLine(IDSService)
            print("Service command executed successfully.")
        except Exception as e:
            print(f"Failed to execute service command. Error: {e}")
            
    elif args.tray:
        print("Starting System Tray Interface (Leave this terminal or launch with pythonw to hide)...")
        run_tray()
        
    elif args.console:
        if not is_admin():
            print("WARNING: Running without Admin privileges. Some events might not be accessible.")
        print("Starting IDS directly in console mode. Press Ctrl+C to stop.")
        reader = LogReader()
        try:
            reader.start()
        except KeyboardInterrupt:
            reader.stop()
            print("\nIDS Stopped.")
            
    elif args.desktop:
        print("Starting Desktop Interface...")
        from ui.desktop_app import run_desktop_app
        run_desktop_app()
            
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
