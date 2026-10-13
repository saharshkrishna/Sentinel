"""
main.py - Main entry point for Sentinel IDS (Windows and Linux).
"""
import sys
import os
import argparse
from core.platform_adapter import is_admin, IS_WINDOWS, IS_LINUX
from core.log_reader import LogReader


def main():
    parser = argparse.ArgumentParser(description="Sentinel IDS & Threat Monitor")
    parser.add_argument("--install", action="store_true", help="Install background service (Requires Admin/root)")
    parser.add_argument("--remove", action="store_true", help="Remove background service (Requires Admin/root)")
    parser.add_argument("--start", action="store_true", help="Start background service (Requires Admin/root)")
    parser.add_argument("--stop", action="store_true", help="Stop background service (Requires Admin/root)")
    parser.add_argument("--tray", action="store_true", help="Run the system tray UI")
    parser.add_argument("--console", action="store_true", help="Run directly in console for testing")
    parser.add_argument("--desktop", action="store_true", help="Run the Tkinter Desktop Analysis UI")

    args = parser.parse_args()

    if args.install or args.remove or args.start or args.stop:
        from service.service_runner import handle_service_command

        action = "install" if args.install else "remove" if args.remove else "start" if args.start else "stop"
        try:
            handle_service_command(action)
        except Exception as e:
            print(f"Failed to execute service command. Error: {e}")

    elif args.tray:
        print("Starting System Tray Interface...")
        from tray.tray_app import run_tray
        run_tray()

    elif args.console:
        if not is_admin():
            priv_label = "Administrator" if IS_WINDOWS else "root / sudo"
            print(f"WARNING: Running without {priv_label} privileges. Some low-level system logs might not be accessible.")
        print("Starting Sentinel IDS in console mode. Press Ctrl+C to stop.")
        from core.process_tree import get_process_tree
        tree = get_process_tree()
        tree.start()

        from core.canary_sentry import get_canary_sentry
        canary = get_canary_sentry()
        canary.start()

        reader = LogReader()
        try:
            reader.start()
        except KeyboardInterrupt:
            reader.stop()
            canary.stop(cleanup=True)
            tree.stop()
            print("\nIDS Stopped.")

    elif args.desktop:
        print("Starting Desktop Interface...")
        from ui.desktop_app import run_desktop_app
        run_desktop_app()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
