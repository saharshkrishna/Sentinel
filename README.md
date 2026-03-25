# Windows IDS & Log Analyzer (SentinelAI)

This project provides a comprehensive Intrusion Detection System (IDS) and Real-Time Log Analyzer for Windows environments. It is designed to detect suspicious behavior and generate actionable alerts. The project offers multiple user interfaces to interact with the service, varying from lightweight background tray applications to full-featured Web and Desktop dashboards.

## Prerequisites

- **Python 3.8+** installed.
- **Administrator Privileges** are required to read system event logs and manage the background service.

#### Installation
```bash
# Install required Python packages
pip install -r requirements.txt
pip install -r ids_project/requirements.txt
```

---

## Interfaces and Running Instructions

The application is structured to allow multiple ways to run and interact with the IDS depending on your needs. Below are the steps to execute each distinct interface.

### 1. The Web Application Dashboard
A Flask and Socket.IO based interface providing a real-time analytics dashboard accessible via a web browser.

**Execution Steps:**
1. Navigate to the project root directory.
2. Run the main web entry script:
   ```bash
   python main.py
   ```
3. Open a browser and navigate to `http://localhost:5000` to view the live dashboard and real-time alerts.

### 2. Desktop Analysis UI (Tkinter)
A standalone Graphical User Interface (GUI) built with Python's Tkinter, used for localized log analysis and managing detected threats directly on the desktop.

**Execution Steps:**
1. Navigate to the `ids_project` directory.
2. Run the script with the `--desktop` flag:
   ```bash
   cd ids_project
   python main.py --desktop
   ```

### 3. System Tray Interface
A lightweight, unobtrusive GUI that rests in the Windows System Tray. It provides rapid access to alerts without cluttering your taskbar.

**Execution Steps:**
1. Navigate to the `ids_project` directory.
2. Run the script with the `--tray` flag:
   ```bash
   cd ids_project
   python main.py --tray
   ```
   *(Tip: Use `pythonw main.py --tray` to launch it natively without keeping a console window permanently open.)*

### 4. Direct Console Mode (CLI)
A terminal-based interface that allows you to observe the log stream and real-time detections directly in a command prompt or PowerShell window. Very useful for verbose testing and debugging.

**Execution Steps:**
1. Open a Command Prompt or PowerShell window **as Administrator** (to capture actual system events).
2. Navigate to the `ids_project` directory.
3. Run the script with the `--console` flag:
   ```bash
   cd ids_project
   python main.py --console
   ```
4. Press `Ctrl+C` to cleanly stop the IDS.

### 5. Windows Background Service
You can install the IDS natively as a Windows Service. This allows the protection engine to run persistently and securely in the background alongside Windows without needing an active console or logged-in user session.

**Execution Steps:** (All commands must be run from an **Administrator** terminal within the `ids_project` directory)

- **To Install the service:**
  ```bash
  cd ids_project
  python main.py --install
  ```

- **To Start the service:**
  ```bash
  python main.py --start
  ```

- **To Stop the service:**
  ```bash
  python main.py --stop
  ```

- **To Remove the service:**
  ```bash
  python main.py --remove
  ```

---

*Note: For legacy compatibility and testing purposes, there is also a monolithic wrapper `Log_analyzer.py` found in the root directory which spins up earlier web interface components. Run this using `python Log_analyzer.py` at the root.*
