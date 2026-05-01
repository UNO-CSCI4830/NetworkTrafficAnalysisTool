# Installation Guide — Network Traffic Analysis Tool

## System Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Operating System | Windows 10 / Windows 11 | Windows-only; Linux/macOS not supported |
| Python | 3.10+ | Tested on Python 3.13 |
| Privileges | Administrator (recommended) | Required for full process enumeration |
| Internet | Optional | Used for DNS/WHOIS enrichment lookups |

---

## Prerequisites

### 1. Install Python 3.10 or later

Download from [python.org](https://www.python.org/downloads/). During installation, check **"Add Python to PATH"**.

Verify your installation:

```powershell
python --version
```

### 2. Clone or download the repository

```powershell
git clone https://github.com/UNO-CSCI4830/NetworkTrafficAnalysisTool.git
cd NetworkTrafficAnalysisTool
```

---

## Installing Dependencies

Install all required packages using pip:

```powershell
pip install -r requirements.txt
```

This installs the following packages:

| Package | Purpose |
|---------|---------|
| `psutil` | Collects live network connections and process information |
| `tqdm` | Progress bar displayed during DNS enrichment |
| `ipwhois` | Reverse IP / WHOIS / RDAP lookups for connection ownership |
| `cryptography` | AES-256-GCM encryption for sensitive log files |

All other dependencies (`json`, `socket`, `hashlib`, `tkinter`, etc.) are part of the Python standard library and require no additional installation.

---

## Optional: Encrypted Logging

The tool supports AES-256-GCM encrypted log storage. To enable it, set the `LOG_KEY` environment variable before running.

**Generate a key:**

```powershell
python -c "import os; print(os.urandom(32).hex())"
```

**Set the key for the current session (PowerShell):**

```powershell
$env:LOG_KEY = "<paste your 64-character hex key here>"
```

**Set the key permanently (System Environment Variables):**

1. Open **System Properties** → **Advanced** → **Environment Variables**
2. Under **User variables**, click **New**
3. Set Variable name: `LOG_KEY`, Variable value: your 64-character hex key

If `LOG_KEY` is not set, encrypted logging is skipped automatically — the tool will still run normally.

---

## Running the Tool

Run with elevated privileges for full process visibility:

1. Open **PowerShell as Administrator**
2. Navigate to the project directory
3. Run:

```powershell
python main.py
```

The tool will:

- Collect active network connections from the system
- Enrich each connection with port/process metadata and DNS ownership info
- Score each connection for risk (LOW / MEDIUM / HIGH / CRITICAL)
- Generate a timestamped Markdown report in the `./reports/` directory
- Display per-process data transfer statistics
- Enter an interactive process lookup mode (type `quit` to exit)

Reports are saved to `./reports/` and encrypted logs (if enabled) are saved to `~/netscan_results/` in your home directory.
