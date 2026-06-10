# 🛡️ Silent Sentry

> **Enterprise-Grade Static AST-based Security Auditor for Python.**

Silent Sentry is a premium security tool designed to inspect Python source code for malicious patterns, obfuscation, and suspicious exfiltration techniques. It performs deep static analysis of the Abstract Syntax Tree (AST) to identify threats without code execution.

```ascii
   _____ _ _            _     _____             _              
  / ____(_) |          | |   / ____|           | |             
 | (___  _| | ___ _ __ | |_ | (___   ___ _ __ | |_ _ __ _   _ 
  \___ \| | |/ _ \ '_ \| __| \___ \ / _ \ '_ \| __| '__| | | |
  ____) | | |  __/ | | | |_  ____) |  __/ | | | |_| |  | |_| |
 |_____/|_|_|\___|_| |_|\__||_____/ \___|_| |_|\__|_|   \__, |
                                                         __/ |
                                                        |___/ 
```

## ✨ Advanced Features

- 🧠 **Import Alias Tracking**: Detects attempts to hide dangerous modules behind aliases (e.g., `import os as dangerous`).
- 🌊 **Variable Taint Analysis**: Tracks data flow from dangerous sources to potentially malicious sinks.
- 📉 **Shannon Entropy Analysis**: Calculates entropy on string literals to detect encrypted or highly obfuscated payloads.
- 📦 **PyPI Integration**: Audit any package directly from PyPI by downloading and extracting it automatically.
- 🎨 **Rich UI**: Beautiful terminal interface with colored tables, progress indicators, and summarized reports.
- 🔍 **Deep Inspection**:
    - **Dynamic Execution**: `eval()`, `exec()`
    - **Shell Commands**: `os.system`, `subprocess`, `pty`
    - **Data Exfiltration**: `os.environ` access, sensitive paths (`/etc/passwd`, `.ssh/`)
    - **Obfuscation**: Base64 detection, hex patterns.

## 🚀 Installation

```bash
pip install .
```

## 🛠️ Usage

### Scan Local Path
Scan a single file or an entire directory:
```bash
silent-sentry scan ./my_project
```

### Audit PyPI Package
Directly audit the latest version of any package on PyPI:
```bash
silent-sentry pypi requests
```

## 📊 Vulnerability Categorization

| Severity | Category | Description |
| :--- | :--- | :--- |
| **CRITICAL** | Dynamic Execution | Potential for arbitrary code execution via `eval`/`exec`. |
| **HIGH** | OS Command / Taint | Unauthorized shell access or use of tainted variables. |
| **MEDIUM** | High Entropy / Obfuscation | Detection of suspicious, non-readable data structures. |
| **LOW** | Suspicious Imports | Presence of networking or system modules in unusual contexts. |

## 📄 License

MIT License.
