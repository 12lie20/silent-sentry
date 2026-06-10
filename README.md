# 🛡️ Silent Sentry

> **Premium Static AST-based Security Auditor targeting PyPI package backdoors.**

Silent Sentry is a high-performance security tool designed to inspect Python source code for malicious patterns, obfuscation, and suspicious exfiltration techniques without executing the code.

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

## ✨ Features

- 🔍 **Dynamic Code Detection**: Flags `eval()` and `exec()`.
- 🔐 **Obfuscation Detection**: Identifies base64, codecs, and suspicious hex strings.
- 🌐 **Networking Heuristics**: Monitors `socket`, `requests`, and `aiohttp` usage.
- 🐚 **Shell Command Auditing**: Detects `subprocess`, `os.system`, and `pty`.
- 📦 **Exfiltration Prevention**: Scans for access to `os.environ` and sensitive system paths like `.ssh/` or `.kube/`.

## 🚀 Installation

```bash
pip install .
```

## 🛠️ Usage

Scan a single file:
```bash
silent-sentry malicious_package.py
```

Scan an entire project directory:
```bash
silent-sentry ./my_project
```

## 📄 License

MIT License.
