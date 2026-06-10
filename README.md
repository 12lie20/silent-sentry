# 🛡️ Silent Sentry (v0.2.0)

> **Advanced Static AST-based Security Auditor & De-obfuscator.**

Silent Sentry is an elite security tool designed to identify malicious patterns, supply-chain backdoors, and advanced obfuscation in Python codebases and PyPI packages. It uses deep AST analysis, constant propagation, and a YAML-driven rule engine to track dataflow from sources to dangerous sinks.

## 🚀 Key Features

- **Partial Evaluation Engine**: Statically resolves string folding, `chr()` arrays, and `''.join()` operations to unmask hidden payloads (e.g., `chr(101)+chr(118)...` -> `eval`).
- **YAML Rule Engine**: Extensible, mini-Semgrep style logic. Define complex patterns in `rules.yaml`.
- **Dynamic Import Solver**: Traces obfuscated imports like `__import__('o'+'s')` or `getattr(builtins, 'exec')`.
- **Interprocedural Taint Tracking**: Monitors variable assignments and constant propagation to detect when dangerous modules are aliased or passed around.
- **PyPI Auditor**: Directly audit any PyPI package by name (`silent-sentry pypi <name>`).
- **Rich Interface**: Beautifully formatted terminal reports with code snippets and severity breakdowns.

## 🛠️ Installation

```bash
pip install .
```

## 📖 Usage

### Scan a Local Project
```bash
silent-sentry scan ./my_project
```

### Audit a PyPI Package
```bash
silent-sentry pypi some-suspicious-pkg
```

## 🛡️ Rule Configuration
Modify `rules.yaml` to add custom detection patterns for your specific security requirements.

## 📄 License
MIT License.
