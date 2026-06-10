import ast
import re
import os

class SilentSentryAnalyzer(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []
        self.suspicious_imports = {'socket', 'urllib', 'requests', 'aiohttp', 'subprocess', 'os', 'sh', 'pty', 'codecs'}

    def add_finding(self, node, severity, category, message):
        self.findings.append({
            'line': node.lineno,
            'severity': severity,
            'category': category,
            'message': message
        })

    def visit_Call(self, node):
        # Detect eval/exec
        if isinstance(node.func, ast.Name):
            if node.func.id in ('eval', 'exec'):
                self.add_finding(node, 'CRITICAL', 'Dynamic Execution', f'Use of {node.func.id}() detected.')
        
        # Detect base64/codecs decoding
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ('b64decode', 'decode', 'encode'):
                 # Check if it's from a decoding/encoding context
                 pass

        # Detect subprocess/os.system
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == 'os' and node.func.attr in ('system', 'popen', 'spawn'):
                    self.add_finding(node, 'CRITICAL', 'OS Command', f'os.{node.func.attr}() execution.')
                if node.func.value.id == 'subprocess':
                    self.add_finding(node, 'HIGH', 'Subprocess', f'subprocess.{node.func.attr}() call.')
        
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in self.suspicious_imports:
                self.add_finding(node, 'MEDIUM', 'Suspicious Import', f'Importing {alias.name} in a potentially sensitive context.')
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module in self.suspicious_imports:
            self.add_finding(node, 'MEDIUM', 'Suspicious Import', f'Importing from {node.module}.')
        self.generic_visit(node)

    def visit_Attribute(self, node):
        # Detect access to environ
        if isinstance(node.value, ast.Name) and node.value.id == 'os' and node.attr == 'environ':
            self.add_finding(node, 'HIGH', 'Data Extraction', 'Accessing environment variables (os.environ).')
        self.generic_visit(node)

    def visit_Constant(self, node):
        # Python 3.8+ uses Constant for strings
        if isinstance(node.value, str):
            self.check_string(node, node.value)
        self.generic_visit(node)

    def visit_Str(self, node):
        # Older Python versions
        self.check_string(node, node.s)
        self.generic_visit(node)

    def check_string(self, node, value):
        # Check for sensitive file paths
        paths = ['/etc/passwd', '.ssh/', '.kube/config', '/proc/self/environ']
        for path in paths:
            if path in value:
                self.add_finding(node, 'HIGH', 'Sensitive Path', f'Reference to sensitive path: {path}')
        
        # Check for long base64-like strings
        if len(value) > 100 and re.match(r'^[A-Za-z0-9+/=]+$', value):
            self.add_finding(node, 'MEDIUM', 'Potential Obfuscation', 'Large base64-like string detected.')

def analyze_file(filepath):
    with open(filepath, 'r') as f:
        tree = ast.parse(f.read())
    analyzer = SilentSentryAnalyzer(filepath)
    analyzer.visit(tree)
    return analyzer.findings
