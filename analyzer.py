import ast
import re
import os
import math
from collections import Counter

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for count in Counter(data).values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

class SilentSentryAnalyzer(ast.NodeVisitor):
    def __init__(self, filename, source_code):
        self.filename = filename
        self.source_code = source_code.splitlines()
        self.findings = []
        self.suspicious_imports = {'socket', 'urllib', 'requests', 'aiohttp', 'subprocess', 'os', 'sh', 'pty', 'codecs'}
        
        # Tracking for alias detection
        self.import_aliases = {} # alias -> real_module
        
        # Tracking for basic taint analysis
        # For simplicity in this static context, we track variable assignments from known dangerous sources
        self.tainted_vars = {} # var_name -> source_type

    def add_finding(self, node, severity, category, message):
        snippet = ""
        try:
            snippet = self.source_code[node.lineno - 1].strip()
        except IndexError:
            pass
            
        self.findings.append({
            'file': self.filename,
            'line': node.lineno,
            'severity': severity,
            'category': category,
            'message': message,
            'snippet': snippet
        })

    def get_real_module(self, name):
        return self.import_aliases.get(name, name)

    def visit_Import(self, node):
        for alias in node.names:
            real_name = alias.name
            target_name = alias.asname or real_name
            self.import_aliases[target_name] = real_name
            
            if real_name in self.suspicious_imports:
                self.add_finding(node, 'MEDIUM', 'Suspicious Import', f'Importing {real_name} (as {target_name})')
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        if module in self.suspicious_imports:
            self.add_finding(node, 'MEDIUM', 'Suspicious Import', f'Importing from {module}')
        
        for alias in node.names:
            # handle 'from os import system as sys_call'
            # technically this is more of a function alias, but for now we track module-level imports
            pass
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Taint tracking: if we assign a dangerous call to a variable
        # e.g., dangerous = os.system
        if isinstance(node.value, ast.Attribute):
            real_mod = ""
            if isinstance(node.value.value, ast.Name):
                real_mod = self.get_real_module(node.value.value.id)
                if real_mod == 'os' and node.value.attr in ('system', 'popen', 'spawn'):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_vars[target.id] = f'os.{node.value.attr}'
                            self.add_finding(node, 'HIGH', 'Taint Tracking', f'Variable {target.id} is assigned a dangerous function: os.{node.value.attr}')
        
        # Also track assignments from environ
        if isinstance(node.value, ast.Attribute):
             if isinstance(node.value.value, ast.Name) and self.get_real_module(node.value.value.id) == 'os' and node.value.attr == 'environ':
                 for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars[target.id] = 'os.environ'

        self.generic_visit(node)

    def visit_Call(self, node):
        # Detect eval/exec
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ('eval', 'exec'):
                self.add_finding(node, 'CRITICAL', 'Dynamic Execution', f'Use of {func_name}() detected.')
            
            # Check if calling a tainted variable
            if func_name in self.tainted_vars:
                self.add_finding(node, 'CRITICAL', 'Tainted Call', f'Calling tainted variable {func_name} (source: {self.tainted_vars[func_name]})')

        # Detect subprocess/os.system via attributes and aliases
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_alias = node.func.value.id
                real_module = self.get_real_module(module_alias)
                
                if real_module == 'os' and node.func.attr in ('system', 'popen', 'spawn'):
                    self.add_finding(node, 'CRITICAL', 'OS Command', f'{real_module}.{node.func.attr}() execution.')
                if real_module == 'subprocess':
                    self.add_finding(node, 'HIGH', 'Subprocess', f'subprocess.{node.func.attr}() call.')
        
        self.generic_visit(node)

    def visit_Attribute(self, node):
        # Detect access to environ
        if isinstance(node.value, ast.Name):
            real_module = self.get_real_module(node.value.id)
            if real_module == 'os' and node.attr == 'environ':
                self.add_finding(node, 'HIGH', 'Data Extraction', 'Accessing environment variables (os.environ).')
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            self.check_string(node, node.value)
        self.generic_visit(node)

    def visit_Str(self, node):
        self.check_string(node, node.s)
        self.generic_visit(node)

    def check_string(self, node, value):
        # Shannon Entropy calculation
        if len(value) > 20:
            entropy = calculate_entropy(value)
            if entropy > 4.5: # Threshold for potential encryption/obfuscation
                self.add_finding(node, 'MEDIUM', 'High Entropy', f'High entropy string detected ({entropy:.2f}). Possible obfuscation.')

        # Check for sensitive file paths
        paths = ['/etc/passwd', '.ssh/', '.kube/config', '/proc/self/environ']
        for path in paths:
            if path in value:
                self.add_finding(node, 'HIGH', 'Sensitive Path', f'Reference to sensitive path: {path}')
        
        # Check for long base64-like strings
        if len(value) > 60 and re.match(r'^[A-Za-z0-9+/=]+$', value):
            # Check if it actually decodes to something suspicious? For now, flag it.
            self.add_finding(node, 'MEDIUM', 'Potential Obfuscation', 'Large base64-like string detected.')

def analyze_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        tree = ast.parse(content)
        analyzer = SilentSentryAnalyzer(filepath, content)
        analyzer.visit(tree)
        return analyzer.findings
    except Exception as e:
        return [{'file': filepath, 'line': 0, 'severity': 'LOW', 'category': 'Error', 'message': str(e), 'snippet': ''}]
