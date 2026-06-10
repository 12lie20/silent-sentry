import ast
import math
import yaml
import os
from collections import deque

class StaticResolver:
    """
    Partial Evaluator / De-obfuscation Engine.
    Statically resolves string operations, chr() calls, and joins.
    """
    @staticmethod
    def resolve(node, scope_vars):
        if isinstance(node, ast.Constant):
            return node.value
        
        # Resolve chr(x) + chr(y)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = StaticResolver.resolve(node.left, scope_vars)
            right = StaticResolver.resolve(node.right, scope_vars)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        
        # Resolve chr(int)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'chr':
            if len(node.args) == 1:
                val = StaticResolver.resolve(node.args[0], scope_vars)
                if isinstance(val, int):
                    try:
                        return chr(val)
                    except:
                        pass
        
        # Resolve ''.join([...])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'join':
            sep = StaticResolver.resolve(node.func.value, scope_vars)
            if isinstance(sep, str) and len(node.args) == 1 and isinstance(node.args[0], ast.List):
                parts = [StaticResolver.resolve(elt, scope_vars) for elt in node.args[0].elts]
                if all(isinstance(p, str) for p in parts):
                    return sep.join(parts)
        
        # Resolve local variable references (Constant Propagation)
        if isinstance(node, ast.Name) and node.id in scope_vars:
            return scope_vars[node.id]
            
        return None

class SilentSentryCore(ast.NodeVisitor):
    def __init__(self, filename, rules_path="rules.yaml"):
        self.filename = filename
        self.findings = []
        self.scope_vars = {} # Simple constant propagation map
        self.taint_map = {}  # Tracks variable origin
        self.import_aliases = {} # Maps alias -> original module
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path):
        if not os.path.exists(path):
            return {"rules": []}
        with open(path, 'r') as f:
            return yaml.safe_load(f)

    def calculate_entropy(self, data):
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def add_finding(self, node, rule_id, message_val):
        for rule in self.rules['rules']:
            if rule['id'] == rule_id:
                self.findings.append({
                    'line': node.lineno,
                    'severity': rule['severity'],
                    'category': rule['category'],
                    'message': rule['message'] % str(message_val),
                    'code': getattr(node, 'lineno', 0)
                })

    def visit_Assign(self, node):
        # Tracking constants and taints
        resolved = StaticResolver.resolve(node.value, self.scope_vars)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if resolved is not None:
                    self.scope_vars[target.id] = resolved
                # Track if it's assigned from a dangerous attribute (taint)
                if isinstance(node.value, ast.Attribute):
                    full_name = self.get_full_attr_name(node.value)
                    if full_name:
                        self.taint_map[target.id] = full_name
        self.generic_visit(node)

    def get_full_attr_name(self, node):
        if isinstance(node, ast.Name):
            return self.import_aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.get_full_attr_name(node.value)
            if base:
                return f"{base}.{node.attr}"
        return None

    def visit_Import(self, node):
        for alias in node.names:
            actual_name = alias.name
            target_name = alias.asname or alias.name
            self.import_aliases[target_name] = actual_name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        for alias in node.names:
            actual_name = f"{module}.{alias.name}"
            target_name = alias.asname or alias.name
            self.import_aliases[target_name] = actual_name
        self.generic_visit(node)

    def visit_Call(self, node):
        # 1. Resolve Dynamic Imports: __import__('o'+'s'), importlib.import_module(...)
        func_name = self.get_full_attr_name(node.func)
        
        # Dynamic import solver
        if func_name in ('__import__', 'importlib.import_module', 'builtins.__import__'):
            module_name = StaticResolver.resolve(node.args[0], self.scope_vars)
            if module_name:
                # We flag this as a dynamic import finding
                self.add_finding(node, 'dynamic-execution', f"dynamic import of '{module_name}'")
        
        # 2. Match against YAML rules (Sinks)
        resolved_func = func_name
        if not resolved_func and isinstance(node.func, ast.Name) and node.func.id in self.taint_map:
            resolved_func = self.taint_map[node.func.id]
            
        if resolved_func:
            for rule in self.rules['rules']:
                if resolved_func in rule['patterns']:
                    self.add_finding(node, rule['id'], resolved_func)

        # 3. Handle getattr(os, 'sys' + 'tem')
        if func_name == 'getattr' and len(node.args) >= 2:
            obj = self.get_full_attr_name(node.args[0])
            attr = StaticResolver.resolve(node.args[1], self.scope_vars)
            if obj and attr:
                full_call = f"{obj}.{attr}"
                for rule in self.rules['rules']:
                    if full_call in rule['patterns']:
                        self.add_finding(node, rule['id'], full_call)

        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) > 20:
            entropy = self.calculate_entropy(node.value)
            if entropy > 4.5: # Threshold for potential obfuscation
                self.findings.append({
                    'line': node.lineno,
                    'severity': 'MEDIUM',
                    'category': 'Obfuscation',
                    'message': f"High entropy string literal ({entropy:.2f}) - potential payload.",
                    'code': node.lineno
                })

def analyze_file(filepath, rules_path="rules.yaml"):
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            tree = ast.parse(content)
        
        analyzer = SilentSentryCore(filepath, rules_path)
        analyzer.visit(tree)
        
        # Add code snippets
        lines = content.splitlines()
        for f in analyzer.findings:
            idx = f['line'] - 1
            if 0 <= idx < len(lines):
                f['snippet'] = lines[idx].strip()
            else:
                f['snippet'] = "N/A"
        
        return analyzer.findings
    except Exception as e:
        raise Exception(f"Failed to analyze {filepath}: {e}")
