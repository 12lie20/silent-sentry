import sys
import os
import argparse
from analyzer import analyze_file

# ANSI Colors
COLORS = {
    'CRITICAL': '\033[91m\033[1m', # Bold Red
    'HIGH': '\033[91m',           # Red
    'MEDIUM': '\033[93m',         # Yellow
    'LOW': '\033[94m',            # Blue
    'RESET': '\033[0m',
    'HEADER': '\033[95m\033[1m'
}

BANNER = r"""
   _____ _ _            _     _____             _              
  / ____(_) |          | |   / ____|           | |             
 | (___  _| | ___ _ __ | |_ | (___   ___ _ __ | |_ _ __ _   _ 
  \___ \| | |/ _ \ '_ \| __| \___ \ / _ \ '_ \| __| '__| | | |
  ____) | | |  __/ | | | |_  ____) |  __/ | | | |_| |  | |_| |
 |_____/|_|_|\___|_| |_|\__||_____/ \___|_| |_|\__|_|   \__, |
                                                         __/ |
                                                        |___/ 
      Static AST Security Auditor for PyPI Packages
"""

def main():
    print(COLORS['HEADER'] + BANNER + COLORS['RESET'])
    parser = argparse.ArgumentParser(description="Silent Sentry: AST-based Security Auditor")
    parser.add_argument('path', help="Path to the Python file or directory to scan")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: {args.path} is not a valid file or directory.")
        sys.exit(1)

    files = []
    if os.path.isfile(args.path):
        files = [args.path]
    else:
        for root, _, filenames in os.walk(args.path):
            for f in filenames:
                if f.endswith('.py'):
                    files.append(os.path.join(root, f))

    total_findings = 0
    for file in files:
        print(f"\n[*] Scanning: {file}")
        try:
            findings = analyze_file(file)
            if not findings:
                print("  [+] No issues found.")
                continue
            
            for f in findings:
                total_findings += 1
                color = COLORS.get(f['severity'], COLORS['RESET'])
                print(f"  {color}[{f['severity']}] {f['category']}{COLORS['RESET']} (Line {f['line']}): {f['message']}")
        except Exception as e:
            print(f"  [!] Error analyzing file: {e}")

    print(f"\n{COLORS['HEADER']}Scan Complete. Total findings: {total_findings}{COLORS['RESET']}")

if __name__ == "__main__":
    main()
