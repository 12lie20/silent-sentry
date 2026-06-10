import sys
import os
import argparse
import tempfile
import shutil
import requests
import tarfile
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from analyzer import analyze_file

console = Console()

BANNER = """
   _____ _ _            _     _____             _              
  / ____(_) |          | |   / ____|           | |             
 | (___  _| | ___ _ __ | |_ | (___   ___ _ __ | |_ _ __ _   _ 
  \___ \| | |/ _ \ '_ \| __| \___ \ / _ \ '_ \| __| '__| | | |
  ____) | | |  __/ | | | |_  ____) |  __/ | | | |_| |  | |_| |
 |_____/|_|_|\___|_| |_|\__||_____/ \___|_| |_|\__|_|   \__, |
                                                         __/ |
                                                        |___/ 
      [bold gold1]Advanced Enterprise-Grade Security Auditor[/bold gold1]
"""

def scan_path(path):
    files = []
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for f in filenames:
                if f.endswith('.py'):
                    files.append(os.path.join(root, f))
    else:
        console.print(f"[red]Error:[/red] {path} is not a valid file or directory.")
        return []

    all_findings = []
    with console.status(f"[bold green]Scanning {len(files)} files..."):
        for file in files:
            findings = analyze_file(file)
            all_findings.extend(findings)
    return all_findings

def download_pypi(package_name):
    console.print(f"[*] Querying PyPI for [bold cyan]{package_name}[/bold cyan]...")
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)
    if response.status_code != 200:
        console.print(f"[red]Error:[/red] Package {package_name} not found on PyPI.")
        return None
    
    data = response.json()
    # Get the latest source distribution
    urls = data['urls']
    sdist = next((u for u in urls if u['packagetype'] == 'sdist'), None)
    if not sdist:
        console.print("[red]Error:[/red] No source distribution found for this package.")
        return None
    
    download_url = sdist['url']
    tmp_dir = tempfile.mkdtemp()
    tar_path = os.path.join(tmp_dir, "package.tar.gz")
    
    console.print(f"[*] Downloading {download_url}...")
    r = requests.get(download_url, stream=True)
    with open(tar_path, 'wb') as f:
        shutil.copyfileobj(r.raw, f)
    
    extract_dir = os.path.join(tmp_dir, "extracted")
    os.makedirs(extract_dir)
    
    console.print("[*] Extracting package...")
    try:
        with tarfile.open(tar_path) as tar:
            tar.extractall(path=extract_dir)
    except Exception as e:
        console.print(f"[red]Error extracting tarball:[/red] {e}")
        return None
        
    return extract_dir

def display_findings(findings):
    if not findings:
        console.print("\n[bold green]✓ No issues found![/bold green]")
        return

    table = Table(title="Silent Sentry Audit Results", show_header=True, header_style="bold magenta")
    table.add_column("File", style="dim")
    table.add_column("Line", justify="right")
    table.add_column("Rule / Category", style="cyan")
    table.add_column("Severity")
    table.add_column("Code Snippet")

    severity_colors = {
        'CRITICAL': 'bold red',
        'HIGH': 'red',
        'MEDIUM': 'yellow',
        'LOW': 'blue'
    }

    stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

    for f in findings:
        sev = f['severity']
        stats[sev] = stats.get(sev, 0) + 1
        color = severity_colors.get(sev, 'white')
        
        snippet_text = f['snippet']
        if len(snippet_text) > 50:
            snippet_text = snippet_text[:47] + "..."
            
        table.add_row(
            os.path.basename(f['file']),
            str(f['line']),
            f['category'],
            f"[{color}]{sev}[/color]",
            snippet_text
        )

    console.print(table)
    
    summary_content = (
        f"Total Issues: {len(findings)}\n"
        f"[bold red]Critical:[/bold red] {stats['CRITICAL']}  "
        f"[red]High:[/red] {stats['HIGH']}  "
        f"[yellow]Medium:[/yellow] {stats['MEDIUM']}  "
        f"[blue]Low:[/blue] {stats['LOW']}"
    )
    console.print(Panel(summary_content, title="Summary", expand=False))

def main():
    console.print(BANNER)
    parser = argparse.ArgumentParser(description="Silent Sentry Security Auditor")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    scan_parser = subparsers.add_parser("scan", help="Scan a local file or directory")
    scan_parser.add_argument("path", help="Path to file or directory")

    pypi_parser = subparsers.add_parser("pypi", help="Scan a PyPI package")
    pypi_parser.add_argument("package", help="Name of the PyPI package")

    args = parser.parse_args()

    if args.command == "scan":
        findings = scan_path(args.path)
        display_findings(findings)
    elif args.command == "pypi":
        extract_path = download_pypi(args.package)
        if extract_path:
            findings = scan_path(extract_path)
            display_findings(findings)
            shutil.rmtree(os.path.dirname(extract_path))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
