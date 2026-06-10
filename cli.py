import sys
import os
import tarfile
import tempfile
import requests
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from analyzer import analyze_file

console = Console()

BANNER = r"""
[bold cyan]
   _____ _ _            _     _____             _              
  / ____(_) |          | |   / ____|           | |             
 | (___  _| | ___ _ __ | |_ | (___   ___ _ __ | |_ _ __ _   _ 
  \___ \| | |/ _ \ '_ \| __| \___ \ / _ \ '_ \| __| '__| | | |
  ____) | | |  __/ | | | |_  ____) |  __/ | | | |_| |  | |_| |
 |_____/|_|_|\___|_| |_|\__||_____/ \___|_| |_|\__|_|   \__, |
                                                         __/ |
                                                        |___/ 
[/bold cyan]
[italic white]      Enterprise-Grade Static AST Security Auditor (v0.2.0)[/italic white]
"""

def scan_path(path):
    files = []
    if os.path.isfile(path):
        files = [path]
    else:
        for root, _, filenames in os.walk(path):
            for f in filenames:
                if f.endswith('.py'):
                    files.append(os.path.join(root, f))
    
    all_findings = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("[cyan]Analyzing codebases...", total=len(files))
        for f in files:
            progress.update(task, description=f"[cyan]Scanning {os.path.basename(f)}")
            try:
                findings = analyze_file(f)
                for find in findings:
                    find['file'] = os.path.relpath(f, start=os.path.dirname(path) if os.path.isdir(path) else ".")
                all_findings.extend(findings)
            except Exception as e:
                console.print(f"[bold red]![/bold red] Error in {f}: {e}")
            progress.advance(task)
    return all_findings, len(files)

def pypi_scan(package):
    console.print(f"[bold blue][*][/bold blue] Querying PyPI for [bold]{package}[/bold]...")
    try:
        res = requests.get(f"https://pypi.org/pypi/{package}/json").json()
        url = res['urls'][-1]['url'] # Get latest source distribution
        filename = res['urls'][-1]['filename']
        
        with tempfile.TemporaryDirectory() as tmpdir:
            console.print(f"[bold blue][*][/bold blue] Downloading {filename}...")
            r = requests.get(url, stream=True)
            tar_path = os.path.join(tmpdir, filename)
            with open(tar_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            console.print(f"[bold blue][*][/bold blue] Extracting and Auditing...")
            with tarfile.open(tar_path) as tar:
                tar.extractall(path=tmpdir)
            
            findings, file_count = scan_path(tmpdir)
            display_results(findings, file_count)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

def display_results(findings, file_count):
    table = Table(title="Security Audit Findings", expand=True)
    table.add_column("File", style="dim")
    table.add_column("Line", justify="right")
    table.add_column("Rule", style="magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Snippet", style="green", no_wrap=True)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for f in findings:
        sev = f['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        sev_style = "bold red" if sev == "CRITICAL" else "red" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "blue"
        
        table.add_row(
            f['file'],
            str(f['line']),
            f['category'],
            f"[{sev_style}]{sev}[/{sev_style}]",
            f['snippet'][:50] + "..." if len(f['snippet']) > 50 else f['snippet']
        )

    console.print(table)
    
    summary = f"Files Scanned: {file_count} | Issues: {len(findings)}\n"
    summary += f"[bold red]CRITICAL: {severity_counts['CRITICAL']}[/bold red] | [red]HIGH: {severity_counts['HIGH']}[/red] | [yellow]MEDIUM: {severity_counts['MEDIUM']}[/yellow] | [blue]LOW: {severity_counts['LOW']}[/blue]"
    
    console.print(Panel(summary, title="Audit Summary", border_style="cyan"))

def main():
    console.print(BANNER)
    parser = argparse.ArgumentParser(description="Silent Sentry: Advanced AST-based Security Auditor")
    subparsers = parser.add_subparsers(dest="command")
    
    scan_parser = subparsers.add_parser('scan')
    scan_parser.add_argument('path', help="Path to file or directory")
    
    pypi_parser = subparsers.add_parser('pypi')
    pypi_parser.add_argument('package', help="PyPI package name")
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        findings, count = scan_path(args.path)
        display_results(findings, count)
    elif args.command == 'pypi':
        pypi_scan(args.package)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
