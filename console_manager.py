import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.theme import Theme
from typing import Any
import argparse
from urllib.parse import urlparse

# Define a custom theme (optional)
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "green",
    "debug": "dim",
    "attack": "cyan",
    "vuln": "bold magenta",
    "severity_critical": "bold red",
    "severity_high": "red",
    "severity_medium": "yellow",
    "severity_low": "cyan",
    "severity_info": "blue",
})

class ConsoleManager:
    def __init__(self, verbose: bool = False, no_color: bool = False):
        # Force stderr for main output to not interfere with potential stdout piping
        self.console = Console(theme=custom_theme, no_color=no_color, stderr=True)
        self.verbose = verbose

    def print_info(self, message: str):
        self.console.print(f"[info][*] {message}[/info]")

    def print_success(self, message: str):
        self.console.print(f"[success][+] {message}[/success]")

    def print_warning(self, message: str):
        self.console.print(f"[warning][!] {message}[/warning]")

    def print_error(self, message: str, fatal: bool = False):
        prefix = "[error][ERROR][/error]" if fatal else "[error][-][/error]"
        self.console.print(f"{prefix} {message}")
        if fatal:
            sys.exit(1)

    def print_debug(self, message: str):
        """Prints only if verbose is enabled."""
        if self.verbose:
            self.console.print(f"[debug][DEBUG] {message}[/debug]")

    def print_finding(self, finding_type: str, severity: str, details: Any, url: str = ""):
        severity_upper = severity.upper()
        # Handle potential invalid severity strings gracefully
        severity_style = f"severity_{severity_upper.lower()}" if severity_upper in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else "white"

        title = f"[{severity_style}]{severity_upper}[/{severity_style}] {finding_type}"
        content = f"[bold]URL:[/bold] {url}\n" if url else ""

        if isinstance(details, dict):
            # Nicer formatting for dict details
            for k, v in details.items():
                 v_str = str(v)
                 if len(v_str) > 200: # Limit long values in findings display
                      v_str = v_str[:200] + "..."
                 content += f"  [bold]{str(k).replace('_', ' ').title()}:[/bold] {v_str}\n"
            content = content.rstrip()
        else:
            details_str = str(details)
            if len(details_str) > 500: # Limit long string details
                 details_str = details_str[:500] + "..."
            content += details_str

        self.console.print(Panel(content, title=title, border_style=severity_style, expand=False, padding=(0, 1)))

    def print_attack_attempt(self, url: str, method: str, payload_type: str, payload: str, status: int, response_len: int, is_vuln: bool = False, verification_method: str = ""):
        status_color = "success" if status < 300 else "warning" if status < 400 else "error"
        vuln_marker = f"[vuln][VULN: {verification_method}][/vuln]" if is_vuln else ""
        payload_display = payload.replace('\n', '\\n').replace('\r', '\\r')
        if len(payload_display) > 80: # Limit displayed payload length
             payload_display = payload_display[:80] + '...'

        self.console.print(f"[attack][ATTEMPT][/attack] {method} {url} - Type: [yellow]{payload_type}[/yellow] - Payload: '{payload_display}' -> Status: [{status_color}]{status}[/{status_color}] (Len: {response_len}) {vuln_marker}")

    def print_summary(self, summary: dict):
        self.console.rule("[bold] Scan Summary [/bold]", style="info")

        sev_table = Table(title="Findings by Severity", show_header=True, header_style="bold magenta", padding=(0,1))
        sev_table.add_column("Severity", style="dim", width=12)
        sev_table.add_column("Count", justify="right")

        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        total_by_severity = 0
        for sev in severities:
            count = summary.get("by_severity", {}).get(sev.lower(), 0)
            if count > 0:
                sev_style = f"severity_{sev.lower()}"
                sev_table.add_row(f"[{sev_style}]{sev}[/{sev_style}]", str(count))
                total_by_severity += count
        if total_by_severity > 0: # Only print table if there are findings
             self.console.print(sev_table)
        else:
             self.print_info("No findings reported by severity.")

        type_table = Table(title="Findings by Type", show_header=True, header_style="bold blue", padding=(0,1))
        type_table.add_column("Type", style="dim")
        type_table.add_column("Count", justify="right")
        # Sort by count descending
        sorted_types = sorted(summary.get("by_type", {}).items(), key=lambda item: item[1], reverse=True)
        total_by_type = 0
        for f_type, count in sorted_types:
             if count > 0:
                type_table.add_row(f_type, str(count))
                total_by_type += count
        if total_by_type > 0: # Only print table if there are findings
             self.console.print(type_table)
        else:
             self.print_info("No findings reported by type.")

        if summary.get("vulnerable_endpoints"):
             self.console.print("\n[bold yellow]Potentially Vulnerable Endpoints:[/bold yellow]")
             # Limit displayed endpoints if too many
             endpoints_to_show = summary["vulnerable_endpoints"][:20] # Show max 20
             for ep in endpoints_to_show:
                 self.console.print(f"- {ep}")
             if len(summary["vulnerable_endpoints"]) > 20:
                 self.console.print(f"- ... and {len(summary['vulnerable_endpoints']) - 20} more.")

        self.console.rule(style="info")


    def print_code(self, code: str, language: str = "javascript", title: str = "Code Snippet"):
        """Prints syntax highlighted code."""
        if not code:
            self.print_warning(f"Attempted to print empty code block for '{title}'")
            return
        try:
            syntax = Syntax(code, language, theme="paraiso-dark", line_numbers=True, background_color="default") # Changed theme
            self.console.print(Panel(syntax, title=title, border_style="blue", expand=False))
        except Exception as e:
            self.print_error(f"Failed to highlight code for {title}: {e}")
            self.console.print(Panel(code, title=f"{title} (plaintext)", border_style="red"))


    def create_progress(self, description="Processing..."):
         """Creates a Rich Progress context manager."""
         # Use transient=False if you want the bar to remain after completion
         return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True # Clears progress bar on completion
         )

def validate_target_url(url: str) -> bool:
    """Valida que la URL objetivo sea válida."""
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)  # Asegúrate de que haya un esquema y un dominio
    except Exception:
        return False

def main():
    """Función principal para ejecutar el escáner de vulnerabilidades web."""
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner with Advanced Features')
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    # ... otros argumentos ...

    args = parser.parse_args()

    # Verificar y agregar 'https://' si es necesario
    if args.url:
        if not (args.url.startswith('http://') or args.url.startswith('https://')):
            args.url = 'https://' + args.url  # Agregar 'https://' si no está presente

    if not validate_target_url(args.url):
        parser.print_help()
        sys.exit(1)

    # ... resto de la función ...