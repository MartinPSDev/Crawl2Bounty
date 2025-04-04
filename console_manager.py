import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.theme import Theme
from typing import Any, Optional
import logging

# Configurar logger
logger = logging.getLogger(__name__)

# Tema personalizado
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
    def __init__(self, verbose: bool = False, no_color: bool = False, use_stderr: bool = True):
        """Inicializa el administrador de consola."""
        self.console = Console(theme=custom_theme, no_color=no_color, stderr=use_stderr)
        self.verbose = verbose
        self.max_display_length = 200  # Configurable vía constructor si se desea

    def print_info(self, message: str):
        """Muestra un mensaje informativo."""
        self.console.print(f"[info][*] {message}[/info]")

    def print_success(self, message: str):
        """Muestra un mensaje de éxito."""
        self.console.print(f"[success][+] {message}[/success]")

    def print_warning(self, message: str):
        """Muestra una advertencia."""
        self.console.print(f"[warning][!] {message}[/warning]")

    def print_error(self, message: str, fatal: bool = False, exit_code: int = 1) -> Optional[int]:
        """Muestra un error, opcionalmente fatal."""
        prefix = "[error][ERROR][/error]" if fatal else "[error][-][/error]"
        self.console.print(f"{prefix} {message}")
        logger.error(message)
        if fatal:
            return exit_code  # Devuelve el código de salida para que el llamador lo maneje
        return None

    def print_debug(self, message: str):
        """Muestra un mensaje de depuración si verbose está habilitado."""
        if self.verbose:
            self.console.print(f"[debug][DEBUG] {message}[/debug]")
            logger.debug(message)

    def print_finding(self, finding_type: str, severity: str, details: Any, url: str = ""):
        """Muestra un hallazgo con formato personalizado."""
        severity_upper = severity.upper()
        severity_style = f"severity_{severity_upper.lower()}" if severity_upper in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else "white"

        title = f"[{severity_style}]{severity_upper}[/{severity_style}] {finding_type}"
        content = f"[bold]URL:[/bold] {url}\n" if url else ""

        try:
            if isinstance(details, dict):
                for k, v in details.items():
                    v_str = str(v)[:self.max_display_length] + "..." if len(str(v)) > self.max_display_length else str(v)
                    content += f"  [bold]{str(k).replace('_', ' ').title()}:[/bold] {v_str}\n"
                content = content.rstrip()
            else:
                details_str = str(details)[:self.max_display_length * 2] + "..." if len(str(details)) > self.max_display_length * 2 else str(details)
                content += details_str
        except Exception as e:
            logger.error(f"Error formateando detalles de hallazgo: {e}")
            content += f"[Error formateando detalles: {e}]"

        self.console.print(Panel(content, title=title, border_style=severity_style, expand=False, padding=(0, 1)))

    def print_attack_attempt(self, url: str, method: str, payload_type: str, payload: str, status: int, response_len: int, is_vuln: bool = False, verification_method: str = ""):
        """Muestra un intento de ataque."""
        status_color = "success" if status < 300 else "warning" if status < 400 else "error"
        vuln_marker = f"[vuln][VULN: {verification_method}][/vuln]" if is_vuln else ""
        payload_display = payload.replace('\n', '\\n').replace('\r', '\\r')
        payload_display = payload_display[:80] + '...' if len(payload_display) > 80 else payload_display

        self.console.print(f"[attack][ATTEMPT][/attack] {method} {url} - Type: [yellow]{payload_type}[/yellow] - Payload: '{payload_display}' -> Status: [{status_color}]{status}[/{status_color}] (Len: {response_len}) {vuln_marker}")

    def print_summary(self, summary: dict):
        """Muestra un resumen de los hallazgos."""
        self.console.rule("[bold] Scan Summary [/bold]", style="info")

        def print_table(title: str, data: dict, key_col: str, value_col: str, style: str):
            table = Table(title=title, show_header=True, header_style=f"bold {style}", padding=(0, 1))
            table.add_column(key_col, style="dim")
            table.add_column(value_col, justify="right")
            total = 0
            for key, count in sorted(data.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    style_key = f"severity_{key.lower()}" if key in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else ""
                    table.add_row(f"[{style_key}]{key}[/{style_key}]" if style_key else key, str(count))
                    total += count
            if total > 0:
                self.console.print(table)
            else:
                self.print_info(f"No findings reported for {title.lower()}.")

        try:
            print_table("Findings by Severity", summary.get("by_severity", {}), "Severity", "Count", "magenta")
            print_table("Findings by Type", summary.get("by_type", {}), "Type", "Count", "blue")

            if endpoints := summary.get("vulnerable_endpoints"):
                self.console.print("\n[bold yellow]Potentially Vulnerable Endpoints:[/bold yellow]")
                for ep in endpoints[:20]:
                    self.console.print(f"- {ep}")
                if len(endpoints) > 20:
                    self.console.print(f"- ... and {len(endpoints) - 20} more.")
        except Exception as e:
            logger.error(f"Error mostrando resumen: {e}")
            self.print_error(f"Failed to display summary: {e}")

        self.console.rule(style="info")

    def print_code(self, code: str, language: str = "javascript", title: str = "Code Snippet"):
        """Muestra código con resaltado de sintaxis."""
        if not code:
            self.print_warning(f"Attempted to print empty code block for '{title}'")
            return
        try:
            syntax = Syntax(code, language, theme="paraiso-dark", line_numbers=True, background_color="default")
            self.console.print(Panel(syntax, title=title, border_style="blue", expand=False))
        except Exception as e:
            logger.error(f"Error resaltando código para {title}: {e}")
            self.console.print(Panel(code, title=f"{title} (plaintext)", border_style="red"))

    def create_progress(self, description: str = "Processing...") -> Progress:
        """Crea un contexto de barra de progreso."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True
        )