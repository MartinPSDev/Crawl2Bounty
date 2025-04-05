import logging
import os
from rich.console import Console
from console_manager import ConsoleManager
from smart_detector import SmartDetector
from attack_engine import AttackEngine
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
import json
from datetime import datetime
import time
from collections import defaultdict
import threading
import subprocess
import asyncio
import signal
import sys
import aiofiles

# Configurar logger global
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Configurar un handler para el logger
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Asegúrate de que `console` esté definido
console = ConsoleManager(verbose=True)

class ReportGenerator:
    def __init__(self, console_manager: ConsoleManager, output_file: str = None, domain_dir: str = None, report_format: str = "txt"):
        self.console = console_manager
        self.findings = defaultdict(list)
        self.metadata = {
            "scan_start": datetime.now().isoformat(),
            "scan_start_time": time.time(),
            "scan_end": None,
            "scan_end_time": None,
            "scan_duration_seconds": None,
            "total_urls": 0,
            "total_findings": 0,
            "vulnerability_types": set(),
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        self.domain_dir = domain_dir or 'reports'
        self.report_format = report_format  # Formato del reporte
        os.makedirs(self.domain_dir, exist_ok=True)
        self.realtime_events = []

    def add_findings(self, category: str, findings: list):
        """Añade hallazgos a una categoría específica."""
        if category not in self.findings:
            self.findings[category] = []
        self.findings[category].extend(findings)
        self.console.print_debug(f"Added {len(findings)} findings to category '{category}'")

    def log_realtime_event(self, event_type: str, message: str, details: dict = None):
        """Registra un evento en tiempo real relevante y lo guarda en un archivo de texto."""
        # Filtrar eventos relevantes
        relevant_status_codes = [200, 301, 302] + list(range(500, 600))
        status_code = details.get('status_code') if details else None

        if status_code in relevant_status_codes:
            event = {"type": event_type, "message": message, "details": details or {}}
            self.realtime_events.append(event)
            self.console.print_info(f"{event_type}: {message}")

            # Guardar el evento en un archivo de texto
            try:
                realtime_report_path = os.path.join(self.domain_dir, 'realtime_events.txt')
                with open(realtime_report_path, 'a') as realtime_file:
                    realtime_file.write(f"{datetime.now().isoformat()} - {event_type}: {message} - {json.dumps(details)}\n")
            except Exception as e:
                self.console.print_error(f"Error guardando evento en tiempo real: {e}")

    def _generate_summary(self):
        """Genera un resumen del escaneo."""
        return {
            "total_urls": self.metadata["total_urls"],
            "total_findings": self.metadata["total_findings"],
            "vulnerability_types": list(self.metadata["vulnerability_types"]),  # Convertir set a lista
            "severity_counts": self.metadata["severity_counts"]
        }

    async def generate_report(self, filename_prefix: str):
        """Genera el reporte en el formato especificado."""
        try:
            report_path = os.path.join(self.domain_dir, f"{filename_prefix}.{self.report_format}")
            
            if self.report_format == "json":
                await self._generate_json_report(report_path)
            elif self.report_format == "txt":
                await self._generate_txt_report(report_path)
            elif self.report_format == "md":
                await self._generate_markdown_report(report_path)
            else:
                raise ValueError(f"Formato no soportado: {self.report_format}")
            
            self.console.print_success(f"Reporte guardado en: {report_path}")
        except Exception as e:
            self.console.print_error(f"Error al generar el reporte: {e}")
            logger.error(f"Error al generar el reporte: {e}", exc_info=True)

    async def _generate_json_report(self, report_path: str):
        """Genera el reporte en formato JSON."""
        async with aiofiles.open(report_path, 'w') as report_file:
            await report_file.write(json.dumps({
                "metadata": {
                    **self.metadata,
                    "vulnerability_types": list(self.metadata["vulnerability_types"])  # Convertir set a lista
                },
                "summary": self._generate_summary(),
                "findings": self.findings
            }, indent=4))

    async def _generate_txt_report(self, report_path: str):
        """Genera el reporte en formato TXT."""
        async with aiofiles.open(report_path, 'w') as report_file:
            await report_file.write("=== Resumen del Escaneo ===\n")
            await report_file.write(f"Inicio del escaneo: {self.metadata['scan_start']}\n")
            await report_file.write(f"Fin del escaneo: {self.metadata['scan_end']}\n")
            await report_file.write(f"Duración: {self.metadata['scan_duration_seconds']} segundos\n")
            await report_file.write(f"Total de URLs escaneadas: {self.metadata['total_urls']}\n")
            await report_file.write(f"Total de hallazgos: {self.metadata['total_findings']}\n")
            await report_file.write("\n=== Hallazgos ===\n")
            for category, findings in self.findings.items():
                await report_file.write(f"\n{category}:\n")
                for finding in findings:
                    await report_file.write(f"- {finding}\n")

    async def _generate_markdown_report(self, report_path: str):
        """Genera el reporte en formato Markdown."""
        async with aiofiles.open(report_path, 'w') as report_file:
            await report_file.write("# Resumen del Escaneo\n")
            await report_file.write(f"- **Inicio del escaneo:** {self.metadata['scan_start']}\n")
            await report_file.write(f"- **Fin del escaneo:** {self.metadata['scan_end']}\n")
            await report_file.write(f"- **Duración:** {self.metadata['scan_duration_seconds']} segundos\n")
            await report_file.write(f"- **Total de URLs escaneadas:** {self.metadata['total_urls']}\n")
            await report_file.write(f"- **Total de hallazgos:** {self.metadata['total_findings']}\n")
            await report_file.write("\n## Hallazgos\n")
            for category, findings in self.findings.items():
                await report_file.write(f"\n### {category}\n")
                for finding in findings:
                    await report_file.write(f"- {finding}\n")

    async def save_js_urls(self, js_urls: List[str], domain: str):
        """Guarda las URLs de archivos .js en un archivo de texto."""
        try:
            js_report_path = os.path.join(self.domain_dir, f"{domain}_js_urls.txt")
            async with aiofiles.open(js_report_path, 'w') as js_file:
                for js_url in js_urls:
                    await js_file.write(f"{js_url}\n")
            self.console.print_success(f"JavaScript URLs saved to: {js_report_path}")
        except Exception as e:
            self.console.print_error(f"Error saving JS URLs: {e}")

async def run_scan(crawler, detector, attack_engine, report_generator, save_screenshots=False, save_responses=False):
    from site_crawler import SmartCrawler  # Importación dentro de la función
    """Ejecuta el escaneo completo."""
    try:
        # Iniciar el crawling
        await crawler.start_crawl(crawler.base_url)
        
        # Analizar URLs descubiertas
        for url in crawler.visited_urls:
            try:
                # Analizar JavaScript
                js_findings = await detector.analyze_js(url)
                if js_findings:
                    report_generator.add_findings("javascript_analysis", js_findings)
                
                # Analizar contenido dinámico
                dynamic_findings = await detector.analyze_dynamic_content(url)
                if dynamic_findings:
                    report_generator.add_findings("dynamic_analysis", dynamic_findings)
                
                # Probar vulnerabilidades
                if attack_engine.interactsh_url:
                    vuln_findings = await attack_engine.test_vulnerabilities(url)
                    if vuln_findings:
                        report_generator.add_findings("vulnerability_scan", vuln_findings)
                
                # Registrar finalización en logs
                report_generator.log_realtime_event("SCAN_COMPLETE", "Escaneo finalizado", {
                    "duración_segundos": report_generator.metadata["scan_duration_seconds"],
                    "total_hallazgos": sum(len(findings) for findings in report_generator.findings.values())
                })
            except Exception as e:
                report_generator.console.print_error(f"Error finalizando reporte: {e}")
    except Exception as e:
        report_generator.console.print_error(f"Error finalizando reporte: {e}")

    def generate_summary(self) -> dict:
        """Generates a summary dictionary from all collected findings."""
        summary = {
            "total_findings": 0,
            "by_severity": defaultdict(int),
            "by_type": defaultdict(int),
            "vulnerable_endpoints": set(),
        }

        all_findings_flat = [finding for section_findings in self.findings.values() for finding in section_findings]
        summary["total_findings"] = len(all_findings_flat)

        for finding in all_findings_flat:
            severity_key = finding.get("severity", "INFO").lower()
            finding_type = finding.get("type", "unknown")

            summary["by_severity"][severity_key] += 1
            summary["by_type"][finding_type] += 1

            url = finding.get("url")
            if url:
                try:
                    summary["vulnerable_endpoints"].add(urlparse(url)._replace(query="", fragment="").geturl())
                except Exception:
                    summary["vulnerable_endpoints"].add(url)

        summary["vulnerable_endpoints"] = sorted(list(summary["vulnerable_endpoints"]))
        return summary

    def _determine_severity(self, finding: dict) -> str:
        """Determines default severity based on finding type."""
        finding_type = finding.get("type", "").lower()

        critical_types = [
            "sql_injection", "command_injection", "ssti", "rce",
            "deserialization", "authentication_bypass", "privilege_escalation",
        ]
        high_types = [
            "xss_reflected", "xss_stored", "path_traversal", "forbidden_bypass", "ssrf",
            "sensitive_data_exposure",
            "js_dynamic_var_modification_error",
        ]
        medium_types = [
            "xss_dom", "open_redirect", "csrf", "information_disclosure",
            "directory_listing", "misconfiguration",
            "js_static_potential_api_key", "js_static_potential_password", "js_static_authorization_header",
            "traffic_sensitive_info",
            "js_dynamic_suspicious_call_chain",
            "js_dynamic_service_connection",
        ]
        low_types = [
            "http_security_headers_missing", "verbose_error_message",
            "software_version_disclosure",
            "js_static_internal_url", "js_static_interesting_endpoint",
            "traffic_internal_endpoint", "js_dynamic_active_single_char_var",
            "js_static_eval_usage", "js_static_html_manipulation", "js_static_storage_access",
            "js_static_sensitive_comment", "js_static_debug_flag",
            "js_error_on_click",
        ]
        info_types = [
            "network_request_on_click",
        ]

        for type_prefix in critical_types:
            if finding_type.startswith(type_prefix): return "CRITICAL"
        for type_prefix in high_types:
            if finding_type.startswith(type_prefix): return "HIGH"
        for type_prefix in medium_types:
            if finding_type.startswith(type_prefix): return "MEDIUM"
        for type_prefix in low_types:
            if finding_type.startswith(type_prefix): return "LOW"
        for type_prefix in info_types:
            if finding_type.startswith(type_prefix): return "INFO"

        return "INFO"

    def generate_report(self, filename_prefix: str, format: str = 'txt'):
        """Genera el archivo de reporte en el formato especificado."""
        self.finalize_report()

        report_summary = self.generate_summary()

        report_data = {
            "metadata": self.metadata,
            "summary": report_summary,
            "findings": {section: findings_list for section, findings_list in self.findings.items() if findings_list}
        }

        if format == 'json':
            json_filename = f"{filename_prefix}.json"
            try:
                with open(json_filename, "w", encoding="utf-8") as f:
                    json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
                self.console.print_success(f"JSON report saved to: {json_filename}")
            except TypeError as e:
                self.console.print_error(f"Failed to serialize report data to JSON for {json_filename}: {e}")
                self.console.print_warning("Attempting fallback JSON serialization...")
                try:
                    def fallback_serializer(obj):
                        if isinstance(obj, (datetime, time.struct_time)): return str(obj)
                        if isinstance(obj, bytes): return obj.decode('utf-8', errors='replace')
                        return repr(obj)
                    with open(json_filename + ".fallback", "w", encoding="utf-8") as f:
                        json.dump(report_data, f, indent=2, ensure_ascii=False, default=fallback_serializer)
                    self.console.print_success(f"Fallback JSON report saved to: {json_filename}.fallback")
                except Exception as fallback_e:
                    self.console.print_error(f"Fallback JSON serialization also failed: {fallback_e}")

        elif format == 'md':
            # Lógica para generar archivo Markdown
            pass
        else:  # Por defecto, generar en formato txt
            txt_filename = os.path.join(self.domain_dir, f"{filename_prefix}.txt")
            with open(txt_filename, "w", encoding="utf-8") as f:
                f.write("Reporte\n")
                f.write("========\n")
                f.write(f"Metadata: {self.metadata}\n")
                f.write(f"Resumen: {report_summary}\n")
                f.write("Hallazgos:\n")
                for section, findings in report_data['findings'].items():
                    f.write(f"{section}:\n")
                    for finding in findings:
                        f.write(f"- {finding}\n")
            self.console.print_success(f"TXT report saved to: {txt_filename}")

async def shutdown(signal: signal.Signals, loop: asyncio.AbstractEventLoop):
    """Cierra todas las tareas al recibir una señal."""
    print("\nRecibido Ctrl+C, cerrando...")
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()

