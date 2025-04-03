from typing import Dict, List, Any, Optional
import json
from datetime import datetime
import threading
import subprocess
import os
import time
from collections import defaultdict
from console_manager import ConsoleManager
from urllib.parse import urlparse

class ReportGenerator:
    def __init__(self, console_manager: ConsoleManager, output_file: str = None, domain_dir: str = None):
        """Initialize the ReportGenerator with console manager."""
        self.console = console_manager
        self.findings = defaultdict(list)  # Inicializar como defaultdict para evitar KeyError
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
        
        # Usar el directorio del dominio si está disponible
        self.domain_dir = domain_dir or 'reports'
        
        # Asegurar que existan los directorios necesarios
        os.makedirs(self.domain_dir, exist_ok=True)
        os.makedirs(os.path.join(self.domain_dir, 'logs'), exist_ok=True)
        os.makedirs(os.path.join(self.domain_dir, 'screenshots'), exist_ok=True)
        os.makedirs(os.path.join(self.domain_dir, 'responses'), exist_ok=True)
        
        # Configurar nombres de archivos
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.report_file = os.path.join(self.domain_dir, f"report_{timestamp}.json")
        self.findings_log_file = os.path.join(self.domain_dir, 'logs', f"findings_{timestamp}.log")
        self.events_log_file = os.path.join(self.domain_dir, 'logs', f"events_{timestamp}.log")
        
        # Si se especifica un archivo de salida, usarlo
        if output_file:
            self.report_file = os.path.join(self.domain_dir, f"{output_file}.json")
            self.findings_log_file = os.path.join(self.domain_dir, 'logs', f"{output_file}_findings.log")
            self.events_log_file = os.path.join(self.domain_dir, 'logs', f"{output_file}_events.log")
            
        # Crear archivos de log vacíos
        for log_file in [self.findings_log_file, self.events_log_file]:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"=== Log iniciado el {datetime.now().isoformat()} ===\n")
                f.flush()
                os.fsync(f.fileno())

    def add_findings(self, section: str, findings: List[Dict[str, Any]]):
        """Adds a list of findings under a specific section, ensuring severity."""
        if not findings:
            return

        processed_findings = []
        for finding in findings:
            if isinstance(finding, dict):
                processed_finding = self._ensure_severity(finding)
                processed_findings.append(processed_finding)
                
                # Registrar hallazgo en tiempo real
                self._log_finding(processed_finding)
            else:
                self.console.print_warning(f"Ignorado hallazgo no-dict en sección '{section}': {str(finding)[:100]}")

        if processed_findings:
            self.findings[section].extend(processed_findings)
            self.console.print_debug(f"Agregados {len(processed_findings)} hallazgos a la sección '{section}'")

    def _log_finding(self, finding: dict):
        """Registra un hallazgo en el archivo de log en tiempo real."""
        try:
            timestamp = datetime.now().isoformat()
            severity = finding.get("severity", "INFO")
            finding_type = finding.get("type", "unknown")
            url = finding.get("url", "N/A")
            details = finding.get("details", {})
            
            # Formatear detalles para el log
            details_str = ""
            if isinstance(details, dict):
                for k, v in details.items():
                    details_str += f"\n  {k}: {v}"
            else:
                details_str = str(details)
            
            # Crear entrada de log
            log_entry = f"[{timestamp}] [{severity}] {finding_type}\nURL: {url}{details_str}\n{'='*80}\n"
            
            # Escribir en el archivo de log
            with open(self.findings_log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
                f.flush()  # Forzar la escritura inmediata
                os.fsync(f.fileno())  # Asegurar que se escriba en el disco
                
            # Mostrar en la consola
            self.console.print_finding(finding_type, severity, details, url)
                
        except Exception as e:
            self.console.print_error(f"Error registrando hallazgo en log: {e}")

    def log_realtime_event(self, event_type: str, message: str, details: Optional[Dict] = None):
        """Registra un evento en tiempo real en el archivo de log."""
        try:
            timestamp = datetime.now().isoformat()
            log_entry = f"[{timestamp}] [{event_type}] {message}"
            
            if details:
                for k, v in details.items():
                    log_entry += f"\n  {k}: {v}"
            
            log_entry += "\n" + "-"*80 + "\n"
            
            # Escribir en el archivo de log
            with open(self.events_log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
                f.flush()  # Forzar la escritura inmediata
                os.fsync(f.fileno())  # Asegurar que se escriba en el disco
                
            # Mostrar en la consola según el tipo de evento
            if event_type == "ERROR":
                self.console.print_error(message)
            elif event_type == "WARNING":
                self.console.print_warning(message)
            elif event_type == "INFO":
                self.console.print_info(message)
            elif event_type == "SUCCESS":
                self.console.print_success(message)
            else:
                self.console.print_debug(message)
                
        except Exception as e:
            self.console.print_error(f"Error registrando evento en log: {e}")

    def _ensure_severity(self, finding: dict) -> dict:
        """Assigns a default severity if missing or invalid, based on type."""
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        current_severity = finding.get("severity")

        if isinstance(current_severity, str) and current_severity.upper() in valid_severities:
            finding["severity"] = current_severity.upper()
        else:
            determined_severity = self._determine_severity(finding)
            finding["severity"] = determined_severity
            if not current_severity or (isinstance(current_severity, str) and current_severity.upper() not in valid_severities):
                self.console.print_debug(f"Assigned default severity '{determined_severity}' to finding type '{finding.get('type','unknown')}'")
        return finding

    def set_scan_target(self, target: str):
        """Establece el objetivo del escaneo y lo registra en los logs."""
        self.metadata["scan_target"] = target
        self.log_realtime_event("SCAN_TARGET", f"Objetivo establecido: {target}")

    def set_scan_status(self, status: str):
        """Establece el estado del escaneo y lo registra en los logs."""
        self.metadata["scan_status"] = status
        self.log_realtime_event("SCAN_STATUS", f"Estado del escaneo: {status}")

    def finalize_report(self):
        """Finaliza el reporte y registra la finalización en los logs."""
        try:
            if self.metadata["scan_end_time"] is None:
                end_time = time.time()
                self.metadata["scan_end_time"] = end_time
                self.metadata["scan_end"] = datetime.now().isoformat()
                if self.metadata["scan_start_time"]:
                    self.metadata["scan_duration_seconds"] = round(end_time - self.metadata["scan_start_time"], 2)
                
                # Registrar finalización en logs
                self.log_realtime_event("SCAN_COMPLETE", "Escaneo finalizado", {
                    "duración_segundos": self.metadata["scan_duration_seconds"],
                    "total_hallazgos": sum(len(findings) for findings in self.findings.values())
                })
        except Exception as e:
            self.console.print_error(f"Error finalizando reporte: {e}")

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

    def generate_report(self, filename_prefix: str):
        """Generates the JSON report file."""
        self.finalize_report()

        report_summary = self.generate_summary()

        report_data = {
            "metadata": self.metadata,
            "summary": report_summary,
            "findings": {section: findings_list for section, findings_list in self.findings.items() if findings_list}
        }

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

        except Exception as e:
            self.console.print_error(f"Failed to write JSON report to {json_filename}: {e}")
