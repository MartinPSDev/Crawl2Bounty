from typing import Dict, List, Any
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
    def __init__(self, console_manager: ConsoleManager):
        self.console = console_manager
        self.findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.metadata = {
            "scan_start_time": time.time(),
            "scan_start_iso": datetime.now().isoformat(),
            "scan_end_time": None,
            "scan_end_iso": None,
            "version": "1.1.0",
            "scan_target": None,
            "scan_duration_seconds": None,
            "scan_status": "initiated"
        }
        self.console.print_debug("ReportGenerator initialized.")

    def add_findings(self, section: str, findings: List[Dict[str, Any]]):
        """Adds a list of findings under a specific section, ensuring severity."""
        if not findings:
            return

        processed_findings = []
        for finding in findings:
            if isinstance(finding, dict):
                processed_findings.append(self._ensure_severity(finding))
            else:
                self.console.print_warning(f"Ignored non-dict finding in section '{section}': {str(finding)[:100]}")

        if processed_findings:
            self.findings[section].extend(processed_findings)
            self.console.print_debug(f"Added {len(processed_findings)} findings to report section '{section}'")

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
        self.metadata["scan_target"] = target

    def set_scan_status(self, status: str):
        """Sets the final scan status (e.g., completed, interrupted, failed)."""
        self.metadata["scan_status"] = status

    def finalize_report(self):
        """Calculates duration and sets final timestamps."""
        if self.metadata["scan_end_time"] is None:
            end_time = time.time()
            self.metadata["scan_end_time"] = end_time
            self.metadata["scan_end_iso"] = datetime.now().isoformat()
            if self.metadata["scan_start_time"]:
                self.metadata["scan_duration_seconds"] = round(end_time - self.metadata["scan_start_time"], 2)

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
