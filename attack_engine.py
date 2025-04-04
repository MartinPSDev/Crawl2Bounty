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
            duration = time.time() - start_time
            self.console.print_debug(f"Response [{payload_info}]: {response.status_code} in {duration:.2f}s (Len:{len(response.content)}) for {url}")
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
            path, path + '/', f"/{path.strip('/')}", f"/{path.strip('/')}/",
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

    async def test_vulnerability(self, url: str, method: str = "GET", params: Optional[dict] = None, data: Optional[dict] = None):
        """Main function to test multiple vulnerabilities on an endpoint/params."""
        params = params or {}
        data = data or {}
        target_fields = list(params.keys()) + list(data.keys())

        self.console.print_info(f"Initiating vulnerability checks for: {method} {url}")

        # If no params/data, check Path Traversal on path itself
        if not target_fields and '?' not in url and not data:
            self.console.print_debug(f"No params/data, checking Path Traversal on path for {url}")
            await self.test_path_traversal(url, method, path_itself=True)
            return # No field-based tests to run

        # Test each parameter/data field
        if target_fields:
             self.console.print_debug(f"Testing fields: {', '.join(target_fields)} for {url}")

        tasks = []
        for field in target_fields:
            if field: # Ensure field name is not empty
                tasks.extend([
                    self.test_sqli(url, method, params, data, field),
                    self.test_xss(url, method, params, data, field),
                    self.test_cmdi(url, method, params, data, field),
                    self.test_ssti(url, method, params, data, field),
                    self.test_path_traversal(url, method, params, data, field)
                ])
        # Run tests concurrently for all fields
        if tasks:
             await asyncio.gather(*tasks)

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
        expected_result_str = str(49) # 7*7

        async def run_check(payload_category: str, check_payloads: list, verification_func: callable, verification_desc: str) -> bool:
            payloads_to_test = check_payloads
            # Flatten nested dicts if necessary (like for code_execution)
            if payload_category == "code_execution":
                 payloads_to_test = [p for engine_payloads in check_payloads.values() for p in engine_payloads]

            for payload_template in payloads_to_test:
                 payload = payload_template
                 if "INTERACTSH_URL" in payload:
                     if not self.interactsh_url: continue
                     payload = payload.replace("INTERACTSH_URL", self.interactsh_url)

                 obfuscated_payload = self.detector.obfuscate_payload(payload, level=0) # No obfuscation for SSTI typically
                 test_values = [str(original_value) + obfuscated_payload, obfuscated_payload]

                 for test_val in test_values:
                    current_params=base_params.copy(); current_data=base_data.copy()
                    if field in current_params: current_params[field]=test_val
                    if field in current_data: current_data[field]=test_val
                    response = await self._make_request(url, method, params=current_params, data=current_data, payload_info=f"SSTI-{payload_category}")

                    if response:
                        is_vuln, details = await verification_func(response, expected_result_str, payload_template, test_val)
                        self.console.print_attack_attempt(url, method, f"SSTI-{payload_category}", test_val, response.status_code, len(response.content), is_vuln, verification_desc)
                        if is_vuln:
                            self.record_finding(f"ssti_{payload_category.lower()}", "CRITICAL", {
                                "field": field, "payload_used": payload, "test_value": test_val,
                                "verification": f"{verification_desc} ({details})"
                            }, url)
                            return True
            return False

        if await run_check("detection", SSTI_PAYLOADS['basic_detection'], self._verify_ssti_calc, f"Calculation Result ({expected_result_str})"): return
        if self.interactsh_url:
             if await run_check("oob", SSTI_PAYLOADS['code_execution'].get('generic_oob',[]), self._verify_oob, "OOB Interaction"): return

    async def _verify_ssti_calc(self, response: httpx.Response, expected_result: str, payload_template: str, test_val: str) -> Tuple[bool, str]:
        if not response: return False, "No Response"
        body = response.text
        if expected_result in body and payload_template not in body and test_val not in body:
             pattern = re.escape(expected_result)
             matches = list(re.finditer(pattern, body))
             payload_indices = [m.start() for m in re.finditer(re.escape(test_val), body)]
             if not payload_indices: payload_indices = [body.find(test_val)]

             for m in matches:
                 is_near = any(abs(m.start() - p_idx) < 100 for p_idx in payload_indices if p_idx != -1)
                 if is_near: continue

                 return True, f"Found calculated '{expected_result}' in response away from input"

        return False, f"Result '{expected_result}' not found or only reflected literally"

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
                 is_vuln, details = self._verify_path_traversal(response, payload)
                 self.console.print_attack_attempt(test_url, method, "PathTrav", payload, response.status_code, len(response.content), is_vuln, "File Content/Error")
                 if is_vuln:
                     self.record_finding("path_traversal", "HIGH", {
                         "target": "URL Path" if path_itself else f"Field: {field}",
                         "payload_used": payload, "tested_value": test_val,
                         "verification": f"Sensitive Content/Error ({details})"
                     }, url)
                     return

    def _verify_path_traversal(self, response: httpx.Response, payload: str) -> Tuple[bool, str]:
        if not response: return False, "No Response"
        text = response.text
        sensitive_content = {
            "root:x:0:0": "/etc/passwd content", "shadow:": "/etc/shadow content",
            "[boot loader]": "Windows boot.ini", "[fonts]": "Windows win.ini",
            "<?php": "PHP source", "<%@": "JSP source", "import java": "Java source",
            "def main": "Python source", "function(": "JavaScript source",
            "<title>Index of /": "Directory Listing", "Microsoft Windows": "Windows info",
            "Linux": "Linux info", "DOCUMENT_ROOT": "PHP Info/Environ",
        }
        for pattern, description in sensitive_content.items():
            if (pattern in text or pattern.lower() in text.lower()) and payload.lower() not in text.lower()[:len(payload)+200]:
                 return True, f"Found '{description}'"
        errors = ["failed to open stream", "include(", "require(", "file_get_contents(", "no such file", "failed opening required", "system cannot find the file", "could not find file", "仮想パス", "open_basedir restriction", "File does not exist"]
        if response.status_code != 404:
            text_lower = text.lower()
            for err in errors:
                if err in text_lower and payload.lower() not in err:
                    return True, f"Detected Error Signature: '{err}'"
        return False, "No Clear Indicator Found"

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


