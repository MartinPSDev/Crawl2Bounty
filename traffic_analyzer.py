from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs
import json
import base64
import re
import time
import logging

# Import ConsoleManager
from console_manager import ConsoleManager
from playwright.async_api import BrowserContext, Request, Response, Error as PlaywrightError

# Configurar logger para este módulo
logger = logging.getLogger(__name__)

class TrafficAnalyzer:
    def __init__(self, console_manager: ConsoleManager):
        self.console = console_manager
        self.requests: List[Dict[str, Any]] = []
        self.responses: List[Dict[str, Any]] = []
        self.failed_requests: List[Dict[str, Any]] = []
        self.console.print_debug("Traffic Analyzer Inicializado")
        self.scope_domain: Optional[str] = None

    def set_scope(self, url: str):
        """Establece el alcance basado en la URL objetivo inicial."""
        try:
            self.scope_domain = urlparse(url).netloc.lower()
            self.console.print_debug(f"Alcance del Traffic Analyzer establecido a: {self.scope_domain}")
        except Exception as e:
            self.console.print_error(f"Error al establecer alcance en Traffic Analyzer desde URL {url}: {e}")

    async def capture_traffic(self, browser_context: BrowserContext):
        """Captura tráfico adjuntando manejadores al BrowserContext."""
        if not hasattr(browser_context, 'on'):
            self.console.print_error("BrowserContext inválido proporcionado a capture_traffic.")
            return
        self.console.print_debug("Adjuntando manejadores de captura de tráfico al contexto del navegador...")
        try:
            browser_context.on("request", self._handle_request)
            browser_context.on("response", self._handle_response)
            browser_context.on("requestfailed", self._handle_request_failed)
            self.console.print_debug("Manejadores de captura de tráfico adjuntados exitosamente.")
        except Exception as e:
            self.console.print_error(f"Error al adjuntar manejadores de tráfico: {e}")

    def _handle_request(self, request: Request):
        """Callback para el evento 'request'."""
        try:
            req_data = {
                "url": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "post_data": request.post_data,
                "resource_type": request.resource_type,
                "is_navigation": request.is_navigation_request(),
                "timestamp": time.time()
            }
            self.requests.append(req_data)
            if self.console.verbose or request.method != 'GET' or request.is_navigation_request():
                self.console.print_debug(f"Request: {request.method} {request.url[:100]}...")
        except Exception as e:
            logger.exception(f"Error manejando evento request para {request.url}: {e}")
            self.console.print_warning(f"Error manejando evento request: {e}")

    async def _handle_response(self, response: Response):
        """Callback para el evento 'response'."""
        body: Optional[str] = None
        body_base64: Optional[str] = None
        error_msg: Optional[str] = None
        status_code = -1
        resp_url = "N/A"
        headers_dict = {}
        ok = False
        resource_type = "unknown"
        from_sw = False
        req = response.request

        try:
            status_code = response.status
            resp_url = response.url
            headers_dict = dict(response.headers)
            ok = response.ok
            resource_type = req.resource_type if req else "unknown"
            from_sw = response.from_service_worker()

            content_type = headers_dict.get('content-type', '').lower()
            content_length_str = headers_dict.get('content-length')
            content_length = int(content_length_str) if content_length_str and content_length_str.isdigit() else 0
            max_body_size = 500 * 1024

            is_text_likely = any(ct in content_type for ct in ['html', 'text', 'json', 'xml', 'javascript', 'css', 'urlencoded'])
            should_read_body = is_text_likely and content_length < max_body_size

            if should_read_body:
                try:
                    body_bytes = await response.body()
                    try:
                        body = body_bytes.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        body = body_bytes.decode('latin-1', errors='replace')
                        error_msg = "Error decodificación UTF-8, usando latin-1"
                except PlaywrightError as pe:
                    error_msg = f"Error PW obteniendo body: {pe}"
                except Exception as e:
                    error_msg = f"Error obteniendo body: {e}"
            elif content_length >= max_body_size:
                error_msg = f"Body de respuesta demasiado grande ({content_length} bytes). Omitido."

            resp_data = {
                "url": resp_url,
                "status": status_code,
                "ok": ok,
                "headers": headers_dict,
                "body": body,
                "error_message": error_msg,
                "resource_type": resource_type,
                "from_service_worker": from_sw,
                "timestamp": time.time()
            }
            self.responses.append(resp_data)

            log_preview = f"(Tamaño:{content_length})" + (f" (Error Body: {error_msg})" if error_msg else "")
            if not ok:
                self.console.print_warning(f"Response: {status_code} {resp_url[:100]}... {log_preview}")
            elif self.console.verbose:
                self.console.print_debug(f"Response: {status_code} {resp_url[:100]}... {log_preview}")

        except Exception as e:
            logger.exception(f"Error manejando evento response para {resp_url}: {e}")
            self.console.print_warning(f"Error manejando evento response: {e}")

    def _handle_request_failed(self, request: Request):
        """Callback para el evento 'requestfailed'."""
        try:
            failure_text = request.failure()
            req_data = {
                "url": request.url,
                "method": request.method,
                "error": failure_text,
                "timestamp": time.time()
            }
            self.failed_requests.append(req_data)
            self.console.print_warning(f"Request Fallido: {request.method} {request.url[:100]}... Error: {failure_text}")
        except Exception as e:
            logger.exception(f"Error manejando evento requestfailed para {request.url}: {e}")
            self.console.print_warning(f"Error manejando evento requestfailed: {e}")

    def analyze_traffic(self) -> List[Dict[str, Any]]:
        """Analiza el tráfico capturado y retorna hallazgos."""
        self.console.print_info("Analizando tráfico capturado...")
        findings = []
        processed = set()

        requests_copy = list(self.requests)
        responses_copy = list(self.responses)

        # Patrones y palabras clave sensibles
        sensitive_kw_url = ['password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'auth', 'sessionid', 'jsessionid', 'bearer', 'jwt']
        sensitive_kw_post = ['password', 'passwd', 'pwd', 'secret', 'creditcard', 'card[number]', 'cvv', 'ssn', 'auth', 'token']
        sensitive_hdr = ['authorization', 'x-api-key', 'x-auth-token', 'proxy-authorization', 'cookie', 'set-cookie']
        sensitive_cookie = ['sessionid', 'sess', 'auth', 'jwt', 'userid', 'admin', 'role', 'token']
        
        info_disc_patterns = [
            re.compile(r'(error|exception|traceback|stack trace|debug error)', re.IGNORECASE),
            re.compile(r'phpinfo\(\)', re.IGNORECASE),
            re.compile(r'(?:php|apache|nginx|iis|python|ruby|java|node\.js|asp\.net)[/\s-]?([\d\.]+)', re.IGNORECASE),
            re.compile(r'jboss|tomcat|jetty|glassfish|websphere|weblogic', re.IGNORECASE),
            re.compile(r'ORA-\d{5}', re.IGNORECASE),
            re.compile(r'(SQLSTATE\[\d+\]|sql error|mysql_)', re.IGNORECASE),
            re.compile(r'(Microsoft VBScript runtime|Microsoft OLE DB|System\.Web)', re.IGNORECASE),
            re.compile(r'Internal Server Error|Runtime Error', re.IGNORECASE),
            re.compile(r'(debug|trace)\s*=\s*(true|1)', re.IGNORECASE),
        ]
        internal_ip_pattern = re.compile(r'(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})')

        # Análisis de requests
        for req in requests_copy:
            url = req['url']
            method = req['method']
            headers = req.get('headers', {})
            key_base = url[:150]

            # 1. Información sensible en parámetros URL (GET)
            if method == 'GET':
                key = f"url_sens:{key_base}"
                if key not in processed:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    for p_name in params:
                        if any(kw in p_name.lower() for kw in sensitive_kw_url):
                            findings.append({
                                "type": "traffic_sensitive_info_in_url",
                                "severity": "MEDIUM",
                                "url": url,
                                "details": f"Parámetro '{p_name}'"
                            })
                            processed.add(key)
                            break

            # 2. Información sensible en datos POST
            if method == 'POST' and req.get('post_data'):
                key = f"post_sens:{key_base}"
                if key not in processed:
                    post_str = req['post_data']
                    found = False
                    if isinstance(post_str, str):
                        content_type = headers.get('content-type', '').lower()
                        if 'application/x-www-form-urlencoded' in content_type:
                            params = parse_qs(post_str)
                        elif 'application/json' in content_type:
                            try:
                                params = json.loads(post_str)
                                params = params if isinstance(params, dict) else {}
                            except:
                                params = {}
                        else:
                            params = {}

                        if params:
                            if any(kw in k.lower() for k in params for kw in sensitive_kw_post):
                                found = True
                        if not found and any(f'"{kw}"' in post_str.lower() or f"'{kw}'" in post_str.lower() for kw in sensitive_kw_post):
                            found = True

                    if found:
                        findings.append({
                            "type": "traffic_sensitive_info_in_post",
                            "severity": "MEDIUM",
                            "url": url,
                            "details": "Datos POST contienen claves/palabras clave potencialmente sensibles."
                        })
                        processed.add(key)

            # 3. Headers de request sensibles
            key = f"req_hdr_sens:{key_base}"
            if key not in processed:
                for h_name, h_value in headers.items():
                    h_lower = h_name.lower()
                    is_sensitive = False
                    details = ""
                    if any(kw in h_lower for kw in sensitive_hdr):
                        if h_lower == 'cookie':
                            try:
                                cookies = [c.split('=',1)[0].strip() for c in h_value.split(';') if '=' in c]
                                found_c = [c for c in cookies if any(sk in c.lower() for sk in sensitive_cookie)]
                                if found_c:
                                    is_sensitive = True
                                    details = f"Cookie(s) sensible(s): {', '.join(found_c)}"
                            except:
                                pass
                        elif h_lower == 'authorization' and h_value.lower().startswith('basic '):
                            try:
                                decoded_auth = base64.b64decode(h_value[6:]).decode()
                                details = f"Header Basic Auth (decodificado): {decoded_auth[:30]}..."
                                is_sensitive = True
                            except Exception:
                                details = "Header Basic Auth (falló decodificación)"
                                is_sensitive = True
                        elif h_value and len(h_value) > 15:
                            is_sensitive = True
                            details = f"Header potencialmente sensible: {h_name}"

                    if is_sensitive:
                        findings.append({
                            "type": "traffic_sensitive_info_in_request_header",
                            "severity": "MEDIUM",
                            "url": url,
                            "details": details
                        })
                        processed.add(key)
                        break

            # 7. Exposición de IPs internas en URL/Headers
            key = f"req_ip_disc:{key_base}"
            if key not in processed:
                found_ip = internal_ip_pattern.search(url)
                if not found_ip:
                    for h_name, h_value in headers.items():
                        if isinstance(h_value, str):
                            found_ip = internal_ip_pattern.search(h_value)
                            break
                if found_ip:
                    findings.append({
                        "type": "traffic_internal_ip_disclosure_request",
                        "severity": "LOW",
                        "url": url,
                        "details": f"Patrón de IP interna encontrado: {found_ip.group(1)}"
                    })
                    processed.add(key)

        # Análisis de responses
        for resp in responses_copy:
            url = resp['url']
            status = resp['status']
            headers = resp.get('headers', {})
            body = resp.get('body', '') if isinstance(resp.get('body'), str) else ""
            key_base = url[:150]

            # 4. Headers de respuesta sensibles
            key = f"resp_hdr_sens:{key_base}"
            if key not in processed:
                for h_name, h_value in headers.items():
                    h_lower = h_name.lower()
                    if h_lower == 'set-cookie':
                        try:
                            c_name = h_value.split(';')[0].split('=', 1)[0].strip()
                            if any(sk in c_name.lower() for sk in sensitive_cookie):
                                findings.append({
                                    "type": "traffic_sensitive_info_in_response_header",
                                    "severity": "MEDIUM",
                                    "url": url,
                                    "details": f"Cookie potencialmente sensible configurada: '{c_name}'"
                                })
                                processed.add(key)
                                break
                        except:
                            pass
                    elif isinstance(h_value, str) and len(h_value) > 20 and (any(kw in h_lower for kw in sensitive_hdr) or any(kw in h_value for kw in sensitive_kw_url)):
                        findings.append({
                            "type": "traffic_sensitive_info_in_response_header",
                            "severity": "MEDIUM",
                            "url": url,
                            "details": f"Datos potencialmente sensibles en header de respuesta '{h_name}'"
                        })
                        processed.add(key)
                        break

            # 5. Divulgación de información en bodies de respuesta
            key = f"info_disc:{key_base}"
            if key not in processed and body:
                body_sample = body[:5000]
                for pattern in info_disc_patterns:
                    match = pattern.search(body_sample)
                    if match:
                        findings.append({
                            "type": "traffic_information_disclosure_body",
                            "severity": "LOW",
                            "url": url,
                            "details": f"Coincidencia de patrón de divulgación: '{match.group(0)[:50]}...'"
                        })
                        processed.add(key)
                        break

            # 6. Headers de seguridad faltantes
            key = f"sec_hdr:{urlparse(url).netloc}"
            if key not in processed:
                missing_headers = []
                expected_headers = {
                    "strict-transport-security": None,
                    "content-security-policy": None,
                    "x-content-type-options": "nosniff",
                    "x-frame-options": ["deny", "sameorigin"],
                }
                present_headers_lower = {h.lower() for h in headers.keys()}
                for name, expected_values in expected_headers.items():
                    if name not in present_headers_lower:
                        missing_headers.append(name)
                    elif expected_values:
                        h_val = headers.get(name, '').lower()
                        if isinstance(expected_values, str) and expected_values not in h_val:
                            missing_headers.append(f"{name}!={expected_values}")
                        elif isinstance(expected_values, list) and not any(val in h_val for val in expected_values):
                            missing_headers.append(f"{name} no en {expected_values}")

                if missing_headers:
                    findings.append({
                        "type": "traffic_missing_security_headers",
                        "severity": "LOW",
                        "url": url,
                        "details": f"Headers de seguridad faltantes/inseguros: {', '.join(missing_headers)}"
                    })
                    processed.add(key)

            # 8. IPs internas en body de respuesta
            key = f"resp_ip_disc:{key_base}"
            if key not in processed and body:
                found_ip = internal_ip_pattern.search(body[:5000])
                if found_ip:
                    findings.append({
                        "type": "traffic_internal_ip_disclosure_response",
                        "severity": "LOW",
                        "url": url,
                        "details": f"Patrón de IP interna encontrado en respuesta: {found_ip.group(1)}"
                    })
                    processed.add(key)

        self.console.print_info(f"Análisis de tráfico completado. Encontrados {len(findings)} hallazgos potenciales.")
        return findings

    def get_endpoints(self) -> List[str]:
        """Extrae URLs únicas (potenciales endpoints) del tráfico capturado."""
        endpoints = set()
        urls_seen = set()
        for request in self.requests:
            try:
                url = request.get("url")
                if url:
                    norm_url = self._normalize_url(url)
                    if norm_url not in urls_seen:
                        urls_seen.add(norm_url)
                        parsed = urlparse(url)
                        if not re.search(r'\.(js|css|png|jpg|jpeg|gif|woff|woff2|svg|ico|map|json)$', parsed.path, re.IGNORECASE):
                            endpoints.add(url)
            except Exception:
                continue
        self.console.print_debug(f"Extraídos {len(endpoints)} endpoints potenciales únicos del tráfico.")
        return sorted(list(endpoints))

    def _is_in_scope(self, url: str) -> bool:
        """Verifica si la URL está dentro del alcance definido."""
        if not self.scope_domain:
            return True
        try:
            return urlparse(url).netloc.lower() == self.scope_domain
        except Exception:
            return False
