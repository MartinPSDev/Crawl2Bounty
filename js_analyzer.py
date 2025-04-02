from typing import List, Dict, Tuple, Optional
import jsbeautifier
import re
import asyncio
from playwright.async_api import Page, Error as PlaywrightError
import logging
from urllib.parse import urljoin

# Configurar logger para este módulo
logger = logging.getLogger(__name__)

class JSAnalyzer:
    """Realiza análisis estático en código JavaScript."""
    def __init__(self):
        # Patrones expandidos
        self.patterns = {
            # Credenciales y Claves (Patrones más específicos y comunes)
            "amazon_aws_access_key_id": r'([^A-Z0-9]|^)(AKIA[0-9A-Z]{16})([^A-Z0-9]|$)',
            "amazon_aws_secret_key": r'([^A-Za-z0-9/+]|^)([A-Za-z0-9/+=]{40})([^A-Za-z0-9/+]|$)',
            "google_api_key": r'AIza[0-9A-Za-z\\-_]{35}',
            "github_token": r'ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}',
            "slack_token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            "firebase_url": r'https://[a-zA-Z0-9\-_]+\.firebaseio\.com',
            "generic_api_key": r'["\']?([aA][pP][iI]_?[kK][eE][yY]|[sS][eE][cC][rR][eE][tT]|[aA][uU][tT][hH]?[_]?[tT][oO][kK][eE][nN])["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-.~+=/]{16,})["\']',
            "basic_auth_pattern": r'["\']Authorization["\']\s*:\s*["\']Basic\s+([a-zA-Z0-9=+/]+)["\']',
            
            # Endpoints y URLs
            "internal_ip_url": r'https?://(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})[:/]?',
            "interesting_endpoint_path": r'["\'](/api/|/v\d+/|/_?internal/|/admin/|/graphql|/debug|/config|/swagger|/user/|/account/)',
            "url_with_params": r'https?://[^\s"\'`]+?\?[^\s"\'`]+=[^\s"\'`]+',
            
            # Funciones Peligrosas / Manipulación DOM
            "eval_usage": r'\b(eval|setTimeout|setInterval|Function)\s*\(',
            "html_manipulation": r'\.(innerHTML|outerHTML|document\.write)\s*[=:(]',
            "script_injection": r'createElement\s*\(\s*["\']script["\']\s*\)',
            
            # Acceso a Almacenamiento
            "storage_modification": r'(localStorage|sessionStorage)\.(setItem|removeItem|clear)\s*\(',
            "cookie_modification": r'document\.cookie\s*=',
            
            # Comentarios
            "sensitive_comment": r'//.*?(TODO|FIXME|HACK|XXX|PASSWORD|SECRET|KEY|TOKEN|BUG|VULN|ADMIN|PASSWD)',
            
            # Flags de Debug / Verificaciones de entorno
            "debug_flag": r'["\']?(debug|test|dev|staging|enable.?logging)["\']?\s*[:=]\s*(true|1)',
            "localhost_check": r'location\.hostname\s*===?\s*["\']localhost["\']',
        }
        logger.debug("JSAnalyzer (Estático) inicializado.")

    async def extract_js_from_page(self, page) -> List[str]:
        """Extracts JavaScript code from a Playwright page."""
        js_content = await self.extract_js_content(page)
        return js_content

    async def extract_js_content(self, page: Page) -> Dict[str, str]:
        """Extrae contenido de scripts inline y obtiene contenido de scripts externos."""
        js_sources: Dict[str, str] = {}
        page_url = page.url

        # 1. Extraer scripts inline
        try:
            inline_script_handles = await page.query_selector_all('script:not([src])', timeout=10000)
            logger.debug(f"Encontrados {len(inline_script_handles)} scripts inline en {page_url}")
            for i, script_handle in enumerate(inline_script_handles):
                content = await script_handle.text_content(timeout=5000)
                if content and content.strip():
                    js_sources[f"{page_url}#inline_{i+1}"] = content
        except PlaywrightError as e:
            logger.warning(f"Error extrayendo scripts inline en {page_url}: {e}")
        except Exception as e:
            logger.error(f"Error inesperado extrayendo scripts inline en {page_url}: {e}")

        # 2. Extraer y obtener scripts externos
        try:
            script_urls = await page.eval_on_selector_all('script[src]', 'scripts => scripts.map(s => s.src)', timeout=10000)
            logger.debug(f"Encontradas {len(script_urls)} URLs de scripts externos en {page_url}")
            fetch_tasks = []
            processed_urls = set()
            
            for url in script_urls:
                if url and isinstance(url, str):
                    try:
                        full_url = urljoin(page.url, url.strip())
                        if full_url not in processed_urls and full_url.startswith('http'):
                            processed_urls.add(full_url)
                            fetch_tasks.append(self._fetch_script(page, full_url))
                        elif not full_url.startswith('http'):
                            logger.debug(f"Ignorando fuente de script no-HTTP(S): {url}")
                    except ValueError:
                        logger.warning(f"Omitiendo URL de script malformada encontrada en {page_url}: {url}")
                        continue

            results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Excepción durante la obtención del script: {result}")
                elif isinstance(result, tuple) and len(result) == 2:
                    fetched_url, content = result
                    if content:
                        js_sources[fetched_url] = content
                else:
                    logger.warning(f"Tipo de resultado inesperado de _fetch_script: {type(result)}")

        except PlaywrightError as e:
            logger.warning(f"Error de Playwright extrayendo URLs de scripts externos en {page_url}: {e}")
        except Exception as e:
            logger.error(f"Error inesperado extrayendo/obteniendo scripts externos en {page_url}: {e}")

        return js_sources

    async def _fetch_script(self, page: Page, url: str) -> Tuple[str, Optional[str]]:
        """Obtiene el contenido de un script externo."""
        logger.debug(f"Obteniendo script externo: {url}")
        try:
            response = await page.request.get(url, timeout=15000)
            if response.ok:
                content_type = response.headers.get('content-type', '').lower()
                if any(ct in content_type for ct in ['javascript', 'ecmascript', 'text/plain', 'application/octet-stream']):
                    body_bytes = await response.body()
                    try:
                        return url, body_bytes.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        logger.warning(f"Decodificación UTF-8 fallida para {url}, intentando latin-1...")
                        return url, body_bytes.decode('latin-1', errors='replace')
                else:
                    logger.debug(f"Ignorando tipo de contenido no-JS '{content_type}' para script: {url}")
                    return url, None
            else:
                logger.warning(f"Error obteniendo script: Estado {response.status} para {url}")
                return url, None
        except PlaywrightError as e:
            logger.warning(f"Error de Playwright obteniendo script {url}: {e}")
            return url, None
        except Exception as e:
            logger.warning(f"Error general obteniendo script {url}: {e}")
            return url, None

    def deobfuscate_js(self, js_code: str) -> str:
        """Intenta desofuscación básica usando jsbeautifier."""
        if not js_code: return ""
        logger.debug(f"Beautificando código JS (longitud: {len(js_code)})...")
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            opts.space_in_empty_paren = True
            beautified = jsbeautifier.beautify(js_code, opts)
            logger.debug("Beautificación JS completada.")
            return beautified
        except Exception as e:
            logger.warning(f"Beautificación JS fallida: {e}")
            return js_code

    def find_suspicious_patterns(self, js_code: str) -> List[Dict]:
        """Encuentra patrones sospechosos definidos en self.patterns."""
        if not js_code: return []
        findings = []
        try:
            lines = js_code.splitlines()
        except Exception as e:
            logger.error(f"No se pudo dividir el código JS en líneas: {e}")
            return []

        logger.debug(f"Escaneando {len(lines)} líneas para {len(self.patterns)} patrones estáticos...")
        match_count = 0

        for name, pattern in self.patterns.items():
            try:
                regex = re.compile(str(pattern), re.IGNORECASE)
            except re.error as e:
                logger.error(f"Regex inválida para patrón '{name}': {e}")
                continue

            try:
                for line_num, line in enumerate(lines):
                    if len(line) > 5000: line = line[:5000]

                    for match in regex.finditer(line):
                        match_count += 1
                        value = match.group(1) if len(match.groups()) > 0 else match.group(0)
                        value = value.strip().strip('\'"`')
                        value_preview = value[:100] + '...' if len(value) > 100 else value

                        findings.append({
                            "type": name,
                            "value": value_preview,
                            "line_number": line_num + 1,
                            "context": line.strip()[:200],
                            "severity": "LOW"
                        })
            except Exception as e:
                logger.warning(f"Error buscando patrón '{name}' en línea {line_num+1}: {e}")
                continue

        logger.debug(f"Escaneo de patrones JS estáticos encontró {len(findings)} puntos potenciales en {match_count} coincidencias.")
        return findings

    async def analyze_webpack(self, page) -> Dict:
        """Analyzes webpack bundles (placeholder)."""
        return {}

    def analyze_source_maps(self, source_map_content: str) -> Dict:
        """Analyzes source maps (placeholder)."""
        return {}

    async def extract_and_analyze_js(self, page):
        """Extracts and analyzes JavaScript (placeholder)."""
        pass
