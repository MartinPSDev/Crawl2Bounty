import random
import asyncio
import re
from typing import Set, Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import jsbeautifier
from playwright.async_api import Page, async_playwright
from datetime import datetime
import time
import logging
import json
import string
import os
from queue import PriorityQueue  # Import PriorityQueue

# Import refactored/new components
from console_manager import ConsoleManager
from smart_detector import SmartDetector
from attack_engine import AttackEngine
from advanced_js_analyzer import AdvancedJSAnalyzer
from js_analyzer import JSAnalyzer # Static analyzer
from traffic_analyzer import TrafficAnalyzer
from report_generator import ReportGenerator # Needed to add findings
from payloads import SQLI_PAYLOADS, XSS_PAYLOADS, CMD_PAYLOADS, SSTI_PAYLOADS, PATH_TRAVERSAL_PAYLOADS, OOB_PAYLOADS

# Configurar logger
logger = logging.getLogger(__name__)

class SmartCrawler:
    def __init__(self, 
                 base_url: str,
                 max_depth: int = 2,
                 timeout: int = 30,
                 rate_limit: float = 1.0,
                 excluded_patterns: List[str] = None,
                 included_patterns: List[str] = None,
                 interactsh_url: Optional[str] = None,
                 report_generator: Optional[ReportGenerator] = None,
                 force: bool = False,
                 domain_dir: str = None):
        """Initialize the SmartCrawler with configuration parameters."""
        # Initialize console manager with verbose enabled
        self.console = ConsoleManager(verbose=True)
        
        # Store report generator
        self.report_generator = report_generator
        
        # Initialize SmartDetector with console manager
        self.detector = SmartDetector(console_manager=self.console)
        
        # Initialize AttackEngine with console manager and SmartDetector
        self.attack_engine = AttackEngine(console_manager=self.console, smart_detector=self.detector, interactsh_url=interactsh_url)
        
        # Set configuration parameters
        self.base_url = base_url
        self.max_depth = max_depth
        self.timeout = timeout * 1000  # Convert to milliseconds
        self.rate_limit_delay = rate_limit
        self.excluded_patterns = excluded_patterns or []
        self.included_patterns = included_patterns or []
        self.force = force
        self.domain_dir = domain_dir or 'reports'
        
        # Configuración de búsqueda
        self.searches_per_page = 3  # Número máximo de búsquedas por página
        self.max_search_depth = 2  # Profundidad máxima para búsquedas
        
        # Initialize crawl state
        self.crawl_queue = PriorityQueue()  # Cambiar a PriorityQueue
        self.visited_urls = set()
        self.used_terms = set()
        self.interaction_counts = {}
        
        # Initialize browser state
        self.browser = None
        self.context = None
        self.page = None
        
        self.max_queue_size = 1000  # Aumentar aún más, opcional
        
        self.console.print_info("SmartCrawler initialized.")

    async def start_crawl(self, start_url: str):
        """Start the crawling process."""
        try:
            playwright = await async_playwright().start()
            self.browser = await playwright.chromium.launch(headless=True, args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-features=IsolateOrigins,site-per-process',
                '--disable-site-isolation-trials',
                '--disable-web-security'
            ])
            
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )
            self.page = await self.context.new_page()
            
            await self.add_to_crawl_queue(start_url, 0)
            
            while not self.crawl_queue.empty():
                try:
                    depth, url = self.crawl_queue.get_nowait()
                    if url not in self.visited_urls and depth <= self.max_depth:
                        self.visited_urls.add(url)
                        await self._process_single_url(url, depth)
                    # No detener por tamaño, solo por profundidad
                    if self.crawl_queue.qsize() > self.max_queue_size:
                        self.console.print_warning(f"Queue size ({self.crawl_queue.qsize()}) exceeds {self.max_queue_size}, but continuing due to depth priority")
                except Exception as e:
                    self.console.print_error(f"Error processing queue item: {e}")
        
        except Exception as e:
            self.console.print_error(f"Error during crawl: {e}")
        finally:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if 'playwright' in locals():
                await playwright.stop()

    async def _crawl(self, page: Page, url: str, depth: int):
        """Recursive function to crawl the website."""
        if depth > self.max_depth:
            self.console.print_debug(f"Reached max depth of {self.max_depth} at {url}")
            return

        try:
            self.console.print_debug(f"Crawling {url} at depth {depth}")
            response = await page.goto(url, timeout=self.timeout // 1000) # Convert to milliseconds

            if response and response.status == 200:
                self.console.print_success(f"Successfully accessed {url} (Status: {response.status})")

                # Extract links from the page
                links = await page.locator("a").evaluate_all("links => links.map(link => link.href)")
                unique_links = list(set(links)) # Remove duplicates

                for link in unique_links:
                    # Basic check to avoid crawling external domains
                    if link.startswith(url) or url in link:
                        await self._crawl(page, link, depth + 1)
                    else:
                        self.console.print_debug(f"Skipping external link: {link}")
            else:
                self.console.print_warning(f"Failed to access {url} (Status: {response.status if response else 'Unknown'})")

        except Exception as e:
            self.console.print_error(f"Error while crawling {url}: {e}")

    async def _process_single_url(self, url: str, depth: int):
        """Process a single URL, including navigation, analysis, and interaction."""
        if self.report_generator:
            self.report_generator.log_realtime_event("URL_PROCESSING", f"Procesando URL: {url}", {
                "depth": depth,
                "timestamp": datetime.now().isoformat()
            })
        
        self.console.print_info(f"Processing URL: {url} (depth: {depth})")
        
        try:
            # Configurar opciones de navegación más robustas
            navigation_options = {
                "wait_until": "domcontentloaded",
                "timeout": self.timeout,
                "referer": self.base_url
            }
            
            # Intentar navegar a la URL
            try:
                await self.page.goto(url, **navigation_options)
            except Exception as e:
                self.console.print_warning(f"Error en primera navegación a {url}: {e}")
                navigation_options["wait_until"] = "load"
                await self.page.goto(url, **navigation_options)
            
            # Esperar a que la página se cargue completamente
            try:
                await self.page.wait_for_load_state("load", timeout=self.timeout)
            except Exception as e:
                self.console.print_warning(f"Error esperando carga completa de {url}: {e}")
            
            # Verificar si hay CAPTCHA
            page_content = await self.page.content()
            if await self._detect_captcha(page_content):
                self.console.print_warning(f"CAPTCHA detectado en {url}")
                if self.report_generator:
                    self.report_generator.add_findings("access_control", [{
                        "type": "captcha_detected",
                        "severity": "INFO",
                        "url": url,
                        "details": "Se detectó un CAPTCHA en la página"
                    }])
                
                # Intentar manejar el CAPTCHA
                if await self._handle_captcha(url):
                    self.console.print_success(f"CAPTCHA superado en {url}")
                else:
                    self.console.print_error(f"No se pudo superar el CAPTCHA en {url}")
                    return
            
            # Verificar si la página está bloqueada
            if any(blocked_text in page_content.lower() for blocked_text in ["access denied", "bot detected", "security check"]):
                self.console.print_warning(f"Página {url} parece estar bloqueada")
                if self.report_generator:
                    self.report_generator.add_findings("access_control", [{
                        "type": "page_blocked",
                        "severity": "INFO",
                        "url": url,
                        "details": "La página parece estar bloqueada"
                    }])
                return
            
            # Static JS analysis
            self.console.print_debug("Performing static JS analysis...")
            try:
                js_findings = await self.detector.analyze_js(page_content)
                if self.report_generator and js_findings:
                    self.report_generator.add_findings("javascript_analysis", js_findings)
                    self.console.print_debug(f"JS findings added to report: {len(js_findings)}")
            except Exception as e:
                self.console.print_error(f"Error en análisis JS: {e}")
            
            # Basic vulnerability checks
            self.console.print_debug("Performing basic vulnerability checks...")
            try:
                parsed_url = urlparse(url)
                params = {k: v[0] for k, v in parse_qs(parsed_url.query).items() if v}
                
                # Llamar a test_vulnerability siempre, pasando params=None si no hay parámetros
                vuln_findings = await self.attack_engine.test_vulnerability(url, "GET", params=params if params else None)
                if self.report_generator and vuln_findings:
                    self.report_generator.add_findings("vulnerability_scan", vuln_findings)
                    self.console.print_debug(f"Vulnerability findings added to report: {len(vuln_findings)}")
            except Exception as e:
                self.console.print_error(f"Error en verificación de vulnerabilidades: {e}")
            
            # Dynamic analysis
            self.console.print_debug("Performing dynamic analysis...")
            try:
                if self.page:
                    dynamic_findings = await self.detector.analyze_dynamic_content(self.page)
                    if self.report_generator and dynamic_findings:
                        self.report_generator.add_findings("dynamic_analysis", dynamic_findings)
                        self.console.print_debug(f"Dynamic findings added to report: {len(dynamic_findings)}")
            except Exception as e:
                self.console.print_error(f"Error en análisis dinámico: {e}")
            
            # Handle interactive elements
            self.console.print_debug("Handling interactive elements...")
            try:
                findings = await self.handle_interactive_elements(self.page, url, depth)
                if self.report_generator and findings:
                    self.report_generator.add_findings("interactive_elements", findings)
                    self.console.print_debug(f"Interactive findings added to report: {len(findings)}")
            except Exception as e:
                self.console.print_error(f"Error manejando elementos interactivos: {e}")
            
            # Handle forms
            self.console.print_debug("Handling forms...")
            try:
                if self.page:
                    forms = await self.page.query_selector_all('form')
                    for form in forms:
                        form_findings = await self.handle_form_submission(self.page, form, url, depth)
                        if self.report_generator and form_findings:
                            self.report_generator.add_findings("form_analysis", form_findings)
                            self.console.print_debug(f"Form findings added to report: {len(form_findings)}")
            except Exception as e:
                self.console.print_error(f"Error manejando formularios: {e}")
            
            # Handle search forms
            self.console.print_debug("Handling search forms...")
            try:
                if self.page:
                    search_findings = await self.handle_search_forms(self.page, url, depth)
                    if self.report_generator and search_findings:
                        self.report_generator.add_findings("search_analysis", search_findings)
                        self.console.print_debug(f"Search findings added to report: {len(search_findings)}")
            except Exception as e:
                self.console.print_error(f"Error manejando formularios de búsqueda: {e}")
            
            # Gather new links
            self.console.print_debug("Gathering new links...")
            try:
                if self.page:
                    # Recolectar enlaces <a>
                    links = await self.page.query_selector_all('a[href]')
                    new_urls = []
                    for link in links:
                        href = await link.get_attribute('href')
                        if href:
                            full_url = urljoin(url, href)
                            if self.is_in_scope(full_url):
                                new_urls.append(full_url)
                                await self.add_to_crawl_queue(full_url, depth + 1)

                    # Recolectar scripts <script src>
                    scripts = await self.page.query_selector_all('script[src]')
                    for script in scripts:
                        src = await script.get_attribute('src')
                        if src:
                            full_script_url = urljoin(url, src)
                            if self.is_in_scope(full_script_url) and full_script_url.endswith('.js'):
                                self.console.print_debug(f"Found JavaScript file: {full_script_url}")
                                new_urls.append(full_script_url)
                                await self.add_to_crawl_queue(full_script_url, depth + 1)
                                # Opcional: Analizar el contenido del archivo .js
                                await self._analyze_js_file(full_script_url)

                    if self.report_generator:
                        self.report_generator.log_realtime_event("LINKS_FOUND", f"Enlaces encontrados en {url}", {
                            "total_links": len(new_urls),
                            "new_urls": new_urls[:5]
                        })
            except Exception as e:
                self.console.print_error(f"Error recolectando enlaces: {e}")
            
            # Wait for rate limiting
            await asyncio.sleep(self.rate_limit_delay)
            
        except Exception as e:
            error_msg = f"Error processing {url}: {str(e)}"
            self.console.print_warning(error_msg)
            if self.report_generator:
                self.report_generator.log_realtime_event("ERROR", error_msg, {
                    "url": url,
                    "error_type": type(e).__name__
                })

    async def handle_form_submission(self, page: Page, base_url: str, form_data: dict, depth: int):
        """Fills form, triggers vuln tests, optionally submits via Playwright."""
        form_selector = form_data.get('selector'); inputs = form_data.get('inputs', []); submit_selector = form_data.get('submit_selector')
        action_raw = form_data.get('action', '')
        # Resolve action URL relative to the *page's current URL*
        action_url = urljoin(page.url, action_raw) if action_raw else page.url
        method = form_data.get('method', 'POST').upper()

        self.console.print_debug(f"Handling form: {form_selector} -> {method} {action_url}")
        if not inputs: return

        test_data_post = {}; params_for_get = {}
        visible_inputs_filled = False

        # --- Fill form & prepare data for AttackEngine ---
        for input_info in inputs:
            input_selector = input_info.get('selector'); input_name = input_info.get('name')
            input_type = input_info.get('type', 'text')
            if not input_selector or not input_name: continue

            # Use SmartDetector's payload generation for better test values
            value = self.detector.generate_test_value(input_name, input_type)
            if not value: continue

            # Try to fill via Playwright ONLY if input likely exists and is interactable
            # This makes the page state ready for a potential JS-driven submission later
            try:
                 input_element = await page.query_selector(input_selector)
                 if input_element and await input_element.is_visible():
                     if input_type in ['checkbox', 'radio']: await input_element.check(timeout=2000)
                     elif input_type != 'file': await input_element.fill(value, timeout=2000)
                     visible_inputs_filled = True # Flag that we interacted via Playwright
            except Exception as e: self.console.print_warning(f"Could not fill input '{input_name}' ({input_selector}): {e}")

            # Store value for Attack Engine regardless of successful fill via Playwright
            if method == "GET": params_for_get[input_name] = value
            else: test_data_post[input_name] = value

        # --- Trigger Attack Engine Tests Directly ---
        self.console.print_debug(f"Triggering AttackEngine for form action: {method} {action_url}")
        if method == "GET": await self.attack_engine.test_vulnerability(action_url, method, params=params_for_get)
        else: await self.attack_engine.test_vulnerability(action_url, method, data=test_data_post) # Pass dict as data

        # --- Optional: Playwright Submission (if submit button found AND inputs filled) ---
        if submit_selector and visible_inputs_filled: # Only submit if we actually filled something via PW
             self.console.print_debug(f"Attempting Playwright submission for form {form_selector} via {submit_selector}")
             try:
                 submit_button = await page.query_selector(submit_selector)
                 if submit_button and await submit_button.is_visible():
                      async with page.expect_navigation(wait_until="domcontentloaded", timeout=self.timeout // 2):
                           await submit_button.click(timeout=5000)
                      await page.wait_for_load_state("load", timeout=self.timeout // 2)
                      self.console.print_info(f"Form submitted (PW), new URL: {page.url}")
                      await self.add_to_crawl_queue(page.url, depth + 1)
             except Exception as e: self.console.print_warning(f"Error submitting form (PW) via {submit_selector}: {e}")

    async def handle_search_forms(self, page: Page, base_url: str, depth: int):
        """Finds search forms, submits a term, tests params, adds result page."""
        self.console.print_debug("Handling search forms...")
        search_selectors = [
            'input[type="search"]',
            'input[type="text"][name*="q"]', 'input[type="text"][name*="query"]', 'input[type="text"][name*="search"]',
            'input[type="text"][id*="q"]', 'input[type="text"][id*="query"]', 'input[type="text"][id*="search"]',
            'input[type="text"][placeholder*="search" i]', 'input[type="text"][aria-label*="search" i]',
        ]
        searches_attempted = 0

        for selector in search_selectors:
            if searches_attempted >= self.searches_per_page: break
            try:
                search_inputs = await page.query_selector_all(selector)
                for input_element in search_inputs:
                     if searches_attempted >= self.searches_per_page: break
                     if await input_element.is_visible():
                         search_term = await self.get_next_search_term()
                         if not search_term: return # No more terms

                         input_selector_str = f"{selector}[name='{await input_element.get_attribute('name') or await input_element.get_attribute('id')}']" # Approximate selector for log
                         submit_button = None
                         form_element = await input_element.query_selector('xpath=ancestor::form')
                         if form_element: submit_button = await form_element.query_selector('button[type="submit"], input[type="submit"]')
                         if not submit_button: # Fallback search near input
                              parent = await input_element.query_selector('xpath=..'); btn_sel = 'button, input[type=button], [role=button]'
                              if parent: submit_button = await parent.query_selector(btn_sel)
                              if not submit_button: # Try sibling
                                   next_sib = await input_element.query_selector('xpath=following-sibling::*[1]')
                                   if next_sib and await next_sib.matches(btn_sel): submit_button = next_sib

                         if submit_button and await submit_button.is_visible():
                              self.console.print_info(f"Performing search: '{search_term}'")
                              await input_element.fill(search_term, timeout=3000)
                              await asyncio.sleep(0.2)

                              async with page.expect_navigation(wait_until="domcontentloaded", timeout=self.timeout // 2):
                                   await submit_button.click(timeout=5000)
                              await page.wait_for_load_state("load", timeout=self.timeout // 2)
                              searches_attempted += 1
                              self.used_terms.add(search_term)
                              search_result_url = page.url
                              self.console.print_info(f"Search submitted, results URL: {search_result_url}")

                              # Test vulnerability on search result parameters
                              parsed_search_url = urlparse(search_result_url)
                              search_params = {k: v[0] for k, v in parse_qs(parsed_search_url.query).items() if v}
                              if search_params:
                                   await self.attack_engine.test_vulnerability(search_result_url, "GET", params=search_params)

                              # Add results page to crawl queue
                              await self.add_to_crawl_queue(search_result_url, depth + 1)
                              break # Found and used a search input, move to next selector type

            except Exception as e: self.console.print_warning(f"Error handling search with selector '{selector}': {e}")

    async def handle_interactive_elements(self, page: Page, base_url: str, depth: int):
        self.console.print_debug("Handling interactive elements...")
        
        # Contador de interacciones por URL
        self.interaction_counts.setdefault(base_url, 0)
        if self.interaction_counts[base_url] >= 5:  # Límite de 5 interacciones por URL
            self.console.print_debug(f"Límite de interacciones alcanzado para {base_url}")
            return
        
        clickable_selectors = [
            'button:not([disabled])',
            'input[type="button"]:not([disabled])',
            'input[type="submit"]:not([disabled])',
            '[role="button"]:not([disabled])',
            'a[href]:not([href^="javascript:"])',
            '[onclick]',
            '[data-action]',
            '[data-toggle]',
            '[data-target]'
        ]
        
        findings = []
        for selector in clickable_selectors:
            try:
                elements = await page.query_selector_all(selector)
                for element in elements:
                    if await element.is_visible() and self.interaction_counts[base_url] < 5:
                        element_type = await element.evaluate('el => el.tagName.toLowerCase()')
                        element_id = await element.get_attribute('id') or ''
                        element_text = await element.inner_text() or ''
                        self.console.print_debug(f"Interacting with {element_type} {element_id} '{element_text}'")
                        
                        # Llamada directa a test_vulnerability antes de hacer clic
                        href = await element.get_attribute('href')
                        if href:
                            full_url = urljoin(base_url, href)
                            if self.is_in_scope(full_url):
                                await self.attack_engine.test_vulnerability(full_url, "GET")  # Forzar prueba de vulnerabilidad
                                await self.add_to_crawl_queue(full_url, depth + 1)
                        
                        try:
                            async with page.expect_navigation(wait_until="domcontentloaded", timeout=5000):
                                await element.click(timeout=5000)
                            await page.wait_for_load_state("load", timeout=self.timeout // 2)
                            current_url = page.url
                            if self.is_in_scope(current_url):
                                await self.attack_engine.test_vulnerability(current_url, "GET")  # Forzar prueba de vulnerabilidad
                                await self.add_to_crawl_queue(current_url, depth + 1)
                            self.interaction_counts[base_url] += 1
                        except Exception as e:
                            self.console.print_warning(f"Error clicking {element_type}: {e}")
            except Exception as e:
                self.console.print_warning(f"Error handling selector '{selector}': {e}")
        
        return findings

    async def add_to_crawl_queue(self, url: str, depth: int):
        """Add a URL to the crawl queue if it's in scope and not already visited."""
        normalized_url = self._normalize_url(url)
        if normalized_url in self.visited_urls or not self.is_in_scope(normalized_url):
            return
        # Añadir con prioridad basada en depth (menor depth = mayor prioridad)
        self.crawl_queue.put_nowait((depth, normalized_url))
        self.console.print_debug(f"Added URL to queue: {normalized_url} (depth: {depth})")
        
        # Analyze URL with SmartDetector
        try:
            await self.detector.analyze_url(normalized_url)
        except Exception as e:
            self.console.print_warning(f"Error analyzing URL {normalized_url}: {e}")

    def is_in_scope(self, url: str) -> bool:
        """Verifica si la URL está dentro del alcance definido."""
        try:
            target_domain = urlparse(self.base_url).netloc.lower()
            parsed_url = urlparse(url)
            url_domain = parsed_url.netloc.lower()
            
            # Permitir archivos .js del dominio objetivo o subdominios
            if not url_domain.endswith(target_domain) and target_domain not in url_domain:
                self.console.print_debug(f"URL fuera de scope excluida: {url}")
                return False
            
            # Excluir patrones si existen
            if self.excluded_patterns:
                for pattern in self.excluded_patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        self.console.print_debug(f"URL coincidente con patrón de exclusión: {url}")
                        return False
            
            # Incluir explícitamente archivos .js
            if url.endswith('.js'):
                self.console.print_debug(f"URL .js incluida: {url}")
                return True
            
            return True
        except Exception as e:
            self.console.print_error(f"Error verificando scope de URL {url}: {e}")
            return False

    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            normalized = parsed._replace(fragment='').geturl()  # Mantén query y params
            if normalized.endswith('/'):
                normalized = normalized[:-1]
            return normalized
        except Exception as e:
            self.console.print_warning(f"Error normalizing URL {url}: {e}")
            return url

    async def get_next_search_term(self) -> Optional[str]:
        """Get the next search term from the SmartDetector."""
        try:
            # Get next term from detector
            term = await self.detector.get_next_search_term()
            
            # Skip if already used
            if term in self.used_terms:
                return None
                
            # Mark as used
            self.used_terms.add(term)
            
            return term
            
        except Exception as e:
            self.console.print_warning(f"Error getting next search term: {e}")
            return None

    async def save_screenshot(self, url: str):
        """Guarda una captura de pantalla de la página."""
        try:
            if not self.page:
                return
                
            
            safe_filename = re.sub(r'[^a-zA-Z0-9]', '_', urlparse(url).path)
            if not safe_filename:
                safe_filename = 'index'
            safe_filename = f"{safe_filename}.png"
            
            
            screenshot_path = os.path.join(self.domain_dir, 'screenshots', safe_filename)
            await self.page.screenshot(path=screenshot_path, full_page=True)
            self.console.print_debug(f"Captura de pantalla guardada: {screenshot_path}")
            
        except Exception as e:
            self.console.print_error(f"Error guardando captura de pantalla: {e}")

    async def save_response(self, url: str):
        """Guarda la respuesta HTTP de la página."""
        try:
            if not self.page:
                return
                
            # Crear nombre de archivo seguro
            safe_filename = re.sub(r'[^a-zA-Z0-9]', '_', urlparse(url).path)
            if not safe_filename:
                safe_filename = 'index'
            safe_filename = f"{safe_filename}.html"
            
            # Guardar en el directorio del dominio
            response_path = os.path.join(self.domain_dir, 'responses', safe_filename)
            content = await self.page.content()
            with open(response_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self.console.print_debug(f"Respuesta guardada: {response_path}")
            
        except Exception as e:
            self.console.print_error(f"Error guardando respuesta: {e}")

    async def _detect_captcha(self, page_content: str) -> dict:
        """Detects if there is a CAPTCHA on the page and returns information about its type."""
        captcha_info = {
            "detected": False,
            "type": None,
            "version": None,
            "details": {}
        }
        
        # More specific detection patterns
        captcha_patterns = {
            "recaptcha": {
                "patterns": [
                    r'class="[^"]*g-recaptcha[^"]*"',
                    r'src="[^"]*recaptcha/api\.js',
                    r'data-sitekey="[^"]*"',
                    r'grecaptcha\.render'
                ],
                "versions": {
                    "v2": [r'data-size="(?:normal|compact)"', r'g-recaptcha-response'],
                    "v3": [r'grecaptcha\.execute', r'action=', r'"recaptcha_score"'],
                    "invisible": [r'data-size="invisible"']
                }
            },
            "hcaptcha": {
                "patterns": [
                    r'class="[^"]*h-captcha[^"]*"',
                    r'src="[^"]*hcaptcha\.com/1/api\.js',
                    r'data-sitekey="[^"]*"',
                    r'hcaptcha\.render'
                ]
            },
            "cloudflare": {
                "patterns": [
                    r'cf-captcha-container',
                    r'cf_captcha_kind',
                    r'cloudflare-challenge',
                    r'turnstile-callback',
                    r'cf-turnstile',
                    r'__cf_chl_captcha'
                ]
            },
            "custom": {
                "patterns": [
                    r'captcha[\s_-]*image',
                    r'captcha[\s_-]*input',
                    r'verification[\s_-]*code',
                    r'security[\s_-]*check',
                    r'human[\s_-]*verification'
                ]
            }
        }
        
        # Detect CAPTCHA type
        for captcha_type, type_info in captcha_patterns.items():
            for pattern in type_info["patterns"]:
                if re.search(pattern, page_content, re.IGNORECASE):
                    captcha_info["detected"] = True
                    captcha_info["type"] = captcha_type
                    
                    # Detect specific version if available
                    if "versions" in type_info:
                        for version, version_patterns in type_info["versions"].items():
                            for ver_pattern in version_patterns:
                                if re.search(ver_pattern, page_content, re.IGNORECASE):
                                    captcha_info["version"] = version
                                    break
                            if captcha_info["version"]:
                                break
                    
                    # Extract sitekey for reCAPTCHA or hCaptcha
                    if captcha_type in ["recaptcha", "hcaptcha"]:
                        sitekey_match = re.search(r'data-sitekey="([^"]*)"', page_content)
                        if sitekey_match:
                            captcha_info["details"]["sitekey"] = sitekey_match.group(1)
                    
                    break
            if captcha_info["detected"]:
                break
        
        # Log result
        if captcha_info["detected"]:
            self.console.print_warning(f"CAPTCHA detected: {captcha_info['type']} {captcha_info['version'] or ''}")
        
        return captcha_info

    async def _handle_captcha(self, url: str) -> bool:
        """Attempts to handle CAPTCHA using multiple strategies."""
        try:
            # Get current content for analysis
            page_content = await self.page.content()
            captcha_info = await self._detect_captcha(page_content)
            
            if not captcha_info["detected"]:
                return True  # No CAPTCHA to handle
            
            self.console.print_info(f"Attempting to handle CAPTCHA on {url}")
            
            # Strategy 1: CAPTCHA evasion techniques
            if await self._try_captcha_evasion(url, captcha_info):
                return True
            
            # Strategy 2: Simulate human behavior
            if await self._try_human_simulation(url, captcha_info):
                return True
            
            # Strategy 3: Use CAPTCHA solving services
            if await self._try_captcha_service(url, captcha_info):
                return True
            
            # Strategy 4: Retry with proxies and new sessions
            if await self._try_session_rotation(url, captcha_info):
                return True
            
            # Strategy 5: Look for alternative paths
            if await self._try_alternative_paths(url):
                return True
            
            # If all strategies failed, report the failure
            self.console.print_error(f"Could not bypass CAPTCHA on {url}")
            
            if self.report_generator:
                self.report_generator.add_findings("access_control", [{
                    "type": "captcha_blocking",
                    "severity": "MEDIUM",
                    "url": url,
                    "details": f"CAPTCHA detected ({captcha_info['type']} {captcha_info['version'] or ''}) that could not be bypassed automatically"
                }])
            
            return False
            
        except Exception as e:
            self.console.print_error(f"Error handling CAPTCHA: {str(e)}")
            return False

    async def _try_captcha_evasion(self, url: str, captcha_info: dict) -> bool:
        """Attempts evasion techniques for different CAPTCHA types."""
        try:
            # Set of headers that may help evade detection
            evasion_headers = {
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "max-age=0",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                "Referer": self.base_url
            }
            
            # 1. Set headers and cookies to appear as a real browser
            await self.context.clear_cookies()
            await self.context.add_cookies([{
                "name": "cf_clearance",  # Cookie often used by CloudFlare
                "value": "".join(random.choices(string.ascii_letters + string.digits, k=32)),
                "domain": urlparse(url).netloc,
                "path": "/"
            }])
            await self.context.set_extra_http_headers(evasion_headers)
            
            # 2. Set browser properties to evade detection
            await self.page.add_init_script("""
                // Hide Playwright/Automation detection
                Object.defineProperty(navigator, 'webdriver', { get: () => false });
                
                // Hide features that reveal automation
                if (window.navigator.permissions) {
                    window.navigator.permissions.query = (function (originalQuery) {
                        return function (permissionDesc) {
                            if (permissionDesc.name === 'notifications') {
                                return Promise.resolve({ state: "prompt", onchange: null });
                            }
                            return originalQuery.apply(this, arguments);
                        };
                    })(window.navigator.permissions.query);
                }
                
                // Create random canvas fingerprint
                const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                HTMLCanvasElement.prototype.toDataURL = function(type) {
                    if (this.width === 16 && this.height === 16) {
                        return originalToDataURL.apply(this, arguments);
                    }
                    return originalToDataURL.apply(this, arguments);
                };
                
                // Fake plugins
                Object.defineProperty(navigator, 'plugins', {
                    get: () => {
                        const plugins = [];
                        for (let i = 0; i < 5; i++) {
                            plugins.push({
                                name: `Plugin ${i}`,
                                description: `Plugin Description ${i}`,
                                filename: `plugin${i}.dll`,
                                length: 1,
                                item: function() { return this; }
                            });
                        }
                        return plugins;
                    }
                });
            """)
            
            # 3. Navigate to page with more human-like patterns
            if urlparse(self.page.url).netloc == urlparse(url).netloc:
                # Perform some human-like actions if already on the same domain
                await self._simulate_human_behavior()
            
            # Random scrolling on the page
            await self.page.evaluate("""
                () => {
                    const scrollMax = Math.max(
                        document.body.scrollHeight,
                        document.documentElement.scrollHeight
                    );
                    const randomScrolls = Math.floor(Math.random() * 5) + 2;
                    
                    for (let i = 0; i < randomScrolls; i++) {
                        const targetScroll = Math.floor(Math.random() * scrollMax);
                        window.scrollTo(0, targetScroll);
                    }
                }
            """)
            
            # Wait random time like a human
            await asyncio.sleep(random.uniform(2, 4))
            
            # 4. Navigate to URL again with new settings
            navigation_options = {
                "wait_until": "domcontentloaded",
                "timeout": self.timeout,
                "referer": self.base_url
            }
            await self.page.goto(url, **navigation_options)
            await asyncio.sleep(random.uniform(1, 3))
            
            # 5. Check if we evaded the CAPTCHA
            page_content = await self.page.content()
            new_captcha_info = await self._detect_captcha(page_content)
            
            if not new_captcha_info["detected"]:
                self.console.print_success(f"CAPTCHA successfully evaded using evasion techniques")
                return True
            
            # 6. Try specific techniques based on CAPTCHA type
            captcha_type = captcha_info["type"]
            if captcha_type == "cloudflare":
                # For CloudFlare, sometimes waiting is enough
                self.console.print_info("CloudFlare detected, waiting for timeout...")
                await asyncio.sleep(random.uniform(5, 8))
                await self.page.reload()
                page_content = await self.page.content()
                if not await self._detect_captcha(page_content)["detected"]:
                    self.console.print_success("CloudFlare CAPTCHA bypassed by timeout")
                    return True
            
            return False
            
        except Exception as e:
            self.console.print_warning(f"Error in CAPTCHA evasion: {str(e)}")
            return False

    async def _try_human_simulation(self, url: str, captcha_info: dict) -> bool:
        """Attempts to simulate human behavior to bypass CAPTCHA."""
        try:
            # If it's a simple image CAPTCHA, we can try to solve it with automatic vision
            if captcha_info["type"] == "custom":
                # Look for CAPTCHA images
                captcha_img = await self.page.query_selector('img[src*="captcha"], img[alt*="captcha" i]')
                if captcha_img:
                    self.console.print_info("Attempting to solve simple image CAPTCHA...")
                    
                    # Download the image
                    img_src = await captcha_img.get_attribute('src')
                    img_url = urljoin(self.page.url, img_src)
                    
                    # Here we could integrate an OCR or AI service to solve the CAPTCHA
                    # For simplicity, this is a placeholder
                    captcha_text = "ABC123"  # You should replace this with real OCR
                    
                    # Look for the CAPTCHA input
                    captcha_input = await self.page.query_selector('input[name*="captcha" i], input[id*="captcha" i], input[placeholder*="captcha" i], input[placeholder*="code" i]')
                    if captcha_input:
                        await captcha_input.fill(captcha_text)
                        await asyncio.sleep(random.uniform(0.5, 1.2))
                        
                        # Look for the submit button
                        submit_button = await self.page.query_selector('button[type="submit"], input[type="submit"], button:has-text("Submit"), button:has-text("Verify")')
                        if submit_button:
                            await submit_button.click()
                            await self.page.wait_for_load_state("domcontentloaded")
                            
                            # Check if it was solved
                            page_content = await self.page.content()
                            if not await self._detect_captcha(page_content)["detected"]:
                                self.console.print_success("Image CAPTCHA successfully solved")
                                return True
            
            # For reCAPTCHA, try to simulate click and drag
            elif captcha_info["type"] == "recaptcha":
                captcha_frame = await self.page.query_selector('iframe[src*="recaptcha"]')
                if captcha_frame:
                    self.console.print_info("reCAPTCHA detected, attempting human simulation...")
                    
                    # Switch to reCAPTCHA frame
                    frame = await captcha_frame.content_frame()
                    if frame:
                        # Click the checkbox
                        checkbox = await frame.query_selector('.recaptcha-checkbox-border')
                        if checkbox:
                            # Simulate mouse movement
                            box = await checkbox.bounding_box()
                            if box:
                                # Realistic mouse movement
                                start_x, start_y = random.randint(50, 500), random.randint(50, 500)
                                steps = random.randint(10, 20)
                                
                                for i in range(steps):
                                    progress = i / steps
                                    x = start_x + (box['x'] + box['width']/2 - start_x) * progress
                                    y = start_y + (box['y'] + box['height']/2 - start_y) * progress
                                    await self.page.mouse.move(x, y)
                                    await asyncio.sleep(random.uniform(0.01, 0.05))
                                
                                # Click the checkbox
                                await checkbox.click({
                                    'delay': random.randint(30, 150)
                                })
                                
                                # Wait to see if CAPTCHA is automatically solved
                                await asyncio.sleep(3)
                                
                                # Return to main frame
                                await self.page.frame_locator('iframe[src*="recaptcha"]').locator('.recaptcha-checkbox-checkmark').click()
                                
                                # Wait for page update
                                await asyncio.sleep(2)
                                
                                # Check if it was solved
                                page_content = await self.page.content()
                                if not await self._detect_captcha(page_content)["detected"]:
                                    self.console.print_success("reCAPTCHA solved through simulation")
                                    return True
            
            return False
            
        except Exception as e:
            self.console.print_warning(f"Error in human simulation for CAPTCHA: {str(e)}")
            return False

    async def _try_captcha_service(self, url: str, captcha_info: dict) -> bool:
        """Attempts to use external services to solve CAPTCHAs."""
        try:
            # Check if we have integration with any solving service
            if not hasattr(self, 'captcha_service') or not self.captcha_service:
                self.console.print_warning("No CAPTCHA solving service configured")
                return False
            
            captcha_type = captcha_info["type"]
            
            # Placeholder for integration with services like 2captcha, Anti-Captcha, etc.
            # In a real implementation, you would connect with the service's API
            
            self.console.print_info(f"Connecting with solving service for {captcha_type}...")
            
            if captcha_type == "recaptcha":
                if "sitekey" in captcha_info["details"]:
                    sitekey = captcha_info["details"]["sitekey"]
                    # Placeholder - In real implementation:
                    # result = await self.captcha_service.solve_recaptcha(url, sitekey)
                    result = "03AGdBq24PBgMT-..."  # Example token
                    
                    # Insert token into page
                    await self.page.evaluate(f"""
                        document.getElementById('g-recaptcha-response').innerHTML = '{result}';
                        if (typeof ___grecaptcha_cfg !== 'undefined') {{
                            Object.keys(___grecaptcha_cfg.clients).forEach(function(key) {{
                                const client = ___grecaptcha_cfg.clients[key];
                                Object.keys(client).forEach(function(key) {{
                                    if (typeof client[key].callback === 'function') {{
                                        client[key].callback('{result}');
                                    }}
                                }});
                            }});
                        }}
                    """)
                    
                    # Look for and click submit button
                    submit_button = await self.page.query_selector('button[type="submit"], input[type="submit"], button:has-text("Submit"), button:has-text("Verify")')
                    if submit_button:
                        await submit_button.click()
                        await self.page.wait_for_load_state("domcontentloaded")
                    
                    # Check if solved
                    await asyncio.sleep(2)
                    page_content = await self.page.content()
                    if not await self._detect_captcha(page_content)["detected"]:
                        self.console.print_success("reCAPTCHA solved through external service")
                        return True
            
            elif captcha_type == "hcaptcha":
                if "sitekey" in captcha_info["details"]:
                    sitekey = captcha_info["details"]["sitekey"]
                    # Placeholder for real integration
                    # result = await self.captcha_service.solve_hcaptcha(url, sitekey)
                    result = "P0_eyJ0eXAiO..."  # Example token
                    
                    # Insert token
                    await self.page.evaluate(f"""
                        document.querySelector('[name="h-captcha-response"]').value = '{result}';
                        if (typeof hcaptcha !== 'undefined') {{
                            hcaptcha.execute();
                        }}
                    """)
                    
                    # Look for and click submit button
                    submit_button = await self.page.query_selector('button[type="submit"], input[type="submit"]')
                    if submit_button:
                        await submit_button.click()
                        await self.page.wait_for_load_state("domcontentloaded")
                    
                    # Check
                    await asyncio.sleep(2)
                    page_content = await self.page.content()
                    if not await self._detect_captcha(page_content)["detected"]:
                        self.console.print_success("hCaptcha solved through external service")
                        return True
            
            return False
            
        except Exception as e:
            self.console.print_warning(f"Error in CAPTCHA solving service: {str(e)}")
            return False

    async def _try_session_rotation(self, url: str, captcha_info: dict) -> bool:
        """Attempts to rotate sessions, IPs and configurations to evade CAPTCHA."""
        try:
            self.console.print_info("Attempting session/IP rotation to evade CAPTCHA...")
            
            # List of more realistic user agents
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
            ]
            
            # Proxies (you should replace these with your own real proxies)
            proxies = [
                None,  # No proxy first
                'http://user:pass@proxy1.example.com:8080',
                'http://user:pass@proxy2.example.com:8080',
                'socks5://user:pass@proxy3.example.com:1080'
            ]
            
            # Browser configurations
            browser_configs = [
                {"viewport": {"width": 1920, "height": 1080}, "locale": "en-US", "timezone": "America/New_York"},
                {"viewport": {"width": 1366, "height": 768}, "locale": "en-GB", "timezone": "Europe/London"},
                {"viewport": {"width": 1536, "height": 864}, "locale": "es-ES", "timezone": "Europe/Madrid"},
                {"viewport": {"width": 1440, "height": 900}, "locale": "fr-FR", "timezone": "Europe/Paris"}
            ]
            
            # Try different combinations
            for user_agent in user_agents:
                for proxy in proxies:
                    for config in browser_configs:
                        self.console.print_debug(f"Trying UA: {user_agent[:20]}... Proxy: {'Yes' if proxy else 'No'}")
                        
                        # Close previous context and create new one
                        if self.context:
                            await self.context.close()
                        
                        # Configure context with new parameters
                        browser_args = [
                            '--disable-blink-features=AutomationControlled',
                            '--disable-features=IsolateOrigins,site-per-process',
                            '--disable-site-isolation-trials'
                        ]
                        
                        if proxy:
                            browser_args.append(f'--proxy-server={proxy}')
                        
                        self.context = await self.browser.new_context(
                            viewport=config["viewport"],
                            user_agent=user_agent,
                            locale=config["locale"],
                            timezone_id=config["timezone"],
                            geolocation={"latitude": random.uniform(-90, 90), "longitude": random.uniform(-180, 180)},
                            permissions=['geolocation']
                        )
                        
                        # Configure detection evasion
                        await self.context.add_init_script("""
                            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                            Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
                        """)
                        
                        # Create new page
                        self.page = await self.context.new_page()
                        
                        # Navigate with new parameters
                        try:
                            await self.page.goto(url, wait_until="domcontentloaded", timeout=self.timeout)
                            await asyncio.sleep(random.uniform(2, 4))
                            
                            # Check if we evaded the CAPTCHA
                            page_content = await self.page.content()
                            if not await self._detect_captcha(page_content)["detected"]:
                                self.console.print_success(f"CAPTCHA evaded with session/IP rotation")
                                return True
                        except Exception as e:
                            self.console.print_warning(f"Error in attempt with configuration: {str(e)}")
                            continue
            
            return False
            
        except Exception as e:
            self.console.print_warning(f"Error in session rotation: {str(e)}")
            return False

    async def _try_alternative_paths(self, url: str) -> bool:
        """Attempts to find alternative paths to access content."""
        try:
            self.console.print_info("Looking for alternative paths to avoid CAPTCHA...")
            
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc
            path = parsed_url.path
            
            # Create alternative URLs
            alternative_urls = []
            
            # 1. Try alternative subdomains
            if base_domain.startswith('www.'):
                # Remove www.
                alt_domain = base_domain[4:]
                alternative_urls.append(f"{parsed_url.scheme}://{alt_domain}{path}")
            else:
                # Add www.
                alternative_urls.append(f"{parsed_url.scheme}://www.{base_domain}{path}")
            
            # 2. Try alternative protocols
            if parsed_url.scheme == 'https':
                alternative_urls.append(f"http://{base_domain}{path}")
            else:
                alternative_urls.append(f"https://{base_domain}{path}")
            
            # 3. Try API or alternative endpoints
            api_paths = ['/api', '/graphql', '/rest', '/v1', '/v2']
            for api_path in api_paths:
                if path.startswith('/'):
                    new_path = f"{api_path}{path}"
                else:
                    new_path = f"{api_path}/{path}"
                alternative_urls.append(f"{parsed_url.scheme}://{base_domain}{new_path}")
            
            # 4. Try mobile apps or specific endpoints
            mobile_indicators = ['m.', 'mobile.', 'app.']
            for indicator in mobile_indicators:
                if not base_domain.startswith(indicator):
                    mobile_domain = f"{indicator}{base_domain.split('.')[-2]}.{base_domain.split('.')[-1]}"
                    alternative_urls.append(f"{parsed_url.scheme}://{mobile_domain}{path}")
            
            # 5. Try alternative formats (JSON, XML, etc.)
            formats = ['.json', '.xml', '.txt']
            for fmt in formats:
                if not path.endswith(fmt):
                    alternative_urls.append(f"{parsed_url.scheme}://{base_domain}{path}{fmt}")
            
            # Try alternative URLs
            for alt_url in alternative_urls:
                self.console.print_debug(f"Trying alternative path: {alt_url}")
                
                try:
                    # Navigate to alternative URL
                    await self.page.goto(alt_url, wait_until="domcontentloaded", timeout=self.timeout // 2)
                    await asyncio.sleep(1)
                    
                    # Check for CAPTCHA
                    page_content = await self.page.content()
                    if not await self._detect_captcha(page_content)["detected"]:
                        # Check if content is useful (not a 404, etc.)
                        if not await self._is_error_page(page_content):
                            self.console.print_success(f"Successfully accessed through alternative path: {alt_url}")
                            return True
                except Exception as e:
                    self.console.print_warning(f"Error accessing alternative path {alt_url}: {str(e)}")
                    continue
            
            return False
            
        except Exception as e:
            self.console.print_warning(f"Error looking for alternative paths: {str(e)}")
            return False

    async def _is_error_page(self, page_content: str) -> bool:
        """Detects if a page is an error (404, etc.)."""
        error_indicators = [
            "404", "not found", "page not found", "error", "does not exist",
            "didn't find", "couldn't find", "no encontrado", "no existe"
        ]
        
        # Check for error text in content
        for indicator in error_indicators:
            if indicator in page_content.lower():
                return True
        
        return False

    async def _simulate_human_behavior(self):
        """Simulates human behavior on the page."""
        try:
            # 1. Random mouse movements
            viewport = await self.page.evaluate("""
                () => ({
                    width: window.innerWidth,
                    height: window.innerHeight
                })
            """)
            
            mouse_moves = random.randint(3, 8)
            for _ in range(mouse_moves):
                x = random.randint(10, viewport["width"] - 10)
                y = random.randint(10, viewport["height"] - 10)
                await self.page.mouse.move(x, y)
                await asyncio.sleep(random.uniform(0.1, 0.3))
            
            # 2. Random scrolling
            scroll_steps = random.randint(2, 5)
            for _ in range(scroll_steps):
                scroll_amount = random.randint(100, 500)
                await self.page.mouse.wheel(0, scroll_amount)
                await asyncio.sleep(random.uniform(0.2, 0.5))
            
            # 3. Random clicks on non-interactive elements
            click_count = random.randint(1, 3)
            for _ in range(click_count):
                x = random.randint(10, viewport["width"] - 10)
                y = random.randint(10, viewport["height"] - 10)
                await self.page.mouse.click(x, y, delay=random.randint(100, 300))
                await asyncio.sleep(random.uniform(0.5, 1.5))
            
            # 4. Random keyboard input
            if random.random() < 0.3:  # 30% chance
                await self.page.keyboard.type(" ".join(random.choices(string.ascii_lowercase, k=random.randint(5, 10))))
                await asyncio.sleep(random.uniform(0.5, 1.0))
            
        except Exception as e:
            self.console.print_warning(f"Error simulating human behavior: {str(e)}")

    async def _analyze_js_file(self, js_url: str):
        """Descarga y analiza un archivo JavaScript."""
        try:
            # Hacer una solicitud directa al archivo .js
            response = await self.page.context.request.get(js_url)
            js_content = await response.text()
            self.console.print_debug(f"Analyzing JavaScript file: {js_url}")
            
            # Usar SmartDetector para analizar el contenido
            js_findings = await self.detector.analyze_js(js_content)
            if self.report_generator and js_findings:
                self.report_generator.add_findings("javascript_analysis", js_findings)
                self.console.print_debug(f"JS findings from {js_url}: {len(js_findings)}")
            
            # Opcional: Buscar URLs embebidas en el JS
            url_pattern = r'(https?://[^\s"\']+)'
            embedded_urls = re.findall(url_pattern, js_content)
            for embedded_url in embedded_urls:
                if self.is_in_scope(embedded_url):
                    await self.add_to_crawl_queue(embedded_url, depth + 1)
                    self.console.print_debug(f"Found embedded URL in JS: {embedded_url}")
                
        except Exception as e:
            self.console.print_error(f"Error analyzing JS file {js_url}: {e}")

    async def test_headers(self, url: str, method: str = "GET"):
        self.console.print_info(f"Testing headers on {method} {url}")
        findings = []
        
        headers_to_test = [
            "User-Agent", "Referer", "X-Forwarded-For", "Accept", "Content-Type",
            "Origin", "Cookie", "X-Requested-With", "X-Custom-Header"
        ]
        
        for header in headers_to_test:
            for category, payloads in PATH_TRAVERSAL_PAYLOADS.items():  # Ejemplo, usa otros payloads si prefieres
                for payload in payloads:
                    test_headers = {header: payload}
                    self.console.print_debug(f"Testing header {header} with {payload}")
                    try:
                        response = await self._make_request(url, method, headers=test_headers)
                        if response.status in [500, 501, 502, 503]:
                            findings.append({
                                "type": "header_injection",
                                "url": url,
                                "header": header,
                                "payload": payload,
                                "status": response.status,
                                "details": f"Server error detected (Status: {response.status})"
                            })
                            self.console.print_success(f"Server error {response.status} on {header}: {payload}")
                    except Exception as e:
                        self.console.print_warning(f"Error testing header {header}: {e}")
        
        return findings

    async def detect_waf(self, url: str, method: str = "GET"):
        self.console.print_info(f"Detecting WAF on {url}")
        waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
            "Akamai": ["akamai-x-cache", "x-akamai-transformed"],
            "Imperva": ["x-iinfo", "x-cdn"],
            "Sucuri": ["x-sucuri-id", "sucuri/cloudproxy"],
            "AWS WAF": ["aws-waf-token", "x-amzn-waf"],
            "F5 BIG-IP": ["bigipserver", "x-f5-"],
            "ModSecurity": ["mod_security", "owasp_crs"]
        }
        
        # Enviar una solicitud con un payload básico para detectar WAF
        test_headers = {"User-Agent": "' OR 1=1 --"}  # Payload simple para provocar respuesta
        try:
            response = await self._make_request(url, method, headers=test_headers)
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = await response.text()
            
            for waf, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in headers or sig in body.lower():
                        self.console.print_warning(f"WAF detected: {waf} (Signature: {sig})")
                        return {"waf": waf, "signature": sig}
            
            # Verificar códigos de bloqueo típicos de WAF
            if response.status in [403, 429]:
                self.console.print_warning(f"Possible WAF detected (Status: {response.status})")
                return {"waf": "Unknown", "signature": f"Status {response.status}"}
            
            self.console.print_debug("No WAF detected")
            return None
        except Exception as e:
            self.console.print_error(f"Error detecting WAF: {e}")
            return None