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

# Import refactored/new components
from console_manager import ConsoleManager
from smart_detector import SmartDetector
from attack_engine import AttackEngine
from advanced_js_analyzer import AdvancedJSAnalyzer
from js_analyzer import JSAnalyzer # Static analyzer
from traffic_analyzer import TrafficAnalyzer
from report_generator import ReportGenerator # Needed to add findings

# Configurar logger
logger = logging.getLogger(__name__)

class SmartCrawler:
    def __init__(self, 
                 base_url: str,
                 max_depth: int = 3,
                 timeout: int = 30,
                 rate_limit: float = 1.0,
                 excluded_patterns: List[str] = None,
                 included_patterns: List[str] = None,
                 interactsh_url: Optional[str] = None,
                 report_generator: Optional[ReportGenerator] = None):
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
        
        # Initialize crawl state
        self.crawl_queue = asyncio.Queue()
        self.visited_urls = set()
        self.used_terms = set()
        self.interaction_counts = {}
        
        # Initialize browser state
        self.browser = None
        self.context = None
        self.page = None
        
        self.console.print_info("SmartCrawler initialized.")

    async def start_crawl(self, start_url: str, max_depth: int = 3):
        """Start the crawling process with the given URL and max depth."""
        self.console.print_info(f"Starting crawl from {start_url} with max depth {max_depth}")
        
        try:
            # Initialize browser and page
            playwright = await async_playwright().start()
            self.browser = await playwright.chromium.launch(headless=True)
            self.context = await self.browser.new_context()
            self.page = await self.context.new_page()
            
            # Add initial URL to crawl queue
            await self.add_to_crawl_queue(start_url, 0)
            
            # Main crawl loop
            while self.crawl_queue:
                url, depth = await self.crawl_queue.get()
                
                # Skip if URL already visited or depth exceeded
                if url in self.visited_urls or depth > max_depth:
                    continue
                
                # Mark URL as visited
                self.visited_urls.add(url)
                
                # Process URL
                await self._process_single_url(url, depth)
                
                # Wait for rate limiting
                await asyncio.sleep(self.rate_limit_delay)
            
            # Cleanup
            await self.page.close()
            await self.context.close()
            await self.browser.close()
            await playwright.stop()
            
            self.console.print_info("Crawl completed successfully")
            
        except Exception as e:
            self.console.print_error(f"Error during crawl: {e}")
            # Cleanup on error
            if hasattr(self, 'page') and not self.page.is_closed():
                await self.page.close()
            if hasattr(self, 'context') and not self.context.is_closed():
                await self.context.close()
            if hasattr(self, 'browser') and not self.browser.is_closed():
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
            # Navigate to URL
            await self.page.goto(url, wait_until="networkidle", timeout=self.timeout)
            await self.page.wait_for_load_state("load", timeout=self.timeout)
            
            if self.report_generator:
                self.report_generator.log_realtime_event("PAGE_LOADED", f"Página cargada: {url}", {
                    "title": await self.page.title(),
                    "status": "success"
                })
            
            # Static JS analysis
            self.console.print_debug("Performing static JS analysis...")
            js_content = await self.page.content()
            js_findings = await self.detector.analyze_js(js_content)
            
            if self.report_generator and js_findings:
                self.report_generator.add_findings("javascript_analysis", js_findings)
            
            # Basic vulnerability checks
            self.console.print_debug("Performing basic vulnerability checks...")
            parsed_url = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed_url.query).items() if v}
            if params:
                vuln_findings = await self.attack_engine.test_vulnerability(url, "GET", params=params)
                if self.report_generator and vuln_findings:
                    self.report_generator.add_findings("vulnerability_scan", vuln_findings)
            
            # Dynamic analysis
            self.console.print_debug("Performing dynamic analysis...")
            dynamic_findings = await self.detector.analyze_dynamic_content(self.page)
            if self.report_generator and dynamic_findings:
                self.report_generator.add_findings("dynamic_analysis", dynamic_findings)
            
            # Handle interactive elements
            self.console.print_debug("Handling interactive elements...")
            interactive_findings = await self.handle_interactive_elements(self.page, url, depth)
            if self.report_generator and interactive_findings:
                self.report_generator.add_findings("interactive_elements", interactive_findings)
            
            # Handle forms
            self.console.print_debug("Handling forms...")
            forms = await self.page.query_selector_all('form')
            for form in forms:
                form_findings = await self.handle_form_submission(self.page, form, url, depth)
                if self.report_generator and form_findings:
                    self.report_generator.add_findings("form_analysis", form_findings)
            
            # Handle search forms
            self.console.print_debug("Handling search forms...")
            search_findings = await self.handle_search_forms(self.page, url, depth)
            if self.report_generator and search_findings:
                self.report_generator.add_findings("search_analysis", search_findings)
            
            # Gather new links
            self.console.print_debug("Gathering new links...")
            links = await self.page.query_selector_all('a[href]')
            new_urls = []
            for link in links:
                href = await link.get_attribute('href')
                if href:
                    full_url = urljoin(url, href)
                    if self.is_in_scope(full_url):
                        new_urls.append(full_url)
                        await self.add_to_crawl_queue(full_url, depth + 1)
            
            if self.report_generator:
                self.report_generator.log_realtime_event("LINKS_FOUND", f"Enlaces encontrados en {url}", {
                    "total_links": len(new_urls),
                    "new_urls": new_urls[:5]  # Limitamos a 5 URLs para el log
                })
            
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
        """Handles interactive elements like buttons, links, and dropdowns."""
        self.console.print_debug("Handling interactive elements...")
        
        # Handle buttons and clickable elements
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
        
        for selector in clickable_selectors:
            try:
                elements = await page.query_selector_all(selector)
                for element in elements:
                    if await element.is_visible():
                        # Get element attributes for logging
                        element_type = await element.evaluate('el => el.tagName.toLowerCase()')
                        element_id = await element.get_attribute('id') or ''
                        element_class = await element.get_attribute('class') or ''
                        element_text = await element.inner_text() or ''
                        
                        self.console.print_debug(f"Found interactive element: {element_type} {element_id} {element_class} {element_text}")
                        
                        # Check if element is in a form
                        form_element = await element.query_selector('xpath=ancestor::form')
                        if form_element:
                            # Handle form submission
                            await self.handle_form_submission(page, form_element, base_url, depth)
                        else:
                            # Handle standalone interactive elements
                            try:
                                # Get element's href or action
                                href = await element.get_attribute('href')
                                if href:
                                    # Normalize URL
                                    full_url = urljoin(base_url, href)
                                    if self.is_in_scope(full_url):
                                        # Test vulnerability on URL parameters
                                        parsed_url = urlparse(full_url)
                                        params = {k: v[0] for k, v in parse_qs(parsed_url.query).items() if v}
                                        if params:
                                            await self.attack_engine.test_vulnerability(full_url, "GET", params=params)
                                        
                                        # Add to crawl queue
                                        await self.add_to_crawl_queue(full_url, depth + 1)
                                
                                # Click element and handle navigation
                                async with page.expect_navigation(wait_until="domcontentloaded", timeout=self.timeout // 2):
                                    await element.click(timeout=5000)
                                await page.wait_for_load_state("load", timeout=self.timeout // 2)
                                
                                # Test new page for vulnerabilities
                                current_url = page.url
                                if self.is_in_scope(current_url):
                                    parsed_url = urlparse(current_url)
                                    params = {k: v[0] for k, v in parse_qs(parsed_url.query).items() if v}
                                    if params:
                                        await self.attack_engine.test_vulnerability(current_url, "GET", params=params)
                                    
                                    await self.add_to_crawl_queue(current_url, depth + 1)
                                
                            except Exception as e:
                                self.console.print_warning(f"Error handling {element_type}: {e}")
                                
            except Exception as e:
                self.console.print_warning(f"Error handling selector '{selector}': {e}")
        
        # Handle dropdowns and select elements
        try:
            select_elements = await page.query_selector_all('select:not([disabled])')
            for select in select_elements:
                if await select.is_visible():
                    # Get all options
                    options = await select.query_selector_all('option')
                    for option in options:
                        try:
                            # Select option and handle change event
                            await select.select_option(value=await option.get_attribute('value'))
                            await asyncio.sleep(0.2)
                            
                            # Test for form submission if in a form
                            form_element = await select.query_selector('xpath=ancestor::form')
                            if form_element:
                                await self.handle_form_submission(page, form_element, base_url, depth)
                            
                        except Exception as e:
                            self.console.print_warning(f"Error handling select option: {e}")
        except Exception as e:
            self.console.print_warning(f"Error handling select elements: {e}")

    async def add_to_crawl_queue(self, url: str, depth: int):
        """Add a URL to the crawl queue if it's in scope and not already visited."""
        # Normalize URL
        normalized_url = self._normalize_url(url)
        
        # Skip if already visited or not in scope
        if normalized_url in self.visited_urls or not self.is_in_scope(normalized_url):
            return
        
        # Add to queue
        await self.crawl_queue.put((normalized_url, depth))
        self.console.print_debug(f"Added URL to queue: {normalized_url} (depth: {depth})")
        
        # Analyze URL with SmartDetector
        try:
            await self.detector.analyze_url(normalized_url)
        except Exception as e:
            self.console.print_warning(f"Error analyzing URL {normalized_url}: {e}")

    def is_in_scope(self, url: str) -> bool:
        """Verifica si la URL está dentro del alcance definido."""
        try:
            # Obtener el dominio base del target
            target_domain = urlparse(self.base_url).netloc.lower()
            
            # Lista de dominios de redes sociales a excluir
            social_networks = [
                'facebook.com', 'fb.com', 'instagram.com', 'twitter.com', 'x.com',
                'linkedin.com', 'youtube.com', 'tiktok.com', 'pinterest.com',
                'reddit.com', 'snapchat.com', 'tumblr.com', 'flickr.com',
                'vimeo.com', 'whatsapp.com', 'telegram.org', 'discord.com',
                'twitch.tv', 'medium.com', 'github.com', 'gitlab.com'
            ]
            
            # Parsear la URL a verificar
            parsed_url = urlparse(url)
            url_domain = parsed_url.netloc.lower()
            
            # Verificar si es una red social
            if any(social in url_domain for social in social_networks):
                self.console.print_debug(f"URL de red social excluida: {url}")
                return False
            
            # Verificar si el dominio coincide con el target
            if target_domain not in url_domain:
                self.console.print_debug(f"URL fuera de scope excluida: {url}")
                return False
            
            # Verificar patrones de exclusión si existen
            if self.excluded_patterns:
                for pattern in self.excluded_patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        self.console.print_debug(f"URL coincidente con patrón de exclusión: {url}")
                        return False
            
            # Verificar patrones de inclusión si existen
            if self.included_patterns:
                for pattern in self.included_patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        self.console.print_debug(f"URL coincidente con patrón de inclusión: {url}")
                        return True
                return False
            
            return True
            
        except Exception as e:
            self.console.print_error(f"Error verificando scope de URL {url}: {e}")
            return False

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL by removing fragments and query parameters."""
        try:
            # Parse URL
            parsed = urlparse(url)
            
            # Remove fragments and query parameters
            normalized = parsed._replace(
                fragment='',
                query='',
                params=''
            ).geturl()
            
            # Remove trailing slash
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