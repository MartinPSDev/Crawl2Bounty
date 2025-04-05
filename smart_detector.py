import logging
import random
import time
import base64
import html
import urllib.parse
from typing import List, Dict, Any, Optional
import re

# Import ConsoleManager
from console_manager import ConsoleManager
from playwright.async_api import Page, Error as PlaywrightError

class SmartDetector:
    def __init__(self, console_manager: ConsoleManager, interactsh_url: Optional[str] = None):
        # Use ConsoleManager for user output
        if not isinstance(console_manager, ConsoleManager):
            raise ValueError("console_manager must be an instance of ConsoleManager")
        self.console = console_manager
        # Ensure verbose is enabled for debug messages
        self.console.verbose = True
        # Use standard logging for internal debug messages if necessary
        self.logger = logging.getLogger('SmartDetector')
        self.interactsh_url = interactsh_url

        # --- User Agents ---
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.82",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", # Common bot
        ]

        # --- WAF Evasion Headers Pool ---
        self.waf_evasion_headers_pool = [
            {"X-Forwarded-For": self._generate_random_ip()},
            {"X-Originating-IP": self._generate_random_ip()},
            {"X-Remote-IP": self._generate_random_ip()},
            {"X-Remote-Addr": self._generate_random_ip()},
            {"X-Client-IP": self._generate_random_ip()},
            {"X-Real-IP": self._generate_random_ip()},
            {"Forwarded": f"for={self._generate_random_ip()};proto=https"},
            {"X-Forwarded-Host": f"example-{random.randint(1,100)}.com"},
            {"X-Host": f"internal-app-{random.randint(1,100)}"},
            {"X-Custom-Header": f"Value{random.randint(1000,9999)}"},
            {"Accept-Language": random.choice(["en-US,en;q=0.9", "es-ES,es;q=0.8", "fr-FR,fr;q=0.7", "*"])},
            {"Referer": random.choice([f"https://www.google.com/search?q=query{random.randint(1,100)}", "https://www.bing.com/", "https://duckduckgo.com/", f"https://internal.portal/dashboard{random.randint(1,10)}"])},
            {"Accept-Encoding": random.choice(["gzip, deflate, br", "gzip", "deflate", "*", "identity"])},
            {"Upgrade-Insecure-Requests": random.choice(["0", "1"])},
            {"Cache-Control": random.choice(["no-cache", "max-age=0"])},
            {"Content-Type": random.choice(["application/json", "application/xml", "application/x-www-form-urlencoded", "text/plain"])}, # For POST/PUT
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-Forwarded-Proto": "https"},
            {"Via": f"1.1 google"},
            # Headers that might cause issues if blindly applied (use with care or context)
            # {"Content-Length": "0"}, # Only for relevant methods
            # {"Transfer-Encoding": "chunked"}, # Requires specific body handling
        ]

        # --- Interactive Element Detection Cues (Used in JS Evaluation) ---
        self.interactive_attributes = {
             "visual_cues": [
                "style.cursor === 'pointer'",
                "(el.offsetWidth > 10 && el.offsetHeight > 10)",
                "(style.backgroundColor !== 'transparent' || style.backgroundImage !== 'none')",
                "(style.borderWidth !== '0px' && style.borderStyle !== 'none')",
                "style.visibility !== 'hidden' && style.display !== 'none' && style.opacity !== '0'",
             ],
             "behavior_cues": [
                "el.onclick !== null",
                "el.onmouseover !== null",
                "el.onfocus !== null",
                # "typeof $ !== 'undefined' && $._data && $._data(el, 'events')", # jQuery specific, might error if no jQuery
                "el.hasAttribute('onclick')", # Check attributes directly
                "el.hasAttribute('onmouseover')",
                "el.hasAttribute('onfocus')",
                "el.hasAttribute('ng-click')",
                "el.hasAttribute('v-on:click')",
                "el.hasAttribute('@click')",
                "el.matches('[data-action], [js-action], [data-onclick]')",
             ],
             "semantic_cues": [
                "['BUTTON', 'A', 'INPUT', 'TEXTAREA', 'SELECT', 'DETAILS'].includes(el.tagName)",
                "(el.tagName === 'INPUT' && ['submit', 'button', 'reset', 'image'].includes(el.type))",
                "el.getAttribute('role') === 'button' || el.getAttribute('role') === 'link' || el.getAttribute('role') === 'menuitem' || el.getAttribute('role') === 'tab'",
                "el.matches('[class*=\"btn\"], [class*=\"button\"], [class*=\"link\"], [class*=\"nav\"], [class*=\"menu\"], [class*=\"action\"]')",
                "el.isContentEditable"
             ],
             "text_cues": [
                "el.textContent && ['submit', 'send', 'login', 'register', 'buy', 'add', 'search', 'go', 'continue', 'next', 'more', 'click', 'view', 'update', 'save', 'delete', 'apply', 'confirm', 'accept'].some(t => el.textContent.trim().toLowerCase().includes(t))"
             ]
        }

        # --- Error Codes ---
        self.error_codes = {
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
            405: "Method Not Allowed", 429: "Too Many Requests", 500: "Internal Server Error",
            501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout"
        }

        # --- Payload Counters ---
        self.identity_rotation_counter = 0
        self.payload_obfuscation_counter = 0 # Can track obfuscation usage if needed

        self.console.print_info("SmartDetector initialized.")

    def _generate_random_ip(self) -> str:
        # Prioritize common private/public ranges slightly
        first_octet = random.choice([10, 172, 192, random.randint(1, 223)])
        if first_octet == 172:
            return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif first_octet == 192:
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif first_octet == 10:
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            # Avoid reserved ranges for potentially 'external' looking IPs
            while first_octet in [0, 127] or (first_octet == 169 and random.randint(0,255) == 254) or first_octet >= 224:
                first_octet = random.randint(1, 223)
            return f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    async def get_next_user_agent_and_headers(self) -> Dict[str, str]:
        """Gets a random User-Agent and a selection of WAF evasion headers."""
        user_agent = random.choice(self.user_agents)
        num_headers = random.randint(2, 5)
        # Ensure we don't select more headers than available
        num_to_select = min(num_headers, len(self.waf_evasion_headers_pool))
        selected_header_dicts = random.sample(self.waf_evasion_headers_pool, num_to_select)

        final_headers: Dict[str, str] = {"User-Agent": user_agent}
        header_keys_added: set[str] = set(["user-agent"])

        for header_dict in selected_header_dicts:
            try:
                key = list(header_dict.keys())[0]
                value = header_dict[key]
                # Ensure value is a string
                value_str = str(value)
                # Normalize key for checking duplicates
                norm_key = key.lower()
                if norm_key not in header_keys_added:
                    final_headers[key] = value_str
                    header_keys_added.add(norm_key)
            except (IndexError, KeyError, TypeError) as e:
                self.console.print_warning(f"Error processing evasion header {header_dict}: {e}")
                continue # Skip malformed header dicts

        self.console.print_info(f"Rotated Identity: UA={user_agent[:20]}..., Headers={list(final_headers.keys())}")
        return final_headers

    async def should_rotate_identity(self) -> bool:
        """Determines if it's time to rotate identity headers."""
        self.identity_rotation_counter += 1
        # Rotate more frequently initially, then less often
        rotate_threshold = random.randint(3, 8) if self.identity_rotation_counter < 50 else random.randint(10, 20)
        should = self.identity_rotation_counter % rotate_threshold == 0
        if should:
             self.console.print_info("Rotating identity...")
        return should

    async def detect_interactive_elements(self, page: Page) -> List[Dict]:
        """Detects interactive elements using a scoring system based on JS evaluation."""
        self.console.print_info("Detecting interactive elements...")

        # Combine cues into a JS function for evaluation
        visual_check = ' || '.join(f"({c})" for c in self.interactive_attributes['visual_cues'])
        behavior_check = ' || '.join(f"({c})" for c in self.interactive_attributes['behavior_cues'])
        semantic_check = ' || '.join(f"({c})" for c in self.interactive_attributes['semantic_cues'])
        text_check = ' || '.join(f"({c})" for c in self.interactive_attributes['text_cues'])

        # Ensure helper function is available in page context before using it
        js_selector_func = """
            function findElementsBySelector(selector) {
                try {
                    const elements = document.querySelectorAll(selector);
                    return Array.from(elements).map(el => ({
                        tag: el.tagName.toLowerCase(),
                        id: el.id || '',
                        classes: Array.from(el.classList),
                        type: el.type || '',
                        name: el.name || '',
                        value: el.value || '',
                        href: el.href || '',
                        src: el.src || '',
                        text: el.textContent.trim(),
                        html: el.outerHTML
                    }));
                } catch (e) {
                    return [];
                }
            }
        """
        try:
            await page.evaluate(js_selector_func) # Define the helper function
        except PlaywrightError as e:
             self.console.print_error(f"Failed to inject CSS selector helper function: {e}")
             return [] # Cannot proceed without selector generation


        js_code = f"""
            () => {{
                const elementsData = [];
                const allElements = document.querySelectorAll('body *:not(script):not(style):not(meta):not(link):not(title)');

                allElements.forEach(el => {{
                    try {{
                        if (el.closest('[data-robot-hunter-ignore]')) return;

                        const style = window.getComputedStyle(el);
                        let score = 0;
                        const reasons = [];

                        const rect = el.getBoundingClientRect();
                        if (!(rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none' && style.opacity !== '0')) {{
                           return;
                        }}

                        if ({visual_check}) {{ score += 1; reasons.push('visual'); }}
                        if ({behavior_check}) {{ score += 3; reasons.push('behavior'); }}
                        if ({semantic_check}) {{ score += 2; reasons.push('semantic'); }}
                        if ({text_check}) {{ score += 1; reasons.push('text'); }}

                        if (score >= 2 && !el.querySelector('[data-rh-interactive="true"]')) {{
                            const selector = findElementsBySelector(el); // Use the injected helper
                            if (!selector) continue; // Skip if selector generation failed

                            el.setAttribute('data-rh-interactive', 'true');
                            elementsData.push({{
                                selector: selector, // Use generated selector
                                score: score,
                                reasons: reasons,
                                text: el.textContent?.trim()?.substring(0, 50) || el.value?.substring(0,50) || el.name || el.id || '',
                                tag: el.tagName,
                                attributes: Array.from(el.attributes).reduce((acc, attr) => {{ acc[attr.name] = attr.value; return acc; }}, {{}}),
                                is_visible: true,
                                bounding_box: {{ top: rect.top, left: rect.left, width: rect.width, height: rect.height }}
                            }});
                        }}
                    }} catch (e) {{
                         // Ignore errors for individual elements
                    }}
                }});

                document.querySelectorAll('[data-rh-interactive]').forEach(el => el.removeAttribute('data-rh-interactive'));
                return elementsData.sort((a, b) => b.score - a.score);
            }}
        """
        try:
            elements_data = await page.evaluate(js_code)
            self.console.print_info(f"Found {len(elements_data)} potentially interactive elements.")
            for element in elements_data[:5]:
                self.console.print_info(f"  -> Tag: {element['tag']}, Score: {element['score']}, Text: '{element['text']}', Selector: {element.get('selector','N/A')[:60]}...")
            return elements_data
        except PlaywrightError as e:
             self.console.print_error(f"Playwright error evaluating interactive elements JS: {e}")
             return []
        except Exception as e:
            self.console.print_error(f"Unexpected error detecting interactive elements via JS: {e}")
            return []


    async def detect_forms(self, page: Page) -> List[Dict]:
        """Detects standard forms and pseudo-forms using JS evaluation."""
        self.console.print_info("Detecting forms...")
        # Ensure CSS selector function is injected if not already done
        js_selector_func = """
            function findElementsBySelector(selector) {
                try {
                    const elements = document.querySelectorAll(selector);
                    return Array.from(elements).map(el => ({
                        tag: el.tagName.toLowerCase(),
                        id: el.id || '',
                        classes: Array.from(el.classList),
                        type: el.type || '',
                        name: el.name || '',
                        value: el.value || '',
                        href: el.href || '',
                        src: el.src || '',
                        text: el.textContent.trim(),
                        html: el.outerHTML
                    }));
                } catch (e) {
                    return [];
                }
            }
        """ # Same function as in detect_interactive_elements

        try:
            await page.evaluate(js_selector_func) # Define helper if not globally defined
        except PlaywrightError as e:
             self.console.print_error(f"Failed to inject CSS selector helper function for forms: {e}")
             return []

        try:
            # Updated JS to reliably generate selectors
            forms_data = await page.evaluate("""
                () => {
                    const results = [];
                    const formElements = new Set(); // Track elements already part of a standard form

                    // Use previously defined findElementsBySelector helper

                    // 1. Standard Forms
                    document.querySelectorAll('form').forEach(form => {
                        const formSelector = findElementsBySelector(form);
                        if (!formSelector) return;

                        const inputs = Array.from(form.querySelectorAll('input, select, textarea'));
                        inputs.forEach(inp => formElements.add(inp));

                        const submitButton = form.querySelector('button[type="submit"], input[type="submit"], button:not([type]), input[type="button"][value*="submit" i]');
                        results.push({
                            type: 'standard_form',
                            selector: formSelector,
                            action: form.action,
                            method: form.method || 'get',
                            inputs: inputs.map(el => ({
                                selector: findElementsBySelector(el), // Generate selector for input
                                type: el.type || el.tagName.toLowerCase(),
                                name: el.name || el.id || `unnamed_${Math.random().toString(16).slice(2)}`, // Generate fallback name
                                id: el.id,
                                value: el.type === 'password' ? null : el.value
                            })).filter(inp => inp.selector && inp.name), // Require selector and name
                            submit_selector: submitButton ? findElementsBySelector(submitButton) : null
                        });
                    });

                    // 2. Pseudo-Forms
                    const orphanedInputs = Array.from(document.querySelectorAll('input, select, textarea')).filter(el => !formElements.has(el));
                    const groupedOrphans = {};

                    orphanedInputs.forEach(input => {
                        let ancestor = input.parentElement;
                        while (ancestor && !['DIV', 'FIELDSET', 'SECTION', 'LI', 'P', 'FORM'].includes(ancestor.tagName) && ancestor.tagName !== 'BODY') { // Added FORM to stop early
                            ancestor = ancestor.parentElement;
                        }
                        // Ensure ancestor is valid before proceeding
                        if (!ancestor || ancestor.tagName === 'BODY') ancestor = input.parentElement;
                        if (!ancestor) return; // Skip if no valid ancestor

                        const ancestorSelector = findElementsBySelector(ancestor);
                        if (!ancestorSelector) return;

                        if (!groupedOrphans[ancestorSelector]) {
                             groupedOrphans[ancestorSelector] = { elementHandle: ancestor, inputs: [] }; // Store element ref if needed? JS context issue. Store selector only.
                        }
                        groupedOrphans[ancestorSelector].inputs.push(input);
                     });

                    Object.entries(groupedOrphans).forEach(([ancestorSelector, group]) => {
                         if (group.inputs.length >= 1) {
                             // Need to re-find the ancestor element to query within it
                             const ancestorElement = document.querySelector(ancestorSelector);
                             if (!ancestorElement) return; // Skip if ancestor selector fails

                             const submitButton = ancestorElement.querySelector('button, [role="button"], input[type="button"], a[href="#"]') ||
                                                  ancestorElement.nextElementSibling?.matches('button, [role="button"], input[type="button"]') ? ancestorElement.nextElementSibling : null;

                             if (group.inputs.length > 1 || (group.inputs.length === 1 && submitButton)) {
                                  results.push({
                                      type: 'pseudo_form',
                                      selector: ancestorSelector,
                                      action: null, method: 'post', // Assume POST
                                      inputs: group.inputs.map(el => ({
                                          selector: findElementsBySelector(el),
                                          type: el.type || el.tagName.toLowerCase(),
                                          name: el.name || el.id || `unnamed_${Math.random().toString(16).slice(2)}`,
                                          id: el.id,
                                          value: el.type === 'password' ? null : el.value
                                      })).filter(inp => inp.selector && inp.name),
                                      submit_selector: submitButton ? findElementsBySelector(submitButton) : null
                                  });
                             }
                         }
                     });

                    return results;
                }
            """) # Removed dependency on element handle passing
            standard_forms = len([f for f in forms_data if f.get('type') == 'standard_form'])
            pseudo_forms = len([f for f in forms_data if f.get('type') == 'pseudo_form'])
            self.console.print_info(f"Detected Forms: {len(forms_data)} (Standard: {standard_forms}, Pseudo: {pseudo_forms})")
            for form in forms_data:
                 self.console.print_info(f"  -> Form Type: {form.get('type')}, Inputs: {len(form.get('inputs',[]))}, Action: {form.get('action','N/A')}, Selector: {form.get('selector','N/A')[:60]}...")
            return forms_data
        except PlaywrightError as e:
             self.console.print_error(f"Playwright error evaluating forms JS: {e}")
             return []
        except Exception as e:
            self.console.print_error(f"Unexpected error detecting forms via JS: {e}")
            return []


    def obfuscate_payload(self, payload: str, level: int = 1) -> str:
        """Applies WAF evasion techniques to payloads."""
        if level <= 0: return payload
        # Keep the improved obfuscation logic from previous response
        original_payload = payload
        techniques_applied = []

        replacements = {
            " ": ["/**/", "%09", "%20", "+", "%0a", "%0d"], # Added newline/cr
            "=": ["= ", "%3d"], "'": ["%27", "`"], "\"": ["%22", "`"],
            "(": ["%28"], ")": ["%29"], "<": ["%3c"], ">": ["%3e"],
            ";": ["%3b"], "|": ["%7c"], "&": ["%26"], "/": ["%2f"], "\\": ["%5c"],
        }
        keywords_sql = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE", "SLEEP"]
        keywords_script = ["SCRIPT", "ALERT", "ONERROR", "IMG", "SVG", "EVAL", "ONLOAD", "IFRAME", "PROMPT", "SRC", "HREF"]
        keywords_cmd = ["SLEEP", "CAT", "WHOAMI", "SYSTEMINFO", "TYPE", "DIR", "ID", "PING", "NSLOOKUP", "CURL", "WGET"]

        # Level 1: Simple space/char replacement, case variation, basic comments
        if level >= 1:
            if ' ' in payload and random.random() < 0.8:
                 payload = payload.replace(' ', random.choice(replacements[' ']), random.randint(1, max(1, payload.count(' ')//2))) # Replace up to half the spaces
                 techniques_applied.append("space_replace")
            if random.random() < 0.5:
                 char_to_replace = random.choice(list(replacements.keys()))
                 if char_to_replace != ' ' and char_to_replace in payload:
                     payload = payload.replace(char_to_replace, random.choice(replacements[char_to_replace]), 1)
                     techniques_applied.append("char_replace")
            if random.random() < 0.6:
                 all_keywords = keywords_sql + keywords_script + keywords_cmd
                 kw_to_vary = random.choice([k for k in all_keywords if len(k) > 2]) # Avoid tiny keywords
                 if re.search(r'\b' + re.escape(kw_to_vary) + r'\b', payload, re.IGNORECASE): # Use word boundary
                     payload = re.sub(r'\b(' + re.escape(kw_to_vary) + r')\b', lambda m: ''.join(random.choice([c.upper(), c.lower()]) for c in m.group(1)), payload, count=1, flags=re.IGNORECASE)
                     techniques_applied.append("case_vary")

        # Level 2: More encoding, versioned comments, URL encoding, char code/entities
        if level >= 2:
            if any(kw in original_payload.upper() for kw in keywords_sql) and random.random() < 0.4:
                parts = re.split(r'(\b(?:' + '|'.join(keywords_sql) + r')\b)', payload, flags=re.IGNORECASE)
                if len(parts) > 2:
                     try:
                          idx = random.choice([i for i, p in enumerate(parts) if p.upper() in keywords_sql])
                          if not parts[idx].startswith('/*!'):
                              parts[idx] = f"/*!50000{parts[idx]}*/"
                              payload = "".join(parts)
                              techniques_applied.append("mysql_comment")
                     except (IndexError, ValueError): pass

            if random.random() < 0.6:
                 chars_to_encode = list("=()<>;&|'/\\" + '"') # More chars
                 for _ in range(random.randint(1, 3)): # Encode a few chars
                     char_to_encode = random.choice(chars_to_encode)
                     if char_to_encode in payload:
                         payload = payload.replace(char_to_encode, urllib.parse.quote(char_to_encode), 1)
                 techniques_applied.append("partial_urlencode")

            # Char Code / Entities (JS/HTML context specific)
            if any(k in original_payload for k in ['alert', 'prompt']) and random.random() < 0.4:
                 payload = payload.replace('(', ''.join(f"&#x{ord(c):x};" for c in '('))
                 techniques_applied.append("html_entity")
            elif '<' in original_payload and random.random() < 0.3:
                  payload = payload.replace('<', ''.join(f"\\u{ord(c):04x}" for c in '<'))
                  techniques_applied.append("js_unicode")

        # Level 3: Full URL encoding, different base encodings, concatenation
        if level >= 3:
            encoding_choice = random.random()
            if encoding_choice < 0.3:
                 payload = urllib.parse.quote(payload)
                 techniques_applied.append("full_urlencode")
            elif encoding_choice < 0.6 and 'alert' in original_payload: # Simple base64 for alert
                  payload = payload.replace("alert(1)", f"eval(atob('{base64.b64encode(b'alert(1)').decode()}'))")
                  techniques_applied.append("base64_eval")
            # Add concatenation breakups if useful (e.g., 'al'+'ert(1)') - needs more logic

        # New Level 4: Unicode encoding and SQL comments
        if level >= 4:
            payload = ''.join([f"%u{ord(c):04x}" for c in payload])
            techniques_applied.append("unicode_encoding")
            payload = re.sub(r"(?<=\w)\s+(?=\w)", "/**/", payload)
            techniques_applied.append("sql_comments")

        self.console.print_info(f"Payload Obfuscation (Level {level}): {original_payload[:30]}... -> {payload[:40]}... | Techniques: {techniques_applied or 'None'}")
        return payload


    async def log_response_status(self, response: Optional[Any], context: str = "") -> Dict[str, Any]:
        """Logs detailed info about HTTP responses (can handle httpx.Response)."""
        status = -1
        url = "N/A"
        content_type = "N/A"
        content_length = 0
        details = ""
        is_error = False
        error_type = "Unknown Error" # Default error type

        if response and isinstance(response, dict) and 'status' in response:
            # Handling dictionary-like response (maybe from evaluate?)
            status = response.get('status', -1)
            url = response.get('url', 'N/A')
            content_type = response.get('headers', {}).get('content-type', 'N/A')
            text_content = response.get('text') or response.get('body') # Handle 'text' or 'body'
            content_length = len(text_content) if isinstance(text_content, (str, bytes)) else 0
            if "error" in response:
                 is_error = True
                 error_type = f"Client-Side Error: {response['error']}"
        elif hasattr(response, 'status_code'): # Handling httpx.Response
            status = response.status_code
            url = str(response.url)
            content_type = response.headers.get("content-type", "N/A")
            content_length = len(response.content)

        log_entry: Dict[str, Any] = {
            "timestamp": time.time(), "status": status, "url": url,
            "content_type": content_type, "content_length": content_length, "context": context
        }

        if status >= 400 or is_error:
            is_error = True # Ensure flag is set
            if not log_entry.get('error_type'): # If not set by client-side error
                log_entry["error_type"] = self.error_codes.get(status, "Unknown HTTP Error")
            log_entry["error"] = True

            if 400 <= status < 500: log_entry["category"] = "client_error"
            elif status >= 500: log_entry["category"] = "server_error"
            else: log_entry["category"] = "client_side_error" # If status ok but client error occurred

            if status == 403: details = "Access Forbidden - Potential WAF or Access Control"
            elif status == 429: details = "Rate Limited - Reduce request frequency"
            elif status >= 500: details = "Server Error - Potential vulnerability or misconfiguration"
            log_entry["details"] = log_entry.get("details", "") or details # Append default details if none specific

        # Log to console
        if is_error or self.console.verbose:
             log_msg = f"Response Status: {status} ({log_entry.get('error_type', 'OK')}) for {url} [{context}] {log_entry.get('details','')}"
             if is_error:
                 self.console.print_warning(log_msg) if status != -1 and status < 500 else self.console.print_error(log_msg)
             else:
                 self.console.print_info(log_msg)

        return log_entry

    async def analyze_url(self, url: str) -> None:
        """Analyze a URL for potential vulnerabilities and interesting patterns."""
        try:
            self.console.print_debug(f"Analyzing URL: {url}")
            
            # Parse URL
            parsed_url = urllib.parse.urlparse(url)
            
            # Check for interesting file extensions
            file_extensions = ['.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py', '.rb', '.exe', '.dll', '.config', '.xml', '.json', '.yaml', '.yml', '.ini', '.env', '.bak', '.old', '.backup']
            path = parsed_url.path.lower()
            for ext in file_extensions:
                if path.endswith(ext):
                    self.console.print_warning(f"Found potentially sensitive file extension: {ext} in {url}")
            
            # Check for interesting parameters
            query_params = urllib.parse.parse_qs(parsed_url.query)
            sensitive_params = ['id', 'user', 'admin', 'password', 'token', 'key', 'secret', 'file', 'path', 'dir', 'url', 'redirect', 'next', 'target', 'dest']
            for param in query_params:
                if any(sensitive in param.lower() for sensitive in sensitive_params):
                    self.console.print_warning(f"Found potentially sensitive parameter: {param} in {url}")
            
            # Check for interesting paths
            sensitive_paths = ['admin', 'login', 'register', 'api', 'backup', 'config', 'database', 'debug', 'test', 'dev', 'staging', 'beta']
            path_parts = path.split('/')
            for part in path_parts:
                if any(sensitive in part.lower() for sensitive in sensitive_paths):
                    self.console.print_warning(f"Found potentially sensitive path component: {part} in {url}")
            
            # Check for interesting subdomains
            subdomain = parsed_url.netloc.split('.')[0]
            sensitive_subdomains = ['admin', 'api', 'dev', 'staging', 'test', 'beta', 'internal', 'secure', 'vpn', 'mail', 'ftp', 'smtp', 'pop', 'imap']
            if any(sensitive in subdomain.lower() for sensitive in sensitive_subdomains):
                self.console.print_warning(f"Found potentially sensitive subdomain: {subdomain} in {url}")
            
            # Check for interesting ports
            if ':' in parsed_url.netloc:
                port = parsed_url.netloc.split(':')[1]
                if port not in ['80', '443', '8080']:
                    self.console.print_warning(f"Found non-standard port: {port} in {url}")
            
            # Check for interesting protocols
            if parsed_url.scheme not in ['http', 'https']:
                self.console.print_warning(f"Found non-standard protocol: {parsed_url.scheme} in {url}")
            
            # Check for interesting fragments
            if parsed_url.fragment:
                self.console.print_warning(f"Found URL fragment: {parsed_url.fragment} in {url}")
            
            # Check for interesting encodings
            encoded_chars = ['%', '\\u', '\\x', '\\0', '\\n', '\\r', '\\t']
            for char in encoded_chars:
                if char in url:
                    self.console.print_warning(f"Found encoded characters in URL: {url}")
                    break
            
            # Check for interesting patterns
            patterns = [
                (r'\d{4}', 'Year pattern'),
                (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP address'),
                (r'[a-fA-F0-9]{32,}', 'Hash pattern'),
                (r'[a-zA-Z0-9_-]{20,}', 'Long token pattern'),
                (r'[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}', 'JWT pattern')
            ]
            
            for pattern, description in patterns:
                if re.search(pattern, url):
                    self.console.print_warning(f"Found {description} in URL: {url}")
            
            self.console.print_debug(f"URL analysis completed for: {url}")
            
        except Exception as e:
            self.console.print_error(f"Error analyzing URL {url}: {e}")

    async def analyze_js(self, js_content: str) -> None:
        """Analyze JavaScript content for potential vulnerabilities and interesting patterns."""
        try:
            self.console.print_debug("Analyzing JavaScript content...")
            
            # Check for sensitive functions and APIs
            sensitive_functions = [
                'eval', 'Function', 'setTimeout', 'setInterval', 'document.write',
                'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.domain',
                'localStorage', 'sessionStorage', 'indexedDB', 'WebSocket',
                'XMLHttpRequest', 'fetch', 'navigator.sendBeacon'
            ]
            
            for func in sensitive_functions:
                if func in js_content:
                    self.console.print_warning(f"Found sensitive JavaScript function: {func}")
            
            # Check for potential XSS vectors
            xss_patterns = [
                r'document\.write\s*\(',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'insertAdjacentHTML\s*\(',
                r'eval\s*\(',
                r'Function\s*\(',
                r'setTimeout\s*\([^)]*function',
                r'setInterval\s*\([^)]*function'
            ]
            
            for pattern in xss_patterns:
                if re.search(pattern, js_content):
                    self.console.print_warning(f"Found potential XSS vector: {pattern}")
            
            # Check for sensitive data
            sensitive_patterns = [
                (r'password\s*[:=]', 'Password field'),
                (r'token\s*[:=]', 'Token field'),
                (r'api[_-]?key\s*[:=]', 'API key'),
                (r'secret\s*[:=]', 'Secret field'),
                (r'private[_-]?key\s*[:=]', 'Private key'),
                (r'jwt\s*[:=]', 'JWT token')
            ]
            
            for pattern, description in sensitive_patterns:
                if re.search(pattern, js_content, re.IGNORECASE):
                    self.console.print_warning(f"Found {description} in JavaScript")
            
            # Check for potential DOM-based vulnerabilities
            dom_patterns = [
                r'location\.hash',
                r'location\.search',
                r'location\.href',
                r'document\.URL',
                r'document\.documentURI',
                r'window\.name'
            ]
            
            for pattern in dom_patterns:
                if re.search(pattern, js_content):
                    self.console.print_warning(f"Found potential DOM-based vulnerability: {pattern}")
            
            # Check for potential prototype pollution
            if 'Object.prototype' in js_content or '__proto__' in js_content:
                self.console.print_warning("Found potential prototype pollution vector")
            
            # Check for potential deserialization
            if 'JSON.parse' in js_content or 'eval(' in js_content:
                self.console.print_warning("Found potential deserialization vector")
            
            self.console.print_debug("JavaScript analysis completed")
            
        except Exception as e:
            self.console.print_error(f"Error analyzing JavaScript content: {e}")

    async def analyze_dynamic_content(self, page: Page) -> None:
        """Analyze dynamic content and behavior of the page."""
        try:
            self.console.print_debug("Analyzing dynamic content...")
            
            # Check for dynamic content loading
            dynamic_patterns = [
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'insertAdjacentHTML\s*\(',
                r'document\.write\s*\(',
                r'appendChild\s*\(',
                r'insertBefore\s*\(',
                r'replaceChild\s*\(',
                r'insertAdjacentElement\s*\(',
                r'insertAdjacentText\s*\('
            ]
            
            # Check for dynamic event handlers
            event_patterns = [
                r'on\w+\s*=',
                r'addEventListener\s*\(',
                r'attachEvent\s*\(',
                r'\.on\s*\(',
                r'\.bind\s*\(',
                r'\.delegate\s*\(',
                r'\.live\s*\('
            ]
            
            # Check for dynamic script loading
            script_patterns = [
                r'createElement\s*\(\s*[\'"]script[\'"]',
                r'new\s+Script\s*\(',
                r'\.src\s*=\s*[\'"]',
                r'\.href\s*=\s*[\'"]',
                r'\.setAttribute\s*\(\s*[\'"]src[\'"]',
                r'\.setAttribute\s*\(\s*[\'"]href[\'"]'
            ]
            
            # Check for dynamic AJAX/Fetch calls
            ajax_patterns = [
                r'XMLHttpRequest\s*\(',
                r'fetch\s*\(',
                r'\.ajax\s*\(',
                r'\.get\s*\(',
                r'\.post\s*\(',
                r'\.put\s*\(',
                r'\.delete\s*\('
            ]
            
            # Check for dynamic iframe creation
            iframe_patterns = [
                r'createElement\s*\(\s*[\'"]iframe[\'"]',
                r'new\s+IFrame\s*\(',
                r'\.setAttribute\s*\(\s*[\'"]src[\'"]'
            ]
            
            # Check for dynamic form creation
            form_patterns = [
                r'createElement\s*\(\s*[\'"]form[\'"]',
                r'new\s+FormData\s*\(',
                r'\.submit\s*\(',
                r'\.reset\s*\('
            ]
            
            # Check for dynamic storage usage
            storage_patterns = [
                r'localStorage\s*\.',
                r'sessionStorage\s*\.',
                r'indexedDB\s*\.',
                r'\.cookie\s*=',
                r'\.setCookie\s*\(',
                r'\.getCookie\s*\('
            ]
            
            # Check for dynamic DOM manipulation
            dom_patterns = [
                r'querySelector\s*\(',
                r'querySelectorAll\s*\(',
                r'getElementById\s*\(',
                r'getElementsByClassName\s*\(',
                r'getElementsByTagName\s*\(',
                r'getElementsByName\s*\(',
                r'closest\s*\(',
                r'matches\s*\('
            ]
            
            # Combine all patterns
            all_patterns = {
                'Dynamic Content Loading': dynamic_patterns,
                'Event Handlers': event_patterns,
                'Script Loading': script_patterns,
                'AJAX/Fetch Calls': ajax_patterns,
                'Iframe Creation': iframe_patterns,
                'Form Creation': form_patterns,
                'Storage Usage': storage_patterns,
                'DOM Manipulation': dom_patterns
            }
            
            # Get page content
            content = await page.content()
            
            # Check each category of patterns
            for category, patterns in all_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content):
                        self.console.print_warning(f"Found {category} pattern: {pattern}")
            
            # Check for dynamic content in iframes
            iframes = await page.query_selector_all('iframe')
            for iframe in iframes:
                try:
                    frame = await iframe.content_frame()
                    if frame:
                        frame_content = await frame.content()
                        for category, patterns in all_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, frame_content):
                                    self.console.print_warning(f"Found {category} pattern in iframe: {pattern}")
                except Exception as e:
                    self.console.print_error(f"Error analyzing iframe content: {e}")
            
            # Check for dynamic content in shadow DOM
            shadow_hosts = await page.query_selector_all('*')
            for host in shadow_hosts:
                try:
                    shadow = await host.evaluate('el => el.shadowRoot')
                    if shadow:
                        shadow_content = await host.evaluate('el => el.shadowRoot.innerHTML')
                        for category, patterns in all_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, shadow_content):
                                    self.console.print_warning(f"Found {category} pattern in shadow DOM: {pattern}")
                except Exception as e:
                    continue  # Skip elements without shadow DOM
            
            self.console.print_debug("Dynamic content analysis completed")
            
        except Exception as e:
            self.console.print_error(f"Error analyzing dynamic content: {e}")

