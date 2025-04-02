import asyncio
import os
import stat
from pathlib import Path
import random
import re
import json
import base64
import jsbeautifier
from typing import List, Dict, Any, Optional
import time

# Import ConsoleManager
from console_manager import ConsoleManager
from playwright.async_api import Page, Error as PlaywrightError


class AdvancedJSAnalyzer:
    def __init__(self, console_manager: ConsoleManager):
        self.console = console_manager
        # Internal list to store findings during analysis for a single page
        self._internal_findings: List[Dict[str, Any]] = []
        self.timeout = 30000 # Default timeout for JS evaluations (ms)

        self.console.print_debug("Initializing AdvancedJSAnalyzer...")

        # Consider making payloads configurable or loading from payloads.py
        self.cmd_injection_payloads = [
            "; id", "& dir", "| cat /etc/passwd", "$(id)", "`id`", "&& whoami", "|| hostname"
        ]

        # Working Directory Setup
        self.working_dir: Optional[Path] = None
        potential_dirs = [Path('/tmp/robot-hunter'), Path.home() / '.robot-hunter-advjs']
        for p_dir in potential_dirs:
            try:
                p_dir.mkdir(parents=True, exist_ok=True)
                # Test write permission (more reliable than just chmod)
                test_file = p_dir / f"test_{random.randint(1000,9999)}.tmp"
                test_file.write_text("test", encoding="utf-8")
                test_file.unlink() # Clean up test file
                self.working_dir = p_dir
                self.console.print_debug(f"AdvancedJSAnalyzer working directory set: {self.working_dir}")
                break # Stop after first successful directory
            except (PermissionError, OSError, Exception) as e:
                self.console.print_warning(f"Cannot use directory {p_dir}: {e}")

        if self.working_dir is None:
            self.console.print_error("Failed to set up a working directory for AdvancedJSAnalyzer. Some features might be disabled.")

        self.console.print_debug("AdvancedJSAnalyzer initialization complete")

    def _add_finding(self, type: str, severity: str, details: dict, url: str = ""):
        """Adds a finding to the internal list, prefixing type."""
        finding = {
            "type": f"js_dynamic_{type}", # Automatic prefix
            "severity": severity,
            "url": url,
            "details": details,
            "timestamp": time.time()
        }
        self._internal_findings.append(finding)
        # Defer printing to the main reporting phase? Or print now if desired?
        # self.console.print_finding(finding["type"], finding["severity"], details, url)


    # --- Error Handlers ---
    async def _handle_permission_error(self, error: Exception, context: Optional[dict] = None):
        self.console.print_error(f"Permission Error (JS Analysis Context): {error}")
        # Basic implementation, more context might be needed for fallbacks
        self.console.print_debug(f"Context: {context}")

    async def _handle_timeout_error(self, error: Exception, context: Optional[dict] = None):
        self.console.print_error(f"Timeout Error (JS Analysis Context): {error}")
        self.console.print_debug(f"Context: {context}")
        # Simple retry logic not implemented here, handled in run_analysis_with_retry

    async def _handle_network_error(self, error: Exception, context: Optional[dict] = None):
        self.console.print_error(f"Network Error (JS Analysis Context): {error}")
        self.console.print_debug(f"Context: {context}")

    # --- Analysis Orchestration ---
    async def run_analysis_with_retry(self, page: Page, max_retries: int = 1) -> Dict[str, List[Dict[str, Any]]]:
        """Runs the full analysis with retries, returning findings."""
        # Reduced default retries for heavy JS analysis
        for attempt in range(max_retries + 1):
            self._internal_findings = [] # Clear findings for this attempt
            try:
                self.console.print_info(f"Starting advanced JS analysis (Attempt {attempt + 1}/{max_retries + 1}) on {page.url}")
                await self.run_full_analysis(page) # This populates self._internal_findings
                self.console.print_success(f"Advanced JS analysis completed (Attempt {attempt + 1}). Found {len(self._internal_findings)} potential points.")
                return {"findings": self._internal_findings} # Return collected findings
            except PermissionError as e:
                self.console.print_warning(f"JS Analysis Permission Error (Attempt {attempt + 1}): {e}")
                await self._handle_permission_error(e, {'operation': 'analysis'})
                if attempt == max_retries: break # Exit after last attempt
            except PlaywrightError as pe:
                 # Handle potential page crashes or context issues
                 self.console.print_error(f"Playwright error during JS analysis (Attempt {attempt + 1}): {pe}")
                 if "crash" in str(pe).lower(): # Specific check for crash
                     self.console.print_error("Page potentially crashed during analysis. Stopping analysis for this page.")
                     return {"findings": self._internal_findings} # Return whatever found before crash
                 if attempt == max_retries: break
                 await asyncio.sleep(1.5 ** attempt) # Exponential backoff
            except Exception as e:
                self.console.print_error(f"General error during JS analysis (Attempt {attempt + 1}): {e}", fatal=False)
                self.console.console.print_exception(show_locals=self.console.verbose)
                if attempt == max_retries: break
                await asyncio.sleep(1.5 ** attempt)

        self.console.print_error("Max retries reached for advanced JS analysis.")
        return {"findings": self._internal_findings} # Return findings even if retries failed

    async def run_full_analysis(self, page: Page):
        """Orchestrates the advanced JS analysis steps on a single page."""
        # Ensure JS helper function is available
        js_selector_func = """ function generateCssSelector(el) { /* ... full code ... */ } """
        try:
            await page.evaluate(js_selector_func)
        except Exception as e:
             self.console.print_error(f"Failed to inject CSS selector helper for Adv JS: {e}")
             # Potentially skip parts requiring selectors?

        # 1. Setup Hooks (should only run once per page load implicitly via JS check)
        await self.setup_debugger(page)

        # 2. Analyze Variables (includes modification tests)
        await self.analyze_variables(page)
        await asyncio.sleep(0.5) # Allow async errors to surface

        # 3. Analyze DB Connections/Ops from JS context
        await self.analyze_db_connections(page)
        await asyncio.sleep(0.2)

        # 4. Trace Execution for *a few* important-looking elements
        await self.trace_limited_interactions(page)

        # 5. Forms analysis is likely better handled by crawler/attack engine

        self.console.print_debug(f"Finished advanced JS analysis steps for {page.url}")
        # Findings are added to self._internal_findings by helper methods


    # --- JS Debugger/Instrumentation Setup ---
    async def setup_debugger(self, page: Page):
        """Configures the JS environment by injecting hooks."""
        self.console.print_debug("Setting up JS debugger hooks...")
        # This complex JS blob contains the core instrumentation logic
        js_hooks_code = """
            (function() {
                const originalFetch = window.fetch;
                const originalXHR = window.XMLHttpRequest;
                const originalWebSocket = window.WebSocket;
                
                // Hook para fetch
                window.fetch = async function(url, options) {
                    try {
                        const response = await originalFetch(url, options);
                        const clone = response.clone();
                        const data = await clone.text();
                        console.log('[RH] Fetch:', {url, options, data});
                        return response;
                    } catch (e) {
                        console.error('[RH] Fetch Error:', e);
                        throw e;
                    }
                };
                
                // Hook para XMLHttpRequest
                window.XMLHttpRequest = function() {
                    const xhr = new originalXHR();
                    const originalOpen = xhr.open;
                    const originalSend = xhr.send;
                    
                    xhr.open = function(method, url) {
                        console.log('[RH] XHR Open:', {method, url});
                        return originalOpen.apply(this, arguments);
                    };
                    
                    xhr.send = function(data) {
                        console.log('[RH] XHR Send:', {data});
                        return originalSend.apply(this, arguments);
                    };
                    
                    return xhr;
                };
                
                // Hook para WebSocket
                window.WebSocket = function(url, protocols) {
                    console.log('[RH] WebSocket:', {url, protocols});
                    return new originalWebSocket(url, protocols);
                };
            })();
        """
        try:
            await page.evaluate(js_hooks_code)
            self.console.print_debug("JS debugger hooks injected successfully.")
        except PlaywrightError as e:
             self.console.print_error(f"Failed to setup JS debugger hooks: {e}")
             # Propagate error? Analysis might be severely limited.
             raise
        except Exception as e:
             self.console.print_error(f"Unexpected error setting up JS debugger: {e}")
             raise


    # --- Analysis Methods ---
    async def analyze_variables(self, page: Page):
        """Retrieves instrumented variable data and records findings."""
        self.console.print_debug("Analyzing JS variables...")
        page_url = page.url
        try:
            # Get data collected by the injected hooks
            collected_data = await page.evaluate("""
                () => window.__debugData ? {
                    singleCharVars: window.__debugData.singleCharVars || {},
                    callGraph: window.__debugData.callGraph || {}
                    // Dont retrieve modifiedVars/errors here, get them after modification tests
                } : {}
            """)

            # Record findings based on initial analysis
            for var_name, info in collected_data.get('singleCharVars', {}).items():
                if info.get('usageCount', 0) > 0 or len(info.get('methodCalls', [])) > 0:
                    self._add_finding("active_single_char_var", "MEDIUM", {
                        "name": var_name, "var_type": info.get('type'), "usage_count": info.get('usageCount', 0),
                        "method_calls_count": len(info.get('methodCalls', [])),
                    }, page_url)

            for caller, callees in collected_data.get('callGraph', {}).items():
                 # Limit noise from common framework/browser internal calls
                 if "playwright" in caller or "zone.js" in caller or "react" in caller or "angular" in caller: continue

                 suspicious_keywords = ['ajax', 'fetch', 'http', 'post', 'send', 'submit', 'request', 'query', 'param', 'token', 'auth', 'key', 'secret', 'password', 'storage', 'cookie', 'eval', 'vulnerable']
                 caller_lower = caller.lower()
                 callee_str = ', '.join(callees).lower()
                 if any(keyword in caller_lower for keyword in suspicious_keywords) or any(keyword in callee_str for keyword in suspicious_keywords):
                          self._add_finding("suspicious_call_chain", "MEDIUM", {
                              "caller_preview": caller[:250], # Limit length
                              "callees": callees,
                              "details": "Potentially sensitive function call chain detected."
                          }, page_url)

            # --- Modification Test Section ---
            # Identify candidates for modification (used objects/functions)
            candidates = []
            initial_vars = await page.evaluate("() => window.__debugData ? window.__debugData.singleCharVars : {}")
            for var_name, info in initial_vars.items():
                 if info and info.get('type') in ['object', 'function'] and info.get('usageCount', 0) > 0:
                      candidates.append((var_name, info))

            # Modify a small, random subset
            max_vars_to_test = 2 # Limit modification attempts aggressively
            vars_to_test = random.sample(candidates, min(len(candidates), max_vars_to_test))

            if vars_to_test:
                self.console.print_info(f"Attempting modification tests on {len(vars_to_test)} JS variables: {[v[0] for v in vars_to_test]}")
                mod_tasks = [self._modify_and_test_variable(page, var_name, info) for var_name, info in vars_to_test]
                await asyncio.gather(*mod_tasks) # Run modification tests

                # --- Capture Post-Modification State ---
                self.console.print_debug("Checking for errors after variable modifications...")
                await asyncio.sleep(1.0) # Allow time for side effects / async errors

                post_mod_data = await page.evaluate("""
                    () => window.__debugData ? {
                         modifiedVars: window.__debugData.modifiedVars || {},
                         errors: window.__debugData.errors || []
                    } : {}
                """)
                last_errors = post_mod_data.get('errors', [])

                # Check modifiedVars for direct errors during modification attempt
                for var_name, mod_info in post_mod_data.get('modifiedVars', {}).items():
                     if mod_info.get('error') and not any(f['details'].get('name') == var_name and 'during controlled modification' in f['details'].get('details','') for f in self._internal_findings): # Avoid double report
                          self._add_finding("var_modification_error", "HIGH", {
                              "name": var_name, "error": mod_info['error'],
                              "details": "Error during controlled modification attempt."
                          }, page_url)

                # Check general errors that occurred *after* modifications might have started (crude check)
                # This needs a baseline error count before modification tests run. Difficult state to manage perfectly.
                # Simplification: Look for errors logged *around* the modification time. Needs timestamp passing.
                # This part is omitted due to complexity of reliable async error attribution.

            else:
                self.console.print_debug("No suitable JS variables found for modification testing.")


        except PlaywrightError as e:
             self.console.print_error(f"Error during JS variable analysis on {page.url}: {e}")
        except Exception as e:
             self.console.print_error(f"Unexpected error during JS variable analysis on {page.url}: {e}")

    async def _modify_and_test_variable(self, page: Page, var_name: str, info: Dict):
        """Internal helper for the modification logic, run via evaluate."""
        # Logic remains largely the same as the last correct implementation, ensuring it uses self.console and interacts with __debugData
        page_url = page.url
        self.console.print_debug(f"Running modification test script for var '{var_name}'...")

        # Use varied payloads
        test_payloads = ["'", "<script>alert('rh_mod_xss')</script>", "' OR 1=1 --", "{{7*7}}", random.choice(self.cmd_injection_payloads), "file:///etc/passwd", None, True, 0]
        payload_to_use = random.choice(test_payloads)
        payload_str = str(payload_to_use)[:50] # Preview for logging

        # Use evaluate to execute modification within page context
        # The JS inside evaluate modifies window.__debugData.modifiedVars[varName]
        await page.evaluate("""
            async ([varName, payload]) => { // Pass as array
                const debugData = window.__debugData || {};
                if (!debugData.modifiedVars) debugData.modifiedVars = {};
                const modInfo = { modified: false, error: null, timestamp: Date.now() }; // Record start time
                debugData.modifiedVars[varName] = modInfo;

                try {
                    const target = window[varName];
                    if (typeof target === 'object' && target !== null) {
                        const propToModify = Object.keys(target)[0] || 'rh_test_prop';
                        modInfo.action = `Assigned to property '${propToModify}'`;
                        target[propToModify] = payload;
                        modInfo.modified = true;
                    } else if (typeof target === 'function') {
                         modInfo.action = `Called function`;
                         target(payload); // Simplistic call
                         modInfo.modified = true;
                    } else {
                         modInfo.action = `Attempted reassignment (likely no effect)`;
                         // Cannot reliably reassign primitives in window scope via evaluate
                         modInfo.modified = false; // Mark as not effectively modified
                    }
                } catch (e) {
                    modInfo.error = e.toString();
                    modInfo.stack = e.stack; // Capture stack if available
                    console.error(`[RH_AdvJS] Error during modification test of ${varName}:`, e);
                }
                // Update status in debugData (accessible by later evaluate calls)
                 debugData.modifiedVars[varName] = modInfo;
            }
        """, [var_name, payload_to_use]) # Pass args as array

        self.console.print_debug(f"Modification script executed for '{var_name}' with payload preview: '{payload_str}...'. Check for errors.")
        # Error checking happens *after* all modifications in analyze_variables


    # --- Other Analysis Methods ---
    async def trace_limited_interactions(self, page: Page):
        """Traces 1-2 high-priority interactions detected."""
        self.console.print_info("Tracing limited interactions...")
        try:
            # Use SmartDetector's logic to find elements, but within AdvJS context
            # This feels redundant. Prefer crawler's interaction tracing.
            # If needed, re-implement element detection here or get selectors from crawler.
            # For now, skip detailed tracing here to avoid duplication.
            self.console.print_debug("Interaction tracing skipped in AdvancedJSAnalyzer to avoid duplicating crawler logic.")
            # Example: If you *did* want to trace here:
            # detector = SmartDetector(self.console) # Need detector instance or pass selectors
            # elements = await detector.detect_interactive_elements(page)
            # count = 0
            # for elem_data in elements[:2]: # Trace top 2
            #      if elem_data.get('selector'):
            #          await self.trace_function_execution(page, elem_data['selector'])
            #          count += 1
            # self.console.print_debug(f"Traced {count} interactions.")

        except Exception as e:
             self.console.print_error(f"Error during limited interaction tracing: {e}")


    async def trace_function_execution(self, page: Page, selector_to_click: str):
        """Analyzes changes caused by clicking. (Refactored Log Only)"""
        # This duplicates the main crawler interaction loop's analysis.
        # Focus this module on JS variable/hook analysis, not general interaction tracing.
        # Keep the logic if absolutely needed, but simplify.
        self.console.print_warning(f"Skipping redundant trace_function_execution for {selector_to_click} within AdvancedJSAnalyzer.")


    async def analyze_db_connections(self, page: Page):
        """Retrieves DB/Storage operation info from JS context."""
        self.console.print_debug("Analyzing DB/Storage operations from JS context...")
        page_url = page.url
        try:
            # Fetch all relevant data points captured by hooks
            hook_data = await page.evaluate("""
                () => window.__debugData ? {
                     dbOps: window.__debugData.dbOperations || [],
                     storageEvents: window.__debugData.storageEvents || []
                 } : {}
            """)

            for operation in hook_data.get('dbOps', []):
                 # Filter operation types for reporting
                 op_type = operation.get('type', 'unknown_db_op')
                 severity = "HIGH" if op_type == 'db_like_data_read' else "MEDIUM" if op_type == 'db_connection' else "INFO"
                 self._add_finding(op_type, severity, {
                     "name": operation.get('name'),
                     "operation_details": operation.get('operation'),
                     "url_context": operation.get('url'),
                     "data_preview": str(operation.get('dataPreview') or operation.get('data'))[:100]+"..."
                 }, page_url)

            for event in hook_data.get('storageEvents', []):
                 self._add_finding("storage_access", "LOW", {
                      "storage_type": event.get('storage'),
                      "action": event.get('method'),
                      "key": event.get('key'),
                      "value_preview": event.get('value', '')[:100] + ('...' if len(event.get('value','')) > 100 else ''),
                      # "stack": event.get('stack') # Too verbose
                 }, page_url)

        except PlaywrightError as e:
             self.console.print_error(f"Error analyzing DB/Storage operations: {e}")
        except Exception as e:
             self.console.print_error(f"Unexpected error analyzing DB/Storage operations: {e}")