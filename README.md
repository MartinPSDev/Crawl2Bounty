<img src="/assets/banner_v2.jpg" width="auto" height="5%" alt="banner image">

**CRAWL2BOUNTY** is an advanced web application security assessment tool designed to identify vulnerabilities and insecure configurations through crawling, dynamic analysis, and automated testing techniques. Its purpose is to assist pentesters and hunters in detecting exploitable flaws in websites.

## Main Components
- **AdvancedJSAnalyzer:**
Function: Analyzes the JavaScript code of web pages to detect sensitive variables, functions, and operations. It injects hooks into fetch, XMLHttpRequest, and WebSocket to monitor dynamic interactions.
Features: Modifies variables in real-time to test for anomalous behaviors and records database or storage operations.

- **AttackEngine:**
Function: Executes vulnerability tests such as SQL injections (SQLi), XSS, command injections (CMDi), SSTI, and directory traversal.
Features: Uses custom payloads, obfuscation to evade WAFs, and bypass techniques for 403 errors.

- **ConsoleManager:**
Function: Provides an enriched console interface with colors and formats using the rich library.
Features: Displays information, warnings, errors, and findings in a clear and structured manner.

- **SmartDetector:**
Function: Identifies interactive elements (buttons, forms, links) and applies WAF evasion techniques.
Features: User agent rotation, payload obfuscation, and advanced detection of standard and pseudo-forms.

- **TrafficAnalyzer:**
Function: Captures and analyzes network traffic during crawling and testing.
Features: Detects sensitive information in URLs, headers, and response bodies, and checks for missing security headers.

# General Functionality
- **Crawling**: Recursively navigates the web application, following links and detecting interactive elements.
- **JavaScript Analysis**: Examines dynamic code to find potential exploitation points.
- **Vulnerability Testing**: Conducts controlled attacks to detect common flaws.
- **Traffic Monitoring**: Analyzes requests and responses for sensitive data or insecure configurations.
- **WAF Evasion**: Implements identity rotation and obfuscation to avoid blocks.

The tool is initiated by providing a target URL. From there:
It performs crawling to map the application.
Analyzes JavaScript and tests dynamic modifications.
Executes vulnerability tests on endpoints and parameters.
Reports findings in real-time via the console.
Findings
Results are classified by type (e.g., sql_injection, xss_reflected) and severity (CRITICAL, HIGH, MEDIUM, LOW, INFO), including details such as affected URLs, payloads used, and steps to reproduce.

In summary, CRAWL2BOUNTY is a comprehensive tool that combines static and dynamic analysis to evaluate web application security, ideal for bug bounty environments or security audits.

<img src="/assets/help_.png" width="auto" height="5%" alt="banner image">

## 📦 **Installation**
To install the required dependencies, run:

```bash
pip install -r requirements.txt
```

## 🛠️ **Usage**
Run the scanner with the following command:

```bash
python crawl2bounty.py <target_url> [options]
```

## 📈 **Example** 

```bash
python3 crawl2bounty.py https://target.com  -v --depth 4  --rate-limit 5 -o results
```

## IMPORTANT

**Social media URLs or bots from Google, Bing, etc. are excluded so as not to go out of scope and start crawling through sites that aren't our target. If we want to analyze a social media ( Facebook, Instagram ,Tik Tok, X ) , Google, Yahoo, etc., we must include the -f or --force flag to remove URL restrictions.**

### Example:

```bash
python3 crawl2bounty.py https://instagram.com --force`
```

 

## 📜 **License**
This project is licensed under the MIT License - see the [LICENSE](path/to/your/license_file.md) file for details.

