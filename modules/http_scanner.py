import requests
import pprint

def normalize_url(target):
    if not target.startswith("http"):
        return "http://"+target
    return target

def fetch_headers(url):
    try:
        response=requests.get(url,timeout=5,allow_redirects=True)
        return response
    except Exception as e:
        print(f"[!] Error fetching URL: {e}")
        return None

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS",
    "Content-Security-Policy": "Prevents XSS",
    "X-Frame-Options": "Prevents Clickjacking",
    "X-XSS-Protection": "Enables XSS Filter",
    "X-Content-Type-Options": "Prevents MIME sniffing"
}

def analyze_security_headers(headers):
    findings={"missing":[],"present":[]}

    for header in SECURITY_HEADERS:
        if header in headers:
            findings["present"].append(header)
        else:
            findings["missing"].append(header)
    
    return findings

def fingerprint_tech(headers):
    tech = []
    server = headers.get("servers","")
    powered = headers.get("X-Powered-By","")

    if "apache" in server.lower():
        tech.append("Apache HTTP Server")
    if "nginx" in server.lower():
        tech.append("Nginx")
    if "cloudflare" in server.lower():
        tech.append("Cloudflare")
    if "php" in powered.lower():
        tech.append("PHP Backend")
    if "asp.net" in powered.lower():
        tech.append("ASP.NET Backend")
    if "express" in powered.lower():
        tech.append("Node.js Express")

    return tech

def version_detection(headers):
    leaks = {}
    for key, value in headers.items():
        if any(char.isdigit() for char in value):
            leaks[key] = value

    return leaks

def web_scan(target):
    url = normalize_url(target)
    print(f"[*] Fetching: {url}")

    response = fetch_headers(url)
    if not response:
        return None
    
    headers = dict(response.headers)

    print(f"[+] HTPP Status Code: ", response.status_code)
    print("\n[+] Server Header:")

    security = analyze_security_headers(headers)
    tech = fingerprint_tech(headers)
    leaks = version_detection(headers)
    ptr = {
        "status": response.status_code,
        "headers": headers,
        "security_headers": security,
        "tech_stack": tech,
        "version_leaks": leaks
    }
    for k,v in ptr.items():
        print(f"    {k}:{v}")
    return {
        "status": response.status_code,
        "headers": headers,
        "security_headers": security,
        "tech_stack": tech,
        "version_leaks": leaks
    }
