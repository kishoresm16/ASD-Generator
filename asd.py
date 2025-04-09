import whois
import dns.resolver
from wappalyzer import Wappalyzer, WebPage
import requests
from colorama import Fore, Style, init

# 🎨 Colorama Init
init(autoreset=True)

# 📧 Email Security Records Lookup
def email_sec(domain):
    spf_record = None
    dmarc_record = None
    dkim_records = []

    try:
        text_records = dns.resolver.resolve(domain, 'TXT')
        for record in text_records:
            record_str = record.to_text().strip('"')
            if record_str.startswith("v=spf1"):
                spf_record = record_str
            elif record_str.startswith("v=DMARC1"):
                dmarc_record = record_str
            elif "dkim" in record_str.lower():
                dkim_records.append(record_str)
    except Exception as e:
        return {"Error": f"Email Security Record Lookup failed: {e}"}

    return {
        "SPF": spf_record or "Not Found",
        "DMARC": dmarc_record or "Not Found",
        "DKIM": dkim_records if dkim_records else ["Not Found"]
    }

# 🧠 Detect Tech Stack
def tech_stack(domain):
    try:
        url = f"https://{domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        response = requests.get(url, headers=headers, timeout=10)
        webpage = WebPage.new_from_response(response)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze(webpage)
        return technologies
    except Exception as e:
        return [f"Tech Stack Detection failed: {e}"]

# 🤩 WHOIS Info Function
def whois_info(domain):
    try:
        info = whois.whois(domain)
        return {
            "Domain_Name": info.domain_name,
            "Registrar": info.registrar,
            "Creation_date": str(info.creation_date),
            "Expiration_date": str(info.expiration_date),
            "Name_servers": info.name_servers
        }
    except Exception as e:
        return {"Error": f"WHOIS Error: {e}"}

# 📬 MX Record Lookup
def dns_mx(domain):
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        mx_records = []
        for record in mx:
            mx_records.append(record.to_text())
        return mx_records
    except Exception as e:
        return [f"MX Lookup Error: {e}"]

# 🛡️ Security Header Check
def security_headers_check(domain):
    url = domain
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=10)

        security_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection"
        ]

        missing = []

        print(f"\n{Fore.CYAN}[!] Checking Security Headers for {url} ...")
        print(Fore.CYAN + "*" * 50)

        for header in security_headers:
            if header not in response.headers:
                missing.append(header)

        if missing:
            print(f"\n{Fore.YELLOW}[!] Missing Security Headers:")
            for m in missing:
                print(f"{Fore.RED} - {m}")
        else:
            print(f"\n{Fore.GREEN}[+] All recommended headers are set!")

    except Exception as e:
        print(f"\n{Fore.MAGENTA}[!] Error: {e}")

# 🌐 CORS Misconfiguration Check
def check_cors(domain):
    try:
        url = f"https://{domain}"
        headers = {
            "Origin": "https://evil.com"
        }

        response = requests.get(url, headers=headers, timeout=10)

        cors_header = response.headers.get("Access-Control-Allow-Origin")
        cors_creds = response.headers.get("Access-Control-Allow-Credentials")

        result = {
            "URL": url,
            "Access-Control-Allow-Origin": cors_header or "Not Present",
            "Access-Control-Allow-Credentials": cors_creds or "Not Present",
            "Vulnerable": False
        }

        if cors_header == "https://evil.com":
            if cors_creds == "true":
                result["Vulnerable"] = True
                result["Severity"] = "High (Credentials + Origin Reflection)"
            else:
                result["Vulnerable"] = True
                result["Severity"] = "Medium (Origin Reflection)"

        return result

    except Exception as e:
        return {"Error": f"CORS check failed: {e}"}

# 🚀 Main Recon Function
def run_recon():
    domain = input("🔍 Enter a domain name (e.g., example.com): ").strip()

    print(f"\n[ WHOIS INFO for {domain} ]")
    print("=" * 40)
    whois_data = whois_info(domain)
    for key, value in whois_data.items():
        print(f"{key}: {value}")

    print(f"\n[ MX RECORDS for {domain} ]")
    print("=" * 40)
    mx_records = dns_mx(domain)
    for record in mx_records:
        print(record)

    print(f"\n[ TECHNOLOGY STACK for {domain} ]")
    print("=" * 40)
    tech = tech_stack(domain)
    for t in tech:
        print(f" - {t}")

    print(f"\n[ EMAIL SECURITY RECORDS for {domain} ]")
    print("=" * 40)
    email_security = email_sec(domain)
    for key, value in email_security.items():
        if isinstance(value, list):
            for v in value:
                print(f"{key}: {v}")
        else:
            print(f"{key}: {value}")

    print(f"\n[ SECURITY HEADERS for {domain} ]")
    print("=" * 40)
    security_headers_check(domain)

    print(f"\n[ CORS CONFIGURATION for {domain} ]")
    print("=" * 40)
    cors_result = check_cors(domain)
    for key, value in cors_result.items():
        if cors_result.get("Vulnerable") and key == "Severity":
            print(f"{Fore.RED}{key}: {value}")
        else:
            print(f"{key}: {value}")

# 🔁 Keep Running Until User Exits
if __name__ == "__main__":
    while True:
        run_recon()
        again = input("\n🔁 Check another domain? (y/n): ").lower()
        if again != 'y':
            print("👋 Exiting...")
            break
