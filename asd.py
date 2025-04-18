import whois
import dns.resolver
from wappalyzer import WebPage, Wappalyzer
import requests
from colorama import Fore, Style, init
import socket
import ssl
import concurrent.futures
from urllib.parse import urlparse
import time
import urllib3
from datetime import datetime, timezone
import warnings
import re
import subprocess
from bs4 import BeautifulSoup
from urllib.parse import urljoin
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
from shodan_scanner import run_shodan_scan

# Suppress Wappalyzer warning
warnings.filterwarnings("ignore", category=UserWarning, module="wappalyzer")

# Initialize colorama
init(autoreset=True)

API_KEY_PATTERNS = [
    # AWS S3 Bucket URLs
    r'https:\/\/s3\.amazonaws\.com\/[a-zA-Z0-9\-\.\/]+',
    r'AKIA[0-9A-Z]{16}',
    r'(?<=AWS_SECRET_ACCESS_KEY\s*=\s*)[A-Za-z0-9/+=]{40}',
    r'AIza[0-9A-Za-z-_]{35}',
    r'sk_live_[0-9a-zA-Z]{24}',
    r'pk_live_[0-9a-zA-Z]{24}',
    r'AKIA[0-9A-Z]{16}',
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    r'SECRET_KEY\s*=\s*[\'"][A-Za-z0-9_\-+=!@#$%^&*()]{16,}[\'"]',
    r'APP_SECRET\s*=\s*[\'"][A-Za-z0-9_\-+=!@#$%^&*()]{16,}[\'"]',
    r'jwt_secret\s*=\s*[\'"][A-Za-z0-9_\-+=!@#$%^&*()]{16,}[\'"]',
    r'apiKey\s*[:=]\s*[\'"]AIza[0-9A-Za-z-_]{35}[\'"]',
    r'authDomain\s*[:=]\s*[\'"][^\'"]+firebaseapp\.com[\'"]',
    r'projectId\s*[:=]\s*[\'"][^\'"]+[\'"]',
    r'storageBucket\s*[:=]\s*[\'"][^\'"]+appspot\.com[\'"]',
    r'messagingSenderId\s*[:=]\s*[\'"][0-9]{6,}[\'"]',
    r'appId\s*[:=]\s*[\'"][0-9a-z:-]{20,}[\'"]',
    r'password\s*=\s*[\'"][^\'"]{6,}[\'"]',
    r'db_password\s*=\s*[\'"][^\'"]{6,}[\'"]',
    r'DB_PASS\s*=\s*[\'"][^\'"]{6,}[\'"]',
    r'mysql_password\s*=\s*[\'"][^\'"]{6,}[\'"]',
    r'postgres_password\s*=\s*[\'"][^\'"]{6,}[\'"]',
    r'DATABASE_PASSWORD\s*=\s*[\'"][^\'"]{6,}[\'"]',
    r'-----BEGIN OPENSSH PRIVATE KEY-----',
    r'-----BEGIN RSA PRIVATE KEY-----',
    r'ghp_[A-Za-z0-9]{36}',
    r'gho_[A-Za-z0-9]{36}',
    r'ghu_[A-Za-z0-9]{36}',
    r'ghr_[A-Za-z0-9]{36}',
    r'EAACEdEose0cBA[0-9A-Za-z]+',
    r'EAA[a-zA-Z0-9]{20,}',
    r'pat-[a-f0-9\-]{36}',
    r'hapikey\s*=\s*[\'"][a-z0-9\-]{20,}[\'"]',
    r'hubspot.key\s[:=]\s*[\'"][a-z0-9\-]{20,}[\'"]',
    r'AccountKey\s*=\s*[A-Za-z0-9+/=]{20,}',
    r'sharedaccesssignature\s*=\s*[A-Za-z0-9%]{30,}',
    r'ClientSecret\s*[:=]\s*[\'"][A-Za-z0-9\-._~+/]{20,}[\'"]',
    r'([a-zA-Z0-9_-]{32,})'
]

class SubfinderWrapper:
    def __init__(self, binary_path="subfinder", debug=False):
        self.binary_path = binary_path
        self.debug = debug

    def _debug_print(self, message):
        if self.debug:
            print(f"{Fore.BLUE}[DEBUG] {message}")

    def find_subdomains(self, domain, silent=False, timeout=None):
        """
        Find subdomains for a given domain using subfinder
        """
        command = [self.binary_path, "-d", domain]
        if silent:
            command.append("-silent")
            
        try:
            process = subprocess.run(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                universal_newlines=True,
                timeout=timeout
            )
            
            if process.returncode != 0:
                print(f"{Fore.RED}[-] Error running subfinder: {process.stderr}")
                return []
            
            self._debug_print(f"Subfinder stderr: {process.stderr}")
            
            subdomains = [line.strip() for line in process.stdout.strip().split('\n') if line.strip()]
            self._debug_print(f"Found {len(subdomains)} subdomains")
            return subdomains
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Timeout expired while running subfinder")
            return []
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Error: subfinder binary not found at {self.binary_path}")
            return []
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {str(e)}")
            return []

def generate_typosquatting_variants(domain):
    """
    Generate typosquatting variants for a domain, including:
    - Single character deletion (e.g., example.com -> xample.com)
    - Character substitution (e.g., example.com -> examp1e.com)
    - Character addition (e.g., example.com -> exammple.com)
    - Character swaps (e.g., example.com -> exmaple.com)
    """
    if "." not in domain:
        return []
    
    base, tld = domain.rsplit(".", 1)
    variants = set()  # Use set to avoid duplicates
    
    # Deletion: Remove one character
    for i in range(len(base)):
        typo = base[:i] + base[i+1:]
        if typo and typo != base:
            variants.add(f"{typo}.{tld}")
    
    # Substitution: Replace characters with common alternatives
    substitutions = {
        'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'l': ['1'], 
        'o': ['0'], 's': ['5', '$'], 't': ['7']
    }
    for i in range(len(base)):
        char = base[i].lower()
        if char in substitutions:
            for sub in substitutions[char]:
                typo = base[:i] + sub + base[i+1:]
                variants.add(f"{typo}.{tld}")
    
    # Addition: Insert common characters
    for i in range(len(base) + 1):
        for char in ['a', 'e', 'l', 'm', 'n', 'o', 'p']:
            typo = base[:i] + char + base[i:]
            variants.add(f"{typo}.{tld}")
    
    # Swap: Swap adjacent characters
    for i in range(len(base) - 1):
        typo = base[:i] + base[i+1] + base[i] + base[i+2:]
        variants.add(f"{typo}.{tld}")
    
    # Cap at 500 variants to avoid excessive queries
    return list(variants)[:500]

def check_typosquatting_domain(typo, timeout=5):
    """
    Check if a typosquatted domain is active via DNS and HTTP
    """
    result = {
        "domain": typo,
        "dns_status": None,
        "ips": [],
        "http_status": None,
        "error": None
    }
    
    # DNS resolution check
    try:
        answers = dns.resolver.resolve(typo, 'A')
        result["ips"] = [rdata.to_text() for rdata in answers]
        result["dns_status"] = "Active"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["dns_status"] = "Inactive"
        return result
    except dns.resolver.NoNameservers:
        result["error"] = "No nameservers found"
        return result
    except Exception as e:
        result["error"] = f"DNS error: {str(e)}"
        return result
    
    # HTTP status check (optional, only if DNS resolves)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    for scheme in ["https", "http"]:
        url = f"{scheme}://{typo}"
        try:
            response = requests.get(url, timeout=timeout, headers=headers, verify=False, allow_redirects=True)
            result["http_status"] = response.status_code
            break
        except requests.RequestException:
            continue
    
    return result

def check_typosquatting_domains(domain, max_workers=10):
    """
    Check for active typosquatted domains in parallel
    """
    print(f"\n{Fore.CYAN}[*] Checking typosquatting for {domain}...")
    typos = generate_typosquatting_variants(domain)
    if not typos:
        print(f"{Fore.YELLOW}[-] No typosquatting variants generated.")
        return []
    
    print(f"{Fore.CYAN}[*] Generated {len(typos)} typosquatting variants")
    results = []
    
    print(f"{'Domain':<40} {'DNS Status':<15} {'HTTP Status':<15} {'IPs'}")
    print("=" * 80)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_typo = {executor.submit(check_typosquatting_domain, typo): typo for typo in typos}
        
        for future in concurrent.futures.as_completed(future_to_typo):
            try:
                result = future.result()
                domain = result["domain"]
                dns_status = result["dns_status"]
                http_status = str(result["http_status"]) if result["http_status"] else "-"
                ips = ", ".join(result["ips"]) if result["ips"] else "-"
                
                if result["error"]:
                    print(f"{Fore.YELLOW}{domain:<40} {dns_status or 'Failed':<15} {http_status:<15} {ips} (Error: {result['error']})")
                elif result["dns_status"] == "Active":
                    print(f"{Fore.GREEN}{domain:<40} {dns_status:<15} {http_status:<15} {ips}")
                else:
                    print(f"{Fore.RED}{domain:<40} {dns_status:<15} {http_status:<15} {ips}")
                
                results.append(result)
            except Exception as e:
                typo = future_to_typo[future]
                print(f"{Fore.RED}{typo:<40} Failed:<15 -:<15> - (Error: {str(e)})")
                results.append({
                    "domain": typo,
                    "dns_status": "Failed",
                    "ips": [],
                    "http_status": None,
                    "error": str(e)
                })
    
    active_count = len([r for r in results if r["dns_status"] == "Active"])
    print(f"\n{Fore.CYAN}[*] Typosquatting Summary:")
    print(f"{Fore.GREEN}[+] Active typosquatted domains: {active_count}")
    print(f"{Fore.RED}[-] Inactive or failed checks: {len(results) - active_count}")
    
    return results

def get_ips_from_domain(domain):
    """
    Resolve all A records for a domain
    """
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips = [rdata.to_text() for rdata in answers]
        return list(set(ips))  # Deduplicate IPs
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        print(f"{Fore.YELLOW}[!] Could not resolve IPs for {domain}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[!] DNS error for {domain}: {str(e)}")
        return []

def get_cohosted_domains(ip):
    """
    Fetch co-hosted domains for a given IP using HackerTarget API
    """
    print(f"{Fore.CYAN}[*] Fetching co-hosted domains for IP: {ip}")
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()  # Raise for 4xx/5xx errors
        
        text = response.text.strip()
        if not text:
            print(f"{Fore.YELLOW}[!] Empty response for IP {ip}")
            return []
        if "error" in text.lower() or "no record" in text.lower():
            print(f"{Fore.YELLOW}[!] API error for IP {ip}: {text}")
            return []
        
        domains = [d.strip() for d in text.split("\n") if d.strip()]
        return list(set(domains))  # Deduplicate domains
    except requests.HTTPError as e:
        status_code = e.response.status_code
        if status_code == 429:
            print(f"{Fore.RED}[!] Rate limit exceeded for IP {ip} (HTTP 429)")
        else:
            print(f"{Fore.RED}[!] HTTP error for IP {ip}: {status_code}")
        return []
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Request failed for IP {ip}: {str(e)}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error for IP {ip}: {str(e)}")
        return []

def check_cohosted_domains(domain, active_subdomains, max_workers=10):
    """
    Check co-hosted domains for the main domain and active subdomains' IPs
    """
    print(f"\n{Fore.CYAN}[*] Checking co-hosted domains for {domain} and subdomains...")
    results = []
    
    # Get IPs for main domain
    main_ips = get_ips_from_domain(domain)
    domains_to_check = [(domain, main_ips)]
    
    # Get IPs for active subdomains
    for subdomain, _ in active_subdomains:
        sub_ips = get_ips_from_domain(subdomain)
        domains_to_check.append((subdomain, sub_ips))
    
    # Deduplicate IPs across all domains
    all_ips = set()
    for _, ips in domains_to_check:
        all_ips.update(ips)
    
    if not all_ips:
        print(f"{Fore.YELLOW}[!] No IPs resolved for {domain} or its subdomains")
        return results
    
    print(f"{Fore.CYAN}[*] Checking {len(all_ips)} unique IPs")
    print(f"{'IP':<16} {'Source Domain':<40} {'Co-hosted Domains'}")
    print("=" * 80)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(get_cohosted_domains, ip): ip for ip in all_ips}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                cohosted = future.result()
                # Find which domains resolved to this IP
                source_domains = [d for d, ips in domains_to_check if ip in ips]
                source_str = ", ".join(source_domains)
                
                if cohosted:
                    print(f"{Fore.GREEN}{ip:<16} {source_str:<40} {len(cohosted)} domains: {', '.join(cohosted[:3])}{'...' if len(cohosted) > 3 else ''}")
                else:
                    print(f"{Fore.YELLOW}{ip:<16} {source_str:<40} None")
                
                results.append({
                    "ip": ip,
                    "source_domains": source_domains,
                    "cohosted_domains": cohosted
                })
            except Exception as e:
                source_domains = [d for d, ips in domains_to_check if ip in ips]
                source_str = ", ".join(source_domains)
                print(f"{Fore.RED}{ip:<16} {source_str:<40} Error: {str(e)}")
                results.append({
                    "ip": ip,
                    "source_domains": source_domains,
                    "cohosted_domains": [],
                    "error": str(e)
                })
    
    total_cohosted = sum(len(r["cohosted_domains"]) for r in results)
    print(f"\n{Fore.CYAN}[*] Co-hosted Domains Summary:")
    print(f"{Fore.GREEN}[+] IPs checked: {len(all_ips)}")
    print(f"{Fore.GREEN}[+] Total co-hosted domains found: {total_cohosted}")
    
    return results

def check_domain_status(domain, timeout=5):
    """
    Check if a domain is active by making an HTTP request
    """
    is_active = False
    status_code = None
    error_msg = None
    
    if not domain.startswith(('http://', 'https://')):
        url_http = f"http://{domain}"
        url_https = f"https://{domain}"
    else:
        parsed = urlparse(domain)
        url_http = f"http://{parsed.netloc}"
        url_https = f"https://{parsed.netloc}"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        response = requests.get(
            url_https, 
            timeout=timeout, 
            allow_redirects=True, 
            verify=False,
            headers=headers
        )
        status_code = response.status_code
        is_active = True
        return domain, status_code, is_active, None
    except requests.RequestException as e:
        error_msg = str(e)
        try:
            response = requests.get(
                url_http, 
                timeout=timeout, 
                allow_redirects=True,
                headers=headers
            )
            status_code = response.status_code
            is_active = True
            return domain, status_code, is_active, None
        except requests.RequestException as e:
            error_msg = str(e)
            return domain, status_code, is_active, error_msg

def check_domains_status(domains, max_workers=10, timeout=5):
    """
    Check multiple domains status in parallel
    """
    active_domains = []
    inactive_domains = []
    
    if not domains:
        print(f"{Fore.YELLOW}[!] No domains found to check status.")
        return {"active": [], "inactive": []}
    
    print(f"\n{Fore.CYAN}[+] Checking status for {len(domains)} domains...")
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(check_domain_status, domain, timeout): domain 
            for domain in domains
        }
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_domain)):
            try:
                domain, status_code, is_active, error_msg = future.result()
                if is_active:
                    active_domains.append((domain, status_code))
                    print(f"{Fore.GREEN}[+] Active [{status_code}]: {domain}")
                else:
                    inactive_domains.append((domain, error_msg or "No response"))
                    print(f"{Fore.RED}[-] Inactive: {domain}")
                
                progress = (i + 1) / len(domains) * 100
                if (i + 1) % 5 == 0 or (i + 1) == len(domains):
                    print(f"{Fore.CYAN}[*] Progress: {i + 1}/{len(domains)} ({progress:.1f}%)")
            except Exception as exc:
                domain = future_to_domain[future]
                print(f"{Fore.RED}[-] Inactive: {domain}")
                inactive_domains.append((domain, str(exc)))
    
    elapsed_time = time.time() - start_time
    print(f"\n{Fore.CYAN}[*] Domain status check completed in {elapsed_time:.2f} seconds")
    print(f"{Fore.GREEN}[+] Active domains: {len(active_domains)}")
    print(f"{Fore.RED}[-] Inactive domains: {len(inactive_domains)}")
    
    return {
        "active": active_domains,
        "inactive": inactive_domains
    }

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

def tech_stack(domain):
    """
    Analyze the technology stack of a domain using Wappalyzer, including versions if exposed.
    """
    try:
        url = f"https://{domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        webpage = WebPage.new_from_response(response)
        wappalyzer = Wappalyzer.latest()
        
        tech_data = wappalyzer.analyze_with_versions_and_categories(webpage)
        
        tech_with_versions = []
        for tech, details in tech_data.items():
            name = tech
            versions = details.get('versions', [])
            version_str = ', '.join(versions) if versions else None
            if version_str:
                tech_with_versions.append(f"{name} ({version_str})")
            else:
                tech_with_versions.append(name)
        
        return tech_with_versions if tech_with_versions else ["No technologies detected"]
    except Exception as e:
        return [f"Tech Stack Detection failed: {str(e)}"]

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

def dns_mx(domain):
    results = []
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for record in mx_records:
            mx_domain = str(record.exchange).rstrip('.')
            try:
                ip = socket.gethostbyname(mx_domain)
                results.append(f"{mx_domain} -> {ip} (MX Active)")
            except Exception:
                results.append(f"{mx_domain} -> IP Not Resolved (MX Active)")
    except Exception as e:
        results.append(f"MX Lookup Error: {e}")
    return results

def security_headers_check(domain):
    """
    Check security headers for a single domain and return results
    """
    url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    security_headers = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection"
    ]
    
    try:
        response = requests.get(url, timeout=10, headers=headers, verify=False, allow_redirects=True)
        missing = [header for header in security_headers if header not in response.headers]
        status = "All headers present" if not missing else f"Missing: {', '.join(missing)}"
        return {
            "domain": domain,
            "status": status,
            "missing_headers": missing,
            "error": None
        }
    except Exception as e:
        return {
            "domain": domain,
            "status": "Check failed",
            "missing_headers": [],
            "error": str(e)
        }

def check_security_headers_active_domains(active_domains, max_workers=10):
    """
    Check security headers for all active domains
    """
    results = []
    print(f"\n{Fore.CYAN}[*] Checking security headers for active domains...")
    print(f"{'Domain':<40} {'Status'}")
    print("=" * 80)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(security_headers_check, domain[0]): domain[0] 
            for domain in active_domains
        }
        
        for future in concurrent.futures.as_completed(future_to_domain):
            try:
                result = future.result()
                domain = result["domain"]
                status = result["status"]
                if result["error"]:
                    print(f"{Fore.YELLOW}{domain:<40} {status}: {result['error']}")
                elif result["missing_headers"]:
                    print(f"{Fore.YELLOW}{domain:<40} {status}")
                else:
                    print(f"{Fore.GREEN}{domain:<40} {status}")
                results.append(result)
            except Exception as e:
                domain = future_to_domain[future]
                print(f"{Fore.RED}{domain:<40} Check failed: {str(e)}")
                results.append({
                    "domain": domain,
                    "status": "Check failed",
                    "missing_headers": [],
                    "error": str(e)
                })
    
    return results

def check_ssl_vulnerabilities(domain, port=443, timeout=10):
    """
    Check SSL/TLS vulnerabilities for a domain
    """
    domain = domain.replace("https://", "").replace("http://", "").strip('/')
    result = {
        "domain": domain,
        "vulnerabilities": [],
        "error": None
    }
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_OPTIONAL
        
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                protocol = ssock.version()
                if protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                    result["vulnerabilities"].append(f"Deprecated protocol: {protocol}")
                
                cipher, _, _ = ssock.cipher()
                weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
                cbc_ciphers = ["CBC"]
                for weak in weak_ciphers:
                    if weak in cipher.upper():
                        result["vulnerabilities"].append(f"Weak cipher: {cipher}")
                        break
                for cbc in cbc_ciphers:
                    if cbc in cipher.upper():
                        result["vulnerabilities"].append(f"Potential Lucky13 vulnerability: {cipher} (CBC mode)")
                
                try:
                    ssock.write(b"\x18\x03\x02\x00\x03\x01\x40\x00")
                    response = ssock.recv(1024)
                    if len(response) > 3:
                        result["vulnerabilities"].append("Potential Heartbleed vulnerability detected")
                except:
                    pass
        
        if not result["vulnerabilities"]:
            result["vulnerabilities"].append("No vulnerabilities detected")
        
        return result
    
    except Exception as e:
        result["error"] = str(e)
        result["vulnerabilities"].append("Check failed")
        return result

def check_ssl_vulnerabilities_active_domains(active_domains, max_workers=10):
    """
    Check SSL vulnerabilities for all active domains
    """
    results = []
    print(f"\n{Fore.CYAN}[*] Checking SSL vulnerabilities for active domains...")
    print(f"{'Domain':<40} {'Vulnerabilities'}")
    print("=" * 80)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(check_ssl_vulnerabilities, domain[0]): domain[0] 
            for domain in active_domains
        }
        
        for future in concurrent.futures.as_completed(future_to_domain):
            try:
                result = future.result()
                domain = result["domain"]
                vulnerabilities = "; ".join(result["vulnerabilities"])
                if result["error"]:
                    print(f"{Fore.YELLOW}{domain:<40} Check failed: {result['error']}")
                elif "No vulnerabilities" in vulnerabilities:
                    print(f"{Fore.GREEN}{domain:<40} {vulnerabilities}")
                else:
                    print(f"{Fore.RED}{domain:<40} {vulnerabilities}")
                results.append(result)
            except Exception as e:
                domain = future_to_domain[future]
                print(f"{Fore.RED}{domain:<40} Check failed: {str(e)}")
                results.append({
                    "domain": domain,
                    "vulnerabilities": ["Check failed"],
                    "error": str(e)
                })
    
    return results

def check_ssl_expiry(domain, port=443, retries=2, timeout=10):
    """
    Check SSL certificate expiry for a domain with enhanced error handling and retries.
    """
    domain = domain.replace("https://", "").replace("http://", "").strip('/')
    error_msg = None
    
    try:
        test_url = f"https://{domain}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(test_url, timeout=5, verify=False, allow_redirects=True, headers=headers)
        if response.status_code >= 400:
            error_msg = f"Domain returned HTTP {response.status_code}"
            return None, False, None, error_msg
    except requests.RequestException as e:
        error_msg = f"Domain not reachable via HTTPS: {str(e)}"
        return None, False, None, error_msg

    for attempt in range(retries):
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_OPTIONAL
            
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return None, False, None, "No certificate provided by server"
                    
                    expire_date_str = cert.get('notAfter')
                    if not expire_date_str:
                        return None, False, None, "Certificate missing notAfter field"
                    
                    try:
                        expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z')
                    except ValueError:
                        expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y GMT')
                    
                    expire_date = expire_date.replace(tzinfo=timezone.utc)
                    
                    current_date = datetime.now(timezone.utc)
                    days_remaining = (expire_date - current_date).days
                    
                    is_valid = days_remaining >= 0
                    return expire_date, is_valid, days_remaining, None
                    
        except ssl.SSLCertVerificationError as e:
            error_msg = f"SSL verification failed: {str(e)}"
        except socket.gaierror:
            error_msg = "Domain not resolved (DNS error)"
        except socket.timeout:
            error_msg = "Connection timed out"
        except ConnectionRefusedError:
            error_msg = "Connection refused"
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            
        if attempt < retries - 1:
            time.sleep(1)
        
    return None, False, None, error_msg

def check_ssl_for_active_domains(active_domains):
    """Check SSL certificates for all active domains"""
    ssl_results = []
    print(f"\n{Fore.CYAN}[*] Checking SSL certificates for active domains...")
    print(f"{'Domain':<40} {'Expires On':<30} {'Days Left':<10} {'Status'}")
    print("=" * 100)
    
    for domain, status in active_domains:
        expire_date, is_valid, days_remaining, error_msg = check_ssl_expiry(domain)
        if expire_date and is_valid:
            expiry_str = expire_date.strftime('%Y-%m-%d %H:%M:%S')
            days_str = f"{days_remaining} days"
            status_icon = '✅' if days_remaining > 0 else '❌ EXPIRED'
            status_str = f"{domain:<40} {expiry_str:<30} {days_str:<10} {status_icon}"
            print(f"{Fore.GREEN if days_remaining > 0 else Fore.RED}{status_str}")
            ssl_results.append({
                "domain": domain,
                "expires_on": expiry_str,
                "days_remaining": days_remaining,
                "valid": is_valid
            })
        else:
            status_str = f"{domain:<40} {'Could not retrieve certificate':<30} {'':<10} ❌ ({error_msg})"
            print(f"{Fore.YELLOW}{status_str}")
            ssl_results.append({
                "domain": domain,
                "expires_on": "Unknown",
                "days_remaining": None,
                "valid": False,
                "error": error_msg
            })
    
    return ssl_results

def save_results(domain, results_dict):
    """Save reconnaissance results to a text file"""
    filename = f"recon_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"Reconnaissance Report for {domain}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("1. SUBDOMAIN ENUMERATION SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Subdomains Found: {results_dict['SUBDOMAIN ENUMERATION']['Total Subdomains']}\n")
            f.write(f"Active Subdomains: {len(results_dict['SUBDOMAIN ENUMERATION']['Active Subdomains'])}\n")
            f.write(f"Inactive Subdomains: {len(results_dict['SUBDOMAIN ENUMERATION']['Inactive Subdomains'])}\n\n")
            
            f.write("2. SUBDOMAIN TAKEOVER SCAN\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Domains Checked: {results_dict['TAKEOVER SCAN']['Total Checked']}\n")
            f.write(f"Vulnerable Domains Found: {len(results_dict['TAKEOVER SCAN']['Vulnerable Domains'])}\n")
            if results_dict['TAKEOVER SCAN']['Vulnerable Domains']:
                f.write("Vulnerable Domains:\n")
                for domain in results_dict['TAKEOVER SCAN']['Vulnerable Domains']:
                    f.write(f"* {domain}\n")
            else:
                f.write("No vulnerable domains found.\n")
            if results_dict['TAKEOVER SCAN']['Errors']:
                f.write("\nErrors:\n")
                for error in results_dict['TAKEOVER SCAN']['Errors']:
                    f.write(f"* {error}\n")
            else:
                f.write("No errors encountered.\n")
            f.write("\n")
            
            f.write("3. ACTIVE SUBDOMAINS\n")
            f.write("-" * 40 + "\n")
            for subdomain in results_dict['SUBDOMAIN ENUMERATION']['Active Subdomains']:
                f.write(f"[+] {subdomain}\n")
            f.write("\n")
            
            f.write("4. SSL CERTIFICATES\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Certificates Checked: {results_dict['SSL CERTIFICATES']['Total Checked']}\n")
            for cert_detail in results_dict['SSL CERTIFICATES']['Details']:
                f.write(f"* {cert_detail}\n")
            f.write("\n")
            
            f.write("5. SSL VULNERABILITIES\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Domains Checked: {len(results_dict['SSL VULNERABILITIES'])}\n")
            for vuln in results_dict['SSL VULNERABILITIES']:
                f.write(f"* {vuln['domain']}: {'; '.join(vuln['vulnerabilities'])}")
                if vuln['error']:
                    f.write(f" (Error: {vuln['error']})\n")
                else:
                    f.write("\n")
            f.write("\n")
            
            f.write("6. SECURITY HEADERS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Domains Checked: {len(results_dict['SECURITY HEADERS'])}\n")
            for header_result in results_dict['SECURITY HEADERS']:
                f.write(f"* {header_result['domain']}: {header_result['status']}")
                if header_result['error']:
                    f.write(f" (Error: {header_result['error']})\n")
                else:
                    f.write("\n")
            f.write("\n")
            
            f.write("7. TYPOSQUATTING CHECK\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Variants Checked: {len(results_dict['TYPOSQUATTING'])}\n")
            active_typos = [t for t in results_dict['TYPOSQUATTING'] if t['dns_status'] == 'Active']
            f.write(f"Active Typosquatted Domains: {len(active_typos)}\n")
            for typo in results_dict['TYPOSQUATTING']:
                status = f"{typo['domain']}: DNS {typo['dns_status']}, HTTP {typo['http_status'] or 'None'}"
                if typo['ips']:
                    status += f", IPs: {', '.join(typo['ips'])}"
                if typo['error']:
                    status += f" (Error: {typo['error']})"
                f.write(f"* {status}\n")
            f.write("\n")
            
            f.write("8. CO-HOSTED DOMAINS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total IPs Checked: {len(results_dict['COHOSTED DOMAINS'])}\n")
            total_cohosted = sum(len(r['cohosted_domains']) for r in results_dict['COHOSTED DOMAINS'])
            f.write(f"Total Co-hosted Domains Found: {total_cohosted}\n")
            for result in results_dict['COHOSTED DOMAINS']:
                status = f"IP {result['ip']} (from {', '.join(result['source_domains'])}): "
                if result['cohosted_domains']:
                    status += f"{len(result['cohosted_domains'])} domains: {', '.join(result['cohosted_domains'][:5])}{'...' if len(result['cohosted_domains']) > 5 else ''}"
                else:
                    status += "None"
                if result.get('error'):
                    status += f" (Error: {result['error']})"
                f.write(f"* {status}\n")
            f.write("\n")
            
            f.write("9. WHOIS INFORMATION\n")
            f.write("-" * 40 + "\n")
            for key, value in results_dict['WHOIS INFO'].items():
                f.write(f"{key}: {value}\n")
            f.write("\n")
            
            f.write("10. DNS RECORDS\n")
            f.write("-" * 40 + "\n")
            f.write("MX Records:\n")
            for record in results_dict['MX RECORDS']:
                f.write(f"* {record}\n")
            f.write("\n")
            
            f.write("11. TECHNOLOGY STACK\n")
            f.write("-" * 40 + "\n")
            for tech in results_dict['TECHNOLOGY STACK']:
                f.write(f"* {tech}\n")
            f.write("\n")
            
            f.write("12. EMAIL SECURITY RECORDS\n")
            f.write("-" * 40 + "\n")
            if isinstance(results_dict['EMAIL SECURITY RECORDS'], dict):
                for key, value in results_dict['EMAIL SECURITY RECORDS'].items():
                    f.write(f"* {key}: {value}\n")
            else:
                for record in results_dict['EMAIL SECURITY RECORDS']:
                    f.write(f"* {record}\n")
            f.write("\n")
            
            f.write("13. INACTIVE SUBDOMAINS\n")
            f.write("-" * 40 + "\n")
            for subdomain in results_dict['SUBDOMAIN ENUMERATION']['Inactive Subdomains']:
                f.write(f"[-] {subdomain}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("End of Report\n")
            
        print(f"\n{Fore.GREEN}[+] Detailed results saved to {filename}")
        
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error saving results: {e}")

def save_results_csv(domain, results_dict):
    """Save reconnaissance results to a CSV file"""
    import csv
    
    filename = f"recon_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            writer.writerow(['Reconnaissance Report', domain])
            writer.writerow(['Scan Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow([])
            
            writer.writerow(['SUBDOMAIN ENUMERATION'])
            writer.writerow(['Total Subdomains', results_dict['SUBDOMAIN ENUMERATION']['Total Subdomains']])
            writer.writerow(['Active Subdomains Count', len(results_dict['SUBDOMAIN ENUMERATION']['Active Subdomains'])])
            writer.writerow(['Inactive Subdomains Count', len(results_dict['SUBDOMAIN ENUMERATION']['Inactive Subdomains'])])
            writer.writerow([])
            
            writer.writerow(['SUBDOMAIN TAKEOVER SCAN'])
            writer.writerow(['Total Checked', results_dict['TAKEOVER SCAN']['Total Checked']])
            writer.writerow(['Vulnerable Domains Count', len(results_dict['TAKEOVER SCAN']['Vulnerable Domains'])])
            writer.writerow(['Vulnerable Domains'])
            if results_dict['TAKEOVER SCAN']['Vulnerable Domains']:
                for domain in results_dict['TAKEOVER SCAN']['Vulnerable Domains']:
                    writer.writerow(['', domain])
            else:
                writer.writerow(['', 'No vulnerable domains found'])
            writer.writerow(['Errors'])
            if results_dict['TAKEOVER SCAN']['Errors']:
                for error in results_dict['TAKEOVER SCAN']['Errors']:
                    writer.writerow(['', error])
            else:
                writer.writerow(['', 'No errors encountered'])
            writer.writerow([])
            
            writer.writerow(['ACTIVE SUBDOMAINS'])
            for subdomain in results_dict['SUBDOMAIN ENUMERATION']['Active Subdomains']:
                writer.writerow(['', subdomain])
            writer.writerow([])
            
            writer.writerow(['SSL CERTIFICATES'])
            writer.writerow(['Total Checked', results_dict['SSL CERTIFICATES']['Total Checked']])
            for cert in results_dict['SSL CERTIFICATES']['Details']:
                writer.writerow(['', cert])
            writer.writerow([])
            
            writer.writerow(['SSL VULNERABILITIES'])
            writer.writerow(['Total Checked', len(results_dict['SSL VULNERABILITIES'])])
            for vuln in results_dict['SSL VULNERABILITIES']:
                writer.writerow(['', f"{vuln['domain']}: {'; '.join(vuln['vulnerabilities'])}"])
            writer.writerow([])
            
            writer.writerow(['SECURITY HEADERS'])
            writer.writerow(['Total Checked', len(results_dict['SECURITY HEADERS'])])
            for header_result in results_dict['SECURITY HEADERS']:
                writer.writerow(['', f"{header_result['domain']}: {header_result['status']}"])
            writer.writerow([])
            
            writer.writerow(['TYPOSQUATTING CHECK'])
            writer.writerow(['Total Variants Checked', len(results_dict['TYPOSQUATTING'])])
            active_typos = [t for t in results_dict['TYPOSQUATTING'] if t['dns_status'] == 'Active']
            writer.writerow(['Active Typosquatted Domains', len(active_typos)])
            for typo in results_dict['TYPOSQUATTING']:
                status = f"{typo['domain']}: DNS {typo['dns_status']}, HTTP {typo['http_status'] or 'None'}"
                if typo['ips']:
                    status += f", IPs: {', '.join(typo['ips'])}"
                if typo['error']:
                    status += f" (Error: {typo['error']})"
                writer.writerow(['', status])
            writer.writerow([])
            
            writer.writerow(['CO-HOSTED DOMAINS'])
            writer.writerow(['Total IPs Checked', len(results_dict['COHOSTED DOMAINS'])])
            total_cohosted = sum(len(r['cohosted_domains']) for r in results_dict['COHOSTED DOMAINS'])
            writer.writerow(['Total Co-hosted Domains Found', total_cohosted])
            for result in results_dict['COHOSTED DOMAINS']:
                status = f"IP {result['ip']} (from {', '.join(result['source_domains'])}): "
                if result['cohosted_domains']:
                    status += f"{len(result['cohosted_domains'])} domains: {', '.join(result['cohosted_domains'][:5])}{'...' if len(result['cohosted_domains']) > 5 else ''}"
                else:
                    status += "None"
                if result.get('error'):
                    status += f" (Error: {result['error']})"
                writer.writerow(['', status])
            writer.writerow([])
            
            writer.writerow(['WHOIS INFO'])
            for key, value in results_dict['WHOIS INFO'].items():
                writer.writerow(['', key, str(value)])
            writer.writerow([])
            
            writer.writerow(['MX RECORDS'])
            for record in results_dict['MX RECORDS']:
                writer.writerow(['', record])
            writer.writerow([])
            
            writer.writerow(['TECHNOLOGY STACK'])
            for tech in results_dict['TECHNOLOGY STACK']:
                writer.writerow(['', tech])
            writer.writerow([])
            
            writer.writerow(['EMAIL SECURITY RECORDS'])
            if isinstance(results_dict['EMAIL SECURITY RECORDS'], dict):
                for key, value in results_dict['EMAIL SECURITY RECORDS'].items():
                    writer.writerow(['', key, str(value)])
            else:
                for record in results_dict['EMAIL SECURITY RECORDS']:
                    writer.writerow(['', record])
            writer.writerow([])
            
            writer.writerow(['INACTIVE SUBDOMAINS'])
            for subdomain in results_dict['SUBDOMAIN ENUMERATION']['Inactive Subdomains']:
                writer.writerow(['', subdomain])
            writer.writerow([])
            
            writer.writerow(['SHODAN SCAN'])
            shodan_results = results_dict.get('SHODAN_SCAN', {})
            writer.writerow(['Success', str(shodan_results.get('success', False))])
            writer.writerow(['IPs Found', len(shodan_results.get('ips', []))])
            writer.writerow(['Total Vulnerabilities', len(shodan_results.get('total_vulns', []))])
            for ip in shodan_results.get('ips', []):
                writer.writerow(['', f"IP: {ip}"])
            for vuln in shodan_results.get('total_vulns', []):
                writer.writerow(['', f"Vulnerability: {vuln}"])
            for error in shodan_results.get('errors', []):
                writer.writerow(['', f"Error: {error}"])
                
        print(f"\n{Fore.GREEN}[+] CSV results saved to {filename}")
        
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error saving CSV: {e}")

def run_subfinder_scan(domain):
    """
    Run subfinder scan and check domain statuses
    """
    print(f"\n{Fore.CYAN}[*] Finding subdomains for {domain}...")
    start_time = time.time()
    
    try:
        subfinder = SubfinderWrapper(binary_path="subfinder", debug=False)
        subdomains = list(set(subfinder.find_subdomains(domain)))  # Remove duplicates
        
        if not subdomains:
            print(f"{Fore.YELLOW}[!] No subdomains found.")
            return {
                "subdomains": [],
                "active": [],
                "inactive": [],
                "ssl_info": []
            }
            
        print(f"{Fore.GREEN}[+] Total subdomains found: {len(subdomains)}")
        
        results = check_domains_status(subdomains)
        
        ssl_results = check_ssl_for_active_domains(results['active'])
        
        print(f"\n{Fore.CYAN}[*] Summary:")
        print(f"{Fore.GREEN}[+] Active domains: {len(results['active'])}")
        print(f"{Fore.RED}[-] Inactive domains: {len(results['inactive'])}")
        print(f"{Fore.CYAN}[*] SSL Certificates checked: {len(ssl_results)}")
        
        elapsed_time = time.time() - start_time
        print(f"\n{Fore.CYAN}[*] Execution completed in {elapsed_time:.2f} seconds.")
        
        return {
            "subdomains": subdomains,
            "active": results["active"],
            "inactive": results["inactive"],
            "ssl_info": ssl_results
        }
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error during subfinder scan: {str(e)}")
        return {
            "subdomains": [],
            "active": [],
            "inactive": [],
            "ssl_info": []
        }

def find_js_files(url):
    """Find all JavaScript files linked in a webpage"""
    js_files = set()
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                full_url = urljoin(url, src)
                if full_url.endswith(".js"):
                    js_files.add(full_url)
    except Exception as e:
        print(f"{Fore.RED}[!] Error fetching scripts from {url}: {str(e)}")
    return js_files

def scan_js_file(js_url):
    """Scan a JavaScript file for potential API keys and secrets"""
    found = []
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        res = requests.get(js_url, headers=headers, timeout=10, verify=False)
        if res.status_code != 200:
            print(f"{Fore.YELLOW}[!] Failed to fetch {js_url}: HTTP {res.status_code}")
            return []
        
        content = res.text
        for pattern in API_KEY_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                found.append({
                    "url": js_url,
                    "key": match,
                    "pattern": pattern
                })
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to scan {js_url}: {str(e)}")
    return found

def scan_domain_for_keys(domain):
    """Scan a domain for exposed API keys and secrets in JavaScript files"""
    results = []
    print(f"\n{Fore.CYAN}[*] Scanning for exposed API keys and secrets...")
    
    for scheme in ['https://', 'http://']:
        url = f"{scheme}{domain}"
        try:
            print(f"{Fore.CYAN}[*] Checking {url}")
            js_files = find_js_files(url)
            
            if not js_files:
                print(f"{Fore.YELLOW}[!] No JavaScript files found on {url}")
                continue
            
            print(f"{Fore.GREEN}[+] Found {len(js_files)} JavaScript files")
            
            for js_file in js_files:
                print(f"{Fore.CYAN}[*] Scanning: {js_file}")
                keys = scan_js_file(js_file)
                if keys:
                    print(f"{Fore.GREEN}[+] Found {len(keys)} potential keys in {js_file}")
                    results.extend(keys)
                time.sleep(1)  # Rate limiting
            
            if results:  # If we found results with HTTPS, no need to try HTTP
                break
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning {url}: {str(e)}")
    
    # Summary
    if results:
        print(f"\n{Fore.GREEN}[+] Found {len(results)} potential API keys and secrets:")
        for result in results:
            print(f"{Fore.YELLOW}[*] {result['url']}:")
            print(f"{Fore.RED}    ↳ {result['key']}")
    else:
        print(f"{Fore.GREEN}[+] No API keys or secrets found")
    
    return results

def check_dns_security(domain):
    """
    Check DNS security features including DNSSEC, CAA, and other DNS security mechanisms
    Returns a dictionary containing the security status of various DNS features
    """
    results = {
        "DNSSEC": {"enabled": False, "error": None},
        "CAA": {"records": [], "error": None},
        "NS": {"records": [], "error": None},
        "DS": {"records": [], "error": None},
        "DNSKEY": {"records": [], "error": None},
        "NSEC3PARAM": {"enabled": False, "error": None}
    }

    print(f"\n{Fore.CYAN}[*] Checking DNS security features for {domain}...")

    # Check DNSSEC
    try:
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO,
4096)
        
        # Check for DNSKEY records
        try:
            dnskey = resolver.resolve(domain, 'DNSKEY')
            results["DNSKEY"]["records"] = [key.to_text() for key in dnskey]
            results["DNSSEC"]["enabled"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results["DNSKEY"]["error"] = "No DNSKEY records found"
        except Exception as e:
            results["DNSKEY"]["error"] = str(e)

        # Check for DS records
        try:
            ds = resolver.resolve(domain, 'DS')
            results["DS"]["records"] = [record.to_text() for record in ds]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results["DS"]["error"] = "No DS records found"
        except Exception as e:
            results["DS"]["error"] = str(e)

        # Check for NSEC3PARAM (DNSSEC with opt-out)
        try:
            nsec3 = resolver.resolve(domain, 'NSEC3PARAM')
            results["NSEC3PARAM"]["enabled"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results["NSEC3PARAM"]["error"] = "No NSEC3PARAM records found"
        except Exception as e:
            results["NSEC3PARAM"]["error"] = str(e)

    except Exception as e:
        results["DNSSEC"]["error"] = f"DNSSEC check failed: {str(e)}"

    # Check CAA records
    try:
        caa = resolver.resolve(domain, 'CAA')
        results["CAA"]["records"] = [record.to_text() for record in caa]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results["CAA"]["error"] = "No CAA records found"
    except Exception as e:
        results["CAA"]["error"] = f"CAA check failed: {str(e)}"

    # Check NS records
    try:
        ns = resolver.resolve(domain, 'NS')
        results["NS"]["records"] = [record.to_text() for record in ns]
    except Exception as e:
        results["NS"]["error"] = f"NS check failed: {str(e)}"

    # Print results
    print(f"\n{Fore.CYAN}[*] DNS Security Results for {domain}:")
    print("=" * 60)

    # DNSSEC Status
    if results["DNSSEC"]["enabled"]:
        print(f"{Fore.GREEN}[+] DNSSEC: Enabled")
        if results["DNSKEY"]["records"]:
            print(f"{Fore.GREEN}  ↳ DNSKEY Records: {len(results['DNSKEY']['records'])} found")
        if results["DS"]["records"]:
            print(f"{Fore.GREEN}  ↳ DS Records: {len(results['DS']['records'])} found")
    else:
        print(f"{Fore.RED}[-] DNSSEC: Not enabled")
        if results["DNSSEC"]["error"]:
            print(f"{Fore.RED}  ↳ Error: {results['DNSSEC']['error']}")

    # CAA Records
    if results["CAA"]["records"]:
        print(f"{Fore.GREEN}[+] CAA Records:")
        for record in results["CAA"]["records"]:
            print(f"{Fore.GREEN}  ↳ {record}")
    else:
        print(f"{Fore.YELLOW}[!] CAA Records: None found")
        if results["CAA"]["error"]:
            print(f"{Fore.YELLOW}  ↳ {results['CAA']['error']}")

    # NS Records
    if results["NS"]["records"]:
        print(f"{Fore.GREEN}[+] NS Records:")
        for record in results["NS"]["records"]:
            print(f"{Fore.GREEN}  ↳ {record}")
    else:
        print(f"{Fore.RED}[-] NS Records: None found")
        if results["NS"]["error"]:
            print(f"{Fore.RED}  ↳ {results['NS']['error']}")

    # NSEC3PARAM Status
    if results["NSEC3PARAM"]["enabled"]:
        print(f"{Fore.GREEN}[+] NSEC3PARAM: Enabled (DNSSEC with opt-out)")
    else:
        print(f"{Fore.YELLOW}[!] NSEC3PARAM: Not enabled")
        if results["NSEC3PARAM"]["error"]:
            print(f"{Fore.YELLOW}  ↳ {results['NSEC3PARAM']['error']}")

    return results

def check_subdomain_takeover(inactive_domains):
    """
    Check for potential subdomain takeover vulnerabilities using Takeover tool
    """
    takeover_results = {
        "vulnerable_domains": [],
        "errors": [],
        "total_checked": 0
    }
    
    if not inactive_domains:
        print(f"{Fore.YELLOW}[!] No inactive domains to check for takeover")
        return takeover_results
        
    print(f"\n{Fore.CYAN}[*] Checking {len(inactive_domains)} inactive domains for potential takeover...")
    
    try:
        for domain, error in inactive_domains:
            takeover_results["total_checked"] += 1
            print(f"{Fore.CYAN}[*] Checking {domain} for takeover possibility...")
            
            command = ["takeover", "-d", domain, "-v"]
            try:
                process = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=30
                )
                
                if "Vulnerable" in process.stdout:
                    print(f"{Fore.RED}[!] Potential takeover found: {domain}")
                    takeover_results["vulnerable_domains"].append({
                        "domain": domain,
                        "details": process.stdout.strip()
                    })
                else:
                    print(f"{Fore.GREEN}[+] No takeover vulnerability found: {domain}")
                    
            except subprocess.TimeoutExpired:
                error_msg = f"Timeout while checking {domain}"
                print(f"{Fore.RED}[-] {error_msg}")
                takeover_results["errors"].append({"domain": domain, "error": error_msg})
            except Exception as e:
                error_msg = f"Error checking {domain}: {str(e)}"
                print(f"{Fore.RED}[-] {error_msg}")
                takeover_results["errors"].append({"domain": domain, "error": error_msg})
            
            time.sleep(1)  # Rate limiting
            
    except Exception as e:
        print(f"{Fore.RED}[-] Error during takeover checks: {str(e)}")
        takeover_results["errors"].append({"domain": "general", "error": str(e)})
    
    # Print summary
    print(f"\n{Fore.CYAN}[*] Takeover Check Summary:")
    print(f"{Fore.GREEN}[+] Total domains checked: {takeover_results['total_checked']}")
    print(f"{Fore.RED}[!] Vulnerable domains found: {len(takeover_results['vulnerable_domains'])}")
    print(f"{Fore.YELLOW}[!] Errors encountered: {len(takeover_results['errors'])}")
    
    return takeover_results

def run_recon():
    domain = input(f"{Fore.CYAN}🔍 Enter a domain name (e.g., example.com): ").strip()
    all_results = {}
    
    try:
        print(f"\n{Fore.CYAN}[*] Phase 1: Running Subdomain Enumeration and SSL Checks...")
        subfinder_results = run_subfinder_scan(domain)
        
        # Add takeover check phase
        print(f"\n{Fore.CYAN}[*] Phase 2: Checking for Subdomain Takeover...")
        takeover_results = check_subdomain_takeover(subfinder_results["inactive"])
        
        all_results["SUBDOMAIN ENUMERATION"] = {
            "Total Subdomains": len(subfinder_results["subdomains"]),
            "Active Subdomains": [f"{d[0]} (Status: {d[1]})" for d in subfinder_results["active"]],
            "Inactive Subdomains": [f"{d[0]} (Error: {d[1]})" for d in subfinder_results["inactive"]]
        }
        
        all_results["TAKEOVER SCAN"] = {
            "Total Checked": takeover_results["total_checked"],
            "Vulnerable Domains": [
                f"{vuln['domain']} - {vuln['details']}" 
                for vuln in takeover_results["vulnerable_domains"]
            ],
            "Errors": [
                f"{err['domain']}: {err['error']}" 
                for err in takeover_results["errors"]
            ]
        }
        
        all_results["SSL CERTIFICATES"] = {
            "Total Checked": len(subfinder_results["ssl_info"]),
            "Details": [
                f"{cert['domain']} (Expires: {cert['expires_on']}, Valid: {'✅' if cert['valid'] else '❌'}, Error: {cert.get('error', 'None')})"
                for cert in subfinder_results["ssl_info"]
            ]
        }

        print(f"\n{Fore.CYAN}[*] Phase 3: Checking SSL Vulnerabilities...")
        all_results["SSL VULNERABILITIES"] = check_ssl_vulnerabilities_active_domains(subfinder_results["active"])
        
        print(f"\n{Fore.CYAN}[*] Phase 4: Checking Security Headers...")
        all_results["SECURITY HEADERS"] = check_security_headers_active_domains(subfinder_results["active"])
        
        print(f"\n{Fore.CYAN}[*] Phase 5: Collecting WHOIS Information...")
        all_results["WHOIS INFO"] = whois_info(domain)
        
        print(f"\n{Fore.CYAN}[*] Phase 6: Collecting DNS Records...")
        all_results["MX RECORDS"] = dns_mx(domain)
        
        print(f"\n{Fore.CYAN}[*] Phase 7: Analyzing Technology Stack...")
        all_results["TECHNOLOGY STACK"] = tech_stack(domain)
        
        print(f"\n{Fore.CYAN}[*] Phase 8: Running Email Security Checks...")
        all_results["EMAIL SECURITY RECORDS"] = email_sec(domain)
        
        print(f"\n{Fore.CYAN}[*] Phase 9: Running Typosquatting Checks...")
        all_results["TYPOSQUATTING"] = check_typosquatting_domains(domain)
        
        print(f"\n{Fore.CYAN}[*] Phase 10: Running Co-hosted Domain Checks...")
        all_results["COHOSTED DOMAINS"] = check_cohosted_domains(domain, subfinder_results["active"])
        
        print(f"\n{Fore.CYAN}[*] Phase 11: Checking DNS Security...")
        all_results["DNS_SECURITY"] = check_dns_security(domain)
        
        print(f"\n{Fore.CYAN}[*] Phase 12: Scanning for exposed API keys...")
        all_results["API_KEYS"] = scan_domain_for_keys(domain)
        
        print(f"\n{Fore.CYAN}[*] Phase 13: Running Shodan Scan...")
        all_results["SHODAN_SCAN"] = run_shodan_scan(domain)

        print(f"\n{Fore.CYAN}[*] Reconnaissance Summary:")
        print(Fore.CYAN + "=" * 40)
        print(f"{Fore.GREEN}✓ Subdomains Found: {all_results['SUBDOMAIN ENUMERATION']['Total Subdomains']}")
        print(f"{Fore.GREEN}✓ Active Subdomains: {len(all_results['SUBDOMAIN ENUMERATION']['Active Subdomains'])}")
        print(f"{Fore.GREEN}✓ Takeover Checks: {all_results['TAKEOVER SCAN']['Total Checked']}")
        print(f"{Fore.RED}! Potential Takeovers: {len(all_results['TAKEOVER SCAN']['Vulnerable Domains'])}")
        print(f"{Fore.GREEN}✓ SSL Certificates Checked: {all_results['SSL CERTIFICATES']['Total Checked']}")
        print(f"{Fore.GREEN}✓ SSL Vulnerabilities Checked: {len(all_results['SSL VULNERABILITIES'])}")
        print(f"{Fore.GREEN}✓ Security Headers Checked: {len(all_results['SECURITY HEADERS'])}")
        print(f"{Fore.GREEN}✓ Technologies Detected: {len(all_results['TECHNOLOGY STACK'])}")
        if all_results["SHODAN_SCAN"]["success"]:
            print(f"{Fore.GREEN}✓ Shodan IPs Found: {len(all_results['SHODAN_SCAN']['ips'])}")
            print(f"{Fore.GREEN}✓ Shodan Vulnerabilities: {len(all_results['SHODAN_SCAN']['total_vulns'])}")

        save_results(domain, all_results)
        save_results_csv(domain, all_results)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Reconnaissance interrupted by user")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during reconnaissance: {str(e)}")

if __name__ == "__main__":
    print(f"{Fore.CYAN}🔍 Domain Reconnaissance Tool")
    print(Fore.CYAN + "=" * 40)
    
    while True:
        run_recon()
        again = input(f"\n{Fore.CYAN}🔁 Check another domain? (y/n): ").lower()
        if again != 'y':
            print(f"{Fore.CYAN}👋 Exiting...")
            break
