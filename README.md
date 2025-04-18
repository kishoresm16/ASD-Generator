Domain Reconnaissance Tool
A comprehensive Python-based tool for performing domain reconnaissance, gathering information about subdomains, DNS records, SSL certificates, security headers, typosquatting, co-hosted domains, and more. The tool leverages various libraries and external services to provide detailed insights into a target domain's infrastructure and security posture.
Features

Subdomain Enumeration: Uses subfinder to discover subdomains and checks their status (active/inactive).
Subdomain Takeover Detection: Identifies potential subdomain takeover vulnerabilities using the takeover tool.
SSL/TLS Analysis:
Checks SSL certificate validity and expiry dates.
Identifies SSL/TLS vulnerabilities (e.g., deprecated protocols, weak ciphers, Heartbleed).


Security Headers Check: Analyzes HTTP security headers (e.g., CSP, HSTS) for active domains.
DNS Records:
Retrieves MX records.
Checks email security records (SPF, DMARC, DKIM).
Analyzes DNS security features (DNSSEC, CAA, NS, etc.).


Typosquatting Detection: Generates and checks typosquatted domain variants for potential abuse.
Co-hosted Domains: Identifies domains hosted on the same IP addresses as the target domain.
WHOIS Information: Retrieves domain registration details.
Technology Stack Analysis: Uses Wappalyzer to detect technologies and their versions.
API Key Scanning: Scans JavaScript files for exposed API keys and secrets.
Shodan Integration: Performs Shodan scans to identify open ports, services, and vulnerabilities.
Results Export: Saves results in both text and CSV formats for easy analysis.

Prerequisites

Python 3.8+
External Tools:
subfinder: For subdomain enumeration.
takeover: For subdomain takeover checks.


API Access:
Shodan API key for Shodan scans (optional, required for Shodan integration).
HackerTarget API for reverse IP lookups (free tier available).


System Dependencies:
Ensure subfinder and takeover binaries are installed and accessible in your system's PATH.



Installation

Clone the repository:
git clone https://github.com/your-username/domain-recon-tool.git
cd domain-recon-tool


Install Python dependencies:
pip install -r requirements.txt


Install subfinder:

Follow instructions from subfinder's GitHub page.
Ensure the subfinder binary is in your PATH or specify its path in the script.


Install takeover:

Follow instructions from takeover's GitHub page.
Ensure the takeover binary is in your PATH.


(Optional) Set up Shodan API:

Obtain a Shodan API key from shodan.io.
Configure the API key in the shodan_scanner.py script or environment variables.



Requirements
Create a requirements.txt file with the following dependencies:
python-whois
dnspython
requests
colorama
wappalyzer
beautifulsoup4
urllib3

Install them using:
pip install -r requirements.txt

Usage
Run the tool and follow the prompts:
python recon_tool.py


Enter the target domain (e.g., example.com).
The tool will perform reconnaissance in multiple phases, including:
Subdomain enumeration
Subdomain takeover checks
SSL/TLS analysis
Security headers analysis
DNS and email security checks
Typosquatting detection
Co-hosted domain analysis
WHOIS lookup
Technology stack detection
API key scanning
Shodan scanning


Results are displayed in the terminal and saved to both a text file (recon_<domain>_<timestamp>.txt) and a CSV file (recon_<domain>_<timestamp>.csv).
Choose to scan another domain or exit.

Example Output
🔍 Domain Reconnaissance Tool
========================================
🔍 Enter a domain name (e.g., example.com): example.com

[*] Phase 1: Running Subdomain Enumeration and SSL Checks...
[+] Total subdomains found: 25
[+] Active domains: 10
[-] Inactive domains: 15

[*] Phase 2: Checking for Subdomain Takeover...
[!] Potential takeover found: vuln-sub.example.com

[*] Phase 3: Checking SSL Vulnerabilities...
example.com: No vulnerabilities detected ✅
sub.example.com: Deprecated protocol: TLSv1 ❌

...

[+] Detailed results saved to recon_example.com_20250417_123456.txt
[+] CSV results saved to recon_example.com_20250417_123456.csv
🔁 Check another domain? (y/n):

Output Files

Text Report: A detailed report with formatted sections for each reconnaissance phase.
CSV Report: A structured CSV file for easy data analysis in spreadsheets or scripts.

Notes

Rate Limiting: The tool includes delays to avoid overwhelming APIs or triggering rate limits (e.g., HackerTarget, Shodan).
Error Handling: Extensive error handling ensures the tool continues running even if individual checks fail.
Parallel Processing: Uses concurrent.futures for efficient parallel execution of checks.
Security: Disables SSL warnings for testing purposes (urllib3.disable_warnings). Use with caution in production environments.
Dependencies: Ensure external tools (subfinder, takeover) are properly installed and configured.
Shodan: Requires a valid Shodan API key for full functionality. Without it, the Shodan scan phase will be skipped or limited.

Limitations

Some checks (e.g., HackerTarget API, Shodan) may be rate-limited or require paid accounts for extensive use.
Subdomain takeover detection depends on the takeover tool's accuracy and configuration.
API key scanning is pattern-based and may produce false positives or miss custom key formats.
DNS and SSL checks may fail for domains with non-standard configurations or restrictive firewalls.

Contributing
Contributions are welcome! Please submit issues or pull requests to improve the tool. Areas for enhancement include:

Adding support for additional reconnaissance tools.
Improving API key detection patterns.
Enhancing performance for large domain lists.
Adding visualization for results (e.g., graphs, charts).

License
This project is licensed under the MIT License. See the LICENSE file for details.
Disclaimer
This tool is intended for authorized security testing and research purposes only. Do not use it to scan domains without explicit permission from the domain owner. The authors are not responsible for any misuse or damage caused by this tool.
