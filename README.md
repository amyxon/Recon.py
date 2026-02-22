# Recon.py
https://app.screencastify.com/watch/s00BmJGFKswyFJV86bST - Shows the tool in action with all features demonstrated.

Recon.py is a fast command-line tool written in Python. It is designed for initial network and web service reconnaissance. My primary goal for Recon.oy is to quickly identify open TCP ports, collect services banners and perform non-intrusive metadata extraction and fingerprinting on web services, HTTPS or HTTP, and their TLS certificates. Recon.py is built to perform ethical scanning practicces, error tolerance and an emphasis on performance The final output is a structured JSON file containing all collected data, as well as a simplified CSV summary for quick review.

Project Goals:
-Concurrency
-Error‑tolerant network probing
-HTTP(S) fingerprinting
-Structured JSON output
-Ethical scanning practices

Requirements:
In order to run Recon.py you need Python3 and the following external libraries:
    1. Requests: used for robust HTTP(S) probing and handling redirects/timeouts
    2. Urllib3: Used by requests, specfically for disabling InsecureRequestWarnings

These can be installed by using the following command: pip install requests

All other libraries used are standard components of Python3 Installation.

Running The Tool:
Usage Syntax:

python3 recon.py --targets <host/file> --ports <list/range> [OPTIONS]

--targets : Path to a file containing hosts (one per line) or a single hostname/IP 
--ports : Comma-separated list of ports or ranges (e.g., 80,443,8000-8100)
--output : Prefix for the output files (creates <prefix>.json and <prefix>.csv)
--workers : Number of concurrent threads for scanning (concurrency level)
--timeout : Connedction timeout in seconds for all network operations
--rate : Global maximum request rate 
--http : Enables full HTTP(S) probing on open ports, even if no initial HTTP banner is found
--tls : Enables deep TLS certificate analysis on open ports
--resume : Loads existing output file and scans only missing/failed targets
--verbose : Enables detailed DEBUG logging to stderr

Examples: Targets used to test recon.py are nmap.scanme.org and  example.com

1. Basic Scan: Scan a single host on common ports, enabling HTTP and TLS probes, and saving results:

python3 recon.py --targets example.com --ports 80,443,8080 --http --tls --output scan_results


2. High-Concurrency Scan with Rate Limiting: Scan a list of hosts on a wide port range, using 50 workers but limiting the overall rate to 5 requests per second:

python3 recon.py --targets hosts.txt --ports 1-1000 --workers 50 --rate 5.0 --output heavy_scan


3. Resuming a Scan: Restart an interrupted scan, continuing from where the existing results left off:

python3 recon.py --targets list.txt --ports 100-200 --output partial_scan --resume


Features Implemented:

1. TCP Connect Scan
Functionality: Attempts a standard TCP connect() to each target host:port.
Output: Classifies result as: open, closed (connection refused), or filtered (timeout or unexpected network error)
Reliability: Works reliably without requiring raw sockets or root privileges. Respects global timeout settings (--timeout).
-Attempts a TCP connect() to each target host:port


2. Banner Collection
Functionality: Attempts a basic connection and banner grab (first 4096 bytes) for open ports.
Output: The raw banner is encoded in base64 for safe and standardized storage in the JSON output.
Robustness: Collects service banners for open ports and records connection failure messages for closed/filtered ports.

3. HTTP(S) Probing
Functionality: Uses the robust requests library to perform a GET request if the --http flag is set or if the initial banner suggests an HTTP service.

Tolerances: Follows a maximum of five redirects and respects the global --timeout setting.

Extracted Metadata:
    -HTTP status code and final URL after redirects.
    -HTML <title> and <meta name="description">.
    -The value of the Server header.
    -The first 4096 bytes of the page body (sample).
    -The first element of the Set-Cookie header (cookie summary).

4. Web Application Fingerprinting (HTTP//HTTPS)

Functionality: Analyzes the HTTP response (headers and body) and performs secondary HEAD requests against common files.
Output:
    -WAF/CDN Detection: Identifies services like Cloudflare, Sucuri, or ModSecurity via proprietary headers.
    -Stack Hints: Detects server software like Nginx, Apache, or frameworks like Django/Express.
    -CMS Hints: Identifies common CMS platforms (WordPress, Drupal, Joomla) by looking for characteristic file paths (/wp-login.php) or generator meta tags.
    -Favicon Hash: Calculates the SHA256 hash of the /favicon.ico file for passive web application identification (similar to techniques used by Shodan).

5. TLS certificate Analysis

Functionality: When the --tls flag is set, it performs a TLS handshake using the ssl module.

Extracted Details:
    -Certificate Subject Common Name (CN) and Issuer CN.
    -Validity period (notBefore and notAfter) with a boolean check for current validity.
    -Subject Alternative Names (SANs) and the certificate chain length.
    -Key properties: Public Key Type (e.g., RSA) and Size (e.g., 2048).

Security Flags: Automatically flags potential weaknesses, such as RSA keys smaller than 2048 bits or the use of deprecated signature algorithms (e.g., MD5).

Requirements:
-Python 3.8+
Standard library modules:
    -socket
    -base64
    -json
    -datetime
    -argparse
    -cncurrent.futures
-No external pip packages are required

6. Structured Output (JSON & CSV)

-JSON Report: All collected data (banner, HTTP probe, TLS analysis, fingerprinting) is stored in a structured, hierarchical JSON file, organized by host and port. This is the primary, machine-readable output.
-CSV Summary: A secondary CSV file is generated that flattens the key findings (Host, Port, Status, Title, Server Header, Certificate Expiration) for easy filtering and manual analysis in spreadsheet software.

7. Concurrency (Thread Pooling)

Functionality: Uses Python's concurrent.futures.ThreadPoolExecutor to run scans in parallel.
Control: The level of concurrency is controlled by the user via the --workers argument (default: 20). This dramatically speeds up the overall scan process.

8. Rate Control

Functionality: Implements a time delay (time.sleep) before each scan operation to limit the requests per second.
Control: Controlled via the --rate argument (e.g., --rate 5.0 ensures a maximum of 5 requests per second). Setting the rate to 0.0 (default) disables rate limiting. This feature supports ethical scanning practices.

9. Resilience 
 Functionality: The tool supports a --resume flag. If the specified output JSON file already exists when this flag is used, the tool will:
    1. Load the previous results from the JSON file.
    2. Identify which hosts and ports have not yet been scanned or are missing data.
    3. Only add the missing items to the concurrent processing queue.


## Advanced Features 
1. TLS Cipher Suite Analysis= - Detects weak/outdated ciphers and protocols
2. HTTP Method Security Audit - Identifies dangerous methods (PUT, DELETE, TRACE)
3. Enhanced Fingerprinting - CMS, framework, and WAF detection with heuristic checks
4. Favicon Hash Database Ready - SHA256 computation for OSINT correlation
5. Rate Limiting - Ethical scanning with configurable request throttling

Extra features implemented:
1. TLS Cipher Suite Analysis & Weak Cipher Detection:
    -TLS Version Detection: Identifies negotiated protocol versions (SSLv3, TLSv1.0-1.3)
    -Cipher Suite Extraction: Captures the exact cryptographic cipher in use
    -Security Assessment: Flags weak and deprecated configurations
    -Identifies servers using weak encryption (RC4, DES) or outdated protocols vulnerable to attacks like POODLE, BEAST, and CRIME.

2. HTTP Method Analysis & Dangerous Method Detection:
    -Method Enumeration: Discover all allowed HTTP methods
    -Security Risk Assessment: Flag potentially dangerous methods
    -Compliance Checking: Identify misconfigured web servers
    -Identifies web servers with excessive permissions that could be exploited for file upload attacks, data destruction, or server compromise.

3. Comprehensive Security Fingerprinting Suite:
CMS & Framework Detection
    -WordPress: wp-content, wp-includes patterns, wp-login.php check
    -Drupal: Generator meta tags, sites/all/themes paths
    -Joomla: Version-specific generator tags
    -Django: CSRF token patterns, debug toolbar detection
    -Express/Node.js: Server header analysis

4. Useful Banner Parsing:
Base64 Banner Preservation:
    -Raw TCP/UDP responses encoded in base64
    -No data corruption from binary/control characters
    -Complete forensic record for investigation

Favicon Hash Correlation:
    -SHA256 hashing of /favicon.ico
    -Enables Shodan/OSINT database correlation
    -Framework identification via known favicon hashes