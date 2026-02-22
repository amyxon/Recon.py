#!/usr/bin/env python3
import argparse
import socket
import requests
import os
import ssl
import base64
import json
import csv
import datetime
import hashlib
import random
import time
import logging
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning

# Disable HTTPS certificate warnings for requests
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
log = logging.getLogger(__name__)


# Argument Parser
def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple network recon tool: TCP banner grabber + HTTP(S) probe",
    )
    parser.add_argument("--targets", required=True, help="Path to file or a single host")
    parser.add_argument("--ports", required=True, help="Comma list or ranges (e.g., 80,443,8000-8100)")
    parser.add_argument("--workers", type=int, default=20, help="Concurrent TCP workers (default 20)")
    parser.add_argument("--http", action="store_true", help="Probe HTTP(S) services and extract metadata")
    parser.add_argument("--tls", action="store_true", help="Attempt TLS retrieval and analysis")
    parser.add_argument("--output", help="Output prefix for JSON/CSV")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout")
    parser.add_argument("--rate", type=float, default=0.0, help="Rate limit (requests/second). 0 for none.")
    parser.add_argument("--resume", action="store_true", help="Resume from existing JSON file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()


def parse_ports(spec: str):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                lo, hi = map(int, part.split("-"))
                for p in range(lo, hi + 1):
                    ports.add(p)
            except ValueError:
                log.warning(f"Invalid port range format: {part}. Skipping.")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                log.warning(f"Invalid port number format: {part}. Skipping.")
    return sorted(ports)


def read_targets(path_or_host):
    if os.path.isfile(path_or_host):
        out = []
        try:
            with open(path_or_host, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        out.append(line)
        except Exception as e:
            log.error(f"Failed to read targets file {path_or_host}: {e}")
            sys.exit(1)
        return out
    return [path_or_host.strip()]


def tcp_connect_scan(host, port, timeout=3.0):
    """
    Performs a TCP connect() scan.
    Returns: ("open" | "closed" | "filtered")
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        status = "filtered"

        for family, socktype, proto, canonname, sa in addr_info:
            try:
                with socket.socket(family, socktype, proto) as current_sock:
                    current_sock.settimeout(timeout)
                    result = current_sock.connect_ex(sa)

                    if result == 0:
                        status = "open"
                        break
                    elif result in (111, 61, 100, 113):
                        status = "closed"
            except Exception:
                pass

    except socket.timeout:
        status = "filtered"
    except Exception:
        status = "filtered"

    return status


def grab_banner(host, port, timeout=4.0, use_tls=False):
    try:
        raw_sock = socket.socket()
        raw_sock.settimeout(timeout)

        with raw_sock:
            raw_sock.connect((host, port))

            sock = raw_sock
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(raw_sock, server_hostname=host)

            sock.settimeout(timeout)
            data = b""
            try:
                if not use_tls and port in (80, 8080):
                    sock.send(b"GET / HTTP/1.0\r\n\r\n")
                elif use_tls and port in (443, 8443):
                    pass

                data = sock.recv(4096)
            except socket.timeout:
                pass
            except Exception:
                pass

        b64 = base64.b64encode(data).decode()
        return True, b64, data

    except Exception as e:
        return False, "", str(e).encode()


def check_cert_validity(not_before_str, not_after_str):
    try:
        date_format = "%b %d %H:%M:%S %Y %Z"
        try:
            not_before = datetime.datetime.strptime(not_before_str, date_format)
            not_after = datetime.datetime.strptime(not_after_str, date_format)
        except ValueError:
            date_format_no_tz = "%b %d %H:%M:%S %Y"
            not_before = datetime.datetime.strptime(not_before_str.replace(" GMT", ""), date_format_no_tz)
            not_after = datetime.datetime.strptime(not_after_str.replace(" GMT", ""), date_format_no_tz)

        now = datetime.datetime.now()
        is_expired = now > not_after
        is_not_yet_valid = now < not_before

        return {
            "is_valid_now": not is_expired and not is_not_yet_valid,
            "is_expired": is_expired,
            "is_not_yet_valid": is_not_yet_valid,
            "expiry_days_left": (not_after - now).days
        }
    except Exception as e:
        return {"error": f"Failed to parse certificate validity dates: {e}"}


def calculate_favicon_hash(host, port, scheme, timeout):
    favicon_url = f"{scheme}://{host}:{port}/favicon.ico"
    try:
        r = requests.get(favicon_url, timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code == 200 and r.content and len(r.content) > 10:
            sha256 = hashlib.sha256(r.content).hexdigest()
            return sha256
    except Exception:
        pass
    return None


def fingerprint_web_app(r: requests.Response):
    fingerprints = {
        "stack_hints": [],
        "cms_hints": [],
        "waf_detection": None,
        "well_known_files": {}
    }

    waf_patterns = {
        "X-Sucuri-ID": "Sucuri WAF",
        "Cloudflare-Ray": "Cloudflare CDN/WAF",
        "X-Mod-Security": "ModSecurity/WAF",
        "Server-Signature": "AkamaiGHost",
        "X-Powered-By": "ASP.NET",
    }
    for header, name in waf_patterns.items():
        if header in r.headers:
            if "Cloudflare-Ray" in header and "Cloudflare" not in r.headers.get("Server", ""):
                pass
            elif "Server" == header and name == r.headers.get(header):
                fingerprints["waf_detection"] = name
                break
            else:
                fingerprints["waf_detection"] = name
                break

    server_header = r.headers.get("Server", "").lower()
    if "apache" in server_header:
        fingerprints["stack_hints"].append("Apache HTTP Server")
    if "nginx" in server_header:
        fingerprints["stack_hints"].append("Nginx")
    if "iis" in server_header:
        fingerprints["stack_hints"].append("Microsoft IIS")
    if "tomcat" in server_header:
        fingerprints["stack_hints"].append("Apache Tomcat")
    if "express" in server_header:
        fingerprints["stack_hints"].append("Node.js / Express")

    lower_text = r.text.lower()
    if "wp-content" in lower_text or "wp-includes" in lower_text or 'generator" content="wordpress' in lower_text:
        fingerprints["cms_hints"].append("WordPress")
    if 'name="Generator" content="Drupal' in r.text or "sites/all/themes" in lower_text:
        fingerprints["cms_hints"].append("Drupal")
    if 'name="generator" content="Joomla!' in r.text:
        fingerprints["cms_hints"].append("Joomla!")
    if "csrftoken" in r.cookies or "django-debug-toolbar" in lower_text:
        if "Django Framework" not in fingerprints["stack_hints"]:
            fingerprints["stack_hints"].append("Django Framework")

    return fingerprints


def http_probe(host, port, timeout, use_https=False):
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"

    http_result = {
        "url": url,
        "final_url": None,
        "status_code": None,
        "title": None,
        "meta_description": None,
        "server_header": None,
        "cookies": None,
        "body_sample": None,
        "fingerprint": None,
        "favicon_hash_sha256": None,
        "allowed_methods": None,
        "unsafe_methods_detected": False,
    }
    
    session = requests.Session()
    session.max_redirects = 5

    try:
        r = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
        http_result["final_url"] = r.url
        http_result["status_code"] = r.status_code
        
        # HTTP OPTIONS METHOD CHECK
        try:
            options_response = session.options(url, timeout=timeout, verify=False, allow_redirects=False)
            allowed_methods = options_response.headers.get("Allow", "")
            if allowed_methods:
                http_result["allowed_methods"] = allowed_methods
                dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
                detected_dangerous = []
                
                for method in dangerous_methods:
                    if method in allowed_methods.upper():
                        detected_dangerous.append(method)
                
                if detected_dangerous:
                    http_result["unsafe_methods_detected"] = True
                    http_result["dangerous_methods"] = detected_dangerous
                    
                    if http_result.get("fingerprint"):
                        if "warnings" not in http_result["fingerprint"]:
                            http_result["fingerprint"]["warnings"] = []
                        http_result["fingerprint"]["warnings"].append(
                            f"Dangerous HTTP methods allowed: {', '.join(detected_dangerous)}"
                        )
        except Exception as e:
            http_result["allowed_methods"] = f"Error: {str(e)}"
        
        # Basic Fingerprinting
        http_result["fingerprint"] = fingerprint_web_app(r)
        
        # Extract title
        title = ""
        title_match = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
        http_result["title"] = title

        # Extract meta description
        meta_desc = ""
        meta_match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']', r.text, re.IGNORECASE)
        if meta_match:
            meta_desc = meta_match.group(1).strip()
        http_result["meta_description"] = meta_desc
        
        # Set-Cookie summary
        cookies = r.headers.get("Set-Cookie", "")
        http_result["cookies"] = cookies.split(";")[0] if cookies else None

        # Body sample (4 KB)
        http_result["body_sample"] = r.text[:4096]
        http_result["server_header"] = r.headers.get("Server")

    except Exception as e:
        http_result["error"] = str(e)
        return http_result

    # File Checks
    file_checks = {
        "/robots.txt": "Robots Exclusion Protocol",
        "/sitemap.xml": "SEO Index",
        "/wp-login.php": "WordPress Login",
        "/xmlrpc.php": "WordPress XML-RPC API"
    }

    well_known_files_status = {}
    for path, description in file_checks.items():
        file_url = f"{scheme}://{host}:{port}{path}"
        try:
            head_r = session.head(file_url, timeout=timeout, verify=False, allow_redirects=True)
            well_known_files_status[path] = {
                "exists": head_r.status_code in (200, 301, 302),
                "status": head_r.status_code,
                "hint": description
            }
        except Exception:
            well_known_files_status[path] = {"exists": False, "status": "Error", "hint": description}

    if http_result["fingerprint"]:
        http_result["fingerprint"]["well_known_files"] = well_known_files_status
    
    # Favicon Hash Calculation
    http_result["favicon_hash_sha256"] = calculate_favicon_hash(host, port, scheme, timeout)

    return http_result


def tls_analyze(host, port, timeout=5.0):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    cert_info = {}

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # TLS CIPHER DETECTION
                try:
                    cipher = ssock.cipher()
                    if cipher:
                        cert_info["cipher_suite"] = cipher[0]
                        cert_info["tls_version"] = cipher[1]
                        cert_info["cipher_key_length"] = cipher[2]
                        
                        weak_ciphers = [
                            "RC4", "DES", "3DES", "NULL", "EXPORT", 
                            "MD5", "SHA1", "ANON", "ADH", "LOW"
                        ]
                        cipher_name = cipher[0].upper()
                        
                        if "weak_flags" not in cert_info:
                            cert_info["weak_flags"] = []
                        
                        if any(weak in cipher_name for weak in weak_ciphers):
                            cert_info["weak_flags"].append(f"Weak cipher detected: {cipher[0]}")
                        
                        if "SSL" in cert_info["tls_version"]:
                            cert_info["weak_flags"].append(f"Outdated protocol: {cert_info['tls_version']}")
                        elif cert_info["tls_version"] in ["TLSv1", "TLSv1.0", "TLSv1.1"]:
                            cert_info["weak_flags"].append(f"Deprecated TLS version: {cert_info['tls_version']}")
                except Exception as e:
                    cert_info["cipher_error"] = str(e)
                
                # Certificate Extraction
                cert = ssock.getpeercert()
                chain = ssock.getpeercert(True)

                # Verify against system CAs
                verification_success = False
                try:
                    verify_context = ssl.create_default_context()
                    verify_context.check_hostname = True
                    verify_context.verify_mode = ssl.CERT_REQUIRED
                    
                    with socket.create_connection((host, port), timeout=timeout) as verify_sock:
                        with verify_context.wrap_socket(verify_sock, server_hostname=host):
                            verification_success = True
                except Exception:
                    verification_success = False

                # Extract Subject, Issuer, and Validity
                cert_info["subject_cn"] = next(
                    (item[0][1] for item in cert.get("subject", []) if item[0][0] == 'commonName'), None
                )
                cert_info["issuer_cn"] = next(
                    (item[0][1] for item in cert.get("issuer", []) if item[0][0] == 'commonName'), None
                )
                cert_info["not_before"] = cert.get("notBefore")
                cert_info["not_after"] = cert.get("notAfter")
                
                # Validity Check
                if cert_info["not_before"] and cert_info["not_after"]:
                    validity = check_cert_validity(cert_info["not_before"], cert_info["not_after"])
                    cert_info.update(validity)
                
                # Public Key and Signature Details
                pubkey = cert.get("pubkey")
                cert_info["pubkey_type"] = pubkey[0] if pubkey and isinstance(pubkey, tuple) else None
                cert_info["pubkey_size"] = pubkey[1] if pubkey and isinstance(pubkey, tuple) else None
                cert_info["signature_algorithm"] = cert.get("signature-alg")

                # SANs
                cert_info["san"] = [item[1] for item in cert.get("subjectAltName", [])]

                # Chain and Verification
                cert_info["chain_length"] = len(chain) if chain else 0
                cert_info["system_ca_verified"] = verification_success

                # Initialize weak_flags if not already done
                if "weak_flags" not in cert_info:
                    cert_info["weak_flags"] = []
                
                # Weak RSA key size
                if cert_info["pubkey_type"] == "RSA" and cert_info["pubkey_size"] and cert_info["pubkey_size"] < 2048:
                    cert_info["weak_flags"].append(f"RSA key size < 2048 ({cert_info['pubkey_size']})")
                
                # Weak Signature Algorithm
                if cert_info["signature_algorithm"] and "md5" in cert_info["signature_algorithm"].lower():
                    cert_info["weak_flags"].append("Weak signature algorithm (MD5)")

                return cert_info

    except ssl.SSLError as e:
        return {"error": f"TLS Handshake Error: {str(e)}", "system_ca_verified": False}
    except socket.timeout:
        return {"error": "TLS Handshake Timeout"}
    except Exception as e:
        return {"error": f"General TLS Error: {str(e)}"}


def scan_one(host, port, args):
    result = {
        "status": "closed",
        "banner": None,
        "service_hint": None,
        "http": None,
        "tls": None,
        "https": None,
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    # 1. Perform TCP connect scan
    tcp_status = tcp_connect_scan(host, port, timeout=args.timeout)
    result["tcp_status"] = tcp_status

    if tcp_status != "open":
        result["status"] = tcp_status
        return result

    # 2. Port is open, continue probing
    result["status"] = "open"

    # 3. Grab generic banner
    open_flag, b64_banner, raw_banner = grab_banner(host, port, timeout=args.timeout, use_tls=False)

    if not open_flag:
        result["status"] = "closed"
        result["banner"] = raw_banner.decode('utf-8', 'ignore')
        return result

    result["status"] = "open"
    result["banner"] = b64_banner

    # 4. HTTP probe (Non-TLS)
    looks_http = raw_banner.startswith(b"HTTP/")
    if args.http or looks_http:
        result["service_hint"] = "http"
        result["http"] = http_probe(host, port, timeout=args.timeout, use_https=False)

    # 5. TLS probe

    if args.tls or port in (443, 8443):
        tls_flag, b64_tls_banner, tls_error_msg = grab_banner(host, port, timeout=args.timeout, use_tls=True)

        if tls_flag:  # <-- FIXED: Only check if TLS socket connection succeeded
            tls_analysis_result = tls_analyze(host, port, timeout=args.timeout)
            result["tls"] = tls_analysis_result
            
            # Store banner if we have one and TLS analysis was successful
            if 'error' not in result['tls'] and b64_tls_banner:
                result['tls']['initial_banner'] = b64_tls_banner

            if args.http and 'error' not in result['tls']:
                result["https"] = http_probe(host, port, timeout=args.timeout, use_https=True)
        else:
            error_message = tls_error_msg.decode('utf-8', 'ignore').strip()
            result["tls"] = {"error": error_message if error_message else "TLS Handshake Failed"}
            # DO NOT PUT return result HERE! Let the function continue to the normal return at the end


    return result

def run_scan_with_retry(host, port, args, delay_sec, max_retries=3):
    if delay_sec > 0.0:
        time.sleep(delay_sec)

    for attempt in range(max_retries):
        try:
            result = scan_one(host, port, args)

            if result.get("tcp_status") not in ("open", "closed"):
                log.warning(f"[{host}:{port}] Scan returned status '{result.get('tcp_status')}'. Attempting retry {attempt + 1}/{max_retries}.")

                if attempt < max_retries - 1:
                    backoff = (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(backoff)
                    continue

            return result

        except Exception as e:
            log.error(f"[{host}:{port}] Unhandled exception during scan: {e}")
            if args.verbose:
                log.debug(f"[{host}:{port}] Stack Trace:", exc_info=True)

            if attempt < max_retries - 1:
                backoff = (2 ** attempt) + random.uniform(0, 1)
                log.warning(f"[{host}:{port}] Transient failure. Retrying in {backoff:.2f}s... ({attempt + 1}/{max_retries})")
                time.sleep(backoff)
                continue

            return {"status": "error", "error": f"Failed after {max_retries} retries: {str(e)}"}

    return {"status": "error", "error": f"Exhausted all {max_retries} retry attempts."}


def write_csv(results_json, output_prefix):
    csv_path = output_prefix + ".csv"
    
    fieldnames = [
        "host", "port", "tcp_status", "service_hint",
        "http_status", "title", "server_header", "favicon_hash_sha256",
        "cert_subject_cn", "cert_not_after", "cert_is_expired", "cert_valid_now",
        "tls_version", "cipher_suite",
        "allowed_methods", "unsafe_methods",
        "banner_snippet", "fingerprint_tags", "well_known_files_found"
    ]
    
    csv_data = []

    for host, host_data in results_json["targets"].items():
        for port, port_data in host_data["ports"].items():
            if not port_data:
                continue

            if port_data.get("tcp_status") == "filtered":
                continue

            row = {
                "host": host,
                "port": port,
                "tcp_status": port_data.get("tcp_status", "n/a"),
                "service_hint": port_data.get("service_hint", "tcp"),
                "http_status": None,
                "title": None,
                "server_header": None,
                "favicon_hash_sha256": None,
                "cert_subject_cn": None,
                "cert_not_after": None,
                "cert_is_expired": None,
                "cert_valid_now": None,
                "tls_version": None,
                "cipher_suite": None,
                "allowed_methods": None,
                "unsafe_methods": None,
                "banner_snippet": None,
                "fingerprint_tags": "",
                "well_known_files_found": "",
            }

            # Handle TLS data
            tls_data = port_data.get("tls")
            if tls_data and not tls_data.get("error"):
                row["cert_subject_cn"] = tls_data.get("subject_cn")
                row["cert_not_after"] = tls_data.get("not_after")
                row["cert_is_expired"] = tls_data.get("is_expired")
                row["cert_valid_now"] = tls_data.get("is_valid_now")
                row["tls_version"] = tls_data.get("tls_version")
                row["cipher_suite"] = tls_data.get("cipher_suite")

            # Handle HTTP/HTTPS data
            http_data = port_data.get("http") or port_data.get("https")
            if http_data and not http_data.get("error"):
                row["http_status"] = http_data.get("status_code")
                row["title"] = http_data.get("title")
                row["server_header"] = http_data.get("server_header")
                row["favicon_hash_sha256"] = http_data.get("favicon_hash_sha256")
                row["allowed_methods"] = http_data.get("allowed_methods")
                row["unsafe_methods"] = http_data.get("unsafe_methods_detected", False)
                
                fp = http_data.get("fingerprint")
                if fp:
                    tags = fp["stack_hints"] + fp["cms_hints"]
                    if fp["waf_detection"]:
                        tags.append("WAF:" + fp["waf_detection"])
                    if fp.get("warnings"):
                        tags.extend(fp["warnings"])
                    row["fingerprint_tags"] = " | ".join(tags)
                    
                    found_files = [k for k, v in fp.get("well_known_files", {}).items() if v.get("exists")]
                    row["well_known_files_found"] = ", ".join(found_files)

            # Handle banner snippet
            banner_b64 = port_data.get("banner")
            if banner_b64 and banner_b64 != "closed":
                try:
                    banner_raw = base64.b64decode(banner_b64).decode('utf-8', 'ignore')
                    row["banner_snippet"] = banner_raw[:50].replace('\n', ' ').replace('\r', '').strip()
                except Exception:
                    row["banner_snippet"] = "n/a"
            
            csv_data.append(row)

    if not csv_data:
        log.info(f"\nNo open services found in data to report. Skipping CSV creation.")
        return

    try:
        with open(csv_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_data)
            log.info(f"Saved CSV summary to {csv_path}")
    except Exception as e:
        log.error(f"Failed to write CSV file: {e}")


def main():
    args = parse_args()
    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log.setLevel(log_level)
    
    delay_sec = (1.0 / args.rate) if args.rate > 0.0 else 0.0
    json_path = args.output + ".json" if args.output else None
    
    targets = read_targets(args.targets)
    ports = parse_ports(args.ports)
    
    results = {
        "metadata": {
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "targets_count": len(targets),
            "ports_count": len(ports),
            "workers": args.workers,
            "rate_limit": args.rate,
            "resumed": False,
        },
        "targets": {}
    }
    
    if args.resume and json_path and os.path.exists(json_path):
        log.info(f"Attempting to resume scan from {json_path}...")
        try:
            with open(json_path, 'r') as f:
                resumed_data = json.load(f)
                results["targets"] = resumed_data.get("targets", {})
                results["metadata"]["resumed"] = True
                log.info(f"Successfully loaded {len(results['targets'])} existing targets.")
        except Exception as e:
            log.warning(f"Failed to load existing JSON file for resume ({e}). Starting a new scan.")
    
    tasks = []
    scanned_count = 0
    
    for host in targets:
        if host not in results["targets"]:
            results["targets"][host] = {"ports": {}}
        
        for port in ports:
            port_str = str(port)
            
            if args.resume and results["targets"][host]["ports"].get(port_str):
                log.debug(f"Skipping scanned target: {host}:{port}")
                scanned_count += 1
                continue
                
            tasks.append((host, port))

    log.info(f"Total tasks to scan: {len(tasks)} (Skipped {scanned_count} already scanned ports).")
    
    if not tasks:
        log.info("No new tasks to run. Exiting.")
        return
        
    current_tasks_run = 0
    
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(run_scan_with_retry, host, port, args, delay_sec, 3): (host, port)
            for host, port in tasks
        }
        
        for future in as_completed(futures):
            host, port = futures[future]
            port_str = str(port)
            current_tasks_run += 1
            
            try:
                port_result = future.result()
                results["targets"][host]["ports"][port_str] = port_result
                
                log.info(
                    f"[{host}:{port_str}] Status: {port_result.get('status', 'error')}"
                    f" (Completed {current_tasks_run}/{len(tasks)})"
                )
            except Exception as e:
                log.error(f"[{host}:{port_str}] Worker failed unexpectedly: {e}")
                results["targets"][host]["ports"][port_str] = {"status": "error", "error": f"Worker failure: {str(e)}"}

    results["metadata"]["end_time"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    results["metadata"]["total_tasks_run"] = current_tasks_run
    
    if json_path:
        try:
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=4)
            log.info(f"Saved JSON results to {json_path}")
        except Exception as e:
            log.error(f"Failed to write JSON output file {json_path}: {e}")
            
    if args.output:
        write_csv(results, args.output)


if __name__ == '__main__':
    main()