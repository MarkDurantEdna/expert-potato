import requests
import os
import socket
import re
import json
import time
import random
from multiprocessing.dummy import Pool as ThreadPool
from colorama import Fore, init
from io import StringIO
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

# Inisialisasi colorama
init(autoreset=True)

# File hasil default
DEFAULT_RESULT_FILE = "Resultz.txt"
SUBDOMAIN_FILE = "Subdomains.txt"

# Set untuk melacak domain yang sudah diproses
scanned_domains = set()
scanned_subdomains = set()
failed_requests = {}  # Track failed requests per source

# Daftar pola regex untuk mengecualikan domain
EXCLUDED_PATTERNS = [
    r'^\*\.',
    r'\.((admin)?([use0-9-]+\.?)?([meursac0-9-]+)?cas([govdf-]+)?\.[mu]s|eng\.cartera\.com)$',
    r'direct\.quickconnect\.[a-z]{2,3}',
    r'\.(google|yandex|heroku(app(dev)?|snitest)?|twitter|onrender|telegram|remotewd|unpkg|github|wordpress|fb|facebook|baidu|pinterest|jquery|shopify|onesignal|cloudflare|naver|bootstrapcdn|maxcdn|sentry-cdn|unit4cloud)\.com$',
    r'\.(mongodb([govqade-]+)?|opendns(test)?)\.net$',
    r'\.(keenetic)\.io$',
    r'\.(keenetic)\.pro$',
    r'\.(keenetic|temporary)\.link$',
    r'\.(now)\.sh$',
    r'\.(quickconnect|baidu)\.cn$',
    r'\.(yandex)\.ru$',
    r'\.(repl)\.co$',
    r'\.(synology|wp|fb|t)\.me$',
    r'\.(altervista|wp|jquery)\.org$',
    r'\.(plex|ui|meraki)\.direct$',
    r'\.(workers|aws|amazon|pages)\.dev$',
    r'\.(vpce|kafka[a-z0-9-]{4,}\.[a-z0-9-]{4,})\.amazonaws\.com(\.cn)?$',
    r'^(cpanel|webmail|webdisk|cpcontacts|cpcalendars)\..+\.[a-z]{2,}$',
    r'\.(azure|azurewebsites|azureedge|azuredns|azure-api|azurefd|trafficmanager)\.(com|net|cn)$',
    r'azure\..+\.[a-z]{2,}$',
    r'^www\..+',
    r'\.plex\.pet$',
    r'\.cloudflarestorage\.[a-z]{2,}$'
]

# User agents untuk rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
]

# Subdomain sources yang TERBUKTI BEKERJA
SUBDOMAIN_SOURCES = [
    {
        'name': 'crt.sh',
        'url': 'https://crt.sh/?q=%.{domain}&output=json',
        'parser': 'parse_crtsh',
        'weight': 10,
        'timeout': 15
    },
    {
        'name': 'hackertarget',
        'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
        'parser': 'parse_hackertarget',
        'weight': 8,
        'timeout': 10
    },
    {
        'name': 'alienvault',
        'url': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
        'parser': 'parse_alienvault',
        'weight': 8,
        'timeout': 10
    },
    {
        'name': 'rapiddns',
        'url': 'https://rapiddns.io/subdomain/{domain}?full=1&output=json',
        'parser': 'parse_rapiddns',
        'weight': 7,
        'timeout': 10
    },
    {
        'name': 'bufferover',
        'url': 'https://dns.bufferover.run/dns?q=.{domain}',
        'parser': 'parse_bufferover',
        'weight': 7,
        'timeout': 10
    },
    {
        'name': 'urlscan',
        'url': 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
        'parser': 'parse_urlscan',
        'weight': 5,
        'timeout': 15
    },
    {
        'name': 'wayback',
        'url': 'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey',
        'parser': 'parse_wayback',
        'weight': 5,
        'timeout': 20
    },
    {
        'name': 'certspotter',
        'url': 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names',
        'parser': 'parse_certspotter',
        'weight': 6,
        'timeout': 10
    },
    {
        'name': 'threatcrowd',
        'url': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
        'parser': 'parse_threatcrowd',
        'weight': 5,
        'timeout': 10
    },
    {
        'name': 'anubis',
        'url': 'https://jldc.me/anubis/subdomains/{domain}',
        'parser': 'parse_anubis',
        'weight': 7,
        'timeout': 10
    }
]

class SubdomainScanner:
    def __init__(self, domain, max_retries=3):
        self.domain = domain
        self.max_retries = max_retries
        self.session = self._create_session()
        self.found_subdomains = set()
        
    def _create_session(self):
        """Create session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _get_headers(self):
        """Get random headers to avoid blocking"""
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
    
    def _make_request(self, url, timeout=10, source_name=""):
        """Make HTTP request with rate limiting and error handling"""
        for attempt in range(self.max_retries):
            try:
                # Rate limiting
                time.sleep(random.uniform(1, 2))
                
                response = self.session.get(
                    url, 
                    headers=self._get_headers(), 
                    timeout=timeout,
                    verify=False  # Disable SSL verification for some sources
                )
                
                if response.status_code == 200:
                    return response
                elif response.status_code == 429:
                    # Too many requests - wait longer
                    wait_time = (attempt + 1) * 5
                    print(Fore.YELLOW + f"[!] Rate limited by {source_name}, waiting {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(Fore.YELLOW + f"[!] {source_name} returned status {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(Fore.YELLOW + f"[!] Timeout for {source_name} (attempt {attempt + 1})")
            except requests.exceptions.ConnectionError:
                print(Fore.YELLOW + f"[!] Connection error for {source_name} (attempt {attempt + 1})")
            except Exception as e:
                print(Fore.YELLOW + f"[!] Error for {source_name}: {str(e)}")
            
            if attempt < self.max_retries - 1:
                time.sleep(2 * (attempt + 1))
        
        return None
    
    # Parser functions for each source
    def parse_crtsh(self, response):
        """Parse crt.sh response"""
        subdomains = set()
        try:
            data = response.json()
            for entry in data:
                if 'name_value' in entry:
                    names = entry['name_value'].split('\n')
                    for name in names:
                        if name and self.domain in name:
                            clean_name = name.strip().lower()
                            if clean_name.endswith(self.domain):
                                subdomains.add(clean_name)
        except:
            pass
        return subdomains
    
    def parse_hackertarget(self, response):
        """Parse hackertarget response"""
        subdomains = set()
        try:
            lines = response.text.strip().split('\n')
            for line in lines:
                if ',' in line:
                    subdomain = line.split(',')[0].strip()
                    if subdomain and self.domain in subdomain:
                        subdomains.add(subdomain.lower())
        except:
            pass
        return subdomains
    
    def parse_alienvault(self, response):
        """Parse alienvault response"""
        subdomains = set()
        try:
            data = response.json()
            if 'passive_dns' in data:
                for entry in data['passive_dns']:
                    if 'hostname' in entry:
                        hostname = entry['hostname'].lower()
                        if hostname.endswith(self.domain):
                            subdomains.add(hostname)
        except:
            pass
        return subdomains
    
    def parse_rapiddns(self, response):
        """Parse rapiddns response"""
        subdomains = set()
        try:
            data = response.json()
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and 'name' in item:
                        name = item['name'].lower()
                        if name.endswith(self.domain):
                            subdomains.add(name)
        except:
            pass
        return subdomains
    
    def parse_bufferover(self, response):
        """Parse bufferover response"""
        subdomains = set()
        try:
            data = response.json()
            if 'FDNS_A' in data:
                for entry in data['FDNS_A']:
                    if ',' in entry:
                        subdomain = entry.split(',')[1].lower()
                        if subdomain.endswith(self.domain):
                            subdomains.add(subdomain)
        except:
            pass
        return subdomains
    
    def parse_urlscan(self, response):
        """Parse urlscan response"""
        subdomains = set()
        try:
            data = response.json()
            if 'results' in data:
                for result in data['results']:
                    if 'page' in result and 'domain' in result['page']:
                        domain = result['page']['domain'].lower()
                        if domain.endswith(self.domain):
                            subdomains.add(domain)
        except:
            pass
        return subdomains
    
    def parse_wayback(self, response):
        """Parse wayback machine response"""
        subdomains = set()
        try:
            data = response.json()
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, list) and len(item) > 0:
                        url = item[0].lower()
                        # Extract domain from URL
                        parsed = urlparse(url)
                        if parsed.netloc:
                            domain = parsed.netloc
                            if domain.endswith(self.domain):
                                subdomains.add(domain)
        except:
            pass
        return subdomains
    
    def parse_certspotter(self, response):
        """Parse certspotter response"""
        subdomains = set()
        try:
            data = response.json()
            for entry in data:
                if 'dns_names' in entry:
                    for name in entry['dns_names']:
                        name = name.lower()
                        if name.endswith(self.domain):
                            subdomains.add(name)
        except:
            pass
        return subdomains
    
    def parse_threatcrowd(self, response):
        """Parse threatcrowd response"""
        subdomains = set()
        try:
            data = response.json()
            if 'subdomains' in data:
                for sub in data['subdomains']:
                    if sub.endswith(self.domain):
                        subdomains.add(sub.lower())
        except:
            pass
        return subdomains
    
    def parse_anubis(self, response):
        """Parse anubis response"""
        subdomains = set()
        try:
            data = response.json()
            if isinstance(data, list):
                for sub in data:
                    if sub.endswith(self.domain):
                        subdomains.add(sub.lower())
        except:
            pass
        return subdomains
    
    def scan(self):
        """Scan all sources for subdomains"""
        print(Fore.CYAN + f"\n[+] Scanning subdomains for {self.domain} from multiple sources...")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for source in SUBDOMAIN_SOURCES:
                url = source['url'].format(domain=self.domain)
                futures.append(
                    executor.submit(
                        self._scan_source, 
                        source['name'], 
                        url, 
                        source['parser'], 
                        source['timeout']
                    )
                )
            
            for future in as_completed(futures):
                try:
                    subdomains = future.result()
                    self.found_subdomains.update(subdomains)
                except Exception as e:
                    print(Fore.RED + f"[!] Error in source scan: {str(e)}")
        
        # Also try the original ip.thc.org source with larger limit
        self._scan_thc_source()
        
        return self.found_subdomains
    
    def _scan_source(self, source_name, url, parser_name, timeout):
        """Scan individual source"""
        subdomains = set()
        try:
            print(Fore.BLUE + f"[~] Querying {source_name}...")
            response = self._make_request(url, timeout, source_name)
            
            if response:
                parser = getattr(self, parser_name)
                subdomains = parser(response)
                if subdomains:
                    print(Fore.GREEN + f"[✓] {source_name}: {len(subdomains)} subdomains found")
                else:
                    print(Fore.YELLOW + f"[-] {source_name}: No subdomains found")
            else:
                print(Fore.RED + f"[✗] {source_name}: Failed to fetch data")
                
        except Exception as e:
            print(Fore.RED + f"[!] Error scanning {source_name}: {str(e)}")
        
        return subdomains
    
    def _scan_thc_source(self):
        """Scan original thc source with larger limit"""
        try:
            # Try with increasing limits to avoid detection
            for limit in [10000, 25000, 50000, 100000]:
                url = f"https://ip.thc.org/api/v1/subdomains/download?domain={self.domain}&limit={limit}&hide_header=true"
                print(Fore.BLUE + f"[~] Querying ip.thc.org with limit {limit}...")
                
                response = self._make_request(url, timeout=20, source_name="ip.thc.org")
                
                if response and response.status_code == 200 and response.text.strip():
                    subdomains = response.text.strip().split('\n')
                    # Filter valid subdomains
                    valid_subdomains = {sub.lower() for sub in subdomains 
                                      if sub and self.domain in sub.lower()}
                    
                    if valid_subdomains:
                        print(Fore.GREEN + f"[✓] ip.thc.org ({limit}): {len(valid_subdomains)} subdomains found")
                        self.found_subdomains.update(valid_subdomains)
                        break  # Stop if successful
                    
        except Exception as e:
            print(Fore.RED + f"[!] Error scanning ip.thc.org: {str(e)}")

# Fungsi untuk mengubah domain menjadi IP
def domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

# Fungsi untuk mendapatkan subdomain (updated)
def get_subdomains(domain, output_file):
    if domain in scanned_subdomains:
        print(Fore.YELLOW + f"[!] Skipping Subdomain Scan for {domain}, already scanned.")
        return

    buffer = StringIO()
    try:
        # Use the new multi-source scanner
        scanner = SubdomainScanner(domain)
        all_subdomains = scanner.scan()
        
        # Filter and save
        new_subdomains = [sub for sub in all_subdomains if sub not in scanned_subdomains]
        
        if new_subdomains:
            print(Fore.BLUE + f"[+] {domain} => {len(new_subdomains)} New Subdomains Found (Total: {len(all_subdomains)})")
            for sub in new_subdomains:
                buffer.write(sub + "\n")
                scanned_subdomains.add(sub)
            
            with open(output_file, "a") as file:
                file.write(buffer.getvalue())
        else:
            print(Fore.YELLOW + f"[?] {domain} => No New Subdomains Found.")
            
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching subdomains for {domain}: {str(e)}")
    finally:
        buffer.close()

# Fungsi untuk reverse IP lookup (sama seperti sebelumnya)
def revip(target, scan_subdomains=False, filter_extensions=False, output_file=DEFAULT_RESULT_FILE, custom_extensions=None):
    if target in scanned_domains:
        print(Fore.YELLOW + f"[!] Skipping Reverse IP Scan for {target}, already scanned.")
        return

    buffer = StringIO()
    unique_domains = set()
    try:
        if not target.replace(".", "").isdigit():
            target = domain_to_ip(target)
            if target is None:
                return

        url = f"https://ip.thc.org/api/v1/download?ip_address={target}&limit=50000&hide_header=true"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        response = requests.get(url, headers=headers, timeout=15)
        time.sleep(1)  # Jeda untuk stabilitas

        if response.status_code == 200 and response.text.strip():
            lines = response.text.strip().split("\n")
            extracted_domains = []
            for line in lines:
                parts = line.split(",")
                if len(parts) > 1:
                    extracted_domains.append(parts[1])

            print(Fore.GREEN + f"[+] {target} => {len(extracted_domains)} Domains Extracted")

            extensions = custom_extensions if filter_extensions and custom_extensions else None
            filtered_domains = []

            for domain in extracted_domains:
                if any(re.search(pattern, domain.lower()) for pattern in EXCLUDED_PATTERNS):
                    continue

                if domain not in scanned_domains and domain not in unique_domains:
                    unique_domains.add(domain)
                    if filter_extensions and extensions:
                        if any(domain.endswith(ext) for ext in extensions):
                            buffer.write(domain + "\n")
                            scanned_domains.add(domain)
                            filtered_domains.append(domain)
                    else:
                        buffer.write(domain + "\n")
                        scanned_domains.add(domain)

            if filter_extensions and extensions:
                print(Fore.BLUE + f"[+] Filtered domains with extensions {extensions}: {len(filtered_domains)}")

            with open(output_file, "a") as file:
                file.write(buffer.getvalue())

            if scan_subdomains:
                print(Fore.CYAN + f"\n[+] Starting subdomain scan for {len(unique_domains if not filter_extensions else filtered_domains)} domains...")
                
                # Use smaller thread pool for subdomain scans due to multiple sources
                pool = ThreadPool(2)  # Reduced thread count to avoid rate limiting
                domains_to_scan = unique_domains if not filter_extensions else filtered_domains
                pool.map(lambda domain: get_subdomains(domain, SUBDOMAIN_FILE), domains_to_scan)
                pool.close()
                pool.join()

    except Exception as e:
        print(Fore.RED + f"[!] Error fetching data for {target}: {str(e)}")
    finally:
        buffer.close()

# Menu utama (sama seperti sebelumnya)
print(Fore.GREEN + "[1] Reverse IP Only")
print(Fore.GREEN + "[2] Reverse IP + Subdomain Scan (Multi-Source)")
print(Fore.GREEN + "[3] Remove Duplicate Domains")
print(Fore.GREEN + "[4] Reverse IP with Custom Extension Filter")
select = input(Fore.WHITE + "root@localhost:~# ")

if select in ["1", "2", "4"]:
    scan_subdomains = select == "2"
    filter_extensions = select == "4"
    custom_extensions = None

    print(Fore.RED + "Starting Scan...")
    print("===============================")

    target_file = input(Fore.WHITE + 'List (file txt):~# ')
    try:
        with open(target_file, 'r') as f:
            targets = f.read().splitlines()
    except FileNotFoundError:
        print(Fore.RED + "[!] File tidak ditemukan!")
        exit()

    output_file = input(Fore.WHITE + 'Output file name (e.g., output.txt):~# ')
    if not output_file:
        output_file = DEFAULT_RESULT_FILE
        print(Fore.YELLOW + f"[!] No output file specified, using default: {DEFAULT_RESULT_FILE}")
    elif not output_file.endswith('.txt'):
        output_file += '.txt'

    if select == "4":
        extensions_input = input(Fore.WHITE + 'Enter extensions to filter (e.g., .com, .org, separate with commas):~# ')
        if extensions_input:
            custom_extensions = [ext.strip() for ext in extensions_input.split(',')]
            print(Fore.BLUE + f"[+] Filtering domains with extensions: {custom_extensions}")
        else:
            print(Fore.RED + "[!] No extensions provided, filter will not be applied.")
            filter_extensions = False

    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            scanned_domains.update(line.strip() for line in f.readlines())

    if scan_subdomains and os.path.exists(SUBDOMAIN_FILE):
        with open(SUBDOMAIN_FILE, "r") as f:
            scanned_subdomains.update(line.strip() for line in f.readlines())

    Thread = input(Fore.WHITE + 'Thread:~# ')
    try:
        thread_count = int(Thread)
        if thread_count > 8:  # Reduced max threads for stability
            print(Fore.YELLOW + "[!] Thread capped at 8 for stability.")
            thread_count = 8
    except ValueError:
        print(Fore.RED + "[!] Masukkan angka yang valid untuk jumlah thread.")
        exit()

    pool = ThreadPool(thread_count)
    pool.map(lambda target: revip(target, scan_subdomains, filter_extensions, output_file, custom_extensions), targets)
    pool.close()
    pool.join()

    print("===============================")
    if os.path.exists(output_file):
        with open(output_file, "r") as file:
            domains = [line.strip() for line in file.readlines()]
        count_result = len(domains)
        print(Fore.GREEN + f"[ + ] Total Domains Found in {output_file}: {count_result}")
    else:
        print(Fore.GREEN + f"[ + ] Total Domains Found in {output_file}: 0")

    if scan_subdomains and os.path.exists(SUBDOMAIN_FILE):
        with open(SUBDOMAIN_FILE, "r") as file:
            subdomains = [line.strip() for line in file.readlines()]
        count_subdomains = len(subdomains)
        print(Fore.BLUE + f"[ + ] Total Subdomains Found in {SUBDOMAIN_FILE}: {count_subdomains}")

elif select == "3":
    output_file = input(Fore.WHITE + 'File to remove duplicates from (e.g., Resultz.txt):~# ')
    if not output_file:
        output_file = DEFAULT_RESULT_FILE
        print(Fore.YELLOW + f"[!] No file specified, using default: {DEFAULT_RESULT_FILE}")
    elif not output_file.endswith('.txt'):
        output_file += '.txt'

    if os.path.exists(output_file):
        with open(output_file, "r") as file:
            unique_domains = set(file.read().splitlines())
        with open(output_file, "w") as file:
            for domain in unique_domains:
                file.write(domain + "\n")
        print(Fore.GREEN + f"[✓] Duplicate domains removed from {output_file}. Total unique domains: {len(unique_domains)}")
    else:
        print(Fore.RED + f"[!] {output_file} not found!")

else:
    print(Fore.RED + "[!] Pilihan tidak valid!")
