import requests
import os
import socket
import re
import json
import time
import random
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import Queue, Manager
from colorama import Fore, init
from io import StringIO
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import threading
from queue import Queue
from collections import defaultdict
import signal
import sys

# Nonaktifkan warning SSL
warnings.filterwarnings('ignore', category=InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Inisialisasi colorama
init(autoreset=True)

# File hasil default
DEFAULT_RESULT_FILE = "Resultz.txt"
SUBDOMAIN_FILE = "Subdomains.txt"

# Global variables with thread safety
manager = Manager()
scanned_domains = manager.list()
scanned_subdomains = manager.list()
domain_lock = threading.Lock()
subdomain_lock = threading.Lock()
stats = manager.dict({
    'total_reverse': 0,
    'total_subdomains': 0,
    'processed_targets': 0,
    'failed_targets': 0,
    'sources_success': defaultdict(int),
    'sources_failed': defaultdict(int)
})

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
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

# Optimized subdomain sources dengan priority
SUBDOMAIN_SOURCES = [
    {
        'name': 'alienvault',
        'url': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
        'parser': 'parse_alienvault',
        'priority': 1,  # High priority - fast and reliable
        'timeout': 10,
        'verify_ssl': True,
        'rate_limit': 2  # Requests per second
    },
    {
        'name': 'hackertarget',
        'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
        'parser': 'parse_hackertarget',
        'priority': 1,
        'timeout': 10,
        'verify_ssl': True,
        'rate_limit': 1
    },
    {
        'name': 'rapiddns',
        'url': 'https://rapiddns.io/subdomain/{domain}?full=1&output=json',
        'parser': 'parse_rapiddns',
        'priority': 2,
        'timeout': 10,
        'verify_ssl': True,
        'rate_limit': 2
    },
    {
        'name': 'bufferover',
        'url': 'https://dns.bufferover.run/dns?q=.{domain}',
        'parser': 'parse_bufferover',
        'priority': 2,
        'timeout': 10,
        'verify_ssl': True,
        'rate_limit': 2
    },
    {
        'name': 'certspotter',
        'url': 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names',
        'parser': 'parse_certspotter',
        'priority': 2,
        'timeout': 10,
        'verify_ssl': True,
        'rate_limit': 3
    },
    {
        'name': 'urlscan',
        'url': 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
        'parser': 'parse_urlscan',
        'priority': 3,
        'timeout': 15,
        'verify_ssl': True,
        'rate_limit': 1
    },
    {
        'name': 'wayback',
        'url': 'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey',
        'parser': 'parse_wayback',
        'priority': 3,
        'timeout': 20,
        'verify_ssl': True,
        'rate_limit': 1
    }
]

# Special sources yang butuh penanganan khusus
SPECIAL_SOURCES = [
    {
        'name': 'crt.sh',
        'url': 'https://crt.sh/?q=%.{domain}&output=json',
        'parser': 'parse_crtsh',
        'timeout': 15,
        'verify_ssl': False,
        'rate_limit': 0.5  # Very slow rate limit
    },
    {
        'name': 'thc',
        'url': 'https://ip.thc.org/api/v1/subdomains/download?domain={domain}&limit=5000&hide_header=true',
        'parser': 'parse_thc',
        'timeout': 15,
        'verify_ssl': False,
        'rate_limit': 1
    }
]

class RateLimiter:
    """Rate limiter for API requests"""
    def __init__(self, max_per_second):
        self.max_per_second = max_per_second
        self.min_interval = 1.0 / max_per_second if max_per_second > 0 else 0
        self.last_time = defaultdict(float)
        self.lock = threading.Lock()
    
    def wait(self, key='default'):
        with self.lock:
            now = time.time()
            last = self.last_time[key]
            if last:
                elapsed = now - last
                if elapsed < self.min_interval:
                    time.sleep(self.min_interval - elapsed)
            self.last_time[key] = time.time()

# Global rate limiters
rate_limiters = {
    'alienvault': RateLimiter(2),
    'hackertarget': RateLimiter(1),
    'rapiddns': RateLimiter(2),
    'bufferover': RateLimiter(2),
    'certspotter': RateLimiter(3),
    'urlscan': RateLimiter(1),
    'wayback': RateLimiter(1),
    'crt.sh': RateLimiter(0.5),
    'thc': RateLimiter(1)
}

class BatchProcessor:
    """Batch processor for parallel execution"""
    def __init__(self, max_workers=10, batch_size=5):
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.results_queue = Queue()
        self.progress_lock = threading.Lock()
        
    def process_batches(self, items, process_func, *args, **kwargs):
        """Process items in parallel batches"""
        total_items = len(items)
        batches = [items[i:i + self.batch_size] for i in range(0, total_items, self.batch_size)]
        
        print(Fore.CYAN + f"[+] Processing {total_items} items in {len(batches)} batches...")
        
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(batches))) as executor:
            futures = []
            for i, batch in enumerate(batches):
                future = executor.submit(
                    self._process_batch, 
                    batch, 
                    i + 1, 
                    len(batches),
                    process_func, 
                    *args, 
                    **kwargs
                )
                futures.append(future)
            
            # Wait for all batches to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(Fore.RED + f"[!] Batch error: {str(e)}")
    
    def _process_batch(self, batch, batch_num, total_batches, process_func, *args, **kwargs):
        """Process a single batch"""
        print(Fore.BLUE + f"[~] Processing batch {batch_num}/{total_batches} ({len(batch)} items)")
        
        # Process items in batch with smaller thread pool
        with ThreadPoolExecutor(max_workers=min(3, len(batch))) as executor:
            futures = []
            for item in batch:
                future = executor.submit(process_func, item, *args, **kwargs)
                futures.append(future)
            
            # Wait for all items in batch
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=30)
                    if result:
                        self.results_queue.put(result)
                except Exception as e:
                    with self.progress_lock:
                        stats['failed_targets'] += 1
                    print(Fore.RED + f"[!] Item error: {str(e)[:50]}")
        
        # Delay between batches
        if batch_num < total_batches:
            time.sleep(random.uniform(2, 4))

class SubdomainScanner:
    def __init__(self, domain, max_retries=2):
        self.domain = domain
        self.max_retries = max_retries
        self.session = self._create_session()
        self.found_subdomains = set()
        
    def _create_session(self):
        """Create session with connection pooling"""
        session = requests.Session()
        retry_strategy = Retry(
            total=1,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _get_headers(self):
        """Get random headers"""
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
    
    def _make_request(self, url, timeout=10, source_name="", verify_ssl=True):
        """Make HTTP request with rate limiting"""
        # Apply rate limiting
        if source_name in rate_limiters:
            rate_limiters[source_name].wait(source_name)
        
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(
                    url, 
                    headers=self._get_headers(), 
                    timeout=timeout,
                    verify=verify_ssl
                )
                
                if response.status_code == 200:
                    stats['sources_success'][source_name] += 1
                    return response
                elif response.status_code == 429:
                    wait_time = (attempt + 1) * 5
                    time.sleep(wait_time)
                else:
                    stats['sources_failed'][source_name] += 1
                    return None
                    
            except Exception as e:
                if attempt == self.max_retries - 1:
                    stats['sources_failed'][source_name] += 1
                time.sleep(1)
        
        return None
    
    # Parser functions (optimized)
    def parse_crtsh(self, response):
        subdomains = set()
        try:
            data = response.json()
            for entry in data[:200]:  # Limit entries
                if 'name_value' in entry:
                    names = entry['name_value'].split('\n')
                    for name in names[:10]:  # Limit per entry
                        if name and self.domain in name:
                            clean_name = name.strip().lower()
                            if clean_name.endswith(self.domain) and '*' not in clean_name:
                                subdomains.add(clean_name)
        except:
            pass
        return subdomains
    
    def parse_hackertarget(self, response):
        subdomains = set()
        try:
            lines = response.text.strip().split('\n')
            for line in lines[:500]:
                if ',' in line:
                    subdomain = line.split(',')[0].strip().lower()
                    if subdomain and subdomain.endswith(self.domain) and '*' not in subdomain:
                        subdomains.add(subdomain)
        except:
            pass
        return subdomains
    
    def parse_alienvault(self, response):
        subdomains = set()
        try:
            data = response.json()
            if 'passive_dns' in data:
                for entry in data['passive_dns'][:300]:
                    if 'hostname' in entry:
                        hostname = entry['hostname'].lower()
                        if hostname.endswith(self.domain) and '*' not in hostname:
                            subdomains.add(hostname)
        except:
            pass
        return subdomains
    
    def parse_rapiddns(self, response):
        subdomains = set()
        try:
            data = response.json()
            if isinstance(data, list):
                for item in data[:300]:
                    if isinstance(item, dict) and 'name' in item:
                        name = item['name'].lower()
                        if name.endswith(self.domain) and '*' not in name:
                            subdomains.add(name)
        except:
            pass
        return subdomains
    
    def parse_bufferover(self, response):
        subdomains = set()
        try:
            data = response.json()
            if 'FDNS_A' in data:
                for entry in data['FDNS_A'][:300]:
                    if ',' in entry:
                        subdomain = entry.split(',')[1].lower()
                        if subdomain.endswith(self.domain) and '*' not in subdomain:
                            subdomains.add(subdomain)
        except:
            pass
        return subdomains
    
    def parse_urlscan(self, response):
        subdomains = set()
        try:
            data = response.json()
            if 'results' in data:
                for result in data['results'][:100]:
                    if 'page' in result and 'domain' in result['page']:
                        domain = result['page']['domain'].lower()
                        if domain.endswith(self.domain) and '*' not in domain:
                            subdomains.add(domain)
        except:
            pass
        return subdomains
    
    def parse_wayback(self, response):
        subdomains = set()
        try:
            data = response.json()
            if isinstance(data, list):
                for item in data[:500]:
                    if isinstance(item, list) and len(item) > 0:
                        url = item[0].lower()
                        parsed = urlparse(url)
                        if parsed.netloc:
                            domain = parsed.netloc.split(':')[0]
                            if domain.endswith(self.domain) and '*' not in domain:
                                subdomains.add(domain)
        except:
            pass
        return subdomains
    
    def parse_certspotter(self, response):
        subdomains = set()
        try:
            data = response.json()
            for entry in data[:50]:
                if 'dns_names' in entry:
                    for name in entry['dns_names'][:20]:
                        name = name.lower().strip()
                        if name.endswith(self.domain) and '*' not in name:
                            subdomains.add(name)
        except:
            pass
        return subdomains
    
    def parse_thc(self, response):
        subdomains = set()
        try:
            if response.text.strip():
                lines = response.text.strip().split('\n')
                for line in lines[:500]:
                    if line and self.domain in line.lower():
                        clean = line.strip().lower()
                        if clean.endswith(self.domain) and '*' not in clean:
                            subdomains.add(clean)
        except:
            pass
        return subdomains
    
    def scan_parallel(self):
        """Scan all sources in parallel"""
        print(Fore.CYAN + f"\n[+] Scanning {self.domain} from multiple sources...")
        
        # Group sources by priority
        priority_groups = defaultdict(list)
        for source in SUBDOMAIN_SOURCES:
            priority_groups[source['priority']].append(source)
        
        # Process high priority first
        for priority in sorted(priority_groups.keys()):
            sources = priority_groups[priority]
            
            with ThreadPoolExecutor(max_workers=min(3, len(sources))) as executor:
                futures = []
                for source in sources:
                    url = source['url'].format(domain=self.domain)
                    futures.append(
                        executor.submit(
                            self._scan_source,
                            source['name'],
                            url,
                            source['parser'],
                            source['timeout'],
                            source['verify_ssl']
                        )
                    )
                
                for future in as_completed(futures):
                    try:
                        subdomains = future.result(timeout=15)
                        self.found_subdomains.update(subdomains)
                    except Exception as e:
                        pass
        
        # Process special sources
        for source in SPECIAL_SOURCES:
            try:
                url = source['url'].format(domain=self.domain)
                subdomains = self._scan_source(
                    source['name'],
                    url,
                    source['parser'],
                    source['timeout'],
                    source['verify_ssl']
                )
                self.found_subdomains.update(subdomains)
            except Exception as e:
                pass
        
        return self.found_subdomains
    
    def _scan_source(self, source_name, url, parser_name, timeout, verify_ssl):
        """Scan individual source"""
        subdomains = set()
        try:
            response = self._make_request(url, timeout, source_name, verify_ssl)
            if response:
                parser = getattr(self, parser_name)
                subdomains = parser(response)
                if subdomains:
                    print(Fore.GREEN + f"[✓] {source_name}: {len(subdomains)}")
        except Exception as e:
            pass
        return subdomains

def domain_to_ip(domain):
    """Convert domain to IP with cache"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def reverse_ip_lookup(target, filter_extensions=False, custom_extensions=None):
    """Perform reverse IP lookup"""
    if target in scanned_domains:
        return []
    
    results = []
    try:
        # Convert domain to IP if needed
        if not target.replace(".", "").isdigit():
            target = domain_to_ip(target)
            if target is None:
                return []
        
        # Try different limits
        for limit in [5000, 10000]:
            url = f"https://ip.thc.org/api/v1/download?ip_address={target}&limit={limit}&hide_header=true"
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200 and response.text.strip():
                lines = response.text.strip().split("\n")
                for line in lines[:2000]:  # Limit per IP
                    parts = line.split(",")
                    if len(parts) > 1:
                        domain = parts[1]
                        
                        # Apply filters
                        if any(re.search(pattern, domain.lower()) for pattern in EXCLUDED_PATTERNS):
                            continue
                        
                        if filter_extensions and custom_extensions:
                            if any(domain.endswith(ext) for ext in custom_extensions):
                                results.append(domain)
                        else:
                            results.append(domain)
                
                if results:
                    break  # Stop if we got results
                    
    except Exception as e:
        pass
    
    return results

def process_target(target, scan_subdomains, filter_extensions, output_file, custom_extensions):
    """Process a single target"""
    try:
        # Reverse IP lookup
        domains = reverse_ip_lookup(target, filter_extensions, custom_extensions)
        
        if domains:
            # Save unique domains
            new_domains = []
            with domain_lock:
                for domain in domains:
                    if domain not in scanned_domains:
                        scanned_domains.append(domain)
                        new_domains.append(domain)
            
            if new_domains:
                with open(output_file, "a") as f:
                    f.write("\n".join(new_domains) + "\n")
                
                stats['total_reverse'] += len(new_domains)
                print(Fore.GREEN + f"[+] {target}: {len(new_domains)} new domains")
                
                # Subdomain scan if requested
                if scan_subdomains and new_domains:
                    # Take only first 3 domains for subdomain scan
                    for domain in new_domains[:3]:
                        if domain not in scanned_subdomains:
                            scanner = SubdomainScanner(domain)
                            subdomains = scanner.scan_parallel()
                            
                            if subdomains:
                                new_subs = []
                                with subdomain_lock:
                                    for sub in subdomains:
                                        if sub not in scanned_subdomains:
                                            scanned_subdomains.append(sub)
                                            new_subs.append(sub)
                                
                                if new_subs:
                                    with open(SUBDOMAIN_FILE, "a") as f:
                                        f.write("\n".join(new_subs) + "\n")
                                    stats['total_subdomains'] += len(new_subs)
        
        with domain_lock:
            stats['processed_targets'] += 1
            
    except Exception as e:
        with domain_lock:
            stats['failed_targets'] += 1

def print_stats():
    """Print current statistics"""
    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.CYAN + "CURRENT STATISTICS:")
    print(Fore.CYAN + f"Processed: {stats['processed_targets']}")
    print(Fore.CYAN + f"Failed: {stats['failed_targets']}")
    print(Fore.GREEN + f"Domains Found: {stats['total_reverse']}")
    print(Fore.BLUE + f"Subdomains Found: {stats['total_subdomains']}")
    print(Fore.CYAN + "="*50 + "\n")

def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    print(Fore.YELLOW + "\n[!] Interrupted by user")
    print_stats()
    sys.exit(0)

# Main menu
print(Fore.GREEN + """
╔══════════════════════════════════════╗
║     PARALLEL BATCH SUBDOMAIN SCANNER  ║
╚══════════════════════════════════════╝
""")

print(Fore.GREEN + "[1] Reverse IP Only")
print(Fore.GREEN + "[2] Reverse IP + Subdomain Scan (Parallel)")
print(Fore.GREEN + "[3] Remove Duplicate Domains")
print(Fore.GREEN + "[4] Reverse IP with Custom Extension Filter")
print(Fore.YELLOW + "[5] Fast Mode (Aggressive Parallel)")

select = input(Fore.WHITE + "root@localhost:~# ")

if select in ["1", "2", "4", "5"]:
    scan_subdomains = select in ["2", "5"]
    filter_extensions = select == "4"
    fast_mode = select == "5"
    custom_extensions = None
    
    print(Fore.RED + "Starting Scan...")
    print("===============================")
    
    target_file = input(Fore.WHITE + 'List (file txt):~# ')
    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + "[!] File tidak ditemukan!")
        exit()
    
    output_file = input(Fore.WHITE + 'Output file name (e.g., output.txt):~# ')
    if not output_file:
        output_file = DEFAULT_RESULT_FILE
    elif not output_file.endswith('.txt'):
        output_file += '.txt'
    
    if select == "4":
        extensions_input = input(Fore.WHITE + 'Enter extensions (e.g., .com,.org):~# ')
        if extensions_input:
            custom_extensions = [ext.strip() for ext in extensions_input.split(',')]
    
    # Load existing data
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            for line in f:
                if line.strip() and line.strip() not in scanned_domains:
                    scanned_domains.append(line.strip())
    
    if scan_subdomains and os.path.exists(SUBDOMAIN_FILE):
        with open(SUBDOMAIN_FILE, "r") as f:
            for line in f:
                if line.strip() and line.strip() not in scanned_subdomains:
                    scanned_subdomains.append(line.strip())
    
    # Configure parallel processing
    if fast_mode:
        max_workers = 15
        batch_size = 10
        print(Fore.YELLOW + "[!] Fast Mode Enabled - Higher speed, may trigger rate limits")
    else:
        max_workers = 8
        batch_size = 5
    
    Thread = input(Fore.WHITE + f'Threads (default {max_workers}):~# ') or str(max_workers)
    try:
        thread_count = int(Thread)
        if thread_count > 20:
            print(Fore.YELLOW + "[!] Thread capped at 20")
            thread_count = 20
    except ValueError:
        thread_count = max_workers
    
    Batch = input(Fore.WHITE + f'Batch size (default {batch_size}):~# ') or str(batch_size)
    try:
        batch_size = int(Batch)
    except ValueError:
        batch_size = batch_size
    
    # Set signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start processing
    print(Fore.CYAN + f"\n[+] Starting parallel processing with {thread_count} threads, batch size {batch_size}")
    print(Fore.CYAN + f"[+] Total targets: {len(targets)}")
    
    processor = BatchProcessor(max_workers=thread_count, batch_size=batch_size)
    
    # Start stats thread
    def stats_updater():
        while True:
            time.sleep(5)
            print_stats()
    
    stats_thread = threading.Thread(target=stats_updater, daemon=True)
    stats_thread.start()
    
    # Process targets
    start_time = time.time()
    processor.process_batches(
        targets,
        process_target,
        scan_subdomains,
        filter_extensions,
        output_file,
        custom_extensions
    )
    
    # Final statistics
    elapsed = time.time() - start_time
    print(Fore.GREEN + "\n" + "="*50)
    print(Fore.GREEN + "FINAL RESULTS:")
    print(Fore.GREEN + f"Time elapsed: {elapsed:.2f} seconds")
    print(Fore.GREEN + f"Targets processed: {stats['processed_targets']}/{len(targets)}")
    print(Fore.GREEN + f"Failed: {stats['failed_targets']}")
    print(Fore.GREEN + f"Total domains found: {stats['total_reverse']}")
    print(Fore.BLUE + f"Total subdomains found: {stats['total_subdomains']}")
    print(Fore.GREEN + "="*50)
    
    # Source statistics
    print(Fore.CYAN + "\nSOURCE PERFORMANCE:")
    for source in stats['sources_success']:
        success = stats['sources_success'][source]
        failed = stats['sources_failed'].get(source, 0)
        total = success + failed
        if total > 0:
            rate = (success / total) * 100
            print(Fore.CYAN + f"{source}: {success}/{total} ({rate:.1f}%)")

elif select == "3":
    output_file = input(Fore.WHITE + 'File to remove duplicates:~# ')
    if not output_file:
        output_file = DEFAULT_RESULT_FILE
    elif not output_file.endswith('.txt'):
        output_file += '.txt'
    
    if os.path.exists(output_file):
        with open(output_file, "r") as file:
            unique_domains = set(file.read().splitlines())
        with open(output_file, "w") as file:
            file.write("\n".join(sorted(unique_domains)))
        print(Fore.GREEN + f"[✓] Removed duplicates. Total unique: {len(unique_domains)}")
    else:
        print(Fore.RED + f"[!] {output_file} not found!")

else:
    print(Fore.RED + "[!] Invalid choice!")
