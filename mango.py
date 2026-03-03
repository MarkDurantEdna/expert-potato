import requests
import json
import time
import argparse
from typing import Set, List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
import sys
import os
import re
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

class DeepSubdomainCrawler:
    def __init__(self, output_file: str = "all_subdomains.txt", threads: int = 5, delay: float = 0.5):
        self.output_file = output_file
        self.threads = threads
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.session.timeout = 30
        
        # Semua sumber API TIDAK memerlukan API key
        self.sources = {
            'crt_sh': {
                'url': 'https://crt.sh/?q=%.{domain}&output=json',
                'parser': self.parse_crtsh,
                'enabled': True,
            },
            'hackertarget': {
                'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
                'parser': self.parse_hackertarget,
                'enabled': True,
            },
            'alienvault': {
                'url': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
                'parser': self.parse_alienvault,
                'enabled': True,
            },
            'urlscan': {
                'url': 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
                'parser': self.parse_urlscan,
                'enabled': True,
            },
            'wayback': {
                'url': 'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey',
                'parser': self.parse_wayback,
                'enabled': True,
            },
            'bufferover': {
                'url': 'https://dns.bufferover.run/dns?q=.{domain}',
                'parser': self.parse_bufferover,
                'enabled': True,
            },
            'rapiddns': {
                'url': 'https://rapiddns.io/subdomain/{domain}?full=1&output=json',
                'parser': self.parse_rapiddns,
                'enabled': True,
            },
            'anubis': {
                'url': 'https://jldc.me/anubis/subdomains/{domain}',
                'parser': self.parse_anubis,
                'enabled': True,
            },
            'threatcrowd': {
                'url': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
                'parser': self.parse_threatcrowd,
                'enabled': True,
            }
        }
        
        self.all_subdomains = set()  # Semua subdomain yang ditemukan
        self.stats = {
            'total_api_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'by_source': {},
            'domains_processed': 0,
            'start_time': time.time()
        }
        
        # Initialize output file
        with open(self.output_file, 'w') as f:
            f.write(f"# Deep Subdomain Crawl Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Format: Satu domain per baris (no duplicates)\n\n")
    
    def parse_crtsh(self, data, domain) -> Set[str]:
        """Parse crt.sh JSON response"""
        subdomains = set()
        try:
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        name = entry.get('name_value', '')
                        if name:
                            for line in name.split('\n'):
                                line = line.strip().lower()
                                if line and (line.endswith(f".{domain}") or line == domain):
                                    if line.startswith('*.'):
                                        line = line[2:]
                                    subdomains.add(line)
        except:
            pass
        return subdomains
    
    def parse_hackertarget(self, data, domain) -> Set[str]:
        """Parse HackerTarget response"""
        subdomains = set()
        try:
            if isinstance(data, str):
                for line in data.split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub and sub.endswith(f".{domain}"):
                            subdomains.add(sub)
        except:
            pass
        return subdomains
    
    def parse_alienvault(self, data, domain) -> Set[str]:
        """Parse AlienVault OTX response"""
        subdomains = set()
        try:
            if isinstance(data, dict):
                for entry in data.get('passive_dns', []):
                    if isinstance(entry, dict):
                        hostname = entry.get('hostname', '').lower()
                        if hostname and hostname.endswith(f".{domain}"):
                            subdomains.add(hostname)
        except:
            pass
        return subdomains
    
    def parse_urlscan(self, data, domain) -> Set[str]:
        """Parse URLScan.io response"""
        subdomains = set()
        try:
            if isinstance(data, dict):
                for result in data.get('results', []):
                    if isinstance(result, dict):
                        page = result.get('page', {})
                        if isinstance(page, dict):
                            url_domain = page.get('domain', '') or page.get('url', '')
                            if url_domain:
                                parsed = urlparse(f"http://{url_domain}")
                                host = parsed.netloc or parsed.path
                                if host:
                                    host = host.split(':')[0].lower()
                                    if host.endswith(f".{domain}"):
                                        subdomains.add(host)
        except:
            pass
        return subdomains
    
    def parse_wayback(self, data, domain) -> Set[str]:
        """Parse Wayback Machine response"""
        subdomains = set()
        try:
            if isinstance(data, list) and len(data) > 1:
                for entry in data[1:]:
                    if entry and len(entry) > 0:
                        url = entry[0]
                        if url:
                            parsed = urlparse(url)
                            host = parsed.netloc or parsed.path
                            if host:
                                host = host.split(':')[0].lower()
                                if host.endswith(f".{domain}"):
                                    subdomains.add(host)
        except:
            pass
        return subdomains
    
    def parse_bufferover(self, data, domain) -> Set[str]:
        """Parse BufferOver.run response"""
        subdomains = set()
        try:
            if isinstance(data, dict):
                for key in ['FDNS_A', 'RDNS']:
                    for entry in data.get(key, []):
                        if isinstance(entry, str):
                            parts = entry.split(',')
                            if len(parts) >= 2:
                                sub = parts[1].strip().lower()
                                if sub.endswith(f".{domain}"):
                                    subdomains.add(sub)
        except:
            pass
        return subdomains
    
    def parse_rapiddns(self, data, domain) -> Set[str]:
        """Parse RAPIDDNS response"""
        subdomains = set()
        try:
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        name = entry.get('name', '').lower()
                        if name and name.endswith(f".{domain}"):
                            subdomains.add(name)
        except:
            pass
        return subdomains
    
    def parse_anubis(self, data, domain) -> Set[str]:
        """Parse Anubis response"""
        subdomains = set()
        try:
            if isinstance(data, list):
                for sub in data:
                    if isinstance(sub, str):
                        sub = sub.lower()
                        if sub.endswith(f".{domain}"):
                            subdomains.add(sub)
        except:
            pass
        return subdomains
    
    def parse_threatcrowd(self, data, domain) -> Set[str]:
        """Parse ThreatCrowd response"""
        subdomains = set()
        try:
            if isinstance(data, dict):
                for sub in data.get('subdomains', []):
                    if isinstance(sub, str):
                        sub = sub.lower()
                        if sub.endswith(f".{domain}"):
                            subdomains.add(sub)
        except:
            pass
        return subdomains
    
    def query_source(self, source_name: str, domain: str) -> Set[str]:
        """Query a single source and return subdomains"""
        source = self.sources[source_name]
        url = source['url'].format(domain=domain)
        subdomains = set()
        
        try:
            self.stats['total_api_calls'] += 1
            response = self.session.get(url, timeout=25, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                except:
                    data = response.text
                
                subdomains = source['parser'](data, domain)
                
                self.stats['successful_calls'] += 1
                self.stats['by_source'][source_name] = self.stats['by_source'].get(source_name, 0) + len(subdomains)
                
                return subdomains
            else:
                self.stats['failed_calls'] += 1
                
        except Exception:
            self.stats['failed_calls'] += 1
        
        time.sleep(self.delay)
        return set()
    
    def scan_single_domain(self, domain: str) -> Set[str]:
        """
        Scan SATU domain dan semua subdomain-nya secara REKURSIF
        Fungsi ini akan terus scan sampai tidak ada subdomain baru lagi
        """
        print(f"\n{Colors.BOLD}{Colors.CYAN}▶ Scanning: {domain}{Colors.RESET}")
        
        all_found = set()
        queue = [domain]  # Antrian domain yang akan di-scan
        scanned = set()   # Domain yang sudah di-scan dalam sesi ini
        
        while queue:
            current = queue.pop(0)
            if current in scanned:
                continue
                
            scanned.add(current)
            indent = "  " * (current.count('.') - domain.count('.'))
            
            print(f"{indent}{Colors.YELLOW}  ├─ Scanning: {current}{Colors.RESET}")
            
            # Scan dari semua sumber
            domain_subs = set()
            for source_name in self.sources:
                new_subs = self.query_source(source_name, current)
                domain_subs.update(new_subs)
                time.sleep(self.delay)  # Rate limiting
            
            # Filter subdomain yang valid (harus di bawah domain utama)
            valid_subs = set()
            for sub in domain_subs:
                if sub.endswith(f".{domain}") and sub not in all_found and sub not in scanned:
                    valid_subs.add(sub)
                    all_found.add(sub)
            
            if valid_subs:
                print(f"{indent}{Colors.GREEN}  ├─ Found {len(valid_subs)} new subdomains{Colors.RESET}")
                # Tambahkan ke queue untuk di-scan lebih dalam
                queue.extend(valid_subs)
            else:
                print(f"{indent}{Colors.DIM}  ├─ No new subdomains{Colors.RESET}")
        
        return all_found
    
    def save_subdomains(self, subdomains: Set[str]):
        """Save subdomains to file (append)"""
        try:
            with open(self.output_file, 'a') as f:
                for sub in sorted(subdomains):
                    f.write(f"{sub}\n")
        except Exception as e:
            print(f"{Colors.RED}Error saving: {e}{Colors.RESET}")
    
    def load_existing_subdomains(self):
        """Load existing subdomains from file"""
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.all_subdomains.add(line)
                print(f"{Colors.CYAN}📂 Loaded {len(self.all_subdomains)} existing subdomains{Colors.RESET}")
            except:
                pass
    
    def crawl_from_file(self, input_file: str):
        """
        MAIN FUNCTION: Memproses domain SATU PER SATU dari file input
        Setelah selesai 1 domain (dengan semua subdomainnya), lanjut ke domain berikutnya
        """
        if not os.path.exists(input_file):
            print(f"{Colors.RED}Error: File {input_file} tidak ditemukan{Colors.RESET}")
            return
        
        # Load existing subdomains
        self.load_existing_subdomains()
        
        # Baca domain dari file input
        domains = []
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Bersihkan domain
                    domain = line.split(',')[0].strip()
                    domain = re.sub(r'^https?://', '', domain)
                    domain = domain.split('/')[0]
                    if domain and '.' in domain:
                        domains.append(domain.lower())
        
        # Hapus duplikat dari input
        domains = list(set(domains))
        
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}  🚀 BATCH SUBDOMAIN CRAWLER{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📁 Total domains in file: {len(domains)}")
        print(f"📊 Existing subdomains: {len(self.all_subdomains)}")
        print(f"⚡ Threads per domain: {self.threads}")
        print(f"⏱️  Delay: {self.delay}s")
        print(f"📄 Output: {self.output_file}{Colors.RESET}\n")
        
        start_time = time.time()
        total_new = 0
        
        # PROSES SATU PER SATU DOMAIN
        for i, domain in enumerate(domains, 1):
            print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*50}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.GREEN}[{i}/{len(domains)}] Processing: {domain}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.GREEN}{'='*50}{Colors.RESET}")
            
            # Scan domain ini dan semua subdomainnya
            domain_start = time.time()
            new_subs = self.scan_single_domain(domain)
            
            # Filter yang benar-benar baru (belum pernah ada)
            truly_new = set()
            for sub in new_subs:
                if sub not in self.all_subdomains:
                    self.all_subdomains.add(sub)
                    truly_new.add(sub)
            
            # Simpan yang baru
            if truly_new:
                self.save_subdomains(truly_new)
                total_new += len(truly_new)
            
            domain_time = time.time() - domain_start
            print(f"\n{Colors.BLUE}📊 Domain {domain}: Found {len(new_subs)} subdomains ({len(truly_new)} new) in {domain_time:.2f}s{Colors.RESET}")
            print(f"{Colors.CYAN}📈 Total so far: {len(self.all_subdomains)} unique subdomains{Colors.RESET}")
        
        elapsed = time.time() - start_time
        self.print_summary(elapsed, total_new)
    
    def print_summary(self, elapsed, total_new):
        """Print crawling summary"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}  📊 CRAWLING COMPLETE{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📈 Total unique subdomains: {Colors.CYAN}{len(self.all_subdomains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}✨ New subdomains found: {Colors.GREEN}{total_new:,}{Colors.RESET}")
        print(f"{Colors.WHITE}🌐 API calls: {Colors.CYAN}{self.stats['total_api_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}✅ Successful: {Colors.GREEN}{self.stats['successful_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}❌ Failed: {Colors.RED}{self.stats['failed_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}⏱️  Total time: {Colors.CYAN}{elapsed:.2f} seconds{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}🏆 Top sources:{Colors.RESET}")
        sorted_sources = sorted(self.stats['by_source'].items(), key=lambda x: x[1], reverse=True)[:5]
        for source, count in sorted_sources:
            print(f"  {Colors.YELLOW}{source:12}: {count:6,} subdomains{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}✅ Results saved to: {self.output_file}{Colors.RESET}")
        
        # Tampilkan sample
        if self.all_subdomains:
            print(f"\n{Colors.DIM}Sample (first 10):{Colors.RESET}")
            for sub in sorted(list(self.all_subdomains))[:10]:
                print(f"  {Colors.WHITE}{sub}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="Deep Subdomain Crawler - BATCH PROCESSING: Selesaikan 1 domain dulu, baru lanjut ke berikutnya",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--input', '-i', default='domains.txt', 
                       help='File input domains')
    parser.add_argument('--output', '-o', default='all_subdomains.txt',
                       help='File output (satu domain per baris)')
    parser.add_argument('--threads', '-t', type=int, default=5,
                       help='Thread count (default: 5)')
    parser.add_argument('--delay', type=float, default=0.5,
                       help='Delay antar request (default: 0.5)')
    parser.add_argument('--domain', help='Single domain (optional)')
    
    args = parser.parse_args()
    
    crawler = DeepSubdomainCrawler(
        output_file=args.output,
        threads=args.threads,
        delay=args.delay
    )
    
    if args.domain:
        # Single domain mode
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}Single domain mode: {args.domain}{Colors.RESET}")
        crawler.load_existing_subdomains()
        start = time.time()
        new_subs = crawler.scan_single_domain(args.domain)
        
        truly_new = set()
        for sub in new_subs:
            if sub not in crawler.all_subdomains:
                crawler.all_subdomains.add(sub)
                truly_new.add(sub)
        
        if truly_new:
            crawler.save_subdomains(truly_new)
        
        elapsed = time.time() - start
        print(f"\n{Colors.GREEN}Found {len(new_subs)} subdomains ({len(truly_new)} new) in {elapsed:.2f}s{Colors.RESET}")
        print(f"{Colors.CYAN}Results saved to: {args.output}{Colors.RESET}")
    else:
        # Batch mode dari file
        crawler.crawl_from_file(args.input)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)
