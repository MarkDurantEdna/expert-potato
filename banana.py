#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deep Subdomain Crawler - Rekursif Subdomain Enumeration dengan Public APIs
Output: Setiap baris berisi satu domain/subdomain (tanpa koma, tanpa duplikat)
"""

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
                'priority': 1  # Priority 1 = paling reliable
            },
            'hackertarget': {
                'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
                'parser': self.parse_hackertarget,
                'enabled': True,
                'priority': 2
            },
            'alienvault': {
                'url': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
                'parser': self.parse_alienvault,
                'enabled': True,
                'priority': 2
            },
            'urlscan': {
                'url': 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
                'parser': self.parse_urlscan,
                'enabled': True,
                'priority': 3
            },
            'wayback': {
                'url': 'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey',
                'parser': self.parse_wayback,
                'enabled': True,
                'priority': 3
            },
            'bufferover': {
                'url': 'https://dns.bufferover.run/dns?q=.{domain}',
                'parser': self.parse_bufferover,
                'enabled': True,
                'priority': 2
            },
            'rapiddns': {
                'url': 'https://rapiddns.io/subdomain/{domain}?full=1&output=json',
                'parser': self.parse_rapiddns,
                'enabled': True,
                'priority': 2
            },
            'anubis': {
                'url': 'https://jldc.me/anubis/subdomains/{domain}',
                'parser': self.parse_anubis,
                'enabled': True,
                'priority': 2
            },
            'threatcrowd': {
                'url': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
                'parser': self.parse_threatcrowd,
                'enabled': True,
                'priority': 3
            }
        }
        
        self.all_subdomains = set()  # Set untuk mencegah duplikat
        self.processed_domains = set()
        self.stats = {
            'total_api_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'by_source': {},
            'start_time': time.time()
        }
        
        # Initialize output file - hanya header saja
        with open(self.output_file, 'w') as f:
            f.write(f"# Deep Subdomain Crawl Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Format: Satu domain per baris (no duplicates)\n")
            f.write(f"# Total {len(self.all_subdomains)} subdomains\n\n")
    
    def parse_crtsh(self, data, domain) -> Set[str]:
        """Parse crt.sh JSON response - PALING RELIABLE"""
        subdomains = set()
        try:
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        name = entry.get('name_value', '')
                        if name:
                            # Handle multiple domains in one entry (separated by newline)
                            for line in name.split('\n'):
                                line = line.strip().lower()
                                # Validasi: harus mengandung domain parent
                                if line and (line.endswith(f".{domain}") or line == domain):
                                    # Hapus wildcard jika ada
                                    if line.startswith('*.'):
                                        line = line[2:]
                                    subdomains.add(line)
        except Exception as e:
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
                                # Extract domain from URL
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
                for entry in data[1:]:  # Skip header
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
                # Try to parse as JSON first
                try:
                    data = response.json()
                except:
                    data = response.text
                
                subdomains = source['parser'](data, domain)
                
                # Validasi tambahan
                valid_subdomains = set()
                for sub in subdomains:
                    # Pastikan format valid
                    if sub and len(sub) > len(domain) and sub.count('.') >= domain.count('.'):
                        valid_subdomains.add(sub)
                
                self.stats['successful_calls'] += 1
                self.stats['by_source'][source_name] = self.stats['by_source'].get(source_name, 0) + len(valid_subdomains)
                
                if valid_subdomains:
                    print(f"{Colors.GREEN}  ✓ {source_name:12}: {len(valid_subdomains):4} subdomains{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}  - {source_name:12}: 0 subdomains{Colors.RESET}")
                
                return valid_subdomains
            else:
                self.stats['failed_calls'] += 1
                print(f"{Colors.RED}  ✗ {source_name:12}: HTTP {response.status_code}{Colors.RESET}")
                
        except requests.exceptions.Timeout:
            self.stats['failed_calls'] += 1
            print(f"{Colors.RED}  ✗ {source_name:12}: Timeout{Colors.RESET}")
        except Exception as e:
            self.stats['failed_calls'] += 1
            print(f"{Colors.RED}  ✗ {source_name:12}: Error{Colors.RESET}")
        
        time.sleep(self.delay)
        return set()
    
    def crawl_domain(self, domain: str, depth: int = 0, max_depth: int = 3) -> Set[str]:
        """Recursively crawl domain and its subdomains"""
        if domain in self.processed_domains or depth > max_depth:
            return set()
        
        domain = domain.lower().strip()
        
        # Skip jika bukan domain valid
        if not domain or '.' not in domain or domain.startswith('*'):
            return set()
        
        self.processed_domains.add(domain)
        
        indent = "  " * depth
        print(f"\n{indent}{Colors.BOLD}{Colors.CYAN}[Depth {depth}] ▶ Crawling: {domain}{Colors.RESET}")
        
        # Query all enabled sources (urut berdasarkan priority)
        sources_priority = sorted(
            [(name, src) for name, src in self.sources.items() if src['enabled']],
            key=lambda x: x[1]['priority']
        )
        
        all_new = set()
        
        # Query sequentially untuk menghindari rate limiting
        for source_name, source in sources_priority:
            new_subs = self.query_source(source_name, domain)
            all_new.update(new_subs)
        
        # Filter yang benar-benar baru
        before = len(self.all_subdomains)
        truly_new = set()
        for sub in all_new:
            if sub not in self.all_subdomains:
                self.all_subdomains.add(sub)
                truly_new.add(sub)
        
        added = len(truly_new)
        
        print(f"{indent}{Colors.BLUE}  ▶ Found {len(all_new)} subdomains ({added} new, total: {len(self.all_subdomains)}){Colors.RESET}")
        
        # Simpan yang baru ke file (append)
        if truly_new:
            self.save_new_subdomains(truly_new, domain, depth)
        
        # Rekursif ke subdomain baru (batasi untuk menghindari explosion)
        if depth < max_depth and truly_new:
            # Ambil maksimal 5 subdomain per depth untuk rekursif
            to_process = sorted(list(truly_new))[:5]
            for sub in to_process:
                # Pastikan subdomain memiliki parent domain
                if sub.endswith(f".{domain}") and sub != domain:
                    deeper = self.crawl_domain(sub, depth + 1, max_depth)
                    # Tambahkan hasil depth lebih dalam
                    for d in deeper:
                        if d not in self.all_subdomains:
                            self.all_subdomains.add(d)
                            self.save_new_subdomains({d}, domain, depth+1)
        
        return truly_new
    
    def save_new_subdomains(self, subdomains: Set[str], parent: str, depth: int):
        """Save only new subdomains to file (append)"""
        try:
            with open(self.output_file, 'a') as f:
                for sub in sorted(subdomains):
                    f.write(f"{sub}\n")
        except Exception as e:
            print(f"{Colors.RED}Error saving to file: {e}{Colors.RESET}")
    
    def load_existing_subdomains(self):
        """Load existing subdomains from file to avoid duplicates"""
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if line and not line.startswith('#'):
                            self.all_subdomains.add(line)
                print(f"{Colors.CYAN}Loaded {len(self.all_subdomains)} existing subdomains from {self.output_file}{Colors.RESET}")
            except:
                pass
    
    def crawl_from_file(self, input_file: str, max_depth: int = 3):
        """Crawl domains from input file"""
        if not os.path.exists(input_file):
            print(f"{Colors.RED}Error: File {input_file} tidak ditemukan{Colors.RESET}")
            return
        
        # Load existing subdomains first
        self.load_existing_subdomains()
        
        # Baca domain dari file
        domains = []
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Bersihkan domain
                    domain = line.split(',')[0].strip()  # Ambil bagian pertama jika ada koma
                    domain = re.sub(r'^https?://', '', domain)
                    domain = domain.split('/')[0]
                    if domain and '.' in domain:
                        domains.append(domain.lower())
        
        # Hapus duplikat
        domains = list(set(domains))
        
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}  🚀 DEEP SUBDOMAIN CRAWLER STARTED{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📁 Input domains: {len(domains)}")
        print(f"📊 Existing subdomains: {len(self.all_subdomains)}")
        print(f"📏 Max depth: {max_depth}")
        print(f"⚡ Threads: {self.threads}")
        print(f"⏱️  Delay: {self.delay}s")
        print(f"📄 Output: {self.output_file}{Colors.RESET}\n")
        
        start_time = time.time()
        
        for i, domain in enumerate(domains, 1):
            print(f"\n{Colors.BOLD}{Colors.GREEN}[{i}/{len(domains)}] Processing root domain: {domain}{Colors.RESET}")
            self.crawl_domain(domain, max_depth=max_depth)
        
        elapsed = time.time() - start_time
        self.print_summary(elapsed)
    
    def print_summary(self, elapsed):
        """Print crawling summary"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}  📊 CRAWLING COMPLETE{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📈 Total unique subdomains: {Colors.CYAN}{len(self.all_subdomains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}🔍 Unique domains processed: {Colors.CYAN}{len(self.processed_domains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}🌐 API calls: {Colors.CYAN}{self.stats['total_api_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}✅ Successful: {Colors.GREEN}{self.stats['successful_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}❌ Failed: {Colors.RED}{self.stats['failed_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}⏱️  Time elapsed: {Colors.CYAN}{elapsed:.2f} seconds{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}🏆 Top sources by findings:{Colors.RESET}")
        sorted_sources = sorted(self.stats['by_source'].items(), key=lambda x: x[1], reverse=True)
        for source, count in sorted_sources[:5]:
            print(f"  {Colors.YELLOW}{source:12}: {count:6,} subdomains{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}✅ Results saved to: {self.output_file}{Colors.RESET}")
        print(f"{Colors.CYAN}💡 Format: Satu domain per baris (no duplicates){Colors.RESET}")
        
        # Tampilkan 10 sample
        if self.all_subdomains:
            print(f"\n{Colors.DIM}Sample (first 10):{Colors.RESET}")
            for sub in sorted(list(self.all_subdomains))[:10]:
                print(f"  {Colors.WHITE}{sub}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="Deep Subdomain Crawler - Output per baris, no duplicates",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--input', '-i', default='domains.txt', 
                       help='File input domains (output dari script pertama)')
    parser.add_argument('--output', '-o', default='all_subdomains.txt',
                       help='File output (satu domain per baris)')
    parser.add_argument('--depth', '-d', type=int, default=2,
                       help='Kedalaman rekursif maksimum (default: 2)')
    parser.add_argument('--threads', '-t', type=int, default=3,
                       help='Jumlah thread concurrent (default: 3)')
    parser.add_argument('--delay', type=float, default=0.3,
                       help='Delay antar request dalam detik (default: 0.3)')
    parser.add_argument('--domain', help='Single domain (optional)')
    
    args = parser.parse_args()
    
    # Validasi input
    if not args.domain and not os.path.exists(args.input):
        print(f"{Colors.RED}Error: File {args.input} tidak ditemukan{Colors.RESET}")
        return
    
    crawler = DeepSubdomainCrawler(
        output_file=args.output,
        threads=args.threads,
        delay=args.delay
    )
    
    if args.domain:
        # Crawl single domain
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}Crawling single domain: {args.domain}{Colors.RESET}")
        crawler.load_existing_subdomains()
        start = time.time()
        crawler.crawl_domain(args.domain, max_depth=args.depth)
        elapsed = time.time() - start
        crawler.print_summary(elapsed)
    else:
        # Crawl from file
        crawler.crawl_from_file(args.input, max_depth=args.depth)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)
