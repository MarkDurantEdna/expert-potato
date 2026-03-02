#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deep Subdomain Crawler - Rekursif Subdomain Enumeration dengan Public APIs
Menggunakan sumber API publik yang TIDAK memerlukan registrasi/api key
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
    RESET = '\033[0m'

class DeepSubdomainCrawler:
    def __init__(self, output_file: str = "all_subdomains.txt", threads: int = 5, delay: float = 0.5):
        self.output_file = output_file
        self.threads = threads
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; SubdomainCrawler/2.0; +https://github.com/yourrepo)'
        })
        
        # Semua sumber API di bawah ini TIDAK memerlukan API key
        self.sources = {
            # Certificate Transparency (paling reliable, unlimited) [citation:8]
            'crt_sh': {
                'url': 'https://crt.sh/?q=%.{domain}&output=json',
                'parser': self.parse_crtsh,
                'enabled': True
            },
            
            # HackerTarget (free, no key required) [citation:8]
            'hackertarget': {
                'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
                'parser': self.parse_hackertarget,
                'enabled': True
            },
            
            # ThreatCrowd (free OSINT API) [citation:8]
            'threatcrowd': {
                'url': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
                'parser': self.parse_threatcrowd,
                'enabled': True
            },
            
            # AlienVault OTX (free, no key) [citation:1][citation:6]
            'alienvault': {
                'url': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
                'parser': self.parse_alienvault,
                'enabled': True
            },
            
            # URLScan.io (public scans, no key needed for basic) [citation:8]
            'urlscan': {
                'url': 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
                'parser': self.parse_urlscan,
                'enabled': True
            },
            
            # Wayback Machine (archive data) [citation:1][citation:6]
            'wayback': {
                'url': 'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey',
                'parser': self.parse_wayback,
                'enabled': True
            },
            
            # C99 (free web-based, no API key) [citation:4]
            'c99': {
                'url': 'https://subdomainfinder.c99.nl/scans/?domain={domain}',
                'parser': self.parse_c99,
                'enabled': True,
                'note': 'Uses web scraping - may be slower'
            },
            
            # BufferOver (free DNS data) [citation:1][citation:6]
            'bufferover': {
                'url': 'https://dns.bufferover.run/dns?q=.{domain}',
                'parser': self.parse_bufferover,
                'enabled': True
            },
            
            # RAPIDDNS (free API) [citation:1][citation:6]
            'rapiddns': {
                'url': 'https://rapiddns.io/subdomain/{domain}?full=1&output=json',
                'parser': self.parse_rapiddns,
                'enabled': True
            },
            
            # Anubis (free OSINT database) [citation:1][citation:6]
            'anubis': {
                'url': 'https://jldc.me/anubis/subdomains/{domain}',
                'parser': self.parse_anubis,
                'enabled': True
            }
        }
        
        self.all_subdomains = set()
        self.processed_domains = set()
        self.stats = {
            'total_api_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'by_source': {}
        }
        
        # Initialize output file
        with open(self.output_file, 'w') as f:
            f.write(f"# Deep Subdomain Crawl Results - {datetime.now().isoformat()}\n")
            f.write(f"# Domain,Depth,Source\n")

    def parse_crtsh(self, data, domain) -> Set[str]:
        """Parse crt.sh JSON response [citation:8]"""
        subdomains = set()
        try:
            for entry in data:
                name = entry.get('name_value', '')
                if name:
                    for line in name.split('\n'):
                        line = line.strip().lower()
                        if line.endswith(f".{domain}") or line == domain:
                            subdomains.add(line)
        except:
            pass
        return subdomains

    def parse_hackertarget(self, data, domain) -> Set[str]:
        """Parse HackerTarget response [citation:8]"""
        subdomains = set()
        try:
            for line in data.split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip().lower()
                    if sub.endswith(f".{domain}"):
                        subdomains.add(sub)
        except:
            pass
        return subdomains

    def parse_threatcrowd(self, data, domain) -> Set[str]:
        """Parse ThreatCrowd JSON [citation:8]"""
        subdomains = set()
        try:
            for sub in data.get('subdomains', []):
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}"):
                    subdomains.add(sub)
        except:
            pass
        return subdomains

    def parse_alienvault(self, data, domain) -> Set[str]:
        """Parse AlienVault OTX response [citation:1][citation:6]"""
        subdomains = set()
        try:
            for entry in data.get('passive_dns', []):
                hostname = entry.get('hostname', '').lower()
                if hostname.endswith(f".{domain}") and hostname != domain:
                    subdomains.add(hostname)
        except:
            pass
        return subdomains

    def parse_urlscan(self, data, domain) -> Set[str]:
        """Parse URLScan.io response [citation:8]"""
        subdomains = set()
        try:
            for result in data.get('results', []):
                page = result.get('page', {})
                url = page.get('domain', '') or page.get('url', '')
                if url:
                    parsed = urlparse(f"http://{url}")
                    host = parsed.netloc or parsed.path
                    if host and host.endswith(f".{domain}"):
                        subdomains.add(host.lower())
        except:
            pass
        return subdomains

    def parse_wayback(self, data, domain) -> Set[str]:
        """Parse Wayback Machine CDX response [citation:1][citation:6]"""
        subdomains = set()
        try:
            for entry in data[1:]:  # Skip header
                if entry and len(entry) > 0:
                    url = entry[0]
                    parsed = urlparse(url)
                    host = parsed.netloc or parsed.path
                    if host and host.endswith(f".{domain}"):
                        subdomains.add(host.lower())
        except:
            pass
        return subdomains

    def parse_c99(self, data, domain) -> Set[str]:
        """Parse C99.nl subdomain finder response [citation:4]"""
        subdomains = set()
        try:
            # C99 returns HTML, we need to extract from text
            import re
            # Look for domain patterns in the response
            pattern = r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain) + r')'
            matches = re.findall(pattern, data)
            for match in matches:
                if match.endswith(f".{domain}") and len(match.split('.')) >= 3:
                    subdomains.add(match.lower())
        except:
            pass
        return subdomains

    def parse_bufferover(self, data, domain) -> Set[str]:
        """Parse BufferOver.run response [citation:1][citation:6]"""
        subdomains = set()
        try:
            # Handle both FDNS and RDNS data
            for key in ['FDNS_A', 'RDNS']:
                for entry in data.get(key, []):
                    parts = entry.split(',')
                    if len(parts) >= 2:
                        sub = parts[1].strip().lower()
                        if sub.endswith(f".{domain}"):
                            subdomains.add(sub)
        except:
            pass
        return subdomains

    def parse_rapiddns(self, data, domain) -> Set[str]:
        """Parse RAPIDDNS response [citation:1][citation:6]"""
        subdomains = set()
        try:
            for entry in data:
                name = entry.get('name', '').lower()
                if name and name.endswith(f".{domain}"):
                    subdomains.add(name)
        except:
            pass
        return subdomains

    def parse_anubis(self, data, domain) -> Set[str]:
        """Parse Anubis response [citation:1][citation:6]"""
        subdomains = set()
        try:
            for sub in data:
                if sub and sub.endswith(f".{domain}"):
                    subdomains.add(sub.lower())
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
            response = self.session.get(url, timeout=30, verify=False)
            
            if response.status_code == 200:
                if 'json' in response.headers.get('Content-Type', ''):
                    data = response.json()
                else:
                    data = response.text
                
                subdomains = source['parser'](data, domain)
                self.stats['successful_calls'] += 1
                self.stats['by_source'][source_name] = self.stats['by_source'].get(source_name, 0) + len(subdomains)
                
                if subdomains:
                    print(f"{Colors.GREEN}  ✓ {source_name}: {len(subdomains)} subdomains{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}  - {source_name}: 0 subdomains{Colors.RESET}")
            else:
                self.stats['failed_calls'] += 1
                print(f"{Colors.RED}  ✗ {source_name}: HTTP {response.status_code}{Colors.RESET}")
                
        except Exception as e:
            self.stats['failed_calls'] += 1
            print(f"{Colors.RED}  ✗ {source_name}: Error - {str(e)[:50]}{Colors.RESET}")
        
        time.sleep(self.delay)  # Rate limiting
        return subdomains

    def crawl_domain(self, domain: str, depth: int = 0, max_depth: int = 3) -> Set[str]:
        """Recursively crawl domain and its subdomains"""
        if domain in self.processed_domains or depth > max_depth:
            return set()
        
        domain = domain.lower().strip()
        self.processed_domains.add(domain)
        
        indent = "  " * depth
        print(f"\n{indent}{Colors.BOLD}{Colors.CYAN}[Depth {depth}] Crawling: {domain}{Colors.RESET}")
        
        # Query all enabled sources in parallel
        new_subdomains = set()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for source_name, source in self.sources.items():
                if source['enabled']:
                    future = executor.submit(self.query_source, source_name, domain)
                    futures[future] = source_name
            
            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    result = future.result(timeout=45)
                    new_subdomains.update(result)
                except Exception as e:
                    print(f"{Colors.RED}  ✗ {source_name}: Thread error - {str(e)[:50]}{Colors.RESET}")
        
        # Add to global set
        before_count = len(self.all_subdomains)
        self.all_subdomains.update(new_subdomains)
        added = len(self.all_subdomains) - before_count
        
        print(f"{indent}{Colors.BLUE}Found {len(new_subdomains)} subdomains (+{added} new) at depth {depth}{Colors.RESET}")
        
        # Save incrementally
        self.save_results(domain, new_subdomains, depth)
        
        # Recursively crawl new subdomains
        if depth < max_depth:
            for sub in sorted(new_subdomains)[:10]:  # Limit recursion to avoid explosion
                if sub not in self.processed_domains:
                    sub_without_domain = sub
                    deeper = self.crawl_domain(sub_without_domain, depth + 1, max_depth)
                    self.all_subdomains.update(deeper)
        
        return new_subdomains

    def save_results(self, domain: str, subdomains: Set[str], depth: int):
        """Save results to file incrementally"""
        try:
            with open(self.output_file, 'a') as f:
                for sub in sorted(subdomains):
                    f.write(f"{sub},{depth},{domain}\n")
        except:
            pass

    def crawl_from_file(self, input_file: str, max_depth: int = 3):
        """Crawl domains from input file (output dari script pertama)"""
        if not os.path.exists(input_file):
            print(f"{Colors.RED}Error: File {input_file} tidak ditemukan{Colors.RESET}")
            return
        
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}  🚀 DEEP SUBDOMAIN CRAWLER STARTED{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}Input domains: {len(domains)}")
        print(f"Max depth: {max_depth}")
        print(f"Threads: {self.threads}")
        print(f"Delay: {self.delay}s")
        print(f"Output: {self.output_file}{Colors.RESET}\n")
        
        for i, domain in enumerate(domains, 1):
            print(f"\n{Colors.BOLD}{Colors.GREEN}[{i}/{len(domains)}] Processing root domain: {domain}{Colors.RESET}")
            self.crawl_domain(domain, max_depth=max_depth)
        
        self.print_summary()

    def print_summary(self):
        """Print crawling summary"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}  📊 CRAWLING COMPLETE{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}Total unique subdomains found: {Colors.CYAN}{len(self.all_subdomains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}Unique domains processed: {Colors.CYAN}{len(self.processed_domains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}API calls made: {Colors.CYAN}{self.stats['total_api_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}Successful: {Colors.GREEN}{self.stats['successful_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}Failed: {Colors.RED}{self.stats['failed_calls']:,}{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}Top sources by findings:{Colors.RESET}")
        sorted_sources = sorted(self.stats['by_source'].items(), key=lambda x: x[1], reverse=True)
        for source, count in sorted_sources[:5]:
            print(f"  {Colors.YELLOW}{source}: {count:,}{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}Results saved to: {self.output_file}{Colors.RESET}")
        print(f"{Colors.CYAN}Tips:{Colors.RESET}")
        print(f"  - Gunakan depth lebih tinggi untuk hasil maksimal")
        print(f"  - Delay bisa disesuaikan untuk menghindari rate limiting")
        print(f"  - Hasil bisa digunakan untuk vulnerability scanning")

def main():
    parser = argparse.ArgumentParser(description="Deep Subdomain Crawler - Rekursif dengan Public APIs")
    parser.add_argument('--input', '-i', default='domains.txt', 
                       help='File input berisi domains (output dari script pertama)')
    parser.add_argument('--output', '-o', default='all_subdomains.txt',
                       help='File output untuk hasil')
    parser.add_argument('--depth', '-d', type=int, default=2,
                       help='Kedalaman rekursif maksimum (default: 2)')
    parser.add_argument('--threads', '-t', type=int, default=5,
                       help='Jumlah thread concurrent (default: 5)')
    parser.add_argument('--delay', type=float, default=0.5,
                       help='Delay antar request dalam detik (default: 0.5)')
    parser.add_argument('--domain', help='Single domain untuk di-crawl (optional)')
    
    args = parser.parse_args()
    
    crawler = DeepSubdomainCrawler(
        output_file=args.output,
        threads=args.threads,
        delay=args.delay
    )
    
    if args.domain:
        # Crawl single domain
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}Crawling single domain: {args.domain}{Colors.RESET}")
        crawler.crawl_domain(args.domain, max_depth=args.depth)
        crawler.print_summary()
    else:
        # Crawl from file
        crawler.crawl_from_file(args.input, max_depth=args.depth)

if __name__ == '__main__':
    main()
