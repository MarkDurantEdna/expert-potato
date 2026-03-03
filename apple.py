#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subdomain Crawler - HYPER PARALLEL + BATCH PROCESSING
Memproses RIBUAN domain SECARA BERSAMAAN dengan batch system
"""

import requests
import json
import time
import argparse
from typing import Set, List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import sys
import os
import re
from datetime import datetime
import threading
import queue
from collections import defaultdict

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
    RESET = '\033[0m'

class ParallelBatchCrawler:
    def __init__(self, output_file: str = "subdomains.txt", 
                 threads: int = 100,  # Parallel threads
                 batch_size: int = 500,  # Domain per batch
                 max_workers: int = 50):  # Concurrent API calls
        self.output_file = output_file
        self.threads = threads
        self.batch_size = batch_size
        self.max_workers = max_workers
        
        # Session dengan connection pooling untuk kecepatan
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=200,
            pool_maxsize=1000,
            max_retries=2
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.timeout = 10
        
        # API Sources yang TERBUKTI BEKERJA
        self.sources = [
            {
                'name': 'crt.sh',
                'url': 'https://crt.sh/?q=%.{domain}&output=json',
                'parse': self.parse_crtsh,
                'weight': 10  # Priority weight
            },
            {
                'name': 'hackertarget',
                'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
                'parse': self.parse_hackertarget,
                'weight': 8
            },
            {
                'name': 'alienvault',
                'url': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
                'parse': self.parse_alienvault,
                'weight': 8
            },
            {
                'name': 'rapiddns',
                'url': 'https://rapiddns.io/subdomain/{domain}?full=1&output=json',
                'parse': self.parse_rapiddns,
                'weight': 7
            },
            {
                'name': 'bufferover',
                'url': 'https://dns.bufferover.run/dns?q=.{domain}',
                'parse': self.parse_bufferover,
                'weight': 7
            },
            {
                'name': 'urlscan',
                'url': 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
                'parse': self.parse_urlscan,
                'weight': 5
            },
            {
                'name': 'wayback',
                'url': 'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey',
                'parse': self.parse_wayback,
                'weight': 5
            }
        ]
        
        # Data structures
        self.all_subdomains = set()
        self.domain_queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.processed_domains = set()
        self.lock = threading.Lock()
        self.running = True
        
        # Statistics
        self.stats = {
            'api_calls': 0,
            'success': 0,
            'failed': 0,
            'found': 0,
            'by_source': defaultdict(int),
            'domains_done': 0,
            'start_time': time.time()
        }
        
        # Initialize output
        with open(self.output_file, 'w') as f:
            f.write(f"# Parallel Batch Subdomain Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Format: Satu domain per baris\n\n")
    
    def parse_crtsh(self, data, domain):
        """Parse crt.sh - paling banyak hasil"""
        subs = set()
        try:
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        name = entry.get('name_value', '')
                        if name:
                            for line in name.split('\n'):
                                line = line.strip().lower()
                                if line and domain in line:
                                    if line.startswith('*.'):
                                        line = line[2:]
                                    subs.add(line)
        except:
            pass
        return subs
    
    def parse_hackertarget(self, data, domain):
        subs = set()
        try:
            if isinstance(data, str):
                for line in data.split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub and domain in sub:
                            subs.add(sub)
        except:
            pass
        return subs
    
    def parse_alienvault(self, data, domain):
        subs = set()
        try:
            if isinstance(data, dict):
                for entry in data.get('passive_dns', []):
                    if isinstance(entry, dict):
                        hostname = entry.get('hostname', '').lower()
                        if hostname and domain in hostname:
                            subs.add(hostname)
        except:
            pass
        return subs
    
    def parse_rapiddns(self, data, domain):
        subs = set()
        try:
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        name = entry.get('name', '').lower()
                        if name and domain in name:
                            subs.add(name)
        except:
            pass
        return subs
    
    def parse_bufferover(self, data, domain):
        subs = set()
        try:
            if isinstance(data, dict):
                for key in ['FDNS_A', 'RDNS']:
                    for entry in data.get(key, []):
                        if isinstance(entry, str):
                            parts = entry.split(',')
                            if len(parts) >= 2:
                                sub = parts[1].strip().lower()
                                if sub and domain in sub:
                                    subs.add(sub)
        except:
            pass
        return subs
    
    def parse_urlscan(self, data, domain):
        subs = set()
        try:
            if isinstance(data, dict):
                for result in data.get('results', []):
                    if isinstance(result, dict):
                        page = result.get('page', {})
                        if isinstance(page, dict):
                            url_domain = page.get('domain', '') or page.get('url', '')
                            if url_domain:
                                host = url_domain.lower().split('/')[0]
                                if domain in host:
                                    subs.add(host)
        except:
            pass
        return subs
    
    def parse_wayback(self, data, domain):
        subs = set()
        try:
            if isinstance(data, list) and len(data) > 1:
                for entry in data[1:]:
                    if entry and len(entry) > 0:
                        url = entry[0]
                        if url:
                            host = url.split('/')[2].lower() if '://' in url else url.split('/')[0].lower()
                            if domain in host:
                                subs.add(host)
        except:
            pass
        return subs
    
    def batch_scan_domains(self, domains: List[str]) -> Dict[str, Set[str]]:
        """
        Scan BANYAK domain sekaligus dalam satu batch
        Ini adalah kunci kecepatan - semua domain di-scan PARALEL
        """
        results = defaultdict(set)
        
        # Buat semua task (domain x source)
        tasks = []
        for domain in domains:
            for source in self.sources:
                tasks.append((domain, source))
        
        print(f"{Colors.CYAN}⚡ Batch scanning {len(domains)} domains with {len(self.sources)} sources = {len(tasks)} total requests{Colors.RESET}")
        
        # Process tasks dengan ThreadPool (PARALEL MASSAL)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {}
            
            for domain, source in tasks:
                future = executor.submit(self.scan_single_source, domain, source)
                future_to_task[future] = (domain, source['name'])
            
            # Kumpulkan hasil
            completed = 0
            for future in as_completed(future_to_task):
                completed += 1
                domain, source_name = future_to_task[future]
                
                try:
                    subs = future.result(timeout=15)
                    if subs:
                        results[domain].update(subs)
                        with self.lock:
                            self.stats['by_source'][source_name] += len(subs)
                except Exception as e:
                    pass
                
                # Progress indicator
                if completed % 50 == 0:
                    print(f"{Colors.DIM}    Progress: {completed}/{len(tasks)} requests{Colors.RESET}")
        
        return results
    
    def scan_single_source(self, domain: str, source: dict) -> Set[str]:
        """Scan satu domain dari satu sumber"""
        try:
            url = source['url'].format(domain=domain)
            resp = self.session.get(url, timeout=8, verify=False)
            
            with self.lock:
                self.stats['api_calls'] += 1
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except:
                    data = resp.text
                
                subs = source['parse'](data, domain)
                
                with self.lock:
                    self.stats['success'] += 1
                
                return subs
            else:
                with self.lock:
                    self.stats['failed'] += 1
                    
        except Exception as e:
            with self.lock:
                self.stats['failed'] += 1
        
        return set()
    
    def process_domain_recursive(self, domain: str, depth: int = 0, max_depth: int = 2):
        """
        Process domain dan subdomainnya secara rekursif dengan BATCH PROCESSING
        """
        if depth > max_depth or domain in self.processed_domains:
            return
        
        self.processed_domains.add(domain)
        
        indent = "  " * depth
        print(f"\n{indent}{Colors.BOLD}{Colors.MAGENTA}[Depth {depth}] Processing: {domain}{Colors.RESET}")
        
        # Batch 1: Scan domain ini dengan semua sumber
        results = self.batch_scan_domains([domain])
        
        new_subs = set()
        if domain in results:
            for sub in results[domain]:
                if sub not in self.all_subdomains and domain in sub:
                    self.all_subdomains.add(sub)
                    new_subs.add(sub)
                    with self.lock:
                        self.stats['found'] += 1
        
        # Simpan hasil
        if new_subs:
            self.save_subdomains(new_subs)
            print(f"{indent}{Colors.GREEN}  ✓ Found {len(new_subs)} new subdomains{Colors.RESET}")
            
            # Batch 2: Rekursif ke subdomain baru (tapi dalam BATCH)
            if depth < max_depth:
                # Kumpulkan semua subdomain untuk depth berikutnya
                next_level_domains = []
                for sub in new_subs:
                    if sub.count('.') > domain.count('.'):
                        next_level_domains.append(sub)
                
                if next_level_domains:
                    print(f"{indent}{Colors.CYAN}  ↪ Recursing to {len(next_level_domains)} subdomains{Colors.RESET}")
                    
                    # Batch scan semua subdomain level berikutnya sekaligus
                    next_results = self.batch_scan_domains(next_level_domains)
                    
                    # Proses hasil dari depth berikutnya
                    for sub_domain, subs in next_results.items():
                        for deeper_sub in subs:
                            if deeper_sub not in self.all_subdomains and domain in deeper_sub:
                                self.all_subdomains.add(deeper_sub)
                                self.save_subdomains({deeper_sub})
                                with self.lock:
                                    self.stats['found'] += 1
        else:
            print(f"{indent}{Colors.YELLOW}  - No new subdomains{Colors.RESET}")
    
    def save_subdomains(self, subdomains: Set[str]):
        """Save to file (thread-safe)"""
        try:
            with self.lock:
                with open(self.output_file, 'a') as f:
                    for sub in sorted(subdomains):
                        f.write(f"{sub}\n")
        except:
            pass
    
    def load_existing(self):
        """Load existing results"""
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
    
    def parallel_batch_crawl(self, input_file: str, max_depth: int = 2):
        """Main crawling function - FULL PARALLEL + BATCH"""
        if not os.path.exists(input_file):
            print(f"{Colors.RED}Error: File {input_file} tidak ditemukan{Colors.RESET}")
            return
        
        # Load existing
        self.load_existing()
        
        # Read all domains
        all_domains = []
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domain = line.split(',')[0].strip()
                    domain = re.sub(r'^https?://', '', domain)
                    domain = domain.split('/')[0]
                    if domain and '.' in domain:
                        all_domains.append(domain.lower())
        
        all_domains = list(set(all_domains))
        
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}  🚀 PARALLEL BATCH SUBDOMAIN CRAWLER{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📁 Total domains: {len(all_domains)}")
        print(f"📊 Existing: {len(self.all_subdomains)}")
        print(f"⚡ Max workers: {self.max_workers}")
        print(f"📦 Batch size: {self.batch_size}")
        print(f"📏 Max depth: {max_depth}")
        print(f"📄 Output: {self.output_file}{Colors.RESET}\n")
        
        start_time = time.time()
        
        # Process domains dalam BATCH-BATCH besar
        for i in range(0, len(all_domains), self.batch_size):
            batch = all_domains[i:i+self.batch_size]
            batch_num = i//self.batch_size + 1
            total_batches = (len(all_domains) + self.batch_size - 1) // self.batch_size
            
            print(f"\n{Colors.BOLD}{Colors.GREEN}[Batch {batch_num}/{total_batches}] Processing {len(batch)} domains{Colors.RESET}")
            
            # Process setiap domain dalam batch secara SEQUENTIAL (tapi tiap domain di-scan PARALEL)
            for domain in batch:
                self.process_domain_recursive(domain, 0, max_depth)
            
            # Progress update
            elapsed = time.time() - start_time
            rate = self.stats['api_calls'] / elapsed if elapsed > 0 else 0
            print(f"{Colors.BLUE}  📊 Progress: {self.stats['found']} ditemukan | {self.stats['api_calls']} requests | {rate:.0f} req/detik{Colors.RESET}")
        
        elapsed = time.time() - start_time
        self.print_summary(elapsed)
    
    def print_summary(self, elapsed):
        """Print final summary"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}  📊 CRAWLING COMPLETE{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📈 Total subdomains: {Colors.CYAN}{len(self.all_subdomains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}✨ Baru ditemukan: {Colors.GREEN}{self.stats['found']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}🌐 API calls: {Colors.CYAN}{self.stats['api_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}✅ Sukses: {Colors.GREEN}{self.stats['success']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}❌ Gagal: {Colors.RED}{self.stats['failed']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}⏱️  Waktu: {Colors.CYAN}{elapsed:.2f} detik{Colors.RESET}")
        print(f"{Colors.WHITE}⚡ Kecepatan: {Colors.CYAN}{self.stats['api_calls']/elapsed:.1f} req/detik{Colors.RESET}\n")
        
        # Top sources
        print(f"{Colors.BOLD}🏆 Sumber terbaik:{Colors.RESET}")
        sorted_sources = sorted(self.stats['by_source'].items(), key=lambda x: x[1], reverse=True)
        for source, count in sorted_sources[:5]:
            print(f"  {Colors.YELLOW}{source:12}: {count:6,} subdomain{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}✅ Hasil: {self.output_file}{Colors.RESET}")
        
        # Sample
        if self.all_subdomains:
            print(f"\n{Colors.CYAN}Contoh (10 pertama):{Colors.RESET}")
            for sub in sorted(list(self.all_subdomains))[:10]:
                print(f"  {Colors.WHITE}{sub}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description="Parallel Batch Subdomain Crawler")
    parser.add_argument('--input', '-i', default='domains.txt', help='Input file')
    parser.add_argument('--output', '-o', default='subdomains.txt', help='Output file')
    parser.add_argument('--workers', '-w', type=int, default=50, help='Max concurrent workers')
    parser.add_argument('--batch', '-b', type=int, default=500, help='Batch size')
    parser.add_argument('--depth', '-d', type=int, default=2, help='Max depth')
    
    args = parser.parse_args()
    
    crawler = ParallelBatchCrawler(
        output_file=args.output,
        threads=100,
        batch_size=args.batch,
        max_workers=args.workers
    )
    
    crawler.parallel_batch_crawl(args.input, max_depth=args.depth)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️ Stopped by user{Colors.RESET}")
        sys.exit(0)
