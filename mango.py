#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deep Subdomain Crawler - Rekursif Subdomain Enumeration dengan Public APIs
FITUR: Setiap subdomain hanya di-scan SATU KALI saja, langsung lanjut ke berikutnya
Output: Setiap baris berisi satu domain/subdomain (tanpa duplikat)
"""

import requests
import json
import time
import argparse
from typing import Set, List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
import sys
import os
import re
from datetime import datetime
import queue
import threading

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
    def __init__(self, output_file: str = "all_subdomains.txt", threads: int = 3, delay: float = 0.3):
        self.output_file = output_file
        self.threads = threads
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.timeout = 25
        
        # Queue untuk domain yang akan di-scan
        self.scan_queue = queue.Queue()
        self.scanned_domains = set()  # Domain yang sudah pernah di-scan
        self.all_subdomains = set()    # Semua subdomain yang ditemukan
        self.processing_lock = threading.Lock()
        self.running = True
        
        # Semua sumber API TIDAK memerlukan API key
        self.sources = {
            'crt_sh': {
                'url': 'https://crt.sh/?q=%.{domain}&output=json',
                'parser': self.parse_crtsh,
                'enabled': True,
                'priority': 1
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
            'rapiddns': {
                'url': 'https://rapiddns.io/subdomain/{domain}?full=1&output=json',
                'parser': self.parse_rapiddns,
                'enabled': True,
                'priority': 2
            },
            'bufferover': {
                'url': 'https://dns.bufferover.run/dns?q=.{domain}',
                'parser': self.parse_bufferover,
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
            }
        }
        
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
    
    def query_source(self, source_name: str, domain: str) -> Set[str]:
        """Query a single source and return subdomains"""
        source = self.sources[source_name]
        url = source['url'].format(domain=domain)
        subdomains = set()
        
        try:
            with self.processing_lock:
                self.stats['total_api_calls'] += 1
            
            response = self.session.get(url, timeout=20, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                except:
                    data = response.text
                
                subdomains = source['parser'](data, domain)
                
                # Validasi tambahan
                valid_subs = set()
                for sub in subdomains:
                    if sub and len(sub) > len(domain) and sub.endswith(f".{domain}"):
                        valid_subs.add(sub)
                
                with self.processing_lock:
                    self.stats['successful_calls'] += 1
                    self.stats['by_source'][source_name] = self.stats['by_source'].get(source_name, 0) + len(valid_subs)
                
                return valid_subs
            else:
                with self.processing_lock:
                    self.stats['failed_calls'] += 1
                
        except Exception:
            with self.processing_lock:
                self.stats['failed_calls'] += 1
        
        return set()
    
    def process_domain(self, domain: str, depth: int) -> Tuple[Set[str], int]:
        """
        Process single domain dan kembalikan subdomain baru yang ditemukan
        INI ADALAH SATU-SATUNYA FUNGSI YANG MELAKUKAN SCAN
        """
        # CEK DUPLIKAT: Skip jika sudah pernah di-scan
        if domain in self.scanned_domains:
            return set(), 0
        
        # Tandai sebagai sedang diproses
        with self.processing_lock:
            if domain in self.scanned_domains:  # Double check
                return set(), 0
            self.scanned_domains.add(domain)
            self.stats['domains_processed'] += 1
        
        indent = "  " * depth
        print(f"{indent}{Colors.CYAN}[Depth {depth}] Scanning: {domain}{Colors.RESET}")
        
        # Query semua sources
        sources_priority = sorted(
            [(name, src) for name, src in self.sources.items() if src['enabled']],
            key=lambda x: x[1]['priority']
        )
        
        all_found = set()
        
        # Scan sequential untuk menghindari rate limiting
        for source_name, _ in sources_priority:
            new_subs = self.query_source(source_name, domain)
            all_found.update(new_subs)
            time.sleep(self.delay)  # Rate limiting
        
        # Filter yang benar-benar baru (belum pernah ditemukan)
        truly_new = set()
        with self.processing_lock:
            for sub in all_found:
                if sub not in self.all_subdomains:
                    self.all_subdomains.add(sub)
                    truly_new.add(sub)
        
        # Simpan yang baru ke file
        if truly_new:
            self.save_subdomains(truly_new)
            print(f"{indent}{Colors.GREEN}  ✓ Found {len(truly_new)} NEW subdomains (total: {len(self.all_subdomains)}){Colors.RESET}")
            
            # Tambahkan subdomain baru ke queue untuk diproses nanti (jika depth masih memungkinkan)
            if depth < self.max_depth:
                for sub in truly_new:
                    # Hanya subdomain yang lebih dalam dari domain saat ini
                    if sub.endswith(f".{domain}") and sub != domain:
                        self.add_to_queue(sub, depth + 1)
        else:
            print(f"{indent}{Colors.YELLOW}  - No new subdomains found{Colors.RESET}")
        
        return truly_new, len(truly_new)
    
    def add_to_queue(self, domain: str, depth: int):
        """Tambahkan domain ke queue untuk diproses nanti"""
        # CEK DUPLIKAT: Jangan tambahkan jika sudah pernah di-scan
        if domain not in self.scanned_domains:
            self.scan_queue.put((domain, depth))
    
    def worker(self):
        """Worker thread untuk memproses queue"""
        while self.running:
            try:
                # Ambil domain dari queue dengan timeout
                domain, depth = self.scan_queue.get(timeout=2)
                
                # CEK LAGI: Pastikan belum di-scan (double check)
                if domain not in self.scanned_domains:
                    self.process_domain(domain, depth)
                
                self.scan_queue.task_done()
                
            except queue.Empty:
                # Queue kosong, cek apakah masih ada worker lain yang hidup
                continue
            except Exception as e:
                print(f"{Colors.RED}Worker error: {e}{Colors.RESET}")
                continue
    
    def load_existing_subdomains(self):
        """Load existing subdomains dari file untuk mencegah duplikat"""
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
    
    def save_subdomains(self, subdomains: Set[str]):
        """Save subdomains ke file (append)"""
        try:
            with open(self.output_file, 'a') as f:
                for sub in sorted(subdomains):
                    f.write(f"{sub}\n")
        except Exception as e:
            print(f"{Colors.RED}Error saving: {e}{Colors.RESET}")
    
    def crawl_from_file(self, input_file: str, max_depth: int = 2):
        """
        Main crawling function
        SETIAP DOMAIN HANYA DI-SCAN SATU KALI
        """
        if not os.path.exists(input_file):
            print(f"{Colors.RED}Error: File {input_file} tidak ditemukan{Colors.RESET}")
            return
        
        self.max_depth = max_depth
        
        # Load existing subdomains
        self.load_existing_subdomains()
        
        # Baca domain dari file input
        root_domains = []
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Bersihkan domain
                    domain = line.split(',')[0].strip()
                    domain = re.sub(r'^https?://', '', domain)
                    domain = domain.split('/')[0]
                    if domain and '.' in domain:
                        root_domains.append(domain.lower())
        
        # Hapus duplikat dari input
        root_domains = list(set(root_domains))
        
        # Filter domain yang sudah pernah di-scan
        domains_to_scan = [d for d in root_domains if d not in self.scanned_domains]
        
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}  🚀 DEEP SUBDOMAIN CRAWLER (NO DUPLICATE SCAN){Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📁 Input domains: {len(root_domains)}")
        print(f"{Colors.WHITE}📊 Already scanned: {len(self.scanned_domains)}")
        print(f"{Colors.WHITE}📈 To scan now: {len(domains_to_scan)}")
        print(f"{Colors.WHITE}📏 Max depth: {max_depth}")
        print(f"{Colors.WHITE}⚡ Threads: {self.threads}")
        print(f"{Colors.WHITE}📄 Output: {self.output_file}{Colors.RESET}\n")
        
        if not domains_to_scan:
            print(f"{Colors.YELLOW}⚠️  Semua domain sudah pernah di-scan!{Colors.RESET}")
            self.print_summary()
            return
        
        # Isi queue dengan root domains
        for domain in domains_to_scan:
            self.add_to_queue(domain, 0)
        
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Monitor progress
        try:
            total_in_queue = self.scan_queue.qsize()
            last_count = 0
            stall_counter = 0
            
            while self.running:
                time.sleep(2)
                
                queue_size = self.scan_queue.qsize()
                processed = len(self.scanned_domains)
                found = len(self.all_subdomains)
                
                # Progress bar sederhana
                print(f"\r{Colors.BLUE}📊 Progress: {processed} domains scanned | {found} subdomains found | Queue: {queue_size}{Colors.RESET}", end="")
                
                # Deteksi jika progress mandek
                if processed == last_count:
                    stall_counter += 1
                    if stall_counter > 10 and queue_size == 0:
                        print(f"\n{Colors.GREEN}✅ Semua domain telah diproses!{Colors.RESET}")
                        break
                else:
                    stall_counter = 0
                    last_count = processed
                
                # Hentikan jika queue kosong dan tidak ada worker yang bekerja
                if queue_size == 0:
                    # Tunggu sebentar untuk memastikan
                    time.sleep(3)
                    if self.scan_queue.qsize() == 0:
                        break
                        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⚠️  Interrupted by user{Colors.RESET}")
            self.running = False
        
        # Tunggu semua thread selesai
        self.running = False
        for t in threads:
            t.join(timeout=1)
        
        self.print_summary()
    
    def print_summary(self):
        """Print crawling summary"""
        elapsed = time.time() - self.stats['start_time']
        
        print(f"\n\n{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}  📊 CRAWLING COMPLETE{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📈 Total unique subdomains: {Colors.CYAN}{len(self.all_subdomains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}🔍 Domains scanned: {Colors.CYAN}{len(self.scanned_domains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}🌐 API calls: {Colors.CYAN}{self.stats['total_api_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}✅ Successful: {Colors.GREEN}{self.stats['successful_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}❌ Failed: {Colors.RED}{self.stats['failed_calls']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}⏱️  Time: {Colors.CYAN}{elapsed:.2f} seconds{Colors.RESET}\n")
        
        # Top sources
        if self.stats['by_source']:
            print(f"{Colors.BOLD}🏆 Top sources:{Colors.RESET}")
            sorted_sources = sorted(self.stats['by_source'].items(), key=lambda x: x[1], reverse=True)[:5]
            for source, count in sorted_sources:
                print(f"  {Colors.YELLOW}{source:12}: {count:6,} subdomains{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}✅ Results saved to: {self.output_file}{Colors.RESET}")
        print(f"{Colors.CYAN}💡 Format: Satu domain per baris (no duplicates){Colors.RESET}")
        
        # Tampilkan sample
        if self.all_subdomains:
            print(f"\n{Colors.DIM}Sample (first 10):{Colors.RESET}")
            for sub in sorted(list(self.all_subdomains))[:10]:
                print(f"  {Colors.WHITE}{sub}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="Deep Subdomain Crawler - SETIAP DOMAIN HANYA DI-SCAN SEKALI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--input', '-i', default='domains.txt', 
                       help='File input domains')
    parser.add_argument('--output', '-o', default='all_subdomains.txt',
                       help='File output (satu domain per baris)')
    parser.add_argument('--depth', '-d', type=int, default=2,
                       help='Kedalaman rekursif (default: 2)')
    parser.add_argument('--threads', '-t', type=int, default=3,
                       help='Thread count (default: 3)')
    parser.add_argument('--delay', type=float, default=0.3,
                       help='Delay antar request (default: 0.3)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"{Colors.RED}Error: File {args.input} tidak ditemukan{Colors.RESET}")
        return
    
    crawler = DeepSubdomainCrawler(
        output_file=args.output,
        threads=args.threads,
        delay=args.delay
    )
    
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
