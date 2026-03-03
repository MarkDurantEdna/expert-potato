#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deep Subdomain Crawler - SPEED + ACCURACY EDITION
Menggabungkan kecepatan tinggi DENGAN akurasi script sebelumnya
Target: 100-200 URL/detik dengan hasil akurat
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
import threading
import queue

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

class FastAccurateCrawler:
    def __init__(self, output_file: str = "all_subdomains.txt", 
                 threads: int = 50, 
                 delay: float = 0.01):
        self.output_file = output_file
        self.threads = threads
        self.delay = delay
        self.session = requests.Session()
        
        # Penting: Gunakan connection pooling untuk kecepatan
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=1000,
            max_retries=2,
            pool_block=False
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Connection': 'keep-alive'
        })
        self.session.timeout = 10
        
        # Semua sumber API yang TERBUKTI BEKERJA dari script sebelumnya
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
        
        self.all_subdomains = set()
        self.stats = {
            'total_requests': 0,
            'successful': 0,
            'failed': 0,
            'by_source': {},
            'start_time': time.time(),
            'domains_processed': 0,
            'total_found': 0
        }
        self.lock = threading.Lock()
        
        # Queue untuk worker threads
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.running = True
        
        # Initialize output file
        with open(self.output_file, 'w') as f:
            f.write(f"# Fast Accurate Subdomain Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Format: Satu domain per baris\n\n")
    
    def parse_crtsh(self, data, domain) -> Set[str]:
        """Parse crt.sh - PALING AKURAT"""
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
                                    # Validasi: harus mengandung domain
                                    if domain in line:
                                        subdomains.add(line)
        except:
            pass
        return subdomains
    
    def parse_hackertarget(self, data, domain) -> Set[str]:
        """Parse HackerTarget - SANGAT AKURAT"""
        subdomains = set()
        try:
            if isinstance(data, str):
                for line in data.split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub and sub.endswith(f".{domain}") and domain in sub:
                            subdomains.add(sub)
        except:
            pass
        return subdomains
    
    def parse_alienvault(self, data, domain) -> Set[str]:
        """Parse AlienVault - SANGAT AKURAT"""
        subdomains = set()
        try:
            if isinstance(data, dict):
                for entry in data.get('passive_dns', []):
                    if isinstance(entry, dict):
                        hostname = entry.get('hostname', '').lower()
                        if hostname and hostname.endswith(f".{domain}") and domain in hostname:
                            subdomains.add(hostname)
        except:
            pass
        return subdomains
    
    def parse_urlscan(self, data, domain) -> Set[str]:
        """Parse URLScan.io"""
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
                                    if host.endswith(f".{domain}") and domain in host:
                                        subdomains.add(host)
        except:
            pass
        return subdomains
    
    def parse_wayback(self, data, domain) -> Set[str]:
        """Parse Wayback Machine"""
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
                                if host.endswith(f".{domain}") and domain in host:
                                    subdomains.add(host)
        except:
            pass
        return subdomains
    
    def parse_bufferover(self, data, domain) -> Set[str]:
        """Parse BufferOver.run"""
        subdomains = set()
        try:
            if isinstance(data, dict):
                for key in ['FDNS_A', 'RDNS']:
                    for entry in data.get(key, []):
                        if isinstance(entry, str):
                            parts = entry.split(',')
                            if len(parts) >= 2:
                                sub = parts[1].strip().lower()
                                if sub.endswith(f".{domain}") and domain in sub:
                                    subdomains.add(sub)
        except:
            pass
        return subdomains
    
    def parse_rapiddns(self, data, domain) -> Set[str]:
        """Parse RAPIDDNS"""
        subdomains = set()
        try:
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        name = entry.get('name', '').lower()
                        if name and name.endswith(f".{domain}") and domain in name:
                            subdomains.add(name)
        except:
            pass
        return subdomains
    
    def parse_anubis(self, data, domain) -> Set[str]:
        """Parse Anubis"""
        subdomains = set()
        try:
            if isinstance(data, list):
                for sub in data:
                    if isinstance(sub, str):
                        sub = sub.lower()
                        if sub.endswith(f".{domain}") and domain in sub:
                            subdomains.add(sub)
        except:
            pass
        return subdomains
    
    def parse_threatcrowd(self, data, domain) -> Set[str]:
        """Parse ThreatCrowd"""
        subdomains = set()
        try:
            if isinstance(data, dict):
                for sub in data.get('subdomains', []):
                    if isinstance(sub, str):
                        sub = sub.lower()
                        if sub.endswith(f".{domain}") and domain in sub:
                            subdomains.add(sub)
        except:
            pass
        return subdomains
    
    def query_source(self, source_name: str, domain: str) -> Set[str]:
        """Query single source dengan error handling"""
        source = self.sources[source_name]
        url = source['url'].format(domain=domain)
        subdomains = set()
        
        try:
            with self.lock:
                self.stats['total_requests'] += 1
            
            response = self.session.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                except:
                    data = response.text
                
                subdomains = source['parser'](data, domain)
                
                with self.lock:
                    self.stats['successful'] += 1
                    self.stats['by_source'][source_name] = self.stats['by_source'].get(source_name, 0) + len(subdomains)
                
                if subdomains:
                    print(f"{Colors.GREEN}    ✓ {source_name}: {len(subdomains)} ditemukan{Colors.RESET}")
                
            else:
                with self.lock:
                    self.stats['failed'] += 1
                    
        except Exception as e:
            with self.lock:
                self.stats['failed'] += 1
        
        return subdomains
    
    def worker(self):
        """Worker thread untuk memproses domain"""
        while self.running:
            try:
                domain, depth, max_depth = self.task_queue.get(timeout=1)
                
                if domain in self.processed_domains:
                    self.task_queue.task_done()
                    continue
                
                with self.lock:
                    self.processed_domains.add(domain)
                
                indent = "  " * depth
                print(f"\n{indent}{Colors.CYAN}[Depth {depth}] Scanning: {domain}{Colors.RESET}")
                
                # Query semua sources untuk domain ini
                all_subs = set()
                for source_name in self.sources:
                    subs = self.query_source(source_name, domain)
                    all_subs.update(subs)
                    time.sleep(self.delay)  # Rate limiting
                
                # Filter subdomain yang valid (harus mengandung domain parent)
                valid_subs = set()
                for sub in all_subs:
                    if domain in sub and sub not in self.all_subdomains:
                        valid_subs.add(sub)
                
                if valid_subs:
                    with self.lock:
                        for sub in valid_subs:
                            self.all_subdomains.add(sub)
                            self.stats['total_found'] += 1
                    
                    # Simpan ke file
                    self.save_subdomains(valid_subs)
                    
                    print(f"{indent}{Colors.GREEN}  ✓ Menemukan {len(valid_subs)} subdomain baru{Colors.RESET}")
                    
                    # Tambahkan subdomain baru ke queue untuk depth berikutnya
                    if depth < max_depth:
                        for sub in valid_subs:
                            if sub != domain and sub.count('.') > domain.count('.'):
                                self.task_queue.put((sub, depth + 1, max_depth))
                else:
                    print(f"{indent}{Colors.YELLOW}  - Tidak ada subdomain baru{Colors.RESET}")
                
                self.task_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"{Colors.RED}Worker error: {e}{Colors.RESET}")
                self.task_queue.task_done()
    
    def save_subdomains(self, subdomains: Set[str]):
        """Save to file"""
        try:
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
    
    def fast_accurate_crawl(self, input_file: str, max_depth: int = 2):
        """Main crawling function - CEPAT DAN AKURAT"""
        if not os.path.exists(input_file):
            print(f"{Colors.RED}Error: File {input_file} tidak ditemukan{Colors.RESET}")
            return
        
        # Load existing
        self.load_existing()
        
        # Set untuk track processed domains
        self.processed_domains = set()
        
        # Baca domains dari file
        domains = []
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domain = line.split(',')[0].strip()
                    domain = re.sub(r'^https?://', '', domain)
                    domain = domain.split('/')[0]
                    if domain and '.' in domain:
                        domains.append(domain.lower())
        
        domains = list(set(domains))
        
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}  🚀 FAST + ACCURATE SUBDOMAIN CRAWLER{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📁 Total domains: {len(domains)}")
        print(f"📊 Existing: {len(self.all_subdomains)}")
        print(f"⚡ Threads: {self.threads}")
        print(f"📏 Max depth: {max_depth}")
        print(f"⏱️  Delay: {self.delay}s")
        print(f"📄 Output: {self.output_file}{Colors.RESET}\n")
        
        # Start workers
        workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            workers.append(t)
        
        # Queue root domains
        for domain in domains:
            self.task_queue.put((domain, 0, max_depth))
        
        # Monitor progress
        start_time = time.time()
        last_count = 0
        stall_counter = 0
        
        try:
            while self.running:
                time.sleep(2)
                
                queue_size = self.task_queue.qsize()
                processed = len(self.processed_domains)
                found = len(self.all_subdomains)
                elapsed = time.time() - start_time
                
                rate = found / elapsed if elapsed > 0 else 0
                
                print(f"\r{Colors.BLUE}📊 Progress: {processed} domain diproses | {found} subdomain ditemukan | Queue: {queue_size} | Rate: {rate:.1f}/detik{Colors.RESET}", end="")
                
                # Cek jika selesai
                if queue_size == 0 and processed == last_count:
                    stall_counter += 1
                    if stall_counter > 5:
                        print(f"\n{Colors.GREEN}✅ Semua domain selesai diproses!{Colors.RESET}")
                        break
                else:
                    stall_counter = 0
                    last_count = processed
                    
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⚠️  Dihentikan user{Colors.RESET}")
            self.running = False
        
        # Wait for queue to empty
        self.task_queue.join()
        self.running = False
        
        elapsed = time.time() - start_time
        self.print_summary(elapsed)
    
    def print_summary(self, elapsed):
        """Print summary"""
        print(f"\n\n{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}  📊 CRAWLING COMPLETE{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📈 Total subdomain unik: {Colors.CYAN}{len(self.all_subdomains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}🔍 Domain diproses: {Colors.CYAN}{len(self.processed_domains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}🌐 Total requests: {Colors.CYAN}{self.stats['total_requests']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}✅ Sukses: {Colors.GREEN}{self.stats['successful']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}❌ Gagal: {Colors.RED}{self.stats['failed']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}⏱️  Waktu: {Colors.CYAN}{elapsed:.2f} detik{Colors.RESET}")
        print(f"{Colors.WHITE}⚡ Kecepatan: {Colors.CYAN}{len(self.all_subdomains)/elapsed:.1f} domain/detik{Colors.RESET}\n")
        
        # Top sources
        print(f"{Colors.BOLD}🏆 Sumber Terbaik:{Colors.RESET}")
        sorted_sources = sorted(self.stats['by_source'].items(), key=lambda x: x[1], reverse=True)
        for source, count in sorted_sources[:5]:
            print(f"  {Colors.YELLOW}{source:12}: {count:6,} subdomain{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}✅ Hasil disimpan di: {self.output_file}{Colors.RESET}")
        
        # Sample
        if self.all_subdomains:
            print(f"\n{Colors.DIM}Contoh (10 pertama):{Colors.RESET}")
            for sub in sorted(list(self.all_subdomains))[:10]:
                print(f"  {Colors.WHITE}{sub}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description="Fast + Accurate Subdomain Crawler")
    parser.add_argument('--input', '-i', default='domains.txt', help='File input')
    parser.add_argument('--output', '-o', default='all_subdomains.txt', help='Output file')
    parser.add_argument('--threads', '-t', type=int, default=50, help='Threads (default: 50)')
    parser.add_argument('--depth', '-d', type=int, default=2, help='Max depth (default: 2)')
    parser.add_argument('--delay', type=float, default=0.01, help='Delay (default: 0.01)')
    
    args = parser.parse_args()
    
    crawler = FastAccurateCrawler(
        output_file=args.output,
        threads=args.threads,
        delay=args.delay
    )
    
    crawler.fast_accurate_crawl(args.input, max_depth=args.depth)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Dihentikan user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)
