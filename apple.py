#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deep Subdomain Crawler - HYPERSPEED EDITION
Target: 500+ URL/detik menggunakan parallel processing maksimal + jq integration
"""

import subprocess
import json
import time
import argparse
from typing import Set, List, Dict
import urllib3
import sys
import os
import re
from datetime import datetime
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import queue
import threading
import signal
import tempfile
import gzip
import io

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

class HyperspeedCrawler:
    def __init__(self, output_file: str = "all_subdomains.txt", 
                 threads: int = 100,  # Increased dramatically
                 batch_size: int = 1000,
                 delay: float = 0.001):  # Minimal delay
        self.output_file = output_file
        self.threads = threads
        self.batch_size = batch_size
        self.delay = delay
        self.all_subdomains = set()
        self.stats = {
            'total_requests': 0,
            'successful': 0,
            'failed': 0,
            'by_source': {},
            'start_time': time.time(),
            'domains_processed': 0
        }
        self.lock = threading.Lock()
        self.running = True
        
        # Initialize output file
        with open(self.output_file, 'w') as f:
            f.write(f"# Hyperspeed Subdomain Crawl Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Target: 500+ URLs/sec\n\n")
    
    def jq_parse_crtsh(self, data: str) -> Set[str]:
        """Parse crt.sh dengan jq untuk kecepatan maksimal"""
        try:
            # Gunakan jq untuk extract domain dengan sangat cepat
            cmd = ['jq', '-r', '.[] | select(.name_value != null) | .name_value | split("\\n")[] | sub("^\\\\*\\."; "") | select(endswith("{domain}"))']
            
            # Ganti placeholder dengan regex di jq
            proc = subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                return set(proc.stdout.strip().split('\n'))
        except:
            pass
        return set()
    
    def jq_parse_json(self, data: str, jq_filter: str) -> Set[str]:
        """Generic jq parser untuk JSON apapun"""
        try:
            proc = subprocess.run(['jq', '-r', jq_filter], 
                                 input=data, capture_output=True, text=True, timeout=3)
            if proc.returncode == 0 and proc.stdout.strip():
                return set(proc.stdout.strip().split('\n'))
        except:
            pass
        return set()
    
    def rapid_batch_request(self, urls: List[str]) -> Dict[str, str]:
        """
        Batch request dengan keep-alive dan connection pooling
        Menggunakan curl paralel untuk kecepatan maksimal
        """
        if not urls:
            return {}
        
        # Buat temporary file untuk URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            for url in urls:
                f.write(f"{url}\n")
            url_file = f.name
        
        try:
            # Gunakan curl dengan parallel (xargs) untuk speed maksimal
            cmd = f"xargs -P {self.threads} -I {{}} curl -s -k -L --connect-timeout 3 -m 5 {{}} < {url_file}"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # Parse output (format: URL:::RESPONSE)
            results = {}
            if proc.returncode == 0:
                # TODO: Parse hasil curl
                pass
        finally:
            os.unlink(url_file)
        
        return results
    
    def curl_batch_get(self, urls: List[str]) -> List[tuple]:
        """
        Gunakan curl parallel untuk fetch banyak URL sekaligus
        Ini JAUH lebih cepat daripada requests python
        """
        if not urls:
            return []
        
        results = []
        
        # Buat file untuk URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            for url in urls:
                f.write(f"{url}\n")
            url_file = f.name
        
        # Buat file untuk output
        output_file = tempfile.mktemp()
        
        try:
            # Gunakan curl dengan parallel processing
            # --parallel --parallel-immediate untuk maksimum kecepatan
            cmd = [
                'curl', '--parallel', '--parallel-immediate', 
                '--parallel-max', str(self.threads),
                '-s', '-k', '-L',
                '--connect-timeout', '3',
                '--max-time', '5',
                '--retry', '1',
                '--output', '/dev/null',
                '--write-out', '%{url_effective}:::HTTP_%{http_code}:::%{size_download}:::time_total:%{time_total}\\n',
                '--config', url_file
            ]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if proc.returncode == 0:
                for line in proc.stdout.split('\n'):
                    if line.strip():
                        parts = line.split(':::')
                        if len(parts) >= 2:
                            url = parts[0]
                            status = parts[1]
                            results.append((url, status))
            
            # Juga ambil response bodies jika perlu
            cmd_body = [
                'curl', '--parallel', '--parallel-immediate',
                '--parallel-max', str(self.threads),
                '-s', '-k', '-L',
                '--connect-timeout', '3',
                '--max-time', '5',
                '--config', url_file
            ]
            
            proc_body = subprocess.run(cmd_body, capture_output=True, text=True, timeout=30)
            if proc_body.returncode == 0 and proc_body.stdout:
                # Simpan response untuk parsing nanti
                with open(f"{output_file}.bodies", 'w') as f:
                    f.write(proc_body.stdout)
                    
        except Exception as e:
            print(f"{Colors.RED}Curl error: {e}{Colors.RESET}")
        finally:
            os.unlink(url_file)
        
        return results
    
    def rapid_scan_domain(self, domain: str) -> Set[str]:
        """
        Hyper-optimized domain scanning
        Menggunakan multiple teknik parallel untuk kecepatan maksimal
        """
        all_found = set()
        queue = [domain]
        scanned = set()
        
        # Siapkan semua URL yang akan di-request
        api_urls = []
        api_configs = []
        
        # Prepare all API URLs untuk batch processing
        for current in queue:
            if current in scanned:
                continue
            scanned.add(current)
            
            # crt.sh
            api_urls.append(f"https://crt.sh/?q=%.{current}&output=json")
            api_configs.append(('crt.sh', current))
            
            # Hackertarget
            api_urls.append(f"https://api.hackertarget.com/hostsearch/?q={current}")
            api_configs.append(('hackertarget', current))
            
            # AlienVault
            api_urls.append(f"https://otx.alienvault.com/api/v1/indicators/domain/{current}/passive_dns")
            api_configs.append(('alienvault', current))
            
            # RapidDNS
            api_urls.append(f"https://rapiddns.io/subdomain/{current}?full=1&output=json")
            api_configs.append(('rapiddns', current))
            
            # BufferOver
            api_urls.append(f"https://dns.bufferover.run/dns?q=.{current}")
            api_configs.append(('bufferover', current))
        
        # BATCH REQUEST SEMUA URL SEKALIGUS
        print(f"{Colors.CYAN}  ⚡ Batch requesting {len(api_urls)} URLs for {domain}{Colors.RESET}")
        
        # Method 1: Parallel curl
        curl_results = self.curl_batch_get(api_urls)
        
        # Method 2: ThreadPool untuk parsing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            # Parse setiap response
            for i, (url, status) in enumerate(curl_results):
                if '200' in status:
                    source, target = api_configs[i]
                    future = executor.submit(self.parse_source_response, source, target, None)  # TODO: Pass response body
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    new_subs = future.result(timeout=5)
                    all_found.update(new_subs)
                except:
                    pass
        
        return all_found
    
    def parse_source_response(self, source: str, domain: str, response_body: str) -> Set[str]:
        """Parse response berdasarkan source"""
        if not response_body:
            return set()
        
        try:
            if source == 'crt.sh':
                # Parse dengan jq untuk kecepatan
                cmd = f"echo '{response_body}' | jq -r '.[] | .name_value // empty' | grep -E '\\.{domain}$' | sed 's/^\\*\\.//'"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                if proc.returncode == 0:
                    return set(proc.stdout.strip().split('\n'))
            
            elif source == 'hackertarget':
                # Hackertarget format: domain,ip
                cmd = f"echo '{response_body}' | cut -d',' -f1 | grep -E '\\.{domain}$'"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                if proc.returncode == 0:
                    return set(proc.stdout.strip().split('\n'))
            
            elif source == 'alienvault':
                cmd = f"echo '{response_body}' | jq -r '.passive_dns[]?.hostname // empty' | grep -E '\\.{domain}$'"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                if proc.returncode == 0:
                    return set(proc.stdout.strip().split('\n'))
            
            elif source == 'rapiddns':
                cmd = f"echo '{response_body}' | jq -r '.[]?.name // empty' | grep -E '\\.{domain}$'"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                if proc.returncode == 0:
                    return set(proc.stdout.strip().split('\n'))
            
            elif source == 'bufferover':
                cmd = f"echo '{response_body}' | jq -r '.FDNS_A[]?, .RDNS[]?' | cut -d',' -f2 | grep -E '\\.{domain}$'"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                if proc.returncode == 0:
                    return set(proc.stdout.strip().split('\n'))
                    
        except:
            pass
        
        return set()
    
    def process_domain_batch(self, domains: List[str]) -> Dict[str, Set[str]]:
        """Process multiple domains sekaligus dalam satu batch"""
        results = {}
        
        # Kumpulkan semua API URLs untuk semua domains
        all_api_urls = []
        url_to_info = []
        
        for domain in domains:
            # crt.sh
            all_api_urls.append(f"https://crt.sh/?q=%.{domain}&output=json")
            url_to_info.append(('crt.sh', domain))
            
            # hackertarget
            all_api_urls.append(f"https://api.hackertarget.com/hostsearch/?q={domain}")
            url_to_info.append(('hackertarget', domain))
            
            # alienvault
            all_api_urls.append(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
            url_to_info.append(('alienvault', domain))
        
        # Batch request semua URLs
        print(f"{Colors.MAGENTA}⚡ Batch processing {len(domains)} domains ({len(all_api_urls)} URLs){Colors.RESET}")
        
        # Gunakan curl parallel
        responses = self.curl_batch_get(all_api_urls)
        
        # Parse responses dengan ThreadPool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_info = {}
            
            for i, (url, status) in enumerate(responses):
                if '200' in status:
                    source, domain = url_to_info[i]
                    # TODO: Dapatkan response body
                    future = executor.submit(self.parse_source_response, source, domain, "")
                    future_to_info[future] = (source, domain)
            
            for future in as_completed(future_to_info):
                source, domain = future_to_info[future]
                try:
                    subs = future.result(timeout=5)
                    if domain not in results:
                        results[domain] = set()
                    results[domain].update(subs)
                except:
                    pass
        
        return results
    
    def hyperspeed_crawl(self, input_file: str, max_depth: int = 2):
        """Main crawling function dengan kecepatan maksimal"""
        if not os.path.exists(input_file):
            print(f"{Colors.RED}Error: File {input_file} tidak ditemukan{Colors.RESET}")
            return
        
        # Baca semua domains
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
        print(f"{Colors.BOLD}{Colors.MAGENTA}  🚀 HYPERSPEED SUBDOMAIN CRAWLER{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}📁 Total domains: {len(domains)}")
        print(f"⚡ Threads: {self.threads}")
        print(f"📦 Batch size: {self.batch_size}")
        print(f"⏱️  Target: 500+ URLs/sec")
        print(f"📄 Output: {self.output_file}{Colors.RESET}\n")
        
        start_time = time.time()
        
        # Process dalam batch besar
        for i in range(0, len(domains), self.batch_size):
            batch = domains[i:i+self.batch_size]
            batch_num = i//self.batch_size + 1
            total_batches = (len(domains) + self.batch_size - 1) // self.batch_size
            
            print(f"\n{Colors.BOLD}{Colors.GREEN}[Batch {batch_num}/{total_batches}] Processing {len(batch)} domains{Colors.RESET}")
            
            # Process batch dengan parallel maksimal
            batch_results = self.process_domain_batch(batch)
            
            # Simpan hasil
            new_subs = set()
            for domain, subs in batch_results.items():
                for sub in subs:
                    if sub not in self.all_subdomains:
                        self.all_subdomains.add(sub)
                        new_subs.add(sub)
            
            if new_subs:
                self.save_subdomains(new_subs)
            
            # Hitung speed
            elapsed = time.time() - start_time
            rate = len(self.all_subdomains) / elapsed if elapsed > 0 else 0
            
            print(f"{Colors.CYAN}  📊 Found {len(new_subs)} new | Total: {len(self.all_subdomains)} | Rate: {rate:.0f}/sec{Colors.RESET}")
        
        elapsed = time.time() - start_time
        total_rate = len(self.all_subdomains) / elapsed
        print(f"\n{Colors.GREEN}✅ COMPLETE! Total: {len(self.all_subdomains)} subdomains in {elapsed:.2f}s ({total_rate:.0f}/sec){Colors.RESET}")
    
    def save_subdomains(self, subdomains: Set[str]):
        """Save subdomains to file"""
        try:
            with open(self.output_file, 'a') as f:
                for sub in sorted(subdomains):
                    f.write(f"{sub}\n")
        except:
            pass

def main():
    parser = argparse.ArgumentParser(description="Hyperspeed Subdomain Crawler - 500+ URLs/sec")
    parser.add_argument('--input', '-i', default='domains.txt', help='Input file')
    parser.add_argument('--output', '-o', default='all_subdomains.txt', help='Output file')
    parser.add_argument('--threads', '-t', type=int, default=200, help='Thread count (default: 200)')
    parser.add_argument('--batch', '-b', type=int, default=1000, help='Batch size (default: 1000)')
    parser.add_argument('--depth', '-d', type=int, default=2, help='Max depth (default: 2)')
    
    args = parser.parse_args()
    
    # Check for required tools
    for tool in ['curl', 'jq', 'xargs']:
        if not subprocess.run(f'which {tool}', shell=True, capture_output=True).returncode == 0:
            print(f"{Colors.RED}Error: {tool} not found. Install with: apt-get install {tool}{Colors.RESET}")
            return
    
    crawler = HyperspeedCrawler(
        output_file=args.output,
        threads=args.threads,
        batch_size=args.batch
    )
    
    crawler.hyperspeed_crawl(args.input, max_depth=args.depth)

if __name__ == '__main__':
    main()
