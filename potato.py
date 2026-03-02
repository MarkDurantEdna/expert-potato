#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GH Archive Domain and IPv4 Grabber - ULTIMATE EDITION
Extract VALID domains and IPv4 addresses from multiple GitHub Archive sources
with COMPREHENSIVE TLD support (ALL valid TLDs from IANA)
"""
import requests
import json
import gzip
import io
import re
from datetime import datetime, timedelta
from typing import Set, List, Dict
import urllib3
import threading
import argparse
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import socket
import dns.resolver
import dns.exception
import warnings
from collections import defaultdict
import hashlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

# Terminal colors
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
    BLINK = '\033[5m'
    RESET = '\033[0m'

class DomainIPGrabber:
    def __init__(self, domains_output: str, ips_output: str, tld_file: str = None):
        self.base_urls = [
            "https://data.gharchive.org",  # Main GH Archive
            "https://gharchive.org",        # Alternative GH Archive
            "https://storage.googleapis.com/gharchive",  # Google Storage mirror
            "https://archive.org/download/gharchive",    # Internet Archive mirror
            "https://gharchive.mirror.com",              # Additional mirror
        ]
        
        self.domains = set()
        self.ips = set()
        self.subdomains = set()
        self.urls = set()
        self.emails = set()
        
        self.domains_lock = threading.Lock()
        self.ips_lock = threading.Lock()
        self.subdomains_lock = threading.Lock()
        self.urls_lock = threading.Lock()
        self.emails_lock = threading.Lock()
        
        self.domains_output = domains_output
        self.ips_output = ips_output
        self.tld_file = tld_file
        
        # Initialize output files with headers
        self.init_output_files()
        
        # Load ALL valid TLDs
        self.valid_tlds = self.load_all_tlds()
        self.compound_tlds = self.load_compound_tlds()
        
        # Load exclude lists
        self.exclude_domains = self.load_exclude_domains()
        self.private_ip_ranges = self.load_private_ip_ranges()
        
        # Enhanced regex patterns
        self.compile_patterns()
        
        # Statistics
        self.stats = self.init_stats()
        
        # Session management
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; GHArchiveGrabber/3.0; +https://github.com/yourrepo)'
        })
        
        # DNS cache
        self.dns_cache = {}
        self.dns_cache_lock = threading.Lock()
        
        # Processing queue
        self.processing_queue = []
        self.queue_lock = threading.Lock()
        
        print(f"{Colors.GREEN}[✓] Loaded {len(self.valid_tlds):,} valid TLDs{Colors.RESET}")
        print(f"{Colors.GREEN}[✓] Loaded {len(self.compound_tlds):,} compound TLDs{Colors.RESET}")
        print(f"{Colors.GREEN}[✓] Loaded {len(self.exclude_domains):,} exclude domains{Colors.RESET}")

    def compile_patterns(self):
        """Compile all regex patterns"""
        # Email pattern (catches all email variations)
        self.email_pattern = re.compile(
            r'\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b',
            re.IGNORECASE
        )

        # URL pattern (all protocols)
        self.url_pattern = re.compile(
            r'(?:(?:https?|ftp|sftp|ssh|git|svn|ws|wss|file|gopher|gemini|gopher)://)?'  # Protocol
            r'(?:[a-zA-Z0-9-]+\.)+'  # Subdomains
            r'([a-zA-Z]{2,})'  # TLD
            r'(?:[:/\?#]|$)',  # End or port/path
            re.IGNORECASE
        )

        # Domain in text pattern (any domain-like string)
        self.domain_pattern = re.compile(
            r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.([a-zA-Z]{2,}))\b',
            re.IGNORECASE
        )

        # Subdomain pattern
        self.subdomain_pattern = re.compile(
            r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b',
            re.IGNORECASE
        )

        # IPv4 pattern (strict)
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )

        # IPv6 pattern (comprehensive)
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|'
            r'\b[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})\b|'
            r'\b:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)\b|'
            r'\bfe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,5}:[0-9a-fA-F]{1,4}\b'
        )

        # API endpoints pattern
        self.api_pattern = re.compile(
            r'\b(?:api|graphql|rest|v[0-9]+)\.([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b',
            re.IGNORECASE
        )

        # CDN domains pattern
        self.cdn_pattern = re.compile(
            r'\b(?:cdn|static|assets|media|images|img|css|js|fonts)\.([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b',
            re.IGNORECASE
        )

    def load_all_tlds(self) -> Set[str]:
        """Load ALL valid TLDs from IANA and other sources"""
        tlds = set()
        
        # Try to load from IANA list
        try:
            response = requests.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', timeout=10)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line and not line.startswith('#'):
                        tlds.add(line.strip().lower())
        except:
            pass
        
        # If IANA failed, use comprehensive built-in list
        if not tlds:
            tlds = self.get_comprehensive_tlds()
        
        # Add common pseudo-TLDs
        pseudo_tlds = {
            'local', 'localhost', 'test', 'example', 'invalid', 'dev', 'staging',
            'prod', 'production', 'development', 'internal', 'intranet', 'corp',
            'home', 'lan', 'domain', 'workgroup', 'blog', 'site', 'wordpress',
            'web', 'server', 'mail', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'ns3',
            'dns', 'dhcp', 'router', 'gateway', 'firewall', 'vpn', 'proxy'
        }
        tlds.update(pseudo_tlds)
        
        return tlds

    def get_comprehensive_tlds(self) -> Set[str]:
        """Comprehensive built-in TLD list (over 1500+ TLDs)"""
        return {
            # Original TLDs
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
            
            # Country code TLDs (ccTLDs)
            'ac', 'ad', 'ae', 'af', 'ag', 'ai', 'al', 'am', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'aw', 'ax', 'az',
            'ba', 'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bm', 'bn', 'bo', 'br', 'bs', 'bt', 'bv', 'bw', 'by', 'bz',
            'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'cr', 'cu', 'cv', 'cw', 'cx', 'cy', 'cz',
            'de', 'dj', 'dk', 'dm', 'do', 'dz',
            'ec', 'ee', 'eg', 'er', 'es', 'et', 'eu',
            'fi', 'fj', 'fk', 'fm', 'fo', 'fr',
            'ga', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gp', 'gq', 'gr', 'gs', 'gt', 'gu', 'gw', 'gy',
            'hk', 'hm', 'hn', 'hr', 'ht', 'hu',
            'id', 'ie', 'il', 'im', 'in', 'io', 'iq', 'ir', 'is', 'it',
            'je', 'jm', 'jo', 'jp',
            'ke', 'kg', 'kh', 'ki', 'km', 'kn', 'kp', 'kr', 'kw', 'ky', 'kz',
            'la', 'lb', 'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv', 'ly',
            'ma', 'mc', 'md', 'me', 'mg', 'mh', 'mk', 'ml', 'mm', 'mn', 'mo', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'my', 'mz',
            'na', 'nc', 'ne', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz',
            'om',
            'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm', 'pn', 'pr', 'ps', 'pt', 'pw', 'py',
            'qa',
            're', 'ro', 'rs', 'ru', 'rw',
            'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si', 'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'sr', 'ss', 'st', 'su', 'sv', 'sx', 'sy', 'sz',
            'tc', 'td', 'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tr', 'tt', 'tv', 'tw', 'tz',
            'ua', 'ug', 'uk', 'us', 'uy', 'uz',
            'va', 'vc', 've', 'vg', 'vi', 'vn', 'vu',
            'wf', 'ws',
            'ye', 'yt',
            'za', 'zm', 'zw',
            
            # Generic TLDs (gTLDs)
            'aaa', 'aarp', 'abarth', 'abb', 'abbott', 'abbvie', 'abc', 'able', 'abogado', 'abudhabi',
            'academy', 'accenture', 'accountant', 'accountants', 'aco', 'actor', 'ads', 'adult',
            'aeg', 'aetna', 'afamilycompany', 'afl', 'africa', 'agakhan', 'agency', 'aig', 'aigo',
            'airbus', 'airforce', 'airtel', 'akdn', 'alfaromeo', 'alibaba', 'alipay', 'allfinanz',
            'allstate', 'ally', 'alsace', 'alstom', 'americanexpress', 'americanfamily', 'amex',
            'amfam', 'amica', 'amsterdam', 'analytics', 'android', 'anquan', 'anz', 'aol', 'apartments',
            'app', 'apple', 'aquarelle', 'arab', 'aramco', 'archi', 'army', 'art', 'arte', 'asda',
            'associates', 'athleta', 'attorney', 'auction', 'audi', 'audible', 'audio', 'auspost',
            'author', 'auto', 'autos', 'avianca', 'aws', 'axa', 'azure',
            'baby', 'baidu', 'banamex', 'bananarepublic', 'band', 'bank', 'bar', 'barcelona', 'barclaycard',
            'barclays', 'barefoot', 'bargains', 'baseball', 'basketball', 'bauhaus', 'bayern', 'bbc',
            'bbt', 'bbva', 'bcg', 'bcn', 'beats', 'beauty', 'beer', 'bentley', 'berlin', 'best', 'bestbuy',
            'bet', 'bharti', 'bible', 'bid', 'bike', 'bing', 'bingo', 'bio', 'biz', 'black', 'blackfriday',
            'blockbuster', 'blog', 'bloomberg', 'blue', 'bms', 'bmw', 'bnpparibas', 'boats', 'boehringer',
            'bofa', 'bom', 'bond', 'boo', 'book', 'booking', 'bosch', 'bostik', 'boston', 'bot', 'boutique',
            'box', 'bradesco', 'bridgestone', 'broadway', 'broker', 'brother', 'brussels', 'budapest',
            'bugatti', 'build', 'builders', 'business', 'buy', 'buzz', 'bzh',
            'cab', 'cafe', 'cal', 'call', 'calvinklein', 'cam', 'camera', 'camp', 'cancerresearch', 'canon',
            'capetown', 'capital', 'capitalone', 'car', 'caravan', 'cards', 'care', 'career', 'careers',
            'cars', 'casa', 'case', 'caseih', 'cash', 'casino', 'catering', 'catholic', 'cba', 'cbn',
            'cbre', 'cbs', 'ceb', 'center', 'ceo', 'cern', 'cfa', 'cfd', 'chanel', 'channel', 'charity',
            'chase', 'chat', 'cheap', 'chintai', 'christmas', 'chrome', 'church', 'cipriani', 'circle',
            'cisco', 'citadel', 'citi', 'citic', 'city', 'cityeats', 'claims', 'cleaning', 'click',
            'clinic', 'clinique', 'clothing', 'cloud', 'club', 'clubmed', 'coach', 'codes', 'coffee',
            'college', 'cologne', 'comcast', 'commbank', 'community', 'company', 'compare', 'computer',
            'comsec', 'condos', 'construction', 'consulting', 'contact', 'contractors', 'cooking',
            'cookingchannel', 'cool', 'coop', 'corsica', 'country', 'coupon', 'coupons', 'courses',
            'cpa', 'credit', 'creditcard', 'creditunion', 'cricket', 'crown', 'crs', 'cruise', 'cruises',
            'csc', 'cuisinella', 'cymru', 'cyou',
            'dabur', 'dad', 'dance', 'data', 'date', 'dating', 'datsun', 'day', 'dclk', 'dds', 'deal',
            'dealer', 'deals', 'degree', 'delivery', 'dell', 'deloitte', 'delta', 'democrat', 'dental',
            'dentist', 'desi', 'design', 'dev', 'dhl', 'diamonds', 'diet', 'digital', 'direct', 'directory',
            'discount', 'discover', 'dish', 'diy', 'dnp', 'docs', 'doctor', 'dog', 'domains', 'dot',
            'download', 'drive', 'dtv', 'dubai', 'duck', 'dunlop', 'dupont', 'durban', 'dvag', 'dvr',
            'earth', 'eat', 'eco', 'edeka', 'education', 'email', 'emerck', 'energy', 'engineer',
            'engineering', 'enterprises', 'epson', 'equipment', 'ericsson', 'erni', 'esq', 'estate',
            'esurance', 'etisalat', 'eurovision', 'eus', 'events', 'exchange', 'expert', 'exposed',
            'express', 'extraspace', 'fage', 'fail', 'fairwinds', 'faith', 'family', 'fan', 'fans',
            'farm', 'farmers', 'fashion', 'fast', 'fedex', 'feedback', 'ferrari', 'ferrero', 'fiat',
            'fidelity', 'fido', 'film', 'final', 'finance', 'financial', 'fire', 'firestone', 'firmdale',
            'fish', 'fishing', 'fit', 'fitness', 'flickr', 'flights', 'flir', 'florist', 'flowers',
            'fly', 'foo', 'food', 'foodnetwork', 'football', 'ford', 'forex', 'forsale', 'forum',
            'foundation', 'fox', 'free', 'fresenius', 'frl', 'frogans', 'frontdoor', 'frontier',
            'ftr', 'fujitsu', 'fujixerox', 'fun', 'fund', 'furniture', 'futbol', 'fyi',
            'gal', 'gallery', 'gallo', 'gallup', 'game', 'games', 'gap', 'garden', 'gay', 'gbiz',
            'gdn', 'gea', 'gent', 'genting', 'george', 'ggee', 'gift', 'gifts', 'gives', 'giving',
            'glade', 'glass', 'gle', 'global', 'globo', 'gmail', 'gmbh', 'gmo', 'gmx', 'godaddy',
            'gold', 'goldpoint', 'golf', 'goo', 'goodyear', 'goog', 'google', 'gop', 'got', 'grainger',
            'graphics', 'gratis', 'green', 'gripe', 'grocery', 'group', 'guardian', 'gucci', 'guge',
            'guide', 'guitars', 'guru', 'hair', 'hamburg', 'hangout', 'haus', 'hbo', 'hdfc', 'hdfcbank',
            'health', 'healthcare', 'help', 'helsinki', 'here', 'hermes', 'hgtv', 'hiphop', 'hisamitsu',
            'hitachi', 'hiv', 'hkt', 'hockey', 'holdings', 'holiday', 'homedepot', 'homegoods', 'homes',
            'homesense', 'honda', 'horse', 'hospital', 'host', 'hosting', 'hot', 'hoteles', 'hotels',
            'hotmail', 'house', 'how', 'hsbc', 'hughes', 'hyatt', 'hyundai', 'ibm', 'icbc', 'ice',
            'icu', 'ieee', 'ifm', 'ikano', 'imamat', 'imdb', 'immo', 'immobilien', 'inc', 'industries',
            'infiniti', 'info', 'ing', 'ink', 'institute', 'insurance', 'insure', 'intel', 'international',
            'intuit', 'investments', 'ipiranga', 'irish', 'ismaili', 'ist', 'istanbul', 'itau', 'itv',
            'iveco', 'jaguar', 'java', 'jcb', 'jcp', 'jeep', 'jetzt', 'jewelry', 'jio', 'jll', 'jmp',
            'jnj', 'joburg', 'jot', 'joy', 'jpmorgan', 'jprs', 'juegos', 'juniper', 'kaufen', 'kddi',
            'kerryhotels', 'kerrylogistics', 'kerryproperties', 'kfh', 'kia', 'kim', 'kinder', 'kindle',
            'kitchen', 'kiwi', 'koeln', 'komatsu', 'kosher', 'kpmg', 'kpn', 'krd', 'kred', 'kuokgroup',
            'kyoto', 'lacaixa', 'lamborghini', 'lamer', 'lancaster', 'lancia', 'land', 'landrover',
            'lanxess', 'lasalle', 'lat', 'latino', 'latrobe', 'law', 'lawyer', 'lds', 'lease', 'leclerc',
            'lefrak', 'legal', 'lego', 'lexus', 'lgbt', 'liaison', 'lidl', 'life', 'lifeinsurance',
            'lifestyle', 'lighting', 'like', 'lilly', 'limited', 'limo', 'lincoln', 'linde', 'link',
            'lipsy', 'live', 'living', 'lixil', 'llc', 'llp', 'loan', 'loans', 'locker', 'locus',
            'loft', 'lol', 'london', 'lotte', 'lotto', 'love', 'lpl', 'lplfinancial', 'ltd', 'ltda',
            'lundbeck', 'lupin', 'luxe', 'luxury',
            'macys', 'madrid', 'maif', 'maison', 'makeup', 'man', 'management', 'mango', 'map', 'market',
            'marketing', 'markets', 'marriott', 'marshalls', 'maserati', 'mattel', 'mba', 'mckinsey',
            'med', 'media', 'meet', 'melbourne', 'meme', 'memorial', 'men', 'menu', 'merckmsd', 'metlife',
            'miami', 'microsoft', 'mini', 'mint', 'mit', 'mitsubishi', 'mlb', 'mls', 'mma', 'mobile',
            'moda', 'moe', 'moi', 'mom', 'monash', 'money', 'monster', 'mopar', 'mormon', 'mortgage',
            'moscow', 'moto', 'motorcycles', 'mov', 'movie', 'msd', 'mtn', 'mtr', 'mutual',
            'nab', 'nadex', 'nagoya', 'name', 'nationwide', 'natura', 'navy', 'nba', 'nec', 'netbank',
            'netflix', 'network', 'neustar', 'new', 'newholland', 'news', 'next', 'nextdirect', 'nexus',
            'nfl', 'ngo', 'nhk', 'nico', 'nike', 'nikon', 'ninja', 'nissan', 'nissay', 'nokia',
            'northwesternmutual', 'norton', 'now', 'nowruz', 'nowtv', 'nra', 'nrw', 'ntt', 'nyc',
            'obi', 'observer', 'off', 'office', 'okinawa', 'olayan', 'olayangroup', 'oldnavy', 'ollo',
            'omega', 'one', 'ong', 'onl', 'online', 'onyourside', 'ooo', 'open', 'oracle', 'orange',
            'organic', 'origins', 'osaka', 'otsuka', 'ott', 'ovh',
            'page', 'panasonic', 'paris', 'pars', 'partners', 'parts', 'party', 'passagens', 'pay',
            'pccw', 'pet', 'pfizer', 'pharmacy', 'phd', 'philips', 'phone', 'photo', 'photography',
            'photos', 'physio', 'pics', 'pictet', 'pictures', 'pid', 'pin', 'ping', 'pink', 'pioneer',
            'pizza', 'place', 'play', 'playstation', 'plumbing', 'plus', 'pnc', 'pohl', 'poker',
            'politie', 'porn', 'post', 'pramerica', 'praxi', 'press', 'prime', 'pro', 'prod', 'productions',
            'prof', 'progressive', 'promo', 'properties', 'property', 'protection', 'pru', 'prudential',
            'pub', 'pwc',
            'qpon', 'quebec', 'quest', 'qvc',
            'racing', 'radio', 'raid', 'read', 'realestate', 'realtor', 'realty', 'recipes', 'red',
            'redstone', 'redumbrella', 'rehab', 'reise', 'reisen', 'reit', 'reliance', 'ren', 'rent',
            'rentals', 'repair', 'report', 'republican', 'rest', 'restaurant', 'review', 'reviews',
            'rexroth', 'rich', 'richardli', 'ricoh', 'rightathome', 'ril', 'rio', 'rip', 'rmit', 'rocher',
            'rocks', 'rodeo', 'rogers', 'room', 'rsvp', 'rugby', 'ruhr', 'run',
            'rwe', 'ryukyu',
            'saarland', 'safe', 'safety', 'sakura', 'sale', 'salon', 'samsclub', 'samsung', 'sandvik',
            'sandvikcoromant', 'sanofi', 'sap', 'sarl', 'sas', 'save', 'saxo', 'sbi', 'sbs', 'sca',
            'scb', 'schaeffler', 'schmidt', 'scholarships', 'school', 'schule', 'schwarz', 'science',
            'scjohnson', 'scor', 'scot', 'search', 'seat', 'secure', 'security', 'seek', 'select',
            'sener', 'services', 'ses', 'seven', 'sew', 'sex', 'sexy', 'sfr', 'shangrila', 'sharp',
            'shaw', 'shell', 'shia', 'shiksha', 'shoes', 'shop', 'shopping', 'shouji', 'show', 'showtime',
            'shriram', 'silk', 'sina', 'singles', 'site', 'ski', 'skin', 'sky', 'skype', 'sling',
            'smart', 'smile', 'sncf', 'soccer', 'social', 'softbank', 'software', 'sohu', 'solar',
            'solutions', 'song', 'sony', 'soy', 'spa', 'space', 'sport', 'spot', 'spreadbetting',
            'srl', 'stada', 'staples', 'star', 'statebank', 'statefarm', 'stc', 'stcgroup', 'stockholm',
            'storage', 'store', 'stream', 'studio', 'study', 'style', 'sucks', 'supplies', 'supply',
            'support', 'surf', 'surgery', 'suzuki', 'swatch', 'swiftcover', 'swiss', 'sydney', 'symantec',
            'systems',
            'tab', 'taipei', 'talk', 'taobao', 'target', 'tatamotors', 'tatar', 'tattoo', 'tax', 'taxi',
            'tci', 'tdk', 'team', 'tech', 'technology', 'tel', 'telefonica', 'temasek', 'tennis',
            'teva', 'tf', 'tgv', 'thd', 'theater', 'theatre', 'tiaa', 'tickets', 'tienda', 'tiffany',
            'tips', 'tires', 'tirol', 'tjmaxx', 'tjx', 'tkmaxx', 'tmall', 'today', 'tokyo', 'tools',
            'top', 'toray', 'toshiba', 'total', 'tours', 'town', 'toyota', 'toys', 'trade', 'trading',
            'training', 'travel', 'travelchannel', 'travelers', 'travelersinsurance', 'trust', 'trv',
            'tube', 'tui', 'tunes', 'tushu', 'tvs',
            'ubank', 'ubs', 'unicom', 'university', 'uno', 'uol', 'ups', 'vacations', 'vana', 'vanguard',
            'vegas', 'ventures', 'verisign', 'versicherung', 'vet', 'viajes', 'video', 'vig', 'viking',
            'villas', 'vin', 'vip', 'virgin', 'visa', 'vision', 'viva', 'vivo', 'vlaanderen', 'vodka',
            'volkswagen', 'volvo', 'vote', 'voting', 'voto', 'voyage',
            'wales', 'walmart', 'walter', 'wang', 'wanggou', 'watch', 'watches', 'weather', 'weatherchannel',
            'webcam', 'weber', 'website', 'wed', 'wedding', 'weibo', 'weir', 'whoswho', 'wien', 'wiki',
            'williamhill', 'win', 'windows', 'wine', 'winners', 'wme', 'wolterskluwer', 'woodside',
            'work', 'works', 'world', 'wow',
            'wtc', 'wtf',
            'xbox', 'xerox', 'xfinity', 'xihuan', 'xin', 'xn--11b4c3d', 'xn--1ck2e1b', 'xn--1qqw23a',
            'xn--2scrj9c', 'xn--30rr7y', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--3hcrj9c',
            'xn--3oq18vl8pn36a', 'xn--3pxu8k', 'xn--42c2d9a', 'xn--45br5cyl', 'xn--45brj9c', 'xn--45q11c',
            'xn--4gbrim', 'xn--54b7fta0cc', 'xn--55qw42g', 'xn--55qx5d', 'xn--5su34j936bgsg', 'xn--5tzm5g',
            'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80adxhks', 'xn--80ao21a', 'xn--80aqecdr1a', 'xn--80asehdb',
            'xn--80aswg', 'xn--8y0a063a', 'xn--90a3ac', 'xn--90ae', 'xn--90ais', 'xn--9dbq2a', 'xn--9et52u',
            'xn--9krt00a', 'xn--b4w605ferd', 'xn--bck1b9a5dre4c', 'xn--c1avg', 'xn--c2br7g', 'xn--cck2b3b',
            'xn--cckwcxetd', 'xn--cg4bki', 'xn--clchc0ea0b2g2a9gcd', 'xn--czr694b', 'xn--czrs0t', 'xn--czru2d',
            'xn--d1acj3b', 'xn--d1alf', 'xn--e1a4c', 'xn--eckvdtc9d', 'xn--efvy88h', 'xn--estv75g',
            'xn--fct429k', 'xn--fhbei', 'xn--fiq228c5hs', 'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s',
            'xn--fjq720a', 'xn--flw351e', 'xn--fpcrj9c3d', 'xn--fzc2c9e2c', 'xn--fzys8d69uvgm',
            'xn--g2xx48c', 'xn--gckr3f0f', 'xn--gecrj9c', 'xn--gk3at1e', 'xn--h2breg3eve', 'xn--h2brj9c',
            'xn--h2brj9c8c', 'xn--hxt814e', 'xn--i1b6b1a6a2e', 'xn--imr513n', 'xn--io0a7i', 'xn--j1aef',
            'xn--j1amh', 'xn--j6w193g', 'xn--jlq61u9w7b', 'xn--jvr189m', 'xn--kcrx77d1x4a', 'xn--kprw13d',
            'xn--kpry57d', 'xn--kpu716f', 'xn--kput3i', 'xn--l1acc', 'xn--lgbbat1ad8j', 'xn--mgb9awbf',
            'xn--mgba3a3ejt', 'xn--mgba3a4f16a', 'xn--mgba7c0bbn0a', 'xn--mgbaakc7dvf', 'xn--mgbaam7a8h',
            'xn--mgbab2bd', 'xn--mgbah1a3hjkrd', 'xn--mgbai9azgqp6j', 'xn--mgbayh7gpa', 'xn--mgbbh1a',
            'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgbca7dzdo', 'xn--mgbcpq6gpa1a', 'xn--mgberp4a5d4ar',
            'xn--mgbgu82a', 'xn--mgbi4ecexp', 'xn--mgbpl2fh', 'xn--mgbt3dhd', 'xn--mgbtx2b', 'xn--mgbx4cd0ab',
            'xn--mix891f', 'xn--mk1bu44c', 'xn--mxtq1m', 'xn--ngbc5azd', 'xn--ngbe9e0a', 'xn--ngbrx',
            'xn--node', 'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--nyqy26a', 'xn--o3cw4h', 'xn--ogbpf8fl',
            'xn--otu796d', 'xn--p1acf', 'xn--p1ai', 'xn--pbt977c', 'xn--pgbs0dh', 'xn--pssy2u', 'xn--q9jyb4c',
            'xn--qcka1pmc', 'xn--qxa6a', 'xn--qxam', 'xn--rhqv96g', 'xn--rovu88b', 'xn--rvc1e0am3e',
            'xn--s9brj9c', 'xn--ses554g', 'xn--t60b56a', 'xn--tckwe', 'xn--tiq49xqyj', 'xn--unup4y',
            'xn--vermgensberater-ctb', 'xn--vermgensberatung-pwb', 'xn--vhquv', 'xn--vuq861b', 'xn--w4r85el8fhu5dnra',
            'xn--w4rs40l', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xhq521b', 'xn--xkc2al3hye2a', 'xn--xkc2dl3a5ee0h',
            'xn--y9a3aq', 'xn--yfro4i67o', 'xn--ygbi2ammx', 'xn--zfr164b', 'xxx', 'xyz',
            'yachts', 'yahoo', 'yamaxun', 'yandex', 'yodobashi', 'yoga', 'yokohama', 'you', 'youtube', 'yun',
            'zappos', 'zara', 'zero', 'zip', 'zone', 'zuerich', 'zw'
        }

    def load_compound_tlds(self) -> Set[str]:
        """Load compound TLDs (e.g., co.uk, com.au)"""
        return {
            # UK variants
            'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk', 'nhs.uk',
            'mod.uk', 'mil.uk', 'police.uk',
            
            # US variants
            'ak.us', 'al.us', 'ar.us', 'az.us', 'ca.us', 'co.us', 'ct.us', 'dc.us', 'de.us', 'fl.us',
            'ga.us', 'hi.us', 'ia.us', 'id.us', 'il.us', 'in.us', 'ks.us', 'ky.us', 'la.us', 'ma.us',
            'md.us', 'me.us', 'mi.us', 'mn.us', 'mo.us', 'ms.us', 'mt.us', 'nc.us', 'nd.us', 'ne.us',
            'nh.us', 'nj.us', 'nm.us', 'nv.us', 'ny.us', 'oh.us', 'ok.us', 'or.us', 'pa.us', 'ri.us',
            'sc.us', 'sd.us', 'tn.us', 'tx.us', 'ut.us', 'va.us', 'vt.us', 'wa.us', 'wi.us', 'wv.us',
            'wy.us',
            
            # Australian variants
            'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au', 'csiro.au',
            
            # Canadian variants
            'ab.ca', 'bc.ca', 'mb.ca', 'nb.ca', 'nf.ca', 'nl.ca', 'ns.ca', 'nt.ca', 'nu.ca', 'on.ca',
            'pe.ca', 'qc.ca', 'sk.ca', 'yk.ca',
            
            # European variants
            'ac.at', 'co.at', 'gv.at', 'or.at',
            'ac.be', 'gov.br', 'com.br', 'net.br', 'org.br',
            'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
            'com.cy', 'net.cy', 'org.cy',
            'ac.il', 'co.il', 'org.il', 'net.il',
            'ac.nz', 'co.nz', 'geek.nz', 'gen.nz', 'maori.nz', 'net.nz', 'org.nz', 'school.nz',
            'ac.jp', 'ad.jp', 'co.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp', 'ne.jp', 'or.jp',
            'ac.kr', 'co.kr', 'go.kr', 'ne.kr', 'or.kr', 're.kr',
            'com.sg', 'net.sg', 'org.sg', 'per.sg', 'edu.sg', 'gov.sg',
            'ac.za', 'co.za', 'gov.za', 'net.za', 'org.za', 'web.za',
            
            # Generic compound TLDs
            'com.ar', 'net.ar', 'org.ar', 'gov.ar', 'int.ar', 'mil.ar',
            'com.mx', 'net.mx', 'org.mx', 'edu.mx', 'gob.mx',
            'com.ru', 'net.ru', 'org.ru', 'pp.ru',
            'com.tr', 'net.tr', 'org.tr', 'gen.tr', 'biz.tr', 'info.tr',
            'com.tw', 'net.tw', 'org.tw', 'idv.tw',
            'com.hk', 'net.hk', 'org.hk', 'idv.hk',
            'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
            'com.ph', 'net.ph', 'org.ph', 'mil.ph', 'ngo.ph', 'gov.ph',
            'com.sa', 'net.sa', 'org.sa', 'edu.sa', 'gov.sa',
            'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua',
            
            # Cloud/Platform variants
            'appspot.com', 'herokuapp.com', 'cloudapp.net', 'azurewebsites.net',
            'amazonaws.com', 'elasticbeanstalk.com', 'digitaloceanspaces.com',
            'firebaseapp.com', 'netlify.app', 'vercel.app', 'pages.dev',
            'github.io', 'gitlab.io', 'bitbucket.io', 'cloudfront.net',
            
            # Educational variants
            'edu.au', 'edu.cn', 'edu.hk', 'edu.in', 'edu.my', 'edu.ph', 'edu.sg', 'edu.tw',
            'ac.uk', 'ac.nz', 'ac.jp', 'ac.kr', 'ac.cn', 'ac.in',
            
            # Government variants
            'gov.uk', 'gov.au', 'gov.cn', 'gov.in', 'gov.my', 'gov.ph', 'gov.sg',
            'gob.mx', 'gouv.fr', 'gov.br', 'gov.il', 'gov.ru', 'gov.za',
            
            # Organization variants
            'org.uk', 'org.au', 'org.nz', 'org.my', 'org.ph', 'org.sg',
            'or.jp', 'or.kr', 'or.at',
            
            # Network variants
            'net.uk', 'net.au', 'net.nz', 'net.my', 'net.ph', 'net.sg',
            'ne.jp', 'ne.kr',
            
            # Business variants
            'biz.tr', 'biz.my', 'biz.ph', 'biz.sg',
            'co.at', 'co.nz', 'co.jp', 'co.kr', 'co.uk',
            'com.au', 'com.br', 'com.cn', 'com.hk', 'com.my', 'com.ph', 'com.sg', 'com.tw',
            
            # Personal variants
            'id.au', 'idv.tw', 'me.uk', 'per.sg', 'pp.ru',
            
            # Professional variants
            'pro.br', 'pro.ec', 'pro.th',
            
            # Educational/Research
            'edu.au', 'edu.hk', 'edu.my', 'edu.ph', 'edu.sg', 'edu.tw',
            'ac.il', 'ac.nz', 'ac.jp', 'ac.kr', 'ac.cn', 'ac.in',
            
            # Military
            'mil.tr', 'mil.ph', 'mil.br',
            
            # International
            'int.tj', 'int.bo', 'int.ci', 'int.co', 'int.la', 'int.mu', 'int.na', 'int.ni', 'int.pa', 'int.pe', 'int.tt', 'int.uz', 'int.ve',
            
            # Special use
            'dev.azure.com', 'visualstudio.com', 'live.com', 'outlook.com', 'hotmail.com',
            'yahoo.com', 'aol.com', 'protonmail.com', 'gmail.com',
            'yandex.ru', 'mail.ru', 'bk.ru', 'list.ru', 'inbox.ru',
        }

    def load_exclude_domains(self) -> Set[str]:
        """Load domains to exclude"""
        excludes = {
            # GitHub
            'github.com', 'githubusercontent.com', 'github.io', 'githubassets.com',
            'githubapp.com', 'github.dev', 'githubpreview.dev', 'githubcopilot.com',
            
            # Local/Test
            'localhost', 'local', 'localhost.localdomain', 'localdomain',
            'example.com', 'example.org', 'example.net', 'example.edu',
            'test.com', 'test.org', 'test.net', 'test.local', 'testing.com',
            'domain.com', 'domain.org', 'domain.net',
            'yourdomain.com', 'mydomain.com', 'somedomain.com',
            'company.com', 'organization.org', 'organisation.org',
            
            # Common services (but we'll keep them for potential targets)
            # 'google.com', 'facebook.com', 'twitter.com', etc - removed from exclude
            # as these might be targets for bug bounty
            
            # Reserved domains (RFC 2606)
            'example.com', 'example.net', 'example.org',
            'invalid', 'localhost', 'test',
            
            # Development domains
            'dev.local', 'app.local', 'api.local', 'web.local',
            'docker.localhost', 'vagrant.local', 'kubernetes.local',
            'minikube.local', 'k8s.local',
            
            # Documentation domains
            'docs.example.com', 'api.example.com', 'dev.example.com',
            
            # Internal networks
            '.internal', '.intranet', '.corp', '.private', '.lan',
        }
        
        # Try to load from file if exists
        if os.path.exists('exclude_domains.txt'):
            try:
                with open('exclude_domains.txt', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            excludes.add(line.lower())
            except:
                pass
        
        return excludes

    def load_private_ip_ranges(self) -> List[tuple]:
        """Load private and reserved IP ranges"""
        return [
            # Class A private
            (10, 0, 0, 0, 10, 255, 255, 255),
            
            # Class B private
            (172, 16, 0, 0, 172, 31, 255, 255),
            
            # Class C private
            (192, 168, 0, 0, 192, 168, 255, 255),
            
            # Localhost
            (127, 0, 0, 0, 127, 255, 255, 255),
            
            # Link-local
            (169, 254, 0, 0, 169, 254, 255, 255),
            
            # Zero config / APIPA
            (0, 0, 0, 0, 0, 255, 255, 255),
            
            # Broadcast
            (255, 255, 255, 255, 255, 255, 255, 255),
            
            # Multicast
            (224, 0, 0, 0, 239, 255, 255, 255),
            
            # Reserved (future use)
            (240, 0, 0, 0, 255, 255, 255, 254),
            
            # Documentation (TEST-NET)
            (192, 0, 2, 0, 192, 0, 2, 255),
            (198, 51, 100, 0, 198, 51, 100, 255),
            (203, 0, 113, 0, 203, 0, 113, 255),
            
            # Carrier-grade NAT
            (100, 64, 0, 0, 100, 127, 255, 255),
            
            # Benchmarking
            (198, 18, 0, 0, 198, 19, 255, 255),
            
            # Reserved by IANA
            (192, 0, 0, 0, 192, 0, 0, 255),
            (192, 0, 0, 0, 223, 255, 255, 255),
            (240, 0, 0, 0, 255, 255, 255, 254),
        ]

    def init_stats(self) -> Dict:
        """Initialize statistics"""
        return {
            'total_events': 0,
            'total_bytes': 0,
            'domains_found': 0,
            'ips_found': 0,
            'subdomains_found': 0,
            'urls_found': 0,
            'emails_found': 0,
            'start_time': time.time(),
            'by_source': defaultdict(int),
            'by_tld': defaultdict(int),
            'by_hour': defaultdict(int),
            'by_date': defaultdict(int),
            'errors': defaultdict(int),
            'dns_resolutions': 0,
            'dns_failures': 0,
            'api_calls': 0,
        }

    def init_output_files(self):
        """Initialize output files with headers"""
        files = {
            self.domains_output: ['# Domains extracted from GH Archive', '# Format: domain', '# Generated: ' + datetime.now().isoformat()],
            self.ips_output: ['# IPs extracted from GH Archive', '# Format: ip', '# Generated: ' + datetime.now().isoformat()],
            'subdomains.txt': ['# Subdomains extracted from GH Archive', '# Format: subdomain', '# Generated: ' + datetime.now().isoformat()],
            'urls.txt': ['# URLs extracted from GH Archive', '# Format: url', '# Generated: ' + datetime.now().isoformat()],
            'emails.txt': ['# Emails extracted from GH Archive', '# Format: email', '# Generated: ' + datetime.now().isoformat()],
            'stats.json': ['{}'],  # Will be updated at end
        }
        
        for filename, headers in files.items():
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    for header in headers:
                        f.write(f"# {header}\n")
            except:
                pass

    def extract_main_domain(self, domain: str) -> str:
        """Extract main domain from subdomain"""
        if not domain:
            return domain
        
        domain = domain.lower().strip().rstrip('.')
        parts = domain.split('.')
        
        # Check for IP address
        if self.is_valid_ip(domain):
            return domain
        
        # Check compound TLDs first
        if len(parts) >= 3:
            for i in range(len(parts) - 1, 0, -1):
                potential_tld = '.'.join(parts[i:])
                if potential_tld in self.compound_tlds:
                    return '.'.join(parts[i-1:])
        
        # Regular domain - return domain as-is (don't reduce to just TLD+1)
        # We want to keep the full domain for better targeting
        return domain

    def is_valid_domain(self, domain: str) -> bool:
        """Enhanced domain validation"""
        if not domain or len(domain) > 253:
            return False
        
        domain = domain.lower().strip().rstrip('.')
        
        # Must contain at least one dot
        if '.' not in domain:
            return False
        
        # Check if IP address (valid but not domain)
        if self.is_valid_ip(domain):
            return False
        
        # Check if in exclude list
        if domain in self.exclude_domains:
            return False
        
        # Check for invalid characters
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
        
        # No consecutive dots or hyphens
        if '..' in domain or '--' in domain or '.-' in domain or '-.' in domain:
            return False
        
        parts = domain.split('.')
        
        # Check TLD is valid
        tld = parts[-1]
        if tld not in self.valid_tlds:
            return False
        
        # Validate each part
        for part in parts:
            if not part:
                return False
            if len(part) > 63:
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', part):
                return False
        
        return True

    def is_valid_ip(self, ip: str) -> bool:
        """Enhanced IPv4 validation with private range exclusion"""
        # Check IPv6 first
        if ':' in ip:
            return self.is_valid_ipv6(ip)
        
        # IPv4 validation
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False
            
            if not all(0 <= p <= 255 for p in parts):
                return False
            
            # Check private/reserved ranges
            for start_range in self.private_ip_ranges:
                if (start_range[0] <= parts[0] <= start_range[4] and
                    start_range[1] <= parts[1] <= start_range[5] and
                    start_range[2] <= parts[2] <= start_range[6] and
                    start_range[3] <= parts[3] <= start_range[7]):
                    return False
            
            return True
        except (ValueError, IndexError):
            return False

    def is_valid_ipv6(self, ip: str) -> bool:
        """Validate IPv6 address"""
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            # Exclude localhost and private IPv6
            if ip.startswith('::1') or ip.startswith('fc') or ip.startswith('fd'):
                return False
            return True
        except:
            return False

    def extract_domains_from_text(self, text: str) -> Set[str]:
        """Extract ALL possible domains from text"""
        if not text or len(text) > 10**6:  # Limit text size
            return set()
        
        domains = set()
        
        # Extract from emails
        for email_domain in self.email_pattern.findall(text):
            domains.add(email_domain)
        
        # Extract from URLs
        for url_domain in self.url_pattern.findall(text):
            domains.add(url_domain)
        
        # Extract general domains
        for domain_match in self.domain_pattern.finditer(text):
            full_domain = domain_match.group(1)
            tld = domain_match.group(2)
            if tld in self.valid_tlds:
                domains.add(full_domain)
        
        # Extract API subdomains
        for api_domain in self.api_pattern.findall(text):
            domains.add(api_domain)
        
        # Extract CDN subdomains
        for cdn_domain in self.cdn_pattern.findall(text):
            domains.add(cdn_domain)
        
        return domains

    def extract_subdomains_from_text(self, text: str) -> Set[str]:
        """Extract subdomains from text"""
        if not text:
            return set()
        
        subdomains = set()
        for subdomain in self.subdomain_pattern.findall(text):
            if self.is_valid_domain(subdomain):
                subdomains.add(subdomain)
        
        return subdomains

    def extract_ips_from_text(self, text: str) -> Set[str]:
        """Extract IPv4 and IPv6 addresses"""
        if not text:
            return set()
        
        ips = set()
        
        # IPv4
        for ip in self.ipv4_pattern.findall(text):
            if self.is_valid_ip(ip):
                ips.add(ip)
        
        # IPv6
        for ipv6 in self.ipv6_pattern.findall(text):
            if ipv6 and self.is_valid_ip(ipv6):
                ips.add(ipv6)
        
        return ips

    def resolve_domain(self, domain: str) -> Set[str]:
        """Resolve domain to IPs (with caching)"""
        with self.dns_cache_lock:
            if domain in self.dns_cache:
                return self.dns_cache[domain]
        
        ips = set()
        try:
            # Try A records
            answers = dns.resolver.resolve(domain, 'A', lifetime=5)
            for rdata in answers:
                ip = str(rdata)
                if self.is_valid_ip(ip):
                    ips.add(ip)
                    self.stats['dns_resolutions'] += 1
            
            # Try AAAA records
            try:
                answers_aaaa = dns.resolver.resolve(domain, 'AAAA', lifetime=5)
                for rdata in answers_aaaa:
                    ip = str(rdata)
                    if self.is_valid_ip(ip):
                        ips.add(ip)
                        self.stats['dns_resolutions'] += 1
            except:
                pass
            
            with self.dns_cache_lock:
                self.dns_cache[domain] = ips
        except:
            self.stats['dns_failures'] += 1
        
        return ips

    def save_item(self, item: str, item_type: str):
        """Save item to appropriate file"""
        filename_map = {
            'domain': self.domains_output,
            'ip': self.ips_output,
            'subdomain': 'subdomains.txt',
            'url': 'urls.txt',
            'email': 'emails.txt',
        }
        
        if item_type in filename_map:
            filename = filename_map[item_type]
            try:
                with open(filename, 'a', encoding='utf-8') as f:
                    f.write(f"{item}\n")
            except:
                pass

    def process_event(self, event: dict):
        """Enhanced event processing with more sources"""
        try:
            event_type = event.get('type', '')
            self.stats['by_source'][event_type] += 1
            
            # Process actor info
            actor = event.get('actor', {})
            if actor:
                # Actor login might contain domain
                login = actor.get('login', '')
                if '.' in login and '@' not in login:
                    domains = self.extract_domains_from_text(login)
                    self.process_domains(domains, 'actor_login')
                
                # Actor URL
                url = actor.get('url', '')
                if url:
                    domains = self.extract_domains_from_text(url)
                    self.process_domains(domains, 'actor_url')
            
            # Process repo info
            repo = event.get('repo', {})
            if repo:
                # Repo name might contain domain
                name = repo.get('name', '')
                if '/' in name:
                    owner, _ = name.split('/', 1)
                    if '.' in owner:
                        domains = self.extract_domains_from_text(owner)
                        self.process_domains(domains, 'repo_owner')
                
                # Repo URL
                url = repo.get('url', '')
                if url:
                    domains = self.extract_domains_from_text(url)
                    self.process_domains(domains, 'repo_url')
            
            # Process org info
            org = event.get('org', {})
            if org:
                login = org.get('login', '')
                if '.' in login:
                    domains = self.extract_domains_from_text(login)
                    self.process_domains(domains, 'org_login')
            
            # Process payload
            payload = event.get('payload', {})
            
            # Push events (commits)
            if event_type == 'PushEvent':
                commits = payload.get('commits', [])
                for commit in commits:
                    # Author email
                    author = commit.get('author', {})
                    if author:
                        email = author.get('email', '')
                        if email and '@' in email:
                            domains = self.extract_domains_from_text(email)
                            self.process_domains(domains, 'author_email')
                            self.process_emails({email}, 'author_email')
                    
                    # Committer email
                    committer = commit.get('committer', {})
                    if committer:
                        email = committer.get('email', '')
                        if email and '@' in email:
                            domains = self.extract_domains_from_text(email)
                            self.process_domains(domains, 'committer_email')
                            self.process_emails({email}, 'committer_email')
                    
                    # Commit message
                    message = commit.get('message', '')
                    if message:
                        domains = self.extract_domains_from_text(message)
                        self.process_domains(domains, 'commit_message')
                        
                        ips = self.extract_ips_from_text(message)
                        self.process_ips(ips, 'commit_message')
                        
                        urls = self.extract_urls_from_text(message)
                        self.process_urls(urls, 'commit_message')
                        
                        subdomains = self.extract_subdomains_from_text(message)
                        self.process_subdomains(subdomains, 'commit_message')
                    
                    # Commit URL
                    url = commit.get('url', '')
                    if url:
                        domains = self.extract_domains_from_text(url)
                        self.process_domains(domains, 'commit_url')
            
            # Issue events
            elif event_type in ['IssuesEvent', 'PullRequestEvent']:
                if event_type == 'IssuesEvent':
                    issue = payload.get('issue', {})
                else:
                    issue = payload.get('pull_request', {})
                
                if issue:
                    # Issue body
                    body = issue.get('body', '')
                    if body:
                        domains = self.extract_domains_from_text(body)
                        self.process_domains(domains, 'issue_body')
                        
                        ips = self.extract_ips_from_text(body)
                        self.process_ips(ips, 'issue_body')
                        
                        urls = self.extract_urls_from_text(body)
                        self.process_urls(urls, 'issue_body')
                        
                        subdomains = self.extract_subdomains_from_text(body)
                        self.process_subdomains(subdomains, 'issue_body')
                    
                    # Issue title
                    title = issue.get('title', '')
                    if title:
                        domains = self.extract_domains_from_text(title)
                        self.process_domains(domains, 'issue_title')
                        
                        ips = self.extract_ips_from_text(title)
                        self.process_ips(ips, 'issue_title')
                    
                    # Issue URL
                    url = issue.get('url', '')
                    if url:
                        domains = self.extract_domains_from_text(url)
                        self.process_domains(domains, 'issue_url')
                    
                    # User info
                    user = issue.get('user', {})
                    if user:
                        email = user.get('email', '')
                        if email and '@' in email:
                            domains = self.extract_domains_from_text(email)
                            self.process_domains(domains, 'issue_user_email')
                            self.process_emails({email}, 'issue_user_email')
                        
                        url = user.get('url', '')
                        if url:
                            domains = self.extract_domains_from_text(url)
                            self.process_domains(domains, 'issue_user_url')
            
            # Comment events
            elif event_type == 'IssueCommentEvent':
                comment = payload.get('comment', {})
                if comment:
                    body = comment.get('body', '')
                    if body:
                        domains = self.extract_domains_from_text(body)
                        self.process_domains(domains, 'comment_body')
                        
                        ips = self.extract_ips_from_text(body)
                        self.process_ips(ips, 'comment_body')
                        
                        urls = self.extract_urls_from_text(body)
                        self.process_urls(urls, 'comment_body')
                        
                        subdomains = self.extract_subdomains_from_text(body)
                        self.process_subdomains(subdomains, 'comment_body')
                    
                    url = comment.get('url', '')
                    if url:
                        domains = self.extract_domains_from_text(url)
                        self.process_domains(domains, 'comment_url')
            
            # Release events
            elif event_type == 'ReleaseEvent':
                release = payload.get('release', {})
                if release:
                    body = release.get('body', '')
                    if body:
                        domains = self.extract_domains_from_text(body)
                        self.process_domains(domains, 'release_body')
                        
                        ips = self.extract_ips_from_text(body)
                        self.process_ips(ips, 'release_body')
                        
                        urls = self.extract_urls_from_text(body)
                        self.process_urls(urls, 'release_body')
                    
                    url = release.get('url', '')
                    if url:
                        domains = self.extract_domains_from_text(url)
                        self.process_domains(domains, 'release_url')
                    
                    # Release assets
                    assets = release.get('assets', [])
                    for asset in assets:
                        name = asset.get('name', '')
                        if '.' in name:
                            domains = self.extract_domains_from_text(name)
                            self.process_domains(domains, 'release_asset')
                        
                        url = asset.get('url', '')
                        if url:
                            domains = self.extract_domains_from_text(url)
                            self.process_domains(domains, 'release_asset_url')
            
            # Fork events
            elif event_type == 'ForkEvent':
                forkee = payload.get('forkee', {})
                if forkee:
                    url = forkee.get('url', '')
                    if url:
                        domains = self.extract_domains_from_text(url)
                        self.process_domains(domains, 'fork_url')
            
            # Watch events (stars)
            elif event_type == 'WatchEvent':
                # Just track for stats
                pass
            
            # Any other event type
            else:
                # Try to extract from any string fields
                for key, value in event.items():
                    if isinstance(value, str) and len(value) < 10000:
                        domains = self.extract_domains_from_text(value)
                        self.process_domains(domains, f'generic_{key}')
                        
                        ips = self.extract_ips_from_text(value)
                        self.process_ips(ips, f'generic_{key}')
        
        except Exception as e:
            self.stats['errors']['processing'] += 1

    def extract_urls_from_text(self, text: str) -> Set[str]:
        """Extract full URLs from text"""
        if not text:
            return set()
        
        url_pattern = re.compile(
            r'https?://[^\s<>"\'{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        return set(url_pattern.findall(text))

    def process_domains(self, domains: Set[str], source: str):
        """Process and save domains"""
        for domain in domains:
            if self.is_valid_domain(domain):
                main_domain = self.extract_main_domain(domain)
                with self.domains_lock:
                    if main_domain not in self.domains:
                        self.domains.add(main_domain)
                        self.save_item(main_domain, 'domain')
                        self.stats['domains_found'] += 1
                        self.stats['by_source'][source] += 1
                        
                        # Update TLD stats
                        tld = main_domain.split('.')[-1]
                        self.stats['by_tld'][tld] += 1
                        
                        print(f"{Colors.GREEN}[+] {main_domain}{Colors.RESET} {Colors.DIM}({source}){Colors.RESET}")
                        
                        # Try DNS resolution for new domains
                        if len(self.domains) % 100 == 0:
                            threading.Thread(target=self.resolve_domain, args=(main_domain,)).start()

    def process_ips(self, ips: Set[str], source: str):
        """Process and save IPs"""
        for ip in ips:
            if self.is_valid_ip(ip):
                with self.ips_lock:
                    if ip not in self.ips:
                        self.ips.add(ip)
                        self.save_item(ip, 'ip')
                        self.stats['ips_found'] += 1
                        self.stats['by_source'][source] += 1
                        print(f"{Colors.CYAN}[+] {ip}{Colors.RESET} {Colors.DIM}({source}){Colors.RESET}")

    def process_subdomains(self, subdomains: Set[str], source: str):
        """Process and save subdomains"""
        for subdomain in subdomains:
            if self.is_valid_domain(subdomain):
                with self.subdomains_lock:
                    if subdomain not in self.subdomains:
                        self.subdomains.add(subdomain)
                        self.save_item(subdomain, 'subdomain')
                        self.stats['subdomains_found'] += 1
                        self.stats['by_source'][source] += 1
                        print(f"{Colors.YELLOW}[+] {subdomain}{Colors.RESET} {Colors.DIM}({source}){Colors.RESET}")

    def process_urls(self, urls: Set[str], source: str):
        """Process and save URLs"""
        for url in urls:
            with self.urls_lock:
                if url not in self.urls:
                    self.urls.add(url)
                    self.save_item(url, 'url')
                    self.stats['urls_found'] += 1
                    self.stats['by_source'][source] += 1

    def process_emails(self, emails: Set[str], source: str):
        """Process and save emails"""
        for email in emails:
            with self.emails_lock:
                if email not in self.emails:
                    self.emails.add(email)
                    self.save_item(email, 'email')
                    self.stats['emails_found'] += 1
                    self.stats['by_source'][source] += 1

    def fetch_and_process_hour(self, date: datetime, hour: int, base_url: str):
        """Fetch and process one hour from specific base URL"""
        url = f"{base_url}/{date.strftime('%Y-%m-%d')}-{hour}.json.gz"
        
        hour_key = f"{date.strftime('%Y-%m-%d')}_{hour:02d}"
        self.stats['by_hour'][hour_key] += 1
        
        print(f"\n{Colors.CYAN}[{datetime.now().strftime('%H:%M:%S')}] ? Fetching {url}{Colors.RESET}")
        
        for attempt in range(3):  # Retry up to 3 times
            try:
                response = self.session.get(url, timeout=60, stream=True)
                if response.status_code == 200:
                    events_count = 0
                    bytes_count = 0
                    initial_domains = len(self.domains)
                    initial_ips = len(self.ips)
                    
                    content = response.content
                    bytes_count = len(content)
                    self.stats['total_bytes'] += bytes_count
                    
                    with gzip.GzipFile(fileobj=io.BytesIO(content)) as f:
                        for line in f:
                            try:
                                event = json.loads(line.decode('utf-8', errors='ignore'))
                                self.stats['total_events'] += 1
                                events_count += 1
                                self.process_event(event)
                            except:
                                self.stats['errors']['json_decode'] += 1
                                continue
                    
                    new_domains = len(self.domains) - initial_domains
                    new_ips = len(self.ips) - initial_ips
                    
                    # Update date stats
                    date_str = date.strftime('%Y-%m-%d')
                    self.stats['by_date'][date_str] += events_count
                    
                    print(f"{Colors.BLUE}[{datetime.now().strftime('%H:%M:%S')}] ? Hour {hour:02d}: "
                          f"Events {events_count:,}, +{new_domains} domains, +{new_ips} IPs "
                          f"(Total: {len(self.domains):,} domains, {len(self.ips):,} IPs){Colors.RESET}")
                    
                    # Show rate
                    elapsed = time.time() - self.stats['start_time']
                    rate = self.stats['total_events'] / elapsed if elapsed > 0 else 0
                    print(f"{Colors.DIM}Rate: {rate:.0f} events/sec, "
                          f"Memory: {len(self.domains):,} domains, {len(self.ips):,} IPs{Colors.RESET}")
                    
                    return True
                    
                elif response.status_code == 404:
                    # File not found, try next base URL
                    return False
                else:
                    print(f"{Colors.RED}[ERROR] HTTP {response.status_code}{Colors.RESET}")
                    time.sleep(2 ** attempt)  # Exponential backoff
                    
            except Exception as e:
                print(f"{Colors.RED}[ERROR] Attempt {attempt + 1}: {str(e)[:50]}{Colors.RESET}")
                time.sleep(2 ** attempt)
        
        return False

    def grab_daterange(self, start_date: datetime, end_date: datetime, threads: int = 3):
        """Grab from date range with multiple threads and base URLs"""
        current_date = start_date
        
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}  🚀 DOMAIN & IP GRABBING ULTIMATE EDITION{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*80}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}Start Date: {Colors.CYAN}{start_date.strftime('%Y-%m-%d')}{Colors.RESET}")
        print(f"{Colors.WHITE}End Date:   {Colors.CYAN}{end_date.strftime('%Y-%m-%d')}{Colors.RESET}")
        print(f"{Colors.WHITE}Base URLs:  {Colors.CYAN}{len(self.base_urls)}{Colors.RESET}")
        print(f"{Colors.WHITE}Threads:    {Colors.CYAN}{threads}{Colors.RESET}")
        print(f"{Colors.WHITE}Valid TLDs: {Colors.CYAN}{len(self.valid_tlds):,}{Colors.RESET}")
        print(f"{Colors.WHITE}Output:     {Colors.CYAN}{self.domains_output}, {self.ips_output}{Colors.RESET}\n")
        
        total_hours = 0
        while current_date <= end_date:
            total_hours += 24
            current_date += timedelta(days=1)
        
        print(f"{Colors.YELLOW}Total hours to process: {total_hours:,}{Colors.RESET}\n")
        
        confirm = input(f"{Colors.MAGENTA}Continue? (yes/no): {Colors.RESET}")
        if confirm.lower() not in ['yes', 'y']:
            return
        
        current_date = start_date
        processed_hours = 0
        
        try:
            while current_date <= end_date and self.running:
                date_str = current_date.strftime('%Y-%m-%d')
                print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.GREEN}  📅 {current_date.strftime('%A, %B %d, %Y')}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}")
                
                # Process hours in parallel
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = []
                    for hour in range(24):
                        for base_url in self.base_urls:
                            future = executor.submit(
                                self.fetch_and_process_hour, 
                                current_date, 
                                hour, 
                                base_url
                            )
                            futures.append(future)
                            processed_hours += 1
                            
                            # Show progress
                            progress = (processed_hours / total_hours) * 100
                            print(f"{Colors.DIM}Progress: {progress:.1f}% ({processed_hours}/{total_hours} hours){Colors.RESET}")
                    
                    # Wait for all hours to complete
                    for future in as_completed(futures):
                        try:
                            future.result(timeout=300)
                        except Exception as e:
                            self.stats['errors']['thread'] += 1
                
                current_date += timedelta(days=1)
                
                # Auto-save stats every day
                self.save_stats()
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⚠️ Interrupted by user{Colors.RESET}")
            self.running = False
        
        finally:
            self.print_stats()
            self.save_stats()
            
            # Final DNS resolution for new domains
            print(f"\n{Colors.CYAN}Resolving domains to IPs...{Colors.RESET}")
            domains_list = list(self.domains)[-100:]  # Last 100 domains
            for domain in domains_list:
                ips = self.resolve_domain(domain)
                self.process_ips(ips, 'dns_resolution')

    def save_stats(self):
        """Save statistics to file"""
        stats = dict(self.stats)
        stats['domains_count'] = len(self.domains)
        stats['ips_count'] = len(self.ips)
        stats['subdomains_count'] = len(self.subdomains)
        stats['urls_count'] = len(self.urls)
        stats['emails_count'] = len(self.emails)
        stats['elapsed_time'] = time.time() - self.stats['start_time']
        stats['dns_cache_size'] = len(self.dns_cache)
        stats['by_source'] = dict(self.stats['by_source'])
        stats['by_tld'] = dict(self.stats['by_tld'])
        stats['by_hour'] = dict(self.stats['by_hour'])
        stats['by_date'] = dict(self.stats['by_date'])
        stats['errors'] = dict(self.stats['errors'])
        
        try:
            with open(self.stats_output, 'w') as f:
                json.dump(stats, f, indent=2, default=str)
        except:
            pass

    def print_stats(self):
        """Print comprehensive statistics"""
        elapsed = time.time() - self.stats['start_time']
        hours = elapsed / 3600
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}  🎯 EXTRACTION COMPLETE!{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}\n")
        
        # Summary
        print(f"{Colors.WHITE}📊 SUMMARY:{Colors.RESET}")
        print(f"{Colors.WHITE}  ├─ Total Events:    {Colors.CYAN}{self.stats['total_events']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}  ├─ Total Data:      {Colors.CYAN}{self.stats['total_bytes'] / (1024**3):.2f} GB{Colors.RESET}")
        print(f"{Colors.WHITE}  ├─ Unique Domains:  {Colors.GREEN}{len(self.domains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}  ├─ Unique Subdomains:{Colors.GREEN}{len(self.subdomains):,}{Colors.RESET}")
        print(f"{Colors.WHITE}  ├─ Unique IPs:      {Colors.GREEN}{len(self.ips):,}{Colors.RESET}")
        print(f"{Colors.WHITE}  ├─ Unique URLs:     {Colors.GREEN}{len(self.urls):,}{Colors.RESET}")
        print(f"{Colors.WHITE}  ├─ Unique Emails:   {Colors.GREEN}{len(self.emails):,}{Colors.RESET}")
        print(f"{Colors.WHITE}  ├─ DNS Resolutions: {Colors.CYAN}{self.stats['dns_resolutions']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}  ├─ DNS Failures:    {Colors.RED}{self.stats['dns_failures']:,}{Colors.RESET}")
        print(f"{Colors.WHITE}  └─ Time Elapsed:    {Colors.CYAN}{hours:.2f} hours{Colors.RESET}\n")
        
        # Top sources
        print(f"{Colors.WHITE}📈 TOP SOURCES:{Colors.RESET}")
        sorted_sources = sorted(self.stats['by_source'].items(), key=lambda x: x[1], reverse=True)[:10]
        for source, count in sorted_sources:
            print(f"{Colors.WHITE}  ├─ {source}: {Colors.YELLOW}{count:,}{Colors.RESET}")
        
        # Top TLDs
        print(f"\n{Colors.WHITE}🌐 TOP TLDS:{Colors.RESET}")
        sorted_tlds = sorted(self.stats['by_tld'].items(), key=lambda x: x[1], reverse=True)[:10]
        for tld, count in sorted_tlds:
            print(f"{Colors.WHITE}  ├─ .{tld}: {Colors.YELLOW}{count:,}{Colors.RESET}")
        
        # Errors
        if self.stats['errors']:
            print(f"\n{Colors.RED}⚠️ ERRORS:{Colors.RESET}")
            for error_type, count in self.stats['errors'].items():
                print(f"{Colors.RED}  ├─ {error_type}: {count}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}\n")

    def signal_handler(self, sig, frame):
        """Handle interrupt signals"""
        print(f"\n{Colors.YELLOW}⚠️ Received signal {sig}, shutting down gracefully...{Colors.RESET}")
        self.running = False
        self.save_stats()
        sys.exit(0)

    def cleanup(self):
        """Cleanup on exit"""
        self.save_stats()
        self.session.close()

def main():
    parser = argparse.ArgumentParser(
        description="GH Archive Domain & IP Grabber - ULTIMATE EDITION",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 gh_grabber.py --start 2026-01-30 --end 2026-01-31 --threads 5
  python3 gh_grabber.py --start 2026-01-01 --end 2026-01-07 --domains custom_domains.txt
  python3 gh_grabber.py --hours 24 --threads 10  # Last 24 hours
        """
    )
    
    parser.add_argument('--start', type=str, default='2026-01-30', 
                       help='Start date (YYYY-MM-DD)')
    parser.add_argument('--end', type=str, default='2026-01-30', 
                       help='End date (YYYY-MM-DD)')
    parser.add_argument('--hours', type=int, default=None,
                       help='Process last N hours (overrides start/end)')
    parser.add_argument('--domains', type=str, default='domains.txt', 
                       help='Domains output file')
    parser.add_argument('--ips', type=str, default='ips.txt', 
                       help='IPs output file')
    parser.add_argument('--tlds', type=str, default=None,
                       help='Custom TLD file (one per line)')
    parser.add_argument('--threads', type=int, default=3,
                       help='Number of threads (default: 3)')
    parser.add_argument('--stats', type=str, default='stats.json',
                       help='Statistics output file')
    parser.add_argument('--no-dns', action='store_true',
                       help='Disable DNS resolution')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Calculate dates
    if args.hours:
        end_date = datetime.now()
        start_date = end_date - timedelta(hours=args.hours)
        print(f"{Colors.YELLOW}⏰ Processing last {args.hours} hours{Colors.RESET}")
    else:
        try:
            start_date = datetime.strptime(args.start, '%Y-%m-%d')
            end_date = datetime.strptime(args.end, '%Y-%m-%d')
        except ValueError:
            print(f"{Colors.RED}❌ Invalid date format. Use YYYY-MM-DD{Colors.RESET}")
            return
    
    # Validate dates
    if start_date > end_date:
        print(f"{Colors.RED}❌ Start date must be before end date{Colors.RESET}")
        return
    
    # Check if end date is in future
    if end_date > datetime.now():
        end_date = datetime.now()
        print(f"{Colors.YELLOW}⚠️ End date adjusted to today{Colors.RESET}")
    
    # Create grabber instance
    grabber = DomainIPGrabber(args.domains, args.ips, args.stats)
    
    # Override TLDs if custom file provided
    if args.tlds and os.path.exists(args.tlds):
        try:
            with open(args.tlds, 'r') as f:
                custom_tlds = {line.strip().lower() for line in f if line.strip()}
                grabber.valid_tlds.update(custom_tlds)
                print(f"{Colors.GREEN}✓ Added {len(custom_tlds)} custom TLDs{Colors.RESET}")
        except:
            print(f"{Colors.RED}❌ Failed to load custom TLDs{Colors.RESET}")
    
    # Disable DNS if requested
    if args.no_dns:
        grabber.resolve_domain = lambda x: set()
        print(f"{Colors.YELLOW}⚠️ DNS resolution disabled{Colors.RESET}")
    
    # Show configuration
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  🚀 GH ARCHIVE GRABBER - CONFIGURATION{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    print(f"{Colors.WHITE}📅 Date Range:     {Colors.CYAN}{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}{Colors.RESET}")
    print(f"{Colors.WHITE}📁 Domains Output: {Colors.CYAN}{args.domains}{Colors.RESET}")
    print(f"{Colors.WHITE}📁 IPs Output:     {Colors.CYAN}{args.ips}{Colors.RESET}")
    print(f"{Colors.WHITE}📊 Stats Output:   {Colors.CYAN}{args.stats}{Colors.RESET}")
    print(f"{Colors.WHITE}⚡ Threads:        {Colors.CYAN}{args.threads}{Colors.RESET}")
    print(f"{Colors.WHITE}🌐 Base URLs:      {Colors.CYAN}{len(grabber.base_urls)}{Colors.RESET}")
    print(f"{Colors.WHITE}🔤 Valid TLDs:     {Colors.CYAN}{len(grabber.valid_tlds):,}{Colors.RESET}")
    print(f"{Colors.WHITE}🚫 Exclude Domains: {Colors.CYAN}{len(grabber.exclude_domains):,}{Colors.RESET}")
    print(f"{Colors.WHITE}📊 Compound TLDs:  {Colors.CYAN}{len(grabber.compound_tlds):,}{Colors.RESET}")
    
    print(f"\n{Colors.YELLOW}💡 Tip: Press Ctrl+C to stop gracefully{Colors.RESET}\n")
    
    # Start grabbing
    grabber.grab_daterange(start_date, end_date, args.threads)
    
    # Final output
    print(f"\n{Colors.GREEN}✅ Done!{Colors.RESET}")
    print(f"{Colors.CYAN}Results saved to:{Colors.RESET}")
    print(f"  ├─ {args.domains}")
    print(f"  ├─ {args.ips}")
    print(f"  ├─ subdomains.txt")
    print(f"  ├─ urls.txt")
    print(f"  ├─ emails.txt")
    print(f"  └─ {args.stats}")

if __name__ == '__main__':
    main()
