#!/usr/bin/env python3
"""
TKX - Improved CLI with better output
"""
import argparse
import json
import sys
import time
from typing import Dict
from tkx_scanner import TKXScanner

def banner():
    print("""
    \033[1;36m
    ████████╗██╗  ██╗██╗  ██╗
    ╚══██╔══╝██║ ██╔╝╚██╗██╔╝
       ██║   █████╔╝  ╚███╔╝ 
       ██║   ██╔═██╗  ██╔██╗ 
       ██║   ██║  ██╗██╔╝ ██╗
       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
    
    TKX - SQL Injection Scanner v1.1
    by KHara Xyra Taiz
    \033[0m
    """)

def print_vulnerability(vuln: Dict, index: int):
    """Print vulnerability in readable format"""
    colors = {
        'error-based': '\033[1;31m',  # Red
        'time-based': '\033[1;33m',   # Yellow
        'union-based': '\033[1;32m',  # Green
        'boolean-based': '\033[1;35m' # Purple
    }
    
    color = colors.get(vuln.get('technique', ''), '\033[1;37m')
    reset = '\033[0m'
    
    print(f"{color}════════ Vulnerability #{index} ════════{reset}")
    print(f"{color}• Technique:{reset} {vuln.get('technique', 'N/A')}")
    print(f"{color}• URL:{reset} {vuln.get('url', 'N/A')}")
    print(f"{color}• Parameter:{reset} {vuln.get('parameter', 'N/A')}")
    print(f"{color}• Payload:{reset} {vuln.get('payload', 'N/A')}")
    print(f"{color}• Evidence:{reset} {vuln.get('evidence', 'N/A')}")
    print(f"{color}• Confidence:{reset} {vuln.get('confidence', 0)}%")
    print(f"{color}• Status:{reset} {vuln.get('status', 'N/A')}")
    print(f"{color}• Response Time:{reset} {vuln.get('response_time', 'N/A')}")
    print()

def main():
    parser = argparse.ArgumentParser(description='TKX - SQL Injection Scanner')
    parser.add_argument('-u', '--url', help='Target URL', required=True)
    parser.add_argument('--no-crawl', action='store_true', help='Disable crawling')
    parser.add_argument('--output', choices=['text', 'json', 'simple'], default='text')
    parser.add_argument('--max-payloads', type=int, default=15, help='Max payloads per parameter')
    parser.add_argument('--timeout', type=int, default=30, help='Scan timeout in seconds')
    
    args = parser.parse_args()
    
    banner()
    
    print(f"\033[1;34m[*] Target:\033[0m {args.url}")
    print(f"\033[1;34m[*] Crawling:\033[0m {'Disabled' if args.no_crawl else 'Enabled'}")
    print(f"\033[1;34m[*] Max Payloads:\033[0m {args.max_payloads}")
    print(f"\033[1;34m[*] Timeout:\033[0m {args.timeout}s")
    print(f"\033[1;34m[*] Output format:\033[0m {args.output}")
    print()
    
    # Initialize scanner
    scanner = TKXScanner(args.url)
    
    # Perform scan with timeout
    start_time = time.time()
    
    try:
        vulnerabilities = scanner.full_scan(
            crawl=not args.no_crawl,
            max_payloads=args.max_payloads
        )
        
        scan_time = time.time() - start_time
        
        # Output results
        print(f"\n{'='*50}")
        print(f"\033[1;36mSCAN COMPLETED IN {scan_time:.1f} SECONDS\033[0m")
        print(f"{'='*50}")
        
        if args.output == 'json':
            result = {
                'scan_info': {
                    'target': args.url,
                    'scan_time': f"{scan_time:.2f}s",
                    'vulnerabilities_found': len(vulnerabilities)
                },
                'vulnerabilities': vulnerabilities
            }
            print(json.dumps(result, indent=2))
            
        elif args.output == 'simple':
            if vulnerabilities:
                print(f"\033[1;32m[+] Found {len(vulnerabilities)} vulnerabilities!\033[0m")
                for vuln in vulnerabilities:
                    print(f"- {vuln['technique']} on {vuln['parameter']}: {vuln['evidence']}")
            else:
                print("\033[1;33m[-] No vulnerabilities found\033[0m")
                
        else:  # text (default)
            if vulnerabilities:
                print(f"\033[1;32m[+] Found {len(vulnerabilities)} vulnerabilities!\033[0m\n")
                for i, vuln in enumerate(vulnerabilities, 1):
                    print_vulnerability(vuln, i)
                
                # Summary
                print(f"\033[1;36m{'='*50}\033[0m")
                print(f"\033[1;36mSUMMARY:\033[0m")
                techniques = {}
                for vuln in vulnerabilities:
                    tech = vuln.get('technique', 'unknown')
                    techniques[tech] = techniques.get(tech, 0) + 1
                
                for tech, count in techniques.items():
                    print(f"  {tech}: {count} vulnerabilities")
                print(f"\033[1;36mTotal: {len(vulnerabilities)} vulnerabilities found\033[0m")
                
            else:
                print("\033[1;33m[-] No vulnerabilities found\033[0m")
        
    except KeyboardInterrupt:
        print(f"\n\033[1;33m[!] Scan interrupted by user after {time.time()-start_time:.1f}s\033[0m")
    except Exception as e:
        print(f"\033[1;31m[!] Error: {str(e)}\033[0m")

if __name__ == '__main__':
    if len(sys.argv) == 1:
        banner()
        print("\033[1;37mUsage:\033[0m python tkx_cli.py -u <URL>")
        print("\033[1;37mExample:\033[0m python tkx_cli.py -u \"http://test.com/page?id=1\"")
        print("\033[1;37mOptions:\033[0m")
        print("  -u, --url URL        Target URL (required)")
        print("  --no-crawl           Disable URL crawling")
        print("  --output FORMAT      Output format: text, json, simple")
        print("  --max-payloads N     Max payloads per parameter (default: 15)")
        print("  --timeout N          Scan timeout in seconds (default: 30)")
    else:
        main()
