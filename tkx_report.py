#!/usr/bin/env python3
"""
TKX Report Generator
"""
import json
import html
from datetime import datetime

def generate_html_report(scan_data: dict, output_file: str = "tkx_report.html"):
    """Generate HTML report"""
    html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>TKX Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .vuln {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .error {{ border-left: 5px solid #e74c3c; }}
        .time {{ border-left: 5px solid #f39c12; }}
        .union {{ border-left: 5px solid #27ae60; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>TKX Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Target:</strong> {html.escape(scan_data['scan_info']['target'])}</p>
        <p><strong>Scan Time:</strong> {scan_data['scan_info']['scan_time']}</p>
        <p><strong>Vulnerabilities Found:</strong> {scan_data['scan_info']['vulnerabilities_found']}</p>
    </div>
    
    <h2>Vulnerabilities</h2>
"""

    for i, vuln in enumerate(scan_data['vulnerabilities'], 1):
        vuln_class = {
            'error-based': 'error',
            'time-based': 'time', 
            'union-based': 'union'
        }.get(vuln['technique'], '')
        
        html_template += f"""
    <div class="vuln {vuln_class}">
        <h3>Vulnerability #{i}: {vuln['technique']}</h3>
        <p><strong>URL:</strong> {html.escape(vuln['url'])}</p>
        <p><strong>Parameter:</strong> {html.escape(vuln['parameter'])}</p>
        <p><strong>Payload:</strong> <code>{html.escape(vuln['payload'])}</code></p>
        <p><strong>Evidence:</strong> {html.escape(vuln['evidence'])}</p>
        <p><strong>Confidence:</strong> {vuln['confidence']}%</p>
    </div>
"""

    html_template += """
</body>
</html>
"""
    
    with open(output_file, 'w') as f:
        f.write(html_template)
    
    print(f"[+] HTML report generated: {output_file}")

# Example usage
if __name__ == "__main__":
    # Load scan results from JSON
    with open('scan_results.json') as f:
        scan_data = json.load(f)
    
    generate_html_report(scan_data)
