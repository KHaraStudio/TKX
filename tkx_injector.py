#!/usr/bin/env python3
from typing import List, Dict
"""
TKX Injector - Payload Execution Engine
"""
import requests
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode

class TKXInjector:
    """Payload injection and exploitation"""
    
    def __init__(self, session=None):
        self.session = session or requests.Session()
        
    def test_parameter(self, url: str, param: str, payloads: List[str]) -> Dict:
        """Test parameter with multiple payloads"""
        results = {
            'url': url,
            'parameter': param,
            'vulnerable': False,
            'technique': None,
            'payload': None,
            'evidence': None
        }
        
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        
        for payload in payloads:
            try:
                # Build test URL
                test_params = base_params.copy()
                test_params[param] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                # Send request
                start_time = time.time()
                response = self.session.get(
                    test_url,
                    params=test_params,
                    timeout=10,
                    verify=False
                )
                response_time = time.time() - start_time
                
                # Check response
                if self._is_vulnerable(response.text, response_time, payload):
                    results.update({
                        'vulnerable': True,
                        'payload': payload,
                        'technique': self._detect_technique(payload),
                        'evidence': self._get_evidence(response.text, response_time)
                    })
                    break
                    
            except Exception as e:
                continue
        
        return results
    
    def _is_vulnerable(self, response_text: str, response_time: float, 
                      payload: str) -> bool:
        """Determine if response indicates vulnerability"""
        
        # Check for SQL errors
        error_indicators = ['sql', 'syntax', 'mysql', 'postgresql', 'oracle', 'error']
        if any(indicator in response_text.lower() for indicator in error_indicators):
            return True
        
        # Check for time delay
        if response_time > 5 and any(x in payload.lower() for x in ['sleep', 'waitfor']):
            return True
        
        return False
    
    def _detect_technique(self, payload: str) -> str:
        """Detect injection technique from payload"""
        payload_lower = payload.lower()
        
        if 'sleep' in payload_lower or 'waitfor' in payload_lower:
            return 'time-based'
        elif 'union' in payload_lower:
            return 'union-based'
        elif 'or ' in payload_lower or 'and ' in payload_lower:
            return 'boolean-based'
        else:
            return 'error-based'
    
    def _get_evidence(self, response_text: str, response_time: float) -> str:
        """Extract evidence from response"""
        if response_time > 5:
            return f"Time delay: {response_time:.2f}s"
        
        # Extract first error line
        lines = response_text.split('\n')
        for line in lines:
            if any(word in line.lower() for word in ['error', 'warning', 'sql', 'syntax']):
                return line[:100]
        
        return "Pattern matched"
