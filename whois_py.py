#!/usr/bin/env python3
"""whois-py — Pure-Python WHOIS lookup. Zero deps."""
import socket
import sys
import re

WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'io':  'whois.nic.io',
    'dev': 'whois.nic.google',
    'ai':  'whois.nic.ai',
    'app': 'whois.nic.google',
    'xyz': 'whois.nic.xyz',
    'me':  'whois.nic.me',
    'co':  'whois.nic.co',
    'us':  'whois.nic.us',
    'uk':  'whois.nic.uk',
    'de':  'whois.denic.de',
    'fr':  'whois.nic.fr',
    'jp':  'whois.jprs.jp',
    'info': 'whois.afilias.net',
}
IANA = 'whois.iana.org'

def whois_query(server: str, query: str, timeout: float = 10) -> str:
    """Send a WHOIS query and return the response."""
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + '\r\n').encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b''.join(chunks).decode('utf-8', errors='replace')

def get_whois_server(tld: str) -> str:
    """Get WHOIS server for a TLD, falling back to IANA."""
    if tld in WHOIS_SERVERS:
        return WHOIS_SERVERS[tld]
    # Ask IANA
    resp = whois_query(IANA, tld)
    m = re.search(r'whois:\s+(\S+)', resp)
    return m.group(1) if m else WHOIS_SERVERS.get(tld, IANA)

def lookup_domain(domain: str) -> str:
    """Full WHOIS lookup for a domain."""
    parts = domain.rstrip('.').split('.')
    tld = parts[-1].lower()
    server = get_whois_server(tld)
    result = whois_query(server, domain)
    
    # Follow referral if present (e.g., Verisign -> registrar)
    m = re.search(r'Registrar WHOIS Server:\s*(\S+)', result, re.IGNORECASE)
    if m:
        referral = m.group(1)
        try:
            result2 = whois_query(referral, domain)
            if len(result2) > 100:
                result = result2
        except Exception:
            pass
    
    return result

def lookup_ip(ip: str) -> str:
    """WHOIS lookup for an IP address."""
    return whois_query('whois.arin.net', f'n + {ip}')

def parse_key_fields(text: str) -> dict:
    """Extract common WHOIS fields."""
    fields = {}
    patterns = {
        'Domain': r'Domain Name:\s*(.+)',
        'Registrar': r'Registrar:\s*(.+)',
        'Created': r'Creat(?:ion|ed)\s*Date:\s*(.+)',
        'Expires': r'Expir(?:ation|y)\s*Date:\s*(.+)',
        'Updated': r'Updated?\s*Date:\s*(.+)',
        'Status': r'Domain Status:\s*(.+)',
        'Nameservers': r'Name Server:\s*(.+)',
    }
    for key, pat in patterns.items():
        matches = re.findall(pat, text, re.IGNORECASE)
        if matches:
            if key in ('Status', 'Nameservers'):
                fields[key] = [m.strip() for m in matches]
            else:
                fields[key] = matches[0].strip()
    return fields

def main():
    if len(sys.argv) < 2:
        print("Usage: whois-py <domain|ip> [--raw]")
        print("  whois-py example.com      — parsed WHOIS")
        print("  whois-py example.com --raw — raw WHOIS response")
        print("  whois-py 8.8.8.8          — IP WHOIS")
        sys.exit(1)
    
    target = sys.argv[1]
    raw = '--raw' in sys.argv
    
    # Detect IP vs domain
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)
    
    try:
        if is_ip:
            result = lookup_ip(target)
            print(result)
        else:
            result = lookup_domain(target)
            if raw:
                print(result)
            else:
                fields = parse_key_fields(result)
                if fields:
                    print(f"🔍 WHOIS: {target}")
                    print("=" * 40)
                    for k, v in fields.items():
                        if isinstance(v, list):
                            print(f"  {k}:")
                            for item in v[:5]:
                                print(f"    • {item}")
                        else:
                            print(f"  {k}: {v}")
                else:
                    print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
