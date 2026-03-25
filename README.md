# whois-py

Pure-Python WHOIS lookup tool. Zero dependencies.

## Usage

```bash
python3 whois_py.py example.com        # Parsed WHOIS
python3 whois_py.py example.com --raw  # Raw response
python3 whois_py.py 8.8.8.8           # IP WHOIS (ARIN)
```

## Features

- Domain WHOIS with automatic referral following
- IP address WHOIS via ARIN
- Parsed output with key fields (registrar, dates, status, nameservers)
- 16+ TLD servers built-in, IANA fallback for unknown TLDs
- Zero dependencies — just Python 3 stdlib
