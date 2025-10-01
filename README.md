DomIP Tool

A Python utility to resolve domains/URLs to their canonical hosts, fetch associated IP addresses, and provide WHOIS information for both domains and IPs. Useful for network reconnaissance, cybersecurity analysis, and IT auditing.

Features
  Resolve any domain or URL to its canonical hostname.
  Follow CNAME records (requires dnspython).
  Fetch all associated IP addresses (IPv4 & IPv6).
  WHOIS lookup for both domain and IP addresses.
  Output results in plain text or JSON format.

Optional --force-www to enforce www. prefix on hostnames.

Installation

  Clone the repository:
    git clone https://github.com/SOWNTHAR04/DomIP.git
    cd  DomIP


  Install dependencies:
     pip install dnspython python-whois
  
  Make sure the whois CLI is installed:
    # Linux
        sudo apt install whois

    # macOS
         brew install whois

Usage
  # Basic domain
    python3 simple_resolve_whois.py example.com

  # Force www prefix
    python3 simple_resolve_whois.py example.com --force-www

  # Output JSON
    python3 simple_resolve_whois.py example.com --json


Example Output (Plain Text):
      
      Domain WHOIS preview: Registrar: Example Corp | Creation Date: 2000-01-01 | ...
      example.com    93.184.216.34
      IP WHOIS: NetRange: 93.184.216.0 - 93.184.216.255 | Organization: Example Corp | ...

License
   This project is licensed under the MIT License.
