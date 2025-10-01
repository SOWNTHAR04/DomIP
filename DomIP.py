#!/usr/bin/env python3


from __future__ import annotations
import sys
import socket
import subprocess
import argparse
from urllib.parse import urlparse

# Optional dnspython for robust CNAME following
try:
    import dns.resolver, dns.name, dns.exception  # type: ignore
    DNSpython = True
except Exception:
    DNSpython = False

def normalize_host(raw: str) -> str | None:
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    return p.hostname

def follow_cname(host: str) -> str:
    """Return final name after following CNAME chain using dnspython if available."""
    if not DNSpython:
        return host
    try:
        resolver = dns.resolver.Resolver()
        current = dns.name.from_text(host)
        visited = set()
        while True:
            name_text = str(current).rstrip('.')
            if name_text in visited:
                break
            visited.add(name_text)
            try:
                ans = resolver.resolve(name_text, 'CNAME', lifetime=3.0)
                target = ans[0].target.to_text(omit_final_dot=True)
                current = dns.name.from_text(target)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                break
        return str(current).rstrip('.')
    except Exception:
        return host

def resolve_ips(host: str) -> list[str]:
    """Resolve both A and AAAA addresses using getaddrinfo; return deduped list."""
    ips: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips

def whois_preview(host: str, chars: int = 500) -> str:
    """Try system 'whois' first, fallback to python-whois module if installed."""
    try:
        p = subprocess.run(["whois", host], capture_output=True, text=True, timeout=10)
        text = p.stdout.strip()
        if text:
            return text[:chars].replace("\n", " | ")
    except Exception:
        pass
    try:
        import whois as w
        r = w.whois(host)
        return str(r)[:chars].replace("\n", " | ")
    except Exception:
        return "(WHOIS not available; install 'whois' CLI or 'python-whois')"

def whois_ip(ip: str, chars: int = 500) -> str:
    """Run WHOIS on an IP address."""
    try:
        p = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=10)
        text = p.stdout.strip()
        if text:
            return text[:chars].replace("\n", " | ")
    except Exception:
        return "(WHOIS for IP not available; install 'whois' CLI)"

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Resolve domain/URL -> canonical host -> IPs + WHOIS preview")
    parser.add_argument("input", help="domain or URL (e.g. example.com or https://example.com/path)")
    parser.add_argument("--force-www", action="store_true", help="force canonical host to have 'www.' prefix")
    parser.add_argument("--json", action="store_true", help="output as JSON instead of plain lines")
    args = parser.parse_args(argv)

    host = normalize_host(args.input)
    if not host:
        print("ERROR: could not parse hostname from input.", file=sys.stderr)
        return 2

    if args.force_www and not host.startswith("www."):
        host = "www." + host

    canonical = follow_cname(host)
    if args.force_www and not canonical.startswith("www."):
        canonical = "www." + canonical

    ips = resolve_ips(canonical)
    if not ips and canonical != host:
        ips = resolve_ips(host)

    domain_whois = whois_preview(canonical)

    # JSON output
    if args.json:
        import json
        ip_info = []
        for ip in ips:
            ip_info.append({
                "ip": ip,
                "whois": whois_ip(ip)
            })
        out = {
            "input": args.input,
            "hostname": host,
            "canonical": canonical,
            "ips": ip_info,
            "domain_whois_preview": domain_whois,
        }
        print(json.dumps(out, indent=2))
        return 0

    # Plain text output
    print(f"Domain WHOIS preview: {domain_whois}\n")
    if not ips:
        print(f"{canonical}\t(no IP resolved)")
        return 0

    for ip in ips:
        print(f"{canonical}\t{ip}")
        ip_whois_text = whois_ip(ip)
        print(f"IP WHOIS: {ip_whois_text}\n")

    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
