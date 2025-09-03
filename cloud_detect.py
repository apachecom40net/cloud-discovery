import requests
import re
import ssl
import json
import sys
import socket
import argparse
from contextlib import closing
from collections import defaultdict

# Optional imports
try:
    import dns.resolver
    import dns.reversename
    HAVE_DNS = True
except Exception:
    HAVE_DNS = False

try:
    from ipwhois import IPWhois
    HAVE_IPWHOIS = True
except Exception:
    HAVE_IPWHOIS = False

import requests
requests.packages.urllib3.disable_warnings()  # quiet self-signed warnings


CNAME_HINTS = {
    # Core clouds
    r"\.cloudfront\.net$": ("AWS", "CloudFront"),
    r"\.amazonaws\.com$": ("AWS", "AWS-hosted"),
    r"\.elasticbeanstalk\.com$": ("AWS", "Elastic Beanstalk"),
    r"\.compute-1\.amazonaws\.com$": ("AWS", "EC2"),
    r"\.s3\.amazonaws\.com$": ("AWS", "S3"),

    r"\.azurewebsites\.net$": ("Azure", "App Service"),
    r"\.cloudapp\.net$": ("Azure", "Cloud Service"),
    r"\.blob\.core\.windows\.net$": ("Azure", "Blob Storage"),
    r"\.trafficmanager\.net$": ("Azure", "Traffic Manager"),
    r"\.azureedge\.net$": ("Azure", "CDN"),
    r"\.azurefd\.net$": ("Azure", "Front Door"),

    r"\.appspot\.com$": ("GCP", "App Engine"),
    r"\.googleusercontent\.com$": ("GCP", "GCP-hosted"),
    r"\.storage\.googleapis\.com$": ("GCP", "GCS"),
    r"\.gvt2\.com$": ("GCP", "GCP-edge"),

    # Major CDNs/hosts
    r"\.cdn\.cloudflare\.net$": ("Cloudflare", "CDN"),
    r"\.cloudflare\.net$": ("Cloudflare", "CDN"),
    r"\.fastly\.net$": ("Fastly", "CDN"),
    r"\.akamaiedge\.net$": ("Akamai", "CDN"),
    r"\.akamai\.net$": ("Akamai", "CDN"),
    r"\.akadns\.net$": ("Akamai", "DNS"),

    # Popular PaaS / JAMstack
    r"\.vercel\.app$": ("Vercel", "PaaS"),
    r"\.vercel-dns\.com$": ("Vercel", "DNS"),
    r"\.netlify\.app$": ("Netlify", "PaaS/CDN"),
    r"\.netlifyglobalcdn\.com$": ("Netlify", "CDN"),
    r"\.herokudns\.com$": ("Heroku", "DNS"),
    r"\.herokuapp\.com$": ("Heroku", "PaaS"),
    r"\.github\.io$": ("GitHub Pages", "Static hosting"),
    r"\.wpengine\.com$": ("WP Engine", "WordPress hosting"),
    r"\.render\.com$": ("Render", "PaaS"),
    r"\.fly\.dev$": ("Fly.io", "PaaS"),

    # Other clouds / VPS
    r"\.digitaloceanspaces\.com$": ("DigitalOcean", "Spaces"),
    r"\.digitalocean\.com$": ("DigitalOcean", "DO-hosted"),
    r"\.linodeusercontent\.com$": ("Linode/Akamai", "Linode"),
    r"\.ovh\.net$": ("OVHcloud", "OVH-hosted"),
    r"\.hetzner\.cloud$": ("Hetzner", "Hetzner Cloud"),
    r"\.oraclecloud\.com$": ("Oracle Cloud", "OCI"),
    r"\.alicdn\.com$": ("Alibaba Cloud", "CDN"),
    r"\.alicloud\.com$": ("Alibaba Cloud", "Cloud"),
    r"\.wixdns\.net$": ("Wix", "Website builder"),
    r"\.squarespace\.com$": ("Squarespace", "Website builder"),
}

ASN_HINTS = {
    "amazon": "AWS",
    "aws": "AWS",
    "google": "GCP",
    "microsoft": "Azure",
    "azure": "Azure",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "digitalocean": "DigitalOcean",
    "linode": "Linode/Akamai",
    "hetzner": "Hetzner",
    "ovh": "OVHcloud",
    "oracle": "Oracle Cloud",
    "alibaba": "Alibaba Cloud",
}

HEADER_HINTS = [
    (r"^server\s*:\s*cloudflare", "Cloudflare"),
    (r"x-served-by:\s*cache-.*?fastly", "Fastly"),
    (r"via:\s*.*?varnish", "Fastly"),   # Fastly often shows Varnish
    (r"x-cache:\s*.*?cloudfront", "AWS"),
    (r"x-amz-cf-", "AWS"),
    (r"server:\s*tsa_b\s*$", "Twitter/Edge"),  # example pattern
    (r"x-vercel-", "Vercel"),
    (r"server:\s*Netlify", "Netlify"),
    (r"x-azure-ref|x-msedge-ref", "Azure"),
]

def resolve_dns(name, rdtype):
    if not HAVE_DNS:
        return []
    try:
        return [rdata.to_text().strip('.') for rdata in dns.resolver.resolve(name, rdtype)]
    except Exception:
        return []

def reverse_dns(ip):
    if not HAVE_DNS:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    try:
        addr = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(addr, "PTR")
        return str(answer[0]).strip('.')
    except Exception:
        return None

def whois_org_for_ip(ip):
    if not HAVE_IPWHOIS:
        return None
    try:
        data = IPWhois(ip).lookup_rdap(depth=1)
        # Prefer network or ASN description fields
        org = (
            (data.get("network") or {}).get("name")
            or (data.get("asn_description") or "")
            or (data.get("asn") or "")
        )
        return org
    except Exception:
        return None

def fetch_http(domain, use_https=True, timeout=7):
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{domain}"
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        return r
    except Exception:
        return None

def fetch_cert_sans(domain, port=443, timeout=7):
    try:
        ctx = ssl.create_default_context()
        with closing(socket.create_connection((domain, port), timeout=timeout)) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        sans = []
        for t, v in cert.get("subjectAltName", []):
            if t.lower() == "dns":
                sans.append(v.lower())
        issuer_parts = []
        for tup in cert.get("issuer", []):
            for k, v in tup:
                issuer_parts.append(f"{k}={v}")
        issuer = ", ".join(issuer_parts)
        return sans, issuer
    except Exception:
        return [], ""

def score_and_decide(signals):
    """
    signals: dict of provider -> list of hints
    Simple scoring: number of distinct sources (DNS/ASN/HTTP/Cert) contributing.
    """
    scores = {}
    for provider, hints in signals.items():
        # Weight by unique hint categories
        cats = set(h[0] for h in hints)  # "DNS", "CNAME", "ASN", "HTTP", "CERT", "PTR", "NS"
        scores[provider] = len(cats) * 10 + len(hints)  # primary weight on sources
    if not scores:
        return None, 0
    best = max(scores, key=scores.get)
    return best, scores[best]

def detect(domain):
    signals = defaultdict(list)
    details = {"domain": domain, "ips": [], "cnames": [], "ns": [], "ptr": {}, "asn_orgs": {}, "http_headers": {}, "cert_sans": [], "cert_issuer": ""}

    # DNS
    ips = resolve_dns(domain, "A") + resolve_dns(domain, "AAAA")
    details["ips"] = ips

    cnames = resolve_dns(domain, "CNAME")
    details["cnames"] = cnames
    for cname in cnames:
        for pat, (provider, product) in CNAME_HINTS.items():
            if re.search(pat, cname, re.IGNORECASE):
                signals[provider].append(("CNAME", f"{cname} ⇒ {product}"))

    nss = resolve_dns(domain, "NS")
    details["ns"] = nss
    for ns in nss:
        # Some NSs are very telling (e.g., cloudflare.com)
        for pat, (provider, product) in CNAME_HINTS.items():
            if re.search(pat, ns, re.IGNORECASE):
                signals[provider].append(("NS", f"{ns} ⇒ {product}"))

    # PTR + ASN
    for ip in ips:
        ptr = reverse_dns(ip)
        if ptr:
            details["ptr"][ip] = ptr
            for pat, (provider, product) in CNAME_HINTS.items():
                if re.search(pat, ptr, re.IGNORECASE):
                    signals[provider].append(("PTR", f"{ip} PTR {ptr} ⇒ {product}"))

        org = whois_org_for_ip(ip)
        if org:
            details["asn_orgs"][ip] = org
            for key, provider in ASN_HINTS.items():
                if key in org.lower():
                    signals[provider].append(("ASN", f"{ip} owner {org}"))

    # HTTP headers
    r = fetch_http(domain, use_https=True) or fetch_http(domain, use_https=False)
    if r is not None:
        # Normalize headers for regex scanning
        lower_headers = {k.lower(): ",".join(v) if isinstance(v, (list, tuple)) else str(v) for k, v in r.headers.items()}
        details["http_headers"] = lower_headers
        raw = "\n".join([f"{k}: {v}" for k, v in lower_headers.items()])
        for pat, provider in HEADER_HINTS:
            if re.search(pat, raw, re.IGNORECASE):
                signals[provider].append(("HTTP", f"header matched: {pat}"))

    # TLS cert SANs / issuer
    sans, issuer = fetch_cert_sans(domain)
    details["cert_sans"] = sans
    details["cert_issuer"] = issuer
    for san in sans:
        for pat, (provider, product) in CNAME_HINTS.items():
            if re.search(pat, san, re.IGNORECASE):
                signals[provider].append(("CERT", f"SAN {san} ⇒ {product}"))
    # Issuer can sometimes hint (rarely decisive), keep as weak signal
    for key, provider in ASN_HINTS.items():
        if key in issuer.lower():
            signals[provider].append(("CERT", f"Issuer {issuer}"))

    provider, score = score_and_decide(signals)
    # Very rough confidence mapping
    confidence = min(99, max(10, score)) if provider else 0

    # Compose friendly summary
    reasons = {p: [f"[{cat}] {msg}" for (cat, msg) in hints] for p, hints in signals.items()}

    return {
        "domain": domain,
        "best_guess_provider": provider or "Unknown",
        "confidence": confidence,
        "reasons": reasons,
        "details": details,
    }


def main():
    ap = argparse.ArgumentParser(description="Guess which cloud/CDN a site runs on using DNS, ASN, HTTP, and TLS heuristics.")
    ap.add_argument("domain", help="Domain to analyze (e.g., example.com)")
    ap.add_argument("--json", action="store_true", help="Output JSON only")
    args = ap.parse_args()

    res = detect(args.domain)
    if args.json:
        print(json.dumps(res, indent=2))
        sys.exit(0)

    print(f"\nDomain: {res['domain']}")
    print(f"Best Guess: {res['best_guess_provider']} (confidence {res['confidence']}/99)\n")

    if res["reasons"]:
        print("Signals:")
        for prov, msgs in sorted(res["reasons"].items(), key=lambda x: (-len(x[1]), x[0])):
            print(f"  - {prov}:")
            for m in msgs:
                print(f"      • {m}")
        print()

    d = res["details"]
    if d["cnames"]:
        print("CNAMEs:")
        for c in d["cnames"]:
            print(f"  - {c}")
    if d["ips"]:
        print("\nIPs:")
        for ip in d["ips"]:
            org = d['asn_orgs'].get(ip, "")
            ptr = d['ptr'].get(ip, "")
            extras = []
            if ptr: extras.append(f"PTR={ptr}")
            if org: extras.append(f"ORG={org}")
            suffix = f"  ({', '.join(extras)})" if extras else ""
            print(f"  - {ip}{suffix}")

    if d["ns"]:
        print("\nNS:")
        for ns in d["ns"]:
            print(f"  - {ns}")

    if d["http_headers"]:
        print("\nHTTP header hints (subset):")
        keep = ["server", "via", "x-cache", "x-amz-cf-pop", "x-vercel-id", "cf-ray", "x-azure-ref"]
        for k in keep:
            v = d["http_headers"].get(k)
            if v:
                print(f"  - {k}: {v}")

    if d["cert_sans"] or d["cert_issuer"]:
        print("\nTLS certificate:")
        if d["cert_issuer"]:
            print(f"  - issuer: {d['cert_issuer']}")
        if d["cert_sans"]:
            shown = ", ".join(d["cert_sans"][:5])
            more = "" if len(d["cert_sans"]) <= 5 else f" (+{len(d['cert_sans'])-5} more)"
            print(f"  - SANs: {shown}{more}")

    print("\nNote: This is heuristic. CDNs (Cloudflare/Akamai/Fastly) may front sites hosted in AWS/Azure/GCP.\n")


if __name__ == "__main__":
    main()
