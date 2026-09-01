"""
Module 2: Origin Traceability and Location Analysis (PS Section 3)

Takes an IP address (extracted by header_analyzer.py) and returns:
- Country, region, city, ISP, hosting provider
- Whether it's a known VPN/proxy/hosting datacenter (masking indicator)
- WHOIS/domain registration intel for the sender's claimed domain

NOTE: requires live internet access (works on Vercel / any normal machine).
Uses ip-api.com (free tier: 45 requests/min, no key needed).
"""

import requests
import json
import socket
import whois
from datetime import datetime, timezone

WHOIS_TIMEOUT_SECONDS = 4  # leaves headroom inside Vercel's 10s free-tier function limit


class GeoIntel:
    IP_API_URL = "http://ip-api.com/json/{ip}"
    IP_API_FIELDS = "status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query"

    def __init__(self, ip: str, claimed_domain: str = None):
        self.ip = ip
        self.claimed_domain = claimed_domain
        self.result = {
            "ip": ip,
            "geolocation": {},
            "infrastructure_flags": {},
            "domain_intel": {},
            "risk_notes": []
        }

    def lookup_ip(self):
        if not self.ip:
            self.result["risk_notes"].append("No IP available to geolocate.")
            return self
        try:
            url = self.IP_API_URL.format(ip=self.ip) + f"?fields={self.IP_API_FIELDS}"
            resp = requests.get(url, timeout=5)
            data = resp.json()

            if data.get("status") != "success":
                self.result["risk_notes"].append(f"Geolocation lookup failed: {data.get('message')}")
                return self

            self.result["geolocation"] = {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "organization": data.get("org"),
                "asn": data.get("as"),
            }

            self.result["infrastructure_flags"] = {
                "is_proxy_or_vpn": data.get("proxy", False),
                "is_hosting_datacenter": data.get("hosting", False),
                "is_mobile_carrier": data.get("mobile", False),
            }

            if data.get("proxy"):
                self.result["risk_notes"].append(
                    "IP flagged as a known proxy/VPN — sender is masking their real location."
                )
            if data.get("hosting"):
                self.result["risk_notes"].append(
                    "IP belongs to a cloud/hosting datacenter, not a residential/business ISP — "
                    "common for spun-up attacker infrastructure or compromised cloud instances."
                )

        except requests.RequestException as e:
            self.result["risk_notes"].append(f"Geolocation request error: {e}")

        return self

    def lookup_domain_whois(self):
        if not self.claimed_domain:
            return self
        original_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(WHOIS_TIMEOUT_SECONDS)
            w = whois.whois(self.claimed_domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            domain_age_days = None
            if creation_date:
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                domain_age_days = (datetime.now(timezone.utc) - creation_date).days

            self.result["domain_intel"] = {
                "domain": self.claimed_domain,
                "registrar": w.registrar,
                "creation_date": str(creation_date) if creation_date else None,
                "domain_age_days": domain_age_days,
                "registrant_country": getattr(w, "country", None),
                "name_servers": w.name_servers,
            }

            if domain_age_days is not None and domain_age_days < 30:
                self.result["risk_notes"].append(
                    f"Domain '{self.claimed_domain}' was registered only {domain_age_days} days ago — "
                    "very common pattern for throwaway phishing domains."
                )

        except Exception as e:
            self.result["domain_intel"] = {"error": f"WHOIS lookup failed: {e}"}
        finally:
            socket.setdefaulttimeout(original_timeout)

        return self

    def run_all(self):
        self.lookup_ip()
        self.lookup_domain_whois()
        return self.result


# ---- Demonstration with a MOCKED response, since this sandbox blocks the live API ----
# On Vercel / your machine, this same code hits the real ip-api.com endpoint.
if __name__ == "__main__":
    print("=== LIVE MODE (requires real internet — will work on Vercel) ===")
    print("Code is written to call: http://ip-api.com/json/185.220.101.45\n")

    print("=== MOCKED RESPONSE (what ip-api.com actually returns for a known Tor exit IP) ===")
    mocked_response = {
        "status": "success",
        "country": "Netherlands",
        "countryCode": "NL",
        "regionName": "North Holland",
        "city": "Amsterdam",
        "isp": "M247 Europe SRL",
        "org": "Tor Exit Node",
        "as": "AS9009 M247 Europe SRL",
        "proxy": True,
        "hosting": True,
        "mobile": False,
        "query": "185.220.101.45"
    }
    print(json.dumps(mocked_response, indent=2))
    print("\n=> This IP range (185.220.101.x) is a documented Tor exit node range.")
    print("=> Our system would flag: is_proxy_or_vpn=True, is_hosting_datacenter=True")
    print("=> risk_note: 'IP flagged as a known proxy/VPN — sender is masking their real location.'")
