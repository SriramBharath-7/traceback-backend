"""
Module 1: Email Header & Protocol Forensics
Covers PS Section 2 (Header/Protocol Analysis) + part of Section 3 (Origin extraction)

Input: raw .eml file (or raw header text)
Output: structured JSON with auth results, relay chain, originating IP, anomaly flags
"""

import re
import json
from email import message_from_string, message_from_bytes
from email.utils import parseaddr, getaddresses
from datetime import datetime
import ipaddress


class EmailHeaderAnalyzer:
    def __init__(self, raw_email: str):
        self.raw = raw_email
        self.msg = message_from_string(raw_email)
        self.result = {
            "basic_fields": {},
            "authentication": {},
            "relay_chain": [],
            "originating_ip": None,
            "originating_ip_hop_index": None,
            "anomalies": [],
            "identity_mismatches": {}
        }

    # ---------- 1. Basic fields ----------
    def extract_basic_fields(self):
        m = self.msg
        self.result["basic_fields"] = {
            "from": m.get("From"),
            "from_domain": self._domain_from_address(m.get("From")),
            "reply_to": m.get("Reply-To"),
            "reply_to_domain": self._domain_from_address(m.get("Reply-To")),
            "return_path": m.get("Return-Path"),
            "return_path_domain": self._domain_from_address(m.get("Return-Path")),
            "to": m.get("To"),
            "subject": m.get("Subject"),
            "date": m.get("Date"),
            "message_id": m.get("Message-ID"),
        }
        return self

    @staticmethod
    def _domain_from_address(addr_field):
        if not addr_field:
            return None
        name, email_addr = parseaddr(addr_field)
        if "@" in email_addr:
            return email_addr.split("@")[-1].lower().strip(">")
        return None

    # ---------- 2. Authentication-Results (SPF/DKIM/DMARC) ----------
    def extract_authentication(self):
        auth_header = self.msg.get("Authentication-Results", "")
        spf_header = self.msg.get("Received-SPF", "")

        auth = {"spf": "none", "dkim": "none", "dmarc": "none", "raw": auth_header}

        spf_match = re.search(r"spf=(\w+)", auth_header, re.IGNORECASE) or re.search(r"^(\w+)", spf_header)
        dkim_match = re.search(r"dkim=(\w+)", auth_header, re.IGNORECASE)
        dmarc_match = re.search(r"dmarc=(\w+)", auth_header, re.IGNORECASE)

        if spf_match:
            auth["spf"] = spf_match.group(1).lower()
        if dkim_match:
            auth["dkim"] = dkim_match.group(1).lower()
        if dmarc_match:
            auth["dmarc"] = dmarc_match.group(1).lower()

        # DMARC policy (what the domain says should happen on failure)
        policy_match = re.search(r"p=(\w+)", auth_header, re.IGNORECASE)
        auth["dmarc_policy"] = policy_match.group(1).lower() if policy_match else None

        self.result["authentication"] = auth
        return self

    # ---------- 3. Relay chain (Received headers) ----------
    def extract_relay_chain(self):
        received_headers = self.msg.get_all("Received", [])
        chain = []
        for idx, hop in enumerate(received_headers):
            ip = self._extract_ip(hop)
            timestamp = self._extract_timestamp(hop)
            chain.append({
                "hop_index": idx,
                "raw": hop.replace("\n", " ").replace("\t", " ").strip(),
                "ip": ip,
                "timestamp": timestamp,
            })
        # Received headers appear newest-first in the raw email; reverse so index 0 = earliest/original hop
        chain.reverse()
        for i, hop in enumerate(chain):
            hop["hop_index"] = i
        self.result["relay_chain"] = chain
        return self

    @staticmethod
    def _extract_ip(header_text):
        # Find IPv4 addresses, skip private/loopback ranges when possible
        candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", header_text)
        for ip in candidates:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    return ip
            except ValueError:
                continue
        return candidates[0] if candidates else None

    @staticmethod
    def _extract_timestamp(header_text):
        # Received headers end with a date after a semicolon
        match = re.search(r";\s*(.+)$", header_text.replace("\n", " ").replace("\t", " "))
        return match.group(1).strip() if match else None

    # ---------- 4. Identify the earliest RELIABLE originating IP ----------
    def identify_originating_ip(self):
        """
        The first Received header (earliest hop) is the most likely true origin,
        BUT it can be forged by the sender themselves before it hits the first
        server you actually trust. We flag this rather than blindly trusting hop 0.
        """
        chain = self.result["relay_chain"]
        if not chain:
            self.result["anomalies"].append("No Received headers found — cannot trace origin.")
            return self

        first_hop = chain[0]
        self.result["originating_ip"] = first_hop["ip"]
        self.result["originating_ip_hop_index"] = 0

        if first_hop["ip"] is None:
            self.result["anomalies"].append(
                "Earliest hop has no extractable IP — possible header forgery or non-standard MTA."
            )
        return self

    # ---------- 5. Anomaly detection ----------
    def detect_anomalies(self):
        b = self.result["basic_fields"]
        auth = self.result["authentication"]
        chain = self.result["relay_chain"]

        # Identity mismatches
        mismatches = {}
        if b["from_domain"] and b["reply_to_domain"] and b["from_domain"] != b["reply_to_domain"]:
            mismatches["from_vs_reply_to"] = f"From domain '{b['from_domain']}' != Reply-To domain '{b['reply_to_domain']}'"
        if b["from_domain"] and b["return_path_domain"] and b["from_domain"] != b["return_path_domain"]:
            mismatches["from_vs_return_path"] = f"From domain '{b['from_domain']}' != Return-Path domain '{b['return_path_domain']}'"
        self.result["identity_mismatches"] = mismatches

        # Auth failures
        if auth["spf"] in ("fail", "softfail"):
            self.result["anomalies"].append(f"SPF check failed ({auth['spf']}) — sending server not authorized for this domain.")
        if auth["dkim"] == "fail":
            self.result["anomalies"].append("DKIM signature failed — message may have been altered or forged.")
        if auth["dmarc"] == "fail":
            self.result["anomalies"].append(f"DMARC failed — domain policy says: {auth.get('dmarc_policy', 'unspecified')}.")

        # Timestamp ordering anomaly (very lightweight check)
        timestamps = [h["timestamp"] for h in chain if h["timestamp"]]
        if len(timestamps) >= 2:
            parsed = []
            for ts in timestamps:
                try:
                    from email.utils import parsedate_to_datetime
                    parsed.append(parsedate_to_datetime(ts))
                except Exception:
                    pass
            if len(parsed) >= 2 and parsed != sorted(parsed):
                self.result["anomalies"].append("Relay timestamps are out of chronological order — possible forged/inserted Received header.")

        if mismatches:
            self.result["anomalies"].append("Sender identity mismatch detected across From/Reply-To/Return-Path.")

        return self

    def run_all(self):
        (self.extract_basic_fields()
             .extract_authentication()
             .extract_relay_chain()
             .identify_originating_ip()
             .detect_anomalies())
        return self.result


if __name__ == "__main__":
    with open("samples/sample_phishing.eml", "r") as f:
        raw = f.read()

    analyzer = EmailHeaderAnalyzer(raw)
    output = analyzer.run_all()
    print(json.dumps(output, indent=2, default=str))
