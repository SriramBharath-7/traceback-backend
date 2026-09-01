"""
Module 4: Rule-Based BEC / Social-Engineering Signal Detector (PS Section 1)

Deterministic pattern matching for Business Email Compromise indicators that
statistical models trained on old spam data tend to miss:
- Urgency & pressure tactics
- Secrecy / isolation language ("don't tell anyone", "confidential")
- Authority impersonation (CEO/CFO/executive claims)
- Payment diversion / fake invoice language
- Credential harvesting language
- Lookalike domain detection (edit distance vs a watchlist of known-legit domains)

Every match is human-readable — this is the "explainability" layer that shows
WHY something was flagged, not just a black-box score.
"""

import re
from difflib import SequenceMatcher


class BECSignalDetector:

    URGENCY_PATTERNS = [
        r"\burgent(ly)?\b", r"\bact now\b", r"\bimmediate(ly)?\b",
        r"\basap\b", r"\bright away\b", r"\btime[-\s]sensitive\b",
        r"\bbefore end of day\b", r"\bdeadline\b", r"\bexpires? (today|soon)\b",
        r"\bfinal notice\b", r"\bwithin (the )?(next )?\d+ (hours?|minutes?)\b",
    ]

    SECRECY_ISOLATION_PATTERNS = [
        r"\bdo not (discuss|tell|share|mention)\b", r"\bkeep this (confidential|between us|private)\b",
        r"\bconfidential(ity)?\b.{0,40}\b(do not|don't|please)\b",
        r"\bcan'?t take calls\b", r"\bin (a )?meeting[s]?\b.{0,30}\b(can'?t|cannot)\b",
        r"\bdon'?t (cc|copy|loop in)\b", r"\bbetween (you and me|us)\b",
    ]

    AUTHORITY_IMPERSONATION_PATTERNS = [
        r"\b(ceo|cfo|coo|president|director|founder)\b", r"\bon behalf of\b",
        r"\bas (discussed|requested) by\b.{0,20}\b(ceo|cfo|management)\b",
    ]

    PAYMENT_DIVERSION_PATTERNS = [
        r"\bwire transfer\b", r"\bwire (the )?funds?\b", r"\bupdate.{0,20}(bank|account) details\b",
        r"\bchange.{0,20}(payment|bank) (method|details|information)\b",
        r"\bnew (vendor|supplier|beneficiary) (account|details)\b",
        r"\boutstanding (invoice|payment)\b", r"\bpay(ment)? (is |was )?(overdue|due)\b",
        r"\bgift cards?\b.{0,30}\bpurchase\b", r"\brouting number\b",
    ]

    CREDENTIAL_HARVESTING_PATTERNS = [
        r"\bverify your (account|password|credentials|login|identity)\b",
        r"\bclick here to (verify|confirm|login|log in|update)\b",
        r"\byour account (will be|has been) (suspended|locked|disabled)\b",
        r"\bconfirm your (password|identity|details)\b",
        r"\bunusual (activity|sign-?in|login)\b.{0,30}\bverify\b",
    ]

    def __init__(self, subject: str, body: str, from_domain: str = None,
                 known_legit_domains: list = None):
        self.subject = subject or ""
        self.body = body or ""
        self.text = f"{self.subject} {self.body}".lower()
        self.from_domain = (from_domain or "").lower()
        self.known_legit_domains = known_legit_domains or [
            "paypal.com", "microsoft.com", "google.com", "amazon.com",
            "apple.com", "bankofamerica.com", "chase.com", "wellsfargo.com",
        ]
        self.result = {
            "signals": [],
            "categories_triggered": set(),
            "lookalike_domain_match": None,
            "bec_rule_score": 0,  # 0-100, weighted sum of category hits
        }

    def _scan(self, patterns, category_name, weight):
        hits = []
        for pattern in patterns:
            if re.search(pattern, self.text, re.IGNORECASE):
                hits.append(pattern)
        if hits:
            self.result["categories_triggered"].add(category_name)
            self.result["bec_rule_score"] += weight
            self.result["signals"].append({
                "category": category_name,
                "matched_patterns": hits,
                "weight": weight
            })
        return self

    def check_urgency(self):
        return self._scan(self.URGENCY_PATTERNS, "urgency_pressure", weight=15)

    def check_secrecy_isolation(self):
        return self._scan(self.SECRECY_ISOLATION_PATTERNS, "secrecy_isolation", weight=20)

    def check_authority_impersonation(self):
        return self._scan(self.AUTHORITY_IMPERSONATION_PATTERNS, "authority_impersonation", weight=15)

    def check_payment_diversion(self):
        return self._scan(self.PAYMENT_DIVERSION_PATTERNS, "payment_diversion", weight=25)

    def check_credential_harvesting(self):
        return self._scan(self.CREDENTIAL_HARVESTING_PATTERNS, "credential_harvesting", weight=25)

    def check_lookalike_domain(self):
        """
        Flags domains that are suspiciously similar (but not identical) to known-legit brands.
        Compares against the domain's core segment (e.g. 'paypa1' in 'paypa1-secure.com'),
        not the full string, since attackers pad real domains with extra words like
        '-secure', '-support', '-verify' that would otherwise dilute the similarity score.
        """
        if not self.from_domain:
            return self

        # Split the domain into alnum segments: "paypa1-secure.com" -> ["paypa1", "secure", "com"]
        segments = re.split(r"[.\-]", self.from_domain)
        segments = [s for s in segments if len(s) >= 3]  # ignore tiny fragments like tld remnants

        best_match = None
        for legit in self.known_legit_domains:
            legit_core = legit.split(".")[0]  # "paypal.com" -> "paypal"
            if self.from_domain == legit:
                continue  # exact real domain, not a lookalike

            for seg in segments:
                if seg == legit_core:
                    continue  # exact segment match to the real brand name is not itself suspicious alone
                similarity = SequenceMatcher(None, seg, legit_core).ratio()
                if similarity > 0.75 and (best_match is None or similarity > best_match["similarity"]):
                    best_match = {
                        "sender_domain": self.from_domain,
                        "suspicious_segment": seg,
                        "resembles": legit,
                        "similarity": round(similarity, 3)
                    }

        if best_match:
            self.result["lookalike_domain_match"] = best_match
            self.result["bec_rule_score"] += 30
            self.result["signals"].append({
                "category": "lookalike_domain",
                "matched_patterns": [
                    f"segment '{best_match['suspicious_segment']}' in '{self.from_domain}' is "
                    f"{round(best_match['similarity']*100)}% similar to real brand '{best_match['resembles']}'"
                ],
                "weight": 30
            })
        return self

    def run_all(self):
        (self.check_urgency()
             .check_secrecy_isolation()
             .check_authority_impersonation()
             .check_payment_diversion()
             .check_credential_harvesting()
             .check_lookalike_domain())
        self.result["bec_rule_score"] = min(self.result["bec_rule_score"], 100)  # cap at 100
        self.result["categories_triggered"] = list(self.result["categories_triggered"])
        return self.result


if __name__ == "__main__":
    import json
    subject = "URGENT: Wire Transfer Approval Needed Today"
    body = """Hi, I need you to process an urgent wire transfer of $48,500 to our new vendor
    before end of day. This is time-sensitive and confidential - please do not
    discuss with anyone else in the office right now, I'm in back-to-back
    meetings and can't take calls. Please confirm once done. Also please verify your login credentials at
    http://paypa1-secure-login.tk/verify?ref=8821 to ensure the payment portal access is active."""

    detector = BECSignalDetector(subject, body, from_domain="paypa1-secure.com")
    output = detector.run_all()
    print(json.dumps(output, indent=2))
