"""
Simulates: it's a week later, the server has restarted, and a BRAND NEW email
arrives that happens to share the same reply-to infrastructure as an attack
from last week. This is a completely separate process from pipeline.py's
__main__ block — proving the comparison works across restarts, not just
within one script run.
"""

from pipeline import analyze_and_store, detect_campaigns
import json

NEW_PHISHING_EMAIL = """Delivered-To: accounting@fourthvictim.com
Received: from new-relay.attacker-infra.net (new-relay.attacker-infra.net. [91.203.5.10])
        by mx.fourthvictim.com with ESMTPS id d99-caseNew
        for <accounting@fourthvictim.com>;
        Mon, 31 Aug 2026 11:00:00 -0700 (PDT)
Received-SPF: fail (google.com: domain of finance@paypa1-refunds.com does not designate 91.203.5.10 as permitted sender) client-ip=91.203.5.10;
Authentication-Results: mx.fourthvictim.com;
       dkim=fail header.i=@paypa1-refunds.com;
       spf=fail smtp.mailfrom=finance@paypa1-refunds.com;
       dmarc=fail (p=REJECT) header.from=paypa1-refunds.com
From: "PayPal Refunds" <finance@paypa1-refunds.com>
Reply-To: support.case8821@mail-response-team.ru
Return-Path: <bounce@new-relay.attacker-infra.net>
To: accounting@fourthvictim.com
Subject: Refund Processing - Verify Account
Date: Mon, 31 Aug 2026 11:00:00 -0700
Message-ID: <newcase@attacker-infra.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Dear Customer,

A refund of $340.00 has been issued to your account but requires
verification. Click here to verify and claim your refund immediately:

http://paypa1-refunds-claim.tk/verify?case=8821

PayPal Refunds Team
"""

if __name__ == "__main__":
    print("=== NEW email arriving in a fresh process (simulating a week later) ===")
    result = analyze_and_store(NEW_PHISHING_EMAIL, source="manual_upload", do_live_lookups=False)
    print(f"Stored {result['case_id']}: {result['risk_level']} ({result['final_score']}/100)\n")

    print("=== Campaigns detected AFTER this new arrival (queried from full historical DB) ===")
    campaigns = detect_campaigns()
    print(json.dumps(campaigns, indent=2))
