"""
Synthetic BEC Data Augmentation

The CEAS_08 and Nazario_5 datasets are from 2001-2008 — they teach the model
to recognize old-school pharma/dating spam, not modern targeted BEC attacks
(fake CEO wire transfer requests, fake invoice fraud, credential phishing
disguised as IT/HR communication).

This script generates realistic synthetic BEC examples using templated
variation (varying names, amounts, companies, urgency phrasing) to give the
classifier real exposure to this attack pattern. Templates are grounded in
well-documented, publicly reported real-world BEC tactics (FBI IC3 reports,
industry threat research) — not copied from any single source.

These are added as label=1 (fraud) alongside a matched set of synthetic
ordinary internal business emails as label=0 (legitimate), so the model
doesn't just learn "business language = fraud".
"""

import pandas as pd
import random

random.seed(42)

EXECUTIVES = ["John Smith", "Sarah Chen", "Michael Torres", "Priya Sharma", "David Okafor", "Lisa Wagner"]
TITLES = ["CEO", "CFO", "COO", "VP of Finance", "Managing Director"]
COMPANIES = ["Meridian Corp", "Northbridge Ltd", "Vantage Holdings", "Silverline Inc", "Crestpoint Group"]
AMOUNTS = ["$12,400", "$48,500", "$27,900", "$63,200", "$8,750", "$115,000"]
VENDORS = ["our new supplier", "the overseas vendor", "the contractor", "our logistics partner"]

BEC_TEMPLATES = [
    "Hi, I need you to process an urgent wire transfer of {amount} to {vendor} before end of day. "
    "This is time-sensitive and confidential — please don't discuss this with anyone else right now, "
    "I'm in back-to-back meetings and can't take calls. Please confirm once done.",

    "This is {name}, {title} at {company}. I'm currently traveling and my usual assistant is unavailable. "
    "I need you to handle a payment of {amount} discreetly today. Please don't loop in the finance team yet, "
    "I'll explain everything when I'm back. Reply to confirm you can action this now.",

    "URGENT — please update the banking details for {vendor}'s account before you release today's payment run. "
    "The new routing number and account details are attached. This needs to go out before 3pm, "
    "please don't call to verify, I'm unreachable by phone for the next few hours.",

    "Hi team, our vendor invoice for {amount} is now overdue and they've threatened to pause deliveries. "
    "Please expedite payment today using the updated account details I sent separately. Keep this between us "
    "for now until I brief the CFO properly.",

    "Hey, quick favor — can you purchase {amount} in gift cards for a client appreciation gift? I need it "
    "done in the next hour, I'm stuck in back-to-back calls. Send me the codes directly once purchased, "
    "don't mention it to procurement, I'll expense it properly later.",

    "Your account access will be suspended within 24 hours due to unusual sign-in activity. "
    "Click here to verify your credentials immediately and confirm your identity to avoid disruption to "
    "payment processing: verify-account-secure-login.com",

    "This is an urgent request from {name} ({title}). We have a confidential acquisition in progress and "
    "I need you to wire {amount} to the escrow account below today. Do not discuss this with anyone in "
    "the office as this deal is not yet public.",
]

LEGIT_TEMPLATES = [
    "Hi team, just a reminder that the quarterly budget review is scheduled for Thursday at 10am. "
    "Please have your department numbers ready ahead of the meeting.",

    "Hi, following up on the invoice from last week — I've approved it through the normal process "
    "and finance should process it in the next payment cycle as usual.",

    "Good morning, attaching the updated project timeline for your review. Let me know if you have "
    "any questions before our sync tomorrow.",

    "Hi all, please remember to submit your timesheets by end of week through the usual portal. "
    "Reach out to HR if you run into any issues.",

    "Thanks for sending this over. I've reviewed the proposal and I think we're good to proceed — "
    "let's discuss next steps in our regular Monday call.",

    "Hi, just confirming receipt of the signed contract. I'll forward this to legal for filing "
    "and loop you in once it's fully processed.",

    "Reminder: the office will be closed on Friday for the public holiday. Normal operations resume Monday.",
]

BEC_SUBJECTS = [
    "URGENT: Wire Transfer Approval Needed Today",
    "Confidential Request - Action Needed",
    "Payment Update Required Before EOD",
    "Re: Overdue Invoice - Please Expedite",
    "Account Verification Required Immediately",
    "Quick Favor - Time Sensitive",
]

LEGIT_SUBJECTS = [
    "Quarterly Budget Review - Thursday 10am",
    "Following up on invoice approval",
    "Updated project timeline attached",
    "Reminder: Timesheets due Friday",
    "Re: Proposal review",
    "Office closed Friday - public holiday",
]


def generate_synthetic_dataset(n_per_class=300):
    rows = []
    for _ in range(n_per_class):
        template = random.choice(BEC_TEMPLATES)
        body = template.format(
            name=random.choice(EXECUTIVES),
            title=random.choice(TITLES),
            company=random.choice(COMPANIES),
            amount=random.choice(AMOUNTS),
            vendor=random.choice(VENDORS),
        )
        rows.append({
            "subject": random.choice(BEC_SUBJECTS),
            "body": body,
            "label": 1
        })

    for _ in range(n_per_class):
        body = random.choice(LEGIT_TEMPLATES)
        rows.append({
            "subject": random.choice(LEGIT_SUBJECTS),
            "body": body,
            "label": 0
        })

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
    return df


if __name__ == "__main__":
    df = generate_synthetic_dataset(n_per_class=300)
    df.to_csv("data/synthetic_bec.csv", index=False)
    print(f"Generated {len(df)} synthetic examples ({df['label'].value_counts().to_dict()})")
    print("\nSample rows:")
    print(df.head(3).to_string())
