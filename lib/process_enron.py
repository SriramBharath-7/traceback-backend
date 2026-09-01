"""
Processes the raw Enron email corpus (file, message columns — RFC822 raw
text, no labels) into clean (subject, body, label=0) rows for training.

This corpus is ALL legitimate internal corporate email — it cannot supply
new fraud/phishing examples (there are none in it), but it's genuinely
useful as diverse, realistic "legitimate" business email to sit alongside
the old Linux-mailing-list "legitimate" examples from CEAS_08, which were a
poor match for what real business email looks like.

We sample rather than process all ~500K emails — a few thousand diverse,
de-duplicated examples give the model plenty of signal without the size/time
cost of the full corpus.
"""

import pandas as pd
import re
from email import message_from_string

SAMPLE_PER_FILE = 3000  # ~12,000 total across 4 files — plenty for this purpose


def extract_subject_body(raw_message: str):
    try:
        msg = message_from_string(raw_message)
        subject = msg.get("Subject", "") or ""
        body = msg.get_payload()
        if isinstance(body, list):  # multipart, rare in this corpus but be safe
            body = body[0].get_payload() if body else ""
        return subject, body or ""
    except Exception:
        return "", ""


def process_enron_files(paths, sample_per_file=SAMPLE_PER_FILE):
    rows = []
    for path in paths:
        print(f"Reading {path} (sampling {sample_per_file} rows)...")
        df = pd.read_csv(path, nrows=sample_per_file * 3)  # read a bit extra, filter, then trim
        df = df.dropna(subset=["message"])

        count = 0
        for msg in df["message"]:
            subject, body = extract_subject_body(msg)
            body = body.strip()
            # Skip near-empty bodies and forwarded/auto-generated noise that adds no signal
            if len(body) < 30 or len(body) > 5000:
                continue
            rows.append({"subject": subject, "body": body, "label": 0})
            count += 1
            if count >= sample_per_file:
                break
        print(f"  -> kept {count} usable rows")

    df_out = pd.DataFrame(rows)
    df_out = df_out.drop_duplicates(subset=["body"])
    return df_out


if __name__ == "__main__":
    paths = [
        "/mnt/user-data/uploads/emails_part1.csv",
        "/mnt/user-data/uploads/emails_part2.csv",
        "/mnt/user-data/uploads/emails_part3.csv",
        "/mnt/user-data/uploads/emails_part4.csv",
    ]
    df = process_enron_files(paths)
    print(f"\nTotal usable, de-duplicated Enron legitimate examples: {len(df)}")
    df.to_csv("data/enron_legit_sample.csv", index=False)
    print("Saved to data/enron_legit_sample.csv")
    print("\nSample rows:")
    print(df.head(3)[["subject", "body"]].to_string())
