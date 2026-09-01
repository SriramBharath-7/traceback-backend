"""
Lightweight text cleaning — deliberately dependency-free (just `re`).

Split out from train_classifier.py so the LIVE inference path (pipeline.py,
used on every incoming email in production) never has to import pandas or
any training-only code. Pulling in pandas at runtime was adding unnecessary
weight to every serverless cold start on Vercel.
"""

import re


def clean_text(text: str) -> str:
    """Lowercase, replace URLs with a token, collapse whitespace."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\.\S+", " URLTOKEN ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()
