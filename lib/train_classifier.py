"""
Module 3: Fraudulent Email Detection Engine — NLP classifier (PS Section 1)

Trains a TF-IDF + Logistic Regression classifier on labeled phishing/legitimate
email text (subject + body). This is the FAST, EXPLAINABLE baseline model.

Datasets used:
- CEAS_08.csv   (39,154 emails: 21,842 phishing/spam, 17,312 legitimate)
- Nazario_5.csv (3,065 emails: 1,565 phishing, 1,500 legitimate)

Output: trained model + vectorizer saved to models/, ready to be loaded by the
scoring pipeline (score_email.py) for real-time inference.
"""

import pandas as pd
import numpy as np
import joblib
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score


from text_utils import clean_text


def load_and_combine(paths, oversample_map=None):
    """
    oversample_map: dict of {path: repeat_count} to duplicate smaller/newer datasets
    so they aren't statistically drowned out by much larger older datasets.
    E.g. 600 synthetic BEC rows vs 42,000 old spam rows would otherwise contribute
    ~1.4% of training signal — oversampling makes the model actually learn from them.
    """
    oversample_map = oversample_map or {}
    dfs = []
    for p in paths:
        df = pd.read_csv(p)
        df = df[["subject", "body", "label"]].copy()
        repeat = oversample_map.get(p, 1)
        if repeat > 1:
            df = pd.concat([df] * repeat, ignore_index=True)
        dfs.append(df)
    combined = pd.concat(dfs, ignore_index=True)
    combined = combined.dropna(subset=["body"])
    combined["subject"] = combined["subject"].fillna("")
    combined["text"] = (combined["subject"] + " " + combined["body"]).apply(clean_text)
    return combined


def train():
    print("Loading datasets...")
    # Split BEFORE oversampling so duplicated synthetic rows never leak across
    # the train/test boundary (which would artificially inflate test accuracy).
    base_df = load_and_combine(["data/CEAS_08.csv", "data/Nazario_5.csv"])
    synth_df = load_and_combine(["data/synthetic_bec.csv"])
    enron_df = load_and_combine(["data/enron_legit_sample.csv"])  # real business email, all label=0

    base_train, base_test, = train_test_split(
        base_df, test_size=0.2, random_state=42, stratify=base_df["label"]
    )
    synth_train, synth_test = train_test_split(
        synth_df, test_size=0.2, random_state=42, stratify=synth_df["label"]
    )
    enron_train, enron_test = train_test_split(
        enron_df, test_size=0.2, random_state=42
    )

    OVERSAMPLE_FACTOR = 25  # 480 synthetic train rows -> 12,000 effective rows (~22% of training data)
    synth_train_oversampled = pd.concat([synth_train] * OVERSAMPLE_FACTOR, ignore_index=True)

    train_df = pd.concat([base_train, synth_train_oversampled, enron_train], ignore_index=True)
    test_df = pd.concat([base_test, synth_test, enron_test], ignore_index=True)  # realistic, un-oversampled

    X_train, y_train = train_df["text"], train_df["label"]
    X_test, y_test = test_df["text"], test_df["label"]

    print(f"Training rows: {len(X_train)} (incl. {len(synth_train_oversampled)} oversampled synthetic BEC rows, "
          f"{len(enron_train)} real Enron legitimate-business rows)")
    print(f"Test rows: {len(X_test)} (real distribution, not oversampled)")
    print(f"Test label distribution:\n{y_test.value_counts()}\n")

    print("Vectorizing text (TF-IDF)...")
    vectorizer = TfidfVectorizer(
        max_features=20000,
        ngram_range=(1, 2),      # unigrams + bigrams catch phrases like "verify account", "wire transfer"
        stop_words="english",
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("Training Logistic Regression classifier...")
    clf = LogisticRegression(max_iter=1000, C=1.0, class_weight="balanced")
    clf.fit(X_train_vec, y_train)

    print("\n=== Evaluation on held-out test set ===")
    y_pred = clf.predict(X_test_vec)
    y_prob = clf.predict_proba(X_test_vec)[:, 1]

    print(classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing/Fraud (1)"]))
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))
    print(f"ROC-AUC score: {roc_auc_score(y_test, y_prob):.4f}")

    # Show the most predictive words/phrases for each class — this is what makes it EXPLAINABLE
    feature_names = np.array(vectorizer.get_feature_names_out())
    coefs = clf.coef_[0]
    top_phishing_idx = np.argsort(coefs)[-20:][::-1]
    top_legit_idx = np.argsort(coefs)[:20]

    print("\n=== Top 20 words/phrases indicating PHISHING/FRAUD ===")
    for i in top_phishing_idx:
        print(f"  {feature_names[i]:30s}  weight={coefs[i]:.3f}")

    print("\n=== Top 20 words/phrases indicating LEGITIMATE ===")
    for i in top_legit_idx:
        print(f"  {feature_names[i]:30s}  weight={coefs[i]:.3f}")

    print("\nSaving model + vectorizer to models/...")
    import os
    models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(clf, os.path.join(models_dir, "fraud_classifier.pkl"))
    joblib.dump(vectorizer, os.path.join(models_dir, "tfidf_vectorizer.pkl"))
    print("Done.")

    return clf, vectorizer


if __name__ == "__main__":
    train()
