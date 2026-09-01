"""
The core pipeline entrypoint, now wired to the database.

Every call to analyze_and_store() does the full analysis AND permanently
saves the result — this is what gives the system memory across days/weeks,
not just within one run.

Campaign detection then queries ALL historical cases (not just the ones
analyzed in this session) to find shared infrastructure — this is the real
version of what campaign_correlation.py demonstrated with in-memory data.
"""

import sys
import os
import json
import uuid
import networkx as nx
from email import message_from_string

sys.path.insert(0, os.path.dirname(__file__))

from header_analyzer import EmailHeaderAnalyzer
from geo_intel import GeoIntel
from bec_rules import BECSignalDetector
from text_utils import clean_text
from db import Case, AccessLog, get_session, hash_raw_email, init_db

import joblib

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
_clf = None
_vectorizer = None


def _load_models():
    global _clf, _vectorizer
    if _clf is None:
        _clf = joblib.load(os.path.join(MODELS_DIR, "fraud_classifier.pkl"))
        _vectorizer = joblib.load(os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl"))
    return _clf, _vectorizer


def _extract_body(raw_email: str) -> str:
    msg = message_from_string(raw_email)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                return payload.decode(errors="ignore") if payload else ""
        return ""
    payload = msg.get_payload(decode=True)
    return payload.decode(errors="ignore") if payload else str(msg.get_payload())


def analyze_and_store(raw_email: str, source: str = "manual_upload", do_live_lookups: bool = True) -> dict:
    """
    Runs the full pipeline on one raw email and permanently saves the result.
    Returns the same structured result your dashboard consumes.
    """
    clf, vectorizer = _load_models()

    header_result = EmailHeaderAnalyzer(raw_email).run_all()
    basic = header_result["basic_fields"]
    originating_ip = header_result.get("originating_ip")
    claimed_domain = basic.get("from_domain")

    geo_result = GeoIntel(originating_ip, claimed_domain).run_all() if do_live_lookups else {
        "geolocation": {}, "infrastructure_flags": {}, "domain_intel": {}, "risk_notes": []
    }

    subject = basic.get("subject", "") or ""
    body = _extract_body(raw_email)
    text = clean_text(subject + " " + body)
    ml_prob = float(clf.predict_proba(vectorizer.transform([text]))[0][1])

    bec_result = BECSignalDetector(subject, body, from_domain=claimed_domain).run_all()

    # --- Combine into final score (same weighting logic as score_email.py) ---
    score = 0.0
    explanation = []
    auth = header_result["authentication"]

    if auth["spf"] in ("fail", "softfail"):
        score += 20
        explanation.append(f"SPF authentication failed ({auth['spf']})")
    if auth["dkim"] == "fail":
        score += 15
        explanation.append("DKIM signature failed")
    if auth["dmarc"] == "fail":
        score += 15
        explanation.append(f"DMARC failed — policy: {auth.get('dmarc_policy')}")
    if header_result["identity_mismatches"]:
        score += 10
        explanation.append("Sender identity mismatch (From/Reply-To/Return-Path)")

    infra_flags = geo_result.get("infrastructure_flags", {})
    if infra_flags.get("is_proxy_or_vpn"):
        score += 8
        explanation.append("Originating IP is a known VPN/proxy")
    if infra_flags.get("is_hosting_datacenter"):
        score += 5
        explanation.append("Originating IP belongs to a hosting/cloud datacenter")

    domain_intel = geo_result.get("domain_intel", {})
    domain_age = domain_intel.get("domain_age_days")
    if domain_age is not None and domain_age < 30:
        score += 10
        explanation.append(f"Sender domain registered only {domain_age} days ago")

    ml_contribution = round(ml_prob * 15, 1)
    score += ml_contribution
    explanation.append(f"ML classifier fraud probability: {round(ml_prob*100,1)}%")

    bec_contribution = round((bec_result["bec_rule_score"] / 100) * 25, 1)
    score += bec_contribution
    if bec_result["signals"]:
        explanation.append(f"BEC signals: {', '.join(bec_result['categories_triggered'])}")
    if bec_result.get("lookalike_domain_match"):
        m = bec_result["lookalike_domain_match"]
        explanation.append(f"Lookalike domain resembles '{m['resembles']}' ({round(m['similarity']*100)}% similar)")

    final_score = min(round(score, 1), 100)
    risk_level = "CRITICAL" if final_score >= 70 else "HIGH" if final_score >= 45 else "MEDIUM" if final_score >= 20 else "LOW"

    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    geo = geo_result.get("geolocation", {})

    # --- Persist to database ---
    db = get_session()
    try:
        case = Case(
            case_id=case_id,
            source=source,
            subject=subject,
            from_address=basic.get("from"),
            from_domain=claimed_domain,
            reply_to=basic.get("reply_to"),
            reply_to_domain=basic.get("reply_to_domain"),
            return_path_domain=basic.get("return_path_domain"),
            originating_ip=originating_ip,
            relay_chain=header_result.get("relay_chain", []),
            geo_country=geo.get("country"),
            geo_region=geo.get("region"),
            geo_city=geo.get("city"),
            geo_isp=geo.get("isp"),
            is_proxy=infra_flags.get("is_proxy_or_vpn", False),
            is_hosting=infra_flags.get("is_hosting_datacenter", False),
            domain_age_days=domain_age,
            spf=auth["spf"], dkim=auth["dkim"], dmarc=auth["dmarc"], dmarc_policy=auth.get("dmarc_policy"),
            ml_probability=round(ml_prob, 4),
            bec_score=bec_result["bec_rule_score"],
            bec_categories=bec_result["categories_triggered"],
            lookalike_domain=bec_result.get("lookalike_domain_match"),
            final_score=final_score,
            risk_level=risk_level,
            explanation=explanation,
            raw_email_hash=hash_raw_email(raw_email),
            raw_email=raw_email,
        )
        db.add(case)
        db.commit()
        db.refresh(case)
    finally:
        db.close()

    return {
        "case_id": case_id,
        "final_score": final_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "header_analysis": header_result,
        "geo_intel": geo_result,
        "ml_classifier": {"phishing_probability": round(ml_prob, 4)},
        "bec_rules": bec_result,
    }


def detect_campaigns(min_cases: int = 2) -> list:
    """
    Queries ALL stored cases (real history, not just this session) and builds
    a correlation graph from shared IP / reply-to / reply-domain / from-domain.
    Returns detected campaigns with confidence ratings.
    """
    db = get_session()
    try:
        all_cases = db.query(Case).all()
        graph = nx.Graph()

        for c in all_cases:
            case_node = f"CASE:{c.case_id}"
            graph.add_node(case_node, type="case", case_id=c.case_id, final_score=c.final_score,
                           subject=c.subject, risk_level=c.risk_level)

            if c.originating_ip:
                ip_node = f"IP:{c.originating_ip}"
                graph.add_node(ip_node, type="ip")
                graph.add_edge(case_node, ip_node)

            if c.reply_to_domain:
                rd_node = f"REPLY_DOMAIN:{c.reply_to_domain}"
                graph.add_node(rd_node, type="reply_domain")
                graph.add_edge(case_node, rd_node)

            if c.reply_to:
                ra_node = f"REPLY_ADDR:{c.reply_to}"
                graph.add_node(ra_node, type="reply_address")
                graph.add_edge(case_node, ra_node)

        campaigns = []
        for component in nx.connected_components(graph):
            case_nodes = [n for n in component if graph.nodes[n].get("type") == "case"]
            if len(case_nodes) >= min_cases:
                shared_infra = []
                for n in component:
                    ntype = graph.nodes[n].get("type")
                    if ntype in ("ip", "reply_domain", "reply_address"):
                        linked_cases = [x for x in graph.neighbors(n) if graph.nodes[x].get("type") == "case"]
                        if len(linked_cases) >= min_cases:
                            shared_infra.append({"type": ntype, "value": n.split(":", 1)[1]})

                campaigns.append({
                    "campaign_id": f"CAMPAIGN-{len(campaigns)+1}",
                    "case_ids": [graph.nodes[c]["case_id"] for c in case_nodes],
                    "num_cases": len(case_nodes),
                    "shared_infrastructure": shared_infra,
                    "avg_fraud_score": round(sum(graph.nodes[c]["final_score"] for c in case_nodes) / len(case_nodes), 1),
                    "confidence": "HIGH" if len(shared_infra) >= 2 else "MEDIUM",
                })
        return campaigns
    finally:
        db.close()


if __name__ == "__main__":
    init_db()

    # Simulate: analyze the same 4 samples, but now through the DB-backed pipeline,
    # run as if they arrived on separate days (this is the real test of "history")
    sample_dir = os.path.join(os.path.dirname(__file__), "..", "..", "email_forensics", "samples")
    for fname in ["sample_phishing.eml", "sample_phishing_2.eml", "sample_phishing_3.eml", "sample_legit.eml"]:
        path = os.path.join(sample_dir, fname)
        with open(path) as f:
            raw = f.read()
        result = analyze_and_store(raw, source="manual_upload", do_live_lookups=False)
        print(f"Stored {result['case_id']}: {result['risk_level']} ({result['final_score']}/100) — {fname}")

    print("\n=== Campaigns detected from STORED HISTORY (queried fresh from DB) ===")
    campaigns = detect_campaigns()
    print(json.dumps(campaigns, indent=2))
