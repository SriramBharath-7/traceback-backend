"""
TRACEBACK — main FastAPI application.

This is the Vercel Python entrypoint (Vercel looks for `app.py` with a
top-level `app` object). Every route the frontend talks to lives here.

Routes:
  POST /api/analyze          — manual upload: analyze one raw email, store it
  GET  /api/cases            — list all stored cases (dashboard case list)
  GET  /api/cases/{case_id}  — full detail for one case
  GET  /api/campaigns        — detect campaigns from full stored history
  GET  /api/gmail/connect    — start Gmail OAuth flow (connect a live mailbox)
  GET  /api/gmail/oauth_callback — Google redirects here after consent
  POST /api/gmail/webhook    — Pub/Sub push notification receiver (live ingestion)
"""

import os
import sys
import json
import base64
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from pipeline import analyze_and_store, detect_campaigns
from db import Case, AccessLog, GmailAccount, get_session, init_db
import gmail_ingest

app = FastAPI(title="TRACEBACK API")

# Frontend runs on a different Vercel "Service"/domain, so CORS is needed.
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN] if FRONTEND_ORIGIN != "*" else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()  # safe to call repeatedly — create_all() is a no-op if tables exist


# ---------------------------------------------------------------------------
# Manual upload / analysis
# ---------------------------------------------------------------------------

@app.post("/api/analyze")
async def analyze_email(request: Request, file: UploadFile = File(None)):
    """
    Accepts EITHER:
      - multipart file upload (a .eml file), or
      - JSON body: {"raw_email": "..."}
    """
    if file is not None:
        raw_bytes = await file.read()
        raw_email = raw_bytes.decode("utf-8", errors="ignore")
    else:
        body = await request.json()
        raw_email = body.get("raw_email")
        if not raw_email:
            raise HTTPException(status_code=400, detail="Provide a file upload or 'raw_email' in JSON body.")

    try:
        result = analyze_and_store(raw_email, source="manual_upload", do_live_lookups=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")

    return JSONResponse(result)


# ---------------------------------------------------------------------------
# Case management (Section 5 of the PS checklist)
# ---------------------------------------------------------------------------

@app.get("/api/cases")
def list_cases(limit: int = 100, risk_level: str = None):
    db = get_session()
    try:
        query = db.query(Case).order_by(Case.received_at.desc())
        if risk_level:
            query = query.filter(Case.risk_level == risk_level.upper())
        cases = query.limit(limit).all()
        return [
            {
                "case_id": c.case_id,
                "received_at": c.received_at.isoformat() if c.received_at else None,
                "source": c.source,
                "subject": c.subject,
                "from_address": c.from_address,
                "from_domain": c.from_domain,
                "originating_ip": c.originating_ip,
                "geo_country": c.geo_country,
                "geo_city": c.geo_city,
                "final_score": c.final_score,
                "risk_level": c.risk_level,
            }
            for c in cases
        ]
    finally:
        db.close()


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    db = get_session()
    try:
        c = db.query(Case).filter(Case.case_id == case_id).first()
        if not c:
            raise HTTPException(status_code=404, detail="Case not found")

        # Chain-of-custody: log every view (Section 6 of the checklist)
        db.add(AccessLog(case_id=case_id, action="viewed"))
        db.commit()

        return {
            "case_id": c.case_id,
            "received_at": c.received_at.isoformat() if c.received_at else None,
            "source": c.source,
            "subject": c.subject,
            "from_address": c.from_address,
            "from_domain": c.from_domain,
            "reply_to": c.reply_to,
            "reply_to_domain": c.reply_to_domain,
            "originating_ip": c.originating_ip,
            "relay_chain": c.relay_chain,
            "geo": {
                "country": c.geo_country, "region": c.geo_region, "city": c.geo_city,
                "isp": c.geo_isp, "is_proxy": c.is_proxy, "is_hosting": c.is_hosting,
            },
            "domain_age_days": c.domain_age_days,
            "authentication": {"spf": c.spf, "dkim": c.dkim, "dmarc": c.dmarc, "dmarc_policy": c.dmarc_policy},
            "ml_probability": c.ml_probability,
            "bec_score": c.bec_score,
            "bec_categories": c.bec_categories,
            "lookalike_domain": c.lookalike_domain,
            "final_score": c.final_score,
            "risk_level": c.risk_level,
            "explanation": c.explanation,
            "raw_email_hash": c.raw_email_hash,
        }
    finally:
        db.close()


@app.get("/api/campaigns")
def get_campaigns():
    return detect_campaigns()


@app.get("/api/cases/{case_id}/audit-log")
def get_audit_log(case_id: str):
    """Chain-of-custody trail for one case — who/what touched it, when."""
    db = get_session()
    try:
        logs = db.query(AccessLog).filter(AccessLog.case_id == case_id).order_by(AccessLog.timestamp).all()
        return [{"action": l.action, "actor": l.actor, "timestamp": l.timestamp.isoformat()} for l in logs]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Gmail live ingestion (Section 7 — real-time requirement)
# ---------------------------------------------------------------------------

@app.get("/api/gmail/connect")
def gmail_connect():
    """Redirects the user to Google's OAuth consent screen."""
    auth_url = gmail_ingest.build_auth_url()
    return RedirectResponse(auth_url)


@app.get("/api/gmail/oauth_callback")
def gmail_oauth_callback(code: str = None, error: str = None):
    """Google redirects here after the user approves/denies access."""
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth denied: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    email_address = gmail_ingest.exchange_code_and_start_watch(code)
    return JSONResponse({
        "status": "connected",
        "email_address": email_address,
        "message": "Live monitoring is now active for this mailbox."
    })


@app.post("/api/gmail/webhook")
async def gmail_webhook(request: Request):
    """
    Pub/Sub POSTs here the instant a watched mailbox changes.
    Body shape: {"message": {"data": "<base64 JSON>", "messageId": "...", ...}, "subscription": "..."}
    """
    body = await request.json()
    message = body.get("message", {})
    data_b64 = message.get("data")
    if not data_b64:
        return JSONResponse({"status": "ignored", "reason": "no data field"})

    decoded = base64.b64decode(data_b64).decode("utf-8")
    payload = json.loads(decoded)  # {"emailAddress": "...", "historyId": "..."}

    new_cases = gmail_ingest.process_new_history(
        email_address=payload["emailAddress"],
        new_history_id=str(payload["historyId"]),
    )

    return JSONResponse({"status": "processed", "new_cases": new_cases})


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}
