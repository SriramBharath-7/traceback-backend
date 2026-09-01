"""
Gmail live ingestion: OAuth connection + Pub/Sub-triggered email fetching.

Flow:
  1. User visits /api/gmail/connect -> redirected to Google consent screen
  2. Google redirects back to /api/gmail/oauth_callback with a code
  3. We exchange the code for tokens, store them, and call users().watch()
     to tell Gmail: "publish a Pub/Sub message every time this inbox changes"
  4. When mail arrives, Pub/Sub POSTs to /api/gmail/webhook (see api/app.py)
  5. That calls process_new_history() here, which asks Gmail "what changed
     since historyId X", fetches each new message's raw content, and feeds
     it into the same analyze_and_store() pipeline manual upload uses.

REQUIRES (real Google Cloud Console setup — cannot be done via code alone):
  - A Google Cloud project with the Gmail API enabled
  - An OAuth 2.0 Client ID (type: Web application) with this redirect URI
    registered: {BACKEND_URL}/api/gmail/oauth_callback
  - A Pub/Sub topic, with gmail-api-push@system.gserviceaccount.com granted
    the "Pub/Sub Publisher" role on that topic
  - A push subscription on that topic pointing to: {BACKEND_URL}/api/gmail/webhook

Environment variables needed:
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GMAIL_PUBSUB_TOPIC
"""

import os
import sys
import base64
from datetime import datetime, timezone, timedelta

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

sys.path.insert(0, os.path.dirname(__file__))
from db import GmailAccount, get_session
from pipeline import analyze_and_store

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

CLIENT_CONFIG = {
    "web": {
        "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
        "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [os.environ.get("GOOGLE_REDIRECT_URI", "")],
    }
}

PUBSUB_TOPIC = os.environ.get("GMAIL_PUBSUB_TOPIC")  # e.g. "projects/my-project/topics/gmail-watch"


def build_auth_url() -> str:
    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES)
    flow.redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")
    auth_url, _ = flow.authorization_url(
        access_type="offline",       # required to get a refresh_token
        prompt="consent",            # forces refresh_token on repeat connects too
        include_granted_scopes="true",
    )
    return auth_url


def exchange_code_and_start_watch(code: str) -> str:
    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES)
    flow.redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")
    flow.fetch_token(code=code)
    creds = flow.credentials

    gmail = build("gmail", "v1", credentials=creds)
    profile = gmail.users().getProfile(userId="me").execute()
    email_address = profile["emailAddress"]

    # Register the watch — tells Gmail to publish to our Pub/Sub topic on any change
    watch_response = gmail.users().watch(
        userId="me",
        body={"topicName": PUBSUB_TOPIC, "labelIds": ["INBOX"], "labelFilterBehavior": "INCLUDE"},
    ).execute()
    # watch_response contains: {"historyId": "...", "expiration": "<epoch ms>"}

    db = get_session()
    try:
        existing = db.query(GmailAccount).filter(GmailAccount.email_address == email_address).first()
        expiration_ms = int(watch_response["expiration"])
        expiration_dt = datetime.fromtimestamp(expiration_ms / 1000, tz=timezone.utc)

        if existing:
            existing.refresh_token = creds.refresh_token or existing.refresh_token
            existing.access_token = creds.token
            existing.history_id = watch_response["historyId"]
            existing.watch_expiration = expiration_dt
        else:
            db.add(GmailAccount(
                email_address=email_address,
                refresh_token=creds.refresh_token,
                access_token=creds.token,
                history_id=watch_response["historyId"],
                watch_expiration=expiration_dt,
            ))
        db.commit()
    finally:
        db.close()

    return email_address


def _get_gmail_client(account: GmailAccount):
    creds = Credentials(
        token=account.access_token,
        refresh_token=account.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        scopes=SCOPES,
    )
    return build("gmail", "v1", credentials=creds)


def process_new_history(email_address: str, new_history_id: str) -> list:
    """
    Called by the webhook. Asks Gmail what changed since our last known
    historyId, fetches each newly added message's raw content, and runs it
    through the same analysis pipeline as manual upload.
    """
    db = get_session()
    try:
        account = db.query(GmailAccount).filter(GmailAccount.email_address == email_address).first()
        if not account:
            return []

        gmail = _get_gmail_client(account)
        last_known_history_id = account.history_id

        new_case_ids = []
        try:
            history_response = gmail.users().history().list(
                userId="me",
                startHistoryId=last_known_history_id,
                historyTypes=["messageAdded"],
            ).execute()
        except Exception as e:
            # historyId too old (>7 days gap) means Gmail expired it — needs a fresh watch().
            return [{"error": f"History fetch failed (may need to re-watch): {e}"}]

        for record in history_response.get("history", []):
            for added in record.get("messagesAdded", []):
                msg_id = added["message"]["id"]
                raw_msg = gmail.users().messages().get(userId="me", id=msg_id, format="raw").execute()
                raw_bytes = base64.urlsafe_b64decode(raw_msg["raw"])
                raw_email = raw_bytes.decode("utf-8", errors="ignore")

                result = analyze_and_store(raw_email, source="gmail_live", do_live_lookups=True)
                new_case_ids.append(result["case_id"])

        # Advance our cursor so we don't re-process the same messages next time
        account.history_id = new_history_id
        db.commit()

        return new_case_ids
    finally:
        db.close()


def renew_watch_if_needed():
    """
    Gmail watches expire after 7 days — call this on a daily cron
    (e.g. a Vercel Cron Job) to renew any watch expiring soon.
    """
    db = get_session()
    try:
        soon = datetime.now(timezone.utc) + timedelta(days=1)
        expiring = db.query(GmailAccount).filter(GmailAccount.watch_expiration < soon).all()
        for account in expiring:
            gmail = _get_gmail_client(account)
            watch_response = gmail.users().watch(
                userId="me",
                body={"topicName": PUBSUB_TOPIC, "labelIds": ["INBOX"], "labelFilterBehavior": "INCLUDE"},
            ).execute()
            expiration_ms = int(watch_response["expiration"])
            account.watch_expiration = datetime.fromtimestamp(expiration_ms / 1000, tz=timezone.utc)
            account.history_id = watch_response["historyId"]
        db.commit()
    finally:
        db.close()
