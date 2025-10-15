#!/usr/bin/env python3
"""
Gmail rule runner:
- Reads rules from Google Sheets
- Finds messages received in the last X minutes
- Applies rules (AND of matchers) and executes verdicts (mark read, add label)
"""

import os
import time
import json
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta

# Google API imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# === Configuration ===
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/spreadsheets.readonly",
]

# Edit these
# <-- put the ID for your Google Sheet
SPREADSHEET_ID = "PUT_YOUR_SPREADSHEET_ID_HERE"
SHEET_NAME = "Sheet1"  # sheet/tab name
LOOKBACK_MINUTES = 60
MAX_MESSAGES_FETCH = 500  # safety cap
CREDENTIALS_FILE = "credentials.json"
TOKEN_FILE = "token.json"

# Logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")


# === Authentication / service creation ===
def get_creds():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())  # pip package google-auth handles this
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        # save token
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
    return creds


# === Sheets ===
def read_rules_from_sheet(sheets_service) -> List[Dict[str, Any]]:
    # We expect header row; read all values
    range_name = f"{SHEET_NAME}"
    sheet = sheets_service.spreadsheets()
    result = sheet.values().get(spreadsheetId=SPREADSHEET_ID, range=range_name).execute()
    values = result.get("values", [])
    if not values or len(values) < 1:
        logging.warning("No data in sheet.")
        return []

    headers = [h.strip() for h in values[0]]
    rows = values[1:]
    rules = []
    for row in rows:
        # Map header -> value (safe access)
        row_map = {headers[i]: (row[i].strip() if i < len(row) else "")
                   for i in range(len(headers))}
        # Only include enabled rows
        enabled = row_map.get("enabled", "").lower() in (
            "true", "1", "yes", "y", "t")
        if not enabled:
            continue
        # Normalize fields
        rule = {
            "name": row_map.get("name", ""),
            "from_contains": row_map.get("from_contains", ""),
            "to_contains": row_map.get("to_contains", ""),
            "subject_contains": row_map.get("subject_contains", ""),
            "body_contains": row_map.get("body_contains", ""),
            "has_attachment": row_map.get("has_attachment", "").lower() in ("true", "1", "yes", "y", "t"),
            "verdict": row_map.get("verdict", ""),
        }
        rules.append(rule)
    logging.info("Loaded %d enabled rules from sheet", len(rules))
    return rules


# === Gmail helpers ===
def build_gmail_service(creds):
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def ensure_label_id(gmail_service, label_name: str) -> str:
    """Return label id for label_name; create it if missing."""
    user_id = "me"
    labels = gmail_service.users().labels().list(
        userId=user_id).execute().get("labels", [])
    for l in labels:
        if l.get("name", "").lower() == label_name.lower():
            return l["id"]
    # create
    body = {"name": label_name, "labelListVisibility": "labelShow",
            "messageListVisibility": "show"}
    created = gmail_service.users().labels().create(
        userId=user_id, body=body).execute()
    logging.info("Created label %s -> %s", label_name, created["id"])
    return created["id"]


def get_recent_message_ids(gmail_service, lookback_minutes=60, cap=500) -> List[Dict[str, Any]]:
    """
    Get messages that arrived within lookback_minutes.
    Strategy: ask Gmail for a recent timeframe (e.g. newer_than:1d) to limit,
    then filter by internalDate in code to precise minute granularity.
    """
    user_id = "me"
    # We ask for messages newer than 1 day to constrain results, then filter to lookback_minutes
    query = "newer_than:1d"
    try:
        res = gmail_service.users().messages().list(
            userId=user_id, q=query, maxResults=min(cap, 500)).execute()
    except HttpError as e:
        logging.exception("Gmail list error: %s", e)
        return []

    messages = res.get("messages", []) or []
    # Now fetch message metadata and filter by internalDate
    recent = []
    threshold_ms = int((datetime.now(timezone.utc) -
                       timedelta(minutes=lookback_minutes)).timestamp() * 1000)
    for m in messages:
        try:
            full = gmail_service.users().messages().get(userId=user_id,
                                                        id=m["id"], format="metadata", metadataHeaders=["From", "To", "Subject"]).execute()
        except HttpError as e:
            logging.exception("Error fetching message %s: %s", m.get("id"), e)
            continue
        internal_date = int(full.get("internalDate", "0"))
        if internal_date >= threshold_ms:
            recent.append(full)
        # safety cap
        if len(recent) >= cap:
            break
    logging.info("Found %d messages in last %d minutes",
                 len(recent), lookback_minutes)
    return recent


def header_value(headers: List[Dict[str, str]], name: str) -> str:
    name = name.lower()
    for h in headers:
        if h.get("name", "").lower() == name:
            return h.get("value", "")
    return ""


def message_matches_rule(message: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """Check all non-empty fields of rule (AND semantics)."""
    headers = message.get("payload", {}).get("headers", [])
    from_v = header_value(headers, "From")
    to_v = header_value(headers, "To")
    subject_v = header_value(headers, "Subject")
    snippet = message.get("snippet", "")

    def contains(hay, needle):
        return needle.strip().lower() in (hay or "").lower()

    # from
    if rule["from_contains"] and not contains(from_v, rule["from_contains"]):
        return False
    if rule["to_contains"] and not contains(to_v, rule["to_contains"]):
        return False
    if rule["subject_contains"] and not contains(subject_v, rule["subject_contains"]):
        return False
    if rule["body_contains"] and not contains(snippet, rule["body_contains"]):
        return False
    if rule["has_attachment"]:
        # quick heuristic: check payload.parts for filename or attachmentId
        parts = message.get("payload", {}).get("parts", []) or []
        found = False
        for p in parts:
            if p.get("filename"):
                found = True
                break
            body = p.get("body", {})
            if body and body.get("attachmentId"):
                found = True
                break
        if not found:
            return False

    return True


def apply_verdicts(gmail_service, message_ids: List[str], verdicts: List[str]):
    """Apply verdict operations to messages (batch where possible)."""
    user_id = "me"
    add_label_ids = []
    remove_label_ids = []
    # We'll collect batch operations per label:
    create_label_ids = {}  # labelname -> id

    # Parse verdicts (e.g., mark_read;add_label:Junk)
    for v in verdicts:
        v = v.strip()
        if v == "mark_read":
            remove_label_ids.append("UNREAD")
        elif v.startswith("add_label:"):
            label_name = v.split(":", 1)[1].strip()
            if label_name:
                # ensure label exists
                label_id = ensure_label_id(gmail_service, label_name)
                add_label_ids.append(label_id)
        elif v.startswith("remove_label:"):
            label_name = v.split(":", 1)[1].strip()
            if label_name:
                # find label id
                labels = gmail_service.users().labels().list(
                    userId=user_id).execute().get("labels", [])
                for l in labels:
                    if l.get("name", "").lower() == label_name.lower():
                        remove_label_ids.append(l["id"])
                        break
        else:
            logging.warning("Unknown verdict token: %s", v)

    # de-dup
    add_label_ids = list(dict.fromkeys(add_label_ids))
    remove_label_ids = list(dict.fromkeys(remove_label_ids))

    if not add_label_ids and not remove_label_ids:
        return

    # call batchModify (up to 1000 ids per request)
    chunk_size = 900
    for i in range(0, len(message_ids), chunk_size):
        ids_chunk = message_ids[i:i+chunk_size]
        body = {"ids": ids_chunk}
        if add_label_ids:
            body["addLabelIds"] = add_label_ids
        if remove_label_ids:
            body["removeLabelIds"] = remove_label_ids
        try:
            gmail_service.users().messages().batchModify(userId=user_id, body=body).execute()
            logging.info("Applied labels to %d messages (add=%s remove=%s)", len(
                ids_chunk), add_label_ids, remove_label_ids)
        except HttpError as e:
            logging.exception("Error applying verdict to messages: %s", e)


def main():
    creds = get_creds()
    sheets_service = build(
        "sheets", "v4", credentials=creds, cache_discovery=False)
    gmail_service = build_gmail_service(creds)

    rules = read_rules_from_sheet(sheets_service)
    if not rules:
        logging.info("No enabled rules found; exiting.")
        return

    recent_messages = get_recent_message_ids(
        gmail_service, lookback_minutes=LOOKBACK_MINUTES, cap=MAX_MESSAGES_FETCH)

    # For each rule, collect matched message IDs and apply verdicts
    # We'll do per-rule application (could be merged for performance)
    for rule in rules:
        matched_ids = []
        for msg in recent_messages:
            try:
                if message_matches_rule(msg, rule):
                    matched_ids.append(msg["id"])
            except Exception:
                logging.exception(
                    "Error checking message against rule %s", rule.get("name"))
        if matched_ids:
            verdict_tokens = [v.strip() for v in rule.get(
                "verdict", "").split(";") if v.strip()]
            logging.info("Rule '%s' matched %d messages; verdict=%s",
                         rule.get("name"), len(matched_ids), verdict_tokens)
            apply_verdicts(gmail_service, matched_ids, verdict_tokens)
        else:
            logging.debug("Rule '%s' matched 0 messages", rule.get("name"))


if __name__ == "__main__":
    main()
