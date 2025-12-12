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
from typing import List, Dict, Any, Optional, TypedDict, Sequence
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Google API imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request

# === Configuration ============================================================

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/spreadsheets.readonly",
]

# Edit these (non-secret defaults). Put secrets in config.private.json
DEFAULT_SPREADSHEET_ID: str = "SHEET_ID"
DEFAULT_SHEET_NAME: str = "SHEET_NAME"
LOOKBACK_MINUTES: int = 60 * 2
MAX_MESSAGES_FETCH: int = 500  # safety cap
CREDENTIALS_FILE: str = "credentials.json"
TOKEN_FILE: str = "token.json"
CONFIG_FILE: str = "config.private.json"

# Logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")


# === Authentication / service creation ========================================

def get_creds() -> Credentials:
    creds: Optional[Credentials] = None
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


# === Sheets ===================================================================

def _load_private_config() -> Dict[str, Any]:
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        logging.warning("Failed to parse %s; ignoring.", CONFIG_FILE)
        return {}


def get_spreadsheet_id() -> str:
    # Precedence: env var -> private config -> default constant
    env_v = os.getenv("SPREADSHEET_ID")
    if env_v:
        return env_v
    cfg = _load_private_config()
    v = cfg.get("SPREADSHEET_ID")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return DEFAULT_SPREADSHEET_ID


def get_sheet_name() -> str:
    # Precedence: env var -> private config -> default constant
    env_v = os.getenv("SHEET_NAME")
    if env_v:
        return env_v
    cfg = _load_private_config()
    v = cfg.get("SHEET_NAME")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return DEFAULT_SHEET_NAME


class Rule(TypedDict, total=False):
    name: str
    from_matcher: str
    to_matcher: str
    subject_matcher: str
    body_matcher: str
    has_attachment: bool
    verdict: str


def read_rules_from_sheet(sheets_service: Any) -> List[Rule]:
    # We expect header row; read all values
    sheet_name = get_sheet_name()
    sheet_id = get_spreadsheet_id()
    logging.info(
        "Opening sheet_name: '%s' in sheet (id: '%s')", sheet_name, sheet_id)
    sheet = sheets_service.spreadsheets()
    result = sheet.values().get(spreadsheetId=get_spreadsheet_id(),
                                range=sheet_name).execute()
    values = result.get("values", [])
    if not values or len(values) < 1:
        logging.warning("No data in sheet.")
        return []

    # Find the header row by looking for a row with "enabled" as the first column value (case-insensitive)
    header_row_index = None
    for idx, row in enumerate(values):
        if row and str(row[0]).strip().lower() == "enabled":
            header_row_index = idx
            break
    if header_row_index is None:
        logging.warning("No header row found with 'enabled' as first column.")
        return []
    headers = [h.strip() for h in values[header_row_index]]

    rows = values[header_row_index:]
    rules: List[Rule] = []
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
        rule: Rule = {
            "name": row_map.get("name", ""),
            "from_matcher": row_map.get("from_matcher", ""),
            "to_matcher": row_map.get("to_matcher", ""),
            "subject_matcher": row_map.get("subject_matcher", ""),
            "body_matcher": row_map.get("body_matcher", ""),
            "has_attachment": row_map.get("has_attachment", "").lower() in ("true", "1", "yes", "y", "t"),
            "verdict": row_map.get("verdict", ""),
        }
        rules.append(rule)
    logging.info("Loaded %d enabled rules from sheet", len(rules))
    return rules


# === Gmail helpers ============================================================

def build_gmail_service(creds: Credentials) -> Any:
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


_LABEL_NAME_TO_ID_CACHE: Dict[str, str] = {}
_LABEL_CACHE_LOCK = threading.Lock()


def _init_label_cache_if_needed(gmail_service: Any) -> None:
    """Populate the global label cache once per process."""
    # Fast-path without lock
    if _LABEL_NAME_TO_ID_CACHE:
        return
    with _LABEL_CACHE_LOCK:
        if _LABEL_NAME_TO_ID_CACHE:
            return
        user_id = "me"
        labels = gmail_service.users().labels().list(
            userId=user_id).execute().get("labels", [])
        for l in labels:
            name = l.get("name", "")
            lid = l.get("id", "")
            if not name or not lid:
                continue
            # Cache both exact and lowercase for case-insensitive lookup
            _LABEL_NAME_TO_ID_CACHE.setdefault(name, lid)
            _LABEL_NAME_TO_ID_CACHE.setdefault(name.lower(), lid)


def _get_label_id_from_cache(gmail_service: Any, label_name: str) -> Optional[str]:
    _init_label_cache_if_needed(gmail_service)
    lid = _LABEL_NAME_TO_ID_CACHE.get(label_name)
    if lid:
        return lid
    return _LABEL_NAME_TO_ID_CACHE.get(label_name.lower())


def ensure_label_id(gmail_service: Any, label_name: str) -> str:
    """Return label id for label_name; create it if missing. Uses cache."""
    existing = _get_label_id_from_cache(gmail_service, label_name)
    if existing:
        return existing
    # create if not found
    user_id = "me"
    body = {"name": label_name, "labelListVisibility": "labelShow",
            "messageListVisibility": "show"}
    created = gmail_service.users().labels().create(
        userId=user_id, body=body).execute()
    created_id = created.get("id", "")
    if created_id:
        with _LABEL_CACHE_LOCK:
            _LABEL_NAME_TO_ID_CACHE.setdefault(label_name, created_id)
            _LABEL_NAME_TO_ID_CACHE.setdefault(label_name.lower(), created_id)
    logging.info("Created label %s -> %s", label_name, created_id)
    return created_id


class GmailHeader(TypedDict):
    name: str
    value: str


class GmailMessage(TypedDict, total=False):
    id: str
    internalDate: str
    snippet: str
    payload: Dict[str, Any]


def get_recent_message_ids(gmail_service: Any, lookback_minutes: int = 60, cap: int = 500) -> List[GmailMessage]:
    """
    Get messages that arrived within lookback_minutes.
    Strategy: ask Gmail for a recent timeframe (e.g. newer_than:1d) to limit,
    then filter by internalDate in code to precise minute granularity.
    """
    user_id = "me"
    start_timestamp = int((datetime.now(timezone.utc) -
                          timedelta(minutes=lookback_minutes)).timestamp())
    query = f"label:inbox after:{start_timestamp}"
    try:
        res = gmail_service.users().messages().list(
            userId=user_id, q=query, maxResults=min(cap, 500)).execute()
    except HttpError as e:
        logging.exception("Gmail list error: %s", e)
        return []

    messages: List[Dict[str, str]] = res.get("messages", []) or []
    # Now fetch message metadata and filter by internalDate
    recent: List[GmailMessage] = []
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
    logging.info("Found %d messages in your inbox from the last %d minutes",
                 len(recent), lookback_minutes)
    return recent


def header_value(headers: Sequence[GmailHeader], name: str) -> str:
    name = name.lower()
    for h in headers:
        if h.get("name", "").lower() == name:
            return h.get("value", "")
    return ""


def message_matches_rule(message: GmailMessage, rule: Rule) -> bool:
    """Check all non-empty fields of rule (AND semantics)."""
    # Bug fix: If all matchers are empty, don't match anything. Without this
    # check, empty rules would match every message (which can cause everything
    # to be marked as read).
    has_any_matcher = (
        bool(rule.get("from_matcher", "").strip()) or
        bool(rule.get("to_matcher", "").strip()) or
        bool(rule.get("subject_matcher", "").strip()) or
        bool(rule.get("body_matcher", "").strip()) or
        rule.get("has_attachment", False)
    )
    if not has_any_matcher:
        return False

    headers: List[GmailHeader] = message.get("payload", {}).get(
        "headers", [])  # type: ignore[assignment]
    from_v = header_value(headers, "From")
    to_v = header_value(headers, "To")
    subject_v = header_value(headers, "Subject")
    snippet = message.get("snippet", "")

    def contains(hay: str, needle: str) -> bool:
        return needle.strip().lower() in (hay or "").lower()

    if rule["from_matcher"] and not contains(from_v, rule["from_matcher"]):
        return False
    if rule["to_matcher"] and not contains(to_v, rule["to_matcher"]):
        return False
    if rule["subject_matcher"] and not contains(subject_v, rule["subject_matcher"]):
        return False
    if rule["body_matcher"] and not contains(snippet, rule["body_matcher"]):
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


def apply_verdicts(
        gmail_service: Any,
        message_ids: List[str],
        verdicts: List[str]
) -> None:
    """Apply verdict operations to messages (batch where possible)."""
    user_id = "me"
    add_label_ids: List[str] = []
    remove_label_ids: List[str] = []
    # We'll collect batch operations per label:
    # labelname -> id (reserved for future use)
    create_label_ids: Dict[str, str] = {}

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
                # Use cache to resolve label id without extra API calls
                lid = _get_label_id_from_cache(gmail_service, label_name)
                if lid:
                    remove_label_ids.append(lid)
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


def get_message_subject(message: GmailMessage) -> str:
    subject = ""
    try:
        payload = message.get("payload", {})
        headers = payload.get("headers", [])
        for h in headers:
            if h.get("name", "").lower() == "subject":
                subject = h.get("value", "")
                break
    except Exception:
        subject = ""

# === Matching in parallel ======================================================


def _safe_int_env(name: str, default: int) -> int:
    try:
        v = int(os.getenv(name, str(default)))
        return v if v > 0 else default
    except Exception:
        return default


def compute_ideal_num_workers(task_len: int) -> int:
    """Derive a sensible default thread count.

    Priority:
    - MATCH_THREADS env var if set and valid (>0)
    - Else base on CPU cores, scaled for I/O-bound work
    - Always cap by number of messages and an upper bound to avoid overload
    """
    # Env override
    env_threads = _safe_int_env("MATCH_THREADS", -1)
    if env_threads > 0:
        return max(1, min(env_threads, max(1, task_len)))

    # Compute from cpu count (I/O bound: allow a multiple)
    try:
        cores = os.cpu_count() or 1
    except Exception:
        cores = 1

    # Heuristic: 4x cores for network-bound matching, but not excessive
    heuristic = max(1, cores * 4)

    # Upper safety cap to avoid creating too many threads
    SAFETY_CAP = 64

    return max(1, min(heuristic, SAFETY_CAP, max(1, task_len)))


def compute_rule_to_matched_ids(
    messages: List[GmailMessage],
    rules: List[Rule],
    workers: int,
) -> Dict[int, List[str]]:
    """Build mapping of rule index -> matched message ids using a thread pool.

    We parallelize over messages to avoid concurrent writes to the same list.
    Each worker computes matches for a single message and returns the indices
    of matching rules, which we aggregate on the main thread.
    """
    if not messages or not rules:
        return {i: [] for i in range(len(rules))}

    def eval_one(msg: GmailMessage) -> List[int]:
        matched: List[int] = []
        subject = get_message_subject(msg)
        logging.info("Handling message id=%s subject=%r",
                     msg.get("id"), subject)
        for idx, rule in enumerate(rules):
            try:
                if message_matches_rule(msg, rule):
                    matched.append(idx)
            except Exception:
                logging.exception(
                    "Error checking message against rule %s", rule.get("name")
                )
        return matched

    out: Dict[int, List[str]] = {i: [] for i in range(len(rules))}

    # Use a bounded thread pool
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_msg = {executor.submit(
            eval_one, msg): msg for msg in messages}
        for fut in as_completed(future_to_msg):
            msg = future_to_msg[fut]
            try:
                matched_rule_idxs = fut.result()
            except Exception:
                logging.exception("Worker failed for message %s", msg.get("id"))
                continue
            msg_id = msg.get("id") or ""
            if not msg_id:
                continue
            for rule_idx in matched_rule_idxs:
                out[rule_idx].append(msg_id)

    return out


def apply_all_verdicts(
    gmail_service: Any,
    rules: List[Rule],
    rule_to_matched_ids: Dict[int, List[str]],
) -> None:
    for rule_idx, matched_msg_ids in rule_to_matched_ids.items():
        if not matched_msg_ids:
            # No messages matched for this rule, skip
            continue
        if rule_idx < 0 or rule_idx >= len(rules):
            logging.warning("Rule index %d out of range", rule_idx)
            continue
        rule = rules[rule_idx]
        verdict_tokens = [v.strip() for v in rule.get(
            "verdict", "").split(";") if v.strip()]
        logging.info(
            "Rule '%s' matched %d messages; verdict=%s",
            rule.get("from_matcher"), len(matched_msg_ids), verdict_tokens
        )
        apply_verdicts(gmail_service, matched_msg_ids, verdict_tokens)

# === Main =====================================================================


def main() -> None:
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

    # Build rule -> matched ids mapping in parallel for speed
    workers = compute_ideal_num_workers(len(recent_messages))
    logging.info("Using %d workers", workers)
    rule_to_matched_ids = compute_rule_to_matched_ids(
        recent_messages, rules, workers
    )

    # Apply verdicts for each rule in parallel
    apply_all_verdicts(
        gmail_service, rules, rule_to_matched_ids)


if __name__ == "__main__":
    main()
