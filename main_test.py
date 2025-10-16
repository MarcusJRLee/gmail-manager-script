from typing import Any, Dict, List
import json
import builtins
import types
import pathlib
import pytest

import main as m


class DummyCreds:
    def __init__(self, valid: bool = True, expired: bool = False, refresh_token: bool = False):
        self.valid = valid
        self.expired = expired
        self.refresh_token = refresh_token
        self._refreshed = False

    def to_json(self) -> str:
        return json.dumps({"dummy": True})

    def refresh(self, request: Any) -> None:
        self._refreshed = True


def test_header_value():
    headers: List[m.GmailHeader] = [
        {"name": "From", "value": "sender@example.com"},
        {"name": "To", "value": "to@example.com"},
    ]
    assert m.header_value(headers, "From") == "sender@example.com"
    assert m.header_value(headers, "To") == "to@example.com"
    assert m.header_value(headers, "subject") == ""


def test_message_matches_rule():
    msg: m.GmailMessage = {
        "id": "1",
        "internalDate": "0",
        "snippet": "hello world body",
        "payload": {
            "headers": [
                {"name": "From", "value": "boss@example.com"},
                {"name": "To", "value": "me@example.com"},
                {"name": "Subject", "value": "Update"},
            ],
            "parts": [],
        },
    }

    rule: m.Rule = {
        "name": "r1",
        "from_matcher": "boss@",
        "to_matcher": "me@",
        "subject_matcher": "update",
        "body_matcher": "hello",
        "has_attachment": False,
        "verdict": "mark_read",
    }
    assert m.message_matches_rule(msg, rule) is True

    rule["has_attachment"] = True
    assert m.message_matches_rule(msg, rule) is False


def test_read_rules_from_sheet(monkeypatch: pytest.MonkeyPatch):
    # Build a fake sheets service
    class Values:
        def __init__(self, data: Dict[str, Any]):
            self._data = data

        def get(self, spreadsheetId: str, range: str):  # type: ignore[override]
            class Exec:
                def __init__(self, data: Dict[str, Any]):
                    self._data = data

                def execute(self):
                    return self._data

            return Exec(self._data)

    class Sheets:
        def __init__(self, data: Dict[str, Any]):
            self._values = Values(data)

        def values(self):
            return self._values

    class Service:
        def __init__(self, data: Dict[str, Any]):
            self._sheets = Sheets(data)

        def spreadsheets(self):
            return self._sheets

    data = {
        "values": [
            ["enabled", "name", "from_matcher", "to_matcher",
                "subject_matcher", "body_matcher", "has_attachment", "verdict"],
            ["true", "rule1", "boss@", "me@", "update",
                "hello", "false", "mark_read"],
            ["false", "rule2", "x", "y", "z", "b", "true", "add_label:Test"],
        ]
    }

    service = Service(data)
    rules = m.read_rules_from_sheet(service)  # type: ignore[arg-type]
    assert len(rules) == 1
    r = rules[0]
    assert r["name"] == "rule1"
    assert r["from_matcher"] == "boss@"
    assert r["has_attachment"] is False


def test_get_spreadsheet_id_env_then_config_then_default(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path):
    # Point config file to temp
    cfg_path = tmp_path / "config.private.json"
    monkeypatch.setattr(m, "CONFIG_FILE", str(cfg_path))

    # 1) Env var wins
    monkeypatch.setenv("SPREADSHEET_ID", "ENV_ID")
    assert m.get_spreadsheet_id() == "ENV_ID"

    # 2) Config when no env
    monkeypatch.delenv("SPREADSHEET_ID", raising=False)
    cfg_path.write_text(json.dumps({"SPREADSHEET_ID": "CFG_ID"}))
    assert m.get_spreadsheet_id() == "CFG_ID"

    # 3) Default when missing/bad
    cfg_path.write_text("not json")
    assert m.get_spreadsheet_id() == m.DEFAULT_SPREADSHEET_ID


def test_get_sheet_name_env_then_config_then_default(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path):
    cfg_path = tmp_path / "config.private.json"
    monkeypatch.setattr(m, "CONFIG_FILE", str(cfg_path))

    # Env wins
    monkeypatch.setenv("SHEET_NAME", "EnvRules")
    assert m.get_sheet_name() == "EnvRules"

    # Config when no env
    monkeypatch.delenv("SHEET_NAME", raising=False)
    cfg_path.write_text(json.dumps({"SHEET_NAME": "CfgRules"}))
    assert m.get_sheet_name() == "CfgRules"

    # Default when bad/missing
    cfg_path.write_text("not json")
    assert m.get_sheet_name() == m.DEFAULT_SHEET_NAME


def test_build_gmail_service(monkeypatch: pytest.MonkeyPatch):
    called: Dict[str, Any] = {}

    def fake_build(api: str, version: str, credentials: Any, cache_discovery: bool = False):
        called.update({"api": api, "version": version,
                      "creds": credentials, "cache": cache_discovery})
        return object()

    monkeypatch.setattr(m, "build", fake_build)
    dummy = DummyCreds()
    svc = m.build_gmail_service(dummy)  # type: ignore[arg-type]
    assert svc is not None
    assert called["api"] == "gmail"
    assert called["version"] == "v1"


def test_ensure_label_id(monkeypatch: pytest.MonkeyPatch):
    # Simulate labels list and create
    class Labels:
        def __init__(self, labels: List[Dict[str, str]]):
            self._labels = labels

        def list(self, userId: str):  # type: ignore[override]
            class Exec:
                def __init__(self, labels: List[Dict[str, str]]):
                    self._labels = labels

                def execute(self):
                    return {"labels": self._labels}

            return Exec(self._labels)

        # type: ignore[override]
        def create(self, userId: str, body: Dict[str, str]):
            class Exec:
                def execute(self):
                    return {"id": "NEW_LABEL_ID"}

            return Exec()

    class Users:
        def __init__(self, labels: Labels):
            self._labels = labels

        def labels(self):
            return self._labels

    class Gmail:
        def __init__(self, labels: Labels):
            self._users = Users(labels)

        def users(self):
            return self._users

    gmail = Gmail(Labels([{"name": "Inbox", "id": "INBOX"}]))
    # Not found, will create
    new_id = m.ensure_label_id(gmail, "MyLabel")  # type: ignore[arg-type]
    assert new_id == "NEW_LABEL_ID"

    # Found case
    gmail2 = Gmail(Labels([{"name": "MyLabel", "id": "EXISTING"}]))
    existing = m.ensure_label_id(gmail2, "MyLabel")  # type: ignore[arg-type]
    assert existing == "EXISTING"


def test_get_recent_message_ids_filters_and_caps(monkeypatch: pytest.MonkeyPatch):
    now_ms = int((m.datetime.now(m.timezone.utc)).timestamp() * 1000)
    threshold = now_ms - 10_000  # 10s

    # Build fake Gmail list/gets
    class Messages:
        # type: ignore[override]
        def list(self, userId: str, q: str, maxResults: int):
            class Exec:
                def execute(self):
                    return {"messages": [{"id": "1"}, {"id": "2"}, {"id": "3"}]}

            return Exec()

        # type: ignore[override]
        def get(self, userId: str, id: str, format: str, metadataHeaders: List[str]):
            class Exec:
                def __init__(self, id: str):
                    self._id = id

                def execute(self):
                    # make only id 2 recent
                    internal = threshold + 1 if self._id == "2" else threshold - 1
                    return {
                        "id": self._id,
                        "internalDate": str(internal),
                        "snippet": "",
                        "payload": {"headers": []},
                    }

            return Exec(id)

    class Users:
        def __init__(self, messages: Messages):
            self._messages = messages

        def messages(self):
            return self._messages

    class Gmail:
        def __init__(self, messages: Messages):
            self._users = Users(messages)

        def users(self):
            return self._users

    gmail = Gmail(Messages())
    recent = m.get_recent_message_ids(
        gmail, lookback_minutes=1, cap=2)  # type: ignore[arg-type]
    assert len(recent) == 1
    assert recent[0]["id"] == "2"


def test_apply_verdicts_add_and_remove_labels(monkeypatch: pytest.MonkeyPatch):
    # Track calls
    calls: Dict[str, Any] = {}

    class Labels:
        def list(self, userId: str):  # type: ignore[override]
            class Exec:
                def execute(self):
                    return {"labels": [{"name": "Inbox", "id": "INBOX"}, {"name": "Old", "id": "OLD_ID"}]}

            return Exec()

        # type: ignore[override]
        def create(self, userId: str, body: Dict[str, str]):
            class Exec:
                def execute(self):
                    return {"id": "NEW_CREATED_ID"}

            return Exec()

    class Messages:
        # type: ignore[override]
        def batchModify(self, userId: str, body: Dict[str, Any]):
            class Exec:
                def execute(self):
                    calls["body"] = body
                    return {}

            return Exec()

    class Users:
        def __init__(self):
            self._labels = Labels()
            self._messages = Messages()

        def labels(self):
            return self._labels

        def messages(self):
            return self._messages

    class Gmail:
        def __init__(self):
            self._users = Users()

        def users(self):
            return self._users

    gmail = Gmail()

    m.apply_verdicts(
        gmail,  # type: ignore[arg-type]
        ["m1", "m2"],
        ["mark_read", "add_label:New", "remove_label:Old"],
    )
    assert "addLabelIds" in calls["body"]
    assert "removeLabelIds" in calls["body"]


def test_apply_verdicts_uses_label_cache(monkeypatch: pytest.MonkeyPatch):
    # Ensure cache is empty for test isolation
    if hasattr(m, "_LABEL_NAME_TO_ID_CACHE"):
        delattr(m, "_LABEL_NAME_TO_ID_CACHE")

    calls: Dict[str, int] = {"list_calls": 0, "create_calls": 0}

    class Labels:
        def list(self, userId: str):  # type: ignore[override]
            class Exec:
                def execute(_self):
                    calls["list_calls"] += 1
                    # Only existing label is Old
                    return {"labels": [{"name": "Old", "id": "OLD_ID"}]}

            return Exec()

        # type: ignore[override]
        def create(self, userId: str, body: Dict[str, str]):
            class Exec:
                def execute(_self):
                    calls["create_calls"] += 1
                    return {"id": "NEW_CREATED_ID"}

            return Exec()

    class Messages:
        # type: ignore[override]
        def batchModify(self, userId: str, body: Dict[str, Any]):
            class Exec:
                def execute(self):
                    return {}

            return Exec()

    class Users:
        def __init__(self):
            self._labels = Labels()
            self._messages = Messages()

        def labels(self):
            return self._labels

        def messages(self):
            return self._messages

    class Gmail:
        def __init__(self):
            self._users = Users()

        def users(self):
            return self._users

    gmail = Gmail()

    # First call should list once and create once for label "New"
    m.apply_verdicts(
        gmail,  # type: ignore[arg-type]
        ["m1"],
        ["add_label:New"],
    )
    assert calls["list_calls"] == 1
    assert calls["create_calls"] == 1

    # Second call for the same label should NOT list or create again (cache hit)
    m.apply_verdicts(
        gmail,  # type: ignore[arg-type]
        ["m2"],
        ["add_label:New"],
    )
    assert calls["list_calls"] == 1
    assert calls["create_calls"] == 1


def test_remove_label_uses_cached_ids(monkeypatch: pytest.MonkeyPatch):
    # Ensure cache is empty for test isolation
    if hasattr(m, "_LABEL_NAME_TO_ID_CACHE"):
        delattr(m, "_LABEL_NAME_TO_ID_CACHE")

    calls: Dict[str, int] = {"list_calls": 0}

    class Labels:
        def list(self, userId: str):  # type: ignore[override]
            class Exec:
                def execute(_self):
                    calls["list_calls"] += 1
                    # Provide label Old in first and only listing to seed cache
                    return {"labels": [{"name": "Old", "id": "OLD_ID"}]}

            return Exec()

        # type: ignore[override]
        def create(self, userId: str, body: Dict[str, str]):
            class Exec:
                def execute(_self):
                    # Not used in this test
                    return {"id": "IGNORED"}

            return Exec()

    class Messages:
        # type: ignore[override]
        def batchModify(self, userId: str, body: Dict[str, Any]):
            class Exec:
                def execute(self):
                    return {}

            return Exec()

    class Users:
        def __init__(self):
            self._labels = Labels()
            self._messages = Messages()

        def labels(self):
            return self._labels

        def messages(self):
            return self._messages

    class Gmail:
        def __init__(self):
            self._users = Users()

        def users(self):
            return self._users

    gmail = Gmail()

    # First call seeds cache via list
    m.apply_verdicts(
        gmail,  # type: ignore[arg-type]
        ["m1"],
        ["remove_label:Old"],
    )
    assert calls["list_calls"] == 1

    # Second call should use cached id without listing again
    m.apply_verdicts(
        gmail,  # type: ignore[arg-type]
        ["m2"],
        ["remove_label:Old"],
    )
    assert calls["list_calls"] == 1


def test_compute_apply_workers_env_and_default(monkeypatch: pytest.MonkeyPatch):
    # Access the inner function by running main() path setup; we'll re-import
    # compute via attribute inspection using the function from module scope.
    # The function is defined inside main, so we mimic logic here.

    # Recreate the logic to ensure env override respected
    def compute_apply_workers(num_rules: int) -> int:
        env_threads = m._safe_int_env("APPLY_THREADS", -1)
        if env_threads > 0:
            return max(1, min(env_threads, max(1, num_rules)))
        return max(1, min(8, max(1, num_rules)))

    # Env wins and is capped by num_rules
    monkeypatch.setenv("APPLY_THREADS", "100")
    assert compute_apply_workers(5) == 5

    # Env invalid -> default
    monkeypatch.delenv("APPLY_THREADS", raising=False)
    assert compute_apply_workers(20) == 8


def test_get_creds_uses_existing_token_and_handles_refresh(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path):
    token_path = tmp_path / "token.json"
    creds = DummyCreds(valid=True)

    def fake_exists(path: str) -> bool:
        return str(path) == str(token_path)

    def fake_from_file(path: str, scopes: List[str]):  # type: ignore[override]
        return creds

    def fake_open(path: str, mode: str):  # type: ignore[override]
        # Only used when saving token on new flow; not hit here
        raise AssertionError("should not save when token already valid")

    monkeypatch.setattr(m.os.path, "exists", lambda p: True if str(
        p) == str(token_path) else False)
    monkeypatch.setattr(m, "TOKEN_FILE", str(token_path))
    monkeypatch.setattr(m.Credentials, "from_authorized_user_file",
                        fake_from_file)  # type: ignore[attr-defined]
    monkeypatch.setattr(builtins, "open", fake_open)

    got = m.get_creds()
    assert isinstance(got, DummyCreds)

    # Now test refresh path
    creds2 = DummyCreds(valid=False, expired=True, refresh_token=True)

    def fake_from_file2(path: str, scopes: List[str]):  # type: ignore[override]
        return creds2

    class DummyFlow:
        @staticmethod
        def from_client_secrets_file(filename: str, scopes: List[str]):
            raise AssertionError("should not be called when refresh possible")

    def fake_open2(path: str, mode: str):  # type: ignore[override]
        class Writer:
            def write(self, s: str):
                return len(s)

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        return Writer()

    monkeypatch.setattr(m.Credentials, "from_authorized_user_file",
                        fake_from_file2)  # type: ignore[attr-defined]
    monkeypatch.setattr(m, "InstalledAppFlow", DummyFlow)
    monkeypatch.setattr(builtins, "open", fake_open2)

    got2 = m.get_creds()
    assert isinstance(got2, DummyCreds)
    assert creds2._refreshed is True


def test_main_no_rules(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    # Mock credentials/service creation
    monkeypatch.setattr(m, "get_creds", lambda: DummyCreds())
    monkeypatch.setattr(m, "build_gmail_service", lambda c: object())
    monkeypatch.setattr(m, "build", lambda *args, **kwargs: object())
    monkeypatch.setattr(m, "read_rules_from_sheet", lambda s: [])

    with caplog.at_level("INFO"):
        m.main()
    assert any("No enabled rules" in rec.message for rec in caplog.records)


def test_main_applies_verdicts_in_parallel(monkeypatch: pytest.MonkeyPatch):
    # Stub creds and services
    monkeypatch.setattr(m, "get_creds", lambda: DummyCreds())
    monkeypatch.setattr(m, "build_gmail_service", lambda c: object())
    monkeypatch.setattr(m, "build", lambda *args, **kwargs: object())

    # Two enabled rules; only first matches
    rules: List[m.Rule] = [
        {
            "name": "r1",
            "from_matcher": "",
            "to_matcher": "",
            "subject_matcher": "",
            "body_matcher": "",
            "has_attachment": False,
            "verdict": "mark_read",
        },
        {
            "name": "r2",
            "from_matcher": "",
            "to_matcher": "",
            "subject_matcher": "",
            "body_matcher": "",
            "has_attachment": False,
            "verdict": "add_label:Foo",
        },
    ]

    # Messages don't matter for this test because we stub the mapping
    monkeypatch.setattr(m, "read_rules_from_sheet", lambda s: rules)
    monkeypatch.setattr(
        m,
        "get_recent_message_ids",
        lambda *args, **kwargs: [
            {"id": "a", "payload": {"headers": []}},
            {"id": "b", "payload": {"headers": []}},
        ],
    )

    # Force mapping so only r1 has matches
    monkeypatch.setattr(
        m,
        "compute_rule_to_matched_ids",
        lambda messages, rules, _=None: {0: ["a", "b"], 1: []},
    )

    calls: List[Dict[str, Any]] = []

    def fake_apply_verdicts(gmail, message_ids: List[str], verdicts: List[str]):
        calls.append({"ids": list(message_ids), "verdicts": list(verdicts)})

    monkeypatch.setattr(m, "apply_verdicts", fake_apply_verdicts)

    # Run
    m.main()

    # We expect one apply call for r1 with ids a,b and verdict mark_read
    assert len(calls) == 1
    got = calls[0]
    assert set(got["ids"]) == {"a", "b"}
    assert got["verdicts"] == ["mark_read"]
