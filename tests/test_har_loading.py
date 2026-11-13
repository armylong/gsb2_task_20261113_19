"""HAR 加载与坏条目处理。"""
from __future__ import annotations

import json

from app.hario import HarLoadError, load_har, normalize_entries


def test_load_rejects_non_json() -> None:
    try:
        load_har(b"this is not json {{{")
    except HarLoadError as exc:
        assert "JSON 解析失败" in str(exc)
    else:
        raise AssertionError("应当抛出 HarLoadError")


def test_load_rejects_wrong_structure() -> None:
    try:
        load_har(json.dumps({"foo": 1}).encode())
    except HarLoadError as exc:
        assert "log" in str(exc)
    else:
        raise AssertionError("应当抛出 HarLoadError")


def test_load_rejects_missing_entries() -> None:
    try:
        load_har(json.dumps({"log": {}}).encode())
    except HarLoadError as exc:
        assert "entries" in str(exc)
    else:
        raise AssertionError("应当抛出 HarLoadError")


def test_broken_entry_marked_but_others_survive() -> None:
    har = {
        "log": {
            "version": "1.2",
            "entries": [
                {"not-an-entry": True},
                {
                    "request": {"method": "GET", "url": "https://x.test/a", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {}},
                },
                {"request": "broken-without-request"},
            ],
        }
    }
    entries = normalize_entries(har)
    assert entries[0]["_broken"] is True
    assert entries[1]["_broken"] is False
    assert entries[2]["_broken"] is True


def test_upload_bad_file_keeps_current_workspace(demo_client) -> None:
    before = demo_client.get("/api/state").json()
    resp = demo_client.post(
        "/api/upload",
        files={"file": ("bad.har", b"not-json", "application/json")},
    )
    assert resp.status_code == 400
    assert "JSON" in resp.json()["detail"]
    after = demo_client.get("/api/state").json()
    # 已打开的文件、条目数与来源名都保留
    assert after["loaded"] is True
    assert after["entry_count"] == before["entry_count"]
    assert after["source_name"] == before["source_name"]


def test_upload_valid_har(demo_client) -> None:
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://x.test/a", "headers": []},
         "response": {"status": 200, "headers": [], "content": {}}},
    ]}}
    resp = demo_client.post(
        "/api/upload",
        files={"file": ("x.har", json.dumps(har).encode(), "application/json")},
    )
    assert resp.status_code == 200
    assert resp.json()["entry_count"] == 1
