"""敏感内容检测:位置覆盖、大小写不敏感、重复参数、多规则聚合与未检查项。"""
from __future__ import annotations

import base64
import json


def _har(entries: list[dict]) -> dict:
    return {"log": {"version": "1.2", "entries": entries}}


def _entry(
    url: str = "https://x.test/a",
    req_headers: list[dict] | None = None,
    resp_headers: list[dict] | None = None,
    post: dict | None = None,
    content: dict | None = None,
    method: str = "GET",
    status: int = 200,
) -> dict:
    request: dict = {
        "method": method,
        "url": url,
        "headers": req_headers or [],
        "queryString": [],
    }
    if post:
        request["postData"] = post
    return {
        "request": request,
        "response": {
            "status": status,
            "headers": resp_headers or [],
            "content": content or {},
        },
    }


def _scan(client, har):
    resp = client.post(
        "/api/upload",
        files={"file": ("t.har", json.dumps(har).encode(), "application/json")},
    )
    assert resp.status_code == 200
    return client.get("/api/findings").json()


def test_authorization_headers_case_insensitive(client) -> None:
    har = _har([_entry(req_headers=[
        {"name": "AUTHORIZATION", "value": "Bearer abcdef123456"},
        {"name": "Proxy-Authorization", "value": "Basic dXNlcjpwdw=="},
    ])])
    data = _scan(client, har)
    locs = {(f["location"], f["target"]["header_name"].lower()) for f in data["findings"]}
    assert ("request_header", "authorization") in locs
    assert ("request_header", "proxy-authorization") in locs


def test_custom_api_key_header_case_insensitive(client) -> None:
    har = _har([_entry(req_headers=[
        {"name": "X-Custom-APIKEY", "value": "k-987654321"},
        {"name": "x-access-token", "value": "tok-abcdef123456"},
    ])])
    data = _scan(client, har)
    header_names = {
        f["target"]["header_name"].lower()
        for f in data["findings"]
        if f["target"]["kind"] == "header"
    }
    assert "x-custom-apikey" in header_names
    assert "x-access-token" in header_names


def test_cookie_each_subfield_checked_and_aggregated(client) -> None:
    har = _har([_entry(req_headers=[
        {"name": "Cookie", "value": "sid=secret-sid-1234; theme=dark; sid2=another-secret-9999"},
    ])])
    data = _scan(client, har)
    cookie_names = {
        f["target"]["name"]
        for f in data["findings"]
        if f["target"]["kind"] == "cookie"
    }
    # 同名/不同名的每个 cookie 子项都要检查
    assert cookie_names == {"sid", "theme", "sid2"}


def test_set_cookie_subfields(client) -> None:
    har = _har([_entry(resp_headers=[
        {"name": "Set-Cookie", "value": "refresh=refresh-value-5678; Path=/; HttpOnly"},
    ])])
    data = _scan(client, har)
    assert any(
        f["location"] == "response_header" and f["target"]["name"] == "refresh"
        for f in data["findings"]
    )


def test_repeated_query_params_all_checked(client) -> None:
    har = _har([_entry(url="https://x.test/a?token=tok-one-1111&token=tok-two-2222&x=1")])
    data = _scan(client, har)
    token_hits = [
        f for f in data["findings"]
        if f["location"] == "query" and f["target"]["name"] == "token"
    ]
    assert len(token_hits) == 2
    indices = {f["target"]["index"] for f in token_hits}
    assert indices == {0, 1}


def test_sensitive_field_names_in_nested_json(client) -> None:
    body = json.dumps({
        "outer": {
            "Password": "p@ss",
            "list": [{"apiKey": "key-12345678"}, {"n": 1}],
        },
        "EMAIL": "u@example.test",
    })
    har = _har([_entry(
        method="POST",
        post={"mimeType": "application/json", "text": body},
    )])
    data = _scan(client, har)
    paths = {tuple(f["target"]["path"]) for f in data["findings"]
             if f["location"] == "request_body"}
    assert ("outer", "Password") in paths
    assert ("outer", "list", 0, "apiKey") in paths
    assert ("EMAIL",) in paths


def test_form_repeated_params(client) -> None:
    har = _har([_entry(
        method="POST",
        post={
            "mimeType": "application/x-www-form-urlencoded",
            "text": "password=p1&password=p2&normal=keep",
        },
    )])
    data = _scan(client, har)
    pwd_hits = [f for f in data["findings"]
                if f["location"] == "request_body" and f["target"]["name"] == "password"]
    assert len(pwd_hits) == 2
    assert {f["target"]["index"] for f in pwd_hits} == {0, 1}


def test_email_and_mobile_in_text_body(client) -> None:
    text = "联系人 alice@example.test 与 13800138000,另一人 bob@example.org"
    har = _har([_entry(content={"mimeType": "text/plain", "text": text})])
    data = _scan(client, har)
    # 2 个邮箱 + 1 个手机号(纯文本按区间命中)
    rules_hit = {rn for f in data["findings"] for rn in f["rule_names"]}
    assert any("邮箱" in r for r in rules_hit)
    assert any("手机号" in r for r in rules_hit)
    assert len(data["findings"]) >= 3
    assert all(f["target"]["kind"] == "text" for f in data["findings"])


def test_binary_response_marked_unchecked(client) -> None:
    png = b"\x89PNG\r\n\x1a\n\x00\x00binary"
    har = _har([_entry(content={
        "mimeType": "image/png",
        "text": base64.b64encode(png).decode(),
        "encoding": "base64",
    })])
    data = _scan(client, har)
    assert len(data["findings"]) == 0
    assert len(data["unchecked"]) == 1
    assert "二进制" in data["unchecked"][0]["reason"]
    assert data["unchecked"][0]["location"] == "response_body"


def test_invalid_base64_marked_unchecked(client) -> None:
    har = _har([_entry(content={
        "mimeType": "text/plain",
        "text": "@@@not-base64@@@",
        "encoding": "base64",
    })])
    data = _scan(client, har)
    assert any(u["reason"].startswith("base64") for u in data["unchecked"])


def test_malformed_json_marked_unchecked_but_text_still_scanned(client) -> None:
    har = _har([_entry(content={
        "mimeType": "application/json",
        "text": '{"email": "leak@example.test", broken}',
    })])
    data = _scan(client, har)
    assert any(u["location"] == "response_body" for u in data["unchecked"])
    # 文本兜底扫描仍应发现邮箱
    assert any(f["location"] == "response_body" for f in data["findings"])


def test_multiple_rules_same_target_produce_one_finding(client) -> None:
    # 字段名含 email 且值也是邮箱:字段名规则与邮箱正则聚合为一条
    body = json.dumps({"email": "alice@example.test"})
    har = _har([_entry(
        method="POST",
        post={"mimeType": "application/json", "text": body},
    )])
    data = _scan(client, har)
    target_hits = [
        f for f in data["findings"]
        if tuple(f["target"]["path"]) == ("email",) and f["target"]["start"] < 0
    ]
    assert len(target_hits) == 1
    assert len(target_hits[0]["rule_ids"]) >= 1


def test_plain_text_request_body_redacts_value_only(client) -> None:
    har = _har([_entry(
        method="POST",
        req_headers=[{"name": "Content-Type", "value": "text/plain"}],
        post={"mimeType": "text/plain",
              "text": 'session_token="abcdef1234567890" and stuff'},
    )])
    data = _scan(client, har)
    assert any(
        f["location"] == "request_body" and f["target"]["kind"] == "text"
        for f in data["findings"]
    )
    preview = client.get("/api/entries/0/preview").json()
    text = preview["request"]["body"]["text"]
    assert "abcdef1234567890" not in text
    assert "session_token" in text  # 字段名保留,只替换值部分


def test_default_list_response_masks_raw_values(client) -> None:
    har = _har([_entry(req_headers=[{"name": "Authorization", "value": "Bearer secrettoken123"}])])
    _scan(client, har)
    findings = client.get("/api/findings").json()["findings"]
    for f in findings:
        assert "raw_value" not in f
        assert "secrettoken123" not in f["value_preview"]
    # 主动 reveal 才能拿到原文
    fid = findings[0]["id"]
    revealed = client.get(f"/api/findings/{fid}/reveal").json()
    assert "secrettoken123" in revealed["raw_value"]
