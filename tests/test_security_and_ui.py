"""安全与界面数据相关测试:脚本内容仅作文本、清空、筛选、未加载防护、日志过滤。"""
from __future__ import annotations

import json
import logging

from app.demo import REPEATED_TOKEN, build_demo_har
from app.hario import normalize_entries


def test_script_content_returned_as_plain_text(demo_client) -> None:
    # 条目 #5 是带 <script> 的 HTML 文本
    detail = demo_client.get("/api/entries/5").json()
    body_text = detail["response"]["body"]["text"]
    assert "<script>" in body_text  # 原样作为文本字段返回
    assert REPEATED_TOKEN in body_text or "xss-test" in body_text
    # 响应 Content-Type 是 JSON,前端再以 textContent 渲染,脚本不可能执行
    resp = demo_client.get("/api/entries/5")
    assert resp.headers["content-type"].startswith("application/json")


def test_frontend_uses_text_content_only() -> None:
    # 静态审查前端代码:数据渲染不得使用 innerHTML/outerHTML/document.write/eval 等
    # 危险 API(匹配实际调用形态,避免命中注释里的说明文字)
    js = open("static/app.js", encoding="utf-8").read().splitlines()
    code = "\n".join(
        line for line in js if not line.lstrip().startswith(("*", "//", "/*"))
    )
    forbidden = [
        ".innerHTML", ".outerHTML", "document.write",
        "insertAdjacentHTML", "eval(", "setTimeout('", 'setTimeout("',
    ]
    for token in forbidden:
        assert token not in code, f"前端出现危险 API:{token}"


def test_clear_removes_all_session_data(demo_client) -> None:
    assert demo_client.get("/api/state").json()["loaded"] is True
    assert demo_client.delete("/api/clear").status_code == 200
    state = demo_client.get("/api/state").json()
    assert state["loaded"] is False
    assert state["entry_count"] == 0
    # 清空后导出应被拒绝
    assert demo_client.get("/api/export/har").status_code == 400
    assert demo_client.get("/api/export/summary").status_code == 400
    # 自定义规则清空,内置规则恢复默认
    rules = demo_client.get("/api/rules").json()["rules"]
    assert all(r["builtin"] for r in rules)


def test_keyword_filter(demo_client) -> None:
    all_entries = demo_client.get("/api/entries").json()["entries"]
    filtered = demo_client.get("/api/entries?keyword=profile").json()["entries"]
    assert 0 < len(filtered) < len(all_entries)
    assert all("profile" in m["url"] for m in filtered if not m["broken"])
    # 状态码筛选
    by_status = demo_client.get("/api/entries?keyword=201").json()["entries"]
    assert all(m["status"] == 201 for m in by_status if not m["broken"])
    # 坏条目也能被错误关键词筛出
    broken = demo_client.get("/api/entries?keyword=request").json()["entries"]
    assert any(m["broken"] for m in broken)


def test_export_requires_loaded_file(client) -> None:
    assert client.get("/api/export/har").status_code == 400
    assert client.get("/api/findings").json()["findings"] == []


def test_demo_download_is_valid_har(demo_client) -> None:
    resp = demo_client.get("/api/demo/download")
    assert resp.status_code == 200
    doc = json.loads(resp.content)
    entries = normalize_entries(build_demo_har())
    assert len(doc["log"]["entries"]) == len(entries)


def test_access_log_strips_query_string() -> None:
    from app.main import _QueryStringFilter

    flt = _QueryStringFilter()
    # 模拟 uvicorn 真实结构:msg 为格式串,路径在 args 下标 2
    record = logging.LogRecord(
        name="uvicorn.access", level=logging.INFO, pathname="", lineno=0,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:1", "GET", "/api/entries?token=SECRET-abc123&x=1", "1.1", 200),
        exc_info=None,
    )
    assert flt.filter(record) is True
    rendered = record.getMessage()
    assert "SECRET-abc123" not in rendered
    assert "<query-stripped>" in rendered
    # 无查询串的请求不受影响
    clean = logging.LogRecord(
        name="uvicorn.access", level=logging.INFO, pathname="", lineno=0,
        msg="%s", args=("/api/state",), exc_info=None,
    )
    flt.filter(clean)
    assert clean.getMessage() == "/api/state"


def test_reveal_endpoint_returns_raw_only_on_demand(demo_client) -> None:
    findings = demo_client.get("/api/findings").json()["findings"]
    fid = findings[0]["id"]
    # 列表不含原文
    assert "raw_value" not in findings[0]
    # reveal 才返回
    raw = demo_client.get(f"/api/findings/{fid}/reveal").json()["raw_value"]
    assert isinstance(raw, str) and raw
    # 不存在的 id 返回 404
    assert demo_client.get("/api/findings/nope/reveal").status_code == 404


def test_invalid_treatment_rejected(demo_client) -> None:
    fid = demo_client.get("/api/findings").json()["findings"][0]["id"]
    resp = demo_client.post("/api/findings/treatment", json={
        "finding_ids": [fid], "treatment": "explode",
    })
    assert resp.status_code in (400, 422)
