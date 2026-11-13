"""脱敏处理与导出:三种处理方式、一致化代号、正文往返、长度更新与摘要防泄漏。"""
from __future__ import annotations

import base64
import json

from app.demo import (
    REPEATED_EMAIL,
    REPEATED_MOBILE,
    REPEATED_SESSION,
    REPEATED_TOKEN,
    build_demo_har,
)
from app.hario import normalize_entries
from app.session import Workspace

DEMO_SECRETS = (
    REPEATED_TOKEN,
    REPEATED_EMAIL,
    REPEATED_MOBILE,
    REPEATED_SESSION,
    "Pa55w0rd-demo!",
    "form-pwd-42",
    "13912345678",
    "csrf-demo-aaaa",
    "trace-demo-001",
)


def _demo_ws() -> Workspace:
    ws = Workspace()
    doc = build_demo_har()
    normalize_entries(doc)
    ws.load(doc, "demo.har")
    return ws


def test_demo_loads_and_flags_broken_entry() -> None:
    ws = _demo_ws()
    entries = ws.entries()
    assert len(entries) == 7
    assert entries[6]["_broken"] is True
    assert ws.scan_status()["finding_count"] > 20
    # 二进制响应必须列为未检查
    unchecked_locs = {(u.entry_index, u.location) for u in ws.unchecked}
    assert (4, "response_body") in unchecked_locs


def test_mask_is_default_and_redacts_every_location() -> None:
    ws = _demo_ws()
    out = json.dumps(ws.sanitized()["har"], ensure_ascii=False)
    for secret in DEMO_SECRETS:
        assert secret not in out, f"默认遮盖仍泄漏:{secret}"


def test_pseudo_same_value_same_code_across_requests() -> None:
    ws = _demo_ws()
    ws.set_treatment([f.id for f in ws.findings], "pseudo", True)
    value_to_code: dict[str, str] = {}
    for f in ws.findings:
        value_to_code.setdefault(f.raw_value, f.pseudo_code)
        assert f.pseudo_code == value_to_code[f.raw_value]
    # 不同原值不能共用代号
    assert len(set(value_to_code.values())) == len(value_to_code)
    # 同一 token 跨请求/跨位置(头、查询、表单、HTML 文本)代号一致
    token_codes = {
        f.pseudo_code for f in ws.findings if f.raw_value == REPEATED_TOKEN
    }
    assert len(token_codes) == 1
    token_locs = {f.target.location for f in ws.findings
                  if f.raw_value == REPEATED_TOKEN}
    assert len(token_locs) >= 3


def test_pseudo_export_has_no_raw_values() -> None:
    ws = _demo_ws()
    ws.set_treatment([f.id for f in ws.findings], "pseudo", True)
    out = json.dumps(ws.sanitized()["har"], ensure_ascii=False)
    for secret in DEMO_SECRETS:
        assert secret not in out


def test_placeholder_is_literal_not_percent_encoded() -> None:
    ws = _demo_ws()
    # 默认 mask 处理,查询与表单中的占位符应保持字面 [REDACTED]
    entry1 = ws.sanitized()["har"]["log"]["entries"][1]
    assert "token=[REDACTED]" in entry1["request"]["url"]
    assert "%5BREDACTED%5D" not in entry1["request"]["url"]
    form_text = ws.sanitized()["har"]["log"]["entries"][2]["request"]["postData"]["text"]
    assert "[REDACTED]" in form_text
    assert "%5BREDACTED%5D" not in form_text


def test_delete_query_param_keeps_other_params() -> None:
    ws = _demo_ws()
    targets = [f for f in ws.findings
               if f.entry_index == 1 and f.target.location == "query"
               and f.target.name == "token"]
    ws.set_treatment([f.id for f in targets], "delete", True)
    url = ws.sanitized()["har"]["log"]["entries"][1]["request"]["url"]
    assert "token=" not in url
    assert "tag=1" in url and "tag=2" in url  # 重复参数保留
    assert "tag" in json.dumps(
        ws.sanitized()["har"]["log"]["entries"][1]["request"]["queryString"]
    )


def test_delete_form_param_keeps_repeats_and_chinese() -> None:
    ws = _demo_ws()
    targets = [f for f in ws.findings
               if f.entry_index == 2 and f.target.kind == "form"
               and f.target.name == "password"]
    ws.set_treatment([f.id for f in targets], "delete", True)
    post = ws.sanitized()["har"]["log"]["entries"][2]["request"]["postData"]
    assert "password=" not in post["text"]
    assert post["text"].count("item=") == 2
    assert "addr=beijing" in post["text"]
    # HAR params 镜像同步,且保留重复项
    assert [p["name"] for p in post["params"]].count("item") == 2
    assert all(p["name"] != "password" for p in post["params"])


def test_delete_single_cookie_keeps_siblings() -> None:
    ws = _demo_ws()
    trace = [f for f in ws.findings
             if f.entry_index == 1 and f.target.kind == "cookie"
             and f.target.name == "trace"]
    ws.set_treatment([f.id for f in trace], "delete", True)
    entry = ws.sanitized()["har"]["log"]["entries"][1]
    cookie = next(
        h["value"] for h in entry["request"]["headers"]
        if h["name"].lower() == "cookie"
    )
    assert "trace" not in cookie
    assert "session=" in cookie and "theme=" in cookie
    # 镜像 cookies 同步
    assert all(c["name"] != "trace" for c in entry["request"]["cookies"])
    assert {c["name"] for c in entry["request"]["cookies"]} == {"session", "theme"}


def test_delete_one_set_cookie_keeps_other_header() -> None:
    ws = _demo_ws()
    sess = [f for f in ws.findings
            if f.entry_index == 0 and f.target.kind == "cookie"
            and f.target.name == "session"]
    ws.set_treatment([f.id for f in sess], "delete", True)
    entry = ws.sanitized()["har"]["log"]["entries"][0]
    sc = [h["value"] for h in entry["response"]["headers"]
          if h["name"].lower() == "set-cookie"]
    assert len(sc) == 1 and sc[0].startswith("csrf=")
    assert all(c["name"] != "session" for c in entry["response"]["cookies"])
    assert any(c["name"] == "csrf" for c in entry["response"]["cookies"])


def test_base64_chinese_roundtrip() -> None:
    ws = _demo_ws()
    ws.set_treatment([f.id for f in ws.findings], "mask", True)
    content = ws.sanitized()["har"]["log"]["entries"][3]["response"]["content"]
    assert content["encoding"] == "base64"  # 表达方式保留
    decoded = base64.b64decode(content["text"]).decode("utf-8")
    assert "你好" in decoded  # 中文保留
    assert REPEATED_MOBILE not in decoded
    assert REPEATED_EMAIL not in decoded
    # size 是解码后真实字节数,不再是旧值
    assert content["size"] == len(decoded.encode("utf-8"))


def test_binary_content_untouched_and_listed_unchecked() -> None:
    ws = _demo_ws()
    original = ws.entries()[4]["response"]["content"]["text"]
    out_entry = ws.sanitized()["har"]["log"]["entries"][4]
    assert out_entry["response"]["content"]["text"] == original
    assert any(u.entry_index == 4 for u in ws.unchecked)


def test_json_array_and_nesting_preserved() -> None:
    ws = _demo_ws()
    ws.set_treatment([f.id for f in ws.findings], "mask", True)
    body = json.loads(
        ws.sanitized()["har"]["log"]["entries"][0]["request"]["postData"]["text"]
    )
    assert body["remember"] is True
    assert body["user"]["contact"]["mobile"] == "[REDACTED]"
    assert body["user"]["email"] == "[REDACTED]"
    # 数组不丢
    resp_body = json.loads(
        ws.sanitized()["har"]["log"]["entries"][0]["response"]["content"]["text"]
    )
    assert isinstance(resp_body["emails"], list) and len(resp_body["emails"]) == 2


def test_length_fields_updated_not_stale() -> None:
    ws = _demo_ws()
    entry_before = ws.entries()[0]
    before_size = entry_before["response"]["content"].get("size")
    ws.set_treatment([f.id for f in ws.findings], "mask", True)
    content = ws.sanitized()["har"]["log"]["entries"][0]["response"]["content"]
    actual = len(content["text"].encode("utf-8"))
    assert content["size"] == actual
    assert content["size"] != before_size or before_size == 0


def test_preview_matches_export() -> None:
    ws = _demo_ws()
    ws.set_treatment([f.id for f in ws.findings], "pseudo", True)
    exported = ws.sanitized()["har"]["log"]["entries"][1]
    preview = ws.preview_entry(1)["entry"]
    assert json.dumps(preview, sort_keys=True, ensure_ascii=False) == \
        json.dumps(exported, sort_keys=True, ensure_ascii=False)


def test_export_contains_all_entries_in_order() -> None:
    ws = _demo_ws()
    out_entries = ws.sanitized()["har"]["log"]["entries"]
    assert len(out_entries) == len(ws.entries())
    for a, b in zip(ws.entries(), out_entries):
        assert a["startedDateTime"] == b["startedDateTime"]
        assert a["response"]["status"] == b["response"]["status"]


def test_untouched_fields_preserved() -> None:
    ws = _demo_ws()
    before = ws.entries()[1]
    after = ws.sanitized()["har"]["log"]["entries"][1]
    assert after["timings"] == before["timings"]
    assert after["startedDateTime"] == before["startedDateTime"]
    assert after["request"]["method"] == "GET"


def test_summary_contains_no_raw_values() -> None:
    from app.summary import build_summary

    ws = _demo_ws()
    ws.set_treatment([f.id for f in ws.findings], "pseudo", True)
    summary = build_summary(ws)
    for secret in DEMO_SECRETS:
        assert secret not in summary
    # 摘要必须提示未检查项与处理明细
    assert "未检查" in summary
    assert "一致化代号" in summary


def test_summary_warns_about_leftovers() -> None:
    from app.summary import build_summary

    ws = _demo_ws()  # 全部未确认
    summary = build_summary(ws)
    assert "未处理" in summary
    assert "⚠️" in summary
    ws.mark_handled([f.id for f in ws.findings], True)
    # 仍有二进制未检查项,警告不应消失
    summary2 = build_summary(ws)
    assert "未检查内容" in summary2


def test_export_filename_has_no_user_data() -> None:
    from app.summary import safe_export_name

    name = safe_export_name("sanitized-har", "har")
    assert name.startswith("sanitized-har-") and name.endswith(".har")
    assert "demo" not in name and "token" not in name


def test_full_flow_via_api(demo_client) -> None:
    # 批量一致化 -> 预览 -> 导出 HAR -> 导出摘要,端到端
    findings = demo_client.get("/api/findings").json()["findings"]
    resp = demo_client.post("/api/findings/treatment", json={
        "finding_ids": [f["id"] for f in findings],
        "treatment": "pseudo",
        "handled": True,
    })
    assert resp.status_code == 200
    har_resp = demo_client.get("/api/export/har")
    assert har_resp.status_code == 200
    exported = json.loads(har_resp.content)
    assert len(exported["log"]["entries"]) == 7
    dumped = har_resp.content.decode("utf-8")
    for secret in DEMO_SECRETS:
        assert secret not in dumped
    summary_resp = demo_client.get("/api/export/summary")
    assert summary_resp.status_code == 200
    for secret in DEMO_SECRETS:
        assert secret not in summary_resp.text
    # 文件名不含敏感数据
    assert "sanitized-har-" in har_resp.headers["content-disposition"]
