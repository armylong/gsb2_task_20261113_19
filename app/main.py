"""FastAPI 入口。

安全约束:
- 默认只监听 127.0.0.1;
- 不访问 HAR 内任何 URL,不调用任何外部服务;
- 访问日志过滤查询串,敏感原文绝不进入服务日志;
- 原始文件不会被覆盖,导出均为新文件下载。
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .demo import build_demo_har
from .hario import (
    HarLoadError,
    entry_meta,
    header_value,
    load_har,
    normalize_entries,
    parse_request_body,
    parse_response_body,
)
from .models import ALL_LOCATIONS, ALL_TREATMENTS
from .rules import new_rule_id, validate_rule
from .session import workspace
from .summary import build_summary, safe_export_name

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="HAR 本地脱敏工具", version="1.0.0")


class _QueryStringFilter(logging.Filter):
    """访问日志剥掉路径里的查询串,避免 token 等原值落盘。

    uvicorn 访问日志的 record.msg 是格式串,真实请求行在 record.args 中,
    路径固定是第 3 个参数(下标 2)。
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            args = record.args
            if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
                path = args[2]
                if "?" in path:
                    new_args = list(args)
                    new_args[2] = path.split("?", 1)[0] + "?<query-stripped>"
                    record.args = tuple(new_args)
        except Exception:  # 过滤逻辑本身绝不能打断请求
            pass
        return True


logging.getLogger("uvicorn.access").addFilter(_QueryStringFilter())


# ---------------- 请求模型 ----------------
class RuleIn(BaseModel):
    name: str = Field(min_length=1)
    match_type: str
    pattern: str
    locations: list[str]
    enabled: bool = True


class RulePatch(BaseModel):
    name: str | None = None
    match_type: str | None = None
    pattern: str | None = None
    locations: list[str] | None = None
    enabled: bool | None = None


class TreatmentIn(BaseModel):
    finding_ids: list[str]
    treatment: str
    handled: bool = True


class MarkIn(BaseModel):
    finding_ids: list[str]
    handled: bool


# ---------------- 状态与文件 ----------------
@app.get("/api/state")
def get_state() -> dict[str, Any]:
    return {
        "loaded": workspace.loaded,
        "source_name": workspace.source_name,
        "entry_count": len(workspace.entries()),
        "rules": [r.to_dict() for r in workspace.rules],
        "scan": workspace.scan_status() if workspace.loaded else None,
    }


@app.post("/api/upload")
async def upload_har(file: UploadFile) -> dict[str, Any]:
    raw = await file.read()
    try:
        doc = load_har(raw)
    except HarLoadError as exc:
        # 解析失败:不触碰 workspace,当前已打开的文件原样保留
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    normalize_entries(doc)
    workspace.load(doc, file.filename or "uploaded.har")
    return {"ok": True, **workspace.scan_status(), "entry_count": len(workspace.entries())}


@app.post("/api/demo")
def load_demo() -> dict[str, Any]:
    doc = build_demo_har()
    normalize_entries(doc)
    workspace.reset_to_demo(doc)
    return {"ok": True, **workspace.scan_status(), "entry_count": len(workspace.entries())}


@app.get("/api/demo/download")
def download_demo() -> Response:
    doc = build_demo_har()
    payload = json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="demo.har"'},
    )


@app.delete("/api/clear")
def clear_workspace() -> dict[str, Any]:
    workspace.clear()
    return {"ok": True}


# ---------------- 规则 ----------------
@app.get("/api/rules")
def list_rules() -> dict[str, Any]:
    return {"rules": [r.to_dict() for r in workspace.rules]}


@app.post("/api/rules")
def create_rule(body: RuleIn) -> dict[str, Any]:
    err = validate_rule(body.match_type, body.pattern, body.locations)
    if err:
        raise HTTPException(status_code=400, detail=err)
    from .models import Rule

    rule = Rule(
        id=new_rule_id(),
        name=body.name,
        match_type=body.match_type,
        pattern=body.pattern,
        locations=list(body.locations),
        enabled=body.enabled,
        builtin=False,
    )
    workspace.rules.append(rule)
    workspace.rescan()
    return {"ok": True, "rule": rule.to_dict(), "scan": workspace.scan_status()}


@app.patch("/api/rules/{rule_id}")
def update_rule(rule_id: str, body: RulePatch) -> dict[str, Any]:
    rule = next((r for r in workspace.rules if r.id == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    merged = {
        "match_type": body.match_type or rule.match_type,
        "pattern": body.pattern if body.pattern is not None else rule.pattern,
        "locations": body.locations or rule.locations,
    }
    err = validate_rule(merged["match_type"], merged["pattern"], merged["locations"])
    if err:
        # 非法修改:拒绝并保留旧规则与已有扫描结果
        raise HTTPException(status_code=400, detail=err)
    if rule.builtin and (body.match_type or body.pattern or body.locations):
        raise HTTPException(status_code=400, detail="内置规则只允许启停,不能修改定义")
    rule.name = body.name if body.name is not None else rule.name
    rule.match_type = merged["match_type"]
    rule.pattern = merged["pattern"]
    rule.locations = list(merged["locations"])
    if body.enabled is not None:
        rule.enabled = body.enabled
    workspace.rescan()
    return {"ok": True, "rule": rule.to_dict(), "scan": workspace.scan_status()}


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str) -> dict[str, Any]:
    rule = next((r for r in workspace.rules if r.id == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    if rule.builtin:
        raise HTTPException(status_code=400, detail="内置规则不能删除,可停用")
    workspace.rules = [r for r in workspace.rules if r.id != rule_id]
    workspace.rescan()
    return {"ok": True, "scan": workspace.scan_status()}


@app.post("/api/rules/rescan")
def rescan_rules() -> dict[str, Any]:
    status = workspace.rescan()
    return {"ok": True, "scan": status}


# ---------------- 条目 ----------------
def _body_view(which: str, obj: dict[str, Any]) -> dict[str, Any]:
    parsed = parse_request_body(obj) if which == "request" else parse_response_body(obj)
    return {
        "kind": parsed.kind,
        "mime": parsed.mime,
        "text": parsed.text,
        "error": parsed.error,
    }


def _entry_detail(entry: dict[str, Any], index: int) -> dict[str, Any]:
    if entry.get("_broken"):
        return {
            "index": index,
            "broken": True,
            "error": entry.get("_error", "条目畸形"),
        }
    request = entry["request"]
    response = entry.get("response") or {}
    url = str(request.get("url", ""))
    query = [
        {"name": unquote(n), "value": unquote(v)}
        for n, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    ]
    return {
        "index": index,
        "broken": False,
        "method": request.get("method", ""),
        "url": url,
        "http_version": request.get("httpVersion", ""),
        "started": entry.get("startedDateTime", ""),
        "time_ms": entry.get("time"),
        "request": {
            "headers": [dict(h) for h in request.get("headers", []) if isinstance(h, dict)],
            "cookies": [dict(c) for c in request.get("cookies", []) if isinstance(c, dict)],
            "query": query,
            "body": _body_view("request", request),
        },
        "response": {
            "status": response.get("status"),
            "status_text": response.get("statusText", ""),
            "headers": [dict(h) for h in response.get("headers", []) if isinstance(h, dict)],
            "cookies": [dict(c) for c in response.get("cookies", []) if isinstance(c, dict)],
            "body": _body_view("response", response),
        },
    }


@app.get("/api/entries")
def list_entries(keyword: str = "") -> dict[str, Any]:
    entries = workspace.entries()
    metas = [entry_meta(i, e) for i, e in enumerate(entries)]
    kw = keyword.strip().lower()
    if kw:
        metas = [
            m for m in metas
            if m["broken"] and kw in m["error"].lower()
            or not m["broken"]
            and (kw in m["url"].lower() or kw in m["method"].lower()
                 or (m["status_text"] and kw in m["status_text"].lower())
                 or (m["status"] is not None and kw in str(m["status"])))
        ]
    finding_counts: dict[int, int] = {}
    unchecked_counts: dict[int, int] = {}
    for f in workspace.findings:
        finding_counts[f.entry_index] = finding_counts.get(f.entry_index, 0) + 1
    for u in workspace.unchecked:
        unchecked_counts[u.entry_index] = unchecked_counts.get(u.entry_index, 0) + 1
    for m in metas:
        m["finding_count"] = finding_counts.get(m["index"], 0)
        m["unchecked_count"] = unchecked_counts.get(m["index"], 0)
    return {"entries": metas}


@app.get("/api/entries/{index}")
def get_entry(index: int) -> dict[str, Any]:
    entries = workspace.entries()
    if not 0 <= index < len(entries):
        raise HTTPException(status_code=404, detail="条目不存在")
    detail = _entry_detail(entries[index], index)
    detail["findings"] = [f.to_dict() for f in workspace.findings_for_entry(index)]
    detail["unchecked"] = [u.to_dict() for u in workspace.unchecked_for_entry(index)]
    return detail


@app.get("/api/entries/{index}/preview")
def preview_entry(index: int) -> dict[str, Any]:
    entries = workspace.entries()
    if not 0 <= index < len(entries):
        raise HTTPException(status_code=404, detail="条目不存在")
    preview = workspace.preview_entry(index)
    detail = _entry_detail(preview["entry"], index)
    detail["changes"] = preview["changes"]
    return detail


# ---------------- 发现项 ----------------
@app.get("/api/findings")
def list_findings() -> dict[str, Any]:
    return {
        "findings": [f.to_dict() for f in workspace.findings],
        "unchecked": [u.to_dict() for u in workspace.unchecked],
        "scan": workspace.scan_status(),
    }


@app.post("/api/findings/treatment")
def set_treatment(body: TreatmentIn) -> dict[str, Any]:
    if body.treatment not in ALL_TREATMENTS:
        raise HTTPException(status_code=400, detail="未知处理方式")
    if not workspace.loaded:
        raise HTTPException(status_code=400, detail="请先上传 HAR 或载入演示数据")
    changed = workspace.set_treatment(body.finding_ids, body.treatment, body.handled)
    return {"ok": True, "changed": changed, "scan": workspace.scan_status()}


@app.post("/api/findings/mark")
def mark_findings(body: MarkIn) -> dict[str, Any]:
    changed = workspace.mark_handled(body.finding_ids, body.handled)
    return {"ok": True, "changed": changed, "scan": workspace.scan_status()}


@app.get("/api/findings/{finding_id}/reveal")
def reveal_finding(finding_id: str) -> dict[str, Any]:
    # 用户主动查看才下发原值;该接口路径不含任何敏感数据,日志不会记录原值
    finding = workspace.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="发现项不存在")
    return {"id": finding.id, "raw_value": finding.raw_value}


# ---------------- 导出 ----------------
@app.get("/api/export/har")
def export_har() -> Response:
    if not workspace.loaded:
        raise HTTPException(status_code=400, detail="没有可导出的 HAR")
    result = workspace.sanitized()
    payload = json.dumps(result["har"], ensure_ascii=False, indent=2).encode("utf-8")
    filename = safe_export_name("sanitized-har", "har")
    return Response(
        content=payload,
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/export/summary")
def export_summary() -> PlainTextResponse:
    if not workspace.loaded:
        raise HTTPException(status_code=400, detail="没有可导出的摘要")
    content = build_summary(workspace)
    filename = safe_export_name("sanitization-summary", "md")
    return PlainTextResponse(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------- 静态页面 ----------------
@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
