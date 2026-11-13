"""HAR 文件读取、条目规范化与正文解析工具。

坏条目策略:顶层结构无法解析 -> 抛 HarLoadError;个别条目畸形 -> 标记 broken 并保留占位,
其余条目照常检查。
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl

from .models import LOC_REQ_BODY, LOC_RESP_BODY


class HarLoadError(Exception):
    """整个文件无法解析时抛出,消息用于直接展示给用户。"""


@dataclass
class ParsedBody:
    kind: str               # json | form | text | empty | binary | base64-error | json-error
    mime: str
    text: str                # 可展示/可匹配的文本(json/form 为原始文本)
    data: Any = None         # json 为解析后的对象;form 为 [(name, value), ...]
    error: str = ""


def load_har(raw: bytes) -> dict[str, Any]:
    """解析并校验 HAR 顶层结构,不修改原始内容。"""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HarLoadError(f"文件不是有效的 UTF-8 文本,无法按 HAR 解析:{exc.reason}") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HarLoadError(
            f"JSON 解析失败(第 {exc.lineno} 行第 {exc.colno} 列附近):{exc.msg}"
        ) from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("log"), dict):
        raise HarLoadError("缺少 HAR 顶层 log 对象,这不是有效的 HAR 1.2 文件")
    log = doc["log"]
    if "entries" not in log or not isinstance(log["entries"], list):
        raise HarLoadError("log.entries 缺失或不是数组,这不是有效的 HAR 1.2 文件")
    return doc


def normalize_entries(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """给每个条目补 _broken/_error 标记,保持原始顺序与内容不变。"""
    entries = doc["log"]["entries"]
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            entries[idx] = {"_broken": True, "_error": "条目不是 JSON 对象", "_entry": entry}
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            entry["_broken"] = True
            entry["_error"] = "缺少有效的 request 对象"
            continue
        if not isinstance(entry.get("response"), dict):
            # response 缺失不阻断请求侧检查,补一个空响应并标注
            entry["response"] = {"status": 0, "statusText": "", "headers": [], "content": {}}
            entry["_response_missing"] = True
        entry.setdefault("_broken", False)
        entry.setdefault("_error", "")
    return entries


def entry_meta(index: int, entry: dict[str, Any]) -> dict[str, Any]:
    """列表页需要的概要信息。"""
    if entry.get("_broken"):
        return {
            "index": index,
            "broken": True,
            "error": entry.get("_error", "条目畸形"),
            "method": "",
            "url": "",
            "status": None,
            "time_ms": None,
            "started": "",
        }
    request = entry["request"]
    response = entry.get("response") or {}
    time_ms = entry.get("time")
    return {
        "index": index,
        "broken": False,
        "error": "",
        "method": request.get("method", ""),
        "url": request.get("url", ""),
        "status": response.get("status"),
        "status_text": response.get("statusText", ""),
        "time_ms": round(time_ms, 2) if isinstance(time_ms, (int, float)) else None,
        "started": entry.get("startedDateTime", ""),
    }


def header_value(headers: list[dict[str, Any]], name: str) -> str:
    """大小写不敏感取头(同名头取第一个)。"""
    target = name.lower()
    for h in headers or []:
        if isinstance(h, dict) and str(h.get("name", "")).lower() == target:
            return str(h.get("value", ""))
    return ""


def get_mime(headers: list[dict[str, Any]], content: dict[str, Any] | None = None) -> str:
    mime = ""
    if isinstance(content, dict) and content.get("mimeType"):
        mime = str(content["mimeType"])
    if not mime:
        mime = header_value(headers, "content-type")
    return mime.lower()


def _is_json_mime(mime: str) -> bool:
    return "json" in mime


def _is_form_mime(mime: str) -> bool:
    return "application/x-www-form-urlencoded" in mime


def parse_request_body(request: dict[str, Any]) -> ParsedBody:
    post = request.get("postData")
    if not isinstance(post, dict):
        return ParsedBody(kind="empty", mime="", text="")
    mime = str(post.get("mimeType", "")).lower()
    text = post.get("text")
    text = "" if text is None else str(text)
    if not text:
        return ParsedBody(kind="empty", mime=mime, text="")
    if _is_json_mime(mime):
        return _parse_json_text(text, mime)
    if _is_form_mime(mime):
        return _parse_form_text(text, mime)
    return ParsedBody(kind="text", mime=mime, text=text)


def parse_response_body(response: dict[str, Any]) -> ParsedBody:
    content = response.get("content")
    if not isinstance(content, dict):
        return ParsedBody(kind="empty", mime="", text="")
    mime = str(content.get("mimeType", "")).lower()
    if not mime:
        mime = get_mime(response.get("headers", []), content)
    text = content.get("text")
    if text is None:
        return ParsedBody(kind="empty", mime=mime, text="")
    text = str(text)
    encoding = str(content.get("encoding", "")).lower()

    if encoding == "base64":
        # HAR 标记 base64:先解码判断内容性质,再按解码后的文本检查,
        # 脱敏后重新编码写回,保持 base64 表达方式不变。
        try:
            raw = base64.b64decode(text, validate=False)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            return ParsedBody(kind="base64-error", mime=mime, text=text,
                              error=f"base64 内容无法解码:{exc}")
        if _looks_binary(raw):
            return ParsedBody(kind="binary", mime=mime, text="",
                              error="base64 解码后为二进制内容,未检查")
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            return ParsedBody(kind="binary", mime=mime, text="",
                              error=f"base64 解码后不是合法 UTF-8 文本,未检查({exc.reason})")
        if _is_json_mime(mime):
            parsed = _parse_json_text(decoded, mime)
            parsed.kind = "json" if parsed.kind == "json" else parsed.kind
            return parsed
        if _is_form_mime(mime):
            return _parse_form_text(decoded, mime)
        return ParsedBody(kind="text", mime=mime, text=decoded)

    # 非 base64:显式二进制类型直接列为未检查,不尝试解码
    if _binary_mime(mime) or _looks_binary(text.encode("utf-8", errors="ignore")):
        return ParsedBody(kind="binary", mime=mime, text="",
                          error="二进制或无法按文本解码的内容,未检查")
    if _is_json_mime(mime):
        return _parse_json_text(text, mime)
    if _is_form_mime(mime):
        return _parse_form_text(text, mime)
    return ParsedBody(kind="text", mime=mime, text=text)


def _parse_json_text(text: str, mime: str) -> ParsedBody:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return ParsedBody(kind="json-error", mime=mime, text=text,
                          error=f"标记为 JSON 但解析失败(第 {exc.lineno} 行):{exc.msg}")
    return ParsedBody(kind="json", mime=mime, text=text, data=data)


def _parse_form_text(text: str, mime: str) -> ParsedBody:
    # keep_blank_values 保留空值;同名参数全部保留为独立元组
    pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=False)
    return ParsedBody(kind="form", mime=mime, text=text, data=pairs)


def _binary_mime(mime: str) -> bool:
    binary_prefixes = (
        "image/", "audio/", "video/", "application/octet-stream",
        "application/zip", "application/pdf", "application/x-protobuf",
        "application/msword",
    )
    base = mime.split(";")[0].strip()
    return base.startswith(binary_prefixes)


def _looks_binary(raw: bytes) -> bool:
    if not raw:
        return False
    # 含 NUL 字节或控制字符占比过高视为二进制
    if b"\x00" in raw:
        return True
    control = sum(1 for b in raw if b < 9 or (13 < b < 32))
    return control / len(raw) > 0.3


def body_location(which: str) -> str:
    return LOC_REQ_BODY if which == "request" else LOC_RESP_BODY
