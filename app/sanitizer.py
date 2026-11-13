"""脱敏执行器:按发现项的定位精确改写 HAR 深拷贝。

预览(单条目)与导出(整文件)共用本模块,因此"所见即所导出"。
长度字段(headersSize/bodySize/content.size/postData 等)随改写同步更新,
删除单个 cookie 子项只动该子项,其他 cookie 原样保留。
"""
from __future__ import annotations

import base64
import copy
import json
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .hario import parse_request_body, parse_response_body
from .models import (
    LOC_QUERY,
    LOC_REQ_BODY,
    LOC_REQ_HEADER,
    LOC_RESP_BODY,
    LOC_RESP_HEADER,
    MASK_VALUE,
    Finding,
    TREATMENT_DELETE,
    TREATMENT_MASK,
    TREATMENT_PSEUDO,
)


def _replacement(finding: Finding) -> str:
    if finding.treatment == TREATMENT_PSEUDO:
        return finding.pseudo_code
    return MASK_VALUE


def _group(findings: list[Finding]) -> dict[int, list[Finding]]:
    grouped: dict[int, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.entry_index].append(f)
    for idx in grouped:
        grouped[idx].sort(key=lambda f: f.id)
    return grouped


def _apply_header(
    headers: list[dict[str, Any]],
    findings: list[Finding],
    location: str,
) -> bool:
    """改写请求/响应头。返回是否发生变化。"""
    by_index: dict[int, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.target.location != location or f.target.kind not in ("header", "cookie"):
            continue
        # cookie 用 header_index 定位所属头(多个同名 Set-Cookie 各自独立);
        # 普通头用 index
        h_idx = f.target.header_index if f.target.kind == "cookie" else f.target.index
        if h_idx < 0:
            continue
        by_index[h_idx].append(f)
    if not by_index:
        return False

    changed = False
    delete_indices: set[int] = set()
    for h_idx, items in by_index.items():
        if h_idx >= len(headers):
            continue
        header = headers[h_idx]
        name = str(header.get("name", ""))
        value = str(header.get("value", ""))
        cookie_items = [f for f in items if f.target.kind == "cookie"]
        whole_items = [f for f in items if f.target.kind == "header"]

        if cookie_items:
            new_value, drop_header = _apply_cookie_value(
                name, value, location, cookie_items
            )
            if drop_header:
                delete_indices.add(h_idx)
                changed = True
            elif new_value != value:
                header["value"] = new_value
                changed = True
                value = new_value
        for f in whole_items:
            if f.treatment == TREATMENT_DELETE:
                delete_indices.add(h_idx)
                changed = True
            else:
                target = f.target
                if target.start >= 0:
                    new_value = (
                        value[: target.start] + _replacement(f) + value[target.end :]
                    )
                else:
                    new_value = _replacement(f)
                if new_value != value:
                    header["value"] = new_value
                    value = new_value
                    changed = True

    for h_idx in sorted(delete_indices, reverse=True):
        del headers[h_idx]
    return changed


def _apply_cookie_value(
    header_name: str, value: str, location: str, items: list[Finding]
) -> tuple[str | None, bool]:
    """返回(新头值, 是否整条删除)。删除单个 cookie 子项不影响其他 cookie。"""
    is_set_cookie = location == LOC_RESP_HEADER
    if is_set_cookie:
        # Set-Cookie:只处理第一个 name=value,属性(Path/Expires 等)原样保留
        head, sep, tail = value.partition(";")
        new_head = _rewrite_cookie_pair(head, items, cookie_index=0)
        if new_head is None:  # 删除整个 cookie 值对 -> 整条 Set-Cookie 删除
            return None, True
        return new_head + (sep + tail if sep else ""), False
    # 请求 Cookie:多段 name=value,按段索引改写,删除某段不影响其他段
    chunks = value.split(";")
    by_index: dict[int, list[Finding]] = defaultdict(list)
    for f in items:
        by_index[f.target.index].append(f)
    out_chunks: list[str] = []
    for c_idx, chunk in enumerate(chunks):
        if c_idx not in by_index:
            out_chunks.append(chunk)
            continue
        rewritten = _rewrite_cookie_pair(chunk, by_index[c_idx], c_idx)
        if rewritten is not None:
            out_chunks.append(rewritten)
        # 删除:整段丢弃,其余 cookie 保留
    return ";".join(out_chunks), False


def _rewrite_cookie_pair(chunk: str, items: list[Finding], cookie_index: int) -> str | None:
    if "=" not in chunk:
        return chunk
    name, sep, val = chunk.partition("=")
    # 只有明确选择"删除字段"的整字段命中才删除;遮盖/代号必须保留名称与结构
    delete_whole = any(
        f.treatment == TREATMENT_DELETE and f.target.start < 0 for f in items
    )
    if delete_whole:
        return None
    # 值片段类命中(正则子串)按区间改写;整字段命中替换整个值
    span_items = sorted(
        (f for f in items if f.target.start >= 0),
        key=lambda f: f.target.start,
        reverse=True,
    )
    new_val = val
    replaced_whole = False
    for f in items:
        if f.target.start < 0:
            new_val = _replacement(f)
            replaced_whole = True
            break
    if not replaced_whole:
        for f in span_items:
            t = f.target
            new_val = new_val[: t.start] + _replacement(f) + new_val[t.end :]
    return name + sep + new_val


def _apply_query(url: str, findings: list[Finding]) -> tuple[str, bool]:
    items = [f for f in findings if f.target.location == LOC_QUERY]
    if not items:
        return url, False
    if "?" not in url:
        return url, False
    base, query = url.split("?", 1)
    parts = query.split("&") if query else []
    by_index: dict[int, list[Finding]] = defaultdict(list)
    for f in items:
        by_index[f.target.index].append(f)
    delete_indices = {
        f.target.index
        for f in items
        if f.treatment == TREATMENT_DELETE and f.target.start < 0
    }
    out_parts: list[str] = []
    for p_idx, part in enumerate(parts):
        if p_idx in delete_indices:
            continue
        if p_idx not in by_index:
            out_parts.append(part)
            continue
        if "=" in part:
            raw_name, sep, raw_val = part.partition("=")
        else:
            raw_name, sep, raw_val = part, "", ""
        new_val = raw_val
        whole = next((f for f in by_index[p_idx] if f.target.start < 0), None)
        if whole is not None and whole.treatment != TREATMENT_DELETE:
            new_val = _replacement(whole)
        else:
            for f in sorted(
                (x for x in by_index[p_idx] if x.target.start >= 0),
                key=lambda x: x.target.start,
                reverse=True,
            ):
                t = f.target
                new_val = new_val[: t.start] + _replacement(f) + new_val[t.end :]
        out_parts.append(raw_name + ("=" + new_val if sep else ""))
    new_query = "&".join(out_parts)
    new_url = base + ("?" + new_query if new_query or "?" in url else "")
    # 查询被删光时去掉结尾的 "?"
    if not new_query and new_url.endswith("?"):
        new_url = new_url[:-1]
    return new_url, new_url != url


def _apply_form_text(text: str, findings: list[Finding]) -> tuple[str, bool]:
    items = [f for f in findings if f.target.location == LOC_REQ_BODY
             and f.target.kind == "form"]
    if not items:
        return text, False
    parts = text.split("&")
    by_index: dict[int, list[Finding]] = defaultdict(list)
    for f in items:
        by_index[f.target.index].append(f)
    delete_indices = {
        f.target.index
        for f in items
        if f.treatment == TREATMENT_DELETE and f.target.start < 0
    }
    out_parts: list[str] = []
    for p_idx, part in enumerate(parts):
        if p_idx in delete_indices:
            continue
        if p_idx not in by_index:
            out_parts.append(part)
            continue
        if "=" in part:
            raw_name, sep, raw_val = part.partition("=")
        else:
            raw_name, sep, raw_val = part, "", ""
        new_val = raw_val
        whole = next((f for f in by_index[p_idx] if f.target.start < 0), None)
        if whole is not None and whole.treatment != TREATMENT_DELETE:
            new_val = _replacement(whole)
        else:
            for f in sorted(
                (x for x in by_index[p_idx] if x.target.start >= 0),
                key=lambda x: x.target.start,
                reverse=True,
            ):
                t = f.target
                new_val = new_val[: t.start] + _replacement(f) + new_val[t.end :]
        out_parts.append(raw_name + ("=" + new_val if sep else ""))
    new_text = "&".join(out_parts)
    return new_text, new_text != text


def _mutate_json(node: Any, path: list[Any], findings: list[Finding]) -> Any:
    """按 path 定位改写 JSON 节点。findings 已按完整路径索引。"""
    if isinstance(node, dict):
        return {k: _mutate_json(v, path + [k], findings) for k, v in node.items()}
    if isinstance(node, list):
        return [_mutate_json(v, path + [i], findings) for i, v in enumerate(node)]
    if isinstance(node, str):
        hits = findings.get(tuple(path), [])
        if not hits:
            return node
        delete_whole = any(f.treatment == TREATMENT_DELETE and f.target.start < 0 for f in hits)
        if delete_whole:
            return None
        whole = next((f for f in hits if f.target.start < 0 and f.treatment != TREATMENT_DELETE), None)
        if whole is not None:
            return _replacement(whole)
        new_val = node
        for f in sorted(
            (x for x in hits if x.target.start >= 0),
            key=lambda x: x.target.start,
            reverse=True,
        ):
            t = f.target
            new_val = new_val[: t.start] + _replacement(f) + new_val[t.end :]
        return new_val
    return node


def _apply_request_body(post: dict[str, Any], findings: list[Finding]) -> bool:
    parsed = parse_request_body({"postData": post})
    items = [f for f in findings if f.target.location == LOC_REQ_BODY]
    if not items:
        return False
    changed = False
    if parsed.kind == "form":
        new_text, changed = _apply_form_text(parsed.text, items)
        if changed:
            post["text"] = new_text
            if isinstance(post.get("params"), list):
                post["params"] = _sync_form_params(post["params"], new_text)
    elif parsed.kind == "json":
        by_path: dict[tuple[Any, ...], list[Finding]] = defaultdict(list)
        for f in items:
            if f.target.kind == "json":
                by_path[tuple(f.target.path)].append(f)
        new_data = _mutate_json(parsed.data, [], by_path)
        new_text = json.dumps(new_data, ensure_ascii=False, separators=(",", ":"))
        if new_text != parsed.text:
            post["text"] = new_text
            changed = True
    else:
        new_text, changed = _apply_plain_text(parsed.text, items)
        if changed:
            post["text"] = new_text
    return changed


def _sync_form_params(params: list[dict[str, Any]], new_text: str) -> list[dict[str, Any]]:
    from urllib.parse import parse_qsl, unquote

    pairs = parse_qsl(new_text, keep_blank_values=True)
    new_params: list[dict[str, Any]] = []
    for name, value in pairs:
        new_params.append({"name": unquote(name), "value": unquote(value)})
    return new_params


def _apply_plain_text(text: str, findings: list[Finding]) -> tuple[str, bool]:
    spans = sorted(
        (f for f in findings if f.target.start >= 0),
        key=lambda f: f.target.start,
        reverse=True,
    )
    if not spans:
        return text, False
    new_text = text
    for f in spans:
        t = f.target
        new_text = new_text[: t.start] + _replacement(f) + new_text[t.end :]
    return new_text, new_text != text


def _apply_response_body(content: dict[str, Any], findings: list[Finding]) -> bool:
    items = [f for f in findings if f.target.location == LOC_RESP_BODY]
    if not items or not isinstance(content, dict) or content.get("text") is None:
        return False
    parsed = parse_response_body({"content": content})
    encoding = str(content.get("encoding", "")).lower()
    original_text = str(content["text"])
    changed = False

    if encoding == "base64":
        # 工作文本是解码后的字符串,改完重新 base64,表达方式不变
        if parsed.kind in ("binary", "base64-error"):
            return False
        work_text = parsed.text
        new_work, changed = _rewrite_resp_text(parsed, work_text, items)
        if changed:
            content["text"] = base64.b64encode(
                new_work.encode("utf-8")
            ).decode("ascii")
    else:
        if parsed.kind == "binary":
            return False
        new_text, changed = _rewrite_resp_text(parsed, original_text, items)
        if changed:
            content["text"] = new_text

    if changed:
        # content.size 按"改后实际字节数"更新,base64 时也是解码后的真实正文大小
        size_text = content["text"]
        if encoding == "base64":
            size_bytes = len(base64.b64decode(size_text))
        else:
            size_bytes = len(size_text.encode("utf-8"))
        content["size"] = size_bytes
        content.pop("compression", None)
    return changed


def _rewrite_resp_text(
    parsed: Any, work_text: str, items: list[Finding]
) -> tuple[str, bool]:
    if parsed.kind == "json":
        by_path: dict[tuple[Any, ...], list[Finding]] = defaultdict(list)
        for f in items:
            if f.target.kind == "json":
                by_path[tuple(f.target.path)].append(f)
        if not by_path:
            return work_text, False
        new_data = _mutate_json(parsed.data, [], by_path)
        new_text = json.dumps(new_data, ensure_ascii=False, separators=(",", ":"))
        return new_text, new_text != work_text
    if parsed.kind == "form":
        return _apply_form_text(work_text, items)
    return _apply_plain_text(work_text, items)


def apply_all(
    har: dict[str, Any], findings: list[Finding]
) -> tuple[dict[str, Any], dict[int, list[dict[str, Any]]]]:
    """对整份 HAR 深拷贝执行脱敏,返回(新 HAR, 按条目索引的变更记录)。"""
    new_har = copy.deepcopy(har)
    entries = new_har["log"]["entries"]
    grouped = _group(findings)
    changes: dict[int, list[dict[str, Any]]] = defaultdict(list)

    for idx, items in grouped.items():
        if idx >= len(entries) or entries[idx].get("_broken"):
            continue
        entry = entries[idx]
        request = entry["request"]
        response = entry.setdefault("response", {"headers": [], "content": {}})

        req_headers = request.setdefault("headers", [])
        if _apply_header(req_headers, items, LOC_REQ_HEADER):
            request["headersSize"] = -1
            _sync_request_cookies(request, req_headers)
        resp_headers = response.setdefault("headers", [])
        if _apply_header(resp_headers, items, LOC_RESP_HEADER):
            response["headersSize"] = -1
            _sync_response_cookies(response, resp_headers)

        new_url, url_changed = _apply_query(str(request.get("url", "")), items)
        if url_changed:
            request["url"] = new_url
            request["queryString"] = _rebuild_query_string(new_url)

        post = request.get("postData")
        if isinstance(post, dict) and _apply_request_body(post, items):
            request["headersSize"] = -1
            request["bodySize"] = len(str(post.get("text", "")).encode("utf-8"))

        content = response.get("content")
        if isinstance(content, dict) and _apply_response_body(content, items):
            response["bodySize"] = content.get("size", response.get("bodySize", 0))

        for f in items:
            changes[idx].append(
                {
                    "finding_id": f.id,
                    "location": f.target.location,
                    "field": f.field_label,
                    "rules": list(f.rule_names),
                    "treatment": f.treatment,
                    "pseudo_code": f.pseudo_code if f.treatment == TREATMENT_PSEUDO else "",
                }
            )
    return new_har, dict(changes)


def _sync_request_cookies(request: dict[str, Any], headers: list[dict[str, Any]]) -> None:
    """HAR 的 request.cookies 是 cookie 头的镜像,改写头后同步,避免残留旧凭据。"""
    cookie_value = ""
    for h in headers:
        if str(h.get("name", "")).lower() == "cookie":
            cookie_value = str(h.get("value", ""))
            break
    cookies: list[dict[str, Any]] = []
    for chunk in cookie_value.split(";"):
        if "=" in chunk:
            name, value = chunk.split("=", 1)
            cookies.append({"name": name.strip(), "value": value.strip()})
    request["cookies"] = cookies


def _sync_response_cookies(response: dict[str, Any], headers: list[dict[str, Any]]) -> None:
    """response.cookies 是 Set-Cookie 的镜像:从头完整重建,原值删除/遮盖后镜像不残留。

    若 HAR 原本没有 cookies 数组则不新建(保持未修改字段不动)。
    """
    cookies = response.get("cookies")
    if not isinstance(cookies, list):
        return
    set_cookie_headers = [
        str(h.get("value", ""))
        for h in headers
        if str(h.get("name", "")).lower() == "set-cookie"
    ]
    new_values: dict[str, str] = {}
    for value in set_cookie_headers:
        head = value.split(";", 1)[0]
        if "=" in head:
            name, val = head.split("=", 1)
            new_values[name.strip()] = val.strip()
    rebuilt: list[dict[str, Any]] = []
    for cookie in cookies:
        name = str(cookie.get("name", ""))
        if name not in new_values:
            continue  # 对应 Set-Cookie 已整条删除
        updated = dict(cookie)
        updated["value"] = new_values[name]
        rebuilt.append(updated)
    response["cookies"] = rebuilt


def _rebuild_query_string(url: str) -> list[dict[str, Any]]:
    from urllib.parse import parse_qsl, unquote, urlsplit

    query = urlsplit(url).query
    return [
        {"name": unquote(name), "value": unquote(value)}
        for name, value in parse_qsl(query, keep_blank_values=True)
    ]


def url_host_only(url: str) -> str:
    """日志/摘要里只保留 scheme+host+path,不带查询串与片段,避免原值进日志。"""
    try:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except ValueError:
        return "(invalid-url)"
