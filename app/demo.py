"""内置演示 HAR(全部为虚构数据,不含任何真实凭据)。

覆盖场景:
- 跨请求重复凭据(同一 token / 邮箱 / cookie 值在多个请求出现,验证一致化代号);
- 嵌套 JSON、重复查询参数、重复表单参数;
- base64 编码的中文响应;
- 二进制响应(未检查项);
- 带 <script> 的 HTML 文本(验证前端不执行脚本);
- 一个畸形条目(验证坏条目标记不影响其他条目);
- Set-Cookie 多属性、请求 Cookie 多子项(验证删一个不丢其他)。
"""
from __future__ import annotations

import base64
import json
from typing import Any

# 跨请求复用的虚构原值
REPEATED_TOKEN = "REPEATED-TOKEN-9f3c2a71b8d04e6a"
REPEATED_EMAIL = "alice.demo@example.test"
REPEATED_MOBILE = "13800138000"
REPEATED_SESSION = "sess-demo-7788abcd1234"


def _response_cookies_from_headers(
    resp_headers: list[tuple[str, str]]
) -> list[dict[str, str]]:
    cookies: list[dict[str, str]] = []
    for name, value in resp_headers:
        if name.lower() != "set-cookie":
            continue
        head = value.split(";", 1)[0]
        if "=" in head:
            cname, cval = head.split("=", 1)
            cookies.append({"name": cname.strip(), "value": cval.strip()})
    return cookies


def _request_cookies_from_headers(
    req_headers: list[tuple[str, str]]
) -> list[dict[str, str]]:
    cookies: list[dict[str, str]] = []
    for name, value in req_headers:
        if name.lower() != "cookie":
            continue
        for chunk in value.split(";"):
            if "=" in chunk:
                cname, cval = chunk.split("=", 1)
                cookies.append({"name": cname.strip(), "value": cval.strip()})
    return cookies


def _entry(
    idx: int,
    method: str,
    url: str,
    status: int,
    req_headers: list[tuple[str, str]],
    resp_headers: list[tuple[str, str]],
    content: dict[str, Any],
    post_data: dict[str, Any] | None = None,
    query_string: list[dict[str, str]] | None = None,
    time_ms: int = 42,
) -> dict[str, Any]:
    started = f"2026-11-13T09:00:{idx:02d}.000Z"
    request: dict[str, Any] = {
        "method": method,
        "url": url,
        "httpVersion": "HTTP/1.1",
        "cookies": _request_cookies_from_headers(req_headers),
        "headers": [{"name": n, "value": v} for n, v in req_headers],
        "queryString": query_string or [],
        "headersSize": -1,
        "bodySize": 0,
    }
    if post_data is not None:
        request["postData"] = post_data
        request["bodySize"] = len(str(post_data.get("text", "")).encode("utf-8"))
    response = {
        "status": status,
        "statusText": "OK" if 200 <= status < 300 else "Error",
        "httpVersion": "HTTP/1.1",
        "cookies": _response_cookies_from_headers(resp_headers),
        "headers": [{"name": n, "value": v} for n, v in resp_headers],
        "content": content,
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": content.get("size", 0),
    }
    return {
        "startedDateTime": started,
        "time": time_ms,
        "request": request,
        "response": response,
        "cache": {},
        "timings": {"send": 1, "wait": time_ms - 2, "receive": 1},
    }


def build_demo_har() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []

    # 1) 登录:嵌套 JSON 请求体 + 两个 Set-Cookie + 响应里的 token/邮箱
    login_body = json.dumps(
        {
            "user": {
                "name": "demo-user",
                "email": REPEATED_EMAIL,
                "contact": {"mobile": REPEATED_MOBILE},
            },
            "password": "Pa55w0rd-demo!",
            "remember": True,
        },
        ensure_ascii=False,
    )
    entries.append(
        _entry(
            0,
            "POST",
            "https://demo.local/api/login",
            200,
            req_headers=[
                ("Content-Type", "application/json; charset=utf-8"),
                ("Authorization", f"Bearer {REPEATED_TOKEN}"),
            ],
            resp_headers=[
                ("Content-Type", "application/json; charset=utf-8"),
                ("Set-Cookie", f"session={REPEATED_SESSION}; Path=/; HttpOnly"),
                ("Set-Cookie", "csrf=csrf-demo-aaaa; Path=/; SameSite=Lax"),
            ],
            content={
                "size": 0,
                "mimeType": "application/json; charset=utf-8",
                "text": json.dumps(
                    {
                        "token": REPEATED_TOKEN,
                        "profile": {"email": REPEATED_EMAIL},
                        "emails": ["a@example.test", "b@example.test"],
                    },
                    ensure_ascii=False,
                ),
            },
            post_data={"mimeType": "application/json; charset=utf-8", "text": login_body},
        )
    )

    # 2) 资料:重复查询参数 + 请求 Cookie 多子项 + 同一 token/邮箱重复出现
    entries.append(
        _entry(
            1,
            "GET",
            f"https://demo.local/api/profile?token={REPEATED_TOKEN}&tag=1&tag=2",
            200,
            req_headers=[
                (
                    "Cookie",
                    f"session={REPEATED_SESSION}; theme=dark; trace=trace-demo-001",
                ),
            ],
            resp_headers=[("Content-Type", "application/json; charset=utf-8")],
            content={
                "size": 0,
                "mimeType": "application/json; charset=utf-8",
                "text": json.dumps(
                    {"email": REPEATED_EMAIL, "phone": REPEATED_MOBILE, "level": 3},
                    ensure_ascii=False,
                ),
            },
            query_string=[
                {"name": "token", "value": REPEATED_TOKEN},
                {"name": "tag", "value": "1"},
                {"name": "tag", "value": "2"},
            ],
        )
    )

    # 3) 下单:表单编码 + 重复表单参数 + 密码字段 + 跨请求复用 token
    form_text = (
        f"item=book-1&item=book-2&addr=beijing&password=form-pwd-42"
        f"&token={REPEATED_TOKEN}&contact=13912345678"
    )
    entries.append(
        _entry(
            2,
            "POST",
            "https://demo.local/api/orders",
            201,
            req_headers=[
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            resp_headers=[("Content-Type", "application/json; charset=utf-8")],
            content={
                "size": 0,
                "mimeType": "application/json",
                "text": json.dumps({"orderId": "NO-20261113-001", "ok": True}),
            },
            post_data={
                "mimeType": "application/x-www-form-urlencoded",
                "text": form_text,
                "params": [
                    {"name": "item", "value": "book-1"},
                    {"name": "item", "value": "book-2"},
                    {"name": "addr", "value": "beijing"},
                    {"name": "password", "value": "form-pwd-42"},
                    {"name": "token", "value": REPEATED_TOKEN},
                    {"name": "contact", "value": "13912345678"},
                ],
            },
        )
    )

    # 4) 中文 base64 文本响应(内含手机号,解码后应被扫描到)
    chinese = "你好,这是演示响应:联系手机号 13800138000,邮箱 alice.demo@example.test。"
    b64_text = base64.b64encode(chinese.encode("utf-8")).decode("ascii")
    entries.append(
        _entry(
            3,
            "GET",
            "https://demo.local/api/message",
            200,
            req_headers=[],
            resp_headers=[("Content-Type", "text/plain; charset=utf-8")],
            content={
                "size": len(chinese.encode("utf-8")),
                "mimeType": "text/plain; charset=utf-8",
                "text": b64_text,
                "encoding": "base64",
            },
        )
    )

    # 5) 二进制响应(PNG 字节,base64 携带)——必须列为未检查
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00binary-demo"
    entries.append(
        _entry(
            4,
            "GET",
            "https://demo.local/img/logo.png",
            200,
            req_headers=[],
            resp_headers=[("Content-Type", "image/png")],
            content={
                "size": len(png_bytes),
                "mimeType": "image/png",
                "text": base64.b64encode(png_bytes).decode("ascii"),
                "encoding": "base64",
            },
        )
    )

    # 6) 带脚本的 HTML 文本(前端必须按文本显示,脚本不得执行)
    html = (
        "<html><body><h1>demo page</h1>"
        f"<script>var token='{REPEATED_TOKEN}';"
        "document.title='xss-test';</script>"
        f"<p>contact: {REPEATED_MOBILE}</p></body></html>"
    )
    entries.append(
        _entry(
            5,
            "GET",
            "https://demo.local/page",
            200,
            req_headers=[("Authorization", f"Bearer {REPEATED_TOKEN}")],
            resp_headers=[("Content-Type", "text/html; charset=utf-8")],
            content={
                "size": len(html.encode("utf-8")),
                "mimeType": "text/html; charset=utf-8",
                "text": html,
            },
        )
    )

    # 7) 畸形条目:缺少 request,应被标记为坏条目且不影响其他条目
    entries.append(
        {
            "startedDateTime": "2026-11-13T09:00:06.000Z",
            "time": 0,
            "response": {"status": 0, "headers": [], "content": {}},
            "cache": {},
            "timings": {},
        }
    )

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "har-sanitizer-demo", "version": "1.0"},
            "pages": [],
            "entries": entries,
        }
    }
