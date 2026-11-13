"""规则定义与编译。

内置规则覆盖需求中的默认识别面:
1. authorization / proxy-authorization 等凭据头;
2. 全部 cookie(请求 Cookie 与响应 Set-Cookie 的每个子项);
3. 字段名含 token/password/secret/key 等(大小写不影响识别);
4. 值形态:邮箱、中国大陆手机号、Bearer/JWT。

fieldname 规则对字段名做大小写不敏感的子串匹配;regex 规则对值做大小写不敏感匹配。
"""
from __future__ import annotations

import re
from uuid import uuid4

from .models import (
    ALL_LOCATIONS,
    LOC_QUERY,
    LOC_REQ_BODY,
    LOC_REQ_HEADER,
    LOC_RESP_BODY,
    LOC_RESP_HEADER,
    Rule,
)

VALID_MATCH_TYPES = ("fieldname", "regex")

# 常见敏感字段名(子串、大小写不敏感)
SENSITIVE_FIELD_NAMES = (
    "token",
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "auth",
    "credential",
    "session",
    "email",
    "mail",
    "phone",
    "mobile",
    "tel",
)

# 值形态正则(大小写不敏感)
EMAIL_RE = r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}"
# 中国大陆手机号:11 位,1 开头,第二位 3-9,要求两侧不是数字避免截断长数字串
MOBILE_CN_RE = r"(?<!\d)1[3-9]\d{9}(?!\d)"
# Bearer 前缀令牌或三段式 JWT
BEARER_JWT_RE = r"Bearer\s+[A-Z0-9._-]{8,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
# 硬编码形态的通用密钥:key="xxxx"(覆盖 HTML/JS 文本里的 token='...' 这类场景)
# 捕获组 1 只圈定值部分,字段名保持原样不被替换
INLINE_SECRET_RE = (
    r"""(?:token|secret|password|api[_-]?key|session)["']?\s*[:=]\s*["']?"""
    r"([A-Za-z0-9._\-]{8,})"
)

_BODY_AND_QUERY = (LOC_QUERY, LOC_REQ_BODY, LOC_RESP_BODY)
_ALL = ALL_LOCATIONS


def builtin_rules() -> list[Rule]:
    return [
        Rule(
            id="builtin-auth-header",
            name="凭据请求头(Authorization 等)",
            match_type="fieldname",
            pattern=(
                "authorization,proxy-authorization,x-api-token,x-auth-token,"
                "x-apikey,api-key,x-api-key,apikey,x-secret,x-access-token"
            ),
            locations=[LOC_REQ_HEADER],
            builtin=True,
        ),
        Rule(
            id="builtin-cookie",
            name="Cookie / Set-Cookie 全部子项",
            match_type="fieldname",
            pattern="*",  # 特殊标记:匹配任意 cookie 子项
            locations=[LOC_REQ_HEADER, LOC_RESP_HEADER],
            builtin=True,
        ),
        Rule(
            id="builtin-sensitive-fields",
            name="敏感字段名(token/密码/密钥/邮箱/手机号等)",
            match_type="fieldname",
            pattern=",".join(SENSITIVE_FIELD_NAMES),
            locations=list(_BODY_AND_QUERY),
            builtin=True,
        ),
        Rule(
            id="builtin-email",
            name="邮箱地址(按值匹配)",
            match_type="regex",
            pattern=EMAIL_RE,
            locations=list(_BODY_AND_QUERY),
            builtin=True,
        ),
        Rule(
            id="builtin-mobile-cn",
            name="中国大陆手机号(按值匹配)",
            match_type="regex",
            pattern=MOBILE_CN_RE,
            locations=list(_BODY_AND_QUERY),
            builtin=True,
        ),
        Rule(
            id="builtin-bearer-jwt",
            name="Bearer 令牌 / JWT(按值匹配)",
            match_type="regex",
            pattern=BEARER_JWT_RE,
            locations=list(_ALL),
            builtin=True,
        ),
        Rule(
            id="builtin-inline-secret",
            name="硬编码密钥形态 token=\"...\"/password=...(按值匹配)",
            match_type="regex",
            pattern=INLINE_SECRET_RE,
            locations=list(_BODY_AND_QUERY),
            builtin=True,
        ),
    ]


def new_rule_id() -> str:
    return f"rule-{uuid4().hex[:12]}"


def validate_rule(match_type: str, pattern: str, locations: list[str]) -> str | None:
    """校验规则,返回错误信息;合法返回 None。"""
    if match_type not in VALID_MATCH_TYPES:
        return f"匹配类型必须是 {VALID_MATCH_TYPES} 之一"
    if not pattern or not pattern.strip():
        return "匹配模式不能为空"
    bad_locs = [loc for loc in locations if loc not in ALL_LOCATIONS]
    if bad_locs:
        return f"存在不支持的检查位置:{', '.join(bad_locs)}"
    if not locations:
        return "至少选择一个检查位置"
    if match_type == "regex":
        try:
            re.compile(pattern, flags=re.IGNORECASE)
        except re.error as exc:
            return f"非法正则:{exc.msg}"
    return None


def split_field_patterns(pattern: str) -> list[str]:
    return [p.strip().lower() for p in pattern.split(",") if p.strip()]


def compile_rules(rules: list[Rule]) -> tuple[list[tuple[Rule, Any]], list[tuple[Rule, str]]]:
    """编译规则,返回(可执行规则列表, 非法规则及原因)。非法规则不影响其他规则。"""
    compiled: list[tuple[Rule, Any]] = []
    invalid: list[tuple[Rule, str]] = []
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.match_type == "regex":
            try:
                compiled.append((rule, re.compile(rule.pattern, flags=re.IGNORECASE)))
            except re.error as exc:
                invalid.append((rule, f"非法正则:{exc.msg}"))
        else:
            compiled.append((rule, split_field_patterns(rule.pattern)))
    return compiled, invalid


def fieldname_matches(rule: Rule, patterns: list[str], field_name: str) -> bool:
    name = (field_name or "").lower()
    if not name:
        return False
    for pat in patterns:
        if pat == "*":
            return True
        if pat in name:
            return True
    return False
