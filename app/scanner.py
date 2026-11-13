"""敏感内容扫描引擎。

关键约定:
- target_key 是命中位置的稳定身份,同一位置被多条规则命中只产生一条 Finding(规则聚合),
  因此后续脱敏不可能对同一处产生互相矛盾的替换;
- 遍历顺序固定(条目顺序 -> 头/参数出现顺序 -> 节点路径),一致化代号按该顺序确定性分配,
  同一原值永远得到同一代号,不同原值不会合并;
- 不认识/无法解码的内容进 unchecked,绝不标记为安全。
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl

from .hario import (
    ParsedBody,
    header_value,
    parse_request_body,
    parse_response_body,
)
from .models import (
    ALL_TREATMENTS,
    LOC_QUERY,
    LOC_REQ_BODY,
    LOC_REQ_HEADER,
    LOC_RESP_BODY,
    LOC_RESP_HEADER,
    Finding,
    Target,
    TREATMENT_MASK,
    UncheckedItem,
)
from .rules import Rule, compile_rules, fieldname_matches

_COOKIE_HEADERS = {"cookie", "set-cookie"}


def _mask_preview(value: str) -> str:
    if not value:
        return "********"
    return "********" if len(value) <= 8 else value[:2] + "******" + value[-2:]


def _target_key(target: Target) -> str:
    return target.key()


def _path_label(path: list[Any]) -> str:
    if not path:
        return "$"
    out = "$"
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}"
    return out


class _FindingBuilder:
    def __init__(self) -> None:
        self._by_key: dict[str, Finding] = {}
        self._order: list[str] = []
        self._seq = 0

    def add(
        self,
        entry_index: int,
        target: Target,
        raw_value: str,
        field_label: str,
        rule: Rule,
    ) -> Finding:
        key = _target_key(target)
        finding = self._by_key.get(key)
        if finding is None:
            self._seq += 1
            finding = Finding(
                id=f"f{self._seq:04d}",
                entry_index=entry_index,
                target=target,
                value_preview=_mask_preview(raw_value),
                raw_value=raw_value,
                field_label=field_label,
            )
            self._by_key[key] = finding
            self._order.append(key)
        if rule.id not in finding.rule_ids:
            finding.rule_ids.append(rule.id)
            finding.rule_names.append(rule.name)
        return finding

    def all(self) -> list[Finding]:
        return [self._by_key[k] for k in self._order]


def _split_cookie_request(value: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for chunk in value.split(";"):
        if "=" in chunk:
            name, val = chunk.split("=", 1)
            pairs.append((name.strip(), val.strip()))
        elif chunk.strip():
            pairs.append((chunk.strip(), ""))
    return pairs


def _split_set_cookie(value: str) -> tuple[str, str]:
    first = value.split(";", 1)[0]
    if "=" in first:
        name, val = first.split("=", 1)
        return name.strip(), val.strip()
    return first.strip(), ""


def _merge_spans(
    spans: list[tuple[int, int, str, Rule]]
) -> list[tuple[int, int, str, list[Rule]]]:
    """合并重叠的正则命中区间,规则聚合到同一区间。元素为 (起点, 终点, 命中值, 规则)。"""
    if not spans:
        return []
    spans = sorted(spans, key=lambda s: (s[0], -s[1]))
    merged: list[tuple[int, int, str, list[Rule]]] = []
    cur_start, cur_end, cur_value, cur_rules = (
        spans[0][0], spans[0][1], spans[0][2], [spans[0][3]],
    )
    for start, end, value, rule in spans[1:]:
        if start >= cur_end:
            merged.append((cur_start, cur_end, cur_value, cur_rules))
            cur_start, cur_end, cur_value, cur_rules = start, end, value, [rule]
        else:
            cur_end = max(cur_end, end)
            if rule not in cur_rules:
                cur_rules.append(rule)
    merged.append((cur_start, cur_end, cur_value, cur_rules))
    return merged


def _match_span(m: re.Match[str]) -> tuple[int, int, str]:
    """正则含捕获组时只取第一个捕获组(值部分),否则取整段匹配。"""
    if m.groups():
        return m.start(1), m.end(1), m.group(1)
    return m.start(), m.end(), m.group(0)


def _pseudo_category(label: str, rule_names: list[str], value: str) -> str:
    """按值形态与字段定位分类,不依赖规则名称(规则名常同时包含多个关键词)。"""
    if re.fullmatch(r"1[3-9]\d{9}", value or ""):
        return "PHONE"
    if re.fullmatch(
        r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", (value or ""), flags=re.IGNORECASE
    ):
        return "EMAIL"
    text = label.lower()
    if "cookie" in text or "set-cookie" in text:
        return "COOKIE"
    if "authorization" in text or "bearer" in text:
        return "TOKEN"
    if "password" in text or "密码" in text or ".pwd" in text:
        return "PWD"
    if "secret" in text or "apikey" in text or "api_key" in text or "密钥" in text:
        return "SECRET"
    if "token" in text or "session" in text:
        return "TOKEN"
    if "@" in (value or ""):
        return "EMAIL"
    return "CODE"


class Scanner:
    def __init__(self, rules: list[Rule]):
        self.compiled, self.invalid = compile_rules(rules)
        self.builder = _FindingBuilder()
        self.unchecked: list[UncheckedItem] = []

    # ---------- 规则分类工具 ----------
    def _rules_for(self, location: str) -> list[tuple[Rule, Any]]:
        return [(r, obj) for r, obj in self.compiled if location in r.locations]

    def _field_rules(self, location: str) -> list[tuple[Rule, list[str]]]:
        return [(r, obj) for r, obj in self._rules_for(location) if r.match_type == "fieldname"]

    def _regex_rules(self, location: str) -> list[tuple[Rule, re.Pattern[str]]]:
        return [(r, obj) for r, obj in self._rules_for(location) if r.match_type == "regex"]

    def _add(
        self,
        entry_index: int,
        target: Target,
        raw: str,
        label: str,
        rules: list[Rule],
    ) -> None:
        for rule in rules:
            self.builder.add(entry_index, target, raw, label, rule)

    # ---------- 头 ----------
    def scan_headers(self, entry_index: int, location: str, headers: list[dict[str, Any]]) -> None:
        for h_idx, header in enumerate(headers):
            if not isinstance(header, dict):
                continue
            name = str(header.get("name", ""))
            value = str(header.get("value", ""))
            low = name.lower()
            if low in _COOKIE_HEADERS:
                self._scan_cookie_header(
                    entry_index, location, name, value, h_idx
                )
                continue
            # 字段名规则(通配 "*" 只用于 cookie,不匹配普通头)
            hit = [
                r for r, pats in self._field_rules(location)
                if pats != ["*"] and fieldname_matches(r, pats, name)
            ]
            if hit:
                target = Target(
                    location=location, header_name=name, kind="header",
                    index=h_idx,
                )
                self._add(entry_index, target, value, f"{name} 头", hit)
            # 值正则规则
            self._scan_text_value(
                entry_index, location, value,
                label_prefix=f"{name} 头",
                header_name=name, kind="header", base_index=h_idx,
            )

    def _scan_cookie_header(
        self, entry_index: int, location: str, header_name: str, value: str, h_idx: int
    ) -> None:
        if location == LOC_REQ_HEADER:
            items = _split_cookie_request(value)
        else:
            name, val = _split_set_cookie(value)
            items = [(name, val)]
        for c_idx, (cname, cval) in enumerate(items):
            hit = [r for r, _ in self._field_rules(location)
                   if fieldname_matches(r, _pats_of(r, self.compiled), cname)]
            label = f"{header_name}.{cname}"
            if hit:
                target = Target(
                    location=location, header_name=header_name, kind="cookie",
                    name=cname, index=c_idx,
                )
                # header_index 标记该 cookie 所属头的数组下标(多个 Set-Cookie 时关键)
                target.header_index = h_idx
                self._add(entry_index, target, cval, label, hit)
            # cookie 值仍跑值正则(如手机号、邮箱),与字段名命中聚合到同一 target
            for rule, pattern in self._regex_rules(location):
                for m in pattern.finditer(cval):
                    s, e, matched = _match_span(m)
                    target = Target(
                        location=location, header_name=header_name, kind="cookie",
                        name=cname, index=c_idx, start=s, end=e,
                    )
                    target.header_index = h_idx
                    self._add(entry_index, target, matched,
                              f"{label} 值片段", [rule])

    # ---------- 查询参数 ----------
    def scan_query(self, entry_index: int, url: str, har_query: list[dict[str, Any]]) -> None:
        location = LOC_QUERY
        # 以 URL 实际查询串为准(保留重复参数与原始编码),HAR 的 queryString 仅作兜底
        if "?" in url:
            pairs = parse_qsl(url.split("?", 1)[1], keep_blank_values=True)
        elif har_query:
            pairs = [(str(q.get("name", "")), str(q.get("value", ""))) for q in har_query]
        else:
            pairs = []
        for q_idx, (name, value) in enumerate(pairs):
            hit = [r for r, pats in self._field_rules(location)
                   if fieldname_matches(r, pats, name)]
            if hit:
                target = Target(location=location, kind="param", name=name, index=q_idx)
                self._add(entry_index, target, value, f"查询参数 {name}", hit)
            for rule, pattern in self._regex_rules(location):
                for m in pattern.finditer(value):
                    s, e, matched = _match_span(m)
                    target = Target(
                        location=location, kind="param", name=name,
                        index=q_idx, start=s, end=e,
                    )
                    self._add(entry_index, target, matched,
                              f"查询参数 {name} 值片段", [rule])

    # ---------- 正文 ----------
    def scan_body(self, entry_index: int, location: str, parsed: ParsedBody) -> None:
        if parsed.kind == "empty":
            return
        if parsed.kind in ("binary", "base64-error", "json-error"):
            self.unchecked.append(
                UncheckedItem(
                    entry_index=entry_index,
                    location=location,
                    reason=parsed.error or "内容无法检查",
                    field_label=parsed.mime,
                )
            )
            # json-error 仍保留对原始文本的值正则扫描,尽量发现明显凭据
            if parsed.kind == "json-error" and parsed.text:
                self._scan_plain_text(entry_index, location, parsed.text)
            return
        if parsed.kind == "json":
            self._scan_json_node(entry_index, location, parsed.data, [])
            return
        if parsed.kind == "form":
            self._scan_form(entry_index, location, parsed.data)
            return
        # 普通文本
        self._scan_plain_text(entry_index, location, parsed.text)

    def _scan_json_node(
        self, entry_index: int, location: str, node: Any, path: list[Any]
    ) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                self._scan_json_node(entry_index, location, child, path + [key])
        elif isinstance(node, list):
            for i, child in enumerate(node):
                self._scan_json_node(entry_index, location, child, path + [i])
        elif isinstance(node, str):
            label = _path_label(path)
            field_name = path[-1] if path and isinstance(path[-1], str) else ""
            hit = [r for r, pats in self._field_rules(location)
                   if field_name and fieldname_matches(r, pats, field_name)]
            if hit:
                target = Target(location=location, kind="json", name=field_name, path=list(path))
                self._add(entry_index, target, node, f"JSON {label}", hit)
            for rule, pattern in self._regex_rules(location):
                for m in pattern.finditer(node):
                    s, e, matched = _match_span(m)
                    target = Target(
                        location=location, kind="json", name=field_name,
                        path=list(path), start=s, end=e,
                    )
                    self._add(entry_index, target, matched,
                              f"JSON {label} 值片段", [rule])
        # 数字/布尔/null:无字符串形态,跳过

    def _scan_form(self, entry_index: int, location: str, pairs: list[tuple[str, str]]) -> None:
        for f_idx, (name, value) in enumerate(pairs):
            hit = [r for r, pats in self._field_rules(location)
                   if fieldname_matches(r, pats, name)]
            if hit:
                target = Target(location=location, kind="form", name=name, index=f_idx)
                self._add(entry_index, target, value, f"表单参数 {name}", hit)
            for rule, pattern in self._regex_rules(location):
                for m in pattern.finditer(value):
                    s, e, matched = _match_span(m)
                    target = Target(
                        location=location, kind="form", name=name,
                        index=f_idx, start=s, end=e,
                    )
                    self._add(entry_index, target, matched,
                              f"表单参数 {name} 值片段", [rule])

    def _scan_plain_text(self, entry_index: int, location: str, text: str) -> None:
        spans = [
            (*_match_span(m), rule)
            for rule, pattern in self._regex_rules(location)
            for m in pattern.finditer(text)
        ]
        for start, end, matched, rules in _merge_spans(spans):
            target = Target(location=location, kind="text", start=start, end=end)
            self._add(entry_index, target, matched, "正文文本片段", rules)

    def _scan_text_value(
        self,
        entry_index: int,
        location: str,
        value: str,
        label_prefix: str,
        header_name: str,
        kind: str,
        base_index: int,
    ) -> None:
        spans = [
            (*_match_span(m), rule)
            for rule, pattern in self._regex_rules(location)
            for m in pattern.finditer(value)
        ]
        for start, end, matched, rules in _merge_spans(spans):
            target = Target(
                location=location, header_name=header_name, kind=kind,
                index=base_index, start=start, end=end,
            )
            self._add(entry_index, target, matched,
                      f"{label_prefix} 值片段", rules)


def _pats_of(rule: Rule, compiled: list[tuple[Rule, Any]]) -> list[str]:
    for r, obj in compiled:
        if r.id == rule.id:
            return obj  # type: ignore[no-any-return]
    return []


def assign_pseudo_codes(findings: list[Finding]) -> dict[str, str]:
    """按确定性顺序为所有原值分配一致化代号(只预分配,是否使用由 treatment 决定)。"""
    pseudo_map: dict[str, str] = {}
    counters: dict[str, int] = {}
    for finding in findings:
        value = finding.raw_value
        if value in pseudo_map:
            finding.pseudo_code = pseudo_map[value]
            continue
        category = _pseudo_category(finding.field_label, finding.rule_names, value)
        counters[category] = counters.get(category, 0) + 1
        code = f"{category}_{counters[category]:03d}"
        pseudo_map[value] = code
        finding.pseudo_code = code
    return pseudo_map


def scan(
    entries: list[dict[str, Any]],
    rules: list[Rule],
    previous: list[Finding] | None = None,
) -> dict[str, Any]:
    """执行全量扫描。previous 用于在重新检查时保留用户已选处理方式与确认状态。"""
    scanner = Scanner(rules)
    prev_by_key = {_target_key(f.target): f for f in (previous or [])}

    for idx, entry in enumerate(entries):
        if entry.get("_broken"):
            continue
        request = entry["request"]
        response = entry.get("response") or {}
        scanner.scan_headers(idx, LOC_REQ_HEADER, request.get("headers", []))
        scanner.scan_headers(idx, LOC_RESP_HEADER, response.get("headers", []))
        scanner.scan_query(idx, str(request.get("url", "")), request.get("queryString", []))
        scanner.scan_body(idx, LOC_REQ_BODY, parse_request_body(request))
        scanner.scan_body(idx, LOC_RESP_BODY, parse_response_body(response))

    findings = scanner.builder.all()
    # 重新检查不叠加旧结果:处理方式按 target 身份继承,找不到身份的旧结果直接丢弃
    for finding in findings:
        old = prev_by_key.get(_target_key(finding.target))
        if old is not None:
            if old.treatment in ALL_TREATMENTS:
                finding.treatment = old.treatment
            finding.handled = old.handled

    pseudo_map = assign_pseudo_codes(findings)
    return {
        "findings": findings,
        "unchecked": scanner.unchecked,
        "invalid_rules": scanner.invalid,
        "pseudo_map": pseudo_map,
    }
