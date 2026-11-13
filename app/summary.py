"""脱敏摘要生成(Markdown)。

硬性要求:摘要与文件名都不得包含敏感原值。这里只输出定位、规则名、处理方式与代号,
原值一律不写入。
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from .models import (
    LOC_QUERY,
    LOC_REQ_BODY,
    LOC_REQ_HEADER,
    LOC_RESP_BODY,
    LOC_RESP_HEADER,
    TREATMENT_DELETE,
    TREATMENT_MASK,
    TREATMENT_PSEUDO,
)
from .session import Workspace

LOCATION_LABELS = {
    LOC_REQ_HEADER: "请求头",
    LOC_RESP_HEADER: "响应头",
    LOC_QUERY: "查询参数",
    LOC_REQ_BODY: "请求体",
    LOC_RESP_BODY: "响应体",
}

TREATMENT_LABELS = {
    TREATMENT_MASK: "固定遮盖",
    TREATMENT_DELETE: "删除字段",
    TREATMENT_PSEUDO: "一致化代号",
}


def build_summary(ws: Workspace) -> str:
    status = ws.scan_status()
    findings = ws.findings
    unchecked = ws.unchecked
    sanitized = ws.sanitized()
    changes = sanitized["changes"]

    lines: list[str] = []
    lines.append("# HAR 脱敏摘要")
    lines.append("")
    lines.append(f"- 生成时间:{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 源文件:{ws.source_name or '(演示数据)'}")
    total = len(ws.entries())
    lines.append(f"- HAR 条目总数:{total}")
    lines.append(f"- 发现项:{status['finding_count']} 条,"
                 f"已确认 {status['handled_count']} 条,"
                 f"未处理 {status['pending_count']} 条")
    lines.append(f"- 未检查内容:{status['unchecked_count']} 处")
    lines.append("")

    if status["has_leftover"]:
        lines.append("> ⚠️ **仍存在未处理的发现项或未检查内容,导出的 HAR 可能仍含敏感信息,请逐条复核。**")
        lines.append("")

    # 按条目分组
    by_entry: dict[int, list[Any]] = defaultdict(list)
    for f in findings:
        by_entry[f.entry_index].append(f)

    lines.append("## 各请求处理明细")
    lines.append("")
    if not by_entry:
        lines.append("本次扫描没有发现敏感内容。")
        lines.append("")
    for idx in sorted(by_entry):
        entry_findings = by_entry[idx]
        lines.append(f"### 请求 #{idx} `{ws.safe_url(idx)}`")
        lines.append("")
        lines.append("| 位置 | 字段定位 | 命中规则 | 处理方式 | 代号 | 状态 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for f in entry_findings:
            loc = LOCATION_LABELS.get(f.target.location, f.target.location)
            rules = "、".join(f.rule_names) or "-"
            treatment = TREATMENT_LABELS.get(f.treatment, f.treatment)
            code = f.pseudo_code if f.treatment == TREATMENT_PSEUDO else "-"
            state = "已确认" if f.handled else "**未处理**"
            lines.append(
                f"| {loc} | {f.field_label} | {rules} | {treatment} | {code} | {state} |"
            )
        lines.append("")

    lines.append("## 未检查内容(不能视为安全)")
    lines.append("")
    if not unchecked:
        lines.append("无。")
    else:
        lines.append("| 请求 | 位置 | 内容类型/字段 | 原因 |")
        lines.append("| --- | --- | --- | --- |")
        for u in unchecked:
            loc = LOCATION_LABELS.get(u.location, u.location)
            lines.append(
                f"| #{u.entry_index} | {loc} | {u.field_label or '-'} | {u.reason} |"
            )
    lines.append("")

    # 代号对照表(只列代号,不列原值)
    pseudo_used = sorted(
        {f.pseudo_code for f in findings
         if f.treatment == TREATMENT_PSEUDO and f.pseudo_code}
    )
    lines.append("## 一致化代号使用情况")
    lines.append("")
    if not pseudo_used:
        lines.append("本次没有使用一致化代号。")
    else:
        lines.append("同一代号代表同一个原值(原值不在本摘要中出现),可据此判断请求间关联:")
        lines.append("")
        for code in pseudo_used:
            owners = [
                f"#{f.entry_index} {LOCATION_LABELS.get(f.target.location, f.target.location)}"
                f"/{f.field_label}"
                for f in findings
                if f.treatment == TREATMENT_PSEUDO and f.pseudo_code == code
            ]
            lines.append(f"- `{code}` 出现 {len(owners)} 处:" + ";".join(owners))
    lines.append("")

    lines.append("## 实际改写位置(导出文件)")
    lines.append("")
    if not changes:
        lines.append("导出文件相对原文件没有正文改写。")
    else:
        for idx in sorted(changes):
            lines.append(f"- 请求 #{idx}:{len(changes[idx])} 处改写")
            for ch in changes[idx]:
                loc = LOCATION_LABELS.get(ch["location"], ch["location"])
                treatment = TREATMENT_LABELS.get(ch["treatment"], ch["treatment"])
                extra = f" → `{ch['pseudo_code']}`" if ch.get("pseudo_code") else ""
                lines.append(f"  - {loc}/{ch['field']}:{treatment}{extra}")
    lines.append("")

    lines.append("## 启用的规则")
    lines.append("")
    for rule in ws.rules:
        if rule.enabled:
            locs = "、".join(LOCATION_LABELS.get(loc, loc) for loc in rule.locations)
            lines.append(f"- {rule.name}({'内置' if rule.builtin else '自定义'}):{locs}")
    lines.append("")
    return "\n".join(lines)


def safe_export_name(prefix: str, ext: str) -> str:
    """生成不含任何用户数据的导出文件名。"""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}.{ext}"
