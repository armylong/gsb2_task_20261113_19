"""内存工作区:保存当前 HAR、规则、扫描结果与用户处理决定。

- 所有数据只在进程内存中,clear() 立即清空,不落盘、不写日志;
- 重新上传/重新扫描时旧脱敏结果不叠加:扫描按 target 身份只继承"处理决定",
  脱敏结果由当前 findings 重新生成;
- 预览与导出共用 sanitizer.apply_all 并带缓存,保证一致。
"""
from __future__ import annotations

import threading
from typing import Any

from .models import ALL_TREATMENTS, Finding, Rule
from .rules import builtin_rules
from .scanner import scan
from .sanitizer import apply_all, url_host_only


class Workspace:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.har: dict[str, Any] | None = None
        self.source_name: str = ""
        self.rules: list[Rule] = builtin_rules()
        self.findings: list[Finding] = []
        self.unchecked: list[Any] = []
        self.invalid_rules: list[tuple[Rule, str]] = []
        self._sanitized_cache: dict[str, Any] | None = None

    # ---------- 生命周期 ----------
    def load(self, har: dict[str, Any], source_name: str) -> None:
        with self._lock:
            self.har = har
            self.source_name = source_name
            self.rules = builtin_rules()
            self._run_scan()
            self._sanitized_cache = None

    def reset_to_demo(self, har: dict[str, Any]) -> None:
        self.load(har, "demo.har")

    def clear(self) -> None:
        with self._lock:
            self.har = None
            self.source_name = ""
            self.rules = builtin_rules()
            self.findings = []
            self.unchecked = []
            self.invalid_rules = []
            self._sanitized_cache = None

    @property
    def loaded(self) -> bool:
        return self.har is not None

    def entries(self) -> list[dict[str, Any]]:
        if not self.har:
            return []
        return self.har["log"]["entries"]

    # ---------- 规则 ----------
    def rescan(self) -> dict[str, Any]:
        with self._lock:
            self._run_scan()
            self._sanitized_cache = None
            return self.scan_status()

    def _run_scan(self) -> None:
        result = scan(self.entries(), self.rules, previous=self.findings)
        self.findings = result["findings"]
        self.unchecked = result["unchecked"]
        self.invalid_rules = result["invalid_rules"]

    def scan_status(self) -> dict[str, Any]:
        handled = sum(1 for f in self.findings if f.handled)
        return {
            "finding_count": len(self.findings),
            "handled_count": handled,
            "pending_count": len(self.findings) - handled,
            "unchecked_count": len(self.unchecked),
            "invalid_rules": [
                {"rule_id": r.id, "rule_name": r.name, "error": err}
                for r, err in self.invalid_rules
            ],
            "has_leftover": (len(self.findings) - handled) > 0 or bool(self.unchecked),
        }

    # ---------- 处理决定 ----------
    def set_treatment(
        self, finding_ids: list[str], treatment: str, handled: bool
    ) -> list[str]:
        if treatment not in ALL_TREATMENTS:
            raise ValueError(f"未知处理方式:{treatment}")
        ids = set(finding_ids)
        changed: list[str] = []
        with self._lock:
            for f in self.findings:
                if f.id in ids:
                    f.treatment = treatment
                    f.handled = handled
                    changed.append(f.id)
            self._sanitized_cache = None
        return changed

    def mark_handled(self, finding_ids: list[str], handled: bool) -> list[str]:
        ids = set(finding_ids)
        changed: list[str] = []
        with self._lock:
            for f in self.findings:
                if f.id in ids:
                    f.handled = handled
                    changed.append(f.id)
            self._sanitized_cache = None
        return changed

    def get_finding(self, finding_id: str) -> Finding | None:
        for f in self.findings:
            if f.id == finding_id:
                return f
        return None

    def findings_for_entry(self, index: int) -> list[Finding]:
        return [f for f in self.findings if f.entry_index == index]

    def unchecked_for_entry(self, index: int) -> list[Any]:
        return [u for u in self.unchecked if u.entry_index == index]

    # ---------- 脱敏执行(预览/导出共用) ----------
    def sanitized(self) -> dict[str, Any]:
        with self._lock:
            if self._sanitized_cache is None:
                if self.har is None:
                    raise RuntimeError("没有已加载的 HAR")
                new_har, changes = apply_all(self.har, self.findings)
                self._sanitized_cache = {"har": new_har, "changes": changes}
            return self._sanitized_cache

    def preview_entry(self, index: int) -> dict[str, Any]:
        sanitized = self.sanitized()
        entries = sanitized["har"]["log"]["entries"]
        if not 0 <= index < len(entries):
            raise IndexError("条目不存在")
        changes = sanitized["changes"].get(index, [])
        return {"entry": entries[index], "changes": changes}

    # ---------- 供摘要使用的安全 URL ----------
    def safe_url(self, index: int) -> str:
        entries = self.entries()
        if 0 <= index < len(entries) and not entries[index].get("_broken"):
            return url_host_only(str(entries[index]["request"].get("url", "")))
        return "(broken-entry)"


# 单例:同一时间只检查一份文件,符合"本地单用户"场景
workspace = Workspace()
