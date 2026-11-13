"""核心数据模型:规则、定位目标、发现项。

设计要点:
- Target 记录命中位置的结构化定位,脱敏时按定位精确改写,不靠字符串替换;
- Finding 的 target_key 是稳定身份(不依赖规则),同一处被多条规则命中只生成一条发现项,
  因此多条规则不会产生互相矛盾的替换结果;
- 发现项里保存原始值,但默认不会通过列表接口返回,只有用户显式请求 reveal 才下发。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# ---- 位置常量 ----
LOC_REQ_HEADER = "request_header"
LOC_RESP_HEADER = "response_header"
LOC_QUERY = "query"
LOC_REQ_BODY = "request_body"
LOC_RESP_BODY = "response_body"

ALL_LOCATIONS = (
    LOC_REQ_HEADER,
    LOC_RESP_HEADER,
    LOC_QUERY,
    LOC_REQ_BODY,
    LOC_RESP_BODY,
)

# ---- 处理方式 ----
TREATMENT_MASK = "mask"          # 固定遮盖
TREATMENT_DELETE = "delete"      # 删除字段
TREATMENT_PSEUDO = "pseudo"      # 一致化代号
ALL_TREATMENTS = (TREATMENT_MASK, TREATMENT_DELETE, TREATMENT_PSEUDO)

# 固定遮盖占位符
MASK_VALUE = "[REDACTED]"


@dataclass
class Rule:
    """一条自定义/内置规则。

    match_type:
      - fieldname: 按字段名匹配(大小写不敏感,子串匹配,多个模式之间为"或")
      - regex:     按正则匹配值(大小写不敏感)
    locations: 规则生效的位置集合。
    """

    id: str
    name: str
    match_type: str          # "fieldname" | "regex"
    pattern: str             # 正则源串;fieldname 规则里用逗号分隔多个字段名模式
    locations: list[str]
    enabled: bool = True
    builtin: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Target:
    """命中位置的结构化定位。"""

    location: str
    # header / cookie: header 名;query/form/json/text: 无意义,留空
    header_name: str = ""
    # cookie 所属头在 headers 数组中的下标(多个同名 Set-Cookie 时用于区分)
    header_index: int = -1
    # header 情况下区分整头("header")与 cookie 子项("cookie")
    kind: str = ""
    # cookie 子项名 / query 或 form 参数名
    name: str = ""
    # 同名参数的第几个(0 起),json 数组下标也用它
    index: int = 0
    # json 节点路径,如 ["user", "emails", 0]
    path: list[Any] = field(default_factory=list)
    # 纯文本正则命中的字符区间(半开区间)
    start: int = -1
    end: int = -1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def key(self) -> str:
        return "|".join(
            [
                self.location,
                self.header_name,
                str(self.header_index),
                self.kind,
                self.name,
                str(self.index),
                "/".join(str(p) for p in self.path),
                str(self.start),
                str(self.end),
            ]
        )


@dataclass
class Finding:
    """一条敏感发现项。同一 target_key 只保留一条,命中规则聚合在 rule_ids 中。"""

    id: str
    entry_index: int
    target: Target
    value_preview: str          # 已遮盖的预览,列表默认展示
    raw_value: str              # 原始值,仅 reveal 接口下发
    field_label: str            # 人类可读的字段定位描述
    rule_ids: list[str] = field(default_factory=list)
    rule_names: list[str] = field(default_factory=list)
    treatment: str = TREATMENT_MASK
    handled: bool = False       # 用户是否已确认处理方式
    # 一致化代号在扫描期按全局确定性顺序预分配,保证预览与导出完全一致
    pseudo_code: str = ""

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        data = {
            "id": self.id,
            "entry_index": self.entry_index,
            "location": self.target.location,
            "target": self.target.to_dict(),
            "value_preview": self.value_preview,
            "field_label": self.field_label,
            "rule_ids": list(self.rule_ids),
            "rule_names": list(self.rule_names),
            "treatment": self.treatment,
            "handled": self.handled,
            "pseudo_code": self.pseudo_code,
        }
        if include_raw:
            data["raw_value"] = self.raw_value
        return data


@dataclass
class UncheckedItem:
    """无法检查的内容(二进制、无法解码、不支持的格式、畸形 JSON 等)。"""

    entry_index: int
    location: str
    reason: str
    field_label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
