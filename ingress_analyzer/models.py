"""路由规则、Header 条件与代理配置模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet


class PathType(str, Enum):
    """路径匹配类型。"""

    EXACT = "exact"
    PREFIX = "prefix"
    WILDCARD = "wildcard"
    DEFAULT = "default"


class HeaderOp(str, Enum):
    """单条 Header 条件的操作符。同一规则内的多条条件按 AND 组合。"""

    PRESENT = "present"
    ABSENT = "absent"
    EXACT = "exact"
    PREFIX = "prefix"
    REGEX = "regex"


@dataclass(frozen=True)
class HeaderCondition:
    name: str
    op: HeaderOp
    value: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("header name 不能为空")
        op = HeaderOp(self.op)
        if op in (HeaderOp.EXACT, HeaderOp.PREFIX, HeaderOp.REGEX):
            if self.value is None:
                raise ValueError(f"{op.value} 条件必须提供 value")
        elif self.value is not None:
            raise ValueError(f"{op.value} 条件不允许带 value")

    @property
    def normalized_name(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class ProxyProfile:
    """描述真实代理（或评审工具）如何处理请求路径。

    ``decode_path``           是否先对百分号编码做 URL 解码再匹配
    ``case_fold``             路径是否大小写不敏感
    ``merge_slashes``         是否折叠重复斜杠
    ``encoded_slash_action``  对 %2F/%5C 的处理策略
    ``invalid_encoding``      非法百分号序列策略：reject/lenient
    """

    name: str
    decode_path: bool = True
    case_fold: bool = False
    merge_slashes: bool = True
    encoded_slash_action: str = "decode"
    invalid_encoding: str = "reject"

    def __post_init__(self) -> None:
        if self.encoded_slash_action not in ("decode", "reject", "keep_encoded"):
            raise ValueError("encoded_slash_action 只能是 decode/reject/keep_encoded")
        if self.invalid_encoding not in ("reject", "lenient"):
            raise ValueError("invalid_encoding 只能是 reject/lenient")


@dataclass
class Rule:
    """一条 Ingress 路由规则。

    ``host=None`` 或空字符串表示捕获所有 host（默认/兜底 host）。
    ``host`` 支持 ``*.example.com`` 形式的单标签通配（Kubernetes 风格）。
    ``methods`` 为空表示允许全部方法。
    ``path_type=DEFAULT`` 时 path 应为 ``/``，表示路径维度的默认路由。
    """

    name: str
    path_type: PathType
    path: str = "/"
    host: str | None = None
    methods: FrozenSet[str] | set[str] | tuple[str, ...] = frozenset()
    headers: tuple[HeaderCondition, ...] | list[HeaderCondition] = ()
    priority: int = 0

    def __post_init__(self) -> None:
        self.path_type = PathType(self.path_type)
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("path 必须是非空字符串")
        if self.path_type is PathType.DEFAULT and self.path != "/":
            raise ValueError("DEFAULT 路由的 path 必须是 /")
        if self.path_type is PathType.WILDCARD and "*" not in self.path:
            raise ValueError("WILDCARD 规则的 path 必须包含 *")
        if self.host is not None:
            self.host = self.host.strip().lower() or None
        method_set = frozenset(m.upper() for m in self.methods)
        self.methods = method_set
        header_tuple = tuple(self.headers)
        seen: dict[str, None] = {}
        for condition in header_tuple:
            seen.setdefault(condition.normalized_name, None)
        if len(seen) != len(header_tuple):
            raise ValueError("同一 header 上的多个条件暂不支持，请合并为一条")
        self.headers = header_tuple

    @property
    def is_default_path(self) -> bool:
        return self.path_type is PathType.DEFAULT

