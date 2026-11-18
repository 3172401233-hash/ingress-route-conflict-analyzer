"""规则重叠/遮蔽分析主入口。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .matcher import (
    PathMatcher,
    Relation,
    build_matcher,
    pattern_relation,
)
from .models import HeaderCondition, HeaderOp, ProxyProfile, Rule
from .normalization import ENCODED_SLASH, NormalizedPath, normalize_path
from .profiles import NGINX_DECODED


@dataclass
class CompiledRule:
    rule: Rule
    matcher: PathMatcher
    path_warnings: list[str] = field(default_factory=list)


@dataclass
class WitnessRequest:
    """一条可以用来复现/区分冲突的具体请求。"""

    host: Optional[str]
    path: str
    method: str
    headers: dict[str, str]
    matched_by: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    first: str
    second: str
    overlap: bool
    full_shadow: bool
    relation: Relation
    reason: str
    witness_requests: list[WitnessRequest] = field(default_factory=list)
    profile_notes: list[str] = field(default_factory=list)


@dataclass
class ChainReport:
    order: list[str]
    shadows: list[AnalysisResult]
    overlaps: list[AnalysisResult]
    unreachable: list[str]
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Host / method / header 维度
# ---------------------------------------------------------------------------


def _host_relation(host_a: Optional[str], host_b: Optional[str]) -> Relation:
    if not host_a and not host_b:
        return Relation.EQUAL
    if not host_a:
        return Relation.CONTAINS  # a 捕获所有 host，包含 b
    if not host_b:
        return Relation.SUBSET

    def wildcard_labels(host: str) -> Optional[tuple[str, ...]]:
        if host.startswith("*."):
            return tuple(host[2:].split("."))
        return None

    labels_a = wildcard_labels(host_a)
    labels_b = wildcard_labels(host_b)
    if labels_a is None and labels_b is None:
        return Relation.EQUAL if host_a == host_b else Relation.DISJOINT
    if labels_a is None:
        suffix = ("." + host_a)
        return Relation.SUBSET if host_a.endswith("." + ".".join(labels_b)) else (
            Relation.DISJOINT
        )
    if labels_b is None:
        return Relation.CONTAINS if host_b.endswith("." + ".".join(labels_a)) else (
            Relation.DISJOINT
        )
    if labels_a == labels_b:
        return Relation.EQUAL
    if len(labels_a) > len(labels_b) and labels_a[-len(labels_b):] == labels_b:
        return Relation.SUBSET
    if len(labels_b) > len(labels_a) and labels_b[-len(labels_a):] == labels_a:
        return Relation.CONTAINS
    return Relation.DISJOINT


def _methods_relation(methods_a: frozenset[str], methods_b: frozenset[str]) -> Relation:
    if not methods_a and not methods_b:
        return Relation.EQUAL
    if not methods_a:
        return Relation.CONTAINS
    if not methods_b:
        return Relation.SUBSET
    if methods_a == methods_b:
        return Relation.EQUAL
    if methods_a < methods_b:
        return Relation.SUBSET
    if methods_b < methods_a:
        return Relation.CONTAINS
    if methods_a & methods_b:
        return Relation.OVERLAP
    return Relation.DISJOINT


def _header_matches(condition: HeaderCondition, headers: dict[str, str]) -> bool:
    value = headers.get(condition.normalized_name)
    if condition.op is HeaderOp.PRESENT:
        return value is not None
    if condition.op is HeaderOp.ABSENT:
        return value is None
    if value is None:
        return False
    if condition.op is HeaderOp.EXACT:
        return value == condition.value
    if condition.op is HeaderOp.PREFIX:
        return value.startswith(condition.value or "")
    return re.search(condition.value or "", value) is not None


def _headers_conflict(
    headers_a: tuple[HeaderCondition, ...], headers_b: tuple[HeaderCondition, ...]
) -> Optional[str]:
    by_a = {condition.normalized_name: condition for condition in headers_a}
    by_b = {condition.normalized_name: condition for condition in headers_b}
    for name in by_a.keys() & by_b.keys():
        condition_a = by_a[name]
        condition_b = by_b[name]
        ops = {condition_a.op, condition_b.op}
        if ops == {HeaderOp.PRESENT, HeaderOp.ABSENT}:
            return f"header {name} 的 present/absent 条件互斥"
        if HeaderOp.ABSENT in ops and HeaderOp.EXACT in ops:
            return f"header {name} 的 absent 与 exact 条件互斥"
        if condition_a.op is HeaderOp.EXACT and condition_b.op is HeaderOp.EXACT:
            if condition_a.value != condition_b.value:
                return f"header {name} 要求不同的精确值"
        if condition_a.op is HeaderOp.PREFIX and condition_b.op is HeaderOp.PREFIX:
            value_a, value_b = condition_a.value or "", condition_b.value or ""
            if not (value_a.startswith(value_b) or value_b.startswith(value_a)):
                return f"header {name} 的两个前缀条件互不包含"
    return None


def _condition_covers(
    covering: HeaderCondition | None, target: HeaderCondition
) -> bool:
    """covering 条件是否能覆盖 target（满足 covering 一定满足 target）。

    covering 为 None 表示该 header 上没有任何约束，天然覆盖任意 target。
    """
    if covering is None:
        return True
    if covering.normalized_name != target.normalized_name:
        return False
    if target.op is HeaderOp.PRESENT:
        return covering.op in (HeaderOp.PRESENT, HeaderOp.EXACT, HeaderOp.PREFIX)
    if target.op is covering.op:
        if covering.op in (HeaderOp.EXACT, HeaderOp.PREFIX):
            return covering.value == target.value
        return True
    if covering.op is HeaderOp.EXACT and target.op is HeaderOp.PREFIX:
        return (covering.value or "").startswith(target.value or "")
    return False


def _headers_implies(
    covering_headers: tuple[HeaderCondition, ...],
    target_headers: tuple[HeaderCondition, ...],
) -> bool:
    """covering 的 header 约束是否蕴含 target 的全部约束。"""
    by_covering = {
        condition.normalized_name: condition for condition in covering_headers
    }
    by_target = {
        condition.normalized_name: condition for condition in target_headers
    }
    # covering 上存在 target 没有的约束时，covering 的语言更窄，无法覆盖
    if any(name not in by_target for name in by_covering):
        return False
    return all(
        _condition_covers(by_covering.get(target.normalized_name), target)
        for target in target_headers
    )


# ---------------------------------------------------------------------------
# 规则编译与分析
# ---------------------------------------------------------------------------


def compile_rule(rule: Rule, profile: ProxyProfile) -> CompiledRule:
    normalized = normalize_path(rule.path, profile)
    matcher = build_matcher(rule.path_type, normalized.normalized)
    return CompiledRule(rule, matcher, list(normalized.warnings))


def _pick_method(methods_a: frozenset[str], methods_b: frozenset[str]) -> str:
    common = methods_a & methods_b if methods_a and methods_b else (methods_a or methods_b)
    return next(iter(common)) if common else "GET"


def _pick_host(host_a: Optional[str], host_b: Optional[str]) -> Optional[str]:
    for host in (host_a, host_b):
        if host:
            return host.lstrip("*.") if host.startswith("*.") else host
    return None


def _build_headers(rule: Rule) -> dict[str, str]:
    headers: dict[str, str] = {}
    for condition in rule.headers:
        if condition.op in (HeaderOp.PRESENT, HeaderOp.EXACT, HeaderOp.PREFIX):
            headers[condition.normalized_name] = condition.value or "value"
    return headers


def compare_rules(
    first: Rule,
    second: Rule,
    profile: ProxyProfile = NGINX_DECODED,
) -> AnalysisResult:
    compiled_a = compile_rule(first, profile)
    compiled_b = compile_rule(second, profile)
    notes = sorted(set(compiled_a.path_warnings + compiled_b.path_warnings))

    host_rel = _host_relation(first.host, second.host)
    method_rel = _methods_relation(first.methods, second.methods)
    if host_rel is Relation.DISJOINT:
        return AnalysisResult(
            first.name, second.name, False, False, Relation.DISJOINT, "host 不相交", notes
        )
    if method_rel is Relation.DISJOINT:
        return AnalysisResult(
            first.name, second.name, False, False, Relation.DISJOINT, "method 不相交", notes
        )

    header_conflict = _headers_conflict(first.headers, second.headers)
    if header_conflict:
        return AnalysisResult(
            first.name, second.name, False, False, Relation.DISJOINT, header_conflict, notes
        )

    path_rel, witnesses = pattern_relation(compiled_a.matcher, compiled_b.matcher)
    if path_rel is Relation.DISJOINT:
        return AnalysisResult(
            first.name,
            second.name,
            False,
            False,
            Relation.DISJOINT,
            "路径模式不相交",
            profile_notes=notes,
        )

    host_covers = host_rel in (Relation.CONTAINS, Relation.EQUAL)
    method_covers = method_rel in (Relation.CONTAINS, Relation.EQUAL)
    # _headers_implies(a, b) 判断 a 的条件是否蕴含 b；前者无条件时
    # 空条件集合蕴含后者的任意条件，因此遮蔽成立
    header_covers = _headers_implies(first.headers, second.headers)
    # 前者遮蔽后者：前者的路径集合包含后者（SUBSET 表示前者更小，
    # CONTAINS/EQUAL 表示前者覆盖后者），这里按“前者语言 ⊇ 后者语言”判断
    path_covers = path_rel in (Relation.CONTAINS, Relation.EQUAL)
    full_shadow = host_covers and method_covers and header_covers and path_covers

    witness_requests: list[WitnessRequest] = []
    host = _pick_host(first.host, second.host)
    method = _pick_method(first.methods, second.methods)
    headers = {**_build_headers(second), **_build_headers(first)}

    for bucket, path in witnesses.items():
        matched: list[str] = []
        if bucket in ("both", "only_a"):
            matched.append(first.name)
        if bucket in ("both", "only_b"):
            matched.append(second.name)
        witness_requests.append(WitnessRequest(host, path, method, dict(headers), matched))

    if full_shadow:
        reason = "第一条规则在 host/method/header/path 四个维度上都覆盖第二条"
    else:
        blockers: list[str] = []
        if not path_covers:
            blockers.append("路径仅部分重叠")
        if not host_covers:
            blockers.append("host 范围更宽")
        if not method_covers:
            blockers.append("method 范围更宽")
        if not header_covers:
            blockers.append("header 条件不蕴含后者")
        reason = "；".join(blockers)

    return AnalysisResult(
        first.name,
        second.name,
        True,
        full_shadow,
        path_rel,
        reason,
        witness_requests,
        notes,
    )


def analyze_chain(
    rules: list[Rule],
    profile: ProxyProfile = NGINX_DECODED,
) -> ChainReport:
    """按实际评估顺序（priority 升序，同优先级按配置顺序）分析整条链路。"""
    ordered = sorted(
        enumerate(rules),
        key=lambda item: (item[1].priority, item[0]),
    )
    order = [rule.name for _, rule in ordered]
    shadows: list[AnalysisResult] = []
    overlaps: list[AnalysisResult] = []
    warnings: list[str] = []
    covered: set[str] = set()

    for index, (_, rule_b) in enumerate(ordered):
        for _, rule_a in ordered[:index]:
            result = compare_rules(rule_a, rule_b, profile)
            warnings.extend(result.profile_notes)
            if not result.overlap:
                continue
            if result.full_shadow:
                shadows.append(result)
                covered.add(rule_b.name)
            else:
                overlaps.append(result)

    return ChainReport(
        order=order,
        shadows=shadows,
        overlaps=overlaps,
        unreachable=sorted(covered),
        warnings=sorted(set(warnings)),
    )


def match_request(
    rule: Rule,
    host: Optional[str],
    raw_path: str,
    method: str,
    headers: Optional[dict[str, str]] = None,
    profile: ProxyProfile = NGINX_DECODED,
) -> tuple[bool, NormalizedPath]:
    """模拟真实代理判断单条规则是否命中，返回 (是否命中, 规范化结果)。"""
    normalized = normalize_path(raw_path, profile)
    if not normalized.ok:
        return False, normalized

    if rule.host:
        request_host = (host or "").lower()
        if rule.host.startswith("*."):
            suffix = rule.host[1:]  # ".example.com"
            if not request_host.endswith(suffix) or request_host.count(".") < 2:
                return False, normalized
        elif request_host != rule.host:
            return False, normalized

    if rule.methods and method.upper() not in rule.methods:
        return False, normalized

    request_headers = {key.lower(): value for key, value in (headers or {}).items()}
    if any(not _header_matches(condition, request_headers) for condition in rule.headers):
        return False, normalized

    compiled = compile_rule(rule, profile)
    return compiled.matcher.matches(normalized.segments()), normalized


def profile_divergence(
    rule: Rule,
    raw_path: str,
    profiles: dict[str, ProxyProfile],
) -> dict[str, dict[str, object]]:
    """同一条规则 + 同一个原始路径在不同代理画像下的命中差异。"""
    report: dict[str, dict[str, object]] = {}
    for label, profile in profiles.items():
        matched, normalized = match_request(
            rule, None, raw_path, "GET", None, profile
        )
        report[label] = {
            "matched": matched,
            "normalized": normalized.normalized,
            "status": normalized.status,
            "warnings": normalized.warnings,
            "detail": normalized.detail,
            "encoded_slash": ENCODED_SLASH in normalized.warnings
            or normalized.status == "rejected",
        }
    return report
