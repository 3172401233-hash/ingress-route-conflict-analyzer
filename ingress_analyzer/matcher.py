"""段级路径模式引擎。

模式由若干 :class:`Atom` 组成：
- 字面量段：精确匹配单个路径段
- ``*``：匹配任意单个路径段
- ``**``：匹配零个或多个任意路径段

前缀/精确/默认路由在解析阶段统一转成上述模式，之后用带记忆化的
递归包含算法判断两个模式之间的子集关系，并通过有界枚举生成
“区分两条规则”的具体请求路径。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import lru_cache

from .models import PathType

LITERAL = 1
SINGLE = 2
MANY = 3


@dataclass(frozen=True)
class Atom:
    kind: int
    value: str | None = None

    @staticmethod
    def literal(value: str) -> "Atom":
        return Atom(LITERAL, value)

    @staticmethod
    def single() -> "Atom":
        return Atom(SINGLE)

    @staticmethod
    def many() -> "Atom":
        return Atom(MANY)


@dataclass(frozen=True)
class PathMatcher:
    path_type: PathType
    pattern: tuple[Atom, ...]

    @lru_cache(maxsize=None)
    def matches(self, segments: tuple[str, ...]) -> bool:
        return _match(self.pattern, 0, segments, 0)

    @property
    def literals(self) -> tuple[str, ...]:
        values: list[str] = []
        for atom in self.pattern:
            if atom.kind != LITERAL:
                continue
            if isinstance(atom.value, tuple):
                values.extend(part for part in atom.value if part)
            else:
                values.append(atom.value)
        return tuple(values)


def _segment_matches(segment: str, atom: Atom) -> bool:
    if atom.kind != LITERAL:
        return False
    if isinstance(atom.value, tuple):
        skeleton = atom.value
        if not segment.startswith(skeleton[0]) or not segment.endswith(skeleton[-1]):
            return False
        cursor = len(skeleton[0])
        for part in skeleton[1:-1]:
            cursor = segment.find(part, cursor)
            if cursor < 0:
                return False
            cursor += len(part)
        return cursor <= len(segment) - len(skeleton[-1])
    return segment == atom.value


def _match(pattern: tuple[Atom, ...], pi: int, segments: tuple[str, ...], si: int) -> bool:
    if pi == len(pattern):
        return si == len(segments)
    atom = pattern[pi]
    if atom.kind == LITERAL:
        return si < len(segments) and _segment_matches(segments[si], atom) and _match(
            pattern, pi + 1, segments, si + 1
        )
    if atom.kind == SINGLE:
        return si < len(segments) and _match(pattern, pi + 1, segments, si + 1)
    if _match(pattern, pi + 1, segments, si):
        return True
    if si < len(segments) and _match(pattern, pi, segments, si + 1):
        return True
    return False


def _parse_wildcard(path: str) -> tuple[Atom, ...]:
    atoms: list[Atom] = []
    for raw_segment in path.split("/"):
        if raw_segment == "":
            continue
        if raw_segment == "**":
            atoms.append(Atom.many())
        elif raw_segment == "*":
            atoms.append(Atom.single())
        elif "*" in raw_segment:
            # 段内混合写法（如 api-*-v1）按段内通配处理，保留字面量骨架，
            # 子集判定会退化为保守的重叠判断。
            parts = raw_segment.split("*")
            atoms.append(Atom(LITERAL, tuple(parts)))  # type: ignore[arg-type]
        else:
            atoms.append(Atom.literal(raw_segment))
    return tuple(atoms)


def build_matcher(path_type: PathType, normalized_path: str) -> PathMatcher:
    path_type = PathType(path_type)
    segments = tuple(part for part in normalized_path.split("/") if part)
    if path_type is PathType.EXACT:
        return PathMatcher(path_type, tuple(Atom.literal(part) for part in segments))
    if path_type is PathType.DEFAULT:
        return PathMatcher(path_type, (Atom.many(),))
    if path_type is PathType.PREFIX:
        if not segments:
            return PathMatcher(path_type, (Atom.many(),))
        return PathMatcher(
            path_type, tuple(Atom.literal(part) for part in segments) + (Atom.many(),)
        )
    return PathMatcher(path_type, _parse_wildcard(normalized_path))


class Relation(str, Enum):
    EQUAL = "equal"
    SUBSET = "subset"  # 第一个模式 ⊆ 第二个
    CONTAINS = "contains"  # 第一个模式 ⊇ 第二个
    OVERLAP = "overlap"
    DISJOINT = "disjoint"
    UNKNOWN = "unknown"


def _atom_implies(atom_a: Atom, atom_b: Atom) -> bool:
    """单段层面：a 能匹配的段集合是否是 b 的子集。"""
    if atom_b.kind == SINGLE:
        return atom_a.kind in (LITERAL, SINGLE)
    if atom_b.kind == LITERAL:
        if atom_a.kind != LITERAL:
            return False
        if isinstance(atom_b.value, tuple):
            if not isinstance(atom_a.value, tuple):
                return _segment_matches(atom_a.value, atom_b)
            return atom_a.value == atom_b.value
        if isinstance(atom_a.value, tuple):
            return False
        return atom_a.value == atom_b.value
    return False


def _is_subset(pattern_a: tuple[Atom, ...], pattern_b: tuple[Atom, ...]) -> bool:
    """判断 pattern_a 的语言是否是 pattern_b 语言的子集。

    标准 antichain 模拟：状态是 (a 的单个 NFA 配置, b 的 NFA 配置集合)。
    a 的一条具体路径，必须始终能在 b 的配置集合中找到至少一条同步路径；
    a 接受时 b 集合内必须存在接受配置。``**`` 的取空通过 ε-闭包表达。
    """

    literal_symbols = sorted(
        {
            atom.value
            for pattern in (pattern_a, pattern_b)
            for atom in pattern
            if atom.kind == LITERAL and isinstance(atom.value, str)
        }
    )
    fresh = "__fresh_symbol__"
    symbols = tuple(literal_symbols) + (fresh,)

    def step(pattern: tuple[Atom, ...], symbol: str) -> frozenset[tuple[Atom, ...]]:
        """消费一个段后的 NFA 后继（不含 ε-取空，取空由 expand_epsilon 处理）。"""
        if not pattern:
            return frozenset()
        atom = pattern[0]
        rest = pattern[1:]
        if atom.kind == LITERAL:
            if isinstance(atom.value, tuple):
                matched = _segment_matches(symbol, atom)
            else:
                matched = atom.value == symbol
            return frozenset({rest}) if matched else frozenset()
        if atom.kind == SINGLE:
            return frozenset({rest})
        # ** 消费一个段后继续保持开放；是否结束由 ε-后继表达
        return frozenset({pattern})

    def epsilon_successors(pattern: tuple[Atom, ...]) -> frozenset[tuple[Atom, ...]]:
        if pattern and pattern[0].kind == MANY:
            return frozenset({pattern[1:]})
        return frozenset()

    def expand_epsilon(pattern: tuple[Atom, ...]) -> frozenset[tuple[Atom, ...]]:
        closure = {pattern}
        pending = [pattern]
        while pending:
            current = pending.pop()
            for nxt in epsilon_successors(current):
                if nxt not in closure:
                    closure.add(nxt)
                    pending.append(nxt)
        return frozenset(closure)

    def is_accept_config(config: tuple[Atom, ...]) -> bool:
        return all(atom.kind == MANY for atom in config)

    def successors(config: tuple[Atom, ...], symbol: str) -> frozenset[tuple[Atom, ...]]:
        result: set[tuple[Atom, ...]] = set()
        for expanded in expand_epsilon(config):
            for nxt in step(expanded, symbol):
                result.update(expand_epsilon(nxt))
        return frozenset(result)

    initial_a = expand_epsilon(pattern_a)
    initial_b = frozenset(expand_epsilon(pattern_b))

    # 收集所有可达 antichain 状态
    antichain_states: set[tuple[tuple[Atom, ...], frozenset]] = set()
    pending = [(config, initial_b) for config in initial_a]
    while pending:
        config_a, set_b = pending.pop()
        state = (config_a, set_b)
        if state in antichain_states:
            continue
        antichain_states.add(state)
        for symbol in symbols:
            next_a_configs = successors(config_a, symbol)
            next_b_configs: set[tuple[Atom, ...]] = set()
            for config_b in set_b:
                next_b_configs.update(successors(config_b, symbol))
            frozen_b = frozenset(next_b_configs)
            for next_a in next_a_configs:
                pending.append((next_a, frozen_b))

    # 最大不动点：先假设全部成立，再剔除反例
    valid_states = set(antichain_states)
    growth = True
    while growth:
        growth = False
        for config_a, set_b in list(valid_states):
            if is_accept_config(config_a) and not any(
                is_accept_config(config_b) for config_b in set_b
            ):
                valid_states.discard((config_a, set_b))
                growth = True
                continue
            for symbol in symbols:
                next_a_configs = successors(config_a, symbol)
                next_b_configs: set[tuple[Atom, ...]] = set()
                for config_b in set_b:
                    next_b_configs.update(successors(config_b, symbol))
                frozen_b = frozenset(next_b_configs)
                for next_a in next_a_configs:
                    if (next_a, frozen_b) not in valid_states:
                        valid_states.discard((config_a, set_b))
                        growth = True
                        break
                if (config_a, set_b) not in valid_states:
                    break

    return all(
        (config, initial_b) in valid_states for config in initial_a
    )


def _expand_segments(pattern_a: PathMatcher, pattern_b: PathMatcher, budget: int = 240):
    """有界 BFS 枚举两个模式共同语言附近的具体段序列。"""
    literals = tuple(
        dict.fromkeys(pattern_a.literals + pattern_b.literals + ("x", "v1", "deep"))
    )
    max_depth = max(
        (len(matcher.pattern) for matcher in (pattern_a, pattern_b)), default=1
    ) + 2
    candidates: list[tuple[str, ...]] = [()]
    seen: set[tuple[str, ...]] = {()}
    results: list[tuple[str, ...]] = []
    while candidates and len(results) < budget:
        current = candidates.pop(0)
        if current:
            results.append(current)
        if len(current) >= max_depth:
            continue
        for literal in literals:
            nxt = current + (literal,)
            if nxt not in seen:
                seen.add(nxt)
                candidates.append(nxt)
    if () not in results:
        results.insert(0, ())
    return results


def _render(segments: tuple[str, ...]) -> str:
    return "/" + "/".join(segments) if segments else "/"


def pattern_relation(
    pattern_a: PathMatcher, pattern_b: PathMatcher
) -> tuple[Relation, dict[str, str]]:
    """返回关系与证据路径（only_a/only_b/both）。"""
    if pattern_a.pattern == pattern_b.pattern:
        return Relation.EQUAL, {"both": _render(_first_match(pattern_a, pattern_b))}

    a_in_b = _is_subset(pattern_a.pattern, pattern_b.pattern)
    b_in_a = _is_subset(pattern_b.pattern, pattern_a.pattern)
    if a_in_b and b_in_a:
        return Relation.EQUAL, {"both": _render(_first_match(pattern_a, pattern_b))}
    if a_in_b:
        return Relation.SUBSET, {"only_a": _render(_first_match(pattern_a, pattern_b))}
    if b_in_a:
        return Relation.CONTAINS, {"only_b": _render(_first_match(pattern_b, pattern_a))}

    only_a = only_b = both = None
    for candidate in _expand_segments(pattern_a, pattern_b):
        match_a = pattern_a.matches(candidate)
        match_b = pattern_b.matches(candidate)
        if match_a and match_b and both is None:
            both = candidate
        elif match_a and only_a is None:
            only_a = candidate
        elif match_b and only_b is None:
            only_b = candidate
        if only_a and only_b and both:
            break

    witnesses: dict[str, str] = {}
    if both is not None:
        witnesses["both"] = _render(both)
    if only_a is not None:
        witnesses["only_a"] = _render(only_a)
    if only_b is not None:
        witnesses["only_b"] = _render(only_b)

    if both is None:
        return Relation.DISJOINT, witnesses
    return Relation.OVERLAP, witnesses


def _first_match(pattern_a: PathMatcher, pattern_b: PathMatcher) -> tuple[str, ...]:
    for candidate in _expand_segments(pattern_a, pattern_b):
        if pattern_a.matches(candidate) and pattern_b.matches(candidate):
            return candidate
    # 兜底：模式至少能匹配空序列或一个字面量
    return (pattern_a.literals[0],) if pattern_a.literals else ()
