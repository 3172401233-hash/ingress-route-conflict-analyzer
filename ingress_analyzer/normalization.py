"""请求/规则路径规范化。

规范化顺序固定为：去 query -> 补前导斜杠 -> 百分号解码 -> 大小写折叠 ->
折叠重复斜杠。顺序与真实代理管道保持一致，便于在 warning 中定位差异。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import ProxyProfile

INVALID_PERCENT = "invalid-percent-encoding"
ENCODED_SLASH = "encoded-slash"
MERGED_SLASH = "merged-duplicate-slash"
RELATIVE_PATH = "relative-path-normalized"


@dataclass
class NormalizedPath:
    raw: str
    normalized: str
    status: str  # ok / rejected
    warnings: list[str] = field(default_factory=list)
    detail: str | None = None
    slashes_merged: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def segments(self) -> tuple[str, ...]:
        if not self.ok:
            return ()
        if self.slashes_merged:
            return tuple(part for part in self.normalized.split("/") if part)
        parts = self.normalized.split("/")
        return tuple(parts[1:-1]) if len(parts) >= 2 else tuple(part for part in parts if part)


def _decode(
    path: str, profile: ProxyProfile, warnings: list[str]
) -> tuple[str | None, str | None]:
    """返回 (解码后路径, 拒绝原因)。被拒绝时路径为 None。"""
    if not profile.decode_path:
        has_invalid_encoding = _contains_invalid_encoding(path)
        if has_invalid_encoding and profile.invalid_encoding == "reject":
            return None, "路径包含非法百分号编码，当前画像拒绝该请求"
        if has_invalid_encoding:
            warnings.append(INVALID_PERCENT)
        if "%2f" in path.lower() or "%5c" in path.lower():
            if profile.encoded_slash_action == "reject":
                return None, "路径包含被编码的斜杠 (%2F)，当前画像拒绝该请求"
            warnings.append(ENCODED_SLASH)
        return path, None

    output: list[str] = []
    index = 0
    while index < len(path):
        char = path[index]
        if char != "%":
            output.append(char)
            index += 1
            continue
        hex_part = path[index + 1 : index + 3]
        if len(hex_part) != 2 or any(ch not in "0123456789abcdefABCDEF" for ch in hex_part):
            if profile.invalid_encoding == "reject":
                return None, f"非法百分号编码：{path[index:index + 3] or path[index:]}"
            warnings.append(INVALID_PERCENT)
            output.append(char)
            index += 1
            continue
        byte = bytes.fromhex(hex_part)
        decoded_char = byte.decode("latin-1")
        if decoded_char in ("/", "\\"):
            if profile.encoded_slash_action == "reject":
                return None, "路径包含被编码的斜杠 (%2F/%5C)，当前画像拒绝该请求"
            if profile.encoded_slash_action == "decode":
                warnings.append(ENCODED_SLASH)
                output.append("/" if decoded_char == "/" else "\\")
            else:
                warnings.append(ENCODED_SLASH)
                output.append(char.upper())
        else:
            output.append(decoded_char)
        index += 3
    return "".join(output), None


def _contains_invalid_encoding(path: str) -> bool:
    index = 0
    while index < len(path):
        if path[index] != "%":
            index += 1
            continue
        hex_part = path[index + 1 : index + 3]
        if len(hex_part) != 2 or any(
            ch not in "0123456789abcdefABCDEF" for ch in hex_part
        ):
            return True
        index += 3
    return False


def normalize_path(raw_path: str, profile: ProxyProfile) -> NormalizedPath:
    warnings: list[str] = []
    if not isinstance(raw_path, str):
        raise TypeError("path 必须是字符串")

    path = raw_path
    for separator in ("?", "#"):
        if separator in path:
            path = path.split(separator, 1)[0]
    if not path:
        path = "/"
        warnings.append(RELATIVE_PATH)
    if not path.startswith("/"):
        path = "/" + path
        warnings.append(RELATIVE_PATH)

    decoded, reject_reason = _decode(path, profile, warnings)
    if reject_reason is not None:
        return NormalizedPath(raw_path, path, "rejected", warnings, reject_reason)
    assert decoded is not None
    path = decoded

    if profile.case_fold:
        path = path.lower()

    path = path.replace("\\", "/")
    slashes_merged = False
    if profile.merge_slashes and "//" in path:
        warnings.append(MERGED_SLASH)
        slashes_merged = True
        while "//" in path:
            path = path.replace("//", "/")

    return NormalizedPath(raw_path, path, "ok", warnings, slashes_merged=slashes_merged)
