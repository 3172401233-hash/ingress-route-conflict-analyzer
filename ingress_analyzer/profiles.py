"""常见代理/评审工具的路径处理画像。

这些画像只描述与路由匹配直接相关的规范化行为，具体版本仍可能通过
配置项改变默认值，分析结果中会保留 warning 便于人工确认。
"""

from .models import ProxyProfile

#: nginx + ingress-nginx 的典型行为：location 基于规范化、解码后的 $uri，
#: 默认 merge_slashes on，路径大小写敏感。
NGINX_DECODED = ProxyProfile(
    name="nginx-decoded",
    decode_path=True,
    case_fold=False,
    merge_slashes=True,
    encoded_slash_action="decode",
    invalid_encoding="reject",
)

#: Envoy 常见生产配置：HCM 上开启 merge_slashes，但默认不做全量 URL 解码，
#: 转义斜杠默认拒绝（path_with_escaped_slashes_action=KEEP_UNCHANGED 时
#: 则按 %2F 字面量参与匹配）。
ENVOY_RAW = ProxyProfile(
    name="envoy-raw",
    decode_path=False,
    case_fold=False,
    merge_slashes=True,
    encoded_slash_action="reject",
    invalid_encoding="reject",
)

#: Traefik v2/v3 的 Path/PathPrefix 规则默认作用在原始（未解码）路径上，
#: 且大小写敏感；Traefik 不默认折叠重复斜杠。
TRAEFIK_RAW = ProxyProfile(
    name="traefik-raw",
    merge_slashes=False,
    decode_path=False,
    encoded_slash_action="keep_encoded",
    invalid_encoding="lenient",
)

#: 配置评审期的严格画像：非法编码直接判为不可匹配，避免“评审通过但线上
#: 400”或反之的偏差。
REVIEW_STRICT = ProxyProfile(
    name="review-strict",
    decode_path=True,
    case_fold=False,
    merge_slashes=True,
    encoded_slash_action="reject",
    invalid_encoding="reject",
)
