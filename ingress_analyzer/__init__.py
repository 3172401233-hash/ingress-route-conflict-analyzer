"""Ingress 路由冲突分析器。"""

from .analyzer import (
    AnalysisResult,
    ChainReport,
    analyze_chain,
    compare_rules,
    match_request,
    profile_divergence,
)
from .models import HeaderCondition, HeaderOp, PathType, ProxyProfile, Rule
from .normalization import NormalizedPath, normalize_path
from .profiles import ENVOY_RAW, NGINX_DECODED, REVIEW_STRICT, TRAEFIK_RAW

__all__ = [
    "AnalysisResult",
    "ChainReport",
    "ENVOY_RAW",
    "NGINX_DECODED",
    "REVIEW_STRICT",
    "TRAEFIK_RAW",
    "HeaderCondition",
    "HeaderOp",
    "NormalizedPath",
    "PathType",
    "ProxyProfile",
    "Rule",
    "analyze_chain",
    "compare_rules",
    "match_request",
    "normalize_path",
    "profile_divergence",
]
