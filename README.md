# ingress-route-conflict-analyzer
Python Ingress 路由冲突分析库，处理 host/path 优先级、通配规则和不可达路由

## 解决的问题

网关新增路由后经常出现两类隐蔽问题：

1. **通配遮蔽**：更具体的路径（如 `/api/v1/users`）被前面评估的宽泛规则
   （如前缀 `/api` 或通配 `/api/**`）完全遮住，永远不会收到流量。
2. **评审与线上不一致**：配置评审基于解码后的路径判断，而真实代理可能在
   原始（未解码）路径上匹配，导致 `%2F`、重复斜杠等场景结论相反。

本库在统一的段级模式模型上判断两条规则是否重叠、前者是否完全遮蔽后者，
并在部分重叠时给出可以区分两条规则的具体请求路径。

## 快速开始

```python
from ingress_analyzer import Rule, PathType, analyze_chain, compare_rules
from ingress_analyzer.profiles import NGINX_DECODED

rules = [
    Rule("catch-all", PathType.DEFAULT, "/", priority=0),
    Rule("api", PathType.PREFIX, "/api", priority=10),
    Rule("users", PathType.PREFIX, "/api/v1/users", priority=20),
]

report = analyze_chain(rules, NGINX_DECODED)
print(report.order)        # ['catch-all', 'api', 'users']
print(report.unreachable)  # ['api', 'users'] 被默认路由完全遮蔽

result = compare_rules(rules[1], rules[2])
print(result.overlap, result.full_shadow)  # True True
for witness in result.witness_requests:
    print(witness.path, witness.matched_by)
```

## 路径类型与通配语义

路径按 `/` 切分成段，匹配始终基于段而不是字符串包含。

| 类型 | 写法示例 | 语义 |
| --- | --- | --- |
| `EXACT` | `/api/v1/users` | 段序列完全相等 |
| `PREFIX` | `/api` | `/api` 及其任意后续段 |
| `WILDCARD` | `/api/*/users/**` | `*` 匹配单个段，`**` 匹配零到多个段 |
| `DEFAULT` | `/` | 路径维度兜底，匹配所有路径 |

段内混合通配（如 `api-*-v1`）按字面量骨架匹配；`*` 不会跨越 `/`。

## 规范化管道

同一条原始路径在不同代理画像（`ProxyProfile`）下会得到不同的规范化结果。
管道顺序固定为：

1. 去掉 query string 与 fragment
2. 补前导 `/`（空路径归一为 `/`）
3. 百分号解码（受 `decode_path` 与编码斜杠策略控制）
4. 大小写折叠（受 `case_fold` 控制，默认关闭）
5. 反斜杠转斜杠、折叠重复斜杠（受 `merge_slashes` 控制）

### 非法百分号编码

- 严格画像（`invalid_encoding="reject"`，默认）：`%zz`、悬空 `%2` 等
  直接判定请求被拒绝，不参与任何路由匹配。
- 宽松画像（`invalid_encoding="lenient"`）：保留原始字节并打
  `invalid-percent-encoding` 警告。

### 编码斜杠 `%2F` / `%5C`

`encoded_slash_action` 有三种策略：

- `decode`：解码成真实 `/`，路径段数可能增加（nginx 典型行为）。
- `reject`：直接拒绝请求（Envoy 常见严格配置、评审严格画像）。
- `keep_encoded`：保留字面量 `%2F`，按普通字符参与匹配（Traefik 类）。

### 重复斜杠与大小写

- 开启 `merge_slashes` 时 `/api//v1` 归一为 `/api/v1`；关闭时空段保留，
  字面量/精确规则会因此失配。
- 默认路径大小写敏感；`case_fold=True` 时统一转小写后再匹配。
- 空 host（`None` 或空字符串）表示捕获所有 host；`*.example.com` 是
  Kubernetes 风格的单标签通配，不匹配裸 `example.com`。

## 代理差异

内置画像只描述与路由匹配相关的规范化行为，真实默认值仍可能随版本和
部署配置变化，分析结果会在 `profile_notes`/`warnings` 中保留提示。

| 画像 | 解码 | 合并斜杠 | 编码斜杠 | 说明 |
| --- | --- | --- | --- | --- |
| `NGINX_DECODED` | 是 | 是 | 解码 | location 基于规范化、解码后的 `$uri` |
| `ENVOY_RAW` | 否 | 是 | 拒绝 | HCM 常在原始路径上匹配，转义斜杠默认拒绝 |
| `TRAEFIK_RAW` | 否 | 否 | 保留 | `Path`/`PathPrefix` 默认作用于原始路径 |
| `REVIEW_STRICT` | 是 | 是 | 拒绝 | 评审期严格画像，提前暴露线上 400 风险 |

用 `profile_divergence` 可以直接对比同一条规则在多个画像下对同一原始
路径的命中差异：

```python
from ingress_analyzer import Rule, PathType, profile_divergence
from ingress_analyzer.profiles import NGINX_DECODED, ENVOY_RAW, TRAEFIK_RAW

rule = Rule("users", PathType.PREFIX, "/api/v1")
print(profile_divergence(
    rule, "/api%2Fv1/users",
    {"nginx": NGINX_DECODED, "envoy": ENVOY_RAW, "traefik": TRAEFIK_RAW},
))
```

上例中 nginx 画像命中（解码后变成 `/api/v1/users`），Envoy 画像拒绝
请求，Traefik 画像保留 `%2F` 字面量因而不命中——这正是“配置评审通过
但线上匹配结果不同”的典型来源。

## 遮蔽判定维度

完整遮蔽要求第一条规则在四个维度上都覆盖第二条：

- **host**：前者 host 集合包含后者（空 host 覆盖一切）
- **method**：前者方法集合包含后者（空集合表示允许全部方法）
- **header**：前者的 header 条件蕴含后者；前者无条件时天然覆盖，
  前者有额外条件时则无法覆盖无约束的后者
- **path**：前者路径模式语言包含后者（通过 NFA antichain 模拟判定）

任一维度不满足即为部分重叠，分析器会返回 `only_a`/`only_b`/`both`
三类证据请求，其中 `only_*` 路径可直接用来区分两条规则。

## 运行测试

```bash
python -m unittest
```
