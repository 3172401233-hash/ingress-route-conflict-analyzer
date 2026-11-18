import unittest

from ingress_analyzer import (
    ENVOY_RAW,
    NGINX_DECODED,
    TRAEFIK_RAW,
    HeaderCondition,
    HeaderOp,
    PathType,
    Rule,
    analyze_chain,
    compare_rules,
    match_request,
    profile_divergence,
)


def make_rule(name, path_type, path, **kwargs):
    return Rule(name=name, path_type=path_type, path=path, **kwargs)


class ShadowTest(unittest.TestCase):
    def test_prefix_shadowed_by_wider_prefix(self):
        wide = make_rule("wide", PathType.PREFIX, "/api")
        narrow = make_rule("narrow", PathType.PREFIX, "/api/v1/users")
        result = compare_rules(wide, narrow)
        self.assertTrue(result.overlap)
        self.assertTrue(result.full_shadow)

    def test_priority_determines_who_shadows_whom(self):
        specific = make_rule("specific", PathType.EXACT, "/api/v1/users", priority=100)
        generic = make_rule("generic", PathType.PREFIX, "/api", priority=10)
        # 低 priority 先评估，generic 在前会遮蔽 specific
        forward = compare_rules(generic, specific)
        self.assertTrue(forward.full_shadow)
        # 调换输入顺序后 specific 在前，不再构成遮蔽
        reverse = compare_rules(specific, generic)
        self.assertTrue(reverse.overlap)
        self.assertFalse(reverse.full_shadow)

    def test_chain_marks_unreachable_rule(self):
        rules = [
            make_rule("catch-all", PathType.DEFAULT, "/", priority=0),
            make_rule("api", PathType.PREFIX, "/api", priority=10),
            make_rule("users", PathType.PREFIX, "/api/v1/users", priority=20),
        ]
        report = analyze_chain(rules)
        self.assertEqual(report.order, ["catch-all", "api", "users"])
        self.assertEqual(set(report.unreachable), {"api", "users"})
        self.assertEqual(len(report.shadows), 3)

    def test_same_priority_keeps_configuration_order(self):
        rules = [
            make_rule("first", PathType.PREFIX, "/api", priority=5),
            make_rule("second", PathType.PREFIX, "/api/v1", priority=5),
        ]
        report = analyze_chain(rules)
        self.assertEqual(report.order, ["first", "second"])
        self.assertEqual(report.unreachable, ["second"])


class MethodHeaderHostTest(unittest.TestCase):
    def test_same_path_different_methods_is_partial(self):
        get_rule = make_rule(
            "get", PathType.EXACT, "/orders", methods=frozenset({"GET"})
        )
        post_rule = make_rule(
            "post", PathType.EXACT, "/orders", methods=frozenset({"POST"})
        )
        result = compare_rules(get_rule, post_rule)
        self.assertFalse(result.overlap)
        self.assertFalse(result.full_shadow)
        self.assertIn("method", result.reason)

    def test_method_subset_can_still_shadow(self):
        any_method = make_rule("any", PathType.PREFIX, "/api")
        get_only = make_rule(
            "get-only", PathType.PREFIX, "/api", methods=frozenset({"GET"})
        )
        result = compare_rules(any_method, get_only)
        self.assertTrue(result.full_shadow)

    def test_header_condition_breaks_shadow(self):
        plain = make_rule("plain", PathType.PREFIX, "/api")
        canary = make_rule(
            "canary",
            PathType.PREFIX,
            "/api",
            headers=(HeaderCondition("x-canary", HeaderOp.EXACT, "true"),),
        )
        result = compare_rules(plain, canary)
        self.assertTrue(result.overlap)
        self.assertTrue(result.full_shadow)

        reverse = compare_rules(canary, plain)
        self.assertFalse(reverse.full_shadow)
        self.assertIn("header", reverse.reason)

    def test_conflicting_headers_are_disjoint(self):
        v1 = make_rule(
            "v1",
            PathType.PREFIX,
            "/api",
            headers=(HeaderCondition("x-version", HeaderOp.EXACT, "v1"),),
        )
        v2 = make_rule(
            "v2",
            PathType.PREFIX,
            "/api",
            headers=(HeaderCondition("x-version", HeaderOp.EXACT, "v2"),),
        )
        result = compare_rules(v1, v2)
        self.assertFalse(result.overlap)

    def test_empty_host_captures_everything(self):
        catch = make_rule("catch", PathType.PREFIX, "/api", host=None)
        scoped = make_rule(
            "scoped", PathType.PREFIX, "/api", host="shop.example.com"
        )
        self.assertTrue(compare_rules(catch, scoped).full_shadow)
        self.assertFalse(compare_rules(scoped, catch).full_shadow)

    def test_wildcard_host_relation(self):
        wildcard_host = make_rule(
            "wild", PathType.PREFIX, "/api", host="*.example.com"
        )
        specific_host = make_rule(
            "specific", PathType.PREFIX, "/api", host="shop.example.com"
        )
        self.assertTrue(compare_rules(wildcard_host, specific_host).full_shadow)


class CaseAndWildcardTest(unittest.TestCase):
    def test_case_sensitive_by_default(self):
        upper = make_rule("upper", PathType.EXACT, "/API/Users")
        lower = make_rule("lower", PathType.EXACT, "/api/users")
        result = compare_rules(upper, lower)
        self.assertFalse(result.overlap)

    def test_multi_level_wildcard_overlap_witness(self):
        rule_a = make_rule("a", PathType.WILDCARD, "/api/**/users")
        rule_b = make_rule("b", PathType.WILDCARD, "/api/v1/**")
        result = compare_rules(rule_a, rule_b)
        self.assertTrue(result.overlap)
        self.assertFalse(result.full_shadow)
        paths = {request.path for request in result.witness_requests}
        self.assertTrue(any("/users" in path for path in paths))


class ProxyBehaviorTest(unittest.TestCase):
    def test_encoded_slash_matches_after_decode(self):
        rule = make_rule("users", PathType.PREFIX, "/api/v1")
        matched, normalized = match_request(
            rule, None, "/api%2Fv1/users", "GET", None, NGINX_DECODED
        )
        self.assertTrue(matched)
        self.assertEqual(normalized.normalized, "/api/v1/users")

    def test_encoded_slash_rejected_or_literal_in_raw_proxies(self):
        rule = make_rule("users", PathType.PREFIX, "/api/v1")
        envoy_match, envoy_path = match_request(
            rule, None, "/api%2Fv1", "GET", None, ENVOY_RAW
        )
        self.assertFalse(envoy_match)
        self.assertFalse(envoy_path.ok)

        traefik_match, traefik_path = match_request(
            rule, None, "/api%2Fv1", "GET", None, TRAEFIK_RAW
        )
        self.assertFalse(traefik_match)
        self.assertEqual(traefik_path.normalized, "/api%2Fv1")

    def test_profile_divergence_report(self):
        rule = make_rule("users", PathType.PREFIX, "/api/v1")
        report = profile_divergence(
            rule,
            "/api%2Fv1/users",
            {"nginx": NGINX_DECODED, "envoy": ENVOY_RAW, "traefik": TRAEFIK_RAW},
        )
        self.assertTrue(report["nginx"]["matched"])
        self.assertFalse(report["envoy"]["matched"])
        self.assertFalse(report["traefik"]["matched"])

    def test_duplicate_slash_divergence(self):
        rule = make_rule("api", PathType.EXACT, "/api/v1")
        merged, merged_path = match_request(
            rule, None, "/api//v1", "GET", None, NGINX_DECODED
        )
        raw, raw_path = match_request(
            rule, None, "/api//v1", "GET", None, TRAEFIK_RAW
        )
        self.assertTrue(merged)
        self.assertFalse(raw)
        self.assertEqual(merged_path.normalized, "/api/v1")
        self.assertEqual(raw_path.normalized, "/api//v1")

    def test_invalid_encoding_request_never_matches(self):
        rule = make_rule("api", PathType.PREFIX, "/api")
        matched, normalized = match_request(
            rule, None, "/api/%zz", "GET", None, NGINX_DECODED
        )
        self.assertFalse(matched)
        self.assertFalse(normalized.ok)


class WitnessTest(unittest.TestCase):
    def test_partial_overlap_produces_distinguishing_request(self):
        rule_a = make_rule("a", PathType.WILDCARD, "/api/*/users")
        rule_b = make_rule("b", PathType.WILDCARD, "/api/v1/*")
        result = compare_rules(rule_a, rule_b)
        self.assertTrue(result.overlap)
        self.assertFalse(result.full_shadow)
        only_a = next(request for request in result.witness_requests if request.matched_by == ["a"])
        only_b = next(request for request in result.witness_requests if request.matched_by == ["b"])
        self.assertNotEqual(only_a.path, only_b.path)


if __name__ == "__main__":
    unittest.main()
