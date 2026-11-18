import unittest

from ingress_analyzer.normalization import (
    ENCODED_SLASH,
    INVALID_PERCENT,
    MERGED_SLASH,
    normalize_path,
)
from ingress_analyzer.profiles import (
    ENVOY_RAW,
    NGINX_DECODED,
    REVIEW_STRICT,
    TRAEFIK_RAW,
)


class NormalizationTest(unittest.TestCase):
    def test_strips_query_and_fragment(self):
        result = normalize_path("/a/b?x=1#frag", NGINX_DECODED)
        self.assertEqual(result.normalized, "/a/b")
        self.assertTrue(result.ok)

    def test_invalid_percent_encoding_rejected_in_strict_mode(self):
        result = normalize_path("/api/%zz/users", REVIEW_STRICT)
        self.assertFalse(result.ok)
        self.assertEqual(result.status, "rejected")
        self.assertIn("非法百分号编码", result.detail)

    def test_invalid_percent_encoding_lenient(self):
        result = normalize_path("/api/%zz", TRAEFIK_RAW)
        self.assertTrue(result.ok)
        self.assertEqual(result.normalized, "/api/%zz")
        self.assertIn(INVALID_PERCENT, result.warnings)

    def test_dangling_percent_is_invalid(self):
        rejected = normalize_path("/a/%2", REVIEW_STRICT)
        self.assertFalse(rejected.ok)
        lenient = normalize_path("/a/%2", TRAEFIK_RAW)
        self.assertTrue(lenient.ok)
        self.assertEqual(lenient.normalized, "/a/%2")

    def test_encoded_slash_decoded_by_nginx(self):
        result = normalize_path("/api%2Fv1/users", NGINX_DECODED)
        self.assertTrue(result.ok)
        self.assertEqual(result.normalized, "/api/v1/users")
        self.assertIn(ENCODED_SLASH, result.warnings)

    def test_encoded_slash_rejected_by_envoy_raw(self):
        result = normalize_path("/api%2Fv1", ENVOY_RAW)
        self.assertFalse(result.ok)
        self.assertIn("编码的斜杠", result.detail)

    def test_encoded_slash_kept_by_traefik(self):
        result = normalize_path("/api%2Fv1", TRAEFIK_RAW)
        self.assertTrue(result.ok)
        self.assertEqual(result.normalized, "/api%2Fv1")
        self.assertIn(ENCODED_SLASH, result.warnings)

    def test_duplicate_slashes_merged_or_preserved(self):
        merged = normalize_path("/a//b///c", NGINX_DECODED)
        self.assertEqual(merged.normalized, "/a/b/c")
        self.assertIn(MERGED_SLASH, merged.warnings)

        raw = normalize_path("/a//b", TRAEFIK_RAW)
        self.assertEqual(raw.normalized, "/a//b")
        self.assertNotIn(MERGED_SLASH, raw.warnings)

    def test_case_preserved_by_default(self):
        result = normalize_path("/API/Users", NGINX_DECODED)
        self.assertEqual(result.normalized, "/API/Users")

    def test_relative_and_empty_paths(self):
        relative = normalize_path("api/v1", NGINX_DECODED)
        self.assertEqual(relative.normalized, "/api/v1")
        empty = normalize_path("", NGINX_DECODED)
        self.assertEqual(empty.normalized, "/")
        root = normalize_path("/", NGINX_DECODED)
        self.assertEqual(root.segments(), ())

    def test_encoded_backslash_normalized_to_slash(self):
        result = normalize_path("/a%5Cb", NGINX_DECODED)
        self.assertEqual(result.normalized, "/a/b")


if __name__ == "__main__":
    unittest.main()
