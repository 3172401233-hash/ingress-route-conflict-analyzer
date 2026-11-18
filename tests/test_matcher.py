import unittest

from ingress_analyzer.matcher import Relation, build_matcher, pattern_relation
from ingress_analyzer.models import PathType


def wildcard(path: str):
    return build_matcher(PathType.WILDCARD, path)


def prefix(path: str):
    return build_matcher(PathType.PREFIX, path)


def exact(path: str):
    return build_matcher(PathType.EXACT, path)


class MatcherMatchTest(unittest.TestCase):
    def test_exact_match(self):
        matcher = exact("/api/v1/users")
        self.assertTrue(matcher.matches(("api", "v1", "users")))
        self.assertFalse(matcher.matches(("api", "v1", "users", "extra")))

    def test_prefix_match_and_root(self):
        matcher = prefix("/api")
        self.assertTrue(matcher.matches(("api",)))
        self.assertTrue(matcher.matches(("api", "v1", "users")))
        self.assertFalse(matcher.matches(("api2",)))

        root = prefix("/")
        self.assertTrue(root.matches(()))
        self.assertTrue(root.matches(("anything", "deep")))

    def test_single_and_double_wildcards(self):
        single = wildcard("/api/*/users")
        self.assertTrue(single.matches(("api", "v1", "users")))
        self.assertFalse(single.matches(("api", "v1", "v2", "users")))

        double = wildcard("/api/**/users")
        self.assertTrue(double.matches(("api", "users")))
        self.assertTrue(double.matches(("api", "v1", "v2", "users")))
        self.assertFalse(double.matches(("api", "admins")))

    def test_segment_internal_wildcard(self):
        matcher = wildcard("/svc/api-*-v1")
        self.assertTrue(matcher.matches(("svc", "api-orders-v1")))
        self.assertFalse(matcher.matches(("svc", "api-orders-v2")))


class MatcherRelationTest(unittest.TestCase):
    def test_prefix_subset(self):
        relation, witnesses = pattern_relation(prefix("/api/v1"), prefix("/api"))
        self.assertEqual(relation, Relation.SUBSET)
        self.assertIn("only_a", witnesses)

    def test_equal_wildcards(self):
        relation, _ = pattern_relation(wildcard("/api/*"), wildcard("/api/*"))
        self.assertEqual(relation, Relation.EQUAL)

    def test_single_vs_double_wildcard(self):
        relation, witnesses = pattern_relation(wildcard("/api/*"), wildcard("/api/**"))
        self.assertEqual(relation, Relation.SUBSET)
        self.assertTrue(witnesses["only_a"].startswith("/api/"))

    def test_partial_overlap_gives_distinguishing_paths(self):
        relation, witnesses = pattern_relation(
            wildcard("/api/*/users"), wildcard("/api/v1/*")
        )
        self.assertEqual(relation, Relation.OVERLAP)
        self.assertIn("only_a", witnesses)
        self.assertIn("only_b", witnesses)
        self.assertIn("both", witnesses)

    def test_multi_level_wildcards_partial_overlap(self):
        relation, witnesses = pattern_relation(
            wildcard("/a/**/c"), wildcard("/a/b/**")
        )
        self.assertEqual(relation, Relation.OVERLAP)
        matcher_a = wildcard("/a/**/c")
        matcher_b = wildcard("/a/b/**")

        def segments(path: str):
            return tuple(part for part in path.split("/") if part)

        only_a = segments(witnesses["only_a"])
        only_b = segments(witnesses["only_b"])
        self.assertTrue(matcher_a.matches(only_a) and not matcher_b.matches(only_a))
        self.assertTrue(matcher_b.matches(only_b) and not matcher_a.matches(only_b))

    def test_disjoint_literals(self):
        relation, _ = pattern_relation(exact("/a"), exact("/b"))
        self.assertEqual(relation, Relation.DISJOINT)

    def test_default_contains_everything(self):
        default = build_matcher(PathType.DEFAULT, "/")
        relation, _ = pattern_relation(prefix("/api"), default)
        self.assertEqual(relation, Relation.SUBSET)

    def test_exact_vs_prefix(self):
        relation, _ = pattern_relation(exact("/api/v1"), prefix("/api"))
        self.assertEqual(relation, Relation.SUBSET)


if __name__ == "__main__":
    unittest.main()
