"""Edit primitives tests: replace/lines/insert/append/delete + diffs."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.edits import apply_ops, EditError, unified_diff


def apply(text, ops):
    return apply_ops(text, ops)


class TestReplace(unittest.TestCase):
    def test_first(self):
        new, n = apply("a\nb\na\n", [{"op": "replace", "find": "a",
                                      "replace": "X"}])
        self.assertEqual(new, "X\nb\na\n")
        self.assertEqual(n, 1)

    def test_all(self):
        new, n = apply("a\nb\na\n", [{"op": "replace", "find": "a",
                                      "replace": "X", "occurrence": "all"}])
        self.assertEqual(new, "X\nb\nX\n")
        self.assertEqual(n, 2)

    def test_nth(self):
        new, n = apply("a\na\na\n", [{"op": "replace", "find": "a",
                                      "replace": "Z", "occurrence": 2}])
        self.assertEqual(new, "a\nZ\na\n")

    def test_regex(self):
        new, n = apply("x=1\ny=22\n", [{"op": "replace", "find": r"=(\d+)",
                                         "replace": r"=\1!", "regex": True,
                                         "occurrence": "all"}])
        self.assertEqual(new, "x=1!\ny=22!\n")

    def test_multiline_find(self):
        new, n = apply("def foo():\n    pass\n", [{"op": "replace",
                                                    "find": "def foo():\n    pass",
                                                    "replace": "def bar():\n    return 1"}])
        self.assertEqual(new, "def bar():\n    return 1\n")

    def test_not_found_raises(self):
        with self.assertRaises(EditError):
            apply("hello\n", [{"op": "replace", "find": "nope",
                                "replace": "x"}])

    def test_regex_invalid(self):
        with self.assertRaises(EditError):
            apply("x", [{"op": "replace", "find": "([", "replace": "y",
                          "regex": True}])


class TestLineOps(unittest.TestCase):
    def test_replace_lines(self):
        new, n = apply("l1\nl2\nl3\n", [{"op": "lines", "start": 2, "end": 3,
                                          "content": "TWO\nTHREE"}])
        self.assertEqual(new, "l1\nTWO\nTHREE\n")
        self.assertEqual(n, 2)

    def test_delete_lines(self):
        new, n = apply("l1\nl2\nl3\n", [{"op": "delete_lines", "start": 1,
                                          "end": 2}])
        self.assertEqual(new, "l3\n")

    def test_insert_before_after(self):
        new, n = apply("b\n", [{"op": "insert", "content": "a", "before_line": 1}])
        self.assertEqual(new, "a\nb\n")
        new, n = apply("a\n", [{"op": "insert", "content": "b", "after_line": 1}])
        self.assertEqual(new, "a\nb\n")

    def test_append(self):
        new, n = apply("a\n", [{"op": "append", "content": "b\nc"}])
        self.assertEqual(new, "a\nb\nc\n")

    def test_range_invalid(self):
        with self.assertRaises(EditError):
            apply("l1\n", [{"op": "lines", "start": 5, "end": 9,
                             "content": "x"}])
        with self.assertRaises(EditError):
            apply("l1\n", [{"op": "delete_lines", "start": 2, "end": 4}])


class TestSequencing(unittest.TestCase):
    def test_multiple_ops(self):
        text = "def f():\n    return 1\n# end\n"
        new, n = apply(text, [
            {"op": "replace", "find": "return 1", "replace": "return 2"},
            {"op": "insert", "content": "# header", "before_line": 1},
            {"op": "append", "content": "# tail"},
        ])
        self.assertEqual(
            new, "# header\ndef f():\n    return 2\n# end\n# tail\n")
        self.assertEqual(n, 3)

    def test_no_change_raises(self):
        with self.assertRaises(EditError):
            apply("same\n", [{"op": "replace", "find": "same",
                              "replace": "same"}])

    def test_all_or_nothing(self):
        """If op 2 fails, nothing applies (exception before any write)."""
        with self.assertRaises(EditError):
            apply("aaa\n", [
                {"op": "replace", "find": "aaa", "replace": "bbb"},
                {"op": "replace", "find": "zzz", "replace": "yyy"},
            ])


class TestDiff(unittest.TestCase):
    def test_diff_generated(self):
        d = unified_diff("a\nb\n", "a\nB\n", "f.txt")
        self.assertIn("-b", d)
        self.assertIn("+B", d)
        self.assertIn("a/f.txt", d)

    def test_diff_truncates_huge(self):
        before = "".join(f"line {i}\n" for i in range(20000))
        after = "".join(f"LINE {i}\n" for i in range(20000))
        d = unified_diff(before, after, "big.txt")
        self.assertLess(len(d), 40 * 1024)
        self.assertIn("diff truncated", d)


if __name__ == "__main__":
    unittest.main()
