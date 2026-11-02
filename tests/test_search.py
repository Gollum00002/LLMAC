"""Search/tree tests: ignores, gitignore subset, caps."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.search import content_search, name_search, tree


class TestContentSearch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="search-test-")
        os.makedirs(os.path.join(self.tmp, "node_modules", "pkg"),
                    exist_ok=True)
        os.makedirs(os.path.join(self.tmp, ".git", "objects"),
                    exist_ok=True)
        os.makedirs(os.path.join(self.tmp, "src"), exist_ok=True)
        with open(os.path.join(self.tmp, "src", "app.py"), "w") as f:
            f.write("def main():\n    return 42\n# end\n")
        with open(os.path.join(self.tmp, "readme.md"), "w") as f:
            f.write("mentions main() too\n")
        with open(os.path.join(self.tmp, "node_modules", "pkg", "junk.js"),
                  "w") as f:
            f.write("def main(): NEVER FIND ME\n")
        with open(os.path.join(self.tmp, ".git", "config"), "w") as f:
            f.write("def main(): EVIL\n")

    def test_basic(self):
        res = content_search(self.tmp, "main")
        paths = [m["path"] for m in res["matches"]]
        self.assertIn(os.path.join(self.tmp, "src", "app.py"), paths)
        self.assertIn(os.path.join(self.tmp, "readme.md"), paths)

    def test_ignores_node_modules_and_git(self):
        res = content_search(self.tmp, "NEVER FIND ME")
        self.assertEqual(res["matches"], [])
        res = content_search(self.tmp, "EVIL")
        self.assertEqual(res["matches"], [])

    def test_regex(self):
        res = content_search(self.tmp, r"return\s+\d+", regex=True)
        self.assertEqual(len(res["matches"]), 1)

    def test_glob_filter(self):
        res = content_search(self.tmp, "main", glob="*.py")
        paths = [m["path"] for m in res["matches"]]
        self.assertEqual(paths, [os.path.join(self.tmp, "src", "app.py")])

    def test_context_lines(self):
        res = content_search(self.tmp, "return", context=1)
        m = res["matches"][0]
        self.assertEqual(len(m["context"]), 3)

    def test_max_results(self):
        res = content_search(self.tmp, "main", max_results=1)
        self.assertEqual(len(res["matches"]), 1)
        self.assertTrue(res["truncated"])

    def test_invalid_regex(self):
        res = content_search(self.tmp, "([", regex=True)
        self.assertIn("error", res)


class TestGitignore(unittest.TestCase):
    def test_gitignore_respected(self):
        tmp = tempfile.mkdtemp(prefix="gi-test-")
        with open(os.path.join(tmp, ".gitignore"), "w") as f:
            f.write("*.log\nbuild/\n")
        os.makedirs(os.path.join(tmp, "build"), exist_ok=True)
        with open(os.path.join(tmp, "app.log"), "w") as f:
            f.write("LOGCONTENT")
        with open(os.path.join(tmp, "keep.txt"), "w") as f:
            f.write("LOGCONTENT")
        res = content_search(tmp, "LOGCONTENT")
        paths = [m["path"] for m in res["matches"]]
        self.assertEqual(paths, [os.path.join(tmp, "keep.txt")])


class TestNameSearch(unittest.TestCase):
    def test_glob(self):
        tmp = tempfile.mkdtemp(prefix="name-test-")
        os.makedirs(os.path.join(tmp, "a", "b"), exist_ok=True)
        for p in ("a/x.py", "a/b/y.py", "a/z.txt"):
            with open(os.path.join(tmp, p), "w") as f:
                f.write("x")
        res = name_search(tmp, "*.py")
        rels = sorted(m["rel"] for m in res["matches"])
        self.assertEqual(rels, ["a/b/y.py", "a/x.py"])


class TestTree(unittest.TestCase):
    def test_tree_depth_and_ignores(self):
        tmp = tempfile.mkdtemp(prefix="tree-test-")
        os.makedirs(os.path.join(tmp, "node_modules", "deep"), exist_ok=True)
        os.makedirs(os.path.join(tmp, "a", "b", "c"), exist_ok=True)
        for p in ("a/one", "a/b/two", "a/b/c/three"):
            with open(os.path.join(tmp, p), "w") as f:
                f.write("x")
        res = tree(tmp, depth=2)
        names = [e["name"] for e in res["entries"]]
        self.assertIn("a", names)
        self.assertIn("one", names)
        self.assertIn("b", names)
        self.assertNotIn("three", names)     # depth-capped
        self.assertNotIn("node_modules", names)

    def test_tree_cap(self):
        tmp = tempfile.mkdtemp(prefix="tree-cap-")
        for i in range(50):
            with open(os.path.join(tmp, f"f{i}.txt"), "w") as f:
                f.write("x")
        res = tree(tmp, max_entries=10)
        self.assertTrue(res["truncated"])
        self.assertEqual(len(res["entries"]), 10)


if __name__ == "__main__":
    unittest.main()
