"""Sandbox v2 tests: containment, traversal, symlinks, exec command checks.

NOTE: fixtures live under <repo>/.test-tmp — deliberately NOT under /tmp
so the exec whitelist (/tmp etc.) can't mask traversal rejections.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sandbox import Sandbox

_TESTBASE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".test-tmp")


def _mkdtemp(prefix):
    import tempfile
    os.makedirs(_TESTBASE, exist_ok=True)
    return tempfile.mkdtemp(prefix=prefix, dir=_TESTBASE)


class TestSandboxResolve(unittest.TestCase):
    def setUp(self):
        self.tmp = _mkdtemp("sb-test-")
        self.root = os.path.join(self.tmp, "shared")
        os.makedirs(self.root, exist_ok=True)
        self.sbx = Sandbox([self.root])

    def test_inside_ok(self):
        self.assertEqual(self.sbx.resolve(os.path.join(self.root, "a.txt")),
                         os.path.join(self.root, "a.txt"))

    def test_traversal_rejected(self):
        with self.assertRaises(PermissionError):
            self.sbx.resolve(os.path.join(self.root, "..", "secret.txt"))
        with self.assertRaises(PermissionError):
            self.sbx.resolve(self.root + "/../../etc/passwd")

    def test_home_rejected(self):
        with self.assertRaises(PermissionError):
            self.sbx.resolve("~/.ssh/id_rsa")
        with self.assertRaises(PermissionError):
            self.sbx.resolve("~/anything")

    def test_symlink_escape_rejected(self):
        link = os.path.join(self.root, "evil")
        os.symlink("/etc", link)
        with self.assertRaises(PermissionError):
            self.sbx.resolve(os.path.join(self.root, "evil", "passwd"))

    def test_symlink_escape_lexical_only_rejected(self):
        """A path that is lexically inside but realpath outside must fail."""
        link = os.path.join(self.root, "outside")
        target = os.path.join(self.tmp, "outside-target")
        os.makedirs(target, exist_ok=True)
        os.symlink(target, link)
        with self.assertRaises(PermissionError):
            self.sbx.resolve(os.path.join(self.root, "outside", "f.txt"))

    def test_symlink_outside_pointing_in_rejected(self):
        """A path outside the root that resolves inside is also rejected."""
        inside = os.path.join(self.root, "real.txt")
        with open(inside, "w") as f:
            f.write("x")
        link = os.path.join(self.tmp, "in-link")
        os.symlink(inside, link)
        with self.assertRaises(PermissionError):
            self.sbx.resolve(link)


class TestExecCommandChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = _mkdtemp("sb-exec-")
        self.root = os.path.join(self.tmp, "shared")
        os.makedirs(self.root, exist_ok=True)
        self.sbx = Sandbox([self.root])
        self.cwd = self.root

    def check(self, command):
        return self.sbx.check_exec_command(command, self.cwd)

    # ---- must PASS ------------------------------------------------------

    def test_plain_relative(self):
        self.assertIsNone(self.check("ls -la"))
        self.assertIsNone(self.check("cat file.txt"))

    def test_inside_paths(self):
        self.assertIsNone(self.check(f"cat {self.root}/file.txt"))
        self.assertIsNone(self.check(f"ls {self.root}"))

    def test_system_paths_allowed(self):
        self.assertIsNone(self.check("which python3"))
        self.assertIsNone(self.check("cat /etc/hostname"))
        self.assertIsNone(self.check("echo hi > /dev/null"))
        self.assertIsNone(self.check("head -c 100 /dev/urandom > /dev/null"))

    def test_redirect_inside(self):
        self.assertIsNone(self.check("echo hi > out.txt"))
        self.assertIsNone(self.check(f"echo hi > {self.root}/out.txt"))

    def test_cd_inside(self):
        os.makedirs(os.path.join(self.root, "sub"), exist_ok=True)
        # cd into a subdir, then reach a sibling file with ../ — stays
        # inside the shared root.
        with open(os.path.join(self.root, "file.txt"), "w") as f:
            f.write("x")
        self.assertIsNone(self.check("cd sub && cat ../file.txt"))

    def test_tmp_allowed(self):
        self.assertIsNone(self.check("ls /tmp"))

    # ---- must REJECT ------------------------------------------------------

    def test_absolute_outside(self):
        self.assertIsNotNone(self.check("cat /etc/passwd"))
        self.assertIsNotNone(self.check("find /mnt/Tera -name file"))
        self.assertIsNotNone(self.check(f"cat {self.tmp}/outside.txt"))

    def test_relative_traversal(self):
        self.assertIsNotNone(self.check("cat ../../etc/passwd"))

    def test_cd_traversal_then_relative(self):
        # The runtime cwd after `cd sub` makes ../../ escape the root.
        os.makedirs(os.path.join(self.root, "sub"), exist_ok=True)
        self.assertIsNotNone(self.check("cd sub && cat ../../outside.txt"))

    def test_home_rejected(self):
        self.assertIsNotNone(self.check("cat ~/.ssh/id_rsa"))
        self.assertIsNotNone(self.check("ls ~"))
        self.assertIsNotNone(self.check("cd ~"))
        self.assertIsNotNone(self.check("grep pattern ~"))

    def test_variables_rejected(self):
        self.assertIsNotNone(self.check("P=$(echo /etc/passwd); cat $P"))
        self.assertIsNotNone(self.check("cat $HOME/secret"))
        self.assertIsNotNone(self.check("echo ${HOME}"))

    def test_substitution_rejected(self):
        self.assertIsNotNone(self.check("cat `which python`"))
        self.assertIsNotNone(self.check("echo $(ls /etc)"))
        self.assertIsNotNone(self.check("cat <(ls /etc)"))

    def test_redirect_outside_rejected(self):
        self.assertIsNotNone(self.check("echo x > /root/.bashrc"))
        self.assertIsNotNone(self.check("echo x >> ~/.bashrc"))

    def test_root_path_rejected(self):
        self.assertIsNotNone(self.check("ls /"))

    def test_sneaky_semicolon_paths(self):
        self.assertIsNotNone(self.check("cat /etc/passwd;rm -rf /"))


if __name__ == "__main__":
    unittest.main()
