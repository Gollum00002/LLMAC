"""InstallPolicy v2 tests: venv markers, npm global position, managers."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.policy import InstallPolicy, _looks_like_venv


class TestVenvMarkers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="venv-test-")
        self.venv = os.path.join(self.tmp, ".venv")
        os.makedirs(os.path.join(self.venv, "bin"), exist_ok=True)
        with open(os.path.join(self.venv, "pyvenv.cfg"), "w") as f:
            f.write("home = /usr/bin\n")

    def test_marker_detected(self):
        self.assertTrue(_looks_like_venv(self.venv))
        self.assertTrue(_looks_like_venv(os.path.join(self.venv, "bin")))
        self.assertTrue(_looks_like_venv(
            os.path.join(self.venv, "bin", "pip")))

    def test_plain_dir_not_venv(self):
        plain = os.path.join(self.tmp, "plain")
        os.makedirs(plain, exist_ok=True)
        self.assertFalse(_looks_like_venv(plain))

    def test_conda_meta_detected(self):
        conda_env = os.path.join(self.tmp, "conda-env")
        os.makedirs(os.path.join(conda_env, "conda-meta"), exist_ok=True)
        self.assertTrue(_looks_like_venv(conda_env))


class TestPolicyVerdicts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pol-test-")
        self.venv = os.path.join(self.tmp, ".venv")
        os.makedirs(os.path.join(self.venv, "bin"), exist_ok=True)
        with open(os.path.join(self.venv, "pyvenv.cfg"), "w") as f:
            f.write("home = /usr/bin\n")
        self.policy = InstallPolicy()
        self.cwd = self.tmp

    def verdict(self, command):
        return self.policy.pre_exec(command, self.cwd)

    # ---- must be ALLOWED (None) -------------------------------------------

    def test_non_install(self):
        self.assertIsNone(self.verdict("ls -la"))
        self.assertIsNone(self.verdict("python3 script.py"))
        self.assertIsNone(self.verdict("grep -r foo ."))

    def test_venv_marker_pip(self):
        self.assertIsNone(self.verdict(".venv/bin/pip install requests"))

    def test_venv_marker_python_m(self):
        self.assertIsNone(self.verdict(".venv/bin/python -m pip install requests"))

    def test_venv_created_this_session(self):
        # venv tracked from creation even before pyvenv.cfg check applies
        self.assertIsNone(
            self.verdict("python3 -m venv .venv && .venv/bin/pip install x"))

    def test_venv_relative_paths(self):
        os.makedirs(os.path.join(self.tmp, "proj"), exist_ok=True)
        self.assertIsNone(self.verdict(
            "cd proj && python3 -m venv v && v/bin/pip install x"))

    def test_local_npm(self):
        self.assertIsNone(self.verdict("npm install"))
        self.assertIsNone(self.verdict("npm install --no-save left-pad"))
        self.assertIsNone(self.verdict("yarn add express"))
        self.assertIsNone(self.verdict("pnpm add lodash"))

    def test_scoped_installers(self):
        self.assertIsNone(self.verdict("pipx install httpie"))
        self.assertIsNone(self.verdict("poetry add requests"))
        self.assertIsNone(self.verdict("pdm add requests"))
        self.assertIsNone(self.verdict("uv add requests"))
        self.assertIsNone(self.verdict("cargo install ripgrep"))
        self.assertIsNone(self.verdict("go install golang.org/x/tools/cmd/goimports@latest"))

    def test_conda_env_scoped(self):
        self.assertIsNone(self.verdict("conda install -n myenv numpy"))
        self.assertIsNone(self.verdict("conda install --prefix ./env numpy"))

    # ---- must be REJECTED ---------------------------------------------------

    def test_bare_pip(self):
        v = self.verdict("pip install requests")
        self.assertIsNotNone(v)
        self.assertEqual(v["rule"], "install_not_in_venv")

    def test_bare_python_m_pip(self):
        self.assertIsNotNone(self.verdict("python3 -m pip install requests"))
        self.assertIsNotNone(self.verdict("python -m pip install requests"))

    def test_system_managers(self):
        for cmd in ("apt install build-essential", "apt-get install x",
                    "yum install x", "dnf -y install x", "brew install wget",
                    "pacman -S gcc", "zypper install x", "apk add curl",
                    "emerge dev-vcs/git", "snap install x", "gem install rails",
                    "choco install x", "winget install x"):
            v = self.verdict(cmd)
            self.assertIsNotNone(v, f"should reject: {cmd}")
            self.assertEqual(v["rule"], "system_package_manager",
                             f"wrong rule for {cmd}: {v['rule']}")

    def test_npm_global_position_aware(self):
        # The v1 regex missed these; v2 must catch both positions.
        v = self.verdict("npm install -g typescript")
        self.assertIsNotNone(v)
        v = self.verdict("npm i typescript -g")
        self.assertIsNotNone(v)
        v = self.verdict("npm i -g typescript")
        self.assertIsNotNone(v)
        v = self.verdict("yarn global add typescript")
        self.assertIsNotNone(v)
        v = self.verdict("pnpm add -g typescript")
        self.assertIsNotNone(v)

    def test_pip_variants(self):
        self.assertIsNotNone(self.verdict("pip3 install x"))
        self.assertIsNotNone(self.verdict("uv pip install x"))
        # venv-scoped uv pip must pass though:
        self.assertIsNone(self.verdict(".venv/bin/python -m pip install x"))

    def test_conda_base_rejected(self):
        v = self.verdict("conda install numpy")
        self.assertIsNotNone(v)
        self.assertEqual(v["rule"], "conda_base_install")

    def test_venv_unknown_rejected(self):
        # A bin/pip path with no pyvenv.cfg anywhere above it.
        fake = os.path.join(self.tmp, "fake-venv", "bin")
        os.makedirs(fake, exist_ok=True)
        v = self.verdict("fake-venv/bin/pip install x")
        self.assertIsNotNone(v)
        self.assertEqual(v["rule"], "install_not_in_venv")


if __name__ == "__main__":
    unittest.main()
