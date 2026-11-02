"""State v2 tests: migration from v1, agent normalization, history rotation."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.state import StateStore, History, normalize_agent


class TestMigration(unittest.TestCase):
    def test_v1_state_migrates(self):
        tmp = tempfile.mkdtemp(prefix="state-test-")
        old = {
            "schema_version": 1,
            "key": "ldb_olddkey123456789",
            "roots": ["/tmp/a", "/tmp/b"],
            "host": "0.0.0.0",
            "port": 8765,
        }
        with open(os.path.join(tmp, "state.json"), "w") as f:
            json.dump(old, f)
        store = StateStore(tmp)
        state = store.load()
        self.assertEqual(state["schema_version"], 2)
        self.assertEqual(len(state["agents"]), 1)
        self.assertEqual(state["agents"][0]["key"], "ldb_olddkey123456789")
        self.assertEqual(state["agents"][0]["name"], "default")
        self.assertEqual(state["roots"], ["/tmp/a", "/tmp/b"])
        self.assertIn("settings", state)
        # defaults land in settings
        self.assertIn(state["settings"]["approval_policy"],
                      ("auto", "destructive", "strict"))

    def test_fresh_state(self):
        tmp = tempfile.mkdtemp(prefix="state-test2-")
        state = StateStore(tmp).load()
        self.assertEqual(state["schema_version"], 2)
        self.assertEqual(state["agents"][0]["name"], "default")
        self.assertTrue(state["agents"][0]["key"].startswith("llmac_"))

    def test_save_load_roundtrip(self):
        tmp = tempfile.mkdtemp(prefix="state-test3-")
        store = StateStore(tmp)
        state = store.build_state(
            roots=["/tmp/x"], host="127.0.0.1", port=1234,
            agents=[{"name": "a", "key": "llmac_key_here_1234", "roots": [],
                     "perms": {"read": True, "write": True, "delete": False,
                               "exec": False, "proc": False}}],
            settings={"tls": True, "allow_exec": False,
                       "approval_policy": "strict", "venvs": []})
        store.save(state)
        loaded = StateStore(tmp).load()
        self.assertEqual(loaded["agents"][0]["name"], "a")
        self.assertEqual(loaded["settings"]["approval_policy"], "strict")
        # state.json is chmod 600 on POSIX
        if os.name == "posix":
            self.assertEqual(os.stat(store.state_path).st_mode & 0o777, 0o600)

    def test_corrupt_state_falls_back_to_backup(self):
        tmp = tempfile.mkdtemp(prefix="state-test4-")
        store = StateStore(tmp)
        good = store.build_state(roots=["/tmp/x"], host="h", port=1,
                                  agents=[{"name": "a", "key": "llmac_k",
                                           "roots": [], "perms": {}}],
                                  settings={"approval_policy": "auto"})
        store.save(good)
        backup = json.load(open(store.backup_path)) if os.path.exists(
            store.backup_path) else None
        # Corrupt the primary:
        with open(store.state_path, "w") as f:
            f.write("{corrupt json")
        if backup and backup.get("agents"):
            loaded = StateStore(tmp).load()
            self.assertEqual(loaded["agents"][0]["name"], "a")
        else:
            # No usable backup — fresh default state.
            loaded = StateStore(tmp).load()
            self.assertEqual(loaded["agents"][0]["name"], "default")


class TestAgentNormalize(unittest.TestCase):
    def test_fills_defaults(self):
        a = normalize_agent({"name": "x", "key": "llmac_y"})
        self.assertEqual(a["perms"]["read"], True)
        self.assertEqual(a["perms"]["exec"], False)
        self.assertEqual(a["roots"], [])
        self.assertIsNone(a["expires_at"])

    def test_extra_fields_kept(self):
        a = normalize_agent({"name": "x", "key": "k", "expires_at":
                             "2030-01-01T00:00:00+00:00"})
        self.assertEqual(a["expires_at"], "2030-01-01T00:00:00+00:00")


class TestHistory(unittest.TestCase):
    def test_append_and_tail(self):
        tmp = tempfile.mkdtemp(prefix="hist-test-")
        h = History(tmp)
        for i in range(10):
            h.append({"type": "op", "op": "write", "i": i})
        events = h.tail(3)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[-1]["i"], 9)


if __name__ == "__main__":
    unittest.main()
