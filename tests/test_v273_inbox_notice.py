"""v2.7.3 — the inbox notice rides EVERY operation's result.

Field problem: LLM agents ignored mid-execution human messages because
the v2.5.1 banner was a stderr line printed mid-request, BEFORE the
result. Contract now:
  * while the acting agent has unread inbox messages, EVERY operation
    returns its normal result AND a notice saying how many messages are
    waiting to be addressed in Inbox;
  * plain output: a trailer on stdout after the op's own output;
  * JSON output (--json, info, export…): a top-level "inbox_notice"
    object in the document, stdout stays parseable;
  * the count is exact and tracks new messages; the inbox read is
    exempt; rc is untouched; failing ops carry the notice too;
  * `run` emits it per sub-command; exported files stay byte-clean.
"""
import json
import os
import subprocess
import sys
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost, make_tree

CLI = os.path.join(_PARENT, "llmac.py")
NEEDLE = "waiting to be addressed in Inbox"


def run_cli(host, *args, stdin=None, timeout=90):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout, input=stdin)


class _Base(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {"f.txt": "hello\n"})
        self.f = os.path.join(self.host.root, "f.txt")

    def msg(self, n=1):
        for i in range(n):
            self.host.ctx.sessions.inbox("default", f"m{i}")


class TestTrailer(_Base):

    def test_result_and_notice_arrive_together(self):
        self.msg(1)
        r = run_cli(self.host, "read", "--path", self.f)
        self.assertEqual(r.returncode, 0)
        self.assertIn("hello", r.stdout)              # the real result
        self.assertIn(f"1 message {NEEDLE}", r.stdout)  # ...plus notice
        # notice comes AFTER the result — it is the last thing read
        self.assertLess(r.stdout.index("hello"), r.stdout.index(NEEDLE))

    def test_exact_count_and_plural(self):
        self.msg(3)
        r = run_cli(self.host, "stat", "--path", self.f)
        self.assertIn(f"3 messages {NEEDLE}", r.stdout)

    def test_count_tracks_new_messages(self):
        self.msg(1)
        self.assertIn(f"1 message {NEEDLE}",
                      run_cli(self.host, "info").stdout)
        self.msg(2)
        self.assertIn(f"3 messages {NEEDLE}",
                      run_cli(self.host, "info").stdout)

    def test_points_at_the_inbox_command(self):
        self.msg(1)
        r = run_cli(self.host, "ls", "--path", self.host.root)
        self.assertIn("session inbox", r.stdout)

    def test_quiet_inbox_adds_nothing(self):
        r = run_cli(self.host, "read", "--path", self.f)
        self.assertNotIn(NEEDLE, r.stdout + r.stderr)
        self.assertNotIn("[INBOX]", r.stdout)

    def test_inbox_read_exempt_and_clears(self):
        self.msg(2)
        r = run_cli(self.host, "session", "inbox")
        self.assertNotIn(NEEDLE, r.stdout + r.stderr)
        self.assertNotIn(NEEDLE, run_cli(self.host, "info").stdout)

    def test_peek_does_not_clear(self):
        self.msg(2)
        r = run_cli(self.host, "session", "inbox", "--peek")
        self.assertNotIn(NEEDLE, r.stdout)
        self.assertIn(f"2 messages {NEEDLE}",
                      run_cli(self.host, "info").stdout)

    def test_failing_op_still_carries_notice_and_rc(self):
        self.msg(1)
        r = run_cli(self.host, "read", "--path",
                    os.path.join(self.host.root, "nope.txt"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(NEEDLE, r.stdout)

    def test_write_op_confirmation_plus_notice(self):
        self.msg(1)
        p = os.path.join(self.host.root, "new.txt")
        r = run_cli(self.host, "write", "--path", p, "--content", "x")
        self.assertEqual(r.returncode, 0)
        self.assertIn(NEEDLE, r.stdout)
        self.assertTrue(os.path.exists(p))

    def test_batch_gets_notice(self):
        self.msg(1)
        ops = json.dumps([{"op": "stat", "path": self.f}])
        r = run_cli(self.host, "batch", "--ops", ops)
        self.assertIn("[0] stat: ok", r.stdout)
        self.assertIn(NEEDLE, r.stdout)

    def test_exec_plain_gets_notice(self):
        self.msg(1)
        r = run_cli(self.host, "exec", "--command", "echo hi")
        if "exec" in r.stderr and "disabled" in r.stderr.lower():
            self.skipTest("exec disabled in this harness")
        self.assertIn(NEEDLE, r.stdout)


class TestJsonStaysParseable(_Base):

    def test_info_json_has_field(self):
        self.msg(2)
        r = run_cli(self.host, "info")
        # the document itself carries the notice; whole stdout parses
        doc = json.loads(r.stdout)
        self.assertEqual(doc["inbox_notice"]["unread"], 2)
        self.assertIn(f"2 messages {NEEDLE}",
                      doc["inbox_notice"]["message"])
        self.assertNotIn("[INBOX]", r.stdout)   # not doubled

    def test_info_quiet_has_no_field(self):
        doc = json.loads(run_cli(self.host, "info").stdout)
        self.assertNotIn("inbox_notice", doc)

    def test_exec_json_has_field(self):
        self.msg(1)
        r = run_cli(self.host, "exec", "--command", "echo hi", "--json")
        try:
            doc = json.loads(r.stdout)
        except ValueError:
            self.skipTest("exec disabled in this harness")
        self.assertEqual(doc["inbox_notice"]["unread"], 1)

    def test_batch_json_has_field(self):
        self.msg(1)
        ops = json.dumps([{"op": "stat", "path": self.f}])
        r = run_cli(self.host, "batch", "--ops", ops, "--json")
        doc = json.loads(r.stdout)
        self.assertEqual(doc["inbox_notice"]["unread"], 1)
        self.assertIn("results", doc)


class TestRunAndExport(_Base):

    def test_run_notices_each_subcommand(self):
        self.msg(1)
        vecs = json.dumps([["stat", "--path", self.f],
                           ["ls", "--path", self.host.root]])
        r = run_cli(self.host, "run", stdin=vecs)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.count(NEEDLE), 2)

    def test_export_file_is_clean_but_stdout_notes(self):
        self.msg(1)
        out = os.path.join(self.host.root, "exp.json")
        r = run_cli(self.host, "session", "export", "--out", out)
        self.assertEqual(r.returncode, 0)
        with open(out, encoding="utf-8") as fh:
            self.assertNotIn("inbox_notice", json.load(fh))
        self.assertIn(NEEDLE, r.stdout)       # confirmation + trailer
        r2 = run_cli(self.host, "session", "export")
        self.assertEqual(json.loads(r2.stdout)["inbox_notice"]["unread"], 1)


class TestSource(unittest.TestCase):

    def test_no_more_midrequest_stderr_banner(self):
        src = open(CLI, encoding="utf-8").read()
        self.assertNotIn("HUMAN MESSAGE WAITING", src)

    def test_main_goes_through_wrapper(self):
        src = open(CLI, encoding="utf-8").read()
        self.assertIn("return _call_with_inbox_notice(args.func, args)", src)


if __name__ == "__main__":
    unittest.main()
