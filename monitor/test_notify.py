import json
import os
import tempfile
import unittest

import notify

REPORT = {"alerts": [{"id": "CVE-2026-1", "severity": "CRITICAL", "title": "Bad\x1b[31m thing " + "x" * 300,
                      "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1"},
                     {"id": "CVE-2026-2", "severity": "HIGH", "title": "t", "url": "javascript:alert(1)"}]}


def write(obj):
    fd, p = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh)
    return p


class Notify(unittest.TestCase):
    def test_message_is_cleaned_and_bounded(self):
        m = notify.build_message(REPORT, "o/r")
        self.assertNotIn("\x1b", m)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2026-1", m)
        self.assertNotIn("javascript:", m)
        self.assertIn("https://github.com/o/r/blob/reports/README.md", m)
        self.assertTrue(all(len(line) < 260 for line in m.split("\n")))

    def test_more_than_max_is_summarised(self):
        rep = {"alerts": [{"id": "CVE-%d" % i, "severity": "HIGH", "title": "t", "url": ""} for i in range(25)]}
        m = notify.build_message(rep, "")
        self.assertIn("and 15 more", m)

    def test_no_alerts_sends_nothing(self):
        sent = []
        self.assertEqual(notify.main(["--report", write({"alerts": []})], env={"SLACK_WEBHOOK_URL": "https://x"}, post=lambda *a: sent.append(a)), 0)
        self.assertEqual(sent, [])

    def test_no_channel_is_not_an_error(self):
        sent = []
        self.assertEqual(notify.main(["--report", write(REPORT)], env={}, post=lambda *a: sent.append(a)), 0)
        self.assertEqual(sent, [])

    def test_all_channels_get_the_message(self):
        sent = []
        env = {"TELEGRAM_BOT_TOKEN": "tok", "TELEGRAM_CHAT_ID": "42", "DISCORD_WEBHOOK_URL": "https://d", "SLACK_WEBHOOK_URL": "https://s"}
        self.assertEqual(notify.main(["--report", write(REPORT)], env=env, post=lambda u, p: sent.append((u, p))), 0)
        self.assertEqual([u for u, _ in sent], ["https://api.telegram.org/bottok/sendMessage", "https://d", "https://s"])
        self.assertEqual(sent[0][1]["chat_id"], "42")
        self.assertIn("content", sent[1][1])
        self.assertIn("text", sent[2][1])

    def test_one_failure_does_not_stop_the_others_and_hides_the_secret(self):
        sent, calls = [], []
        def post(u, p):
            calls.append(u)
            if u == "https://d":
                raise OSError("boom https://d")
        env = {"DISCORD_WEBHOOK_URL": "https://d", "SLACK_WEBHOOK_URL": "https://s"}
        import io, contextlib
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = notify.main(["--report", write(REPORT)], env=env, post=post)
        self.assertEqual(rc, 3)
        self.assertEqual(calls, ["https://d", "https://s"])
        self.assertNotIn("https://d", err.getvalue())

    def test_unreadable_report_is_usage_error(self):
        self.assertEqual(notify.main(["--report", "/nonexistent/x.json"], env={}), 2)


if __name__ == "__main__":
    unittest.main()
