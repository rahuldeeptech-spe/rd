import contextlib
import io
import os
import subprocess
import tempfile
import unittest

import phpini

BAD = "allow_url_include = On\ndisable_functions =\ndisplay_errors = On ; dev\nexpose_php=On\n[Session]\nsession.cookie_httponly = 0\n"
GOOD = "allow_url_include=Off\ndisplay_errors=Off\nexpose_php=Off\nsession.cookie_httponly=1\nsession.cookie_secure=1\nsession.use_strict_mode=1\n"


def tmp(text):
    fd, p = tempfile.mkstemp(suffix=".ini")
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return p


class PhpIni(unittest.TestCase):
    def go(self, argv, run=subprocess.run):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = phpini.main(argv, run)
        return rc, out.getvalue(), err.getvalue()

    def test_parse_ini_strips_comments_sections_quotes(self):
        d = phpini.parse_ini('; c\n[X]\na = "b" ; tail\nc=1\n')
        self.assertEqual(d, {"a": "b", "c": "1"})

    def test_bad_file_has_high_and_exits_1(self):
        rc, out, _ = self.go(["--ini", tmp(BAD)])
        self.assertEqual(rc, 1)
        self.assertIn("[HIGH] allow_url_include", out)
        self.assertIn("[MEDIUM] display_errors", out)
        self.assertIn("[LOW] expose_php", out)
        self.assertLess(out.index("HIGH"), out.index("MEDIUM"))
        self.assertLess(out.index("[MEDIUM] display_errors"), out.index("[LOW] disable_functions"))   # severity, not alphabet

    def test_good_file_is_clean(self):
        rc, out, _ = self.go(["--ini", tmp(GOOD)])
        self.assertEqual(rc, 0)
        self.assertIn("no risky setting", out)

    def test_unmentioned_keys_are_not_judged(self):
        rc, out, _ = self.go(["--ini", tmp("memory_limit=1G\n")])
        self.assertEqual(rc, 0)
        self.assertNotIn("[", out.split("\n", 1)[1])

    def test_medium_only_exits_0(self):
        rc, out, _ = self.go(["--ini", tmp("display_errors=On\n")])
        self.assertEqual(rc, 0)
        self.assertIn("[MEDIUM]", out)

    def test_php_binary_json(self):
        fake = lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout='{"allow_url_include":"1","expose_php":"","disable_functions":null}', stderr="")
        rc, out, _ = self.go(["--php", "php"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("[HIGH] allow_url_include", out)
        self.assertIn("disable_functions", out)       # empty value is a LOW finding
        self.assertNotIn("expose_php", out)           # empty = off

    def test_php_failures_are_exit_3_not_clean(self):
        for res in (subprocess.CompletedProcess([], 1, stdout="", stderr=""),
                    subprocess.CompletedProcess([], 255, stdout='{"allow_url_include":"0"}', stderr="Fatal"),
                    subprocess.CompletedProcess([], 0, stdout="not json", stderr=""),
                    subprocess.CompletedProcess([], 0, stdout="[1]", stderr="")):
            rc, out, err = self.go(["--php", "php"], lambda *a, _r=res, **k: _r)
            self.assertEqual(rc, 3)
            self.assertIn("Nothing was audited", err)
        def boom(*a, **k):
            raise FileNotFoundError()
        self.assertEqual(self.go(["--php", "nophp"], boom)[0], 3)

    def test_unreadable_ini_is_usage_error(self):
        self.assertEqual(self.go(["--ini", "/no/such/php.ini"])[0], 2)


if __name__ == "__main__":
    unittest.main()
