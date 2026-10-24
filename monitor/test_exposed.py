import contextlib
import io
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import exposed

FILES = {
    "/.env": "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n",
    "/.git/HEAD": "ref: refs/heads/main\n",
    "/phpinfo.php": "<html><title>phpinfo()</title>PHP Version 8.3.1</html>",
    "/composer.lock": "<html>custom 404 page</html>",          # looks wrong: must NOT be reported
    "/info.php": "Not Found",
}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redir/.env":
            self.send_response(302); self.send_header("Location", "/login"); self.end_headers(); return
        if self.path in FILES:
            body = FILES[self.path].encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *a):
        pass


class Exposed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), H)
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def run_main(self, args, **kw):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = exposed.main(args, pause=0, **kw)
        return rc, out.getvalue(), err.getvalue()

    def test_finds_real_exposures_only_and_never_prints_content(self):
        rc, out, _ = self.run_main([self.base])
        self.assertEqual(rc, 1)
        self.assertIn("/.env", out)
        self.assertIn("/.git/HEAD", out)
        self.assertIn("/phpinfo.php", out)
        self.assertNotIn("composer.lock", out)       # 200 but not the real thing
        self.assertNotIn("/info.php", out)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("APP_KEY", out)

    def test_clean_site(self):
        rc, out, _ = self.run_main([self.base + "/empty"])
        self.assertEqual(rc, 0)
        self.assertIn("none of the", out)

    def test_redirects_are_not_followed(self):
        status, _ = exposed.fetch(self.base + "/redir/.env")
        self.assertEqual(status, 302)

    def test_unreachable_is_never_clean(self):
        rc, out, err = self.run_main(["http://127.0.0.1:1"])
        self.assertEqual(rc, 3)
        self.assertIn("not a clean result", err)
        self.assertEqual(out, "")

    def test_bad_urls_are_usage_errors(self):
        for bad in ("ftp://x.example", "example.com", "http://u:p@x.example", "http://x.example/?a=1", ""):
            self.assertEqual(self.run_main([bad])[0], 2, bad)

    def test_signatures(self):
        sig = {p: s for p, _, s in exposed.CHECKS}
        self.assertTrue(sig["/.env"].search("A_B=1"))
        self.assertFalse(sig["/.env"].search("<html>hello</html>"))
        self.assertFalse(sig["/.git/HEAD"].search("<html>ref: refs/</html>"))
        self.assertTrue(sig["/.htpasswd"].search("bob:$apr1$x$y"))


if __name__ == "__main__":
    unittest.main()
