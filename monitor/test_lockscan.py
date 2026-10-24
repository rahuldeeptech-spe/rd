import io
import contextlib
import json
import os
import tempfile
import unittest

import lockscan as L

LOCK3 = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-lodash.tgz"},
    "node_modules/a/node_modules/@s/b": {"version": "1.0.0"},
    "node_modules/local": {"link": True, "resolved": "../local"},
    "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://x"}}})
LOCK1 = json.dumps({"lockfileVersion": 1, "dependencies": {
    "x": {"version": "1.2.3", "dependencies": {"y": {"version": "0.1.0"}}}, "z": {"version": "github:o/r"}}})
COMPOSER = json.dumps({"packages": [{"name": "a/b", "version": "v1.2.3"}, {"name": "c/d", "version": "dev-main"}],
                       "packages-dev": [{"name": "e/f", "version": "2.0.0"}]})
GOMOD = """module m
go 1.22
require github.com/x/y v1.2.3
require (
\tgolang.org/x/net v0.10.0 // indirect
\tgithub.com/a/b v0.0.0-20200101000000-abcdef // indirect
)
"""
REQ = "Django==3.2.0\nrequests>=2\n# c\nFlask[async]==2.0.1 ; python_version>'3'\n-r other.txt\nSome_Pkg==1.0\n"


class Parsers(unittest.TestCase):
    def test_npm_v3(self):
        p, _ = L.parse_package_lock(LOCK3)
        self.assertEqual(p, {("npm", "lodash", "4.17.15"), ("npm", "@s/b", "1.0.0")})

    def test_npm_v1_nested_and_nonversion(self):
        p, sk = L.parse_package_lock(LOCK1)
        self.assertEqual(p, {("npm", "x", "1.2.3"), ("npm", "y", "0.1.0")})
        self.assertEqual(len(sk), 1)

    def test_composer(self):
        p, sk = L.parse_composer_lock(COMPOSER)
        self.assertEqual(p, {("Packagist", "a/b", "1.2.3"), ("Packagist", "e/f", "2.0.0")})
        self.assertEqual(len(sk), 1)

    def test_go_mod(self):
        p, _ = L.parse_go_mod(GOMOD)
        self.assertEqual(p, {("Go", "github.com/x/y", "1.2.3"), ("Go", "golang.org/x/net", "0.10.0"),
                             ("Go", "github.com/a/b", "0.0.0-20200101000000-abcdef")})

    def test_requirements_pinned_only(self):
        p, sk = L.parse_requirements(REQ)
        self.assertEqual(p, {("PyPI", "django", "3.2.0"), ("PyPI", "flask", "2.0.1"), ("PyPI", "some-pkg", "1.0")})
        self.assertIn("requests>=2", sk)
        self.assertIn("-r other.txt", sk)


def fake_http(calls):
    def http(url, payload=None, timeout=30):
        calls.append((url, payload))
        if url.endswith("/querybatch"):
            res = []
            for q in payload["queries"]:
                if q["package"]["name"] == "lodash":
                    res.append({"vulns": [{"id": "GHSA-aaaa"}], **({"next_page_token": "t"} if "page_token" not in q else {})})
                    if "page_token" in q:
                        res[-1] = {"vulns": [{"id": "GHSA-bbbb"}]}
                else:
                    res.append({})
            return {"results": res}
        vid = url.rsplit("/", 1)[1]
        return {"summary": "Bad \x1b[0m thing", "aliases": ["CVE-2020-1"], "database_specific": {"severity": "HIGH" if vid == "GHSA-aaaa" else "LOW"},
                "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}
    return http


class Scan(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        with open(os.path.join(self.d, "package-lock.json"), "w") as fh:
            fh.write(LOCK3)
        os.makedirs(os.path.join(self.d, "node_modules", "q"))
        with open(os.path.join(self.d, "node_modules", "q", "package-lock.json"), "w") as fh:
            fh.write(LOCK1)

    def run_main(self, args, http):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = L.main(args, http)
        return rc, out.getvalue(), err.getvalue()

    def test_findings_pagination_and_cleaning(self):
        calls = []
        rc, out, _ = self.run_main([self.d], fake_http(calls))
        self.assertEqual(rc, 1)
        self.assertIn("GHSA-aaaa", out)
        self.assertIn("GHSA-bbbb", out)          # came from the second page
        self.assertIn("4.17.21", out)
        self.assertNotIn("\x1b", out)
        self.assertEqual(sum(1 for u, _ in calls if u.endswith("querybatch")), 2)
        self.assertNotIn("node_modules", out)    # skipped directory

    def test_fail_on_never_and_high(self):
        self.assertEqual(self.run_main([self.d, "--fail-on", "never"], fake_http([]))[0], 0)
        self.assertEqual(self.run_main([self.d, "--fail-on", "high"], fake_http([]))[0], 1)   # one HIGH finding

    def test_low_only_passes_fail_on_high(self):
        def http(url, payload=None, timeout=30):
            if url.endswith("querybatch"):
                return {"results": [{"vulns": [{"id": "GHSA-bbbb"}]} if q["package"]["name"] == "lodash" else {} for q in payload["queries"]]}
            return fake_http([])(url, payload)
        self.assertEqual(self.run_main([self.d, "--fail-on", "high"], http)[0], 0)

    def test_clean_result(self):
        http = lambda url, payload=None, timeout=30: {"results": [{} for _ in payload["queries"]]}
        rc, out, _ = self.run_main([self.d], http)
        self.assertEqual(rc, 0)
        self.assertIn("no known vulnerabilities", out)

    def test_lookup_failure_is_never_clean(self):
        def http(*a, **k):
            raise L.OSVError("down")
        rc, out, err = self.run_main([self.d], http)
        self.assertEqual(rc, 3)
        self.assertIn("not a clean result", err)
        self.assertNotIn("no known vulnerabilities", out)

    def test_bad_response_shape_is_failure(self):
        rc, _, _ = self.run_main([self.d], lambda *a, **k: {"results": []})
        self.assertEqual(rc, 3)

    def test_usage_errors(self):
        self.assertEqual(self.run_main(["/no/such/path"], fake_http([]))[0], 2)
        f = os.path.join(self.d, "other.txt")
        open(f, "w").write("x")
        self.assertEqual(self.run_main([f], fake_http([]))[0], 2)
        bad = os.path.join(self.d, "composer.lock")
        open(bad, "w").write("{not json")
        self.assertEqual(self.run_main([bad], fake_http([]))[0], 2)

    def test_json_output(self):
        rc, out, _ = self.run_main([self.d, "--json", "--fail-on", "never"], fake_http([]))
        data = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertEqual(data["packages"], 2)
        self.assertEqual(len(data["findings"]), 2)


if __name__ == "__main__":
    unittest.main()
