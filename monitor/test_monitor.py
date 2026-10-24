"""Tests for monitor.py. Run: python3 -m unittest discover -s monitor -v

Feed payloads below follow each provider's published schema. Only the nodejs.org index was
compared against a live response while writing this; the first scheduled run on GitHub is the
real check for the others, which is why every shape error is reported as a failed source.
"""
import datetime as dt
import json
import os
import shutil
import tempfile
import unittest

import monitor as m

NOW = dt.datetime(2026, 10, 24, 5, 17, tzinfo=dt.timezone.utc)
HERE = os.path.dirname(os.path.abspath(__file__))
WATCH = m.load_watchlist(os.path.join(HERE, "watchlist.tsv"))
FIXED = {("php", "8.4"): "8.4.27", ("php", "8.3"): "8.3.36", ("node", "26"): "26.12.1", ("node", "24"): "24.22.1",
         ("go", "1.26"): "1.26.10", ("go", "1.27"): "1.27.3"}


class FakeNet:
    """Maps a URL substring to a payload (or an exception to raise)."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, headers=None, retries=3):
        self.calls.append(url)
        for key, val in self.routes.items():
            if key in url:
                if isinstance(val, Exception):
                    raise val
                return val(url) if callable(val) else val
        raise m.SourceError("no route for " + url)


def kev(*vulns):
    return {"catalogVersion": "2026.10.24", "vulnerabilities": list(vulns)}


def kev_entry(cve, added, vendor="Vendor", product="Product", name="Name", desc="desc"):
    return {"cveID": cve, "dateAdded": added, "vendorProject": vendor, "product": product, "vulnerabilityName": name,
            "shortDescription": desc, "dueDate": "2026-11-14", "knownRansomwareCampaignUse": "Unknown"}


class Helpers(unittest.TestCase):
    def test_clean_neutralises_mentions_refs_links_and_markup(self):
        out = m.clean("hi @octocat see #123 http://evil.example/x `rm -rf` <script>alert(1)</script> [a](b) | x")
        self.assertNotIn("@octocat", out)
        self.assertNotIn("#123", out)
        self.assertNotIn("http://evil", out)
        self.assertNotIn("<script>", out)
        self.assertNotIn("`", out.replace("\\`", ""))
        self.assertIn("&lt;script&gt;", out)

    def test_clean_strips_control_and_bidi_and_truncates(self):
        out = m.clean("a\x00b‮c\n\n\td" + "x" * 500, limit=40)
        self.assertNotIn("\x00", out)
        self.assertNotIn("‮", out)
        self.assertLessEqual(len(out), 45)
        self.assertTrue(out.endswith("…"))

    def test_parse_ts_variants(self):
        self.assertEqual(m.parse_ts("2026-10-24T05:17:00Z"), NOW)
        self.assertEqual(m.parse_ts("2026-10-24T07:17:00+02:00"), NOW)
        self.assertEqual(m.parse_ts("2026-10-24T05:17:00.123"), NOW.replace())  # fraction ignored, UTC assumed
        self.assertEqual(m.parse_ts("2026-10-24"), dt.datetime(2026, 10, 24, tzinfo=dt.timezone.utc))
        with self.assertRaises(ValueError):
            m.parse_ts("yesterday")

    def test_vcmp(self):
        self.assertEqual(m.vcmp("8.3.36", "8.3.36"), 0)
        self.assertEqual(m.vcmp("8.3.10", "8.3.9"), 1)
        self.assertEqual(m.vcmp("1.26", "1.26.0"), 0)
        self.assertEqual(m.vcmp("26.12.1", "26.12.2"), -1)

    def test_watch_is_whole_word(self):
        self.assertEqual(WATCH.match("A flaw in PHP before 8.3"), ["php"])
        self.assertEqual(WATCH.match("phpMyAdmin issue"), [])
        self.assertEqual(WATCH.match("Google Chrome"), [])
        self.assertIn("node.js", WATCH.match("Node.js Brotli decoder"))

    def test_load_rules_reads_only_fixed_rows(self):
        rules = m.load_rules(os.path.join(HERE, "..", "advisories.tsv"))
        self.assertEqual(rules[("php", "8.3")], "8.3.36")
        self.assertNotIn(("php", "8.1"), rules)


class Sources(unittest.TestCase):
    def test_kev_window_watchlist_and_invalid_ids(self):
        net = FakeNet({"known_exploited": kev(
            kev_entry("CVE-2026-1001", "2026-10-24", "PHP Group", "PHP", "PHP RCE"),
            kev_entry("CVE-2026-1002", "2026-10-23", "Acme", "Widget"),
            kev_entry("CVE-2026-1003", "2026-10-01", "Old", "Old"),
            kev_entry("not-a-cve", "2026-10-24"))})
        r = m.src_kev(net, NOW, 24, WATCH)
        ids = [i["id"] for i in r["items"]]
        self.assertEqual(ids, ["CVE-2026-1001", "CVE-2026-1002"])
        self.assertTrue(r["items"][0]["alert"])
        self.assertFalse(r["items"][1]["alert"])

    def test_nvd_critical_watchlist_and_unscored(self):
        def vuln(cid, desc, score=None, sev="CRITICAL"):
            metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": sev}}]} if score is not None else {}
            return {"cve": {"id": cid, "published": "2026-10-24T01:00:00.000", "descriptions": [{"lang": "en", "value": desc}], "metrics": metrics}}
        payload = {"totalResults": 5, "vulnerabilities": [
            vuln("CVE-2026-2001", "Some product RCE", 9.8),
            vuln("CVE-2026-2002", "Medium thing", 5.0, "MEDIUM"),
            vuln("CVE-2026-2003", "Node.js Brotli flaw", 8.1, "HIGH"),
            vuln("CVE-2026-2004", "A flaw in the CPython parser, awaiting analysis"),
            vuln("CVE-2026-2005", "A WordPress plugin for Python snippets has an XSS", 5.0, "MEDIUM")]}
        r = m.src_nvd(FakeNet({"nvd.nist.gov": payload}), NOW, 24, WATCH)
        by = {i["id"]: i for i in r["items"]}
        self.assertEqual(set(by), {"CVE-2026-2001", "CVE-2026-2003", "CVE-2026-2004"})
        self.assertFalse(by["CVE-2026-2001"]["alert"])
        self.assertTrue(by["CVE-2026-2003"]["alert"])
        self.assertTrue(by["CVE-2026-2004"]["alert"])
        self.assertEqual(r["items"][0]["id"], "CVE-2026-2003")  # alerts first, then by score

    def test_nvd_paginates(self):
        pages = [{"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2026-3001", "descriptions": [], "metrics": {}}}] * 2},
                 {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2026-3002", "descriptions": [], "metrics": {}}}]}]

        class Pager(FakeNet):
            def get(self, url, headers=None, retries=3):
                self.calls.append(url)
                return pages[0] if "startIndex=0" in url else pages[1]
        net = Pager({})
        m.src_nvd(net, NOW, 24, WATCH)
        self.assertEqual(len(net.calls), 2)

    def test_ghsa_filters(self):
        def adv(gid, sev, eco, when="2026-10-24T02:00:00Z", url=None):
            return {"ghsa_id": gid, "cve_id": "CVE-2026-9", "published_at": when, "summary": "s", "severity": sev,
                    "html_url": url or "https://github.com/advisories/" + gid,
                    "vulnerabilities": [{"package": {"ecosystem": eco, "name": "pkg"}, "first_patched_version": "1.2.3"}]}
        crit = [adv("GHSA-cccc-ffff-gggg", "critical", "maven"), adv("GHSA-cccc-ffff-hhhh", "critical", "npm", when="2026-10-01T00:00:00Z")]
        high = [adv("GHSA-cccc-ffff-hhhh", "high", "npm"), adv("GHSA-cccc-ffff-jjjj", "high", "maven"),
                adv("GHSA-cccc-ffff-mmmm", "high", "pip", url="https://evil.example/x")]

        class Router(FakeNet):
            def get(self, url, headers=None, retries=3):
                return crit if "severity=critical" in url else high
        r = m.src_ghsa(Router({}), NOW, 24, WATCH)
        ids = [(i["id"], i["severity"]) for i in r["items"]]
        self.assertIn(("GHSA-cccc-ffff-gggg", "CRITICAL"), ids)           # critical, any ecosystem
        self.assertNotIn(("GHSA-cccc-ffff-hhhh", "CRITICAL"), ids)        # outside window
        self.assertIn(("GHSA-cccc-ffff-hhhh", "HIGH"), ids)               # high, watched ecosystem
        self.assertNotIn(("GHSA-cccc-ffff-jjjj", "HIGH"), ids)            # high, unwatched ecosystem
        bad = [i for i in r["items"] if i["id"] == "GHSA-cccc-ffff-mmmm"][0]
        self.assertEqual(bad["url"], "")                                  # untrusted link dropped

    def test_node_latest_and_recent(self):
        idx = [{"version": "v26.12.1", "date": "2026-10-21", "security": True},
               {"version": "v26.12.0", "date": "2026-10-14", "security": False},
               {"version": "v24.22.1", "date": "2026-10-20", "security": True},
               {"version": "v24.22.0", "date": "2026-10-01", "security": False}]
        r = m.src_node(FakeNet({"nodejs.org": idx}), NOW, 96)
        self.assertEqual(r["upstream"][("node", "26")], "26.12.1")
        self.assertTrue(r["security_flags"][("node", "26")])
        self.assertEqual([i["id"] for i in r["items"]], ["node 26.12.1", "node 24.22.1"])

    def test_go_ignores_prereleases_and_unstable(self):
        idx = [{"version": "go1.27.3", "stable": True}, {"version": "go1.28rc1", "stable": False},
               {"version": "go1.26.10", "stable": True}, {"version": "go1.26.9", "stable": True}, {"version": "go1.27", "stable": True}]
        r = m.src_go(FakeNet({"go.dev": idx}), NOW, 24)
        self.assertEqual(r["upstream"], {("go", "1.27"): "1.27.3", ("go", "1.26"): "1.26.10"})

    def test_php_both_response_shapes_and_bad_shape(self):
        a = m.src_php(FakeNet({"version=8.4": {"version": "8.4.27", "date": "21 Oct 2026"}}), NOW, 24, branches=["8.4"])
        self.assertEqual(a["upstream"][("php", "8.4")], "8.4.27")
        b = m.src_php(FakeNet({"version=8.4": {"8.4.26": {}, "8.4.27": {}}}), NOW, 24, branches=["8.4"])
        self.assertEqual(b["upstream"][("php", "8.4")], "8.4.27")
        with self.assertRaises(m.SourceError):
            m.src_php(FakeNet({"version=8.4": {"version": "7.0.1"}}), NOW, 24, branches=["8.4"])


class Classification(unittest.TestCase):
    """Real descriptions from the first live NVD run (2026-10-24): runtime bugs vs apps that mention a runtime."""

    ABOUT = [
        ("node.js", "A flaw in Node.js DNS resolution allows hostnames containing a NUL byte to be silently truncated by the dns.resolve*() functions"),
        ("node.js", "A flaw in Node.js TLS hostname verification allows a certificate without a matching IP address SAN to authenticate a connection"),
        ("node.js", "Node.js before 24.22.1 mishandles a Brotli stream"),
        ("php", "PHP before 8.3.36 allows remote attackers to execute arbitrary code via a use-after-free in the upload progress feature"),
        ("php", "A heap overflow in the PHP-FPM status page"),
        ("python", "A flaw in CPython's tarfile module allows path traversal"),
        ("go", "A flaw in the Go standard library net/http allows request smuggling"),
        ("openssl", "OpenSSL 3.5 mishandles a malformed certificate"),
    ]
    NOT_ABOUT = [
        ("php", "The Prime Mover - Backup and Migration plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 2.2.1"),
        ("php", "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in AncoraThemes Your Dress allows PHP Local File Inclusion."),
        ("python", "Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, the parser allows a remote peer to exhaust memory"),
        ("python", "pypdf is a free and open-source pure-python PDF library. Prior to 6.21.2, an attacker can craft a PDF"),
        ("python", "Hugging Face Datasets through 5.1.0 contains an insecure deserialization vulnerability that allows attackers to execute arbitrary Python code"),
        ("node.js", "Happy DOM is a JavaScript implementation of a web browser without its graphical user interface."),
    ]

    def test_runtime_bugs_are_core(self):
        for product, text in self.ABOUT:
            self.assertIn(product, WATCH.core(text), text)

    def test_apps_that_merely_mention_a_runtime_are_not_core(self):
        for product, text in self.NOT_ABOUT:
            self.assertNotIn(product, WATCH.core(text), text)

    def test_nvd_lists_core_and_counts_mention_only(self):
        def vuln(cid, desc, score):
            return {"cve": {"id": cid, "published": "2026-10-24T01:00:00.000", "descriptions": [{"lang": "en", "value": desc}],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]}}}
        payload = {"totalResults": 3, "vulnerabilities": [
            vuln("CVE-2026-4001", self.ABOUT[0][1], 7.4),
            vuln("CVE-2026-4002", self.NOT_ABOUT[0][1], 8.1),
            vuln("CVE-2026-4003", self.NOT_ABOUT[2][1], 8.7)]}
        r = m.src_nvd(FakeNet({"nvd.nist.gov": payload}), NOW, 24, WATCH)
        self.assertEqual([i["id"] for i in r["items"]], ["CVE-2026-4001"])
        self.assertTrue(r["items"][0]["alert"])
        self.assertIn("2 more only mention one", r["note"])

    def test_kev_vendor_field_counts_but_description_mention_does_not(self):
        net = FakeNet({"known_exploited": kev(
            kev_entry("CVE-2026-5001", "2026-10-24", "PHP Group", "PHP", "PHP RCE", "desc"),
            kev_entry("CVE-2026-5002", "2026-10-24", "Acme", "Shop", "Shop SQLi", "A WordPress plugin written in PHP allows SQL injection"))})
        by = {i["id"]: i for i in m.src_kev(net, NOW, 24, WATCH)["items"]}
        self.assertTrue(by["CVE-2026-5001"]["alert"])
        self.assertFalse(by["CVE-2026-5002"]["alert"])

    def test_bad_core_pattern_fails_loudly(self):
        path = os.path.join(tempfile.mkdtemp(), "w.tsv")
        with open(path, "w") as fh:
            fh.write("x\tfoo\t-\t(unclosed\n")
        with self.assertRaises(Exception):
            m.load_watchlist(path)


class Consistency(unittest.TestCase):
    def test_newer_equal_and_ahead(self):
        up = {("php", "8.4"): "8.4.28", ("php", "8.3"): "8.3.36", ("node", "26"): "26.12.1", ("node", "24"): "24.22.0"}
        alerts = m.consistency(FIXED, up, {("node", "26"): True}, {"php": True, "node": True, "go": False})
        titles = " ".join(a["title"] for a in alerts)
        self.assertIn("php 8.4 is 8.4.28", titles)           # upstream moved on
        self.assertNotIn("php 8.3", titles)                   # equal -> quiet
        self.assertIn("CHECK DATA", titles)                   # node 24 rule ahead of upstream
        self.assertNotIn("go 1.2", titles)                    # go source down -> no claims

    def test_security_flag_mentioned(self):
        up = {("node", "26"): "26.13.0"}
        alerts = m.consistency(FIXED, up, {("node", "26"): True}, {"node": True})
        self.assertIn("security release", alerts[0]["title"])

    def test_new_major_branch(self):
        up = {("node", "26"): "26.12.1", ("node", "27"): "27.0.0", ("go", "1.28"): "1.28.0"}
        alerts = m.consistency(FIXED, up, {}, {"node": True, "go": True})
        titles = " ".join(a["title"] for a in alerts)
        self.assertIn("new node branch 27", titles)
        self.assertIn("new go branch 1.28", titles)


class EndToEnd(unittest.TestCase):
    def run_main(self, routes, extra=()):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        rc = m.main(["--out", d, "--now", "2026-10-24T05:17:00Z"] + list(extra), net=FakeNet(routes))
        with open(os.path.join(d, "report.md"), encoding="utf-8") as fh:
            md = fh.read()
        with open(os.path.join(d, "report.json"), encoding="utf-8") as fh:
            js = json.load(fh)
        return rc, md, js, d

    def good_routes(self):
        """Upstream exactly matches the real advisories.tsv, so the only alert is the KEV entry."""
        rules = m.load_rules(os.path.join(HERE, "..", "advisories.tsv"))
        node = [{"version": "v%s" % v, "date": "2026-10-20", "security": True} for (rt, _b), v in rules.items() if rt == "node"]
        go = [{"version": "go%s" % v, "stable": True} for (rt, _b), v in rules.items() if rt == "go"]
        php = {b: v for (rt, b), v in rules.items() if rt == "php"}
        return {"known_exploited": kev(kev_entry("CVE-2026-1001", "2026-10-24", "PHP Group", "PHP", "PHP RCE")),
                "nvd.nist.gov": {"totalResults": 0, "vulnerabilities": []},
                "api.github.com/advisories": [],
                "nodejs.org": node, "go.dev": go,
                "php.net": lambda url: {"version": php[url.split("version=")[1]]}}

    def test_all_good_has_alert_from_kev_and_exit_zero(self):
        rc, md, js, d = self.run_main(self.good_routes())
        self.assertEqual(rc, 0)
        self.assertTrue(js["complete"])
        self.assertIn("CVE-2026-1001", md)
        self.assertIn("**watching: php**", md)
        self.assertTrue(os.path.exists(os.path.join(d, "alerts.md")))
        self.assertNotIn("INCOMPLETE", md)

    def test_failed_source_is_loud_and_never_reads_as_quiet(self):
        routes = self.good_routes()
        routes["known_exploited"] = m.SourceError("HTTP 503 for cisa")
        rc, md, js, _ = self.run_main(routes)
        self.assertEqual(rc, 3)
        self.assertFalse(js["complete"])
        self.assertIn("INCOMPLETE REPORT", md)
        self.assertIn("Source unavailable", md)
        self.assertNotIn("No new entries in the window", md)   # must not claim quiet for the failed source

    def test_unexpected_shape_is_a_failed_source_not_a_crash(self):
        routes = self.good_routes()
        routes["known_exploited"] = {"surprise": True}
        rc, md, js, _ = self.run_main(routes)
        self.assertEqual(rc, 3)
        self.assertIn("unexpected response shape", json.dumps(js["sources"]))

    def test_no_alerts_removes_stale_alerts_file(self):
        routes = self.good_routes()
        routes["known_exploited"] = kev()
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "alerts.md"), "w") as fh:
            fh.write("stale")
        rc = m.main(["--out", d, "--now", "2026-10-24T05:17:00Z"], net=FakeNet(routes))
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(os.path.join(d, "alerts.md")))

    def test_untrusted_text_is_sanitised_in_report(self):
        routes = self.good_routes()
        routes["known_exploited"] = kev(kev_entry("CVE-2026-1004", "2026-10-24", "X", "Y", "ping @everyone #1 http://phish.example", "d"))
        _rc, md, _js, _ = self.run_main(routes)
        self.assertNotIn("@everyone", md)
        self.assertNotIn("http://phish", md)

    def test_usage_errors(self):
        self.assertEqual(m.main(["--out", tempfile.mkdtemp(), "--sources", "bogus"]), 2)
        self.assertEqual(m.main(["--out", tempfile.mkdtemp(), "--hours", "0"]), 2)
        self.assertEqual(m.main([]), 2)
        self.assertEqual(m.main(["--out", tempfile.mkdtemp(), "--watchlist", "/nonexistent/w.tsv"]), 2)

    def test_sources_subset_never_claims_the_skipped_ones_are_quiet(self):
        rc, md, js, _ = self.run_main(self.good_routes(), ["--sources", "node"])
        self.assertEqual(rc, 0)
        self.assertEqual([s["name"] for s in js["sources"]], ["node"])
        self.assertIn("Not checked in this run", md)
        self.assertIn("not run: kev, nvd, ghsa, go, php", md)
        self.assertNotIn("No new entries in the window", md)
        self.assertFalse(js["complete"])

    def test_tracked_table_only_lists_known_or_newer_branches(self):
        _rc, md, _js, _ = self.run_main(self.good_routes(), ["--sources", "node"])
        self.assertIn("| node | 26 |", md)
        self.assertNotIn("| node | 0 |", md)
        self.assertNotIn("| node | 12 |", md)


if __name__ == "__main__":
    unittest.main()
