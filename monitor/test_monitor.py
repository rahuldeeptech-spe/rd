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
            vuln("CVE-2026-2003", "A flaw in Node.js Brotli handling", 8.1, "HIGH"),
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
    """Real NVD descriptions from the live run of 2026-10-24: is the CVE about the runtime, or only an app that mentions it?"""

    ABOUT = [  # (CVE, start of description, product)
        ("CVE-2026-109618", "PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request.", "php"),
        ("CVE-2026-109619", "PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be reset.", "php"),
        ("CVE-2026-105482", "A flaw in Node.js DNS resolution allows hostnames containing a NUL byte to be silently truncated by the dns.resolve*() functions", "node.js"),
        ("CVE-2026-105483", "A flaw in Node.js TLS hostname verification allows a certificate without a matching IP address SAN to authenticate a connection", "node.js"),
        ("CVE-2026-105481", "A flaw in Node.js HTTP Agent connection reuse can cause a client to accept as valid a response that was sent by", "node.js"),
        ("CVE-2026-106070", "A flaw in the Node.js `zlib.ZipFile` API can cause it to return bytes that do not belong to the requested entry", "node.js"),
        ("CVE-2026-106074", "A flaw in Node.js `crypto` causes the internal entropy caches used by `crypto.randomUUID()`", "node.js"),
        ("CVE-2026-106071", "A flaw in Node.js Permission Model filesystem enforcement can grant access to paths that do not match a wildcard", "node.js"),
        ("synthetic", "In PHP versions 8.1.* before 8.1.31, when using the CGI mode", "php"),
        ("synthetic", "A heap overflow in the PHP-FPM status page", "php"),
        ("synthetic", "Node.js before 24.22.1 mishandles a stream", "node.js"),
        ("synthetic", "A flaw in CPython's tarfile module allows path traversal", "python"),
        ("synthetic", "A flaw in the Go standard library allows request smuggling", "go"),
        ("synthetic", "In net/http, a malformed request causes a panic", "go"),
        ("synthetic", "OpenSSL 3.5 mishandles a malformed certificate", "openssl"),
        ("synthetic", "A vulnerability in nginx before 1.27.2 allows a worker crash", "nginx"),
    ]
    NOT_ABOUT = [  # third-party apps and libraries that merely mention a watched product
        ("CVE-2026-108357", "PhpSpreadsheet is a pure PHP library for reading and writing spreadsheet files. From 3.3.0 until 3.10.8", "php"),
        ("CVE-2026-54630", "Part-DB is an open source inventory management system for electronic components. Prior to version 2.12.1, the PHP upload handler", "php"),
        ("CVE-2026-115806", "The Prime Mover - Backup and Migration plugin for WordPress is vulnerable to PHP Object Injection in all versions up to", "php"),
        ("CVE-2026-112832", "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in AncoraThemes", "php"),
        ("CVE-2021-48016", "DedeCMS through 5.8.1-beta contains a PHP code injection vulnerability in ShowMsg() where the HTTP Referer header", "php"),
        ("CVE-2016-20101", "Issuu Panel plugin for WordPress before 1.6.6 contains a PHP file inclusion vulnerability that allows", "php"),
        ("CVE-2026-54630", "Part-DB is an open source inventory management system. The Apache configuration routes .phar to PHP-FPM, so the stored file is executed as PHP", "php"),
        ("CVE-2026-108358", "PhpSpreadsheet is a pure PHP library for reading and writing spreadsheet files. This can permit local file access or SSRF on PHP before 8.0 or when LIBXML_NOENT is enabled.", "php"),
        ("CVE-2026-114254", "A vulnerability was identified in oretnom23 file-management-system-php up to 2e3c1ebe60f1. This affects", "php"),
        ("CVE-2026-114259", "A flaw has been found in oretnom23 file-management-system-php up to 2e3c1ebe60f121e8df4fb3f544f0e9591d9a01e4.", "php"),
        ("CVE-2026-114403", "PHPOffice PHPPresentation through 1.2.0 contains an insecure deserialization vulnerability", "php"),
        ("CVE-2026-111756", "follow-redirects is a Node.js HTTP and HTTPS client wrapper that automatically follows redirects. From version 1.16.0", "node.js"),
        ("CVE-2026-115570", "Electron is a framework for writing cross-platform desktop applications using JavaScript, HTML and CSS. Prior to 42.11.16, Node.js", "node.js"),
        ("CVE-2026-115895", "Happy DOM is a JavaScript implementation of a web browser without its graphical user interface.", "node.js"),
        ("CVE-2026-114636", "Traefik v3.7.13 before v3.7.14 contains an access-control bypass in the Kubernetes Ingress NGINX provider, where the HTTP router", "nginx"),
        ("CVE-2026-114640", "Traefik from v3.7.0 before v3.7.14 contains an authentication bypass vulnerability in its Kubernetes Ingress-NGINX provider", "nginx"),
        ("CVE-2026-113812", "Mozilla::CA versions before 20261020 for Perl provide a CA certificate bundle containing a root linked to compromised", "openssl"),
        ("CVE-2026-96639", "Pillow is a Python imaging library. From 11.0.0 until 13.0.0, multi-frame loaders can retain an ImagingCore", "python"),
        ("CVE-2026-115775", "Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, the parser", "python"),
        ("CVE-2026-115572", "pypdf is a free and open-source pure-python PDF library. Prior to 6.21.2, an attacker can craft a PDF", "python"),
        ("CVE-2026-57845", "Hugging Face Datasets through 5.1.0 contains an insecure deserialization vulnerability that allows attackers to execute arbitrary Python code", "python"),
        ("CVE-2026-115727", "AgenticSeek before commit 409840c contains a remote code execution vulnerability because llm_server/app.py hardcodes Flask debug mode", "python"),
        ("CVE-2026-89312", "`AesGcmCryptor.Open` passed a caller-supplied nonce straight to `cipher.AEAD.Open` without checking its length in a Go library", "go"),
    ]

    def test_runtime_bugs_are_about_the_runtime(self):
        for cve, text, product in self.ABOUT:
            self.assertIn(product, WATCH.about(text), "%s should be about %s" % (cve, product))

    def test_apps_that_merely_mention_a_runtime_are_not(self):
        for cve, text, product in self.NOT_ABOUT:
            self.assertNotIn(product, WATCH.about(text), "%s is not about %s" % (cve, product))

    def test_php2shell_cves_raise_alerts(self):
        """The first version of the filter missed CVE-2026-109618 itself. This must never regress."""
        def vuln(cid, desc):
            return {"cve": {"id": cid, "published": "2026-10-21T10:00:00.000", "descriptions": [{"lang": "en", "value": desc}],
                            "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 9.2, "baseSeverity": "CRITICAL"}}]}}}
        payload = {"totalResults": 2, "vulnerabilities": [vuln(c, t) for c, t, _p in self.ABOUT[:2]]}
        r = m.src_nvd(FakeNet({"nvd.nist.gov": payload}), NOW, 96, WATCH)
        self.assertEqual({i["id"]: i["alert"] for i in r["items"]}, {"CVE-2026-109618": True, "CVE-2026-109619": True})
        self.assertEqual(r["items"][0]["watch"], ["php"])

    def test_nvd_lists_about_and_counts_mention_only(self):
        def vuln(cid, desc, score):
            return {"cve": {"id": cid, "published": "2026-10-24T01:00:00.000", "descriptions": [{"lang": "en", "value": desc}],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]}}}
        payload = {"totalResults": 3, "vulnerabilities": [
            vuln("CVE-2026-4001", self.ABOUT[2][1], 7.4),
            vuln("CVE-2026-4002", self.NOT_ABOUT[0][1], 8.8),
            vuln("CVE-2026-4003", self.NOT_ABOUT[18][1], 8.7)]}
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

    def test_bad_extra_pattern_fails_loudly(self):
        path = os.path.join(tempfile.mkdtemp(), "w.tsv")
        with open(path, "w") as fh:
            fh.write("x\tfoo\t-\t(unclosed\n")
        with self.assertRaises(Exception):
            m.load_watchlist(path)


class ClassificationNewProducts(unittest.TestCase):
    """Java, Docker, Kubernetes and WordPress core.

    REAL = description copied from the live NVD run of 2026-10-24.
    REPRESENTATIVE = standard vendor phrasing written from memory (none of these products had such a CVE in that run);
    the first live reports are the real check for them.
    """

    ABOUT = [
        ("REAL", "java", "Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE)."),
        ("REPRESENTATIVE", "java", "In OpenJDK before 21.0.6, a flaw in the HotSpot compiler allows a heap overflow"),
        ("REPRESENTATIVE", "docker", "Docker Desktop before 4.34.3 allows a local user to escalate privileges"),
        ("REPRESENTATIVE", "docker", "Moby is an open-source project created by Docker to enable software containerization. Prior to 27.1.1 a flaw allows"),
        ("REPRESENTATIVE", "docker", "runc is a CLI tool for spawning and running containers according to the OCI specification. In runc 1.1.11 and earlier"),
        ("REPRESENTATIVE", "docker", "containerd is an open-source container runtime. Prior to 1.7.13 a flaw allows"),
        ("REPRESENTATIVE", "kubernetes", "A security issue was discovered in Kubernetes where a user that can create pods on Windows nodes may escalate to admin"),
        ("REPRESENTATIVE", "kubernetes", "A security issue was discovered in kube-apiserver that could allow a user to bypass admission"),
        ("REPRESENTATIVE", "kubernetes", "Kubernetes before 1.30.2 allows an attacker to read secrets"),
        ("REPRESENTATIVE", "wordpress-core", "WordPress before 6.8.3 allows a remote attacker to run arbitrary script via the block editor"),
        ("REPRESENTATIVE", "wordpress-core", "WordPress Core is vulnerable to Stored Cross-Site Scripting in versions up to, and including, 6.8.2"),
    ]
    NOT_ABOUT = [
        ("REAL", "kubernetes", "A Kubernetes tenant with create permission on Console custom resources can set spec.containers.api.spec.image to an arbitrary container image. The operator deploys"),
        ("REAL", "kubernetes", "Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. From 2.7.0 until 2.13.1 a flaw allows"),
        ("REAL", "kubernetes", "Traefik v3.7.13 before v3.7.14 contains an access-control bypass in the Kubernetes Ingress NGINX provider"),
        ("REAL", "kubernetes", "Lagoon is an application delivery platform for Kubernetes. Versions prior to 2.33.1 have a"),
        ("REAL", "kubernetes", "Missing authentication for critical function in Azure Kubernetes Configuration Service allows an attacker"),
        ("REAL", "wordpress-core", "Issuu Panel plugin for WordPress before 1.6.6 contains a PHP file inclusion vulnerability that allows"),
        ("REAL", "docker", "Part-DB is an open source inventory management system for electronic components. Prior to version 2.12.1, the upload handler in the Docker image"),
        ("REAL", "docker", "Trigger.dev before 4.5.6 self-hosted Docker Compose deployments using the default secrets allow"),
        ("REAL", "java", "CGM CLININET is vulnerable to Remote Code Execution caused by deserialization of untrusted data in Java"),
        ("REPRESENTATIVE", "docker", "A Docker image of Acme Server before 3.1 ships with a default admin password"),
        ("REPRESENTATIVE", "java", "Acme Library is a Java library for parsing XML. Prior to 2.3.1 an XXE flaw allows"),
        ("REPRESENTATIVE", "wordpress-core", "The Foo Gallery plugin for WordPress is vulnerable to Stored Cross-Site Scripting in all versions up to 1.2.3"),
        ("REPRESENTATIVE", "wordpress-core", "WordPress Popular Posts plugin before 7.0 allows SQL injection"),
        ("REPRESENTATIVE", "kubernetes", "A Kubernetes operator for Foo Database before 1.2 grants excessive RBAC"),
    ]

    def test_products_are_loaded(self):
        names = [r[0] for r in WATCH.rows]
        for product in ("java", "docker", "kubernetes", "wordpress-core"):
            self.assertIn(product, names)

    def test_about(self):
        for kind, product, text in self.ABOUT:
            self.assertIn(product, WATCH.about(text), "%s: should be about %s: %s" % (kind, product, text[:70]))

    def test_not_about(self):
        for kind, product, text in self.NOT_ABOUT:
            self.assertNotIn(product, WATCH.about(text), "%s: must not be about %s: %s" % (kind, product, text[:70]))

    def test_mentions_are_still_counted_as_mentions(self):
        self.assertIn("kubernetes", WATCH.match("Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes."))
        self.assertIn("docker", WATCH.match("self-hosted Docker Compose deployments"))

    def test_deny_vetoes_the_vendor_field_too(self):
        self.assertEqual(WATCH.match_field("Docker Docker Engine"), ["docker"])
        self.assertEqual(WATCH.match_field("Acme Docker image"), [])

    def test_kev_java_and_docker_by_vendor_product(self):
        net = FakeNet({"known_exploited": kev(
            kev_entry("CVE-2026-6001", "2026-10-24", "Oracle", "Java SE", "Java SE Unspecified Vulnerability", "x"),
            kev_entry("CVE-2026-6002", "2026-10-24", "Docker", "Docker Engine", "Docker Engine Authz Bypass", "x"),
            kev_entry("CVE-2026-6003", "2026-10-24", "Acme", "Shop", "Shop RCE", "Runs inside a Docker image"))})
        by = {i["id"]: i for i in m.src_kev(net, NOW, 24, WATCH)["items"]}
        self.assertEqual(by["CVE-2026-6001"]["watch"], ["java"])
        self.assertEqual(by["CVE-2026-6002"]["watch"], ["docker"])
        self.assertFalse(by["CVE-2026-6003"]["alert"])

    def test_old_four_column_watchlist_still_loads(self):
        path = os.path.join(tempfile.mkdtemp(), "w.tsv")
        with open(path, "w") as fh:
            fh.write("foo\tfoo\t-\t-\n")
        self.addCleanup(os.remove, path)
        self.assertEqual(m.load_watchlist(path).about("A flaw in foo allows"), ["foo"])

    def test_bad_deny_pattern_fails_loudly(self):
        path = os.path.join(tempfile.mkdtemp(), "w.tsv")
        with open(path, "w") as fh:
            fh.write("x\tfoo\t-\t-\t(unclosed\n")
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
