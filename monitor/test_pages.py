import json
import os
import tempfile
import unittest
import xml.dom.minidom

import pages as psite

EVIL = {"generated_at": "2026-10-24T10:00:00Z", "alerts": [
    {"id": "CVE-2026-1", "severity": "CRITICAL", "date": "2026-10-21", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
     "title": '<script>alert(1)</script> & "quotes" \x1b'},
    {"id": "CVE-2026-2", "severity": "HIGH", "date": "2026-10-21", "url": 'javascript:alert(1)', "title": "x"}]}


class Pages(unittest.TestCase):
    def test_html_escapes_untrusted_text_and_drops_bad_links(self):
        h = psite.render_index(EVIL, "o/r")
        self.assertNotIn("<script>alert", h)
        self.assertIn("&lt;script&gt;", h)
        self.assertNotIn("javascript:", h)
        self.assertIn('href="https://nvd.nist.gov/vuln/detail/CVE-2026-1"', h)
        self.assertNotIn("\x1b", h)

    def test_feed_is_well_formed_xml(self):
        f = psite.render_feed(EVIL, "o/r", "https://o.github.io/r/")
        xml.dom.minidom.parseString(f.encode("utf-8"))
        self.assertIn("urn:patchcheck:CVE-2026-1", f)
        self.assertNotIn("javascript:", f)

    def test_empty_report(self):
        h = psite.render_index({"alerts": []}, "o/r")
        self.assertIn("No alerts", h)
        xml.dom.minidom.parseString(psite.render_feed({"alerts": []}, "o/r", "https://o.github.io/r/").encode())

    def test_main_writes_files_and_validates_repo(self):
        d = tempfile.mkdtemp()
        rp = os.path.join(d, "r.json")
        json.dump(EVIL, open(rp, "w"))
        self.assertEqual(psite.main(["--report", rp, "--out", os.path.join(d, "s"), "--repo", "o/r"]), 0)
        self.assertTrue(os.path.exists(os.path.join(d, "s", "index.html")))
        self.assertTrue(os.path.exists(os.path.join(d, "s", "feed.xml")))
        self.assertEqual(psite.main(["--report", rp, "--out", d, "--repo", "bad repo"]), 2)
        self.assertEqual(psite.main(["--report", "/nope", "--out", d, "--repo", "o/r"]), 2)


if __name__ == "__main__":
    unittest.main()
