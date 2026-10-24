"""Tests for propose.py. Run: python3 -m unittest discover -s monitor -v"""
import json
import os
import shutil
import tempfile
import unittest

import monitor as m
import propose as p
from test_monitor import FakeNet

HERE = os.path.dirname(os.path.abspath(__file__))
FIXED = {("php", "8.4"): "8.4.27", ("php", "8.3"): "8.3.36", ("node", "26"): "26.12.1", ("node", "24"): "24.22.1", ("go", "1.26"): "1.26.10"}
ALL = {"php", "node", "go"}
NODE = {  # newest first, like the real index
    "26": [{"version": "26.13.0", "date": "2026-11-04", "security": True}, {"version": "26.12.1", "date": "2026-10-21", "security": True}],
    "24": [{"version": "24.22.2", "date": "2026-11-04", "security": False}, {"version": "24.22.1", "date": "2026-10-20", "security": True}],
}
TEXT = """#@ updated 2026-10-24
# comment line that must survive
# runtime\tbranch\tstatus\tfixed\tid\tsource\tnote
php\t8.4\tfixed\t8.4.27\tCVE-X\thttps://example.test/\tnote
node\t24\tfixed\t24.22.1\tN-1\thttps://example.test/\tnote
"""


class Plan(unittest.TestCase):
    def test_nothing_new(self):
        up = {("php", "8.4"): "8.4.27", ("php", "8.3"): "8.3.36", ("node", "26"): "26.12.1", ("node", "24"): "24.22.1", ("go", "1.26"): "1.26.10"}
        pl = p.plan(FIXED, {}, up, NODE, ALL)
        self.assertEqual((pl["bumps"], pl["security"], pl["new_branches"]), ([], [], []))

    def test_php_ahead_is_a_bump_that_says_read_the_notes(self):
        pl = p.plan(FIXED, {}, {("php", "8.4"): "8.4.28"}, NODE, ALL)
        self.assertEqual([(b["runtime"], b["branch"], b["upstream"]) for b in pl["bumps"]], [("php", "8.4", "8.4.28")])
        self.assertIn("read the release notes", pl["bumps"][0]["flag"])
        self.assertEqual(pl["security"], [])

    def test_already_reviewed_is_quiet_and_the_next_release_is_not(self):
        self.assertEqual(p.plan(FIXED, {("php", "8.4"): "8.4.28"}, {("php", "8.4"): "8.4.28"}, NODE, ALL)["bumps"], [])
        self.assertEqual(len(p.plan(FIXED, {("php", "8.4"): "8.4.28"}, {("php", "8.4"): "8.4.29"}, NODE, ALL)["bumps"]), 1)

    def test_node_security_release_is_never_a_bump(self):
        pl = p.plan(FIXED, {}, {("node", "26"): "26.13.0"}, NODE, ALL)
        self.assertEqual(pl["bumps"], [])
        self.assertEqual(pl["security"][0]["security_versions"], ["26.13.0"])

    def test_node_non_security_release_is_a_bump_with_a_release_link(self):
        pl = p.plan(FIXED, {}, {("node", "24"): "24.22.2"}, NODE, ALL)
        self.assertEqual(pl["security"], [])
        self.assertEqual(pl["bumps"][0]["url"], "https://github.com/nodejs/node/releases/tag/v24.22.2")

    def test_old_security_releases_before_the_reviewed_point_are_ignored(self):
        pl = p.plan(FIXED, {("node", "26"): "26.13.0"}, {("node", "26"): "26.13.0"}, NODE, ALL)
        self.assertEqual((pl["bumps"], pl["security"]), ([], []))

    def test_security_release_in_the_middle_of_a_gap_still_blocks_the_bump(self):
        releases = {"24": [{"version": "24.23.0", "date": "d", "security": False}, {"version": "24.22.5", "date": "d", "security": True},
                           {"version": "24.22.2", "date": "d", "security": False}]}
        pl = p.plan(FIXED, {}, {("node", "24"): "24.23.0"}, releases, ALL)
        self.assertEqual(pl["bumps"], [])
        self.assertEqual(pl["security"][0]["security_versions"], ["24.22.5"])

    def test_unusable_source_proposes_nothing_for_that_runtime(self):
        pl = p.plan(FIXED, {}, {("php", "8.4"): "8.4.28", ("go", "1.26"): "1.26.11"}, NODE, {"go"})
        self.assertEqual([b["runtime"] for b in pl["bumps"]], ["go"])

    def test_new_branches(self):
        pl = p.plan(FIXED, {}, {("node", "27"): "27.0.0", ("go", "1.28"): "1.28.0", ("go", "1.26"): "1.26.10"}, NODE, ALL)
        self.assertEqual({(n["runtime"], n["branch"]) for n in pl["new_branches"]}, {("node", "27"), ("go", "1.28")})

    def test_hostile_version_strings_are_ignored(self):
        pl = p.plan(FIXED, {}, {("php", "8.4"): "8.4.28 [click](http://evil.example) @everyone"}, NODE, ALL)
        self.assertEqual(pl["bumps"], [])


class Apply(unittest.TestCase):
    BUMP = [{"runtime": "php", "branch": "8.4", "upstream": "8.4.28"}]

    def test_inserts_after_updated_and_leaves_everything_else_alone(self):
        out = p.apply_bumps(TEXT, self.BUMP, "2026-11-07")
        lines = out.split("\n")
        self.assertEqual(lines[0], "#@ updated 2026-11-07")
        self.assertEqual(lines[1], "#@ reviewed php 8.4 8.4.28 2026-11-07")
        self.assertEqual([l for l in lines if not l.startswith("#@")], [l for l in TEXT.split("\n") if not l.startswith("#@")])

    def test_replaces_an_existing_line_and_is_idempotent(self):
        once = p.apply_bumps(TEXT, self.BUMP, "2026-11-07")
        twice = p.apply_bumps(once, self.BUMP, "2026-11-07")
        self.assertEqual(once, twice)
        later = p.apply_bumps(once, [{"runtime": "php", "branch": "8.4", "upstream": "8.4.29"}], "2026-11-14")
        self.assertEqual(later.count("#@ reviewed php 8.4"), 1)
        self.assertIn("#@ reviewed php 8.4 8.4.29 2026-11-14", later)

    def test_the_result_still_loads_everywhere(self):
        out = p.apply_bumps(TEXT, self.BUMP, "2026-11-07")
        path = os.path.join(tempfile.mkdtemp(), "a.tsv")
        with open(path, "w") as fh:
            fh.write(out)
        self.addCleanup(shutil.rmtree, os.path.dirname(path), True)
        self.assertEqual(m.load_reviewed(path), {("php", "8.4"): "8.4.28"})
        self.assertEqual(m.load_rules(path)[("php", "8.4")], "8.4.27")  # the fixed version is untouched


class Body(unittest.TestCase):
    def test_body_separates_security_from_bumps_and_states_what_merging_means(self):
        pl = p.plan(FIXED, {}, {("node", "26"): "26.13.0", ("php", "8.4"): "8.4.28", ("go", "1.28"): "1.28.0"}, NODE, ALL)
        body = p.render_body(pl, "2026-11-07", "advisories.tsv", [])
        self.assertIn("Needs a rule: Node.js security releases (NOT part of this diff)", body)
        self.assertIn("Merging this pull request is your statement", body)
        self.assertIn("new upstream branches", body)
        self.assertLess(body.index("Needs a rule"), body.index("Proposed: mark as reviewed"))

    def test_failed_sources_are_named(self):
        self.assertIn("nothing was proposed for them: php", p.render_body(p.plan(FIXED, {}, {}, NODE, ALL), "2026-11-07", "advisories.tsv", ["php"]))

    def test_nothing_to_review_message(self):
        self.assertIn("Nothing to review", p.render_body(p.plan(FIXED, {}, {}, NODE, ALL), "2026-11-07", "advisories.tsv", []))


def routes(node=None, go=None, php=None):
    node = node if node is not None else [{"version": "v24.22.1", "date": "2026-10-20", "security": True}]
    go = go if go is not None else [{"version": "go1.26.10", "stable": True}]
    php = php or {"8.4": "8.4.27"}
    return {"nodejs.org": node, "go.dev": go, "php.net": lambda url: {"version": php[url.split("version=")[1]]}}


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.adv = os.path.join(self.dir, "adv.tsv")
        with open(self.adv, "w") as fh:
            fh.write("#@ updated 2026-10-24\nphp\t8.4\tfixed\t8.4.27\tC\thttps://example.test/\tn\nnode\t24\tfixed\t24.22.1\tN\thttps://example.test/\tn\n"
                     "go\t1.26\tfixed\t1.26.10\tG\thttps://example.test/\tn\n")
        self.out = os.path.join(self.dir, "out")

    def run_main(self, r, extra=()):
        rc = p.main(["--advisories", self.adv, "--out", self.out, "--today", "2026-11-07"] + list(extra), net=FakeNet(r))
        with open(os.path.join(self.out, "summary.json")) as fh:
            summary = json.load(fh)
        return rc, summary

    def adv_text(self):
        with open(self.adv) as fh:
            return fh.read()

    def test_nothing_new_changes_nothing(self):
        before = self.adv_text()
        rc, s = self.run_main(routes(), ["--write"])
        self.assertEqual((rc, s["changed"], s["has_security"]), (0, False, False))
        self.assertEqual(self.adv_text(), before)

    def test_php_bump_is_written_only_with_write(self):
        before = self.adv_text()
        rc, s = self.run_main(routes(php={"8.4": "8.4.28"}))
        self.assertEqual((rc, s["changed"]), (0, True))
        self.assertEqual(self.adv_text(), before)
        self.run_main(routes(php={"8.4": "8.4.28"}), ["--write"])
        self.assertIn("#@ reviewed php 8.4 8.4.28 2026-11-07", self.adv_text())

    def test_node_security_release_is_reported_but_not_written(self):
        node = [{"version": "v24.22.2", "date": "2026-11-04", "security": True}, {"version": "v24.22.1", "date": "2026-10-20", "security": True}]
        before = self.adv_text()
        rc, s = self.run_main(routes(node=node), ["--write"])
        self.assertEqual((rc, s["changed"], s["has_security"]), (0, False, True))
        self.assertEqual(self.adv_text(), before)
        with open(os.path.join(self.out, "body.md")) as fh:
            self.assertIn("security release(s) 24.22.2", fh.read())

    def test_a_failed_source_exits_3_and_proposes_nothing_for_it(self):
        r = routes(php={"8.4": "8.4.28"})
        r["php.net"] = m.SourceError("HTTP 503 for php.net")
        rc, s = self.run_main(r, ["--write"])
        self.assertEqual(rc, 3)
        self.assertEqual(s["failed"], ["php"])
        self.assertEqual(s["bumps"], [])
        self.assertNotIn("#@ reviewed", self.adv_text())

    def test_an_unexpected_response_shape_is_a_failed_source_not_a_crash(self):
        r = routes()
        r["go.dev"] = {"surprise": True}
        rc, s = self.run_main(r)
        self.assertEqual((rc, s["failed"]), (3, ["go"]))

    def test_usage_errors(self):
        self.assertEqual(p.main(["--out", self.out, "--advisories", os.path.join(self.dir, "missing.tsv")], net=FakeNet({})), 2)
        self.assertEqual(p.main(["--out", self.out, "--advisories", self.adv, "--today", "tomorrow"], net=FakeNet({})), 2)
        self.assertEqual(p.main([], net=FakeNet({})), 2)

    def test_the_demo_fixture_loads_and_has_something_to_review_against_real_versions(self):
        fx = os.path.join(HERE, "testdata", "demo-advisories.tsv")
        fixed = m.load_rules(fx)
        self.assertEqual(fixed[("php", "8.4")], "8.4.1")
        self.assertEqual(fixed[("node", "24")], "24.1.0")


if __name__ == "__main__":
    unittest.main()
