#!/usr/bin/env python3
"""Propose a weekly review of advisories.tsv. Python 3.9+, standard library only.

Compares the newest upstream release of every tracked branch (php.net, go.dev, nodejs.org) with what a person has
reviewed in advisories.tsv, and writes a pull-request body plus, with --write, an updated advisories.tsv.

Rules this script keeps:
  * It only advances '#@ reviewed' lines. It never edits a fixed version, never invents an advisory id and never
    touches the vulnerability rows: writing a rule needs a person who has read the advisory.
  * A Node.js release that the official index flags as a security release is NEVER marked reviewed. It is listed as
    "needs a rule" and the daily REVIEW alert keeps firing until a person adds the rows.
  * php.net and go.dev publish no security flag. Those releases are proposed with a link and an explicit
    "read the notes" instruction; merging the pull request is the person's statement that they did.
  * A source that fails is reported and exits 3. A failed source is never treated as "nothing new".

Exit codes: 0 ok | 2 usage or configuration error | 3 at least one source failed
"""
import argparse
import datetime as dt
import json
import os
import re
import sys

import monitor as m

NOTES_URL = {
    "php": "https://www.php.net/ChangeLog-8.php",
    "go": "https://go.dev/doc/devel/release",
    "node": "https://nodejs.org/en/blog/vulnerability",
}
VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,2}$")
BRANCH_RE = re.compile(r"^\d+(?:\.\d+)?$")
UPDATED_RE = re.compile(r"^#@ updated .*$")


def _known_branches(fixed, runtime):
    return sorted({br for (rt, br) in fixed if rt == runtime}, key=m.vtuple)


def plan(fixed, reviewed, upstream, node_releases, usable):
    """Return {"bumps": [...], "security": [...], "new_branches": [...]} for the runtimes in `usable`."""
    out = {"bumps": [], "security": [], "new_branches": []}
    for (rt, br), fixed_ver in sorted(fixed.items(), key=lambda kv: (kv[0][0], m.vtuple(kv[0][1]))):
        up = upstream.get((rt, br))
        if rt not in usable or up is None or not VERSION_RE.match(up):
            continue
        covered = reviewed.get((rt, br))
        covered = covered if covered and m.vcmp(covered, fixed_ver) > 0 else fixed_ver
        if m.vcmp(up, covered) <= 0:
            continue
        item = {"runtime": rt, "branch": br, "covered": covered, "upstream": up, "url": NOTES_URL[rt]}
        if rt == "node":
            sec = [r["version"] for r in node_releases.get(br, [])
                   if r["security"] and VERSION_RE.match(r["version"]) and m.vcmp(r["version"], covered) > 0 and m.vcmp(r["version"], up) <= 0]
            if sec:
                item["security_versions"] = sorted(sec, key=m.vtuple)
                out["security"].append(item)
                continue
            item["url"] = "https://github.com/nodejs/node/releases/tag/v%s" % up
            item["flag"] = "nodejs.org marks no release between %s and %s as a security release" % (covered, up)
        else:
            item["flag"] = "%s publishes no security flag: read the release notes" % ("php.net" if rt == "php" else "go.dev")
        out["bumps"].append(item)
    for rt, parse in (("node", int), ("go", m.vtuple)):
        known = _known_branches(fixed, rt)
        if rt not in usable or not known:
            continue
        top = max(parse(b) for b in known)
        for (r, br), up in sorted(upstream.items(), key=lambda kv: kv[0]):
            if r == rt and BRANCH_RE.match(br) and VERSION_RE.match(up) and parse(br) > top:
                out["new_branches"].append({"runtime": rt, "branch": br, "upstream": up, "url": NOTES_URL[rt]})
    return out


def apply_bumps(text, bumps, today):
    """Advance or insert '#@ reviewed' lines and refresh '#@ updated'. Everything else is left byte-for-byte."""
    lines = text.split("\n")
    for b in bumps:
        new = "#@ reviewed %s %s %s %s" % (b["runtime"], b["branch"], b["upstream"], today)
        prefix = "#@ reviewed %s %s " % (b["runtime"], b["branch"])
        for i, line in enumerate(lines):
            if line.startswith(prefix):
                lines[i] = new
                break
        else:
            at = next((i for i, line in enumerate(lines) if UPDATED_RE.match(line)), 0)
            lines.insert(at + 1, new)
    for i, line in enumerate(lines):
        if UPDATED_RE.match(line):
            lines[i] = "#@ updated %s" % today
            break
    return "\n".join(lines)


def render_body(pl, today, data_file, failed):
    L = ["# Advisory data review %s" % today, "",
         "Opened automatically by the weekly `data-review` workflow from `%s`. **Nothing here is merged automatically.**" % data_file, ""]
    if failed:
        L += ["> **Incomplete:** these sources failed, so nothing was proposed for them: %s." % ", ".join(sorted(failed)), ""]
    if pl["security"]:
        L += ["## Needs a rule: Node.js security releases (NOT part of this diff)", "",
              "nodejs.org flags these as security releases. Read the advisory, then add rows to `advisories.tsv` (see CONTRIBUTING.md).",
              "Until then the daily report keeps raising a REVIEW alert for them, which is the intended behaviour.", ""]
        for it in pl["security"]:
            L.append("- node %s: security release(s) %s after %s (latest %s) - [advisories](%s)" % (
                it["branch"], ", ".join(it["security_versions"]), it["covered"], it["upstream"], it["url"]))
        L.append("")
    if pl["bumps"]:
        L += ["## Proposed: mark as reviewed", "",
              "**Merging this pull request is your statement that you read the notes for each line below and found no security fix that needs a row.**",
              "If a release does fix a security bug, do not merge: add the rows first (or remove that line from the diff).", "",
              "| Runtime | Branch | Reviewed up to | Newest upstream | What the source says | Notes |", "|---|---|---|---|---|---|"]
        for it in pl["bumps"]:
            L.append("| %s | %s | %s | %s | %s | [read](%s) |" % (it["runtime"], it["branch"], it["covered"], it["upstream"], it["flag"], it["url"]))
        L.append("")
    if pl["new_branches"]:
        L += ["## Needs a human: new upstream branches with no rule", "",
              "Not touched by this diff. Until a rule exists the checker falls back to the 'newer' row for these.", ""]
        for it in pl["new_branches"]:
            L.append("- %s %s (latest %s) - [notes](%s)" % (it["runtime"], it["branch"], it["upstream"], it["url"]))
        L.append("")
    if not (pl["security"] or pl["bumps"] or pl["new_branches"]):
        L += ["Nothing to review: every tracked branch is reviewed up to its newest upstream release.", ""]
    L += ["---", "_Generated by `monitor/propose.py`. Versions come from php.net, go.dev and nodejs.org; each is validated as a plain version number before use._", ""]
    return "\n".join(L)


def main(argv=None, net=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--advisories", default=os.path.join(here, "..", "advisories.tsv"))
    ap.add_argument("--out", required=True, help="directory for body.md and summary.json")
    ap.add_argument("--write", action="store_true", help="also update the advisories file in place")
    ap.add_argument("--today", help="override today's date (YYYY-MM-DD), for tests")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    today = a.today or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", today):
        print("propose: bad --today", file=sys.stderr)
        return 2
    try:
        fixed = m.load_rules(a.advisories)
        reviewed = m.load_reviewed(a.advisories)
        with open(a.advisories, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        print("propose: cannot read %s: %s" % (a.advisories, e), file=sys.stderr)
        return 2
    net = net or m.Net()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    upstream, node_releases, usable, failed = {}, {}, set(), []
    branches = _known_branches(fixed, "php")
    for name, fn in (("node", m.src_node), ("go", m.src_go), ("php", m.src_php)):
        try:
            res = fn(net, now, 24, branches=branches)
        except m.SourceError as e:
            failed.append(name)
            print("propose: %s failed: %s" % (name, e), file=sys.stderr)
            continue
        except (KeyError, TypeError, ValueError, IndexError) as e:
            failed.append(name)
            print("propose: %s unexpected response shape (%s: %s)" % (name, type(e).__name__, e), file=sys.stderr)
            continue
        usable.add(name)
        upstream.update(res.get("upstream", {}))
        node_releases.update(res.get("releases", {}))
    pl = plan(fixed, reviewed, upstream, node_releases, usable)
    os.makedirs(a.out, exist_ok=True)
    data_file = os.path.relpath(a.advisories, os.getcwd()) if os.path.isabs(a.advisories) else a.advisories
    with open(os.path.join(a.out, "body.md"), "w", encoding="utf-8") as fh:
        fh.write(render_body(pl, today, data_file.replace(os.sep, "/"), failed))
    changed = False
    if pl["bumps"]:
        new_text = apply_bumps(text, pl["bumps"], today)
        changed = new_text != text
        if a.write and changed:
            with open(a.advisories, "w", encoding="utf-8") as fh:
                fh.write(new_text)
    title = "Advisory data review %s: %d to mark reviewed, %d need a rule" % (today, len(pl["bumps"]), len(pl["security"]) + len(pl["new_branches"]))
    summary = {"changed": changed, "has_security": bool(pl["security"] or pl["new_branches"]), "title": title, "failed": sorted(failed),
               "bumps": pl["bumps"], "security": pl["security"], "new_branches": pl["new_branches"]}
    with open(os.path.join(a.out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("propose: %d bump(s), %d security, %d new branch(es), %d source(s) failed" % (len(pl["bumps"]), len(pl["security"]), len(pl["new_branches"]), len(failed)))
    return 3 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
