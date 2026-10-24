#!/usr/bin/env python3
"""Build a static site (index.html + feed.xml) from report.json. Python 3.9+, standard library only.

  python3 pages.py --report report.json --out site --repo owner/name

Everything that came from a feed (titles, ids, links) is HTML/XML-escaped, links must be https, and nothing is
loaded from outside the page (no scripts, no fonts, no images).
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import sys
from xml.sax.saxutils import escape as xml_escape

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(text, limit=300):
    text = _CTRL.sub(" ", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def safe_url(url):
    url = str(url)
    return url if re.match(r"^https://[^\s<>\"']+$", url) else ""


def render_index(report, repo):
    alerts = report.get("alerts") or []
    gen = clean(report.get("generated_at", ""), 40)
    rows = []
    for a in alerts:
        link = safe_url(a.get("url", ""))
        ident = html.escape(clean(a.get("id", "?"), 60))
        cell = '<a href="%s">%s</a>' % (html.escape(link, quote=True), ident) if link else ident
        rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            cell, html.escape(clean(a.get("severity", ""), 12)), html.escape(clean(a.get("date", ""), 12)),
            html.escape(clean(a.get("title", ""), 220))))
    body = "\n".join(rows) if rows else '<tr><td colspan="4">No alerts in this window.</td></tr>'
    repo_e = html.escape(clean(repo, 100))
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHP2Shell and Node2Shell security report - patchcheck</title>
<meta name="description" content="Daily free security report: PHP2Shell (CVE-2026-109618), Node2Shell (CVE-2026-111497), Go and Python Brotli alerts.">
<link rel="alternate" type="application/atom+xml" href="feed.xml" title="patchcheck alerts">
<style>:root{color-scheme:light dark}body{font:16px/1.5 system-ui,sans-serif;max-width:60rem;margin:0 auto;padding:1rem}
table{border-collapse:collapse;width:100%%}th,td{border-bottom:1px solid #8884;padding:.4rem;text-align:left;vertical-align:top}
@media(max-width:600px){td:nth-child(3){display:none}th:nth-child(3){display:none}}</style></head>
<body><h1>Security report</h1>
<p>Generated %(gen)s. <a href="feed.xml">Atom feed</a> · <a href="https://github.com/%(repo)s">Source and checker (patchcheck)</a>.
Check your own server: <code>curl -fsSLO https://github.com/%(repo)s/releases/latest/download/install.sh &amp;&amp; bash install.sh</code></p>
<table><thead><tr><th>ID</th><th>Severity</th><th>Date</th><th>What</th></tr></thead><tbody>
%(body)s
</tbody></table></body></html>
""" % {"gen": html.escape(gen), "repo": repo_e, "body": body}


def render_feed(report, repo, base):
    alerts = report.get("alerts") or []
    updated = clean(report.get("generated_at", ""), 40) or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = ['<?xml version="1.0" encoding="utf-8"?>', '<feed xmlns="http://www.w3.org/2005/Atom">',
           "<title>patchcheck security alerts</title>", '<id>%s</id>' % xml_escape(base),
           '<link href="%s" rel="self"/>' % xml_escape(base + "feed.xml", {'"': "&quot;"}),
           "<updated>%s</updated>" % xml_escape(updated)]
    for a in alerts:
        link = safe_url(a.get("url", ""))
        out.append("<entry><title>%s</title><id>%s</id>%s<updated>%s</updated><summary>%s</summary></entry>" % (
            xml_escape("%s %s" % (clean(a.get("id", "?"), 60), clean(a.get("severity", ""), 12))),
            xml_escape("urn:patchcheck:%s" % clean(a.get("id", "?"), 60)),
            '<link href="%s"/>' % xml_escape(link, {'"': "&quot;"}) if link else "",
            xml_escape(updated), xml_escape(clean(a.get("title", ""), 400))))
    out.append("</feed>")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--report", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo", required=True, help="owner/name")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", a.repo):
        print("pages: --repo must look like owner/name", file=sys.stderr)
        return 2
    try:
        with open(a.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as e:
        print("pages: cannot read %s: %s" % (a.report, e), file=sys.stderr)
        return 2
    owner, name = a.repo.split("/")
    base = "https://%s.github.io/%s/" % (owner.lower(), name)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(render_index(report, a.repo))
    with open(os.path.join(a.out, "feed.xml"), "w", encoding="utf-8") as fh:
        fh.write(render_feed(report, a.repo, base))
    print("pages: wrote index.html and feed.xml (%d alert(s))" % len(report.get("alerts") or []))
    return 0


if __name__ == "__main__":
    sys.exit(main())
