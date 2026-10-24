#!/usr/bin/env python3
"""Send the day's alerts to chat. Python 3.9+, standard library only.

Reads report.json (written by monitor.py) and posts one short digest to every channel whose secret is set:
  TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, DISCORD_WEBHOOK_URL, SLACK_WEBHOOK_URL
Channels without a secret are skipped. A channel that fails is reported and makes the exit code 3, so the workflow
run shows it; the other channels still get the message. Text from the feeds is untrusted: it is stripped of control
characters and cut to a fixed length, and only https links are used.

Exit codes: 0 sent (or nothing to send / no channel configured) | 2 usage | 3 at least one channel failed
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

MAX_ITEMS = 10
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean(text, limit):
    text = _CTRL.sub(" ", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def safe_url(url):
    url = str(url)
    return url if re.match(r"^https://[^\s<>\"']+$", url) else ""


def build_message(report, repo):
    alerts = report.get("alerts") or []
    if not alerts:
        return ""
    lines = ["Security alerts (%d)" % len(alerts)]
    for a in alerts[:MAX_ITEMS]:
        lines.append("- %s %s: %s %s" % (clean(a.get("severity", "?"), 12), clean(a.get("id", "?"), 40),
                                          clean(a.get("title", ""), 110), safe_url(a.get("url", ""))))
    if len(alerts) > MAX_ITEMS:
        lines.append("… and %d more" % (len(alerts) - MAX_ITEMS))
    if repo:
        lines.append("Report: https://github.com/%s/blob/reports/README.md" % clean(repo, 100))
    return "\n".join(lines)


def _post(url, payload, opener=None):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "patchcheck-notify"})
    with (opener or urllib.request.urlopen)(req, timeout=20) as resp:
        if not 200 <= resp.status < 300:
            raise OSError("HTTP %d" % resp.status)


def channels(env):
    out = []
    if env.get("TELEGRAM_BOT_TOKEN") and env.get("TELEGRAM_CHAT_ID"):
        out.append(("telegram", "https://api.telegram.org/bot%s/sendMessage" % env["TELEGRAM_BOT_TOKEN"],
                    lambda m: {"chat_id": env["TELEGRAM_CHAT_ID"], "text": m, "disable_web_page_preview": True}))
    if env.get("DISCORD_WEBHOOK_URL"):
        out.append(("discord", env["DISCORD_WEBHOOK_URL"], lambda m: {"content": m[:1900]}))
    if env.get("SLACK_WEBHOOK_URL"):
        out.append(("slack", env["SLACK_WEBHOOK_URL"], lambda m: {"text": m}))
    return out


def main(argv=None, env=None, post=_post):
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--report", required=True, help="path to report.json")
    ap.add_argument("--repo", default=env.get("GITHUB_REPOSITORY", ""), help="owner/name, for the report link")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        with open(a.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as e:
        print("notify: cannot read %s: %s" % (a.report, e), file=sys.stderr)
        return 2
    msg = build_message(report, a.repo)
    if not msg:
        print("notify: no alerts, nothing sent")
        return 0
    chans = channels(env)
    if not chans:
        print("notify: no channel configured (set TELEGRAM_*, DISCORD_WEBHOOK_URL or SLACK_WEBHOOK_URL), nothing sent")
        return 0
    failed = 0
    for name, url, shape in chans:
        try:
            post(url, shape(msg))
            print("notify: sent to %s" % name)
        except (OSError, urllib.error.URLError) as e:
            failed += 1
            print("notify: %s failed: %s" % (name, type(e).__name__), file=sys.stderr)   # never print the URL: it holds a secret
    return 3 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
