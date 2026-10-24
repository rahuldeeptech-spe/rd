#!/usr/bin/env python3
"""Check YOUR OWN website for files that should never be public. Python 3.9+, standard library only.

  python3 exposed.py https://example.com

Sends one GET per path in a fixed list (/.env, /.git/HEAD, /phpinfo.php, ...) and reports a path only when the response
body looks like the real thing (an .env file has KEY=value lines, .git/HEAD starts with "ref:", and so on), so a custom 404
page or a login redirect is not a finding. Redirects are not followed. At most 4 KB of each response is read and the content
is never printed, because it may hold secrets: only the path and what it looks like.

Only scan sites you own or are allowed to test. Requests are sequential, with a short pause.

Exit codes: 0 nothing exposed | 1 something exposed | 2 usage | 3 the site could not be reached
"""
import argparse
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CHECKS = [
    ("/.env", "environment file with KEY=value lines (passwords, API keys)", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}=.+")),
    ("/.env.local", "environment file with KEY=value lines", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}=.+")),
    ("/.env.production", "environment file with KEY=value lines", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}=.+")),
    ("/.git/HEAD", "git repository metadata (the whole source can be downloaded)", re.compile(r"^ref: refs/")),
    ("/.git/config", "git repository config", re.compile(r"(?m)^\[core\]")),
    ("/.svn/entries", "Subversion metadata", re.compile(r"(?m)^(dir|file)$")),
    ("/phpinfo.php", "phpinfo() page (versions, paths, environment)", re.compile(r"phpinfo\(\)|PHP Version")),
    ("/info.php", "phpinfo() page (versions, paths, environment)", re.compile(r"phpinfo\(\)|PHP Version")),
    ("/server-status", "Apache server-status page", re.compile(r"Apache Server Status")),
    ("/wp-config.php.bak", "WordPress config backup (database password)", re.compile(r"DB_PASSWORD|DB_NAME")),
    ("/wp-config.php~", "WordPress config backup (database password)", re.compile(r"DB_PASSWORD|DB_NAME")),
    ("/config.php.bak", "PHP config backup", re.compile(r"<\?php|password", re.I)),
    ("/.htpasswd", "password hashes", re.compile(r"(?m)^[^:\s]+:(\$|\{SHA\})")),
    ("/.aws/credentials", "AWS credentials", re.compile(r"aws_access_key_id", re.I)),
    ("/composer.lock", "dependency list (tells an attacker your exact versions)", re.compile(r'"packages"\s*:')),
    ("/package-lock.json", "dependency list (tells an attacker your exact versions)", re.compile(r'"lockfileVersion"')),
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, timeout=10, opener=None):
    """Return (status, first 4 KB as text) or raise OSError for a network problem. HTTP errors return their status."""
    op = opener or urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "patchcheck-exposed (self-check)", "Accept": "*/*"})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except urllib.error.URLError as e:
        raise OSError(type(e.reason).__name__ if getattr(e, "reason", None) else "URLError")


def scan(base, fetcher=fetch, pause=0.3):
    found, reached = [], 0
    last_err = ""
    for path, what, sig in CHECKS:
        try:
            status, body = fetcher(base.rstrip("/") + path)
            reached += 1
        except OSError as e:
            last_err = str(e)
            continue
        if status == 200 and sig.search(body):
            found.append((path, what))
        if pause:
            time.sleep(pause)
    if not reached:
        raise OSError(last_err or "no response")
    return found


def main(argv=None, fetcher=fetch, pause=0.3):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("url", help="site root, e.g. https://example.com (only sites you own)")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    u = urllib.parse.urlparse(a.url)
    if u.scheme not in ("http", "https") or not u.netloc or u.username or u.query or u.fragment:
        print("exposed: give a plain http(s) site address like https://example.com", file=sys.stderr)
        return 2
    base = "%s://%s%s" % (u.scheme, u.netloc, u.path.rstrip("/"))
    try:
        found = scan(base, fetcher, pause)
    except OSError as e:
        print("exposed: could not reach %s (%s). This is not a clean result." % (base, e), file=sys.stderr)
        return 3
    if not found:
        print("exposed: none of the %d known sensitive paths is publicly readable on %s" % (len(CHECKS), base))
        return 0
    for path, what in found:
        print("[EXPOSED] %s%s - %s" % (base, path, what))
    print("exposed: %d file(s) readable by anyone. Block them in the web server, remove them, and rotate any secret that was in them." % len(found))
    return 1


if __name__ == "__main__":
    sys.exit(main())
