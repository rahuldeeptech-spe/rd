#!/usr/bin/env python3
"""Audit PHP settings that matter for security. Python 3.9+, standard library only. Read-only.

  python3 phpini.py                 # asks the php on PATH (php -r, ini_get_all)
  python3 phpini.py --php /usr/bin/php8.3
  python3 phpini.py --ini /etc/php/8.3/fpm/php.ini [--ini ...]

Important: the php CLI and php-fpm / Apache read DIFFERENT php.ini files. To audit what your website really uses, pass the
FPM or Apache file with --ini. A key a file does not mention is not judged (PHP's built-in default applies and cannot be seen from the file).

Exit codes: 0 nothing HIGH | 1 at least one HIGH finding | 2 usage or unreadable input | 3 php could not be run
"""
import argparse
import json
import re
import subprocess
import sys

# (key, bad-test, severity, advice)
def _on(v):
    return str(v).strip().lower() in ("1", "on", "true", "yes")


def _empty(v):
    return str(v).strip() == ""


RULES = [
    ("allow_url_include", _on, "HIGH", "set allow_url_include = Off (remote file inclusion becomes remote code execution)"),
    ("display_errors", lambda v: _on(v) or str(v).strip().lower() in ("stdout", "stderr"), "MEDIUM", "set display_errors = Off in production (error pages leak paths and queries)"),
    ("expose_php", _on, "LOW", "set expose_php = Off (removes the X-Powered-By version header)"),
    ("session.cookie_httponly", lambda v: not _on(v), "MEDIUM", "set session.cookie_httponly = 1 (JavaScript cannot read the session cookie)"),
    ("session.cookie_secure", lambda v: not _on(v), "MEDIUM", "set session.cookie_secure = 1 on HTTPS sites"),
    ("session.use_strict_mode", lambda v: not _on(v), "MEDIUM", "set session.use_strict_mode = 1 (blocks session fixation)"),
    ("allow_url_fopen", _on, "LOW", "set allow_url_fopen = Off if no code needs to open URLs as files"),
    ("disable_functions", _empty, "LOW", "list dangerous functions you never use (exec, system, passthru, shell_exec, proc_open, popen)"),
    ("open_basedir", _empty, "LOW", "set open_basedir to the site directory to limit what a compromised script can read"),
    ("cgi.fix_pathinfo", _on, "LOW", "with nginx + php-fpm set cgi.fix_pathinfo = 0 (path-info script execution tricks)"),
]
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def parse_ini(text):
    out = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in ";#[":
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            v = v.split(";")[0].strip().strip("\"'")
            out[k.strip()] = v
    return out


def settings_from_php(php, run=subprocess.run):
    try:
        r = run([php, "-r", "echo json_encode(ini_get_all(null, false));"], capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise OSError("%s: %s" % (php, type(e).__name__))
    if r.returncode != 0:
        raise OSError("%s exited with %d" % (php, r.returncode))
    try:
        data = json.loads(r.stdout)
    except ValueError:
        raise OSError("%s did not return settings" % php)
    if not isinstance(data, dict):
        raise OSError("%s did not return settings" % php)
    return {str(k): ("" if v is None else str(v)) for k, v in data.items()}


def audit(settings):
    findings = []
    for key, bad, sev, advice in RULES:
        if key not in settings:
            continue                          # a file that does not mention a key: PHP's default applies, unknown here
        if bad(settings[key]):
            findings.append((sev, key, _CTRL.sub(" ", settings[key])[:40], advice))
    return sorted(findings, key=lambda f: (ORDER[f[0]], f[1]))


def main(argv=None, run=subprocess.run):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--php", default="php")
    ap.add_argument("--ini", action="append", default=[], help="a php.ini file (repeatable)")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    sources = []
    if a.ini:
        for path in a.ini:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    sources.append((path, parse_ini(fh.read()), True))
            except OSError as e:
                print("phpini: cannot read %s: %s" % (path, type(e).__name__), file=sys.stderr)
                return 2
    else:
        try:
            sources.append((a.php, settings_from_php(a.php, run), False))
        except OSError as e:
            print("phpini: could not run php (%s). Nothing was audited." % e, file=sys.stderr)
            return 3
    high = 0
    for name, settings, explicit in sources:
        found = audit(settings)
        print("phpini: %s (%d setting(s) read)" % (name, len(settings)))
        if not found:
            print("  no risky setting found among the %d checked" % len(RULES))
        for sev, key, val, advice in found:
            print("  [%s] %s = %r - %s" % (sev, key, val, advice))
            high += sev == "HIGH"
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
