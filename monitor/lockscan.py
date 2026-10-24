#!/usr/bin/env python3
"""Scan dependency lock files for known vulnerabilities via OSV.dev. Python 3.9+, standard library only.

  python3 lockscan.py [--json] [--fail-on any|high|never] PATH...

PATH is a lock file or a directory (searched recursively, skipping node_modules, vendor and .git). Understands:
  package-lock.json (npm v1/v2/v3), composer.lock, go.mod, requirements.txt (only lines pinned with ==)
Only exact versions are looked up; a range such as "^1.2" is not a version and is skipped, and the skip is printed.

This sends package names and versions (nothing else) to https://api.osv.dev. The checker patchcheck.sh stays offline.
A lookup that fails is never reported as "clean": the run exits 3.

Exit codes: 0 nothing found | 1 vulnerabilities found (per --fail-on) | 2 usage / unreadable file | 3 lookup failed
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

OSV = "https://api.osv.dev/v1"
SKIP_DIRS = {"node_modules", "vendor", ".git"}
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
SEV_ORDER = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def clean(text, limit=160):
    text = _CTRL.sub(" ", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# ---- parsers: each returns (set of (ecosystem, name, version), list of skipped notes) ----

def parse_package_lock(text):
    data = json.loads(text)
    pkgs, skipped = set(), []
    if isinstance(data.get("packages"), dict):                      # lockfileVersion 2/3
        for path, meta in data["packages"].items():
            if not path or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            ver = meta.get("version")
            if name and isinstance(ver, str) and re.match(r"^\d", ver) and not meta.get("resolved", "").startswith(("file:", "git")):
                pkgs.add(("npm", name, ver))
    else:                                                           # lockfileVersion 1
        def walk(deps):
            for name, meta in (deps or {}).items():
                ver = meta.get("version", "")
                if re.match(r"^\d", ver):
                    pkgs.add(("npm", name, ver))
                else:
                    skipped.append("%s %s" % (name, ver))
                walk(meta.get("dependencies"))
        walk(data.get("dependencies"))
    return pkgs, skipped


def parse_composer_lock(text):
    data = json.loads(text)
    pkgs, skipped = set(), []
    for key in ("packages", "packages-dev"):
        for p in data.get(key) or []:
            name, ver = p.get("name"), str(p.get("version", "")).lstrip("v")
            if name and re.match(r"^\d+(\.\d+)*", ver) and not ver.startswith("dev-"):
                pkgs.add(("Packagist", name, ver))
            else:
                skipped.append("%s %s" % (name, p.get("version")))
    return pkgs, skipped


_GO_REQ = re.compile(r"^\s*(?:require\s+)?([^\s()]+)\s+(v\d[^\s]*)")


def parse_go_mod(text):
    pkgs, in_block = set(), False
    for line in text.splitlines():
        s = line.split("//")[0].strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if in_block or s.startswith("require "):
            m = _GO_REQ.match(s)
            if m:
                pkgs.add(("Go", m.group(1), m.group(2).lstrip("v")))
    return pkgs, []


def parse_requirements(text):
    pkgs, skipped = set(), []
    for line in text.splitlines():
        s = line.split("#")[0].split(";")[0].strip()
        if not s or s.startswith(("-", "git+", "http")):
            if s:
                skipped.append(s)
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([0-9][A-Za-z0-9.!+_-]*)$", s)
        if m:
            pkgs.add(("PyPI", re.sub(r"[-_.]+", "-", m.group(1)).lower(), m.group(2)))
        else:
            skipped.append(s)
    return pkgs, skipped


PARSERS = {"package-lock.json": parse_package_lock, "composer.lock": parse_composer_lock, "go.mod": parse_go_mod,
           "requirements.txt": parse_requirements}


def find_files(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                out += [os.path.join(root, f) for f in sorted(files) if f in PARSERS]
        elif os.path.isfile(p):
            if os.path.basename(p) not in PARSERS:
                raise OSError("not a supported file (%s): %s" % (", ".join(sorted(PARSERS)), p))
            out.append(p)
        else:
            raise OSError("no such file or directory: %s" % p)
    return out


# ---- OSV ----

class OSVError(Exception):
    pass


def _http(url, payload=None, timeout=30):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "patchcheck-lockscan"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise OSVError("%s: %s" % (url, type(e).__name__))


def query_batch(pkgs, http=_http):
    """pkgs: list of (eco, name, ver). Returns {pkg: [vuln ids]}."""
    found = {}
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i:i + 500]
        queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for (e, n, v) in chunk]
        pending = list(range(len(chunk)))
        for _ in range(20):                                         # follow pagination
            res = http(OSV + "/querybatch", {"queries": [queries[j] for j in pending]}).get("results")
            if not isinstance(res, list) or len(res) != len(pending):
                raise OSVError("unexpected querybatch response")
            nxt = []
            for j, r in zip(pending, res):
                key = chunk[j]
                found.setdefault(key, [])
                found[key] += [v["id"] for v in (r.get("vulns") or []) if isinstance(v, dict) and "id" in v]
                if r.get("next_page_token"):
                    queries[j] = dict(queries[j], page_token=r["next_page_token"])
                    nxt.append(j)
            if not nxt:
                break
            pending = nxt
        else:
            raise OSVError("too many result pages")
    return {k: sorted(set(v)) for k, v in found.items() if v}


def vuln_detail(vid, pkg, http=_http):
    d = http("%s/vulns/%s" % (OSV, vid))
    eco, name, _ = pkg
    fixed = []
    for aff in d.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("name") == name and p.get("ecosystem") == eco:
            for rng in aff.get("ranges") or []:
                fixed += [ev["fixed"] for ev in rng.get("events") or [] if "fixed" in ev]
    sev = str((d.get("database_specific") or {}).get("severity", "")).upper()
    cves = [a for a in d.get("aliases") or [] if str(a).startswith("CVE-")]
    return {"id": clean(vid, 40), "cves": [clean(c, 30) for c in cves[:3]], "summary": clean(d.get("summary", "")),
            "severity": sev if sev in SEV_ORDER else "UNKNOWN", "fixed": sorted({clean(f, 40) for f in fixed})}


def scan(paths, http=_http, out=sys.stdout):
    files = find_files(paths)
    pkgs, where, skipped = set(), {}, []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                got, sk = PARSERS[os.path.basename(f)](fh.read())
        except (OSError, ValueError, UnicodeDecodeError) as e:
            raise OSError("cannot read %s: %s" % (f, type(e).__name__))
        for p in got:
            where.setdefault(p, f)
        pkgs |= got
        skipped += ["%s: %s" % (f, s) for s in sk]
    pkgs_sorted = sorted(pkgs)
    hits = query_batch(pkgs_sorted, http)
    findings = []
    for pkg, ids in sorted(hits.items()):
        for vid in ids:
            d = vuln_detail(vid, pkg, http)
            d.update(ecosystem=pkg[0], package=clean(pkg[1], 80), version=clean(pkg[2], 40), file=where[pkg])
            findings.append(d)
    return {"files": files, "packages": len(pkgs_sorted), "skipped": skipped, "findings": findings}


def main(argv=None, http=_http):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=("any", "high", "never"), default="any")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        res = scan(a.paths, http)
    except OSError as e:
        print("lockscan: %s" % e, file=sys.stderr)
        return 2
    except OSVError as e:
        print("lockscan: lookup FAILED (%s). This is not a clean result." % e, file=sys.stderr)
        return 3
    if a.json:
        print(json.dumps(res, indent=2, sort_keys=True))
    else:
        print("lockscan: %d file(s), %d package version(s) checked against OSV.dev" % (len(res["files"]), res["packages"]))
        for s in res["skipped"]:
            print("  skipped (not an exact version): %s" % clean(s, 120))
        for f in res["findings"]:
            print("[%s] %s %s %s -> %s  %s %s" % (f["severity"], f["package"], f["version"], f["id"],
                  ",".join(f["fixed"]) or "no fix listed", ",".join(f["cves"]), f["summary"]))
        if not res["findings"]:
            print("lockscan: no known vulnerabilities in the exact versions found")
    bad = [f for f in res["findings"] if a.fail_on == "any" or (a.fail_on == "high" and SEV_ORDER.get(f["severity"], 0) >= 3)]
    if a.fail_on == "high" and any(f["severity"] == "UNKNOWN" for f in res["findings"]):
        bad = bad or [f for f in res["findings"] if f["severity"] == "UNKNOWN"]   # unknown severity is not "safe"
    return 1 if bad and a.fail_on != "never" else 0


if __name__ == "__main__":
    sys.exit(main())
