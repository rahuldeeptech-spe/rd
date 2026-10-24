#!/usr/bin/env python3
"""patchcheck daily security monitor.

Pulls public security feeds, filters them to the last N hours, cross-checks the
fixed versions in advisories.tsv against what upstream actually ships, and writes a
markdown + JSON report. Python 3.9+, standard library only.

Rules this script keeps:
  * A source that fails is reported as FAILED. A report never says "nothing new" for a source
    that could not be read, and the exit code is 3 so the CI run is marked failed.
  * Everything that comes from a feed is untrusted: it is sanitised before it reaches markdown
    (no @mentions, no #refs, no live links) and only links to known hosts are emitted.
  * It never edits advisories.tsv. Differences are raised as REVIEW alerts for a human.

Exit codes: 0 ok | 2 usage error | 3 at least one source failed
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "patchcheck-monitor/1.0 (+https://github.com/rahuldeeptech-spe/rd)"
MAX_BYTES = 25 * 1024 * 1024
LIST_CAP = 25

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_URL = "https://api.github.com/advisories"
NODE_URL = "https://nodejs.org/dist/index.json"
GO_URL = "https://go.dev/dl/?mode=json"
PHP_URL = "https://www.php.net/releases/index.php?json&version="

ALL_SOURCES = ["kev", "nvd", "ghsa", "node", "go", "php"]
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
_CTRL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")
ZWSP = "​"


class SourceError(Exception):
    """A feed could not be fetched or did not look like we expected."""


# ---------------------------------------------------------------- helpers ----

def clean(text, limit=300):
    """Make untrusted feed text safe to put in markdown on a public repo."""
    t = _CTRL.sub("", str(text if text is not None else ""))
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) > limit:
        t = t[: limit - 1].rstrip() + "…"
    t = html.escape(t, quote=False)
    t = re.sub(r"([\\`*_\[\]()|!~])", r"\\\1", t)
    t = t.replace("@", "@" + ZWSP).replace("#", "#" + ZWSP)
    t = re.sub(r"(?i)\b(https?|ftp):(//)", lambda m: m.group(1) + ":" + ZWSP + m.group(2), t)
    return t


def parse_ts(value):
    """ISO-8601 (with Z, offset, fractions or none) -> aware UTC datetime."""
    s = str(value).strip().replace("Z", "+00:00")
    m = re.match(r"^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?)(\.\d+)?)?\s*([+-]\d{2}:?\d{2})?$", s)
    if not m:
        raise ValueError("bad timestamp: %r" % value)
    day, hms, _frac, off = m.groups()
    hms = hms or "00:00"
    if hms.count(":") == 1:
        hms += ":00"
    d = dt.datetime.fromisoformat("%sT%s" % (day, hms))
    if off:
        off = off if ":" in off else off[:3] + ":" + off[3:]
        sign = 1 if off[0] == "+" else -1
        hh, mm = int(off[1:3]), int(off[4:6])
        d = d - sign * dt.timedelta(hours=hh, minutes=mm)
    return d.replace(tzinfo=dt.timezone.utc)


def vtuple(v):
    parts = re.findall(r"\d+", str(v))
    if not parts:
        raise ValueError("bad version: %r" % v)
    return tuple(int(p) for p in parts)


def vcmp(a, b):
    ta, tb = vtuple(a), vtuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def safe_url(url, prefixes):
    return url if isinstance(url, str) and any(url.startswith(p) for p in prefixes) else ""


class Net:
    """HTTP GET -> parsed JSON, with retries. Replaced by a fake in tests."""

    def __init__(self, sleep=time.sleep):
        self.sleep = sleep

    def get(self, url, headers=None, retries=3):
        hdrs = {"User-Agent": UA, "Accept": "application/json"}
        hdrs.update(headers or {})
        last = None
        for attempt in range(1, retries + 1):
            try:
                req = urllib.request.Request(url, headers=hdrs)
                with urllib.request.urlopen(req, timeout=40) as resp:
                    raw = resp.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise SourceError("response larger than %d bytes" % MAX_BYTES)
                return json.loads(raw.decode("utf-8"))
            except urllib.error.HTTPError as e:
                last = "HTTP %s" % e.code
                if e.code not in (403, 408, 429, 500, 502, 503, 504):
                    break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last = "network error: %s" % getattr(e, "reason", e)
            except ValueError as e:
                raise SourceError("response is not valid JSON (%s)" % e)
            if attempt < retries:
                self.sleep(6 * attempt)
        raise SourceError("%s for %s" % (last, url.split("?")[0]))


# --------------------------------------------------------- config loading ----

# Words that may precede a product name when the product is the *subject* of a CVE description:
# "A flaw in Node.js ...", "In PHP versions ...", "A heap overflow in the PHP-FPM ...".
# An app names itself first ("PhpSpreadsheet is a PHP library", "Traefik v3 ...", "Part-DB is ..."),
# so its description has other words before the product name and is not about the product.
_LEAD_OK = frozenset(
    "a an the in of on at within affecting found discovered identified detected determined issue issues flaw flaws bug bugs "
    "vulnerability vulnerabilities weakness weaknesses problem problems was were is are there exists existed been has have "
    "heap stack buffer based overflow overflows underflow use after free integer memory leak out bounds read write double "
    "null pointer dereference race condition denial service remote code execution arbitrary information disclosure "
    "incomplete fix improper input validation security".split())


class Watch:
    """Products to watch.

    match(text): products the text *mentions*.
    about(text): products the text is *about* - the product is the subject of the description (see _LEAD_OK),
    or an optional per-product extra pattern matches. Only "about" hits raise alerts, so a WordPress plugin
    or a library that says "PHP" or "Python" does not look like a PHP or Python vulnerability.
    A per-product deny pattern vetoes both about() and match_field() for phrasings that look like the product
    but are not ("A Docker image of X ...").
    """

    def __init__(self, rows):
        self.rows = [tuple(r) + (None,) * (5 - len(r)) for r in rows]  # (name, keywords, ecosystems, extra, deny)
        self._kw, self._extra, self._deny = {}, {}, {}
        for name, kws, _eco, extra, deny in self.rows:
            if kws:
                self._kw[name] = re.compile(r"(?<![\w.])(?:%s)(?!\w)" % "|".join(re.escape(k) for k in kws), re.I)
            if extra:
                self._extra[name] = re.compile(extra, re.I)
            if deny:
                self._deny[name] = re.compile(deny, re.I)

    @property
    def ecosystems(self):
        return sorted({e for _n, _k, es, _x, _d in self.rows for e in es})

    def _denied(self, name, text):
        return name in self._deny and bool(self._deny[name].search(text))

    def match(self, text):
        return [n for n, rx in self._kw.items() if rx.search(text or "")]

    def match_field(self, text):
        """Products named in a structured field (CISA vendor/product): a keyword hit counts, minus denials."""
        text = text or ""
        return [n for n in self.match(text) if not self._denied(n, text)]

    def about(self, text):
        text = text or ""
        out = []
        for name, _kws, _eco, _x, _d in self.rows:
            if self._denied(name, text):
                continue
            rx = self._kw.get(name)
            m = rx.search(text) if rx else None
            subject = bool(m) and m.start() <= 60 and all(w in _LEAD_OK for w in re.findall(r"[a-z]+", text[: m.start()].lower()))
            extra = name in self._extra and bool(self._extra[name].search(text))
            if subject or extra:
                out.append(name)
        return out


def _dash(value):
    value = (value or "").strip()
    return None if value in ("", "-") else value


def _split(value):
    return [v.strip() for v in (value or "").split(",") if v.strip() and v.strip() != "-"]


def load_watchlist(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            f = line.split("\t") + [""] * 5
            if len(line.split("\t")) < 3:
                continue
            extra, deny = _dash(f[3]), _dash(f[4])
            for pattern in (extra, deny):
                if pattern:
                    re.compile(pattern)  # a bad pattern should fail loudly at start-up, not hide alerts
            rows.append((f[0], _split(f[1]), _split(f[2]), extra, deny))
    return Watch(rows)


def load_rules(path):
    """advisories.tsv -> {(runtime, branch): fixed_version} for status=fixed rows."""
    fixed = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            f = line.split("\t")
            if len(f) >= 7 and f[2] == "fixed" and f[3] != "-":
                fixed[(f[0], f[1])] = f[3]
    return fixed


REVIEWED_RE = re.compile(r"^#@ reviewed (php|node|go) (\d+(?:\.\d+)?) (\d+\.\d+(?:\.\d+)?) (\d{4}-\d{2}-\d{2})\s*$")


def load_reviewed(path):
    """advisories.tsv '#@ reviewed <runtime> <branch> <version> <date>' lines -> {(runtime, branch): version}.

    A reviewed line records that a person read the release notes up to <version> and found no new security fix that
    needs a rule. It silences the REVIEW alert up to that version and never changes what patchcheck reports."""
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            hit = REVIEWED_RE.match(line.rstrip("\r\n"))
            if hit:
                out[(hit.group(1), hit.group(2))] = hit.group(3)
    return out


# ---------------------------------------------------------------- sources ----

def src_kev(net, now, hours, watch, **_):
    data = net.get(KEV_URL)
    vulns = data["vulnerabilities"]
    since = (now - dt.timedelta(hours=hours)).date()
    items = []
    for v in vulns:
        added = dt.date.fromisoformat(v["dateAdded"])
        cve = str(v["cveID"])
        if added < since or not CVE_RE.match(cve):
            continue
        text = " ".join(str(v.get(k, "")) for k in ("vendorProject", "product", "vulnerabilityName", "shortDescription"))
        hit = sorted(set(watch.match_field("%s %s" % (v.get("vendorProject", ""), v.get("product", "")))) | set(watch.about(text)))
        items.append({
            "source": "kev", "id": cve, "date": v["dateAdded"],
            "title": "%s %s - %s" % (v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", "")),
            "detail": v.get("shortDescription", ""),
            "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "due": v.get("dueDate", ""),
            "url": "https://nvd.nist.gov/vuln/detail/" + cve,
            "watch": hit, "alert": bool(hit),
        })
    items.sort(key=lambda i: (not i["alert"], i["id"]))
    return {"items": items, "note": "catalog %s" % data.get("catalogVersion", "?")}


def _cvss(cve):
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            d = m.get("cvssData") or {}
            if "baseScore" in d:
                return float(d["baseScore"]), str(d.get("baseSeverity") or m.get("baseSeverity") or "").upper()
    return None, ""


def src_nvd(net, now, hours, watch, **_):
    start = now - dt.timedelta(hours=hours)
    fmt = lambda d: urllib.parse.quote(d.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"), safe="")
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    items, index, total, mention_only = [], 0, None, 0
    for _page in range(10):
        url = "%s?pubStartDate=%s&pubEndDate=%s&resultsPerPage=2000&startIndex=%d" % (NVD_URL, fmt(start), fmt(now), index)
        data = net.get(url, headers)
        vulns = data["vulnerabilities"]
        total = int(data["totalResults"])
        for entry in vulns:
            cve = entry["cve"]
            cid = str(cve["id"])
            if not CVE_RE.match(cid):
                continue
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            score, sev = _cvss(cve)
            mentions = watch.match(desc)
            hit = watch.about(desc)
            if mentions and not hit and not (score is not None and score >= 9.0):
                mention_only += 1
            if (score is not None and score >= 9.0) or hit:
                items.append({
                    "source": "nvd", "id": cid, "date": str(cve.get("published", ""))[:10],
                    "title": desc, "score": score, "severity": sev or "UNSCORED",
                    "url": "https://nvd.nist.gov/vuln/detail/" + cid,
                    "watch": hit, "alert": bool(hit) and (score is None or score >= 7.0),
                })
        index += len(vulns)
        if not vulns or index >= total:
            break
    else:
        raise SourceError("NVD returned more than 10 pages")
    items.sort(key=lambda i: (not i["alert"], -(i["score"] or 0), i["id"]))
    note = "%d CVEs published in window; showing CRITICAL (9.0+) and CVEs about a watched product itself" % (total or 0)
    if mention_only:
        note += "; %d more only mention one (apps, plugins, libraries) and are not listed" % mention_only
    return {"items": items, "note": note}


def src_ghsa(net, now, hours, watch, **_):
    since = now - dt.timedelta(hours=hours)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    watched = set(watch.ecosystems)
    items = []
    for severity in ("critical", "high"):
        for page in range(1, 4):
            q = urllib.parse.urlencode({"type": "reviewed", "severity": severity, "per_page": 100, "page": page,
                                        "published": ">=" + since.strftime("%Y-%m-%d"), "sort": "published", "direction": "desc"})
            rows = net.get("%s?%s" % (GHSA_URL, q), headers)
            if not isinstance(rows, list):
                raise SourceError("advisories response is not a list")
            for a in rows:
                gid = str(a["ghsa_id"])
                if not GHSA_RE.match(gid) or parse_ts(a["published_at"]) < since:
                    continue
                pkgs = []
                for v in a.get("vulnerabilities") or []:
                    p = v.get("package") or {}
                    pkgs.append((str(p.get("ecosystem", "")).lower(), str(p.get("name", "")), str(v.get("first_patched_version") or "")))
                ecos = {e for e, _n, _f in pkgs}
                if severity == "high" and not (ecos & watched):
                    continue
                items.append({
                    "source": "ghsa", "id": gid, "cve": a.get("cve_id") or "", "date": str(a["published_at"])[:10],
                    "severity": severity.upper(), "title": a.get("summary", ""),
                    "packages": ["%s:%s%s" % (e, n, (" (fixed " + f + ")") if f else "") for e, n, f in pkgs][:4],
                    "url": safe_url(a.get("html_url"), ["https://github.com/advisories/"]),
                    "watch": [], "alert": False,
                })
            if len(rows) < 100:
                break
    items.sort(key=lambda i: (i["severity"] != "CRITICAL", i["id"]))
    return {"items": items, "note": "critical in all ecosystems; high only for %s" % (", ".join(sorted(watched)) or "none")}


def src_node(net, now, hours, **_):
    data = net.get(NODE_URL)
    if not isinstance(data, list):
        raise SourceError("node index is not a list")
    since = (now - dt.timedelta(hours=hours)).date()
    latest, recent = {}, []
    for e in data:
        ver = str(e["version"]).lstrip("v")
        major = ver.split(".")[0]
        if major not in latest:
            latest[major] = {"version": ver, "security": bool(e.get("security")), "date": e["date"]}
        if dt.date.fromisoformat(e["date"]) >= since:
            recent.append({"source": "node", "id": "node " + ver, "date": e["date"], "security": bool(e.get("security")),
                           "title": "Node.js %s released%s" % (ver, " (security release)" if e.get("security") else ""),
                           "url": "https://nodejs.org/en/blog/vulnerability", "watch": ["node.js"], "alert": False})
    upstream = {("node", m): v["version"] for m, v in latest.items()}
    flags = {("node", m): v["security"] for m, v in latest.items()}
    releases = {}
    for e in data:
        ver = str(e["version"]).lstrip("v")
        releases.setdefault(ver.split(".")[0], []).append({"version": ver, "date": e["date"], "security": bool(e.get("security"))})
    return {"items": recent, "upstream": upstream, "security_flags": flags, "releases": releases, "note": "%d versions in index" % len(data)}


def src_go(net, now, hours, **_):
    data = net.get(GO_URL)
    if not isinstance(data, list):
        raise SourceError("go download index is not a list")
    best = {}
    for r in data:
        m = re.match(r"^go(\d+\.\d+)(?:\.(\d+))?$", str(r["version"]))
        if not m or not r.get("stable"):
            continue
        ver = "%s.%s" % (m.group(1), m.group(2) or "0")
        if m.group(1) not in best or vcmp(ver, best[m.group(1)]) > 0:
            best[m.group(1)] = ver
    if not best:
        raise SourceError("no stable Go releases found in index")
    return {"items": [], "upstream": {("go", b): v for b, v in best.items()}, "note": "branches: " + ", ".join(sorted(best))}


def src_php(net, now, hours, branches=(), **_):
    upstream = {}
    for b in branches:
        d = net.get(PHP_URL + urllib.parse.quote(b))
        if isinstance(d, dict) and "version" in d:
            ver = str(d["version"])
        elif isinstance(d, dict) and d:
            ver = max((k for k in d if re.match(r"^\d+\.\d+\.\d+$", k)), key=vtuple, default="")
        else:
            ver = ""
        if not re.match(r"^%s\.\d+$" % re.escape(b), ver):
            raise SourceError("unexpected php.net response for branch %s" % b)
        upstream[("php", b)] = ver
    return {"items": [], "upstream": upstream, "note": "branches: " + ", ".join(branches)}


SOURCE_FUNCS = {"kev": src_kev, "nvd": src_nvd, "ghsa": src_ghsa, "node": src_node, "go": src_go, "php": src_php}
SOURCE_LABELS = {"kev": "CISA Known Exploited Vulnerabilities", "nvd": "NVD (new CVEs)", "ghsa": "GitHub Advisory Database",
                 "node": "nodejs.org release index", "go": "go.dev downloads", "php": "php.net releases"}


# ------------------------------------------------------------ consistency ----

def consistency(fixed, upstream, security_flags, source_ok, reviewed=None):
    """Compare advisories.tsv fixed versions with upstream's latest. Returns alert dicts.

    A person can mark newer upstream releases as read with a '#@ reviewed' line; that silences the REVIEW alert up to
    that version (a later release alerts again). CHECK DATA still compares against the real fixed version."""
    alerts = []
    reviewed = reviewed or {}

    def alert(rt, br, title):
        alerts.append({"source": "rules", "id": "%s %s" % (rt, br), "date": "", "alert": True, "watch": [rt], "url": "", "title": title})

    for (rt, br), fixed_ver in sorted(fixed.items()):
        if not source_ok.get(rt):
            continue
        up = upstream.get((rt, br))
        if up is None:
            continue
        if vcmp(up, fixed_ver) < 0:
            alert(rt, br, "CHECK DATA: advisories.tsv says %s %s is fixed at %s but upstream's latest is only %s. The rule may be wrong." % (rt, br, fixed_ver, up))
            continue
        covered = reviewed[(rt, br)] if vcmp(reviewed.get((rt, br), fixed_ver), fixed_ver) > 0 else fixed_ver
        c = vcmp(up, covered)
        if c > 0:
            sec = " and upstream marks it a security release" if security_flags.get((rt, br)) else ""
            alert(rt, br, "REVIEW: upstream %s %s is %s, advisories.tsv is reviewed up to %s%s. Read the release notes for new security fixes and update the rules." % (rt, br, up, covered, sec))
        elif c < 0:
            alert(rt, br, "CHECK DATA: the '#@ reviewed' line for %s %s says %s but upstream's latest is only %s. The line may be a typo." % (rt, br, covered, up))
    for rt, parse in (("node", lambda b: int(b)), ("go", lambda b: vtuple(b))):
        if not source_ok.get(rt):
            continue
        known = [parse(br) for (r, br) in fixed if r == rt]
        up_br = {br for (r, br) in upstream if r == rt}
        for br in sorted(up_br, key=parse):
            if known and parse(br) > max(known):
                alerts.append({"source": "rules", "id": "%s %s" % (rt, br), "date": "", "alert": True, "watch": [rt], "url": "",
                               "title": "REVIEW: new %s branch %s exists upstream but advisories.tsv has no rule for it (it falls back to the 'newer' rule)." % (rt, br)})
    return alerts


# ----------------------------------------------------------------- report ----

def run_all(net, now, hours, watch, fixed, sources, reviewed=None):
    results, statuses = {}, []
    branches = sorted({br for (rt, br) in fixed if rt == "php"}, key=vtuple)
    for name in sources:
        try:
            res = SOURCE_FUNCS[name](net, now, hours, watch=watch, branches=branches)
            results[name] = res
            statuses.append({"name": name, "label": SOURCE_LABELS[name], "ok": True, "count": len(res["items"]), "note": res.get("note", "")})
        except SourceError as e:
            statuses.append({"name": name, "label": SOURCE_LABELS[name], "ok": False, "count": 0, "note": str(e)})
        except (KeyError, TypeError, ValueError, IndexError) as e:
            statuses.append({"name": name, "label": SOURCE_LABELS[name], "ok": False, "count": 0,
                             "note": "unexpected response shape (%s: %s)" % (type(e).__name__, e)})
    upstream, flags = {}, {}
    for r in results.values():
        upstream.update(r.get("upstream", {}))
        flags.update(r.get("security_flags", {}))
    ok = {s["name"]: s["ok"] for s in statuses}
    cons = consistency(fixed, upstream, flags, ok, reviewed)
    return {"results": results, "statuses": statuses, "consistency": cons, "upstream": upstream}


def _bullet(i):
    bits = ["**%s**" % clean(i["id"], 60)]
    if i.get("score") is not None:
        bits.append("CVSS %.1f %s" % (i["score"], clean(i.get("severity", ""), 12)))
    elif i.get("severity"):
        bits.append(clean(i["severity"], 12))
    if i.get("ransomware"):
        bits.append("used in ransomware")
    line = " ".join(bits) + " - " + clean(i.get("title", ""), 220)
    if i.get("packages"):
        line += " (" + clean(", ".join(i["packages"]), 160) + ")"
    if i.get("watch"):
        line += " - **watching: %s**" % clean(", ".join(i["watch"]), 60)
    if i.get("url"):
        line += " - [source](%s)" % i["url"]
    return "- " + line


def _section(title, items, empty, failed, skipped=False):
    out = ["## %s" % title, ""]
    if skipped:
        return out + ["> **Not checked in this run.** Nothing can be concluded about this section.", ""]
    if failed:
        out += ["> **Source unavailable.** This section is incomplete. Do not read it as \"nothing happened\".", ""]
        return out
    if not items:
        return out + [empty, ""]
    out += [_bullet(i) for i in items[:LIST_CAP]]
    if len(items) > LIST_CAP:
        out.append("- ...and %d more (see the source)." % (len(items) - LIST_CAP))
    return out + [""]


def render(run, now, hours):
    st = {s["name"]: s for s in run["statuses"]}
    res = run["results"]
    failed = [s for s in run["statuses"] if not s["ok"]]
    alerts = [i for r in res.values() for i in r["items"] if i.get("alert")] + run["consistency"]
    L = ["# Security report %s" % now.strftime("%Y-%m-%d"), "",
         "Generated %s UTC by an automated job. Window: last %d hours. Not a substitute for the official vendor advisories." % (now.strftime("%Y-%m-%d %H:%M"), hours), ""]
    skipped = [n for n in ALL_SOURCES if n not in st]
    if failed or skipped:
        why = []
        if failed:
            why.append("%d source(s) failed: %s" % (len(failed), ", ".join(s["name"] for s in failed)))
        if skipped:
            why.append("not run: %s" % ", ".join(skipped))
        L += ["> **INCOMPLETE REPORT.** %s. Missing data is not the same as no incidents." % "; ".join(why), ""]
    L += ["## Needs attention (%d)" % len(alerts), ""]
    if alerts:
        L += [_bullet(i) for i in alerts[:LIST_CAP]]
    elif failed or skipped:
        L += ["Nothing flagged in the sources that were read. This report is incomplete (see the banner above)."]
    else:
        L += ["Nothing flagged for the watchlist or the tracked runtimes."]
    L += [""]
    def sec(title, name, empty):
        return _section(title, res.get(name, {}).get("items", []), empty, name in st and not st[name]["ok"], name not in st)
    L += sec("Actively exploited (CISA KEV, added in window)", "kev", "No new entries in the window.")
    L += sec("Critical new CVEs and CVEs about watched products (NVD)", "nvd", "No critical or watchlist CVEs published in the window.")
    L += sec("GitHub reviewed advisories (critical, plus high in watched ecosystems)", "ghsa", "No matching advisories in the window.")
    L += sec("Node.js releases in window", "node", "No Node.js release in the window.")
    L += ["## Tracked versions (upstream latest vs advisories.tsv)", ""]
    fx = run.get("fixed", {})
    ups = {}
    for (rt, br), v in run["upstream"].items():
        known = [vtuple(b) for (r, b) in fx if r == rt]
        if (rt, br) in fx or (known and vtuple(br) > max(known)):
            ups[(rt, br)] = v
    if ups:
        L += ["| Runtime | Branch | Upstream latest | advisories.tsv fixed | Reviewed up to |", "|---|---|---|---|---|"]
        for (rt, br), v in sorted(ups.items(), key=lambda kv: (kv[0][0], vtuple(kv[0][1]))):
            L.append("| %s | %s | %s | %s | %s |" % (rt, br, clean(v, 20), clean(run.get("fixed", {}).get((rt, br), "-"), 20),
                                                    clean(run.get("reviewed", {}).get((rt, br), "-"), 20)))
        L.append("")
    else:
        L += ["No upstream version data could be read.", ""]
    L += ["## Sources", "", "| Source | Status | Items | Note |", "|---|---|---|---|"]
    for s in run["statuses"]:
        L.append("| %s | %s | %d | %s |" % (clean(s["label"], 60), "OK" if s["ok"] else "**FAILED**", s["count"], clean(s["note"], 160)))
    L += ["", "## How to use this", "",
          "- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.",
          "- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.",
          "- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.", ""]
    return "\n".join(L), alerts


def to_json(run, now, hours, alerts):
    return {"generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "window_hours": hours, "complete": all(s["ok"] for s in run["statuses"]) and {s["name"] for s in run["statuses"]} == set(ALL_SOURCES),
            "sources": run["statuses"], "alerts": alerts,
            "items": {n: r["items"] for n, r in run["results"].items()},
            "upstream": {"%s %s" % k: v for k, v in sorted(run["upstream"].items())}}


def main(argv=None, net=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True, help="directory for report.md, report.json, alerts.md")
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--now", help="override the clock (ISO-8601 UTC), for tests")
    ap.add_argument("--sources", default=",".join(ALL_SOURCES), help="comma list of: " + ",".join(ALL_SOURCES))
    ap.add_argument("--watchlist", default=os.path.join(here, "watchlist.tsv"))
    ap.add_argument("--advisories", default=os.path.join(here, "..", "advisories.tsv"))
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    sources = [s for s in a.sources.split(",") if s]
    bad = [s for s in sources if s not in SOURCE_FUNCS]
    if bad or a.hours < 1 or a.hours > 24 * 14:
        print("monitor: bad --sources or --hours", file=sys.stderr)
        return 2
    now = parse_ts(a.now) if a.now else dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    try:
        watch = load_watchlist(a.watchlist)
        fixed = load_rules(a.advisories)
        reviewed = load_reviewed(a.advisories)
    except (OSError, re.error) as e:
        print("monitor: cannot load configuration: %s" % e, file=sys.stderr)
        return 2
    run = run_all(net or Net(), now, a.hours, watch, fixed, sources, reviewed)
    run["fixed"] = fixed
    run["reviewed"] = reviewed
    md, alerts = render(run, now, a.hours)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(md + "\n")
    with open(os.path.join(a.out, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(to_json(run, now, a.hours, alerts), fh, indent=2, sort_keys=True)
        fh.write("\n")
    alerts_path = os.path.join(a.out, "alerts.md")
    if alerts:
        with open(alerts_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(["Automated alert from the daily security job. Full report: see the `reports` branch.", ""] + [_bullet(i) for i in alerts[:LIST_CAP]]) + "\n")
    elif os.path.exists(alerts_path):
        os.remove(alerts_path)
    failed = [s["name"] for s in run["statuses"] if not s["ok"]]
    print("report: %d alert(s), %d source(s) failed%s" % (len(alerts), len(failed), (": " + ", ".join(failed)) if failed else ""))
    return 3 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
