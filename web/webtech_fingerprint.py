#!/usr/bin/env python3
"""
webtech_fingerprint.py

Wappalyzer-style technology/version fingerprinting tool for web app pentests.

Given a URL, this loads the page in a real (headless) browser and identifies
third-party JS/CSS libraries and their versions, then produces the three
pieces of evidence needed for the "[UNPATCHED/UNSUPPORTED SOFTWARE]" report
template stanza for each one:

  1. Source URL + excerpt   -- the file the version string was found in, and
                                the actual text snippet showing that version
                                (mirrors the "Version Reference" screenshot).
  2. Script/link tag        -- the exact <script src=...> or <link href=...>
                                tag in the page's HTML that caused that file
                                to be retrieved (mirrors the "Script Tag"
                                screenshot / live-use confirmation step),
                                plus the 1-indexed line number that tag
                                appears on in the page's HTML source, so a
                                remediator can jump straight to it instead of
                                searching the page source by hand.
  3. Support status         -- EOL/Unsupported (the release cycle itself is
                                EOL or unmaintained) or Unpatched/Outdated
                                (cycle still supported, but not the absolute
                                latest version of the product overall -- not
                                just the latest within its own cycle), via
                                the endoflife.date public API (only for
                                products confirmed to be tracked there --
                                see ENDOFLIFE_PRODUCT_SLUGS). Includes the
                                release date of the version in use (when
                                endoflife.date publishes one) and of the
                                absolute latest available version.

It also parses "<Product>/<Version>" tokens out of the Server and
X-Powered-By headers (e.g. "nginx/1.18.0", "Microsoft-IIS/10.0") and runs
those through the same endoflife.date check. IIS is a known exception:
it's reported but not auto-checked, since IIS's own version doesn't map 1:1
to a specific Windows Server release.

When a library's own bundled code links to its source repo (e.g. a
`source:"https://github.com/zloirock/core-js"` banner left in by the
bundler), the owner/repo is read directly out of that URL -- no slug-
guessing -- and cross-checked against the GitHub REST API for its release
history and any published GitHub Security Advisories. Only github.com is
actually queried; a gitlab.com/bitbucket.org link is still reported as a
lead for manual follow-up. This does NOT assign an EOL/Unpatched label the
way the endoflife.date check does -- GitHub has no formal support-lifecycle
concept, so the release dates/advisory list are presented as facts for the
tester to interpret, not an automated verdict.

A final cross-target summary (host / component / version / status /
absolute latest / detection method) prints after all targets finish, split
into two tables -- "Version Status Confirmed" (a real version comparison
completed, whether that's EOL/Unsupported, Unpatched/Outdated, Up-To-Date,
or a GitHub-heuristic equivalent) and "Version Status NOT Confirmed"
(nothing to check this component against at all) -- so it's immediately
clear which components still need a tester to determine patch/support
status manually.

After every run (unless --no-zip is passed), everything from this run --
a full transcript of the terminal output plus every per-host .json/.txt
file actually written -- is bundled into a single
webtech_fingerprint_results.zip in the output directory, so the whole
run's evidence can be handed off (e.g. to a downstream analysis skill) as
one file instead of a loose folder of outputs.

Detection methods, in order of reliability:
  - js-global:       reads a live runtime value, e.g. window.jQuery.fn.jquery,
                      window.React.version -- the same thing a tester checks
                      manually via devtools console.
  - content-banner:  license/comment header inside a fetched JS/CSS body,
                      e.g. "/*! jQuery v3.6.0 */".
  - path-version:    version embedded in the URL's directory structure,
                      e.g. /libs/jquery/3.6.0/jquery.min.js
  - query-version:   version embedded in a query string (WordPress-style
                      ?ver=X.Y.Z enqueueing).
  - vendor-chunk:    lower-confidence fallback for bundlers (Vite/webpack)
                      that split a dependency into its own hashed chunk file
                      (e.g. bootstrap-hPTEutI2.js) with no window global and
                      no surviving license banner. Infers the library name
                      from the filename and looks for a literal version-
                      assignment statement in the code. Always flagged with
                      a "note" for manual verification.

It also reports Server/X-Powered-By headers, cookie-based tech hints, and any
<meta name="generator"> tag, since Wappalyzer flags those too.

USAGE:
    pip install playwright requests beautifulsoup4 --break-system-packages
    playwright install chromium
    python3 webtech_fingerprint.py https://target.example.com
    python3 webtech_fingerprint.py https://target.example.com --json out.json
    python3 webtech_fingerprint.py -f targets.txt -o results/
    python3 webtech_fingerprint.py https://target.example.com --no-eol
    python3 webtech_fingerprint.py https://target.example.com --no-repo-check
    python3 webtech_fingerprint.py https://target.example.com --no-zip
    python3 webtech_fingerprint.py -r captured_request.py -o results/
    python3 webtech_fingerprint.py -r captured_request.curl -o results/

-r/--request-file crawls as an authenticated user instead of anonymously --
point it at a file holding a captured, logged-in request (Burp Suite's
"Copy as Python-Requests" or "Copy as curl-command" output, saved as-is to a
file) and it's parsed for the target URL plus every header/cookie that
session used, so components that only render post-login (e.g. behind an
authwall) get picked up too. Replaces the positional url argument -- not
combinable with -f/--targets-file, since a captured session is inherently
tied to one specific target.

NOTE: The endoflife.date lookup (see 3. above) requires outbound internet
access to https://endoflife.date/api/v1/ separate from access to the target
itself. Pass --no-eol to skip it (e.g. fully offline runs). Only a handful of
products are confirmed mapped to endoflife.date right now (jQuery, Bootstrap,
Font Awesome, AngularJS, Angular, Vue, React, nginx, Apache HTTP Server, PHP)
-- anything else (Lodash, core-js, React Router, DevExtreme, Toastify, IIS,
etc.) falls back to the source-repo/GitHub check below, or reports "no data
available" if no source repo link was found either.

The source-repo/GitHub check hits https://api.github.com, which caps
UNAUTHENTICATED requests at 60/hour per IP -- confirmed by hitting that cap
while building this feature. Set a GITHUB_TOKEN environment variable (a
plain classic PAT, no scopes needed for public repos) to raise that to
5,000/hour. Pass --no-repo-check to skip this lookup entirely. CVE-level
vulnerability data beyond GitHub's own published Security Advisories is
still out of scope (a follow-up enhancement, e.g. via retire.js's DB).
"""

import argparse
import ast
import io
import json
import os
import re
import sys
import warnings
import zipfile
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# 0. Request-file parsing (-r) -- authenticated session support
# ---------------------------------------------------------------------------
# Headers that a real HTTP client (requests.Session) is fine setting
# explicitly, but that a real browser (Playwright/Chromium) manages itself at
# the connection level -- forcing these via Playwright's extra-HTTP-headers
# mechanism has been unreliable/rejected in practice, so they're only
# forwarded to the requests.Session used for the follow-up JS/CSS file
# fetches, never to the browser context itself.
BROWSER_UNSAFE_HEADERS = {"host", "connection", "content-length", "te", "transfer-encoding", "upgrade"}


def _extract_dict_literal(content, varname_pattern):
    """Finds `<varname_pattern> = { ... }` and returns the exact `{ ... }`
    substring (brace-matched, quote-aware -- so a `}` inside a header/cookie
    value string doesn't end the match early), or None if not found. Used
    instead of a regex-only capture because Burp's Python-Requests export
    prints these dicts on one line, but there's no guarantee of that -- this
    walks the actual braces so it works either way."""
    m = re.search(varname_pattern + r"\s*=\s*\{", content)
    if not m:
        return None
    start = m.end() - 1
    depth = 0
    in_str = None
    i = start
    while i < len(content):
        ch = content[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[start : i + 1]
        i += 1
    return None


def _parse_python_requests_file(content):
    """Parses a Burp Suite "Copy as Python-Requests" export (or any script
    following the same burp<N>_url/burp<N>_headers/burp<N>_cookies +
    requests.get(...)/requests.post(...) convention) into (url, headers,
    cookies). Only ever reads literal values via ast.literal_eval -- never
    executes the file -- so a captured request script can't run arbitrary
    code just by being handed to this fingerprinter."""
    url_m = re.search(r"burp\d*_url\s*=\s*(['\"])(.*?)\1", content)
    if not url_m:
        url_m = re.search(r"\burl\s*=\s*(['\"])(https?://.*?)\1", content)
    if not url_m:
        raise ValueError(
            "Could not find a burp*_url (or url = \"...\") assignment in the request file."
        )
    url = url_m.group(2)

    headers = {}
    headers_literal = _extract_dict_literal(content, r"burp\d*_headers") or _extract_dict_literal(content, r"\bheaders")
    if headers_literal:
        try:
            headers = ast.literal_eval(headers_literal)
        except Exception as e:
            raise ValueError("Could not parse the headers dict in the request file: " + str(e))

    cookies = {}
    cookies_literal = _extract_dict_literal(content, r"burp\d*_cookies") or _extract_dict_literal(content, r"\bcookies")
    if cookies_literal:
        try:
            cookies = ast.literal_eval(cookies_literal)
        except Exception as e:
            raise ValueError("Could not parse the cookies dict in the request file: " + str(e))

    return url, headers, cookies


def _unescape_ansi_c(s):
    """Minimal unescaping for bash's $'...' ANSI-C-quoted strings (what
    Burp's "Copy as curl-command" wraps every header/cookie/URL value in) --
    just the handful of escape sequences that actually show up in captured
    HTTP headers, not a full ANSI-C-quoting implementation."""
    return (
        s.replace("\\\\", "\x00")
        .replace("\\'", "'")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\x00", "\\")
    )


def _parse_curl_request_file(content):
    """Parses a "Copy as curl-command" export into (url, headers, cookies).
    Handles both bash's $'...' ANSI-C quoting (what Burp actually emits) and
    plain '...'/"..." quoting, and joins trailing-backslash line
    continuations first so a multi-line curl command tokenizes as one
    logical line."""
    joined = re.sub(r"\\\s*\n\s*", " ", content)

    def iter_quoted_args(flag):
        pattern = r"-{}\s+(?:\$'((?:[^'\\]|\\.)*)'|'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\")".format(re.escape(flag))
        for m in re.finditer(pattern, joined):
            if m.group(1) is not None:
                yield _unescape_ansi_c(m.group(1))
            else:
                yield m.group(2) if m.group(2) is not None else m.group(3)

    headers = {}
    for h in iter_quoted_args("H"):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    cookies = {}
    for c in iter_quoted_args("b"):
        for part in c.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

    # Some curl exports carry the session cookie as an explicit `-H 'Cookie:
    # ...'` header instead of (or in addition to) `-b`; fold it into the same
    # cookie dict either way and don't also forward it as a literal header.
    cookie_header = headers.pop("Cookie", None) or headers.pop("cookie", None)
    if cookie_header:
        for part in cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies.setdefault(k.strip(), v.strip())

    url_m = re.search(
        r"\$'(https?://[^']*)'|'(https?://[^']*)'|\"(https?://[^\"]*)\"|(https?://\S+)", joined
    )
    if not url_m:
        raise ValueError("Could not find a target URL (https?://...) in the curl command.")
    url = next(g for g in url_m.groups() if g)

    return url, headers, cookies


def parse_request_file(path):
    """Parses a captured authenticated request -- either a Burp Suite "Copy
    as Python-Requests" script or a "Copy as curl-command" export -- into
    (url, headers, cookies), so the fingerprinter can crawl the target using
    a real logged-in session (real cookies + the exact headers that session
    used) instead of an anonymous request. This is what lets it pick up
    components that only render for an authenticated user."""
    with open(path, encoding="utf-8") as f:
        content = f.read()

    if re.search(r"^\s*curl\b", content, re.MULTILINE):
        url, headers, cookies = _parse_curl_request_file(content)
    elif "requests.get(" in content or "requests.post(" in content or re.search(r"burp\d*_url", content):
        url, headers, cookies = _parse_python_requests_file(content)
    else:
        raise ValueError(
            "Could not detect the request file format -- expected a Burp Suite "
            "\"Copy as Python-Requests\" script (burp0_url/burp0_headers/burp0_cookies + a "
            "requests.get/post call) or a \"Copy as curl-command\" export."
        )

    if not url:
        raise ValueError("Request file parsed, but no target URL was found in it.")
    return url, headers, cookies


# ---------------------------------------------------------------------------
# 1. Known JS global-variable version probes (most reliable signal available)
# ---------------------------------------------------------------------------
JS_VERSION_PROBES = {
    "jQuery":       "window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery",
    "jQuery UI":    "window.jQuery && window.jQuery.ui && window.jQuery.ui.version",
    "React":        "window.React && window.React.version",
    "ReactDOM":     "window.ReactDOM && window.ReactDOM.version",
    "Vue.js":       "window.Vue && (window.Vue.version || (window.Vue.default && window.Vue.default.version))",
    "AngularJS":    "window.angular && window.angular.version && window.angular.version.full",
    "Angular (2+)": "(function(){var el=document.querySelector('[ng-version]'); return el ? el.getAttribute('ng-version') : null;})()",
    "Lodash/Underscore": "window._ && window._.VERSION",
    "Moment.js":    "window.moment && window.moment.version",
    "Backbone.js":  "window.Backbone && window.Backbone.VERSION",
    "D3.js":        "window.d3 && window.d3.version",
    "Handlebars":   "window.Handlebars && window.Handlebars.VERSION",
    "Knockout.js":  "window.ko && window.ko.version",
    "Ember.js":     "window.Ember && window.Ember.VERSION",
    "Bootstrap":    "window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION",
    "Alpine.js":    "window.Alpine && window.Alpine.version",
    "Chart.js":     "window.Chart && window.Chart.version",
    "Modernizr":    "window.Modernizr && window.Modernizr._version",
    "Swiper":       "window.Swiper && window.Swiper.version",
    "Popper.js":    "window.Popper && window.Popper.version",
    "GSAP":         "window.gsap && window.gsap.version",
    "Highcharts":   "window.Highcharts && window.Highcharts.version",
    "CKEditor":     "window.CKEDITOR && window.CKEDITOR.version",
    "PDF.js":       "window.pdfjsLib && window.pdfjsLib.version",
    "Leaflet":      "window.L && window.L.version",
    "Three.js":     "window.THREE && window.THREE.REVISION && ('r' + window.THREE.REVISION)",
    "React Router": "window.__reactRouterVersion && window.__reactRouterVersion",
    # core-js exposes its own version via a well-known shared registry object
    # (used internally to detect duplicate/conflicting core-js instances) --
    # this is not present as literal text anywhere in the page or its
    # scripts, only as this live runtime structure, which is why it's easy
    # to miss with content/banner-based scanning.
    "core-js": "window['__core-js_shared__'] && window['__core-js_shared__'].versions && window['__core-js_shared__'].versions[0] && window['__core-js_shared__'].versions[0].version",
}

NAME_TO_URL_ALIASES = {
    "lodashunderscore": ["lodash", "underscore"],
    "angular2": ["angular"],
    "reactdom": ["react-dom", "reactdom", "react"],
    "reactrouter": ["react-router", "reactrouter", "router"],
    "corejs": ["core-js", "corejs", "core.js"],
}

CONTENT_VERSION_PATTERNS = [
    r"/\*!?[\s*]*([A-Za-z][\w.\- ]{1,30}?)\s+v?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)",
    r"@license\s+([A-Za-z][\w.\- ]{1,30}?)\s+v?(\d+\.\d+(?:\.\d+)?)",
    r"([A-Za-z][\w.\-]{1,30}?)\s+JavaScript Library\s+v(\d+\.\d+(?:\.\d+)?)",
]

DIR_VERSION_RE = re.compile(r"/([A-Za-z][\w.\-]*?)/(\d+\.\d+(?:\.\d+)?)/")
FILE_VERSION_RE = re.compile(r"/([A-Za-z][\w]*?)[-_](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)(?:$|\?)", re.IGNORECASE)
QUERY_VERSION_RE = re.compile(r"[?&]ver(?:sion)?=([0-9]+(?:\.[0-9]+){1,3})", re.IGNORECASE)

GENERIC_STEMS = {"index", "script", "main", "bundle", "all", "style", "app", "vendor", "common"}

# ---------------------------------------------------------------------------
# 5. Vendor-chunk fallback -- covers bundlers (Vite/webpack/Rollup) that split
#    a dependency into its own file named "<package>-<contenthash>.ext" (e.g.
#    bootstrap-hPTEutI2.js) where the library exposes no window global AND
#    its license banner got stripped during minification, so neither the
#    js-global probe nor the content-banner scan can find it. Content hashes
#    generated by these bundlers mix upper/lower case (base62-ish), which is
#    what distinguishes them from ordinary descriptive filenames like
#    "customerportal-portal-styles.css" (all lowercase, multiple real words).
# ---------------------------------------------------------------------------
CHUNK_NAME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]{2,30}?)-([A-Za-z0-9_]{5,14})\.(?:js|css)$")

# Many libraries retain a literal version-assignment statement in their code
# even after the license banner comment is stripped -- these patterns catch
# the common conventions (Lodash/Underscore/Backbone/Ember/older Bootstrap all
# use "X.VERSION=", jQuery uses "fn.jquery=", CJS/UMD builds often use
# "exports.version="). Modern ESM builds (lodash-es, Bootstrap 5.2+) instead
# declare it as a bare top-level constant with no leading dot at all, e.g.
# lodash-es: `var VERSION='4.17.21'`, Bootstrap: `const VERSION="5.3.3"` --
# that bare form is what was missing and caused some real-world
# bootstrap/lodash vendor chunks to stay undetected even with this fallback
# in place.
GENERIC_VERSION_PATTERNS = [
    r'\.fn\.jquery\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?)["\']',
    r'\.VERSION\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[\w.]+)?)["\']',
    r'\bVERSION\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[\w.]+)?)["\']',
    r'\bVERSION\s*:\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[\w.]+)?)["\']',
    r'exports\.version\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[\w.]+)?)["\']',
    r'\.version\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[\w.]+)?)["\']',
]

# Some minifiers hoist a hardcoded version string into a shared local
# variable and assign THAT to `.VERSION`, rather than inlining the literal
# at the assignment site -- e.g. Lodash's own minified build emits
# `u.VERSION=il` where `il="4.17.23"` was declared earlier in the same
# scope. None of the GENERIC_VERSION_PATTERNS above catch this because the
# right-hand side isn't a quoted literal. This traces that one level of
# indirection: find the identifier `.VERSION` was assigned, then find where
# that identifier is itself assigned a literal semver string.
INDIRECT_VERSION_REF_RE = re.compile(r'\.VERSION\s*=\s*([A-Za-z_$][\w$]*)\b')


def resolve_indirect_version(body):
    m = INDIRECT_VERSION_REF_RE.search(body)
    if not m:
        return None
    ident = m.group(1)
    lit_re = re.compile(
        r'(?<![\w$])' + re.escape(ident) + r'\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[\w.]+)?)["\']'
    )
    return lit_re.search(body)


CHUNK_DISPLAY_NAMES = {
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "lodash": "Lodash",
    "underscore": "Underscore",
    "react": "React",
    "reactdom": "ReactDOM",
    "vue": "Vue.js",
    "angular": "Angular",
    "moment": "Moment.js",
    "dayjs": "Day.js",
    "toastify": "Toastify (react-toastify)",
    "router": "React Router",
    "devextremereact": "DevExtreme React",
    "devextreme": "DevExtreme",
    "axios": "Axios",
    "d3": "D3.js",
}


def looks_like_content_hash(segment):
    """Bundler content hashes mix case; descriptive filename segments don't."""
    return bool(re.search(r"[a-z]", segment)) and bool(re.search(r"[A-Z]", segment))


def already_reported(stem, findings):
    """Avoid a duplicate entry when a more reliable method (js-global,
    content-banner) already identified this same library under a different
    dict key/casing."""
    norm = re.sub(r"[^a-z0-9]", "", stem.lower())
    if not norm:
        return False
    for f in findings.values():
        norm_name = re.sub(r"[^a-z0-9]", "", f["name"].lower())
        if norm in norm_name or norm_name in norm:
            return True
    return False

HEADER_HINTS = ["server", "x-powered-by", "x-generator", "x-drupal-cache", "x-varnish"]

COOKIE_FINGERPRINTS = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (Servlet container)",
    "ASP.NET_SessionId": "ASP.NET",
    "laravel_session": "Laravel",
    "wordpress_logged_in": "WordPress",
    "CFID": "ColdFusion",
    "CFTOKEN": "ColdFusion",
}


def extract_excerpt(text, start, end, context=60):
    s = max(0, start - context)
    e = min(len(text), end + context)
    return re.sub(r"\s+", " ", text[s:e]).strip()


def find_version_literal(text, version):
    """Search for `version` as a literal substring, but reject matches that
    are embedded inside a longer run of digits/dots (e.g. minified SVG path
    data like "...3.5.1.8..." spuriously containing "3.5.1"). This is what
    keeps js-global correlation from attributing a version to the wrong file
    just because the digits happen to appear somewhere unrelated."""
    pattern = r"(?<![\d.])" + re.escape(version) + r"(?![\d.])"
    return re.search(pattern, text)


def name_from_path(url):
    path = urlparse(url).path
    base = os.path.basename(path)
    stem = re.sub(r"\.(min\.)?(js|css)$", "", base, flags=re.IGNORECASE)
    stem = re.sub(r"[-_.]?v?\d+(\.\d+)*$", "", stem, flags=re.IGNORECASE)
    if stem.lower() in GENERIC_STEMS or not stem:
        parts = [p for p in path.split("/") if p and p.lower() not in GENERIC_STEMS]
        stem = parts[-2] if len(parts) >= 2 else (parts[-1] if parts else base)
    return stem or base


def build_tag_index(html, base_url):
    """Maps each resolved resource URL to the exact <script>/<link> tag that
    references it, plus the 1-indexed line number that tag appears on in the
    page's HTML source. bs4's html.parser tracks source position natively
    (tag.sourceline) -- this is what lets a remediator jump straight to the
    right line in view-source instead of having to search the page for the
    tag by hand."""
    soup = BeautifulSoup(html, "html.parser")
    index = {}
    for tag in soup.find_all("script", src=True):
        index[urljoin(base_url, tag["src"])] = (str(tag), tag.sourceline)
    for tag in soup.find_all("link", href=True):
        rel = tag.get("rel") or []
        rel = [r.lower() for r in rel] if isinstance(rel, list) else [str(rel).lower()]
        if any(r in ("stylesheet", "modulepreload", "preload", "import") for r in rel):
            index[urljoin(base_url, tag["href"])] = (str(tag), tag.sourceline)
    return index


def find_tag_snippet(url, tag_index):
    """Returns (tag_str, line_number) for the <script>/<link> tag that loaded
    `url` -- (None, None) if no static tag in the DOM snapshot matched it."""
    if url in tag_index:
        return tag_index[url]
    base = url.split("?")[0]
    for k, v in tag_index.items():
        if k.split("?")[0] == base:
            return v
    return None, None


def fetch_body(url, cache, session=None):
    """`session` is an authenticated requests.Session (see parse_request_file
    / the -r flag) when the fingerprinter is running from a logged-in user's
    session -- follow-up JS/CSS file fetches need the same cookies/headers
    the browser used, or they'll silently hit a login page instead of the
    real file. Falls back to a bare requests.get for unauthenticated runs."""
    if url in cache:
        return cache[url]
    try:
        client = session if session is not None else requests
        r = client.get(url, timeout=10, verify=False)
        body = r.text if r.ok else ""
    except Exception:
        body = ""
    cache[url] = body
    return body


def correlate_name_to_resource(name, resources):
    key = re.sub(r"[^a-z0-9]", "", name.lower())
    candidates = NAME_TO_URL_ALIASES.get(key, [key])
    for cand in candidates:
        for url in resources:
            if cand and cand in url.lower():
                return url
    return None


def is_reliable_search_key(version):
    """A short, dotless value like a bare major version ("6") is far too
    generic to search for as a literal substring across arbitrary file
    content -- it will coincidentally match inside hex colors, font
    subsetting data, cache-busting hashes, etc. Only proper dotted versions
    (e.g. "7.13.1") are safe to use as a cross-file correlation key."""
    return "." in version and len(version) >= 4


def correlate_name_to_resource_deep(name, version, resources, body_cache):
    """Filename match first; if that fails (e.g. the library is bundled inside
    a larger webpacked/minified file with a hashed name), fall back to
    searching every already-fetched resource body for the literal version
    string -- this catches bundled Bootstrap/etc. that don't ship as their
    own named file. Skipped entirely for short/generic version values (see
    is_reliable_search_key) since that fallback would otherwise attribute the
    finding to a coincidentally-matching, completely unrelated file."""
    url = correlate_name_to_resource(name, resources)
    if url:
        return url
    if not is_reliable_search_key(version):
        return None
    for url in resources:
        body = body_cache.get(url, "")
        if body and find_version_literal(body, version):
            return url
    return None


def probe_js_globals(page):
    results = {}
    for name, expr in JS_VERSION_PROBES.items():
        try:
            val = page.evaluate(expr)
        except Exception:
            val = None
        if val:
            results[name.lower()] = {"name": name, "version": str(val)}
    return results


def build_js_global_finding(name, version, resources, body_cache, tag_index, expr, session=None):
    source_url = correlate_name_to_resource_deep(name, version, resources, body_cache)
    excerpt = None
    script_tag = None
    tag_line = None

    if source_url:
        body = fetch_body(source_url, body_cache, session=session)
        lit = find_version_literal(body, version) if body else None
        if lit:
            excerpt = extract_excerpt(body, lit.start(), lit.end())
        else:
            excerpt = (
                "Version '" + version + "' read live from the page's JS runtime "
                "(`" + expr + "`); not present as literal text in "
                + os.path.basename(urlparse(source_url).path) + "."
            )
        script_tag, tag_line = find_tag_snippet(source_url, tag_index)
    else:
        excerpt = (
            "Version '" + version + "' read live from the page's JS runtime (`" + expr + "`). "
            "No loaded JS/CSS resource matched this library by filename or contained the "
            "literal version string -- confirm manually via the browser's Network tab which "
            "file defines it."
        )

    if source_url and not script_tag:
        script_tag = (
            "No static <script>/<link> tag in the DOM snapshot matched " + source_url + ". "
            "It was observed as a network request, so it is likely injected dynamically "
            "(e.g. by another script) -- confirm manually via the Network/Initiator tab."
        )
    elif not source_url:
        script_tag = (
            "No JS/CSS resource was correlated to this library by filename (it's likely "
            "bundled inside a larger webpacked/minified file rather than shipped as its "
            "own script). Confirm manually via the browser's Network/Initiator tab which "
            "request actually defines this global, then reference that request's initiator "
            "chain in place of a <script> tag."
        )

    # react-router v6.22+ intentionally hardcodes this global to the SemVer
    # MAJOR version only (e.g. "6"), for its own version-conflict detection;
    # v7+ switched to reporting the full version instead. So a bare integer
    # here isn't an unresolved finding that needs more digging -- it's the
    # complete signal available at runtime for a v6.x app. Confirmed via the
    # react-router changelog (v6.22.0 release notes).
    if name == "React Router" and re.fullmatch(r"[0-9]+", version):
        excerpt += (
            " (Expected: react-router v6.22+ intentionally hardcodes this global to the "
            "SemVer MAJOR version only, for its own version-conflict detection -- v7+ "
            "reports the full version instead. There is no minor/patch obtainable from "
            "this runtime signal for a v6.x app.)"
        )
        if not source_url:
            script_tag = (
                "Not applicable: this is a runtime-only signal that react-router v6.x "
                "sets itself, independent of any specific loaded file, and it doesn't "
                "expose a more precise source than the major version shown above."
            )

    return {
        "name": name,
        "version": version,
        "method": "js-global",
        "source_url": source_url,
        "excerpt": excerpt,
        "script_tag": script_tag,
        "tag_line": tag_line,
    }


def scan_resource_content(url, body, tag_index, findings):
    for pattern in CONTENT_VERSION_PATTERNS:
        m = re.search(pattern, body[:20000], re.IGNORECASE)
        if m:
            lib, ver = m.groups()
            lib = lib.strip().rstrip(".")
            key = lib.lower()
            if key not in findings:
                tag, tag_line = find_tag_snippet(url, tag_index)
                if not tag:
                    tag = "No static <script>/<link> tag in the DOM snapshot matched " + url + ". Confirm manually via the Network/Initiator tab."
                findings[key] = {
                    "name": lib,
                    "version": ver,
                    "method": "content-banner",
                    "source_url": url,
                    "excerpt": extract_excerpt(body, m.start(), m.end()),
                    "script_tag": tag,
                    "tag_line": tag_line,
                }
            return


def scan_path_version(url, tag_index, findings):
    m = DIR_VERSION_RE.search(url) or FILE_VERSION_RE.search(url)
    method = "path-version"
    if not m:
        m = QUERY_VERSION_RE.search(url)
        method = "query-version"
        if m:
            lib = name_from_path(url)
            ver = m.group(1)
        else:
            return
    else:
        lib, ver = m.groups()

    key = lib.lower()
    if key in findings:
        return

    tag, tag_line = find_tag_snippet(url, tag_index)
    if not tag:
        tag = "No static <script>/<link> tag in the DOM snapshot matched " + url + ". Confirm manually via the Network/Initiator tab."

    findings[key] = {
        "name": lib,
        "version": ver,
        "method": method,
        "source_url": url,
        "excerpt": "Version string embedded directly in the resource URL: ..." + extract_excerpt(url, m.start(), m.end(), context=25) + "...",
        "script_tag": tag,
        "tag_line": tag_line,
    }


def scan_vendor_chunk(url, body, tag_index, findings):
    """Last-resort fallback: bundler-generated single-package chunk with no
    exposed global and no surviving license banner. Infers the library name
    from the "<package>-<contenthash>.ext" filename convention and looks for
    a literal version-assignment statement in the code itself. Lower
    confidence than the other methods, so it only fires when nothing more
    reliable already found this library, and it's flagged with a "note" for
    manual verification."""
    base = os.path.basename(urlparse(url).path)
    m = CHUNK_NAME_RE.match(base)
    if not m:
        return
    stem, hashpart = m.groups()
    if stem.lower() in GENERIC_STEMS or not looks_like_content_hash(hashpart):
        return

    key = stem.lower()
    if key in findings or already_reported(stem, findings):
        return

    vm = None
    indirect = False
    for pattern in GENERIC_VERSION_PATTERNS:
        vm = re.search(pattern, body)
        if vm:
            break
    if not vm:
        vm = resolve_indirect_version(body)
        indirect = True
    if not vm:
        return

    ver = vm.group(1)
    name = CHUNK_DISPLAY_NAMES.get(key, stem[:1].upper() + stem[1:])
    tag, tag_line = find_tag_snippet(url, tag_index)
    if not tag:
        tag = "No static <script>/<link> tag in the DOM snapshot matched " + url + ". Confirm manually via the Network/Initiator tab."

    note = (
        "Lower-confidence heuristic: the library name was inferred from the "
        "bundler's chunk filename (\"" + base + "\"), not from a banner or "
        "window global (this chunk likely doesn't expose one). This version was "
        "the FIRST version-shaped assignment found anywhere in the file -- if the "
        "bundler concatenated multiple dependencies into this one chunk (common "
        "with Vite/webpack vendor chunks, e.g. a router chunk that also inlines "
        "React and ReactDOM), that match can belong to a different library than "
        "the one named here. Verify manually (e.g. cross-check against Wappalyzer "
        "or grep the file for the library's own version marker) before citing in "
        "the report."
    )
    if indirect:
        note += (
            " This value required one extra hop to resolve: the minifier assigned "
            "\".VERSION\" to a bare variable name instead of inlining the literal, "
            "so this scan traced that variable back to its own literal assignment "
            "elsewhere in the same file. Treat this one as especially worth a "
            "manual double-check."
        )

    findings[key] = {
        "name": name,
        "version": ver,
        "method": "vendor-chunk",
        "source_url": url,
        "excerpt": extract_excerpt(body, vm.start(), vm.end()),
        "script_tag": tag,
        "tag_line": tag_line,
        "note": note,
    }


# ---------------------------------------------------------------------------
# 6. EOL/support-lifecycle cross-check via the endoflife.date public API
#    (https://endoflife.date/api/v1/products/{product}). Detecting a version
#    is only half of "[UNPATCHED/UNSUPPORTED SOFTWARE]" -- this looks up
#    whether that specific version's release cycle is still supported.
#
#    Only libraries CONFIRMED to exist as endoflife.date products (checked
#    directly against the live API) are mapped below. Guessing at slugs is
#    deliberately avoided -- a wrong slug could silently attribute EOL status
#    to the wrong product, which is worse than reporting nothing. Anything
#    not in this map (Lodash, core-js, React Router, DevExtreme, Toastify,
#    etc. are NOT tracked as of this writing) is reported as "no data
#    available" rather than guessed at.
# ---------------------------------------------------------------------------
ENDOFLIFE_PRODUCT_SLUGS = {
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "fontawesome": "font-awesome",
    "angularjs": "angularjs",
    "angular2": "angular",
    "vuejs": "vue",
    "react": "react",
    # Server/platform components parsed out of the Server / X-Powered-By
    # headers (see build_server_component_finding below).
    "nginx": "nginx",
    "apache": "apache-http-server",
    "php": "php",
}

_ENDOFLIFE_CACHE = {}


def fetch_endoflife_product(slug):
    """Fetch and cache a product's full release-cycle data from
    endoflife.date. Returns None on any failure (404, network error, rate
    limit) -- callers must treat that as "no data available", not crash."""
    if slug in _ENDOFLIFE_CACHE:
        return _ENDOFLIFE_CACHE[slug]
    result = None
    try:
        r = requests.get("https://endoflife.date/api/v1/products/" + slug, timeout=10)
        if r.ok:
            result = r.json().get("result")
    except Exception:
        result = None
    _ENDOFLIFE_CACHE[slug] = result
    return result


def match_release_cycle(version, releases):
    """endoflife.date release cycles aren't a fixed granularity -- some
    products cycle by major only ("5"), others by major.minor ("3.5"), and a
    single product can mix both (e.g. Vue's legacy "1" alongside "3.5").
    Find the cycle whose name is the longest matching prefix of `version`;
    require a dot boundary so "31.0.0" can't falsely match a "3" cycle."""
    best = None
    for rel in releases:
        cycle = rel.get("name", "")
        if not cycle:
            continue
        if version == cycle or version.startswith(cycle + "."):
            if best is None or len(cycle) > len(best.get("name", "")):
                best = rel
    return best


def version_sort_key(v):
    """Parse a dotted version string into a tuple of ints for correct
    numeric comparison (e.g. "5.3.8" > "5.20.1" as plain strings would be
    wrong -- lexicographic "5.3" > "5.20" -- this compares (5,3,8) vs
    (5,20,1) correctly). Any non-numeric chunk (pre-release suffixes, etc.)
    is treated as 0 rather than raising."""
    parts = []
    for chunk in re.split(r"[.\-]", v):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts)


def find_absolute_latest(releases):
    """The matched release cycle's own "latest" is only the newest patch
    WITHIN that cycle (e.g. jQuery 3.x's latest is 3.7.1) -- it is NOT
    necessarily the newest version of the product overall (jQuery 4.x
    exists with 4.0.0). Scan every cycle's "latest" entry and keep the
    numerically greatest one across the whole product."""
    best = None
    best_key = None
    for rel in releases:
        latest = rel.get("latest") or {}
        lname = latest.get("name")
        if not lname:
            continue
        key = version_sort_key(lname)
        if best_key is None or key > best_key:
            best_key = key
            best = latest
    return best


def find_version_date(version, releases):
    """endoflife.date only publishes a release date for the current "latest"
    patch of each cycle (ProductVersion.date) -- it does not expose a date
    for every historical patch version. This returns that date only when
    `version` happens to BE one of those documented "latest" entries;
    otherwise None (honestly unavailable, not guessed)."""
    for rel in releases:
        latest = rel.get("latest") or {}
        if latest.get("name") == version:
            return latest.get("date")
    return None


def build_eol_finding(name, version):
    """Returns a dict describing the support/EOL status for this exact
    detected version, or None if this library isn't one we can look up."""
    key = re.sub(r"[^a-z0-9]", "", name.lower())
    slug = ENDOFLIFE_PRODUCT_SLUGS.get(key)
    if not slug:
        return None

    url = "https://endoflife.date/" + slug
    product = fetch_endoflife_product(slug)
    if product is None:
        return {
            "product": slug,
            "matched_cycle": None,
            "is_eol": None,
            "is_maintained": None,
            "latest_in_cycle": None,
            "absolute_latest_version": None,
            "absolute_latest_date": None,
            "version_release_date": None,
            "status_label": None,
            "url": url,
            "summary": (
                "Couldn't reach endoflife.date to check " + name + " " + version
                + " (network error, rate limit, or the product isn't listed there)."
            ),
        }

    releases = product.get("releases", [])
    release = match_release_cycle(version, releases)
    absolute_latest = find_absolute_latest(releases)
    absolute_latest_version = absolute_latest.get("name") if absolute_latest else None
    absolute_latest_date = absolute_latest.get("date") if absolute_latest else None
    version_release_date = find_version_date(version, releases)

    if release is None:
        return {
            "product": slug,
            "matched_cycle": None,
            "is_eol": None,
            "is_maintained": None,
            "latest_in_cycle": None,
            "absolute_latest_version": absolute_latest_version,
            "absolute_latest_date": absolute_latest_date,
            "version_release_date": version_release_date,
            "status_label": None,
            "url": url,
            "summary": "No matching release cycle found on endoflife.date for " + name + " " + version + ".",
        }

    is_eol = release.get("isEol")
    eol_from = release.get("eolFrom")
    is_maintained = release.get("isMaintained")
    latest = release.get("latest") or {}
    latest_in_cycle = latest.get("name")

    # Two distinct callouts worth surfacing separately:
    #   EOL/Unsupported    -- the release cycle itself is EOL or unmaintained.
    #   Unpatched/Outdated -- the cycle is still supported, but this isn't the
    #                         absolute latest version of the product overall
    #                         (not just the latest within its own cycle).
    if is_eol:
        status_label = "EOL/Unsupported"
        summary = (
            name + " " + version + " is END OF LIFE"
            + (" (since " + eol_from + ")" if eol_from else " (end-of-life date not published)")
            + "."
        )
    elif is_maintained is False:
        status_label = "EOL/Unsupported"
        summary = name + " " + version + " is no longer maintained per endoflife.date, though not formally marked EOL."
    elif absolute_latest_version and absolute_latest_version != version:
        status_label = "Unpatched/Outdated"
        summary = (
            name + " " + version + " is within a currently supported release cycle, "
            "but is not the absolute latest version available."
        )
    else:
        status_label = "Up-To-Date"
        summary = name + " " + version + " is within a currently supported release cycle and is the latest version available."

    if version_release_date:
        summary += " Release date of the version in use: " + version_release_date + "."
    else:
        summary += " Release date of the version in use is not published by endoflife.date for this specific patch."

    if absolute_latest_version and absolute_latest_version != version:
        summary += " Absolute latest available: " + absolute_latest_version
        if absolute_latest_date:
            summary += " (released " + absolute_latest_date + ")"
        summary += "."

    summary += " Source: " + url

    return {
        "product": slug,
        "matched_cycle": release.get("name"),
        "is_eol": is_eol,
        "is_maintained": is_maintained,
        "latest_in_cycle": latest_in_cycle,
        "absolute_latest_version": absolute_latest_version,
        "absolute_latest_date": absolute_latest_date,
        "version_release_date": version_release_date,
        "status_label": status_label,
        "url": url,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# 7. Server/platform component check -- parses "<Product>/<Version>" tokens
#    out of the Server / X-Powered-By headers (e.g. "nginx/1.18.0",
#    "Apache/2.4.51", "Microsoft-IIS/10.0") and runs them through the same
#    endoflife.date lookup used for JS/CSS libraries. IIS is a special case:
#    it's detected but NOT auto-checked, because IIS's own version number
#    doesn't map 1:1 to a specific Windows Server release (IIS 10.0 covers
#    Server 2016 through 2025 alike) and isn't independently tracked on
#    endoflife.date -- guessing which OS build is running would be exactly
#    the kind of wrong-slug false claim this tool avoids elsewhere.
# ---------------------------------------------------------------------------
SERVER_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9._-]*)/([0-9]+(?:\.[0-9]+){0,3})")


def parse_server_tokens(value):
    return SERVER_TOKEN_RE.findall(value or "")


def build_server_component_finding(name, version):
    key = re.sub(r"[^a-z0-9]", "", name.lower())
    if key in ("microsoftiis", "iis"):
        return {
            "status_label": None,
            "summary": (
                "IIS/" + version + " detected, but IIS's own version number isn't "
                "independently tracked on endoflife.date and doesn't map 1:1 to a single "
                "Windows Server release (IIS 10.0 covers Server 2016, 2019, 2022, and 2025 "
                "alike). Identify the specific Windows Server build via other means (e.g. "
                "SMB/OS fingerprinting) and check https://endoflife.date/windows-server "
                "manually before citing an EOL/support claim in the report."
            ),
        }
    return build_eol_finding(name, version)


# ---------------------------------------------------------------------------
# 8. Source-repository detection + GitHub release/security lookup -- some
#    libraries embed a link to their own source repo directly in the bundled
#    code (e.g. core-js's `source:"https://github.com/zloirock/core-js"`
#    banner) even when they aren't tracked on endoflife.date at all. When one
#    is found, the release history and any published security advisories are
#    pulled straight from the GitHub REST API -- no slug-guessing needed,
#    since the owner/repo is read directly out of the matched URL.
#
#    NOTE: GitHub's REST API is capped at 60 requests/hour per IP when
#    unauthenticated (confirmed while building this -- a handful of calls
#    from the dev sandbox were enough to exhaust it). Set a GITHUB_TOKEN
#    environment variable (a plain classic PAT, no scopes needed for public
#    repos) to raise that to 5,000/hour. Every call below fails soft into an
#    honest "couldn't reach" note rather than a crash or a guess.
# ---------------------------------------------------------------------------
REPO_URL_RE = re.compile(
    r"https?://(github\.com|gitlab\.com|bitbucket\.org)/"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)"
    r"(?:\.git)?(?=[\"'\s)>,;]|$)"
)

# Path segments that are part of the host's own site chrome, not a project
# owner, so a random UI link doesn't get mistaken for a source repo.
_REPO_HOST_RESERVED_OWNERS = {
    "github", "about", "sponsors", "marketplace", "apps", "orgs",
    "settings", "notifications", "topics", "collections", "search",
}


def find_source_repo(body):
    """Scan a fetched JS/CSS file's body for a link to its own source repo
    (github.com/gitlab.com/bitbucket.org), e.g. a
    `source:"https://github.com/zloirock/core-js"` banner left in by the
    bundler. Returns the FIRST match found -- libraries that embed this at
    all put it in their own license/info banner near the top of the file, so
    this is a strong lead, not a certainty; confirm manually if in doubt."""
    for m in REPO_URL_RE.finditer(body):
        host, owner, repo = m.group(1), m.group(2), m.group(3)
        if owner.lower() in _REPO_HOST_RESERVED_OWNERS:
            continue
        return {"host": host, "owner": owner, "repo": repo, "url": "https://" + host + "/" + owner + "/" + repo}
    return None


def find_source_repo_near(body, version, window=3000):
    """Same idea as find_source_repo, but scoped to a window of text around
    where THIS library's own version literal appears, instead of scanning
    the whole file. A plain whole-file scan misattributes when multiple
    libraries are concatenated into one bundle -- e.g. core-js and Lodash
    both shipped inside the same dist/bundle.js: a whole-file scan finds
    core-js's own `source:"https://github.com/zloirock/core-js"` banner
    first and wrongly attaches it to the Lodash finding too, which is
    simply wrong (confirmed happening in real-world testing against sites
    bundling both libraries together). Anchoring the search to the version
    literal's own position keeps it scoped to that library's own declaration
    block. If the version literal can't be located in the body at all (e.g.
    a runtime-only js-global signal like React Router's major-version-only
    global, with no literal text match), this returns None rather than
    falling back to a whole-file scan that could misattribute again."""
    lit = find_version_literal(body, version)
    if not lit:
        return None
    start = max(0, lit.start() - window)
    end = min(len(body), lit.end() + window)
    return find_source_repo(body[start:end])


_GITHUB_CACHE = {}


def _github_headers():
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers


def fetch_github_json(url):
    """GET a github.com REST API URL. Returns (data, error) -- exactly one of
    the two is not None. Never raises."""
    try:
        r = requests.get(url, headers=_github_headers(), timeout=10)
    except Exception as e:
        return None, "network error reaching " + url + " (" + str(e) + ")"
    if r.status_code == 403:
        return None, (
            "rate-limited by GitHub's API (unauthenticated requests are capped at 60/hour "
            "per IP -- set a GITHUB_TOKEN environment variable to raise this to 5,000/hour) "
            "while calling " + url
        )
    if r.status_code == 404:
        # Both the releases-list and security-advisories-list endpoints return
        # HTTP 200 with an empty array when there's simply nothing published --
        # a 404 here means the repo itself wasn't found (bad owner/repo, or it
        # was renamed/deleted since the source link was written), which is a
        # real problem worth surfacing, not silent "nothing to report".
        return None, "GitHub API returned 404 for " + url + " (repo not found, renamed, or moved)"
    if not r.ok:
        return None, "GitHub API returned HTTP " + str(r.status_code) + " for " + url
    try:
        return r.json(), None
    except Exception:
        return None, "GitHub API returned a non-JSON response for " + url


def _norm_tag(tag):
    """Strip a leading 'v'/'V' from a release tag (e.g. "v3.48.0" -> "3.48.0")
    so it can be compared against the version string detected in-page, but
    only when followed by a digit -- doesn't mangle a tag that's genuinely
    just "v" or a non-numeric codename."""
    return re.sub(r"^[vV](?=\d)", "", tag or "")


def fetch_github_repo_info(host, owner, repo):
    """Fetch + cache this repo's releases and published security advisories.
    Only implemented for github.com (a gitlab.com/bitbucket.org link is still
    surfaced as a source-repo lead, just without this lookup). Returns a
    dict; never None, but individual fields may be None with an accompanying
    "*_error" note when a call failed."""
    cache_key = (host, owner, repo)
    if cache_key in _GITHUB_CACHE:
        return _GITHUB_CACHE[cache_key]

    result = {"releases": None, "releases_error": None, "advisories": None, "advisories_error": None}

    if host == "github.com":
        api_base = "https://api.github.com/repos/" + owner + "/" + repo
        result["releases"], result["releases_error"] = fetch_github_json(api_base + "/releases?per_page=100")
        result["advisories"], result["advisories_error"] = fetch_github_json(api_base + "/security-advisories?per_page=100")
    else:
        result["releases_error"] = "release/advisory lookup is only implemented for github.com"

    _GITHUB_CACHE[cache_key] = result
    return result


def build_repo_finding(source_repo, version):
    """Given a detected {"host","owner","repo","url"} source-repo reference
    and the version string already found for this library, look up the
    repo's release history and published GitHub Security Advisories.

    Deliberately does NOT assign an EOL/Unpatched status_label the way
    build_eol_finding does -- GitHub has no formal support-lifecycle concept
    the way endoflife.date does (a repo can go years without a new release
    without being "EOL" in any documented sense). The facts are laid out for
    the tester to interpret; "status"/"latest" used in the summary table
    below are a conservative, clearly-labeled best-effort derived from them,
    not an authoritative verdict."""
    host, owner, repo, url = source_repo["host"], source_repo["owner"], source_repo["repo"], source_repo["url"]
    info = fetch_github_repo_info(host, owner, repo)

    lines = ["Source repo: " + url]
    latest_release_tag = None
    latest_release_date = None
    advisory_count = 0

    releases = info["releases"]
    if releases is None:
        if info["releases_error"]:
            lines.append("Couldn't check GitHub releases (" + info["releases_error"] + ").")
    elif not releases:
        lines.append("No GitHub releases are published for this repo (tags may still exist; check manually).")
    else:
        # GitHub's own "latest release" (the thing /releases/latest returns)
        # is defined as the most recent NON-prerelease, NON-draft release --
        # not simply the newest entry in the list. Filtering here client-side
        # (rather than making a second API call to /releases/latest) matches
        # that same definition, since /releases already comes back ordered
        # by creation date, and saves a request against GitHub's 60/hour
        # unauthenticated cap. Without this filter, a repo that only has a
        # pre-release ahead of its last stable cut (e.g. core-js's
        # "v4.0.0-alpha.1") would get reported as "latest" here, which would
        # be misleading for an unpatched/outdated determination.
        stable_releases = [r for r in releases if not r.get("draft") and not r.get("prerelease")]
        if stable_releases:
            latest = stable_releases[0]
            latest_release_tag = latest.get("tag_name")
            latest_release_date = (latest.get("published_at") or "")[:10] or None
            lines.append(
                "Latest stable GitHub release: " + (latest_release_tag or "?")
                + (" (published " + latest_release_date + ")" if latest_release_date else " (publish date not available)")
                + "."
            )
        else:
            lines.append(
                "All " + str(len(releases)) + " release(s) returned by GitHub in the most recent 100 are "
                "pre-release/draft -- no stable release found in that window."
            )
        match = next((rel for rel in releases if _norm_tag(rel.get("tag_name")) == _norm_tag(version)), None)
        if match:
            match_date = (match.get("published_at") or "")[:10] or None
            if match_date:
                lines.append("Release date of the version in use (" + version + "): " + match_date + ".")
        elif latest_release_tag and _norm_tag(latest_release_tag) != _norm_tag(version):
            lines.append(
                "The in-use version (" + version + ") was not found as a matching GitHub release tag in "
                "the most recent 100 releases -- it may be older than that window, or the repo may tag "
                "releases differently than its published version string."
            )

    advisories = info["advisories"]
    if advisories is None:
        if info["advisories_error"]:
            lines.append("Couldn't check GitHub Security Advisories (" + info["advisories_error"] + ").")
    elif not advisories:
        lines.append("No published GitHub Security Advisories for this repo.")
    else:
        advisory_count = len(advisories)
        lines.append(
            str(advisory_count) + " published GitHub Security Advisor" + ("y" if advisory_count == 1 else "ies")
            + " for this repo (confirm applicability to " + version + " manually):"
        )
        for adv in advisories[:5]:
            ghsa = adv.get("ghsa_id", "?")
            severity = (adv.get("severity") or "unknown").upper()
            summary = adv.get("summary", "")
            cve = adv.get("cve_id")
            ranges = sorted({
                v.get("vulnerable_version_range")
                for v in (adv.get("vulnerabilities") or [])
                if v.get("vulnerable_version_range")
            })
            line = "  - [" + severity + "] " + ghsa + (" / " + cve if cve else "") + ": " + summary
            if ranges:
                line += " (affects: " + "; ".join(ranges) + ")"
            lines.append(line)

    return {
        "url": url,
        "owner": owner,
        "repo": repo,
        "latest_release_tag": latest_release_tag,
        "latest_release_date": latest_release_date,
        "advisory_count": advisory_count,
        "summary": "\n".join(lines),
    }


def fingerprint(target_url, timeout=25000, check_eol=True, check_repo=True, extra_headers=None, extra_cookies=None):
    """`extra_headers`/`extra_cookies` (from -r/parse_request_file) let this
    crawl as an authenticated user instead of anonymously -- applied to both
    the Playwright browser context (so the rendered page itself reflects the
    logged-in view) and a requests.Session used for every follow-up JS/CSS
    file fetch this function makes (so those don't silently fall back to an
    anonymous response, e.g. a login redirect, instead of following the
    browser's session)."""
    findings = {}
    resources = []
    headers = {}
    cookies = []
    html = ""
    final_url = target_url

    session = requests.Session()
    if extra_headers:
        session.headers.update(extra_headers)
    if extra_cookies:
        session.cookies.update(extra_cookies)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)

        if extra_headers:
            browser_headers = {k: v for k, v in extra_headers.items() if k.lower() not in BROWSER_UNSAFE_HEADERS}
            if browser_headers:
                context.set_extra_http_headers(browser_headers)
        if extra_cookies:
            context.add_cookies([{"name": k, "value": v, "url": target_url} for k, v in extra_cookies.items()])

        page = context.new_page()

        def on_response(response):
            try:
                ct = response.headers.get("content-type", "")
                if "javascript" in ct or "css" in ct or response.url.split("?")[0].endswith((".js", ".css")):
                    resources.append(response.url)
            except Exception:
                pass

        page.on("response", on_response)

        response = page.goto(target_url, timeout=timeout, wait_until="load")
        page.wait_for_timeout(2000)
        if response:
            headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = context.cookies()
        final_url = page.url

        js_globals = probe_js_globals(page)
        html = page.content()
        browser.close()

    tag_index = build_tag_index(html, final_url)
    body_cache = {}

    # Prefetch every JS/CSS resource body up front so the js-global deep
    # correlation fallback (searching bundle contents for a literal version
    # string) has something to search against.
    for url in dict.fromkeys(resources):
        fetch_body(url, body_cache, session=session)

    for key, data in js_globals.items():
        expr = JS_VERSION_PROBES[data["name"]]
        findings[key] = build_js_global_finding(data["name"], data["version"], resources, body_cache, tag_index, expr, session=session)

    header_hits = {h: headers[h] for h in HEADER_HINTS if h in headers}

    cookie_hits = []
    for c in cookies:
        tech = COOKIE_FINGERPRINTS.get(c["name"])
        if tech:
            cookie_hits.append({"cookie": c["name"], "technology": tech})

    meta_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.IGNORECASE)
    generator = meta_match.group(1) if meta_match else None

    seen = set()
    for url in resources:
        if url in seen:
            continue
        seen.add(url)
        scan_path_version(url, tag_index, findings)
        body = fetch_body(url, body_cache, session=session)
        if body:
            scan_resource_content(url, body, tag_index, findings)
            scan_vendor_chunk(url, body, tag_index, findings)

    if check_eol:
        for f in findings.values():
            f["eol"] = build_eol_finding(f["name"], f["version"])

    if check_repo:
        for f in findings.values():
            body = body_cache.get(f.get("source_url") or "", "")
            f["source_repo"] = find_source_repo_near(body, f["version"]) if body else None
            f["repo_info"] = build_repo_finding(f["source_repo"], f["version"]) if f["source_repo"] else None

    server_components = []
    if check_eol:
        for header_name, header_value in header_hits.items():
            for comp_name, comp_version in parse_server_tokens(header_value):
                server_components.append({
                    "name": comp_name,
                    "version": comp_version,
                    "header": header_name,
                    "eol": build_server_component_finding(comp_name, comp_version),
                })

    return {
        "url": target_url,
        "final_url": final_url,
        "libraries": list(findings.values()),
        "server_components": server_components,
        "headers": header_hits,
        "cookies": cookie_hits,
        "generator": generator,
        "resources_seen": sorted(seen),
    }


def build_report_text(data):
    """Build the human-readable report as a single string (used both for
    printing to the console and for writing the per-target .txt file)."""
    lines = []
    lines.append("\nTarget: " + data["url"])
    if data["final_url"] != data["url"]:
        lines.append("(resolved to: " + data["final_url"] + ")")
    lines.append("")

    if data["generator"]:
        lines.append("Meta generator: " + data["generator"])
    for h, v in data["headers"].items():
        lines.append("Header  " + h + ": " + v)
    for c in data["cookies"]:
        lines.append("Cookie  " + c["cookie"] + " -> " + c["technology"])

    if data.get("server_components"):
        lines.append("\nServer/platform components detected:\n")
        for comp in data["server_components"]:
            lines.append(comp["name"] + " " + comp["version"] + "   [from: " + comp["header"] + " header]")
            comp_eol = comp.get("eol")
            if comp_eol:
                comp_label = comp_eol.get("status_label")
                comp_prefix = ("*** " + comp_label + " *** ") if comp_label else ""
                lines.append("  " + comp_prefix + comp_eol["summary"])
        lines.append("")

    libs = sorted(data["libraries"], key=lambda x: x["name"].lower())
    label = "library" if len(libs) == 1 else "libraries"
    lines.append("\n" + str(len(libs)) + " " + label + " detected.\n")

    for lib in libs:
        lines.append("=" * 78)
        lines.append(lib["name"] + " " + lib["version"] + "   [detected via: " + lib["method"] + "]")
        lines.append("=" * 78)
        lines.append("Source URL:\n  " + (lib["source_url"] or "(not resolved to a specific file)") + "\n")
        lines.append("Excerpt showing version:\n  " + lib["excerpt"] + "\n")
        tag_line = lib.get("tag_line")
        tag_line_prefix = ("Line " + str(tag_line) + ": ") if tag_line else ""
        lines.append("Script/link tag that caused this file to load:\n  " + tag_line_prefix + lib["script_tag"] + "\n")
        if lib.get("note"):
            lines.append("NOTE: " + lib["note"] + "\n")
        if lib.get("eol"):
            eol = lib["eol"]
            label = eol.get("status_label")
            prefix = ("*** " + label + " *** ") if label else ""
            lines.append("Support status: " + prefix + eol["summary"] + "\n")
        if lib.get("repo_info"):
            lines.append(lib["repo_info"]["summary"] + "\n")

    lines.append("All JS/CSS resources loaded (" + str(len(data["resources_seen"])) + "):")
    for r in data["resources_seen"]:
        lines.append("  " + r)

    return "\n".join(lines)


def print_report(data):
    print(build_report_text(data))


def build_summary_rows(host, data):
    """One row per detected library/server-component, for the final
    cross-target summary table.

    Every row now gets a real, non-blank status value -- previously anything
    without an EOL/Outdated/GitHub-heuristic determination fell through to a
    bare "-", which made "we checked and it's fine" and "we had nothing to
    check it against" look identical at a glance. The taxonomy is now:
      EOL/Unsupported             -- endoflife.date-confirmed EOL.
      Unpatched/Outdated          -- endoflife.date-confirmed, not EOL, but
                                     not the absolute latest version either.
      Up-To-Date                  -- endoflife.date-confirmed to BE the
                                     absolute latest version.
      Advisories Published (GitHub) / Possibly Outdated (GitHub) /
      Up-To-Date (GitHub)         -- no endoflife.date data, but a linked
                                     GitHub source repo's release history
                                     gave a best-effort read instead (GitHub
                                     has no formal support-lifecycle concept,
                                     so these are heuristics, not a verdict).
      Unconfirmed                 -- no endoflife.date match and no linked
                                     GitHub source repo -- nothing to check
                                     this against at all.
    """
    rows = []
    for lib in data.get("libraries", []):
        eol = lib.get("eol")
        status = eol.get("status_label") if eol else None
        latest = eol.get("absolute_latest_version") if eol else None
        repo_info = lib.get("repo_info")
        if status is None and latest is None and repo_info and repo_info.get("latest_release_tag"):
            latest = repo_info["latest_release_tag"]
            if repo_info.get("advisory_count"):
                status = "Advisories Published (GitHub)"
            elif _norm_tag(repo_info["latest_release_tag"]) != _norm_tag(lib["version"]):
                status = "Possibly Outdated (GitHub)"
            else:
                status = "Up-To-Date (GitHub)"
        if status is None:
            status = "Unconfirmed"
        rows.append({
            "host": host,
            "component": lib["name"],
            "version": lib["version"],
            "status": status,
            "latest": latest or "-",
            "method": lib["method"],
        })
    for comp in data.get("server_components", []):
        eol = comp.get("eol")
        status = eol.get("status_label") if eol else None
        latest = eol.get("absolute_latest_version") if eol else None
        if status is None:
            status = "Unconfirmed"
        rows.append({
            "host": host,
            "component": comp["name"],
            "version": comp["version"],
            "status": status,
            "latest": latest or "-",
            "method": "header",
        })
    return rows


def format_summary_table(rows):
    """Plain fixed-width text table -- no third-party dependency needed."""
    if not rows:
        return "(no libraries or server components detected)"
    headers = ["Host", "Component", "Version", "Status", "Latest Available", "Detected Via"]
    cols = ["host", "component", "version", "status", "latest", "method"]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(cols):
            widths[i] = max(widths[i], len(str(r.get(c, ""))))

    def fmt_row(vals):
        return "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(vals))

    lines = [fmt_row(headers), "  ".join("-" * w for w in widths)]
    for r in rows:
        lines.append(fmt_row([r.get(c, "") for c in cols]))
    return "\n".join(lines)


def host_of(url):
    """Same thing `awk -F/ '{print $3}'` pulls out of a URL -- the
    host[:port] portion, used to name the per-target output files."""
    netloc = urlparse(url).netloc
    return netloc or re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url).split("/")[0]


def read_targets_file(path):
    """One URL per line. Blank lines and lines starting with '#' are
    skipped, so a target list can carry comments same as a hosts file."""
    targets = []
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


class _Tee:
    """Duplicates writes to both the real stream and an in-memory buffer, so
    the full terminal transcript can be captured (for bundling into the
    results zip -- see main()) without changing anything about what actually
    prints to the screen."""

    def __init__(self, real_stream, buffer):
        self.real_stream = real_stream
        self.buffer = buffer

    def write(self, s):
        self.real_stream.write(s)
        self.buffer.write(s)

    def flush(self):
        self.real_stream.flush()


def process_target(url, outdir, json_path=None, write_txt=True, check_eol=True, check_repo=True, written_files=None, extra_headers=None, extra_cookies=None):
    """Fingerprint one target, print the "=== host ===" banner + report, and
    (unless disabled) write the per-host .json/.txt files -- this is the
    native equivalent of the bash loop's `echo "=== $host ==="` / `--json
    "${host}.json"` / `tee "${host}.txt"`. If `written_files` is passed a
    list, every .json/.txt path actually written is appended to it, so the
    caller (main()) can bundle exactly this run's output files into the
    results zip. `extra_headers`/`extra_cookies` (from -r) run this target
    as an authenticated user -- see fingerprint()."""
    host = host_of(url)
    print("=== " + host + " ===")

    try:
        data = fingerprint(url, check_eol=check_eol, check_repo=check_repo, extra_headers=extra_headers, extra_cookies=extra_cookies)
    except Exception as e:
        print("ERROR fingerprinting " + url + ": " + str(e))
        return None

    report_text = build_report_text(data)
    print(report_text)

    json_out = json_path or os.path.join(outdir, host + ".json")
    with open(json_out, "w") as f:
        json.dump(data, f, indent=2)
    print("\nWrote " + json_out)
    if written_files is not None:
        written_files.append(json_out)

    if write_txt:
        txt_out = os.path.join(outdir, host + ".txt")
        with open(txt_out, "w") as f:
            f.write(report_text + "\n")
        print("Wrote " + txt_out)
        if written_files is not None:
            written_files.append(txt_out)

    return data


def main(argv=None):
    ap = argparse.ArgumentParser(description="Wappalyzer-style tech/version fingerprinter")
    ap.add_argument("url", nargs="?", help="a single target URL")
    ap.add_argument("-f", "--targets-file", help="text file with one target URL per line (blank lines and '#' comments are skipped)")
    ap.add_argument(
        "-r",
        "--request-file",
        help="file containing a captured authenticated request -- a Burp Suite 'Copy as "
        "Python-Requests' script or a 'Copy as curl-command' export -- to crawl as that logged-in "
        "user instead of anonymously (real cookies + headers, so components that only render "
        "post-login get picked up too). Replaces the 'url' argument; not combinable with -f.",
    )
    ap.add_argument("-o", "--outdir", default=".", help="directory to write the per-host .json/.txt files into (default: current directory)")
    ap.add_argument("--json", help="explicit JSON output path (single-URL mode only; ignored with --targets-file, which always auto-names per host)")
    ap.add_argument("--no-txt", action="store_true", help="don't write the per-host .txt report file (JSON is still written)")
    ap.add_argument("--no-eol", action="store_true", help="skip the endoflife.date support/EOL lookup for each detected library")
    ap.add_argument("--no-repo-check", action="store_true", help="skip source-repo detection and the GitHub release/security-advisory lookup")
    ap.add_argument("--no-zip", action="store_true", help="don't bundle the transcript/.json/.txt output into webtech_fingerprint_results.zip")
    args = ap.parse_args(argv)

    if not args.url and not args.targets_file and not args.request_file:
        ap.error("provide a URL, --targets-file, or --request-file")
    provided = [bool(args.url), bool(args.targets_file), bool(args.request_file)]
    if sum(provided) > 1:
        ap.error("provide only one of: a URL, --targets-file, --request-file")

    extra_headers = None
    extra_cookies = None
    request_file_url = None
    if args.request_file:
        try:
            request_file_url, extra_headers, extra_cookies = parse_request_file(args.request_file)
        except (OSError, ValueError) as e:
            ap.error("couldn't parse --request-file " + args.request_file + ": " + str(e))
        print("Parsed " + args.request_file + " -- target: " + request_file_url
              + ", " + str(len(extra_headers)) + " header(s), " + str(len(extra_cookies)) + " cookie(s)")

    os.makedirs(args.outdir, exist_ok=True)
    check_eol = not args.no_eol
    check_repo = not args.no_repo_check
    all_rows = []
    written_files = []

    # Everything printed from here down is captured into transcript_buffer
    # (in addition to still printing normally) so the full terminal
    # transcript -- banners, per-target reports, "Wrote ..." lines, and the
    # final SUMMARY table -- can be bundled into the results zip below.
    # Restored in the `finally` block so the zip/transcript "Wrote ..."
    # messages themselves print normally without being self-referential.
    transcript_buffer = io.StringIO()
    real_stdout = sys.stdout
    sys.stdout = _Tee(real_stdout, transcript_buffer)
    try:
        if args.targets_file:
            try:
                targets = read_targets_file(args.targets_file)
            except OSError as e:
                ap.error("couldn't read targets file " + args.targets_file + ": " + str(e))
            if not targets:
                ap.error("no targets found in " + args.targets_file)
            ok = 0
            for url in targets:
                data = process_target(url, args.outdir, write_txt=not args.no_txt, check_eol=check_eol, check_repo=check_repo, written_files=written_files)
                if data is not None:
                    ok += 1
                    all_rows.extend(build_summary_rows(host_of(url), data))
            print("\n" + str(ok) + "/" + str(len(targets)) + " targets completed successfully.")
        elif args.request_file:
            data = process_target(request_file_url, args.outdir, json_path=args.json, write_txt=not args.no_txt, check_eol=check_eol, check_repo=check_repo, written_files=written_files, extra_headers=extra_headers, extra_cookies=extra_cookies)
            if data is not None:
                all_rows.extend(build_summary_rows(host_of(request_file_url), data))
        else:
            data = process_target(args.url, args.outdir, json_path=args.json, write_txt=not args.no_txt, check_eol=check_eol, check_repo=check_repo, written_files=written_files)
            if data is not None:
                all_rows.extend(build_summary_rows(host_of(args.url), data))

        if all_rows:
            # Split into the same two groups the downstream report-writing
            # skill uses ("Version Status Confirmed" / "Version Status NOT
            # Confirmed"), so this terminal table and that Word doc always
            # agree on which components got a real determination vs. which
            # ones automation had nothing to check at all.
            confirmed_rows = [r for r in all_rows if r["status"] != "Unconfirmed"]
            unconfirmed_rows = [r for r in all_rows if r["status"] == "Unconfirmed"]
            print("\n" + "=" * 78)
            print("SUMMARY")
            print("=" * 78)
            print("\nVersion Status Confirmed")
            print(format_summary_table(confirmed_rows))
            print("\nVersion Status NOT Confirmed")
            print(format_summary_table(unconfirmed_rows))
    finally:
        sys.stdout = real_stdout

    if not args.no_zip:
        transcript_path = os.path.join(args.outdir, "webtech_fingerprint_transcript.txt")
        with open(transcript_path, "w", encoding="utf-8") as f:
            f.write(transcript_buffer.getvalue())

        zip_path = os.path.join(args.outdir, "webtech_fingerprint_results.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(transcript_path, arcname=os.path.basename(transcript_path))
            for path in written_files:
                if os.path.exists(path):
                    zf.write(path, arcname=os.path.basename(path))
        print("Wrote " + transcript_path)
        print("Wrote " + zip_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
