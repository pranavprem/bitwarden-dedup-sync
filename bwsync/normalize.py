"""URL and username normalisation used to decide when two entries are "the same site".

Grouping is only as good as this module. Two entries are candidates for merging
only when their *registrable domain* and username both normalise to the same
value, so getting the domain boundary right is what prevents both false merges
(collapsing two unrelated accounts) and false splits (leaving obvious dupes).
"""

from __future__ import annotations

import base64
import re
from urllib.parse import unquote, urlsplit

# Multi-label public suffixes. A full Public Suffix List is ~10k entries and
# would need network refresh; this curated set covers the country-code SLDs and
# the shared-hosting domains that realistically show up in a password vault.
# Anything not listed falls back to "last two labels", which is correct for the
# overwhelming majority of gTLDs.
_MULTI_LABEL_SUFFIXES = frozenset(
    """
    co.uk org.uk me.uk ac.uk gov.uk net.uk sch.uk ltd.uk plc.uk
    com.au net.au org.au edu.au gov.au id.au asn.au
    co.nz net.nz org.nz govt.nz ac.nz
    co.in net.in org.in gen.in firm.in ind.in ac.in edu.in res.in gov.in nic.in
    co.jp or.jp ne.jp ac.jp go.jp ad.jp ed.jp gr.jp lg.jp
    com.br net.br org.br gov.br edu.br
    com.cn net.cn org.cn gov.cn edu.cn ac.cn
    co.kr or.kr ne.kr re.kr pe.kr go.kr ac.kr
    com.mx org.mx net.mx gob.mx edu.mx
    co.za org.za net.za gov.za ac.za web.za
    com.sg net.sg org.sg edu.sg gov.sg
    com.hk net.hk org.hk edu.hk gov.hk idv.hk
    com.tw net.tw org.tw edu.tw gov.tw
    com.tr net.tr org.tr gov.tr edu.tr
    com.ar net.ar org.ar gob.ar edu.ar
    com.co net.co org.co gov.co edu.co
    co.il org.il net.il ac.il gov.il
    com.my net.my org.my gov.my edu.my
    com.ph net.ph org.ph gov.ph edu.ph
    co.th in.th ac.th go.th or.th
    com.vn net.vn org.vn gov.vn edu.vn
    co.id or.id ac.id go.id web.id my.id
    com.pl net.pl org.pl gov.pl edu.pl
    com.ua com.ru net.ru org.ru
    com.es com.pt com.gr com.pe com.ec com.uy com.ve com.do com.gt
    com.sa com.eg com.ng com.gh com.kw com.qa com.bh com.om
    com.pk com.bd com.lk com.np
    co.ke co.tz co.ug co.zw co.ma
    """.split()
)

# Shared-hosting domains where each subdomain is a *different* site and account.
# Without these, every foo.atlassian.net would collapse into one group.
_SHARED_HOSTING_SUFFIXES = frozenset(
    """
    github.io gitlab.io herokuapp.com appspot.com azurewebsites.net
    vercel.app netlify.app netlify.com pages.dev workers.dev
    firebaseapp.com web.app glitch.me repl.co replit.dev ngrok.io ngrok-free.app
    blogspot.com wordpress.com tumblr.com myshopify.com bigcartel.com
    zendesk.com freshdesk.com atlassian.net jira.com sharepoint.com
    slack.com service-now.com okta.com onelogin.com auth0.com
    lightning.force.com my.salesforce.com salesforce.com
    sentry.io statuspage.io readthedocs.io surge.sh fly.dev
    """.split()
)

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Chrome exports Android app credentials as
#   android://<base64-sha256>==@com.example.app/
_ANDROID_RE = re.compile(r"^android://[^@]*@([A-Za-z0-9_.\-]+)/?", re.IGNORECASE)

# Apple/iOS occasionally emit bare reverse-DNS bundle ids as the "URL".
_BUNDLE_ID_RE = re.compile(r"^[a-z0-9_\-]+(\.[a-z0-9_\-]+){2,}$", re.IGNORECASE)

# Android/iOS bundle prefixes that carry no organisation information; the
# organisation label sits one position further right (e.g. com.google.android.gm).
_GENERIC_BUNDLE_LABELS = frozenset({"com", "net", "org", "io", "co", "app", "me", "dev"})


def _strip_port(host: str) -> str:
    # Bracketed IPv6 literals keep their brackets; only a trailing :port is cut.
    if host.startswith("["):
        end = host.find("]")
        return host[: end + 1] if end != -1 else host
    return host.split(":", 1)[0]


def package_to_domain(package: str) -> str:
    """Convert a reverse-DNS app id to its most likely web domain.

    com.spotify.music        -> spotify.com
    com.google.android.gm    -> google.com
    org.mozilla.firefox      -> mozilla.org

    This is a heuristic, and a deliberately conservative one: it only ever
    yields a two-label domain, so a wrong guess groups an app with its own
    website rather than with an unrelated service.
    """
    labels = [label for label in package.lower().split(".") if label]
    if len(labels) < 2:
        return package.lower()
    tld, org = labels[0], labels[1]
    if tld in _GENERIC_BUNDLE_LABELS and org in _GENERIC_BUNDLE_LABELS and len(labels) > 2:
        org = labels[2]
    return f"{org}.{tld}"


def extract_host(url: str) -> str:
    """Pull a bare hostname out of anything a password manager calls a "URL"."""
    if not url:
        return ""
    text = unquote(url.strip()).strip()
    if not text:
        return ""

    android = _ANDROID_RE.match(text)
    if android:
        return package_to_domain(android.group(1))

    lowered = text.lower()
    for prefix in ("androidapp://", "ios://", "iosapp://", "app://"):
        if lowered.startswith(prefix):
            return package_to_domain(text[len(prefix) :].strip("/"))

    # Apple exports sometimes carry a trailing label: "https://x.com (Work)".
    text = text.split(" ", 1)[0]

    if "//" not in text:
        # Bare "example.com/login" or a naked bundle id.
        if _BUNDLE_ID_RE.match(text) and "/" not in text:
            known_tlds_last = text.lower().rsplit(".", 1)[-1]
            # "com.spotify.music" reads as a bundle; "mail.google.com" does not.
            if text.lower().split(".", 1)[0] in _GENERIC_BUNDLE_LABELS and known_tlds_last not in {
                "com",
                "net",
                "org",
            }:
                return package_to_domain(text)
        text = "//" + text

    parts = urlsplit(text if "//" in text else "//" + text)
    host = parts.netloc or parts.path
    host = host.split("/", 1)[0]
    if "@" in host:  # strip userinfo
        host = host.rsplit("@", 1)[1]
    host = _strip_port(host).strip().strip(".").lower()
    return host


def registrable_domain(host: str) -> str:
    """Reduce a hostname to the unit that identifies one account namespace."""
    if not host:
        return ""
    if host.startswith("[") or _IPV4_RE.match(host):
        return host  # IP literals are their own identity
    if host == "localhost":
        return host

    labels = host.split(".")
    if len(labels) < 2:
        return host

    # Shared hosting: keep one label above the platform suffix.
    for depth in (3, 2, 1):
        if len(labels) > depth:
            candidate = ".".join(labels[-depth:])
            if candidate in _SHARED_HOSTING_SUFFIXES:
                return ".".join(labels[-(depth + 1) :])

    two = ".".join(labels[-2:])
    if two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return two


def domain_key(urls: tuple[str, ...] | list[str], name: str = "") -> str:
    """The domain half of a grouping key.

    Uses the first URL that yields a registrable domain. Falls back to the entry
    title so that URL-less entries ("Wi-Fi router", "Bank PIN") still group with
    their own duplicates instead of collapsing into one giant blank bucket.
    """
    for url in urls:
        domain = registrable_domain(extract_host(url))
        if domain:
            return domain
    fallback = re.sub(r"\s+", " ", (name or "").strip().lower())
    return f"name:{fallback}" if fallback else ""


def username_key(username: str, aggressive: bool = False) -> str:
    """The username half of a grouping key.

    Default is case-folding and whitespace trimming only. `aggressive` also
    canonicalises Gmail-style addresses (dots and +tags are ignored by Google),
    which merges more but can merge accounts a user considers separate — hence
    opt-in.
    """
    key = (username or "").strip().lower()
    if not key or not aggressive or "@" not in key:
        return key
    local, _, domain = key.rpartition("@")
    if domain in {"gmail.com", "googlemail.com"}:
        local = local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"
    else:
        local = local.split("+", 1)[0]
    return f"{local}@{domain}"


def normalize_uri(url: str) -> str:
    """Canonical form used to de-duplicate the URI list on a merged item."""
    host = extract_host(url)
    return host[4:] if host.startswith("www.") else host
