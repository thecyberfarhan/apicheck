"""Individual checks. Each returns a list of Finding. Standard library only.

Every check sends a small number of ordinary requests. Nothing here exploits anything:
findings are indicators to verify by hand.
"""
from __future__ import annotations

import http.client
import json
import ssl
import urllib.parse
from dataclasses import dataclass, asdict

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    fix: str

    def to_dict(self) -> dict:
        return asdict(self)


class Target:
    """Small HTTP client bound to one base URL."""

    def __init__(self, base: str, timeout: float = 5.0, token: str | None = None):
        u = urllib.parse.urlparse(base)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("base URL must look like http://host[:port]")
        self.scheme, self.host = u.scheme, u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.prefix = u.path.rstrip("/")
        self.timeout, self.token = timeout, token
        self.requests = 0

    @property
    def base(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}{self.prefix}"

    def request(self, method: str, path: str, headers: dict | None = None, auth: bool = False, body: bytes | None = None):
        """Return (status, headers dict with lower-case names, raw Set-Cookie list, body bytes) or None."""
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        h = {"User-Agent": "apicheck/1.0", "Accept": "*/*"}
        h.update(headers or {})
        if auth and self.token:
            h["Authorization"] = f"Bearer {self.token}"
        try:
            conn.request(method, self.prefix + path, body=body, headers=h)
            r = conn.getresponse()
            data = r.read(262144)
            cookies = r.msg.get_all("Set-Cookie") or []
            self.requests += 1
            return r.status, {k.lower(): v for k, v in r.getheaders()}, cookies, data
        except (OSError, http.client.HTTPException):
            return None
        finally:
            conn.close()


def check_headers(t: Target) -> list:
    res = t.request("GET", "/")
    if not res:
        return [Finding("connect", "info", "Target did not answer", f"No response from {t.base}", "Check the URL and that the service is up.")]
    _, h, _, _ = res
    out = []
    wanted = {
        "content-security-policy": ("medium", "Content-Security-Policy missing", "Add a CSP that limits script and frame sources."),
        "x-content-type-options": ("low", "X-Content-Type-Options missing", "Send X-Content-Type-Options: nosniff."),
        "x-frame-options": ("low", "Clickjacking protection missing", "Send X-Frame-Options: DENY or a CSP frame-ancestors rule."),
        "referrer-policy": ("low", "Referrer-Policy missing", "Send Referrer-Policy: strict-origin-when-cross-origin."),
    }
    if t.scheme == "https":
        wanted["strict-transport-security"] = ("medium", "HSTS missing", "Send Strict-Transport-Security with a long max-age.")
    for key, (sev, title, fix) in wanted.items():
        if key == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
            continue
        if key not in h:
            out.append(Finding("headers", sev, title, f"Response to GET / has no {key} header.", fix))
    for key in ("server", "x-powered-by", "x-aspnet-version"):
        if key in h and any(c.isdigit() for c in h[key]):
            out.append(Finding("headers", "info", "Version disclosed in header", f"{key}: {h[key]}", "Hide or genericise version strings."))
    return out


def check_cookies(t: Target) -> list:
    res = t.request("GET", "/")
    if not res:
        return []
    out = []
    for c in res[2]:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if t.scheme == "https" and "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            out.append(Finding("cookies", "medium" if "HttpOnly" in missing and "sess" in name.lower() else "low",
                               f"Cookie '{name}' lacks {', '.join(missing)}", c[:120],
                               "Set HttpOnly, Secure (on HTTPS) and SameSite on session cookies."))
    return out


def check_cors(t: Target) -> list:
    evil = "https://evil.example"
    res = t.request("GET", "/", headers={"Origin": evil})
    if not res:
        return []
    h = res[1]
    acao, acac = h.get("access-control-allow-origin", ""), h.get("access-control-allow-credentials", "").lower()
    if acao == evil and acac == "true":
        return [Finding("cors", "high", "CORS reflects any origin with credentials", f"Origin {evil} was echoed with Allow-Credentials: true.",
                        "Use an allow-list of origins; never reflect Origin when credentials are allowed.")]
    if acao == evil:
        return [Finding("cors", "medium", "CORS reflects arbitrary origins", f"Origin {evil} was echoed.", "Use an allow-list of origins.")]
    if acao == "*" and acac == "true":
        return [Finding("cors", "medium", "Wildcard CORS with credentials header", "Allow-Origin * together with Allow-Credentials true.", "Remove the wildcard or the credentials header.")]
    return []


def check_methods(t: Target) -> list:
    out = []
    res = t.request("TRACE", "/")
    if res and res[0] == 200 and b"TRACE" in res[3][:200]:
        out.append(Finding("methods", "low", "TRACE method enabled", "The server echoed a TRACE request.", "Disable TRACE."))
    res = t.request("OPTIONS", "/")
    if res:
        allow = res[1].get("allow", "")
        risky = [m for m in ("PUT", "DELETE", "PATCH") if m in allow.upper()]
        if risky:
            out.append(Finding("methods", "low", "Write methods advertised", f"Allow: {allow}", "Confirm these methods need authentication and are intended on this path."))
    return out


SENSITIVE = [
    ("/.git/HEAD", b"ref:", "high", "Git repository exposed"),
    ("/.env", b"=", "high", "Environment file exposed"),
    ("/.DS_Store", b"Bud1", "low", "macOS metadata file exposed"),
    ("/phpinfo.php", b"phpinfo", "medium", "phpinfo page exposed"),
    ("/server-status", b"Apache Server Status", "medium", "Apache server-status exposed"),
    ("/backup.zip", b"PK", "high", "Backup archive exposed"),
    ("/config.php.bak", b"<?php", "high", "Config backup exposed"),
    ("/robots.txt", b"Disallow", "info", "robots.txt lists paths worth a look"),
    ("/swagger.json", b'"paths"', "info", "OpenAPI document published"),
    ("/openapi.json", b'"paths"', "info", "OpenAPI document published"),
    ("/api/docs", b"", "info", "API docs path answers"),
]


def check_sensitive(t: Target) -> list:
    out = []
    baseline = t.request("GET", "/apicheck-does-not-exist-9f3a")
    soft404 = bool(baseline and baseline[0] == 200)
    for path, marker, sev, title in SENSITIVE:
        res = t.request("GET", path)
        if not res or res[0] != 200:
            continue
        if soft404 and baseline and res[3][:200] == baseline[3][:200]:
            continue
        if marker and marker not in res[3][:4096]:
            continue
        if not marker and not res[3]:
            continue
        out.append(Finding("exposure", sev, title, f"GET {path} returned 200 ({len(res[3])} bytes).",
                           "Remove the file from the web root or block access to it."))
    return out


def check_listing(t: Target, paths=("/", "/uploads/", "/images/", "/static/", "/config/", "/docs/", "/backup/")) -> list:
    out = []
    for p in paths:
        res = t.request("GET", p)
        if res and res[0] == 200 and (b"Index of /" in res[3][:2048] or b"<title>Directory listing" in res[3][:2048]):
            out.append(Finding("listing", "medium", "Directory listing enabled", f"GET {p} shows a file index.", "Disable autoindex or add an index file."))
    return out


def check_errors(t: Target) -> list:
    res = t.request("GET", "/%27%22%3C%00")
    if not res:
        return []
    body = res[3][:8192].lower()
    for marker, what in ((b"traceback (most recent call last)", "Python stack trace"), (b"at java.", "Java stack trace"),
                         (b"fatal error", "PHP fatal error"), (b"sql syntax", "SQL error text"), (b"stack trace:", "stack trace")):
        if marker in body:
            return [Finding("errors", "medium", f"Verbose error output ({what})", "A malformed path produced an error page that exposes internals.",
                            "Return a generic error page and log details server-side.")]
    return []


def check_auth(t: Target, endpoints: list) -> list:
    """For each endpoint: request with and without the token. Same 200 response without a token is a finding."""
    out = []
    for ep in endpoints:
        anon = t.request("GET", ep)
        if not anon:
            continue
        if anon[0] == 200:
            if t.token:
                authed = t.request("GET", ep, auth=True)
                same = bool(authed and authed[0] == 200 and authed[3] == anon[3])
                if same:
                    out.append(Finding("auth", "high", f"{ep} answers without credentials", "The response with no token matches the response with a token.",
                                       "Require authentication and authorisation on this endpoint (verify by hand)."))
            else:
                out.append(Finding("auth", "info", f"{ep} answers without credentials", "Returned 200 with no token. Pass --token to compare; verify whether this data is meant to be public.",
                                   "If the endpoint is private, require authentication."))
    return out


def endpoints_from_openapi(t: Target) -> list:
    for path in ("/openapi.json", "/swagger.json", "/v2/api-docs"):
        res = t.request("GET", path)
        if res and res[0] == 200:
            try:
                doc = json.loads(res[3])
            except ValueError:
                continue
            return [p for p, ops in doc.get("paths", {}).items() if "get" in {k.lower() for k in ops} and "{" not in p]
    return []


ALL_CHECKS = [check_headers, check_cookies, check_cors, check_methods, check_sensitive, check_listing, check_errors]
