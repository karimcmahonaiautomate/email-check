#!/usr/bin/env python3
"""
emailcheck.py - verify an email address and find likely emails for a person.

Install:   pip install dnspython
Usage:
    python emailcheck.py verify jane@example.com
    python emailcheck.py verify jane@example.com --json
    python emailcheck.py find "Jane Doe" example.com
    python emailcheck.py find "Jane Doe" example.com --scan-site --all

Verification layers (same approach as Hunter.io / ZeroBounce etc.):
    1. Syntax check
    2. Disposable / role-account / free-provider flags
    3. DNS MX lookup (can the domain receive mail at all?)
    4. SMTP handshake: ask the mail server "would you accept RCPT TO:<email>?"
       (no email is actually sent)
    5. Catch-all detection (server says yes to everything -> result is "risky")

IMPORTANT LIMITS
    * Many home ISPs and cloud hosts (AWS, GCP, Azure, DigitalOcean) block outbound
      port 25. If so, you will get "unknown". Run it from a VPS that allows port 25.
    * Microsoft 365 / Google Workspace / Yahoo and some corporate gateways often
      accept all recipients or throttle probes, so results can be "risky"/"unknown".
    * Set --helo and --from to a real domain you control; be polite, don't bulk-hammer servers.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import smtplib
import socket
import ssl
import string
import sys
import time
import urllib.request
from dataclasses import dataclass, field, asdict

try:
    import dns.resolver
    import dns.exception
except ImportError:
    sys.exit("Missing dependency. Run: pip install dnspython")

# --------------------------------------------------------------------------- #
# Reference data (extend as needed)
# --------------------------------------------------------------------------- #
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "yopmail.com", "trashmail.com", "sharklasers.com",
    "getnada.com", "throwawaymail.com", "dispostable.com", "maildrop.cc",
    "fakeinbox.com", "mailnesia.com", "mintemail.com", "mohmal.com",
}
FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
    "gmx.com", "zoho.com", "yandex.com", "mail.com",
}
ROLE_ACCOUNTS = {
    "admin", "administrator", "info", "contact", "sales", "support", "help",
    "billing", "accounts", "hr", "jobs", "careers", "press", "media", "marketing",
    "office", "postmaster", "webmaster", "hostmaster", "abuse", "noreply",
    "no-reply", "team", "hello", "enquiries", "inquiries", "legal", "security",
}

EMAIL_RE = re.compile(
    r"^(?=.{1,254}$)(?=.{1,64}@)"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+(?<!\.)@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


@dataclass
class Result:
    email: str
    status: str = "unknown"          # valid | invalid | risky | unknown
    reason: str = ""
    syntax_ok: bool = False
    disposable: bool = False
    role_account: bool = False
    free_provider: bool = False
    mx_records: list = field(default_factory=list)
    smtp_code: int | None = None
    smtp_message: str = ""
    catch_all: bool | None = None
    score: int = 0                   # 0-100 confidence the address is deliverable


# --------------------------------------------------------------------------- #
# Core checks
# --------------------------------------------------------------------------- #
def get_mx_hosts(domain: str, timeout: float = 8.0) -> list[str]:
    """Return MX hosts sorted by priority. Falls back to A record per RFC 5321."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(domain, "MX")
        hosts = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in hosts if str(r.exchange) != "."]
    except (dns.resolver.NoAnswer):
        try:  # implicit MX
            resolver.resolve(domain, "A")
            return [domain]
        except dns.exception.DNSException:
            return []
    except dns.exception.DNSException:
        return []


DEBUG = False


def _rcpt_session(host: str, email: str, helo: str, mail_from: str,
                  timeout: float, use_tls: bool) -> tuple[int, str]:
    # Passing host here connects immediately and records the hostname, which
    # starttls() needs on Python 3.9 and older.
    smtp = smtplib.SMTP(host, 25, local_hostname=helo, timeout=timeout)
    if DEBUG:
        smtp.set_debuglevel(1)
    try:
        smtp.ehlo(helo)
        if use_tls and smtp.has_extn("starttls"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False       # MX certs are often mismatched; we only
            ctx.verify_mode = ssl.CERT_NONE  # need the mailbox answer, not trust
            smtp.starttls(context=ctx)       # on failure we raise and retry without TLS
            smtp.ehlo(helo)
        code, msg = smtp.mail(mail_from)
        if code >= 400:
            return code, msg.decode(errors="ignore")
        code, msg = smtp.rcpt(email)
        return code, msg.decode(errors="ignore")
    finally:
        try:
            smtp.quit()
        except Exception:
            smtp.close()


def smtp_rcpt(email: str, mx_hosts: list[str], helo: str, mail_from: str,
              timeout: float) -> tuple[int | None, str]:
    """Ask the MX server RCPT TO. Never sends DATA, so no mail is sent.
    Tries with STARTTLS first, then plain, for each of the first 3 MX hosts."""
    last_err = "could not connect to any MX host on port 25"
    for host in mx_hosts[:3]:
        for use_tls in (True, False):
            try:
                return _rcpt_session(host, email, helo, mail_from, timeout, use_tls)
            except (socket.timeout, TimeoutError):
                last_err = f"{host}: timed out (port 25 blocked or server not responding)"
                break                # no point retrying without TLS on a timeout
            except (smtplib.SMTPException, OSError, ValueError) as e:
                last_err = f"{host}: {type(e).__name__}: {e} ({'with' if use_tls else 'without'} TLS)"
    return None, last_err


def random_local() -> str:
    return "zz" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))


def check_catch_all(domain: str, mx_hosts, helo, mail_from, timeout) -> bool | None:
    code, _ = smtp_rcpt(f"{random_local()}@{domain}", mx_hosts, helo, mail_from, timeout)
    if code is None:
        return None
    return 200 <= code < 300


def verify_email(email: str, helo="example.com", mail_from="verify@example.com",
                 timeout=10.0, skip_smtp=False, mx_cache: dict | None = None,
                 catch_all_cache: dict | None = None) -> Result:
    email = email.strip()
    r = Result(email=email)

    # 1. Syntax
    if not EMAIL_RE.match(email):
        r.status, r.reason = "invalid", "Invalid syntax"
        return r
    r.syntax_ok = True
    local, domain = email.rsplit("@", 1)
    domain = domain.lower()

    # 2. Flags
    r.disposable = domain in DISPOSABLE_DOMAINS
    r.role_account = local.lower() in ROLE_ACCOUNTS
    r.free_provider = domain in FREE_PROVIDERS
    if r.disposable:
        r.status, r.reason = "invalid", "Disposable email domain"
        return r

    # 3. MX
    mx_cache = mx_cache if mx_cache is not None else {}
    if domain not in mx_cache:
        mx_cache[domain] = get_mx_hosts(domain)
    r.mx_records = mx_cache[domain]
    if not r.mx_records:
        r.status, r.reason = "invalid", "Domain has no mail server (no MX/A record)"
        return r
    if skip_smtp:
        r.status, r.reason, r.score = "unknown", "MX found; SMTP check skipped", 40
        return r

    # 4. SMTP RCPT TO
    code, msg = smtp_rcpt(email, r.mx_records, helo, mail_from, timeout)
    r.smtp_code, r.smtp_message = code, msg[:200]

    if code is None:
        r.status = "unknown"
        r.reason = f"Could not complete SMTP check ({msg}). Port 25 may be blocked."
        r.score = 40
        return r

    if code in (250, 251):
        # 5. Catch-all
        catch_all_cache = catch_all_cache if catch_all_cache is not None else {}
        if domain not in catch_all_cache:
            catch_all_cache[domain] = check_catch_all(domain, r.mx_records, helo, mail_from, timeout)
        r.catch_all = catch_all_cache[domain]
        if r.catch_all:
            r.status, r.reason, r.score = "risky", "Server accepts all addresses (catch-all); can't confirm mailbox", 55
        else:
            r.status, r.reason, r.score = "valid", "Mailbox accepted by server", 95
            if r.role_account:
                r.reason += " (role account, e.g. info@/sales@)"
                r.score = 80
    elif code in (550, 551, 553, 554, 511, 513):
        r.status, r.reason, r.score = "invalid", "Mailbox does not exist / rejected", 3
        low = msg.lower()
        if any(k in low for k in ("spam", "blocked", "blacklist", "denied", "policy", "reputation")):
            r.status, r.reason, r.score = "unknown", "Rejected for policy/reputation reasons, not mailbox status", 30
    elif code in (450, 451, 452, 421):
        r.status, r.reason, r.score = "unknown", "Temporary failure / greylisting; try again later", 40
    else:
        r.status, r.reason, r.score = "unknown", f"Unclear SMTP response ({code})", 35
    return r


# --------------------------------------------------------------------------- #
# Email finder
# --------------------------------------------------------------------------- #
# Ordered roughly by how common each pattern is in practice.
PATTERNS = [
    "{first}.{last}", "{first}", "{f}{last}", "{first}{last}", "{first}{l}",
    "{f}.{last}", "{last}", "{first}_{last}", "{last}.{first}", "{last}{f}",
    "{first}-{last}", "{f}{l}", "{last}{first}", "{first}.{l}", "{l}{first}",
]


def clean(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def candidate_emails(full_name: str, domain: str) -> list[str]:
    parts = full_name.strip().split()
    if len(parts) < 2:
        sys.exit("Please provide first and last name, e.g. \"Jane Doe\"")
    first, last = clean(parts[0]), clean(parts[-1])
    vals = {"first": first, "last": last, "f": first[:1], "l": last[:1]}
    seen, out = set(), []
    for p in PATTERNS:
        addr = f"{p.format(**vals)}@{domain}"
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def scan_site_for_emails(domain: str, timeout=8) -> list[str]:
    """Look for publicly listed emails on the company's own website (to infer the pattern)."""
    found = set()
    paths = ["", "/contact", "/about", "/team", "/about-us", "/contact-us", "/press"]
    pat = re.compile(r"[A-Za-z0-9._%+-]+@" + re.escape(domain), re.I)
    for path in paths:
        for scheme in ("https://",):
            url = f"{scheme}{domain}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (emailcheck)"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    html = resp.read(500_000).decode("utf-8", errors="ignore")
                found.update(m.lower() for m in pat.findall(html))
            except Exception:
                continue
    return sorted(found)


def infer_pattern_hint(known_emails: list[str]) -> str | None:
    """Very rough guess at the company's format from a few known addresses."""
    for e in known_emails:
        local = e.split("@")[0]
        if local in ROLE_ACCOUNTS:
            continue
        if "." in local:
            a, b = local.split(".", 1)
            return "{first}.{last}" if len(a) > 1 and len(b) > 1 else "{f}.{last}"
        if "_" in local:
            return "{first}_{last}"
    return None


def find_email(full_name, domain, helo, mail_from, timeout, scan_site, find_all, delay):
    domain = domain.lower().strip()
    candidates = candidate_emails(full_name, domain)

    hint = None
    if scan_site:
        print(f"[*] Scanning {domain} for publicly listed emails...")
        known = scan_site_for_emails(domain)
        if known:
            print(f"    Found: {', '.join(known[:10])}")
            hint = infer_pattern_hint(known)
            if hint:
                print(f"    Pattern hint: {hint}")
        else:
            print("    Nothing found.")
    if hint:  # move hinted pattern to the front
        parts = full_name.split()
        first, last = clean(parts[0]), clean(parts[-1])
        top = hint.format(first=first, last=last, f=first[:1], l=last[:1]) + "@" + domain
        candidates = [top] + [c for c in candidates if c != top]

    mx_cache, ca_cache = {}, {}
    mx = get_mx_hosts(domain)
    mx_cache[domain] = mx
    if not mx:
        sys.exit(f"[!] {domain} has no mail server. Check the domain.")

    print(f"[*] Checking whether {domain} is a catch-all...")
    ca = check_catch_all(domain, mx, helo, mail_from, timeout)
    ca_cache[domain] = ca
    if ca is None:
        print("[!] Couldn't reach the mail server on port 25 (blocked?). Showing ranked guesses only:\n")
        for i, c in enumerate(candidates, 1):
            print(f"  {i:>2}. {c}")
        return
    if ca:
        print("[!] Catch-all domain: the server accepts every address, so guesses can't be confirmed.")
        print("    Ranked by pattern popularity:\n")
        for i, c in enumerate(candidates[:8], 1):
            print(f"  {i:>2}. {c}")
        return

    print(f"[*] Testing {len(candidates)} candidate addresses...\n")
    hits = []
    for c in candidates:
        res = verify_email(c, helo, mail_from, timeout, mx_cache=mx_cache, catch_all_cache=ca_cache)
        mark = {"valid": "✔", "invalid": "✘", "risky": "?", "unknown": "?"}[res.status]
        print(f"  {mark} {c:<45} {res.status:<8} {res.reason}")
        if res.status == "valid":
            hits.append(c)
            if not find_all:
                break
        time.sleep(delay)

    print()
    if hits:
        print("Most likely email(s):", ", ".join(hits))
    else:
        print("No confirmed match. The person may use a different format, or the server hides mailbox status.")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def print_result(r: Result):
    icon = {"valid": "✔", "invalid": "✘", "risky": "⚠", "unknown": "?"}[r.status]
    print(f"\n{icon} {r.email}  ->  {r.status.upper()}  (score {r.score}/100)")
    print(f"  Reason       : {r.reason}")
    print(f"  Syntax OK    : {r.syntax_ok}")
    print(f"  Disposable   : {r.disposable}")
    print(f"  Role account : {r.role_account}")
    print(f"  Free provider: {r.free_provider}")
    print(f"  MX records   : {', '.join(r.mx_records) or '-'}")
    if r.smtp_code:
        print(f"  SMTP response: {r.smtp_code} {r.smtp_message}")
    if r.catch_all is not None:
        print(f"  Catch-all    : {r.catch_all}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Verify emails and find likely email addresses.")
    ap.add_argument("--helo", default="example.com", help="Your server's hostname for EHLO (use a real domain)")
    ap.add_argument("--from", dest="mail_from", default="verify@example.com", help="MAIL FROM address (use a real one you control)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--debug", action="store_true", help="Print the raw SMTP conversation")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="Verify one or more emails")
    v.add_argument("emails", nargs="+")
    v.add_argument("--json", action="store_true")
    v.add_argument("--no-smtp", action="store_true", help="Only syntax + DNS checks")

    f = sub.add_parser("find", help="Find a person's likely email")
    f.add_argument("name", help='Full name, e.g. "Jane Doe"')
    f.add_argument("domain", help="Company domain, e.g. acme.com")
    f.add_argument("--scan-site", action="store_true", help="Look for emails on the company website to infer format")
    f.add_argument("--all", action="store_true", help="Keep going after the first valid hit")
    f.add_argument("--delay", type=float, default=1.5, help="Seconds between probes (be polite)")

    a = ap.parse_args()
    global DEBUG
    DEBUG = a.debug

    if a.cmd == "verify":
        mx_cache, ca_cache, results = {}, {}, []
        for e in a.emails:
            res = verify_email(e, a.helo, a.mail_from, a.timeout, a.no_smtp, mx_cache, ca_cache)
            results.append(res)
            if not a.json:
                print_result(res)
        if a.json:
            print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        find_email(a.name, a.domain, a.helo, a.mail_from, a.timeout, a.scan_site, a.all, a.delay)


if __name__ == "__main__":
    main()
