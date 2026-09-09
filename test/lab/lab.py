"""Shared plumbing for the lab traffic generators.

These scripts drive traffic at a local proxy-waf instance so its detection,
recording and tuning views can be exercised against realistic input. They are
deliberately restricted to the local lab: the target must resolve to a loopback
address, and only lab hostnames are accepted.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import ssl
import sys
import urllib3

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Hostnames the lab serves. Anything else is refused.
LAB_HOSTS = ("shop.local", "api.local", "blog.local", "demo.local", "fresh.local", "lab.local")

DEFAULT_ADDR = "127.0.0.1"
DEFAULT_PORT = 8443


class RefusedTarget(RuntimeError):
    """Raised when a target is not the local lab."""


def install_lab_dns(addr: str = DEFAULT_ADDR) -> None:
    """Resolve the lab hostnames to addr for this process only.

    This is what lets the scripts use real hostnames, so SNI, the Host header
    and the certificate's SAN list all line up, without touching /etc/hosts.
    """
    if not ipaddress.ip_address(addr).is_loopback:
        raise RefusedTarget(
            f"refusing to run against {addr}: these scripts only drive a local lab"
        )

    original = socket.getaddrinfo

    def patched(host, port, family=0, type=0, proto=0, flags=0):
        if host in LAB_HOSTS:
            return original(addr, port, family, type, proto, flags)
        return original(host, port, family, type, proto, flags)

    socket.getaddrinfo = patched


def check_host(host: str) -> str:
    """Return host if it is a lab hostname, otherwise refuse."""
    if host not in LAB_HOSTS:
        raise RefusedTarget(
            f"{host!r} is not a lab hostname. Allowed: {', '.join(LAB_HOSTS)}"
        )
    return host


def base_url(host: str, port: int = DEFAULT_PORT) -> str:
    return f"https://{check_host(host)}:{port}"


# Browsers, crawlers and tools, so the recorded traffic has a realistic spread
# of user agents and TLS fingerprints.
BROWSERS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.6 Safari/605.1.15",
]

CRAWLERS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
]

SCANNERS = [
    "sqlmap/1.8.2#stable (https://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)",
    "Wget/1.21.4",
    "python-requests/2.32.5",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
]


def session(user_agent: str, source_ip: str | None = None) -> requests.Session:
    """Build a session with a fixed user agent and claimed source address.

    The proxy believes X-Forwarded-For only from an address inside the app's
    trusted_cidrs. The lab trusts the Docker gateway, which is what makes these
    synthetic source addresses show up as distinct clients.
    """
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = user_agent
    s.headers["Accept-Language"] = random.choice(["en-GB,en;q=0.9", "en-US,en;q=0.8", "de-DE,de;q=0.7"])
    if source_ip:
        s.headers["X-Forwarded-For"] = source_ip
    return s


def random_public_ip() -> str:
    """An address from a documentation range, so nothing real is implied."""
    block = random.choice(["203.0.113", "198.51.100", "192.0.2"])
    return f"{block}.{random.randint(2, 250)}"


def request(sess: requests.Session, method: str, url: str, **kwargs) -> int:
    """Send one request, returning the status code. Failures are not fatal."""
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("allow_redirects", False)
    try:
        return sess.request(method, url, **kwargs).status_code
    except requests.RequestException as exc:
        print(f"  ! {method} {url}: {exc}", file=sys.stderr)
        return 0


def tls_context_for(profile: str) -> ssl.SSLContext:
    """A TLS configuration per client profile, so JA3/JA4 differ between them."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if profile == "legacy":
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx
