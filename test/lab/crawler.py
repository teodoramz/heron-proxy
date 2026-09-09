#!/usr/bin/env python3
"""Drives realistic visitor traffic at the lab.

Each visitor keeps a session, moves through pages with think time, and
occasionally posts a form or calls the API. The point is to give the analyser a
believable baseline, so attack traffic stands out against something rather than
against an empty table.

    python3 test/lab/crawler.py --visitors 8 --duration 120
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import lab  # noqa: E402

# A shallow site map per app, with rough weights for how often each is hit.
JOURNEYS = {
    "shop.local": [
        (30, "GET", "/html", None),
        (20, "GET", "/get?category=tools", None),
        (15, "GET", "/get?category=garden&page=2", None),
        (10, "GET", "/json", None),
        (8, "GET", "/bytes/8192", None),
        (7, "GET", "/status/404", None),
        (5, "POST", "/post", {"sku": "TL-4417", "qty": 2}),
        (3, "GET", "/delay/1", None),
        (2, "GET", "/status/500", None),
    ],
    "api.local": [
        (35, "GET", "/json", None),
        (20, "GET", "/get?fields=id,name&limit=50", None),
        (15, "POST", "/post", {"query": "orders", "since": "2026-09-01"}),
        (10, "GET", "/headers", None),
        (8, "GET", "/status/201", None),
        (6, "GET", "/status/429", None),
        (4, "GET", "/status/503", None),
        (2, "GET", "/delay/2", None),
    ],
    "blog.local": [
        (40, "GET", "/html", None),
        (25, "GET", "/get?post=the-quiet-part", None),
        (15, "GET", "/get?tag=security", None),
        (10, "GET", "/status/304", None),
        (6, "POST", "/post", {"comment": "Great write-up, thanks.", "author": "reader"}),
        (4, "GET", "/status/404", None),
    ],
}


def weighted_choice(entries):
    total = sum(w for w, *_ in entries)
    pick = random.uniform(0, total)
    upto = 0.0
    for weight, method, path, body in entries:
        upto += weight
        if upto >= pick:
            return method, path, body
    return entries[-1][1:]


def visitor(name: str, deadline: float, counter: dict, lock: threading.Lock) -> None:
    """One visitor: a stable source address, user agent and session."""
    host = random.choice(list(JOURNEYS))
    agent = random.choice(lab.BROWSERS if random.random() < 0.85 else lab.CRAWLERS)
    source = lab.random_public_ip()
    sess = lab.session(agent, source)
    base = lab.base_url(host)

    while time.time() < deadline:
        method, path, body = weighted_choice(JOURNEYS[host])
        kwargs = {}
        if body is not None:
            if random.random() < 0.5:
                kwargs["json"] = body
            else:
                kwargs["data"] = body

        status = lab.request(sess, method, base + path, **kwargs)
        with lock:
            counter["requests"] += 1
            counter.setdefault("status", {})
            counter["status"][status] = counter["status"].get(status, 0) + 1

        # Think time: people read pages, they do not hammer them.
        time.sleep(random.uniform(0.3, 2.0))

        # Occasionally a visitor moves to another part of the estate.
        if random.random() < 0.05:
            host = random.choice(list(JOURNEYS))
            base = lab.base_url(host)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--visitors", type=int, default=6, help="concurrent visitors")
    parser.add_argument("--duration", type=int, default=60, help="seconds to run")
    parser.add_argument("--addr", default=lab.DEFAULT_ADDR, help="loopback address of the proxy")
    args = parser.parse_args()

    try:
        lab.install_lab_dns(args.addr)
    except lab.RefusedTarget as exc:
        print(exc, file=sys.stderr)
        return 2

    print(f"crawling with {args.visitors} visitors for {args.duration}s")
    deadline = time.time() + args.duration
    counter: dict = {"requests": 0}
    lock = threading.Lock()

    threads = [
        threading.Thread(target=visitor, args=(f"v{i}", deadline, counter, lock), daemon=True)
        for i in range(args.visitors)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    statuses = counter.get("status", {})
    print(f"sent {counter['requests']} requests")
    print("status codes:", json.dumps(dict(sorted(statuses.items())), indent=None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
