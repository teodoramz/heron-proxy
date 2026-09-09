# Lab traffic generators

Scripts that drive traffic at a local Heron Proxy instance, so its detection,
recording and tuning views can be exercised against realistic input.

They only ever target the local lab: the address must be loopback and the
hostname must be one of `shop.local`, `api.local`, `blog.local`, `demo.local`,
`lab.local`. Anything else is refused. See `lab.py`.

## Setup

The lab needs apps whose hostnames match, each pointed at an upstream, and a
certificate covering those names. With the compose stack running:

```bash
docker run -d --name pw-shop --network heron_default mccutchen/go-httpbin:v2.15.0
openssl req -x509 -newkey rsa:2048 -nodes -keyout lab.key -out lab.crt -days 30 \
  -subj "/CN=lab.local" \
  -addext "subjectAltName=DNS:shop.local,DNS:api.local,DNS:blog.local,DNS:demo.local"
```

Add the app and upload the certificate in the UI, then set the app's trusted
proxy range to your Docker gateway (`172.16.0.0/12`) so the scripts' synthetic
source addresses are honoured rather than ignored.

## Crawling

Simulates visitors: each keeps a session, moves through pages with think time,
and occasionally posts a form or calls the API. This is the baseline attacks
need to stand out against.

```bash
python3 crawler.py --visitors 8 --duration 120
```

## Attacking

Runs campaigns of the categories the Core Rule Set is written against: SQL
injection, cross-site scripting, path traversal, command and template injection,
JNDI, NoSQL and XXE, exposed-path enumeration, credential stuffing, and
header-borne payloads. Each campaign is one actor with its own source address
and user agent, so recorded traffic groups the way an intrusion attempt does.

```bash
python3 attacker.py --rounds 3
python3 attacker.py --campaign sqli --host shop.local
```

Requires `requests`.
