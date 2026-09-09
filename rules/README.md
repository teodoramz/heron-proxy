# Custom rules

Every `.conf` file in this directory is appended to the OWASP Core Rule Set at
startup and on reload. Use it for rules that should apply to every application.

Per-application exclusions are generated from the UI and stored in Postgres;
they do not belong here.
