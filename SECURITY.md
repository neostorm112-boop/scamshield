# Security policy

## Supported versions

Only the latest commit on `main` is supported.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
**Security → Report a vulnerability** (private vulnerability reporting) on this repository,
with steps to reproduce and the commit you tested. You should get an answer within a week.

## Scope

ScamShield is a single-user tool that listens on `127.0.0.1` only and has no login.
In scope:

- a web page in the user's browser being able to drive the local app (cross-site requests, DNS rebinding);
- HTML or script injection through domain names, page titles or other data taken from suspicious sites;
- escape from the snapshot browser sandbox, or the snapshot reaching private network addresses;
- secrets from `.env` appearing in logs, pages or the database.

Out of scope: running the app on a public interface (it is not designed for that), and findings
that require an attacker who already controls the user's machine.
