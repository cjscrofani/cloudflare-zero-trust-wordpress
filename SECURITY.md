# Security Policy

This plugin stands between the public internet and the WordPress login. Reports are
taken seriously and handled quickly.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 2.x     | Yes       |
| 1.0.5   | Security fixes only, until 2.0.x has been out for 90 days |
| < 1.0.5 | No. 1.0.4 and earlier contain a primary-mode bypass and a shared OIDC state; update. |

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository.
If that is unavailable, email the maintainer address shown on the GitHub profile with
"cloudflare-zero-trust-wordpress" in the subject.

Include the plugin version, the login mode (primary or secondary), whether the site is
behind the Cloudflare proxy, and the steps to reproduce. A proof of concept against your
own test site is welcome; please do not test against sites you do not own.

You will get an acknowledgement within three business days and a fix or a mitigation
plan within fourteen. Credit is given in the changelog unless you prefer otherwise.

## Scope notes

- The client secret is encrypted at rest with keys derived from the site's WordPress
  salts. Anyone who can read `wp-config.php` and the database can recover it; that is
  the same trust boundary as WordPress itself.
- Rate limiting trusts `CF-Connecting-IP` only when the request arrives from Cloudflare's
  published IP ranges. Sites whose origin is reachable directly should firewall it to
  those ranges; that is a hosting configuration, not a plugin setting.
- Application passwords, XML-RPC, cron and WP-CLI are not interactive logins and are not
  subject to primary mode. Disable them in WordPress if your policy requires it.
