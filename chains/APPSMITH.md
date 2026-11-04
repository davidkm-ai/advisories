# Appsmith Community Edition ≤ 1.99 — unauthenticated-signup to super-admin takeover (CVE-2026-94829 / 94830 / 94831)

**Researcher:** David Kutz-Marks (@davidkm-ai)
**Vendor:** Appsmith, Inc. — `github.com/appsmithorg/appsmith`
**Reported:** 2026-04-11 to `security@appsmith.com`; refiled as GitHub Security Advisories
**Fixed:** v2.0 (mitigation) → **v2.2** (explicit fix, commit `48ac053d5e`) → v2.3 (hardening)
**Status:** remediated on current releases. Current version at time of writing: v2.4.3.

---

## Summary

A default `docker-compose` install of Appsmith Community Edition ships an embedded Redis with
**no password**, stores Spring sessions in it with a 30-day TTL, leaves **open signup on by
default**, and exposes a Redis datasource plugin that connects over **raw TCP, bypassing the
SSRF filter entirely**.

Put together, that means: *anyone who can reach the login page can become super-admin.*

```
  open signup (default-on)          ─┐
         ↓                           │
  create Redis datasource to         │  CVE-2026-94830   DB plugins never touch the SSRF filter
  127.0.0.1:6379                     │
         ↓                           │
  KEYS spring:session:sessions:*     │  CVE-2026-94831   embedded Redis has no requirepass
  HGETALL → super-admin session UUID │
         ↓                           │
  set SESSION cookie = that UUID     │  → super-admin
         ↓                           │
  GET /api/v1/admin/env              ─┘  CVE-2026-94829   MongoDB root URI in cleartext
         ↓
  mongodb://appsmith:<pw>@… with role: root — every user, every datasource secret
```

Verified live on `appsmith-ce:latest` at v1.98, fresh install, **zero configuration changes**,
using a regular non-super account created through the public signup form.

---

## Affected

| | |
|---|---|
| Product | Appsmith Community Edition, **self-hosted** |
| CVE-2026-94831 | **≤ v1.99** — fixed v2.0 (mitigated), v2.2 (explicit) |
| CVE-2026-94830 | **≤ v2.2** — fixed v2.3 |
| CVE-2026-94829 | **≤ v1.99** for the unauthenticated path; endpoint still super-admin gated today |
| Not affected | Appsmith Cloud |

---

## CVE-2026-94831 — unauthenticated embedded Redis → session theft → super-admin
**CWE-287 / CWE-384 · CVSS 3.1 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N) · GHSA-qhfj-g87x-m39w**

The bundled Redis listens on `127.0.0.1:6379` with `requirepass` **empty**. Spring Session
writes every live session there under `spring:session:sessions:<UUID>`, TTL 30 days. Each
record contains the whole user identity in cleartext JSON:

```
appsmith-session:{"userId":"…","email":"…","name":"…","state":"ACTIVATED","isEnabled":true,…}
```

The attack needs no privileges beyond a self-registered account:

1. Sign up through the public form (open signup is on by default).
2. Create a **Redis datasource** pointing at `127.0.0.1:6379`. The datasource API does not care
   that this is the instance's own loopback.
3. Run `KEYS spring:session:sessions:*`, then `HGETALL` each one. Read the JSON. Find the
   session whose email belongs to a super-admin.
4. Set your own `SESSION` cookie to that UUID.

You are now the super-admin. No credential was cracked, no token was forged, no CSRF was
needed.

## CVE-2026-94830 — every database plugin bypasses the SSRF filter
**CWE-918 · CVSS 3.1 6.5 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)**

Appsmith's SSRF protection lives in `WebClientUtils.java` and applies to **Spring WebClient
HTTP requests**. The database plugins do not make HTTP requests:

| Plugin | Transport | Goes through `WebClientUtils`? |
|---|---|---|
| Redis | Jedis, raw TCP | no |
| PostgreSQL / MySQL / MSSQL | JDBC, raw TCP | no |
| MongoDB | MongoDB Java driver, raw TCP | no |

At v1.98 **none of their `validateDatasource()` methods performed any host validation at all.**
Any authenticated user could point a datasource at an arbitrary internal host and port and get
a usable oracle back. Measured on a live instance:

| Target | Response | Meaning |
|---|---|---|
| `127.0.0.1:6379` | 221 ms — *"Unable to validate object"* | open, speaking a different protocol |
| `127.0.0.1:27017` | 20 s timeout | open, Mongo |
| `127.0.0.1:59999` | 52 ms — *"Failed connecting"* | closed |

That is a clean three-state port scanner, and for Redis specifically it is the enabling step
for CVE-2026-94831.

Separately: the REST-API SSRF filter that *does* exist never blocked RFC 1918 ranges — only
cloud-metadata IPs and Docker-mode localhost.

### What the fix did and did not do

v2.3 (PR #41985) applies `RestrictedHostFilter` on the datasource **connection** path, and the
Redis plugin now calls `RestrictedHostFilter.isHostBlocked(host)` and routes through a
`RestrictedHostJedisSocketFactory`. The loopback path is closed.

**`RestrictedHostFilter` still deliberately permits RFC 1918 / site-local addresses**, and
PR #41985 says so explicitly — the reasoning is that in a typical Docker or Kubernetes
deployment, legitimate customer datasources live on private networks. So "an Appsmith user can
still open a TCP connection to `10.x`" remains true and is a **documented vendor trade-off**,
not an open vulnerability. This CVE is scoped to the *complete absence* of host policy on that
code path prior to v2.3.

## CVE-2026-94829 — `/api/v1/admin/env` discloses MongoDB root credentials
**CWE-200 · CVSS 3.1 4.9 (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N)**

`GET /api/v1/admin/env` returns the instance environment **unmasked**, including:

- `mongodb://appsmith:<password>@…` — the full connection URI with embedded credentials
- the Redis connection URL
- other secrets in the environment

The MongoDB user holds **`role: root`**, confirmed directly:

```js
db.runCommand({connectionStatus: 1}).authInfo.authenticatedUserRoles
```

The password is randomly generated per install — and then handed out in cleartext to anyone
holding a super-admin session, which CVE-2026-94831 provides for free. Result: full read/write
on every Appsmith collection — user records, datasource secrets, application data.

The endpoint is super-admin gated (non-super gets HTTP 403), which is why this is scored 4.9
standalone. It is the **last link** in the chain, not a standalone finding, and it is listed
here because that is what it is.

*Related:* CVE-2026-50189 (supervisord XML-RPC RCE) cites `APPSMITH_SUPERVISOR_PASSWORD`
exposure via this same endpoint as its precondition. Different claimed vulnerability; same
underlying exposure.

---

## Remediation

**Upgrade to v2.3 or later** (v2.4.3 current). Then, on any self-hosted instance:

1. **Turn off open signup**, or restrict it to an email domain allowlist. It is on by default
   and it is the entry ticket for the whole chain.
2. **Set `APPSMITH_REDIS_PASSWORD`** and confirm `requirepass` is actually present in the
   generated `redis.conf`. v2.0's `entrypoint.sh` does this automatically with a random
   per-install value — verify it took.
3. **Audit existing datasources** for any pointed at loopback, the instance's own address, or
   internal ranges. A datasource created before you upgraded still exists after you upgrade.
4. Treat `/api/v1/admin/env` output as a credential dump. If a non-trusted account has ever
   held super-admin on this instance, **rotate the Mongo password** — the fix does not
   retroactively un-leak it.

---

## Fix timeline — verified in git on 2026-10-06

| Version | Date | Commit | What |
|---|---|---|---|
| v1.98 | 2026-03-23 | — | version tested; full chain live |
| v1.99 | 2026-04-16 | — | still vulnerable |
| **v2.0** | 2026-05-21 | `0d99237a1` (PR #41634) | *"set password on embedded Redis instance"* — `entrypoint.sh` writes `requirepass ${APPSMITH_REDIS_PASSWORD}`. **Silently breaks the chain.** |
| v2.1 | 2026-05-29 | — | chain confirmed broken at Stage 2; Stage 1 still live |
| **v2.2** | 2026-07-09 | `48ac053d5e` | *"fix(security): block Redis datasource from internal Appsmith Redis **(GHSA-qhfj-g87x-m39w)**"* |
| **v2.3** | 2026-08-13 | `800cf99804` (PR #41985) | `RestrictedHostFilter` applied to the datasource connection path |
| v2.4.3 | 2026-09-30 | — | current |

The v2.0 fix shipped with no advisory and no CVE. The v2.2 commit message names the advisory
directly, which is the vendor's own acknowledgement of the report.

---

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-03 | Chain found and verified on v1.98 |
| 2026-04-11 | Reported to `security@appsmith.com` |
| 2026-04-15 | Vendor replies, asks for individual GitHub Security Advisories |
| 2026-05-21 | **v2.0 silently patches the headline bug** — no advisory, no CVE |
| 2026-06-06 | Reply noticed; re-verified on v2.1; GHSAs filed |
| 2026-07-07 | Vendor commits the explicit fix, citing GHSA-qhfj-g87x-m39w |
| 2026-10-03 | MITRE assigns CVE-2026-94829 / 94830 / 94831 |
| 2026-10-21 | This write-up published |

**Credit:** David Kutz-Marks.
