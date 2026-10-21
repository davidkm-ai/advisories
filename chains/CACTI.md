# Cacti — pre-authentication RCE chain (CVE-2026-39955 → CVE-2026-40941 → CVE-2026-39939)

**Researcher:** David Kutz-Marks (`@davidkm-ai` / dkmsecurity)
**Reported:** 2026-03-25 (GitHub Security Advisories on `Cacti/cacti`)
**Fixed:** Cacti **1.2.31** (a 33-fix security release)
**Published CVEs:** 2026-06-24 / 2026-06-25
**Status:** fully remediated. Published here for defenders and for the record.

---

## Summary

Three bugs on the Cacti **`develop` branch (`1.3.0-dev`)** chain into **unauthenticated remote code execution** as the web
server user. Each is individually CVE-worthy; together they take you from an anonymous HTTP
GET to a PHP webshell with no credentials.

```
  graph_view.php?graph_template_id=…     ─┐
  pre-auth time-based blind SQLi          │  CVE-2026-39955   extract admin bcrypt hash
                                          │
  package import, signature bypass        │  CVE-2026-40941   self-signed package accepted
  !import_validate_signature(…)           │
                                          │
  package import, path traversal          │  CVE-2026-39939   write scripts/../shell.php
  str_contains($f,'scripts/')             ─┘
                                             ↓
                                 uid=33(www-data) — RCE
```

Demonstrated end to end on a local Cacti **`develop` (`1.3.0-dev`, commit `c869d9b2`)** container: 64 seconds from first request to
interactive reverse shell.

---

## Affected

| | |
|---|---|
| Product | Cacti (`github.com/Cacti/cacti`) |
| Affected | **`develop` branch (`1.3.0-dev`) only** for links 1–2 (SQLi + sig-bypass); `1.2.x` stable and `main` are **NOT affected** (numeric-list filter + correct bool key check). The link-3 traversal sink exists on all branches but is post-auth (`PR:L`) on its own; the **pre-auth chain is develop-only**. |
| Fixed | **1.2.31** |
| Precondition for the pre-auth link | the **guest account** feature must be enabled (`guest_user` must name a real row) |

### On the guest precondition — stated plainly

Link 1 is only reachable without credentials when Cacti's guest-account feature is turned on.
`include/auth.php:133-150` holds the only pre-auth `return true`, and it fires only when a page
sets `$guest_account`; `get_guest_account()` (`lib/functions.php:2953`) returns `0` when
`guest_user` names no row, which is the default. I spent real time trying to remove this
precondition and could not. The variable-variable escape only *unsets*, and `register_globals`
cannot exist on the PHP ≥ 8 that Cacti requires. **Without guest access the chain starts at
link 2 and requires an authenticated admin holding realm 17 (Import Templates).**

I am stating this because the exploit video says "pre-auth" and it is true only under that
configuration. Say the quiet part.

---

## CVE-2026-39955 — pre-auth SQL injection in `graph_view.php`

**CWE-89 · CVSS 3.1 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) · GHSA-gp82-qhrg-crv7**

`graph_template_id` is validated with `FILTER_VALIDATE_REGEXP` using an **unanchored** pattern.
An unanchored regex matches a *substring*, so a payload that merely *contains* a legal-looking
numeric list passes validation and then reaches the query intact. Sinks:
`lib/html_graph.php:255`, duplicated at `:1052`.

No graphs need to be visible on the target — the boolean-blind variant needs rendered graphs,
but the **time-based** variant works against an empty install, which is what the PoC falls back
to automatically:

```
[!] No graphs visible for template_id=1 — boolean blind not viable
[*] Switching to time-based blind (works without graphs)
[+] SQL injection CONFIRMED (time-based signal detected)
```

Yield: `user_auth` in full, including `admin`'s bcrypt hash and `must_change_password`. On a
default install that hash is `admin`, so the chain usually does not even need cracking.

## CVE-2026-40941 — package import signature validation bypass

**CWE-347 · CVSS 3.1 8.8 · GHSA-274c-97hj-pv2v**

`import_validate_signature()` returns a **mixed type** — an array like
`['valid' => false, …]` for an untrusted key. The caller applies boolean `!` to it:

```php
if (!import_validate_signature($xml, $public_key)) { /* reject */ }
```

In PHP, `!array(...)` on a **non-empty** array is always `false`, regardless of what is in it.
So the rejection branch is unreachable and an untrusted key passes exactly like a trusted one.
On the `main` branch the situation was simpler still: the `is_cacti_public_key()` check had
been removed outright.

Practical effect: an attacker generates their own RSA-2048 keypair, signs their own Cacti
package with it, and imports it.

## CVE-2026-39939 — path traversal in package import → arbitrary file write

**CWE-22 / CWE-434 · CVSS 3.1 8.8 · GHSA-vp35-4h28-r883**

The import writer checks that a member filename *contains* `scripts/`:

```php
if (str_contains($filename, 'scripts/')) { /* treat as a script, write it */ }
```

`str_contains` is a containment test. `scripts/../shell.php` contains `scripts/`. There is no
`realpath()` containment check and no `../` rejection, and the attacker-controlled file content
goes straight to `fwrite()` at the resolved path — which is the webroot.

### ⚠️ Correction to the vendor's own changelog

Cacti's shipped CHANGELOG lists this as fixed in **1.2.31**. The commit that actually contains
the fix, `36fa99bda`, is dated **61 days after 1.2.31 shipped**, and its inline comment
describes this exact bypass. `lib/import.php:597` in 1.2.31 still guards with a substring test
and has no traversal containment. The advisory's `patched_versions` field is right and **the
changelog is the wrong document** — the `1.2.x` branch HEAD declares 1.2.32.

If you are an operator who read the changelog and concluded you were safe on 1.2.31: check the
commit, not the changelog.

---

## Chain walkthrough

1. **Anonymous.** Hit `graph_view.php?graph_template_id=<payload>` as guest. Time-based blind
   extraction of `user_auth` → `admin` + bcrypt hash. Default install: password is `admin`.
2. **Authenticate** as admin with the recovered credential.
3. **Build a malicious package** (~2 KB): generate an RSA-2048 keypair, add a member named
   `scripts/../shell.php` whose body is a PHP webshell, sign with the attacker's own key.
4. **Import it.** Signature check passes (CVE-2026-40941); traversal writes the member to the
   webroot (CVE-2026-39939).
5. **`GET /cacti/shell.php?cmd=id`** → `uid=33(www-data) gid=33(www-data)`.

Observed end state in the recorded run:

```
[+] WEBSHELL IS LIVE at http://localhost:8080/cacti/shell.php
[*] Executing: id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[+] Reverse shell connected! (bash /dev/tcp)
www-data@baedb093be83:~/html/cacti$
```

---

## Remediation

**Upgrade to 1.2.31 or later**, and if you read the changelog for the traversal fix, confirm
you are on a build containing `36fa99bda` (i.e. 1.2.32 / current `1.2.x` HEAD).

Defence in depth, in priority order:

1. **Leave the guest account off.** It is off by default. Turning it on converts an
   admin-gated chain into a pre-auth one.
2. Restrict realm 17 (Import Templates) to accounts that genuinely need it. Package import is
   a code-execution feature by design.
3. The webroot should not be writable by the web server user.

---

## Also found, not in this chain

- **CVE-2026-94826** — 13 unauthenticated REST endpoints under `/api/public/v1/`.
  `api/public/index.php` includes `global.php` but never `auth.php`, and there is no API key,
  token, session or IP middleware. Leaks monitored-host IPs and hostnames, internal subnet
  ranges, DNS config, exact software versions and DB status. **Develop branch only; ships in
  no tagged release**; requires `composer install` for Slim 4. Reported as GHSA-mx5c-qj6m-2w89;
  no vendor action. Separate write-up pending.
- **Unauthenticated password-policy disclosure** via `auth_changepassword.php?action=checkpass`,
  which runs before the session check. Information leak only. Not filed.

---

## Timeline

| Date | Event |
|---|---|
| 2026-03-25 | Five advisories filed on `Cacti/cacti` |
| 2026-03-28 | No vendor response; MITRE web-form requests submitted in parallel |
| 2026-06-24 | CVE-2026-39955, CVE-2026-39938, CVE-2026-39899 published |
| 2026-06-25 | CVE-2026-40941 published |
| 2026-10-03 | MITRE assigns a second, duplicate block; four withdrawn (see `../CVE-INVENTORY.md`) |
| 2026-10-21 | This write-up published |

**Credit:** David Kutz-Marks.

---

*Each issue above was reproduced against a local Docker instance of the affected release.
Where a demonstration video accompanies this write-up it is a presentation artifact; the
proof-of-concept and its transcript are the evidence.*
