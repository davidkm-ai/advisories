# SubMgr ≤ 3.42 — pre-authentication RCE chain + 5 further issues (CVE-2026-94832 … CVE-2026-94838)

**Researcher:** David Kutz-Marks (dkmsecurity)
**Vendor:** Devin Emke — `github.com/devinemke/submgr`
**Reported:** 2026-03-28
**Fixed:** commit **`658d46c8`** (2026-04-18) on `main` — *"various security fixes (thanks @dkmsecurity)"*
**Status:** all seven remediated at the sinks (source-verified 2026-06-06).
⚠️ **No tagged release carries the fix.** See *Remediation*.

---

## Summary

SubMgr is a PHP submission-manager used by literary magazines, journals and university
departments. Seven issues; two of them chain into **pre-authentication remote code execution**
on installs running PHP < 8.1.

```
  public submission form, `email` field     CVE-2026-94832   blind SQLi → admin bcrypt hash
            ↓                                                (PHP < 8.1 only)
  Config > General, `mysqldump_path`        CVE-2026-94835   shell_exec() command injection
            ↓
  Maintenance > Backup                                       arbitrary code as the web user
```

Five further issues stand alone: two more SQL injections, an admin path traversal, and two
file-upload holes — one of which is reachable **unauthenticated**.

---

## Affected

| | |
|---|---|
| Product | SubMgr (Submission Manager), Devin Emke |
| Affected | **all versions through 3.42** |
| Fixed | commit `658d46c8` on `main`, 2026-04-18 |
| Chain precondition | **PHP < 8.1** for link 1 (~20–30% of live installs sampled; PHP 7.3 and 7.4 confirmed on university-hosted instances) |

---

## The chain

### CVE-2026-94832 — pre-auth blind SQL injection via `email`
**CWE-89 · CVSS 3.1 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)**

Three facts have to line up, and on PHP 7.x they do:

1. `email_check()` at `inc_common.php:1544` validates with a regex that **explicitly permits
   single quotes in the local part** — legal per RFC 5321, fatal here.
2. The value is passed through `htmlspecialchars()`. **Before PHP 8.1 the default flag set was
   `ENT_COMPAT`, which does not encode `'`.** PHP 8.1 changed the default to
   `ENT_QUOTES|ENT_SUBSTITUTE`, which does — and that single language change is the only thing
   standing between a modern install and this bug.
3. The unescaped value is interpolated into a query at `inc_common.php:1664`.

The email regex also permits `/`, `*` and `#`, which is everything an attacker needs: `/**/`
substitutes for whitespace and `#` terminates the statement. Boolean-based blind extraction of
the full 60-character bcrypt admin hash takes roughly **2000 HTTP requests** against the public
submission form, with no account.

### CVE-2026-94835 — OS command injection in the database backup function
**CWE-78 · CVSS 3.1 7.2 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)**

An admin sets `mysqldump_path` under *Configuration > General*. On save it passes through
`strip_tags()` and `stripslashes()` — neither of which touches a shell metacharacter. At run
time there are exactly two guards:

- `strpos($mysqldump_path, 'mysqldump')` — the string must *contain* "mysqldump".
- if the value contains a space, it gets double-quoted.

Both are trivially satisfied: keep the literal `mysqldump` somewhere in the payload, and use
`${IFS}` instead of spaces so the quoting branch never fires. The value reaches `shell_exec()`
at `inc_login.php:1302` when *Maintenance > Backup* runs.

`strip_tags()` survives a base64 round-trip, so the reliable primitive is
`echo <b64>|base64${IFS}-d>file;#`.

**Chained:** 94832 yields the admin hash → crack or replay → 94835 is a web shell.

---

## The other five

### CVE-2026-94833 — `popup.php`: `extract($_REQUEST)` → unconstrained SQL injection
**CWE-89 / CWE-621 · CVSS 3.1 8.8**

Line 9 is `extract($_REQUEST)`, which overwrites every local and global variable with
attacker-supplied values. Line 17 then builds:

```php
"SELECT $field FROM `$table` WHERE $id_name = $id_value"
```

Four of the five components are now attacker-controlled, with **no character restrictions and
full query control** — and the result is rendered back on the page, so it is a direct read, not
a blind one. If the MySQL user holds `FILE`, `INTO OUTFILE` writes a webshell to the webroot.

Authorization is `$_SESSION['contact']['access']` being *truthy*, which includes **reader** —
the lowest staff role.

The `extract()` also overwrites `$config`, `$nonce` and friends. Lower impact, but it is the
same defect.

### CVE-2026-94836 — SQL injection in the tag bulk-action handler
**CWE-89 · CVSS 3.1 6.5**

`inc_login.php:572` `implode()`s `$_POST['tag'][]` directly into an `IN()` clause with no
escaping:

```
tag[]=1) UNION SELECT password,2,email,4,5 FROM contacts--
```

A second unsanitized `implode()` at `inc_login.php:579` consumes values derived from the first
query's results — not independently exploitable, since those come from the database.

### CVE-2026-94834 — arbitrary file read in `download.php`
**CWE-22 · CVSS 3.1 4.9**

`download.php:40` concatenates `$upload_path . $_GET['year'] . $_GET['file']` with no traversal
check. Admin-only, and an admin already holds a lot — but it crosses the trust boundary out of
the upload directory: `file=../../config_db.php` yields the database credentials,
`file=../../../etc/passwd` the system file.

### CVE-2026-94837 — TOCTOU in file upload: written before validated
**CWE-434 / CWE-367 · CVSS 3.1 7.5**

`upload()` at `inc_common.php:1708` **moves the file into the upload directory first** and
`form_check()` validates the extension **second**. When validation fails, `exit_error()` fires —
and the file is still on disk. It is only cleaned up if the *same session* uploads again.

The resulting name is `temp_<unix_timestamp>_<attacker_chosen_name>.php`, and the timestamp
comes straight out of the HTTP `Date` response header. Both halves are known.

Reachable from the **public, unauthenticated** submission form at `main_home.php:30`, as well as
the authenticated one at `main_login.php:396`. Exploitation needs `upload_path` to be
web-accessible; SubMgr's documentation recommends putting it outside the webroot but **does not
enforce it**.

### CVE-2026-94838 — action attachments: no extension validation at all
**CWE-434 · CVSS 3.1 8.8**

Submission uploads at least check an allowlist (the `file_types` table). The *action attachment*
path does not check anything. `main_login.php:1319` calls `upload()` and then tests only for
upload errors and size. The original extension is preserved when the file is permanently renamed
to `action_<id>.<ext>` at `main_login.php:694`, and `action_id` is **sequential**.

So: any staff user — reader included — attaches `shell.php` to a submission and fetches
`action_<n>.php`. Permanent file, guessable name, no validation.

---

## Remediation

**Update to `main` at commit `658d46c8` (2026-04-18) or later.**

⚠️ **There is no tagged release containing these fixes.** The in-tree version string reads
`3.42` both before and after the fix commit. If you installed from a tag, a release archive or
a vendor bundle, **you are almost certainly still vulnerable even though you believe you are on
the latest version.** Check the commit, not the version string.

Fixes as landed:

| CVE | File:line on `main` | Fix |
|---|---|---|
| 94832 | `inc_common.php:1600` | `real_escape` at the email SQL sink |
| 94833 | `popup.php:17-29` | `extract()` removed; parameter allowlist; `(int)`; `real_escape` |
| 94834 | `download.php:34-36` | `basename` + `realpath` + `(int)` |
| 94835 | `inc_login.php:1302` | `escapeshellcmd` |
| 94836 | `inc_login.php:572` | `(int)` + `real_escape` on `tag[]` |
| 94837 | `inc_common.php:1567` | temp file unlinked on invalid extension |
| 94838 | `main_login.php:1349-1354` | extension allowlist + MIME check + temp delete |

Operator hardening regardless of version:

1. **Put `upload_path` outside the webroot.** This alone defeats 94837 and 94838. The docs
   recommend it; nothing enforces it.
2. **Run PHP ≥ 8.1.** It closes CVE-2026-94832 as a side effect of the `htmlspecialchars()`
   default change — which is luck, not defence, but take it.
3. Do not grant the application's MySQL user `FILE`.

### Residual, not exploitable — noted for completeness

- `exclude_file_types` (`inc_common.php:39`) is a **denylist** and misses `phtml`, `php3`–`php7`,
  `phps`, `pht`, `phar`, `shtml`. The allowlist still gates, so this is defence-in-depth only.
- `extract()` remains in `form_check`, but on `$GLOBALS` and not attacker-controlled.
- 94837's fix leaves a sub-millisecond move-before-validate race.

---

## Timeline

| Date | Event |
|---|---|
| 2026-03-28 | Seven issues reported to the vendor |
| 2026-04-18 | Vendor ships `658d46c8` fixing all seven, crediting `@dkmsecurity` |
| 2026-06-06 | Fixes independently verified at every sink |
| 2026-10-03 | MITRE assigns CVE-2026-94832 … CVE-2026-94838 |
| 2026-10-21 | This write-up published |

**Note for operators:** all seven issues were fixed on the `main` branch, but no tagged
release carries the fixes and the in-tree version string is unchanged at 3.42 both before and
after the fix commit. Installations deployed from a tag or a source archive therefore remain
affected. Deploy from `main` at or after `658d46c8`, or apply the commit directly.

**Credit:** David Kutz-Marks.
