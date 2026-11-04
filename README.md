# Security advisories — David Kutz-Marks

Vulnerability research by **David Kutz-Marks** (@davidkm-ai). Each CVE below has its own record in
this repository. The narrative write-ups, with video, live at **https://dkmsecurity.net/research.html**.

**Fourteen distinct vulnerabilities across three products.** Every one was reported to the vendor
before publication. Every one is fixed, with two stated exceptions.

---

## Cacti

Pre-authentication RCE chain plus one unauthenticated information disclosure. Fixed in **1.2.31**
(a 33-fix security release). Full write-up: [`chains/CACTI.md`](chains/CACTI.md).

| CVE | Vulnerability | CWE | Status |
|---|---|---|---|
| [CVE-2026-39955](CVE-2026-39955.md) | Pre-auth SQL injection, `graph_view.php` | 89 | **Published** 2026-06-24 |
| [CVE-2026-40941](CVE-2026-40941.md) | Package-import signature validation bypass | 347 | **Published** 2026-06-25 |
| [CVE-2026-39939](CVE-2026-39939.md) | Package-import path traversal → arbitrary file write | 22, 434 | Reserved |
| [CVE-2026-94826](CVE-2026-94826.md) | Unauthenticated REST API, 13 endpoints | 306 | Reserved — fixed on `develop`, in **no release** |

**Cacti's shipped CHANGELOG claims 1.2.31 fixed the traversal. The fix commit `36fa99bda` is dated
61 days after 1.2.31 shipped.** If you read the changelog and concluded you were safe, check the commit.

## Appsmith Community Edition

Open-signup → super-admin takeover chain on self-hosted installs. Fixed across **v2.0 → v2.2 → v2.3**.
Full write-up: [`chains/APPSMITH.md`](chains/APPSMITH.md).

| CVE | Vulnerability | CWE | Status |
|---|---|---|---|
| [CVE-2026-94831](CVE-2026-94831.md) | Unauthenticated embedded Redis → session theft → super-admin | 287, 384 | Reserved |
| [CVE-2026-94830](CVE-2026-94830.md) | Database plugins bypass the SSRF filter | 918 | Reserved |
| [CVE-2026-94829](CVE-2026-94829.md) | `/api/v1/admin/env` leaks MongoDB root credentials | 200 | Reserved |

The vendor's own fix commit `48ac053d5e` is titled *"block Redis datasource from internal Appsmith
Redis (GHSA-qhfj-g87x-m39w)"* — it names the advisory.

## SubMgr (Submission Manager)

Seven issues, two of which chain into pre-authentication RCE on PHP < 8.1. All fixed in commit
**`658d46c8`** (2026-04-18). Full write-up: [`chains/SUBMGR.md`](chains/SUBMGR.md).

| CVE | Vulnerability | CWE | Status |
|---|---|---|---|
| [CVE-2026-94832](CVE-2026-94832.md) | Pre-auth blind SQLi via `email` (PHP < 8.1) | 89 | Reserved |
| [CVE-2026-94835](CVE-2026-94835.md) | OS command injection, `mysqldump_path` | 78 | Reserved |
| [CVE-2026-94833](CVE-2026-94833.md) | `extract($_REQUEST)` → unconstrained SQLi | 89, 621 | Reserved |
| [CVE-2026-94838](CVE-2026-94838.md) | Action attachments: no extension validation | 434 | Reserved |
| [CVE-2026-94837](CVE-2026-94837.md) | TOCTOU upload — written before validated | 434, 367 | Reserved |
| [CVE-2026-94836](CVE-2026-94836.md) | SQLi in the tag bulk-action handler | 89 | Reserved |
| [CVE-2026-94834](CVE-2026-94834.md) | Arbitrary file read, `download.php` | 22 | Reserved |

**There is no tagged release carrying the fix** — the repository has published no releases and
no tags at all, and `version.txt` reads `3.42` at the fix commit's parent, at the fix, and today.
**No version string distinguishes a patched install from an unpatched one.** If you deployed before
2026-04-18, update to `main` at `658d46c8` or later and verify by inspecting the sinks, not the version.

---

## Notes on these records

- **CVSS vectors are the researcher's own assessment** and may differ from the vendor's or NVD's.
- **Reserved** means MITRE has assigned the ID but the record is not yet populated. Those appear here
  first; the CVE records follow.
- Nothing in this repository is a statement about any system other than the researcher's own test
  instances. No third-party host was tested.

**Contact:** davidkm@dkmsecurity.net · **Site:** https://dkmsecurity.net
