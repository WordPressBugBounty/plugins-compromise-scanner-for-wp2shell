=== Compromise Scanner for wp2shell ===
Contributors: eyesecurity
Tags: security, malware, forensics, wp2shell, vulnerability
Requires at least: 5.6
Tested up to: 7.0
Requires PHP: 7.2
Stable tag: 1.1.0
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Read-only forensic scanner for the WordPress core exploit chain CVE-2026-63030 / CVE-2026-60137 (wp2shell). Reports a scored verdict; changes nothing.

== Description ==

Compromise Scanner for wp2shell is a **read-only** forensic scanner for the WordPress core exploit chain publicly tracked as **CVE-2026-63030** (REST batch route confusion) and **CVE-2026-60137** (`author__not_in` SQL injection), widely referred to as *wp2shell*.

It inspects the database and the plugin directory for artifacts the exploit leaves behind — even when the attacker cleaned up afterwards — and presents a scored verdict on its own admin screen. It does **not** change anything on your site, and it does **not** fix the vulnerability. To close the hole, update WordPress core.

**What it checks (each weighted by severity):**

* `oembed_cache` entries that loop back to your own site, that number exactly three, or that were created around the disclosure date (the exploit uses oembed rendering as a write primitive).
* Object-graph artifacts: posts with implausibly high parent IDs, known proof-of-concept titles/slugs, and `customize_changeset` entries created since disclosure.
* Account artifacts: the `wp2_` login prefix and `@wp2shell.invalid` email used by public exploit code, and non-founder administrator accounts created since disclosure.
* Deleted-admin traces: orphaned user metadata and gaps in the user-ID sequence (create-then-delete).
* Webshell plugin files or directories matching `wp2shell_*`.

**How it reads:** the weighted score maps to *No indicators* (under 25), *Some indicators* (25–49), or *Multiple indicators* (50+). Each check is shown with its severity and detail so you can verify it yourself. Matched checks are not proof of a breach.

**Export:** the **Export report (.zip)** button downloads a zip archive for record-keeping or to hand to an investigator. Because the exploit hides its SQL injection and pre-auth admin creation inside a REST batch request body — which web servers do not log — the database artifacts are the primary evidence, so the archive includes the raw rows a human needs to review: the report as JSON and plain text, the relevant `oembed_cache`, `customize_changeset`, suspect posts, suspect users (exploit-default logins/emails and new administrators; never password hashes), orphaned usermeta and changed plugin files, plus `LOG-COLLECTION-GUIDE.txt` listing the server-side logs to gather by hand (the plugin cannot read those itself). If the server lacks the PHP zip extension, a single JSON file with the same data is downloaded instead. The export is generated on the fly and stores nothing on the site.

This is a focused, single-purpose tool. It is best-effort: matched checks are not proof of a breach on their own, and an all-clear result is not a guarantee. Do not act on this quick check alone — verify matched checks with your webmaster, consider a proper investigation (server and access logs, file integrity) if anything is unexplained, and treat reinstalling WordPress as a last resort. It complements, and does not replace, updating core and a professional investigation.

== Installation ==

1. In wp-admin, go to Plugins → Add New → Upload Plugin and upload the zip, then Activate.
2. Open **Compromise Scanner for wp2shell** in the admin menu.
3. Click **Run scan** and review the findings.
4. When finished, use **Remove this plugin** on the scan screen to deactivate and delete it.

== Frequently Asked Questions ==

= Does this change anything on my site? =
No. It only reads the database and lists files in the plugin directory. It never creates, edits, or deletes posts, users, options, or files (other than removing itself when you click the self-destruct button).

= Does it fix the vulnerability? =
No. It only detects artifacts. Update WordPress core to a fixed version (6.8.6 / 6.9.5 / 7.0.2 or later) to close the vulnerability.

= A check is marked "Matched" but I know it is legitimate. =
That can happen — for example, three recent legitimate embeds, or an administrator you onboarded recently, can match individual checks. The verdict is a weighted score across many indicators; review each detected item against your own records.

= A scan matched nothing. Am I safe? =
It means no known wp2shell artifacts were found. A careful attacker can remove traces, and other attacks leave different evidence, so treat "Clean" as reassuring but not conclusive.

== Screenshots ==

1. The scan screen: status, forensic score, and severity-graded findings.

== Changelog ==

= 1.1.0 =
* New: an **Export report (.zip)** button on the scan screen. The archive contains the report (JSON + plain text), the raw database rows an investigator needs to review — `oembed_cache`, `customize_changeset`, suspect posts, suspect users (exploit-default logins/emails and new administrators; never password hashes or session tokens), orphaned usermeta, user-ID accounting, and changed plugin files — and a `LOG-COLLECTION-GUIDE.txt` explaining which server-side logs to collect by hand. Because the exploit hides its SQL injection and admin creation in a request body that web servers do not log, these database rows are the primary evidence. Rows and content excerpts are capped so the archive stays reviewable. Falls back to a single JSON download when the PHP zip extension is missing. The archive is built in a temporary file removed in the same request — the plugin still changes nothing on the site.

= 1.0.1 =
* The user-ID-gap check no longer matches on shared-user-table installs (multisite or platform hosting such as WordPress.com), where IDs are allocated platform-wide, and ignores gaps that dwarf the account count (imports, bulk cleanup). It explains in the detail column why it was not counted.
* The new-accounts check now counts only administrator accounts, as the exploit creates an administrator; ordinary sign-ups on sites with open registration no longer match.
* Documentation: the fixed-version list consistently includes the 6.8.6 backport.

= 1.0.0 =
* Initial release: read-only scan with a dedicated admin screen, a separate version-status panel, severity-graded checks, and objective, non-alarming reporting.

== Upgrade Notice ==

= 1.1.0 =
Adds an Export report (.zip) button: report plus the raw database evidence for review and a guide to the server logs to collect.

= 1.0.1 =
Fewer false positives: the user-ID-gap check understands shared hosting (e.g. WordPress.com), and the new-accounts check counts administrators only.

= 1.0.0 =
Initial release.
