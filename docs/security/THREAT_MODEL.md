# DVWA Threat Model and Risk Assessment

**Status:** Revision 2 — targeted controls implemented and tested; residual-risk assessment prepared for group review.
**Review date:** 29 September 2026.
**Evidence commit on main:** `3857b3d`.
**Project:** https://github.com/Ruchira20031209/ie3142-dvwa-devsecops

## 1. Scope and assumptions

This model covers four selected Low-security implementations in the
group's DVWA copy: SQL injection, reflected XSS, command injection and
file inclusion. Before/after demonstrations and regression tests use
the Low setting so that results exercise the group's repaired code.

The assumed attacker has access to the local application and an
authenticated session. The reflected-XSS scenario additionally requires
a user to load a crafted request.

The application runs as PHP and Apache in a Linux container on Docker
Desktop. MariaDB 10.11 runs in a separate container. The web service is
published at 127.0.0.1:4280, and MariaDB has no published host port.
The services communicate through the Compose network named dvwa.

These settings limit exposure. They do not validate application input
or establish complete network isolation. Outbound container networking
is available.

Impact is assessed within the lab using synthetic data and the affected
process's permissions. The evidence does not establish host administrator
access, container escape or compromise of unrelated systems.

The remaining DVWA exercises and other security levels are outside the
four code repairs. The application remains deliberately vulnerable.

## 2. Architecture, assets and trust boundaries

See [the architecture diagram](../architecture/DVWA_Architecture.png)
and [its editable source](../architecture/DVWA_Architecture.drawio).

| Element | Asset or role |
| --- | --- |
| E1 — Browser / tester | Page content and authenticated user actions |
| P1 — DVWA | Request processing and web-process permissions |
| P2 — MariaDB | Application records accessible to database user dvwa |
| D1 — Web files | Web-container files, sessions and uploads |
| D2 — Database volume | Persistent database files at /var/lib/mysql |

TB1 surrounds the web container. F1 carries browser input into P1;
F2 returns HTML and cookies. TB2 surrounds the database container.
F3 carries queries to P2, and F4 returns results. F5 represents P1's
access to D1. F6 represents database persistence to D2.

Container boundaries identify changes in control. They do not themselves
prevent SQL injection, XSS, command injection or unsafe file inclusion.

## 3. Risk assessment method

Risk score = likelihood × impact, using a 3 × 3 matrix.

Likelihood is conditional on the authenticated local-access assumptions.
Scores are qualitative judgments, not measured attack probabilities.

| Rating | Likelihood | Impact within the lab |
| --- | --- | --- |
| 1 — Low | Additional conditions or failure of an implemented control would be needed | Small, contained disruption |
| 2 — Medium | Extra interaction or another condition is needed | Browser-page integrity or limited user context affected |
| 3 — High | Input directly reaches a sensitive operation with few additional conditions | Broad application-data exposure, unintended file access or server-process execution |

| Likelihood / Impact | 1 | 2 | 3 |
| --- | --- | --- | --- |
| 3 | 3 — Medium | 6 — High | 9 — High |
| 2 | 2 — Low | 4 — Medium | 6 — High |
| 1 | 1 — Low | 2 — Low | 3 — Medium |

Priority bands: Low = 1–2; Medium = 3–4; High = 6–9.

Initial scores are retained from the original assessment. Residual
scores reduce likelihood based on the implemented controls and tests.
Impact is retained because a future bypass or regression could restore
the original consequence.

## 4. Initial and residual risk register

| ID | Threat and STRIDE category | Initial L × I | Residual L × I | Status |
| --- | --- | --- | --- | --- |
| T1 | SQL injection: Information disclosure and Tampering of query logic | 3 × 3 = 9, High | 1 × 3 = 3, Medium | Mitigated in assessed implementation |
| T2 | Reflected XSS: Tampering of browser content | 2 × 2 = 4, Medium | 1 × 2 = 2, Low | Mitigated in assessed implementation |
| T3 | Command injection: Elevation of privilege from web input to server-process actions | 3 × 3 = 9, High | 1 × 3 = 3, Medium | Mitigated in assessed implementation |
| T4 | Unsafe file inclusion: Information disclosure | 3 × 3 = 9, High | 1 × 3 = 3, Medium | Mitigated in assessed implementation |

"Mitigated" means the targeted control is implemented and the selected
normal and malicious test cases pass. It does not mean zero risk or
that every possible input and execution path has been tested.

Residual scores require group review and reassessment if the code,
deployment or exposure changes.

## 5. Threats, implemented controls and verification

### T1 — SQL injection / C1

Before remediation, vulnerabilities/sqli/source/low.php read id from
the request and interpolated it into SQL. The original MySQL query
appeared at lines 10–11; the SQLite query appeared at lines 31–34.

Mapping: F1 → P1 → F3 → P2, returning through F4 and F2.
Affected boundaries: TB1 and TB2.

Initial likelihood was High because input directly affected query
construction. Impact was High because additional application records
could be disclosed within the database account's permissions.

Implemented control, commit `747ce16`:
- Accept a scalar positive integer within the configured integer range.
- Use prepared statements and bound values in both database branches [2].
- Encode displayed values and return generic database-error feedback.

The original input `1' OR '1'='1` returned additional users before the
fix and is rejected after the fix. Normal user lookups still work.
Automated checks also cover another user, a missing user and array input.

Evidence: screenshots 26–27 and 36–38; regression tests 01–05.

Residual likelihood is Low because input validation and parameter
binding protect this query path. SQLite was repaired in code but was
not runtime-tested; the demonstrated backend is MariaDB/MySQL.
Database modification and authentication bypass were not demonstrated.

### T2 — Reflected XSS / C2

Before remediation, vulnerabilities/xss_r/source/low.php line 8
inserted the supplied name directly into the HTML response.

Mapping: F1 → P1 → F2 → E1, crossing TB1.

Initial likelihood was Medium because the scenario requires a user to
load a crafted request. Impact was Medium for the demonstrated browser
execution and page-integrity effect.

Implemented control, commit `df34565`:
- Validate that the submitted name is a string.
- Encode it for HTML text using htmlspecialchars with ENT_QUOTES,
  ENT_SUBSTITUTE and explicit UTF-8 [3].

The original script input produced an alert before the fix and appears
as encoded text afterwards. Normal names still display correctly.
Automated checks verify encoding and rejection of array input.

Evidence: screenshots 28–29 and 39–42; regression tests 06–08.

Residual likelihood is Low for this HTML text context. This encoding
decision does not establish protection for other contexts such as
JavaScript, CSS or URLs. Cookie theft and account takeover were not
demonstrated.

### T3 — Operating-system command injection / C3

Before remediation, vulnerabilities/exec/source/low.php read ip from
the request and concatenated it into a shell command on line 14 in
the Linux implementation.

Mapping: F1 → P1 across TB1, with potential effects on P1 and F5/D1.
D2 is mounted in the database container, not directly in P1.

Initial likelihood was High because input reached shell execution.
Impact was High because additional commands could execute with the
web process's permissions.

Implemented control, commit `c32e7d3`:
- Accept a scalar literal IP address validated with FILTER_VALIDATE_IP.
- Invoke the fixed ping executable through a proc_open argument array [4].
- Use fixed ping count, timeout and deadline options.
- Limit captured output and encode it before displaying it.

The original input `127.0.0.1; echo IE3142-CMD` produced the extra marker
before the fix and is rejected afterwards. A normal loopback ping still
works. Array input is also rejected.

Evidence: screenshots 30–31 and 43–46; regression tests 09–11.

Residual likelihood is Low for command injection in this Linux path.
Permitted ping requests can still consume resources and reach network
destinations available to the container. Rate limiting and outbound
destination restrictions were not implemented by this repair.

### T4 — Unsafe file inclusion / C4

Before remediation, vulnerabilities/fi/source/low.php line 4 assigned
page directly to $file. The controller in vulnerabilities/fi/index.php
passed that value to include on line 36.

Mapping: F1 → P1 → F5/D1, with output returned to E1 across TB1.

Initial likelihood was High because a caller selected the included
path. Impact was High because files readable by the web process could
be accessed outside the intended page set. PHP inclusion can also
evaluate PHP content, depending on the selected file [1].

Implemented control, commit `0356ae1`:
- Map include.php and file1.php, file2.php and file3.php to fixed,
  server-owned local paths.
- Reject unknown and non-scalar input before inclusion.

The original traversal request for ../../../../../etc/os-release
displayed container operating-system information before the fix and
returns HTTP 400 afterwards. The default page and all three legitimate
links still work. Array input also returns HTTP 400.

Evidence: screenshots 32–33 and 47–50; regression tests 12–14.

Residual likelihood is Low for caller-controlled path selection in
this implementation. The permitted files must remain trusted.
Disclosure of application secrets or remote-code execution was not
demonstrated.

## 6. Verification and SAST interpretation

The regression suite is tests/test_security_regression.py. It verifies
login, Low security and the MySQL backend, then checks normal behaviour,
the original demonstration inputs and malformed array input.

The local run reported 14 passing tests. The regression-test step also
passed in CI run 13 after restoring the SQLi repair.

The original full SAST comparison used the same frozen PHP rules:

| Measurement | Before four repairs | After four repairs |
| --- | --- | --- |
| PHP files scanned | 169 | 169 |
| Total findings | 44 | 40 |
| ERROR findings | 24 | 21 |
| WARNING findings | 20 | 19 |

SQLi findings in the selected Low file fell from two to zero. Command
injection findings in its Low file fell from four to two. The two
remaining command findings were reviewed as false positives in the
validated, argument-array implementation and remain in the raw report.

The selected reflected-XSS and file-inclusion paths had no findings
under these rules before or after repair. Their verification therefore
relies on code review and behavioural tests. Zero SAST findings alone
would not prove that these paths are safe.

### Real gate failure and recovery

The SAST gate fails on new Semgrep ERROR findings relative to a fixed
repaired baseline. Existing findings remain visible in the full report.

On branch demo/sast-sqli-gate:
- Run 12, commit `2360380`: restoring the original SQLi file produced
  two new ERROR findings; the gate returned BLOCKED with exit code 1.
- Run 13, commit `4d755e2`: restoring the repaired file produced zero
  new ERROR findings; the gate returned PASS with exit code 0.

Both runs used the same scanner, rules, gate script and baseline,
with no scanner errors.

See [the gate demonstration evidence](pipeline/gate-demo/README.md).

## 7. Remaining risks and operating limits

- Other deliberately vulnerable DVWA modules remain outside these
  repairs. The remaining SAST findings are not all dismissed as false
  positives. This project is not a production-security certification.
- Trivy reports retain High and Critical package findings in the
  application and database images. Container scanning currently reports
  findings without a severity-blocking gate. Package findings need
  applicability review and evaluation of available vendor updates.
- Composer audit found no advisories in the recorded six-package
  dependency snapshot. That result is time-specific and does not cover
  every component in the containers.
- Gitleaks scans fetched Git history. Four exact fingerprint exceptions
  and two rule-specific allowlists document reviewed public/example
  values. Remaining findings and scanner failures still fail the job.
  A passing scan cannot prove that every possible secret is absent.
- Local database values are supplied through ignored environment
  configuration; CI uses GitHub Actions secrets. Anyone controlling
  the laptop, Docker runtime or sufficiently privileged workflow changes
  remains within the trusted administration boundary.
- Local HTTP, session handling, authentication, audit logging, request
  rate limits and other STRIDE areas have not received a comprehensive
  security assessment.
- Passing CI checks detect selected problems. Enforcement of repository
  merge restrictions has not been established by these run results.

Maintain localhost-only exposure, protect project and secret access,
retain the regression checks and review dependency/image updates.
Reassess this model before changing deployment exposure or adding code.

## 8. References and provenance

[1] PHP Documentation Group, "include," PHP Manual.
https://www.php.net/manual/en/function.include.php
Accessed: September 29, 2026.

[2] PHP Documentation Group, "Prepared Statements," PHP Manual.
https://www.php.net/manual/en/mysqli.quickstart.prepared-statements.php
Accessed: September 29, 2026.

[3] PHP Documentation Group, "htmlspecialchars," PHP Manual.
https://www.php.net/manual/en/function.htmlspecialchars.php
Accessed: September 29, 2026.

[4] PHP Documentation Group, "proc_open," PHP Manual.
https://www.php.net/manual/en/function.proc-open.php
Accessed: September 29, 2026.

Method: SLIIT IE3142 Lab Sheet 08, "Threat Modeling," and the supplied
2026 assignment brief, section 2.2.

Project evidence: source excerpts, remediation commits, before/after
demonstrations, regression-test output and preserved CI artifacts.
Original vulnerable-code line numbers are historical references.

AI assistance: ChatGPT assisted with code interpretation, proposed
controls, testing guidance and drafting. The group must review the
assessment and disclose this assistance in the final report.