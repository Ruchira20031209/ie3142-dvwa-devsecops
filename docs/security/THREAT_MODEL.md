# DVWA Threat Model and Risk Assessment

**Status:** Draft 1 — source review; exploit demonstrations and mitigation verification pending.  
**Review date:** 26 September 2026.  
**Last confirmed project commit:** `8a72d1d` (`docs: add DVWA runtime architecture`).  
**Project:** [IE3142 DVWA DevSecOps](https://github.com/Ruchira20031209/ie3142-dvwa-devsecops).

## 1. Scope and assumptions

This model covers four selected **Low-security implementations** in the group's local DVWA copy: SQL injection, reflected XSS, command injection, and file inclusion. Source evidence comes from the PHP excerpts supplied by the group. Line numbers below refer to those excerpts before remediation.

The last observed running security setting was **Impossible**. Planned before/after demonstrations will explicitly select **Low** and retain that level while testing the group's code fixes. The findings below concern the inspected Low implementations, and do not establish a vulnerability in an Impossible implementation.

The assumed attacker can interact with the local DVWA instance and has an authenticated session for the selected exercises. The file-inclusion controller explicitly calls `dvwaPageStartup(array('authenticated'))` on line 6. The reflected-XSS scenario additionally requires a user to load an attacker-controlled request.

DVWA runs as PHP and Apache in a Linux container on Docker Desktop. MariaDB 10.11 is a separate service. The web service is published at `127.0.0.1:4280`; MariaDB has no published host port. The services share the Compose network `dvwa`. These settings limit network exposure, but unsafe inputs can still reach the application through an authenticated local session.

Impact is assessed within the lab, using synthetic data and the permissions available to the affected process. Host administrator access, a container escape, and access to unrelated systems are not established by these findings.

## 2. Architecture, assets and boundaries

See [the architecture diagram](../architecture/DVWA_Architecture.png) and [its editable source](../architecture/DVWA_Architecture.drawio).

| Element | Asset or role |
|---|---|
| E1 — Browser / tester | Browser page content and authenticated user actions. |
| P1 — DVWA | Request handling and the web-server process's execution privileges. |
| P2 — MariaDB | Application records accessible to the database user `dvwa`. |
| D1 — Web files | Web-container files, sessions and uploads; access depends on filesystem permissions. |
| D2 — Database volume | Persistent database files, mounted at `/var/lib/mysql` in the database container. |

**TB1** surrounds the web container: F1 carries browser input into P1; F2 returns HTML and cookies. **TB2** surrounds the database container: F3 carries application queries to P2; F4 returns results. F5 represents P1's filesystem access to D1. F6 represents database persistence to D2. A dashed container boundary identifies a change in control; it does not itself validate input.

## 3. Risk method: 3 × 3 matrix

**Risk score = likelihood × impact.** These are qualitative estimates from source review, before the targeted code fixes. Likelihood is conditional on authenticated local access and the selected Low implementation being active; it is not an estimate of internet-wide attack probability.

| Rating | Likelihood | Impact within the assessed lab |
|---|---|---|
| 1 — Low | Several additional barriers or uncertain conditions are needed. | Small, contained disruption with little effect on protected assets. |
| 2 — Medium | Extra interaction or another condition is needed. | Browser-page integrity or a limited user context is affected. |
| 3 — High | Input directly reaches a sensitive operation with few additional conditions. | Broad application-data exposure, arbitrary file access, or execution with server-process permissions. |

| Likelihood ↓ / Impact → | 1 — Low | 2 — Medium | 3 — High |
|---|---|---|---|
| 3 — High | 3 — Medium | 6 — High | 9 — High |
| 2 — Medium | 2 — Low | 4 — Medium | 6 — High |
| 1 — Low | 1 — Low | 2 — Low | 3 — Medium |

Priority bands: **Low = 1–2; Medium = 3–4; High = 6–9**. These are the possible score bands for this matrix. Ratings must be revisited if testing changes the assumptions or demonstrated impact.

## 4. Initial risk register

| ID | Threat | STRIDE category | L × I | Priority | Status |
|---|---|---|---|---|---|
| T1 | SQL injection exposes additional database records | Information disclosure; Tampering of query logic | 3 × 3 = 9 | High | Open |
| T2 | Reflected XSS changes a user's DVWA page | Tampering | 2 × 2 = 4 | Medium | Open |
| T3 | Command injection executes unintended server commands | Elevation of privilege | 3 × 3 = 9 | High | Open |
| T4 | File inclusion accesses files outside the permitted page set | Information disclosure | 3 × 3 = 9 | High | Open |

**Open** means the targeted mitigation has not yet been implemented and verified. It does not mean that a working exploit has already been recorded.

### T1 — SQL injection

**Scenario and evidence:** In `vulnerabilities/sqli/source/low.php`, line 5 obtains `id` from the request. Lines 10–11 interpolate it into a MySQL query and execute the resulting SQL. An authenticated caller could change the query's selection logic and retrieve additional data accessible to the application's database account. The file also contains an unsafe SQLite query on lines 31–34; the current deployment uses MariaDB.

**Diagram mapping:** F1 → P1 → F3 → P2, with results returning through F4 and F2. The affected boundaries are TB1 and TB2.

**Rating justification:** L3 reflects direct input-to-query construction with no parameter binding in the shown code. I3 reflects potential disclosure beyond the requested record, within the database account's permissions; database modification and authentication bypass have not been demonstrated.

**Planned control:** C1.

### T2 — Reflected cross-site scripting

**Scenario and evidence:** In `vulnerabilities/xss_r/source/low.php`, line 8 places the submitted `name` into an HTML response without encoding. A user loading a crafted request could receive attacker-controlled markup or script in the DVWA page. The primary modelled consequence is tampering with page content. Cookie theft is not assumed.

**Diagram mapping:** F1 → P1 → F2 → E1. Untrusted input crosses TB1 and returns in browser-interpreted content.

**Rating justification:** L2 reflects the requirement for a user to load the crafted request. I2 reflects the scoped browser-page integrity effect; a harmless script demonstration alone would not establish account takeover or wider data loss.

**Planned control:** C2.

### T3 — Operating-system command injection

**Scenario and evidence:** In `vulnerabilities/exec/source/low.php`, line 5 reads `ip`. The Linux branch on line 14 concatenates it into `shell_exec('ping -c 4 ' . $target)`. Crafted input could introduce additional shell commands, giving a web caller actions available to the web-server process. The Windows branch on line 10 uses the same unsafe construction, but Linux is the current runtime.

**Diagram mapping:** F1 → P1 across TB1. Consequences may affect P1's availability and files accessible through F5/D1. D2 is mounted in the database container, not directly in P1.

**Rating justification:** L3 reflects direct input-to-shell construction without an IP check in the shown code. I3 reflects execution with server-process permissions, potentially affecting application files or availability; Mac administrator privileges and a container escape are not implied.

**Planned control:** C3.

### T4 — Unsafe file inclusion / path traversal

**Scenario and evidence:** `vulnerabilities/fi/source/low.php` line 4 assigns the requested `page` to `$file`. In `vulnerabilities/fi/index.php`, lines 17–32 select and load the security-level implementation, and lines 35–36 pass `$file` to `include`. Under Low, the shown path has no allowlist restricting the requested file. A caller could select a readable local file outside the intended page set. PHP content is evaluated when included, so the exact effect depends on the selected file [1].

**Diagram mapping:** F1 → P1 → F5/D1, with resulting output returned to E1. The entry point crosses TB1.

**Rating justification:** L3 reflects caller-controlled filename selection reaching `include` directly once the session and Low-level assumptions hold. I3 reflects potentially broad disclosure of files readable by the web process; the demonstration must establish the actual scope using a harmless lab fixture.

**Planned control:** C4.

## 5. Threat-to-control mapping — planned changes

| Control | Threat | Proposed implementation and location |
|---|---|---|
| C1 | T1 | In `vulnerabilities/sqli/source/low.php`, validate the ID and replace SQL interpolation with prepared statements and bound values [2]. Parameterize both retained database branches, encode displayed values, and avoid returning detailed database errors to the browser. |
| C2 | T2 | In `vulnerabilities/xss_r/source/low.php`, validate that the name is a string and encode it for the HTML text context using `htmlspecialchars` with `ENT_QUOTES`, `ENT_SUBSTITUTE`, and explicit UTF-8 [3]. |
| C3 | T3 | In `vulnerabilities/exec/source/low.php`, validate a literal IP address and use a fixed executable with an argument array rather than a shell-built command. PHP supports direct process execution with an array through `proc_open` [4]. Bound execution time and output; encode displayed output. |
| C4 | T4 | In `vulnerabilities/fi/source/low.php`, map an explicit set of permitted page identifiers to server-owned local paths. Reject other values before the `include` in `vulnerabilities/fi/index.php`. Confirm the existing legitimate page names before implementing the map. |

These are proposed locations, not completed changes. No remediation commit or passing test is claimed. Existing container and network settings limit exposure but do not substitute for these code controls.

## 6. Verification and scope limits

For each threat, retain the exact request/input and capture its effect before remediation. After the corresponding code change, repeat the same request at the same Low security level, confirm the unwanted effect is blocked, and verify legitimate use still works. Record the patch commit, before/after screenshots, and SAST finding counts or diff using a consistent scan configuration. All of this evidence is currently **pending**.

Only mark a threat **Mitigated** after its control is implemented and verified. Residual ratings are unassigned until that review. Four targeted fixes will not establish that the rest of DVWA is secure; other deliberately vulnerable modules remain outside this remediation scope.

STRIDE categories can overlap, and separate vulnerabilities can share a category. These four entries concentrate on Information disclosure, Tampering and Elevation of privilege. Spoofing, Repudiation and Denial of service are further review areas for authentication/session controls, audit logging and resource limits; they are not claimed as assessed findings here.

## 7. References and provenance

[1] PHP Documentation Group, “include,” PHP Manual. [Online]. Available: https://www.php.net/manual/en/function.include.php. Accessed: Sep. 26, 2026.

[2] PHP Documentation Group, “Prepared Statements,” PHP Manual. [Online]. Available: https://www.php.net/manual/en/mysqli.quickstart.prepared-statements.php. Accessed: Sep. 26, 2026.

[3] PHP Documentation Group, “htmlspecialchars,” PHP Manual. [Online]. Available: https://www.php.net/manual/en/function.htmlspecialchars.php. Accessed: Sep. 26, 2026.

[4] PHP Documentation Group, “proc_open,” PHP Manual. [Online]. Available: https://www.php.net/manual/en/function.proc-open.php. Accessed: Sep. 26, 2026.

Method and submission requirements: SLIIT, IE3142 Lab Sheet 08, “Threat Modeling,” and the supplied 2026 assignment brief, section 2.2. Project-specific findings are based on the group's supplied source excerpts and confirmed Compose setup.

**AI assistance:** ChatGPT assisted with interpretation, organisation and drafting from the supplied code. Group review and practical verification are pending; this assistance must also be included in the final report's AI disclosure.
