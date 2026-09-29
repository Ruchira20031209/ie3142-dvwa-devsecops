# SAST security gate

Policy: fail on any new Semgrep ERROR finding.
Fixed comparison baseline: `21fb6a96ffce7b16b3a807896001bba4b7a76968`.
Existing baseline findings remain in the full SAST report.
ERROR is rule severity; scanner/report errors also fail.

New ERROR findings: **2**.
Result: **BLOCKED**.

- `vulnerabilities/sqli/source/low.php:10` - `php.lang.security.injection.tainted-sql-string.tainted-sql-string`
- `vulnerabilities/sqli/source/low.php:31` - `php.lang.security.injection.tainted-sql-string.tainted-sql-string`

Gate exit code: **1**.
