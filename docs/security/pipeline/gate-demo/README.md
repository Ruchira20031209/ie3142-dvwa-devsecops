# SAST security gate demonstration

The demonstration used branch `demo/sast-sqli-gate`.

The original vulnerable SQL injection module was restored from the
before-fix commit. After the gate blocked it, the repaired module was
restored from commit `36a60d8`.

| Check | Vulnerable run 12 | Repaired run 13 |
| --- | --- | --- |
| Source commit | 2360380 | 4d755e2 |
| New Semgrep ERROR findings | 2 | 0 |
| Gate result | BLOCKED | PASS |
| Gate exit code | 1 | 0 |
| Full SAST findings | 42 | 40 |
| Full-scan PHP files | 169 | 169 |
| Scanner errors | 0 | 0 |

## Failed run

https://github.com/Ruchira20031209/ie3142-dvwa-devsecops/actions/runs/36600072352

The gate detected SQL injection findings in
`vulnerabilities/sqli/source/low.php` at lines 10 and 31.

Both findings used the rule:
`php.lang.security.injection.tainted-sql-string.tainted-sql-string`.

Evidence is preserved in `failed-run-12/`.

## Repaired run

https://github.com/Ruchira20031209/ie3142-dvwa-devsecops/actions/runs/36602312118

Restoring input validation and prepared statements removed both new
findings. The gate passed, and the overall workflow succeeded.

Evidence is preserved in `passed-run-13/`.

## Comparison integrity

Both scans used Semgrep 1.177.0, the same frozen rules, the same gate
script and the same fixed comparison baseline. The saved checksums
and policy files record these inputs.

The gate blocks new ERROR findings relative to the repaired baseline.
The 40 existing findings remain visible in the full scan.

This demonstration proves that a reintroduced SQL injection vulnerability
causes a gate failure and that restoring the repair produces a passing run.