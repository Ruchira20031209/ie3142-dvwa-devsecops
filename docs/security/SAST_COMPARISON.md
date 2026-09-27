# SAST Comparison and Finding Review

## Scan scope

Both scans used Semgrep Community Edition 1.177.0 with the OSS
engine and the saved `.semgrep/php.yml` configuration.

Both scans examined the same 169 tracked files selected by the
PHP include pattern. The scan summaries reported 23 rules run.

The after-fix source checkpoint is commit `0356ae1`.
Each scan's full source commit is recorded in its source-commit.txt.

## Overall results

| Measurement | Before | After |
|---|---:|---:|
| Total findings | 44 | 40 |
| ERROR severity | 24 | 21 |
| WARNING severity | 20 | 19 |
| Files scanned | 169 | 169 |
| Rules run | 23 | 23 |
| Reported scanner errors | 0 | 0 |
| Scanner exit code | 0 | 0 |

The raw finding count decreased by four.

Comparing rule ID, file path, location and severity identified
six removed finding locations, two findings at the replacement
command-execution call, and 38 unchanged findings.

Finding counts represent scanner alerts. One vulnerability can
produce multiple alerts.

## Selected remediation areas

| Area | Before | After | Review |
|---|---:|---:|---|
| SQL injection: sqli/source/low.php | 2 | 0 | Both SQL-construction alerts disappeared. Prepared statements and positive-integer validation were implemented. |
| Command injection: exec/source/low.php | 4 | 2 | Both remaining alerts refer to the same proc_open call and were reviewed below. |
| Reflected XSS: xss_r/source/low.php | 0 | 0 | The original vulnerability was demonstrated manually. The fix applies HTML output encoding. |
| File inclusion: fi/source/low.php and fi/index.php | 0 | 0 | The original vulnerability was demonstrated manually. The fix restricts selection to a fixed mapping of approved files. |

All five source/sink files listed above were included in both scans.

## Review of the command-injection alerts

Both after-scan alerts occur at line 31 of
`vulnerabilities/exec/source/low.php`:

- WARNING: `php.lang.security.injection.tainted-exec.tainted-exec`
- ERROR: `php.lang.security.tainted-exec.tainted-exec`

The statement is:
`$process = proc_open($command, $descriptors, $pipes);`

Review classification: false positives for command injection
in the reviewed Linux/PHP implementation.

The input must be a string containing a valid IP address.
The executable is fixed as /usr/bin/ping. The options are fixed,
and the IP is passed as a separate argument after the "--"
option terminator. The command is an argument array, so PHP
starts the process without invoking a shell.

Normal loopback ping still works. The original input containing
a semicolon and an echo command is rejected as an invalid IP.

This classification applies specifically to the reviewed call
and its validation. Changes to this code require another review.

## Coverage and limitations

This scan configuration did not report the manually demonstrated
reflected-XSS and low-level file-inclusion vulnerabilities before
remediation. Their zero counts are therefore a detection gap.

The recorded browser tests showed normal functionality and
rejection or neutralisation of the original inputs after fixing
all four selected vulnerabilities.

The SQL injection browser tests used the MySQL backend.
The SQLite code path was updated but has not been runtime-tested.

The other 38 findings are outside these selected remediation
areas and remain in the raw report. They require separate review.
This work does not establish that the entire DVWA application
is secure.

The comparison retains the raw scanner output. The two reviewed
alerts remain included in the total of 40.

An exit code of zero from this scan does not demonstrate a
blocking CI security gate. That gate will be configured and
tested separately.

## Evidence locations

- Before scan: docs/security/baseline/sast/
- After scan: docs/security/remediation/sast/
- Before browser demonstrations: docs/security/baseline/screenshots/
- After browser demonstrations: docs/security/remediation/sqli/,
  xss/, cmd/ and fi/

## References

- PHP proc_open documentation:
  https://www.php.net/manual/en/function.proc-open.php
- Semgrep CLI and exit-code documentation:
  https://semgrep.dev/docs/cli-reference