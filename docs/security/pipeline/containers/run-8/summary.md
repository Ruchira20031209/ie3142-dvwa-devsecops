# Trivy container image scan

Scope: the exact images used by the DVWA and database CI containers.
Mode: report all vulnerability severities; no container severity gate yet.
Scanner errors, missing coverage and invalid reports fail the job.

| Image | Critical | High | Medium | Low | Unknown | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| dvwa | 3 | 164 | 1504 | 922 | 508 | 3101 |
| db | 1 | 21 | 42 | 22 | 1 | 87 |

- dvwa: debian 13.7; 222 OS packages catalogued; 0 HIGH/CRITICAL findings with a reported fix version.
- db: ubuntu 22.04; 151 OS packages catalogued; 22 HIGH/CRITICAL findings with a reported fix version.

Counts are package-vulnerability occurrences; a CVE may appear more than once.
