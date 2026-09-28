# Review of secret-scan matches in Trivy reports

Review date: 2026-09-29 (Sri Lanka).
Affected workflow: run 9, source commit 16cc31e.
Run: https://github.com/Ruchira20031209/ie3142-dvwa-devsecops/actions/runs/36478380824
Original evidence: secrets-9-1.zip, retained in the project scan_results folder.

All 11,042 reported findings were introduced with the two saved run-8 Trivy
JSON reports. The reported locations were compared with those original reports.

| Rule | Report | Finding occurrences | Reviewed content |
| --- | --- | ---: | --- |
| sourcegraph-access-token | dvwa-trivy.json | 11,037 | Public Git/build hashes and public signing-key fingerprints |
| generic-api-key | db-trivy.json | 5 | Public MariaDB signing-key fingerprint in image build history |

The first group covers 11,033 distinct lines: 11,018 public reference URL
lines, 13 advisory-description lines containing commit/build identifiers,
and 2 GPG_KEYS metadata lines. Multiple fingerprints on those two lines
account for four additional finding occurrences.

The five database findings are at lines 69, 75, 80, 115 and 120. They name
the same public MariaDB signing-key fingerprint, also published in the
official MariaDB 10.11 Dockerfile. They are not private signing keys.

## Decision and scope

The repository-root .gitleaks.toml adds two rule-specific allowlists. Each
requires the introducing commit AND the exact report path AND the reviewed
public-value pattern. They do not apply to other rules, other files or
findings introduced by later commits. The existing two fingerprint
exceptions remain in .gitleaksignore. Default detection rules remain enabled.

The original Trivy JSON reports remain unchanged. Their SHA-256 checksums are:

```text
d43550b6a20b30022c1513dfa008dd52df1a44ea4ef476fe2e342ca8c08661c9  dvwa-trivy.json
f540fec0f89257ce3deb46da8d443068c94200b09c1af357a3c4655ab2204c6d  db-trivy.json
```

The next CI run must verify the result with these scoped exceptions.
This is false-positive triage. The separate demonstration of a real SQL
injection causing a SAST gate failure remains to be completed.

References:
- https://github.com/gitleaks/gitleaks/blob/master/README.md
- https://github.com/gitleaks/gitleaks/issues/1898
- https://github.com/MariaDB/mariadb-docker/blob/master/10.11/Dockerfile