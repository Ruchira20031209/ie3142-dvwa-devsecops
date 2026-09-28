"""Save sanitized Gitleaks findings and the CI summary."""

import json
import os
from pathlib import Path

output = Path(os.environ['SECRETS_RESULTS_DIR'])
raw = Path(os.environ['RUNNER_TEMP']) / 'ie3142-gitleaks-raw/gitleaks.json'

if not raw.is_file() or raw.stat().st_size == 0:
    raise SystemExit('No Gitleaks report was produced. Check the scan log.')

try:
    findings = json.loads(raw.read_text())
finally:
    raw.unlink(missing_ok=True)

scan_exit = int((output / 'exit-code.txt').read_text().strip())

if findings is None and scan_exit == 0:
    findings = []

if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
    raise SystemExit('Unexpected Gitleaks report format.')

# Preserve locations, but omit Secret, Match and commit Message fields.
fields = ('RuleID', 'File', 'StartLine', 'EndLine', 'Commit', 'Fingerprint')
safe_findings = [{key: finding.get(key) for key in fields} for finding in findings]

(output / 'gitleaks-locations.json').write_text(
    json.dumps(safe_findings, indent=2) + '\n'
)

commits = int((output / 'commits-available.txt').read_text().strip())
exception_count = sum(
    1 for line in (output / 'gitleaksignore.txt').read_text().splitlines()
    if line.strip() and not line.lstrip().startswith('#')
)

summary = '\n'.join([
    '# Gitleaks secret scan',
    '',
    'Scope: Git history across all fetched refs.',
    'Rules: built-in defaults with reviewed fingerprint exceptions.',
    f'Reviewed fingerprint exceptions configured: {exception_count}',
    'Exception details: gitleaksignore.txt and triage.md.',
    f'Commits available in checkout: {commits}',
    f'Findings after reviewed exceptions: {len(findings)}',
    f'Gitleaks exit code: {scan_exit}',
    'Policy: any remaining finding or scanner error fails this job.',
    'The saved JSON contains finding locations, without matched values.',
]) + '\n'

print(summary)
(output / 'summary.md').write_text(summary)

with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as handle:
    handle.write(summary)

if scan_exit != (10 if findings else 0):
    raise SystemExit('Unexpected scanner result. Review the scan log.')