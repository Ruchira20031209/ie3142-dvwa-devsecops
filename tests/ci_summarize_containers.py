"""Validate Trivy evidence and summarize both CI service images."""

import json
import os
from collections import Counter
from pathlib import Path

output = Path(os.environ['CONTAINER_RESULTS_DIR'])
output.mkdir(parents=True, exist_ok=True)
severities = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
errors = []
details = []
lines = [
    '# Trivy container image scan',
    '',
    'Scope: the exact images used by the DVWA and database CI containers.',
    'Mode: report all vulnerability severities; no container severity gate yet.',
    'Scanner errors, missing coverage and invalid reports fail the job.',
    '',
    '| Image | Critical | High | Medium | Low | Unknown | Total |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: |',
]

for service in ('dvwa', 'db'):
    try:
        scan_exit = int((output / f'{service}-exit-code.txt').read_text().strip())
        if scan_exit != 0:
            raise ValueError(f'scanner exit code {scan_exit}')
        report = json.loads((output / f'{service}-trivy.json').read_text())
        if report.get('ArtifactType') != 'container_image':
            raise ValueError('expected a container-image report')
        metadata = report['Metadata']
        expected_id = (output / f'{service}-image-id.txt').read_text().strip()
        if metadata.get('ImageID') != expected_id:
            raise ValueError('report image ID does not match the CI container image')
        results = report['Results']
        os_packages = sum(
            len(result.get('Packages') or []) for result in results
            if result.get('Class') == 'os-pkgs'
        )
        if not os_packages:
            raise ValueError('no OS package inventory found; inspect scan coverage')
        findings = [
            finding for result in results
            for finding in (result.get('Vulnerabilities') or [])
        ]
        counts = Counter(
            finding.get('Severity') if finding.get('Severity') in severities
            else 'UNKNOWN' for finding in findings
        )
        values = ' | '.join(str(counts[level]) for level in severities)
        lines.append(f'| {service} | {values} | {len(findings)} |')
        fixable_high = sum(
            1 for finding in findings
            if finding.get('Severity') in ('HIGH', 'CRITICAL')
            and finding.get('FixedVersion')
        )
        operating_system = metadata['OS']
        details.append(
            f"- {service}: {operating_system['Family']} {operating_system['Name']}; "
            f'{os_packages} OS packages catalogued; '
            f'{fixable_high} HIGH/CRITICAL findings with a reported fix version.'
        )
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        errors.append(f'{service}: {error}')

lines += ['', *details, '',
          'Counts are package-vulnerability occurrences; a CVE may appear more than once.']
if errors:
    lines += ['', 'Scan/report errors:', *[f'- {error}' for error in errors]]
summary = '\n'.join(lines) + '\n'
print(summary)
(output / 'summary.md').write_text(summary)
with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as handle:
    handle.write(summary)
if errors:
    raise SystemExit(1)