"""Block new Semgrep ERROR findings relative to the repaired baseline."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

BASELINE = '21fb6a96ffce7b16b3a807896001bba4b7a76968'
IMAGE = 'semgrep/semgrep@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198'
RULES_SHA256 = 'ccfc3341c7ac7a66b85f249713a277f4d4a0e9de93c75c609e2f82e52f0aabac'


def checked_findings(report, scan_exit):
    if report['version'] != '1.177.0':
        raise ValueError('Unexpected Semgrep version.')
    if report['errors'] or report.get('skipped_rules', []):
        raise ValueError('Differential scan contains errors or skipped rules.')
    findings = report['results']
    if not isinstance(findings, list):
        raise ValueError('Invalid results list.')
    if any(item['extra']['severity'] != 'ERROR' for item in findings):
        raise ValueError('Unexpected finding severity.')
    if scan_exit != (1 if findings else 0):
        raise ValueError(f'Scanner exit code {scan_exit} disagrees with report.')
    return findings


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Run this script through GitHub Actions.')
    output = Path(os.environ['SAST_RESULTS_DIR']).resolve()
    output.mkdir(parents=True, exist_ok=True)
    lines = [
        '# SAST security gate', '',
        'Policy: fail on any new Semgrep ERROR finding.',
        f'Fixed comparison baseline: `{BASELINE}`.',
        'Existing baseline findings remain in the full SAST report.',
        'ERROR is rule severity; scanner/report errors also fail.', '',
    ]
    gate_exit = 2
    try:
        workspace = Path.cwd().resolve()
        rules_hash = hashlib.sha256(Path('.semgrep/php.yml').read_bytes()).hexdigest()
        if rules_hash != RULES_SHA256:
            raise ValueError('Frozen rules changed; review the gate policy.')
        if (output / 'scanner-image.txt').read_text().strip() != IMAGE:
            raise ValueError('Full scan and gate must use the same pinned scanner.')
        subprocess.run(['git', 'merge-base', '--is-ancestor', BASELINE, 'HEAD'], check=True)
        subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], check=True)
        policy = {
            'baseline_commit': BASELINE, 'blocking_severity': 'ERROR',
            'scope': 'new findings across PHP files relative to the fixed baseline',
            'scanner_image': IMAGE, 'rules_sha256': rules_hash,
        }
        (output / 'gate-policy.json').write_text(json.dumps(policy, indent=2) + '\n')
        script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        (output / 'gate-script.sha256').write_text(f'{script_hash}  tests/ci_gate_sast.py\n')
        command = [
            'docker', 'run', '--rm', '--network', 'none',
            '--user', f'{os.getuid()}:{os.getgid()}', '-e', 'HOME=/tmp',
            '-v', f'{workspace}:/src', '-v', f'{output}:/results', '-w', '/src',
            IMAGE, 'semgrep', 'scan', '--config', '.semgrep/php.yml',
            '--baseline-commit', BASELINE, '--severity', 'ERROR', '--error', '--strict',
            '--oss-only', '--metrics=off', '--disable-version-check',
            '--no-rewrite-rule-ids', '--include', '*.php',
            '--json-output', '/results/gate.json',
            '--sarif-output', '/results/gate.sarif', '.',
        ]
        (output / 'gate-command.json').write_text(json.dumps(command, indent=2) + '\n')
        with (output / 'gate-console.txt').open('w') as log:
            with subprocess.Popen(command, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True) as process:
                for line in process.stdout:
                    print(line, end='', flush=True)
                    log.write(line)
                scan_exit = process.wait()
        (output / 'gate-scanner-exit-code.txt').write_text(f'{scan_exit}\n')
        findings = checked_findings(json.loads((output / 'gate.json').read_text()), scan_exit)
        gate_exit = 1 if findings else 0
        lines += [f'New ERROR findings: **{len(findings)}**.',
                  f'Result: **{"BLOCKED" if findings else "PASS"}**.', '']
        for item in findings:
            lines.append(f"- `{item['path']}:{item['start']['line']}` - `{item['check_id']}`")
    except (OSError, ValueError, KeyError, TypeError, AttributeError,
            subprocess.SubprocessError) as error:
        gate_exit = 2
        lines += ['Result: **ERROR - scan or policy validation failed**.', str(error)]
    lines += ['', f'Gate exit code: **{gate_exit}**.']
    summary = '\n'.join(lines) + '\n'
    print(summary, flush=True)
    (output / 'gate-summary.md').write_text(summary)
    (output / 'gate-exit-code.txt').write_text(f'{gate_exit}\n')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as handle:
        handle.write(summary)
    raise SystemExit(gate_exit)


if __name__ == '__main__':
    main()