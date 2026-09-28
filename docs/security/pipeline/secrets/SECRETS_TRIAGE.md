# Gitleaks finding review

Review date: 2026-09-28.

Original evidence: `run-5/`, downloaded from `secrets-5-1.zip`.
Source commit: `1e18cd8d891de33ccd80c7bae41a48753c14ab07`.
Run: https://github.com/Ruchira20031209/ie3142-dvwa-devsecops/actions/runs/36412811879

Gitleaks v8.30.1 reported two generic-api-key findings and exited with code 10.
Its console recorded 637 commits scanned; the checkout contained 850 commits.
The original report is preserved unchanged. The code sections were inspected
at the exact historical commits reported by Gitleaks, using git show.

## Finding 1: CSRF help-page example

- File: `vulnerabilities/csrf/help/help.php`, line 54.
- Commit: `b124bd741ed959c88c4018e86e0cb7c39b325833`.
- Context: a user-token header inside a code example introduced as a sample
  request, with the example host dvwa.test.
- Classification: documentation example; accepted as a non-production match
  based on the displayed source context. No live token validity was tested.
- Decision: exclude only this finding's exact fingerprint.

## Finding 2: public reCAPTCHA site key

- File: `external/recaptcha/recaptchalib.php`, line 41.
- Commit: `5ce2b495222960a379fc51f8e717ae0089a36c0e`.
- Context: a data-sitekey attribute in browser-rendered reCAPTCHA HTML.
- Classification: public client-side site key. Google's documentation
  distinguishes this from the backend secret key that must be kept private.
- Decision: exclude only this finding's exact fingerprint.
- Reference: https://developers.google.com/recaptcha/intro

## Exception scope and validation

The repository-root `.gitleaksignore` records the two reviewed fingerprints.
All default rules and scanning across all fetched Git refs remain enabled.
Each exception identifies a commit, file, rule and line. Other findings in
these files remain subject to the gate. Any remaining finding or scanner
error fails the job.

The next CI run must verify the result after applying these exceptions.
This change documents review of non-sensitive matches. Evidence of a real
vulnerability blocking the pipeline and its subsequent repair is a separate
assignment requirement and remains to be completed.