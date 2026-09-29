# IE3142 — DVWA DevSecOps Project

SLIIT DevOps Security group assignment using Damn Vulnerable Web
Application (DVWA), PHP/Apache and MariaDB.

This project demonstrates threat modelling, four targeted vulnerability
repairs, regression testing and a GitHub Actions security pipeline.

DVWA remains deliberately vulnerable outside the selected repairs.
Run this project as a local teaching lab. The Compose configuration
publishes the web application only on 127.0.0.1.

## Group

| Student ID | Name |
| --- | --- |
| IT24102823 | W. Sasnuka Indisa |
| IT24103196 | Ubhayarathna K.S.N |
| IT24101313 | Wanigasinghe R.K. |
| IT24103061 | Nimsara M.A.K |

Group number: awaiting allocation.

Individual contributions and signatures are recorded separately in the
submission. This member list does not assign or imply contribution shares.

## Project and upstream source

- Group repository: https://github.com/Ruchira20031209/ie3142-dvwa-devsecops
- Upstream project: https://github.com/digininja/DVWA
- Original guide: [README.upstream.md](README.upstream.md)

The group modified an existing application rather than building DVWA
from scratch. DVWA's GPLv3-or-later licensing and existing notices apply.

Use the instructions below for the group's Docker-based deployment.

## 1. Requirements

The project has been run on an Apple M4 MacBook using Docker Desktop.

Required:
- Docker Desktop running, including Docker Compose v2.
- Git and access to the group repository.
- A terminal; VS Code's integrated terminal is suitable.
- Internet access for the initial clone, image downloads and build.
- OpenSSL for generating fresh local database credentials.

PHP, Apache, MariaDB and Composer run inside containers.
The regression-test instructions below also use a Python container.

Run terminal commands from the repository root, where compose.yml,
Dockerfile and this README are located.

## 2. Architecture

| Component | Purpose |
| --- | --- |
| dvwa | Locally built PHP/Apache application image: ie3142-dvwa:local |
| db | MariaDB 10.11 database service |
| dvwa network | Communication between application and database |
| dvwa volume | Persistent database storage at /var/lib/mysql |

Browser address: http://127.0.0.1:4280

The application connects to db:3306 inside Docker.
The database has no published host port.

See the [architecture diagram](docs/architecture/DVWA_Architecture.png)
and [threat model](docs/security/THREAT_MODEL.md).

## 3. First setup on a new machine

### Clone

```bash
git clone https://github.com/Ruchira20031209/ie3142-dvwa-devsecops.git
cd ie3142-dvwa-devsecops
```

Authenticate with GitHub when required for private-repository access.

### Create local database credentials

The following creates .env only when it does not already exist:

```bash
if [ ! -e .env ]; then
  (
    umask 077
    printf 'DB_PASSWORD=%s\nDB_ROOT_PASSWORD=%s\n' \
      "$(openssl rand -hex 32)" \
      "$(openssl rand -hex 32)" > .env
  )
fi
```

The Compose file requires DB_PASSWORD and DB_ROOT_PASSWORD.
Keep .env private and excluded from Git.

Keep the existing credentials when reusing an initialized database
volume. Editing .env alone does not change existing database passwords.

### Build and start

```bash
docker compose config --quiet
docker compose up -d --build --wait
docker compose ps
```

The first build downloads the required images and dependencies.

### Initialize a fresh DVWA database

1. Open http://127.0.0.1:4280/setup.php.
2. For a new database, select Create / Reset Database.
3. Open http://127.0.0.1:4280/login.php.
4. Use the initial DVWA lab login: admin / password.
5. Open DVWA Security, select Low and submit.

The database-reset action resets lab data. It is a first-setup action,
not part of normal startup.

The lab login is separate from the generated database credentials.
The four repaired modules are the Low-security implementations.

## 4. Normal startup and offline operation

After initial setup, with the application and database images cached:

```bash
docker compose up -d --no-build --pull never --wait
```

Open http://127.0.0.1:4280.

This command uses existing images without rebuilding or pulling.
Offline operation requires those images, the local configuration and
Docker Desktop to remain available.

Check status:

```bash
docker compose ps
```

Stop the application while retaining its containers and database:

```bash
docker compose stop
```

The MariaDB data is stored in a named volume. Preserve that volume
when retaining the lab's current data.

GitHub Actions and fresh vulnerability-database downloads require
internet access; the offline claim concerns the prepared local lab.

## 5. Running the security regression tests

While online, download the test image once:

```bash
docker pull python:3.12-slim
```

Start DVWA using the normal startup command above. Initialize the
database first if this is a new installation.

Run the tests from the repository root:

```bash
docker run --rm --pull never \
  --network "container:$(docker compose ps -q dvwa)" \
  -e DVWA_BASE_URL=http://127.0.0.1 \
  -e DVWA_USERNAME=admin \
  -e DVWA_PASSWORD=password \
  -v "$PWD/tests:/tests:ro" \
  python:3.12-slim \
  python -B -u /tests/test_security_regression.py
```

The test container shares the web container's network namespace, so its
target is the application's internal port 80.

Expected result: 14 tests pass and the process exits with code 0.

The suite checks login, Low security and the MySQL backend, then checks
normal requests, the original demonstration inputs and malformed array
inputs. It uses Python's standard library.

These instructions assume the initial local DVWA lab login is unchanged.
CI initializes its own disposable database and uses a separate runtime
login password.

## 6. Updating application code

The application source is copied into the image during the build.
A saved PHP edit requires rebuilding and recreating the web container:

```bash
docker compose up -d --build --force-recreate --no-deps dvwa
```

Keep the database service running, then repeat the regression tests.

Rebuilding can require internet access if dependencies or build layers
are not cached.

## 7. Selected repairs

| Module | Implemented control | Original repair commit |
| --- | --- | --- |
| SQL injection | Positive integer validation and prepared statements | 747ce16 |
| Reflected XSS | String validation and HTML text encoding | df34565 |
| Command injection | Literal IP validation and direct argument-array execution | c32e7d3 |
| File inclusion | Fixed mapping of permitted page names to local files | 0356ae1 |

Before/after demonstrations retained the Low setting.

The demonstrated SQL backend is MariaDB/MySQL. The SQLite branch was
repaired in code but was not runtime-tested.

## 8. GitHub Actions pipeline

Workflow: [.github/workflows/devsecops.yml](.github/workflows/devsecops.yml)

The workflow runs on pushes and can also be started manually.

| Check | Tool or approach | Policy |
| --- | --- | --- |
| Build and tests | Docker Compose and Python regression suite | Build/setup/test failures fail the job |
| SAST | Semgrep with frozen PHP rules | New ERROR findings relative to the fixed repaired baseline fail the gate |
| SCA | Composer audit of the locked API dependencies | Advisories, abandoned dependencies and audit failures fail the job |
| Secrets | Gitleaks across fetched Git history | Findings remaining after reviewed exceptions fail the job |
| Container images | Trivy on the images used by CI | Findings are reported; scanner/coverage errors fail the job |

Container scanning runs inside the build-and-test job.
A successful workflow does not mean the container reports contain
zero vulnerabilities.

The workflow records source commits, tool versions, scan reports and
exit codes in downloadable artifacts. Relevant evidence is also
preserved under docs/security.

### CI secrets

The repository uses these GitHub Actions secret names:

- CI_DB_PASSWORD
- CI_DB_ROOT_PASSWORD

Their values are supplied at runtime and are not documented here.
Local .env configuration is separate from GitHub Actions secrets.

Reviewed Gitleaks exceptions are documented in:

- [Original triage](docs/security/pipeline/secrets/SECRETS_TRIAGE.md)
- [Trivy metadata review](docs/security/pipeline/secrets/TRIVY_REPORT_REVIEW.md)

## 9. Verified SAST gate demonstration

Demonstration branch: demo/sast-sqli-gate

| Run | Change | New ERROR findings | Gate |
| --- | --- | --- | --- |
| 12 — 2360380 | Reintroduced original SQLi code | 2 | BLOCKED, exit 1 |
| 13 — 4d755e2 | Restored the SQLi repair | 0 | PASS, exit 0 |

The scanner rules, gate script and fixed baseline were unchanged
between these runs.

- [Failed run](https://github.com/Ruchira20031209/ie3142-dvwa-devsecops/actions/runs/36600072352)
- [Passing run](https://github.com/Ruchira20031209/ie3142-dvwa-devsecops/actions/runs/36602312118)
- [Preserved comparison and artifacts](docs/security/pipeline/gate-demo/README.md)

The original four-repair SAST comparison reduced total findings from
44 to 40. Existing findings remain visible in the full scan.

## 10. Evidence and limitations

- [Architecture](docs/architecture/)
- [Threat model and residual risks](docs/security/THREAT_MODEL.md)
- [Remediation evidence](docs/security/remediation/)
- [Pipeline evidence](docs/security/pipeline/)
- [Gate failure and recovery](docs/security/pipeline/gate-demo/)

The four repairs do not secure every DVWA module. SAST coverage has
limits, and dependency/container results depend on the scanned versions
and advisory database at scan time.

The demonstrated gate fails CI. Repository branch-protection or merge
restrictions require separate configuration and verification.

## 11. AI assistance

ChatGPT assisted with explanations, remediation guidance, test and
pipeline development, troubleshooting and documentation drafting.
The group is responsible for reviewing the work, understanding the
implementation and accurately recording individual contributions.
The final report includes the required AI disclosure.