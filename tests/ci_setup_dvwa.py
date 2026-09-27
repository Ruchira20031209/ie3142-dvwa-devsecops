"""Initialize the disposable GitHub Actions database and test account."""

import os
import secrets
import subprocess
import time
from pathlib import Path
from urllib.error import URLError

from test_security_regression import Client


def main():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("COMPOSE_PROJECT_NAME") != "ie3142-ci"
        or not os.environ.get("GITHUB_ENV")
    ):
        raise SystemExit("This initializer is only for the disposable GitHub CI job.")

    base_url = os.environ.get("DVWA_BASE_URL")
    if base_url != "http://127.0.0.1:4280":
        raise SystemExit("Unexpected CI application address.")

    client = Client(base_url)
    for attempt in range(30):
        try:
            setup = client.request("setup.php")
            if setup.status == 200 and setup.inputs.get("user_token"):
                break
        except (URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(2)
    else:
        raise SystemExit("DVWA setup page did not become ready.")

    result = client.request("setup.php", form={
        "create_db": "Create / Reset Database",
        "user_token": setup.token(),
    })
    if result.status != 200 or "Setup successful" not in result.text:
        raise SystemExit("DVWA database initialization failed.")
    print("CI database initialized.", flush=True)

    # Generate a fresh CI login password and mask it before any further use.
    password = secrets.token_hex(32)
    print(f"::add-mask::{password}", flush=True)
    child_env = dict(os.environ, DVWA_PASSWORD=password)

    # DVWA's existing login uses MD5; this preserves its current login format.
    php = r"""<?php
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
try {
    $db = new mysqli(
        getenv('DB_SERVER'), getenv('DB_USER'), getenv('DB_PASSWORD'),
        getenv('DB_DATABASE'), (int) getenv('DB_PORT')
    );
    $password = getenv('DVWA_PASSWORD');
    if (!is_string($password) || strlen($password) !== 64) {
        throw new RuntimeException('Missing CI login password.');
    }
    $hash = md5($password);
    $stmt = $db->prepare('UPDATE users SET password = ? WHERE user_id = 1');
    $stmt->bind_param('s', $hash);
    $stmt->execute();
    if ($stmt->affected_rows !== 1) {
        throw new RuntimeException('CI admin account was not updated.');
    }
    $stmt->close();
    $db->close();
    echo "Temporary CI login configured.\n";
} catch (Throwable $error) {
    fwrite(STDERR, "CI login configuration failed.\n");
    exit(1);
}
"""
    subprocess.run(
        ["docker", "compose", "exec", "-T", "-e", "DVWA_PASSWORD", "dvwa", "php"],
        input=php, text=True, check=True, env=child_env,
    )

    # Make the login available to subsequent steps without storing it in Git.
    with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as handle:
        handle.write(f"DVWA_USERNAME=admin\nDVWA_PASSWORD={password}\n")

    results = Path(os.environ["CI_RESULTS_DIR"])
    results.mkdir(parents=True, exist_ok=True)
    (results / "setup-status.txt").write_text(
        "CI database initialized; temporary test login configured.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()