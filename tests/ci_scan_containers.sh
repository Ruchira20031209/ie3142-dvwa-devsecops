#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "Run this script through GitHub Actions."
  exit 1
fi

# Trivy v0.74.0, pinned to its published container image digest.
TRIVY_IMAGE="ghcr.io/aquasecurity/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
trivy_cache_dir="$RUNNER_TEMP/ie3142-trivy-cache"
trivy_input_dir="$RUNNER_TEMP/ie3142-trivy-inputs"
mkdir -p "$CONTAINER_RESULTS_DIR" "$trivy_cache_dir" "$trivy_input_dir"

git rev-parse HEAD > "$CONTAINER_RESULTS_DIR/source-commit.txt"
sha256sum tests/ci_scan_containers.sh tests/ci_summarize_containers.py \
  > "$CONTAINER_RESULTS_DIR/scripts.sha256"
printf '%s/%s/actions/runs/%s\n' \
  "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID" \
  > "$CONTAINER_RESULTS_DIR/run-url.txt"
printf '%s\n' "$TRIVY_IMAGE" > "$CONTAINER_RESULTS_DIR/scanner-image.txt"
: > "$CONTAINER_RESULTS_DIR/empty-trivyignore.txt"

docker pull "$TRIVY_IMAGE"
docker run --rm -v "$trivy_cache_dir:/cache" "$TRIVY_IMAGE" image \
  --cache-dir /cache --download-db-only --no-progress \
  --disable-telemetry --skip-version-check --timeout 10m \
  2>&1 | tee "$CONTAINER_RESULTS_DIR/database-download-console.txt"
cp "$trivy_cache_dir/db/metadata.json" "$CONTAINER_RESULTS_DIR/database-metadata.json"
docker run --rm --network none -v "$trivy_cache_dir:/cache" \
  "$TRIVY_IMAGE" version --cache-dir /cache --format json \
  > "$CONTAINER_RESULTS_DIR/trivy-version.json"

overall_exit=0
for service in dvwa db; do
  container_id=$(docker compose ps -q "$service")
  if [[ -z "$container_id" ]]; then
    echo "::error::No running CI container found for $service."
    exit 1
  fi
  image_id=$(docker inspect --format '{{.Image}}' "$container_id")
  printf '%s\n' "$image_id" > "$CONTAINER_RESULTS_DIR/$service-image-id.txt"
  docker image inspect --format '{{json .RepoDigests}}' "$image_id" \
    > "$CONTAINER_RESULTS_DIR/$service-repo-digests.json"
  docker image save --output "$trivy_input_dir/$service.tar" "$image_id"
  sha256sum "$trivy_input_dir/$service.tar" \
    > "$CONTAINER_RESULTS_DIR/$service-archive.sha256"
  date -u +'%Y-%m-%dT%H:%M:%SZ' > "$CONTAINER_RESULTS_DIR/$service-scan-time-utc.txt"

  set +e
  docker run --rm --network none \
    -v "$trivy_cache_dir:/cache" \
    -v "$trivy_input_dir:/inputs:ro" \
    -v "$CONTAINER_RESULTS_DIR:/results" \
    "$TRIVY_IMAGE" image \
    --cache-dir /cache --input "/inputs/$service.tar" \
    --scanners vuln --pkg-types os,library --list-all-pkgs \
    --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
    --ignorefile /results/empty-trivyignore.txt \
    --skip-db-update --skip-java-db-update --offline-scan \
    --disable-telemetry --skip-version-check --no-progress --timeout 10m \
    --exit-code 0 --format json --output "/results/$service-trivy.json" \
    2>&1 | tee "$CONTAINER_RESULTS_DIR/$service-trivy-console.txt"
  scan_exit=$?
  set -e
  printf '%s\n' "$scan_exit" > "$CONTAINER_RESULTS_DIR/$service-exit-code.txt"
  printf '%s scanner exit code: %s\n' "$service" "$scan_exit"
  if [[ "$scan_exit" -ne 0 ]]; then
    overall_exit="$scan_exit"
  fi
done
exit "$overall_exit"