#!/usr/bin/env bash
# Container entrypoint wrapper.
# Runs the assessment CLI, then uploads reports to GCS if OUTPUT_GCS_BUCKET is set.
set -e

python -m assessment.cli "$@"

if [[ -n "${OUTPUT_GCS_BUCKET:-}" ]]; then
  echo "Uploading reports to gs://${OUTPUT_GCS_BUCKET}/reports/"
  gsutil -m cp -r /tmp/output/* "gs://${OUTPUT_GCS_BUCKET}/reports/" \
    && echo "Reports uploaded." \
    || echo "Warning: GCS upload failed (reports may not be persisted)."
fi
