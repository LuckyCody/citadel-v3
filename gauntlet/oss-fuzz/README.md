# Continuous fuzzing config (Tier 3 sustained)

Ready-to-use configuration to run Citadel's 8 cargo-fuzz targets **continuously and
free**, so fuzzing runs for days/weeks instead of our 40-second smoke. Two paths —
**ClusterFuzzLite is recommended** for a project this size.

## Path A — ClusterFuzzLite (recommended: self-hosted, no acceptance gate)

Runs the same fuzzers inside Citadel's own GitHub Actions. No approval needed; you
control it. Setup:

1. Copy `Dockerfile` and `build.sh` to **`.clusterfuzzlite/`** in the repo root.
2. Add the two workflows below (`.github/workflows/cflite_pr.yml` for per-PR short
   runs, `cflite_batch.yml` for scheduled longer runs). Templates:
   https://google.github.io/clusterfuzzlite/
3. Optionally add a storage repo for the corpus so coverage accumulates across runs.

Minimal `cflite_pr.yml`:
```yaml
name: ClusterFuzzLite PR
on: [pull_request]
permissions: read-all
jobs:
  Fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - id: build
        uses: google/clusterfuzzlite/actions/build_fuzzers@v1
        with: { sanitizer: address }
      - uses: google/clusterfuzzlite/actions/run_fuzzers@v1
        with:
          fuzz-seconds: 600
          mode: 'code-change'
          sanitizer: address
```

## Path B — OSS-Fuzz (Google-hosted 24/7, but selective)

`project.yaml` + `Dockerfile` + `build.sh` here are drop-in for a
`projects/citadel-v3/` directory in a fork of github.com/google/oss-fuzz.

1. Fork google/oss-fuzz.
2. Create `projects/citadel-v3/` with the three files here.
3. Test locally:
   ```bash
   python infra/helper.py build_image citadel-v3
   python infra/helper.py build_fuzzers --sanitizer address citadel-v3
   python infra/helper.py check_build citadel-v3
   ```
4. Open a PR to google/oss-fuzz.

**Caveat (honest):** OSS-Fuzz acceptance now favors widely-used / critical-infra
projects. A newer solo project may be declined — which is exactly why Path A
(ClusterFuzzLite) is the recommended primary. The `build.sh`/`Dockerfile` are
identical, so nothing is wasted either way.

## What this buys

Our local Tier 3 was a 40s/target smoke (~71M execs, 0 crashes). Continuous
fuzzing runs each target for hours-to-days with an accumulating corpus and
coverage tracking — the real depth an auditor expects, at no cost.
