# Feedback task starting environment

Upstream: https://github.com/trbs/rfc3161ng
Upstream commit: `f9b29640ef9b808647a4c7daa0b14d0d02b473e3`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e "rfc3161ng@file://$PWD"
.venv/bin/python -m pytest -q -o addopts= tests/test_api.py::test_encode_decode_timestamp_request tests/test_api.py::test_generalized_time_decoding
```

Scope note: Existing request DER round-trip and generalized time unit tests only; the other upstream test_api cases contact public TSA servers and are not part of this offline baseline.

Observed baseline (2026-11-13): `2 passed in 2.36s`
Whole-command wall time: 2.703 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
