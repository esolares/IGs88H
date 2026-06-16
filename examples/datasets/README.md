# Test Datasets — Known Vulnerability Benchmarks

Three curated datasets with **known, labeled vulnerabilities** for testing
IGs88H's detection accuracy. Each dataset includes a `ground_truth.json`
manifest and a pre-built `graph.json` for the harness. Vulnerable source
code is **not included** — clone it yourself (see below).

> **Warning:** These datasets contain deliberately vulnerable code.
> **Never execute or run** any of the source files on your host machine.
> The harness reads code as text — it does not need to execute the target.

## Setup

Clone the vulnerable source into each dataset directory:

```bash
# DSVW
git clone https://github.com/stamparm/DSVW.git /tmp/dsvw
cp /tmp/dsvw/dsvw.py examples/datasets/dsvw/dsvw.py

# DSVPWA
git clone https://github.com/sgabe/DSVPWA.git /tmp/dsvpwa
cp /tmp/dsvpwa/dsvpwa.py /tmp/dsvpwa/attacks.py /tmp/dsvpwa/handlers.py \
   /tmp/dsvpwa/server.py examples/datasets/dsvpwa/

# SecurityEval
git clone https://github.com/s2e-lab/SecurityEval.git /tmp/securityeval
cp /tmp/securityeval/dataset.jsonl examples/datasets/securityeval/
```

Rebuild graph files if needed:

```bash
python examples/build_test_graphs.py        # all three
python examples/build_test_graphs.py dsvw   # just one
```

The builder uses `ast.parse()` only — it never executes the vulnerable code.

---

## Dataset 1: DSVW (Damn Small Vulnerable Web)

**Source:** [stamparm/DSVW](https://github.com/stamparm/DSVW) — Unlicense (public domain)

A single 98-line Python web server with 26 labeled vulnerabilities. Tainted
HTTP parameters flow through string formatting into SQL queries, `subprocess`,
`pickle.loads`, `exec()`, `open()`, and XML parsers.

| Metric | Value |
|--------|-------|
| Vulnerabilities | 26 |
| Graph nodes | 6 |
| Files | 1 |

**Evaluating results:** The `ground_truth.json` lists all 26 vulnerability
types. The harness should flag SQL injection in `do_GET`, command injection
in the `domain` handler, pickle deserialization in the `object` handler,
and path traversal in the `path` handler.

---

## Dataset 2: DSVPWA (Damn Simple Vulnerable Python Web Application)

**Source:** [sgabe/DSVPWA](https://github.com/sgabe/DSVPWA) — MIT License

A multi-file Python web application with 12 labeled vulnerabilities across
4 source files. Vulnerabilities span module boundaries — the entry point is
`dsvpwa.py`, requests route through `server.py` and `handlers.py`, and
attack surfaces are in `attacks.py`.

**Best for:** Testing cross-module graph traversal. The harness must follow
call edges across files to trace vulnerability propagation.

| Metric | Value |
|--------|-------|
| Vulnerabilities | 12 |
| Graph nodes | 72 |
| Files | 4 |

**Evaluating results:** The `ground_truth.json` lists 12 CWEs. SQL injection
should be found in `attacks.py` and traced back through `handlers.py`;
command injection should be found in `attacks.py`; path traversal should be
flagged in file-serving handlers.

---

## Dataset 3: SecurityEval

**Source:** [s2e-lab/SecurityEval](https://github.com/s2e-lab/SecurityEval) — academic dataset (cite MSR4P&S'22)

121 isolated Python code snippets, each containing one known vulnerability
labeled by CWE ID. Covers 69 unique CWEs.

**Best for:** Testing per-node detection accuracy. Each snippet is standalone
— no cross-module data flow to trace.

| Metric | Value |
|--------|-------|
| Samples | 121 |
| Unique CWEs | 69 |

**Evaluating results:** Each node ID starts with the CWE (e.g.,
`securityeval.CWE-089_author_1`). A correct detection should flag the
node and identify the matching vulnerability category.

---

## Combined CWE Coverage

| CWE | Description | SecurityEval | DSVW | DSVPWA |
|-----|-------------|:---:|:---:|:---:|
| CWE-89 | SQL Injection | 2 | 4 | 1 |
| CWE-22 | Path Traversal | 4 | 2 | 1 |
| CWE-78 | OS Command Injection | 2 | 1 | 1 |
| CWE-79 | Cross-Site Scripting | 3 | 4 | 1 |
| CWE-94/95 | Code/Eval Injection | 3 | 1 | - |
| CWE-502 | Deserialization | 4 | 1 | 1 |
| CWE-798 | Hardcoded Credentials | 1 | - | - |
| CWE-611 | XXE | 6 | 2 | - |
| CWE-352 | CSRF | - | 1 | 1 |
| CWE-601 | Open Redirect | 5 | 1 | 1 |
| CWE-918 | SSRF | - | 1 | - |
| CWE-384 | Session Fixation | - | - | 2 |
