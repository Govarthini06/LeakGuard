# LeakGuard ML

**Zero-dependency hybrid security scanner for exposed secrets and sensitive data.**

LeakGuard combines:
1. deterministic secret-pattern detection,
2. entropy analysis, and
3. a logistic-regression ML classifier implemented from scratch with Python's standard library.

## Why it matters

Known secret formats can be caught with rules, but unknown or unusual credentials
may not match a predefined signature. LeakGuard uses ML to prioritize suspicious
high-entropy strings for review.

## Run

```bash
python leakguard.py demo_project
```

JSON report:

```bash
python leakguard.py demo_project --json report.json
```

Tests:

```bash
python -m unittest -v
```

## Zero dependency

`requirements.txt` is empty. Runtime code uses only Python standard-library modules.

## Security note

The included demo credentials are fake. LeakGuard redacts evidence in terminal
output. Detection is heuristic and should be used as a security aid, not as a
guarantee that a repository is secret-free.

## Track

Track E — Security & Crypto Utilities.

## Bonus alignment

- Single-file core scanner: `leakguard.py`
- Package Killer: demonstrates replacements for common scanner/ML dependencies
- STDLIB Log: 10 standard-library substitutions are documented
