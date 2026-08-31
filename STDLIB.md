# STDLIB.md — How LeakGuard Replaces Common Packages

LeakGuard has **zero third-party runtime dependencies**. The ML classifier,
feature extraction, scanner, reporting, and CLI are implemented with Python's
standard library.

| Normally considered | LeakGuard uses instead |
|---|---|
| scikit-learn | A small logistic-regression implementation using `math` |
| NumPy | Python lists + `math` |
| regex third-party package | `re` |
| pathlib/file scanning packages | `pathlib` |
| Click/Typer | `argparse` |
| Rich/colorama | plain terminal output + ANSI/Unicode |
| pandas | lists/dicts + `json` |
| requests | `urllib` would be available in the standard library if HTTP were needed |
| detect-secrets | LeakGuard's own rule engine |
| entropy/ML helper libraries | `math` + custom functions |

## ML approach

The model is logistic regression trained from a small transparent set of
positive and negative examples. Features include string length, normalized
Shannon entropy, digit ratio, uppercase/lowercase ratio, special-character
ratio, hexadecimal-character ratio, and security-keyword context.

The ML result is combined with deterministic pattern detection and entropy.
The ML component is a prioritization/anomaly detector, not proof that a string
is a secret.

## Runtime dependency proof

`requirements.txt` is intentionally empty.

Run:

```bash
python -m unittest -v
python leakguard.py demo_project
```

No `pip install` is required.
