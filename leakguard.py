#!/usr/bin/env python3
"""
LeakGuard ML - zero-dependency hybrid secret scanner.

Runtime dependencies: Python standard library only.
"""

import argparse
import json
import math
import re
import sys
from pathlib import Path

DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv",
    "node_modules", "dist", "build", ".idea", ".vscode"
}

PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 98, "CRITICAL"),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 96, "CRITICAL"),
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 90, "CRITICAL"),
    ("BEARER_TOKEN", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"), 88, "HIGH"),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), 92, "CRITICAL"),
    ("DATABASE_URL", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+"), 90, "CRITICAL"),
    ("PASSWORD", re.compile(r"""(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^"'\s]{4,}"""), 84, "HIGH"),
    ("API_KEY", re.compile(r"""(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{8,}"""), 86, "HIGH"),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 38, "MEDIUM"),
    ("PHONE", re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{8,}\d)(?!\d)"), 28, "LOW"),
    ("CREDIT_CARD_LIKE", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), 65, "HIGH"),
]

KEYWORDS = re.compile(r"(?i)\b(?:secret|token|password|passwd|pwd|api[_-]?key|private[_-]?key|credential|auth)\b")
ASSIGNMENT = re.compile(r"""(?i)\b(?:secret|token|password|passwd|pwd|api[_-]?key|private[_-]?key|credential|auth)\b\s*[:=]\s*["']?([A-Za-z0-9._~+/!@#$%^&*()=\-]{6,})""")

# Small transparent training set. Labels: 0 = ordinary text, 1 = likely secret.
TRAINING_DATA = [
    ("hello world", 0), ("student name", 0), ("normal_function_name", 0),
    ("welcome to the application", 0), ("http://localhost:8000", 0),
    ("count = 123", 0), ("user@example.com", 0), ("password123", 1),
    ("AKIA1234567890ABCDEF", 1), ("a8F!92LmQx7Zp3K", 1),
    ("xJ7kP9vQ2mL8nR4sT6", 1), ("eyJhbGciOiJIUzI1NiJ9.abc12345.xyz67890", 1),
    ("ghp_abcdefghijklmnopqrstuvwxyz123456", 1), ("mySecretKey123!", 1),
    ("postgres://admin:SuperSecret123@db.local/app", 1),
    ("token=Qx8!Lm92Pq7#Za31", 1), ("normal text with spaces", 0),
    ("function calculate_total(items)", 0), ("version_2026_08", 0),
    ("config_value", 0), ("a9F!k82LmQ#7xP2q", 1),
]

def entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def features(s):
    n = max(len(s), 1)
    digits = sum(c.isdigit() for c in s) / n
    upper = sum(c.isupper() for c in s) / n
    lower = sum(c.islower() for c in s) / n
    special = sum(not c.isalnum() for c in s) / n
    hexchars = sum(c in "0123456789abcdefABCDEF" for c in s) / n
    ent = entropy(s) / 8.0
    longness = min(len(s) / 40.0, 1.0)
    keyword = 1.0 if KEYWORDS.search(s) else 0.0
    return [longness, ent, digits, upper, lower, special, hexchars, keyword]

class LogisticRegression:
    def __init__(self, lr=0.25, epochs=900):
        self.lr = lr
        self.epochs = epochs
        self.w = []
        self.b = 0.0

    @staticmethod
    def sigmoid(z):
        if z < -60:
            return 0.0
        if z > 60:
            return 1.0
        return 1.0 / (1.0 + math.exp(-z))

    def fit(self, X, y):
        m = len(X)
        d = len(X[0])
        self.w = [0.0] * d
        self.b = 0.0
        for _ in range(self.epochs):
            gw = [0.0] * d
            gb = 0.0
            for xi, yi in zip(X, y):
                p = self.sigmoid(sum(a*b for a, b in zip(self.w, xi)) + self.b)
                e = p - yi
                for j in range(d):
                    gw[j] += e * xi[j]
                gb += e
            for j in range(d):
                self.w[j] -= self.lr * gw[j] / m
            self.b -= self.lr * gb / m
        return self

    def predict_proba(self, x):
        return self.sigmoid(sum(a*b for a, b in zip(self.w, x)) + self.b)

def train_model():
    X = [features(s) for s, _ in TRAINING_DATA]
    y = [label for _, label in TRAINING_DATA]
    return LogisticRegression().fit(X, y)

def level(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"

def is_binary(path):
    try:
        data = path.read_bytes()[:4096]
        return b"\x00" in data
    except OSError:
        return True

def candidate_strings(line):
    # Keep useful quoted/unquoted chunks and assignment values.
    found = []
    for m in re.finditer(r"""["']([^"'\\]{6,})["']|(?<![\w])([A-Za-z0-9_./+=!@#$%^&*~-]{8,})(?![\w])""", line):
        s = m.group(1) or m.group(2)
        if s:
            found.append(s)
    return found

def scan_text(text, path, model):
    findings = []
    seen = set()

    for lineno, line in enumerate(text.splitlines(), 1):
        # Deterministic pattern detections.
        for name, pattern, base, sev in PATTERNS:
            for match in pattern.finditer(line):
                key = (name, lineno, match.group(0))
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "type": name,
                    "severity": sev,
                    "risk": base,
                    "ml_probability": round(model.predict_proba(features(match.group(0))) * 100, 1),
                    "entropy": round(entropy(match.group(0)), 2),
                    "file": str(path),
                    "line": lineno,
                    "evidence": redact(match.group(0)),
                    "reason": "Known sensitive pattern"
                })

        # ML candidate detection for unknown patterns.
        for candidate in candidate_strings(line):
            p = model.predict_proba(features(candidate))
            ent = entropy(candidate)
            context = bool(KEYWORDS.search(line))
            if p >= 0.68 and ent >= 2.8:
                risk = min(99, round(35 + p * 45 + min(ent / 6, 1) * 15 + (8 if context else 0)))
                sev = level(risk)
                key = ("ML_ANOMALY", lineno, candidate)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "type": "ML_ANOMALY",
                    "severity": sev,
                    "risk": risk,
                    "ml_probability": round(p * 100, 1),
                    "entropy": round(ent, 2),
                    "file": str(path),
                    "line": lineno,
                    "evidence": redact(candidate),
                    "reason": "High-confidence ML anomaly with high entropy"
                })
    return findings

def redact(value):
    if len(value) <= 8:
        return "*" * len(value)
    return value[:3] + "*" * min(12, len(value) - 6) + value[-3:]

def discover_files(root):
    if root.is_file():
        return [root]
    result = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in DEFAULT_EXCLUDES for part in p.parts):
            continue
        result.append(p)
    return result

def scan(root):
    model = train_model()
    findings = []
    scanned = 0
    skipped = 0

    for path in discover_files(root):
        if is_binary(path):
            skipped += 1
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        scanned += 1
        findings.extend(scan_text(text, path, model))

    # Overall score: strongest findings dominate while multiple findings add weight.
    if findings:
        ordered = sorted((f["risk"] for f in findings), reverse=True)
        overall = min(100, round(ordered[0] * 0.65 + sum(ordered[1:6]) * 0.07))
    else:
        overall = 0

    return {
        "files_scanned": scanned,
        "files_skipped": skipped,
        "findings": findings,
        "finding_count": len(findings),
        "overall_risk": overall,
        "status": level(overall) if overall else "SAFE",
        "model": "Standard-library logistic regression + rule engine + entropy analysis"
    }

def print_report(report):
    print("\n" + "╔" + "═" * 52 + "╗")
    print("║" + " LEAKGUARD ML — ZERO-DEPENDENCY SECURITY SCANNER".center(52) + "║")
    print("╚" + "═" * 52 + "╝")
    print(f"\nFiles scanned : {report['files_scanned']}")
    print(f"Files skipped : {report['files_skipped']}")
    print(f"Findings      : {report['finding_count']}")
    print(f"Project risk  : {report['overall_risk']}/100")
    print(f"Status        : {report['status']}\n")
    print("─" * 54)
    for f in sorted(report["findings"], key=lambda x: x["risk"], reverse=True):
        print(f"[{f['severity']}] {f['type']}  Risk={f['risk']}/100")
        print(f"  {f['file']}:{f['line']}")
        print(f"  ML probability: {f['ml_probability']}% | Entropy: {f['entropy']}")
        print(f"  Evidence: {f['evidence']}")
        print(f"  Reason: {f['reason']}")
        print("─" * 54)
    if not report["findings"]:
        print("No suspicious secrets or sensitive patterns detected.")

def main():
    parser = argparse.ArgumentParser(description="LeakGuard ML zero-dependency security scanner")
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument("--json", metavar="FILE", help="write JSON report")
    args = parser.parse_args()
    root = Path(args.path)
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        return 2
    report = scan(root)
    print_report(report)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.json}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
