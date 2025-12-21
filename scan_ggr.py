#!/usr/bin/env python3
"""
scan_ggr.py — Deep scanner for GGR / revenue-share settings in codebases.

This variant prints verbose runtime information to the terminal (stdout)
so you can see everything the script is doing even when run from Windows CMD.

Usage example (same flags as before):
  python scan_ggr.py --path /path/to/site --target 15 --tolerance 0.5 --json ggr_report.json

Notes:
- By design this script is verbose and logs debug/info messages to stdout.
- If you want to quiet it later, you can modify the logger level in main().
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
import io
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# ----- configuration defaults -----
DEFAULT_EXTS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".json", ".html", ".htm", ".css", ".scss", ".sass", ".less",
    ".php", ".phtml", ".php5", ".php7", ".php8",
    ".py", ".rb", ".go", ".java", ".kt", ".kts", ".cs",
    ".c", ".cpp", ".cc", ".h", ".hpp",
    ".ini", ".cfg", ".conf", ".config",
    ".xml", ".yml", ".yaml",
    ".env", ".env.local", ".properties",
    ".sql", ".twig", ".blade.php",
    ".md", ".txt"
}

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules",
    "dist", "build", "out", ".next", ".nuxt", ".vercel",
    ".idea", ".vscode", ".venv", "venv", ".cache",
    "coverage", ".pytest_cache", "target", "bin", "obj",
    ".gradle", ".terraform", "vendor", "storage", "cache"
}

# Primary keyword families (case-insensitive)
KEYWORD_PATTERN = re.compile(
    r"""(?ix)
    \b(
        ggr |
        gross \s* gaming \s* revenue |
        rev(?:enue)? \s* share |
        revshare |
        revenue \s* split |
        commission |
        take \s* rate |
        house \s* edge |
        margin |
        rtp |
        return \s* to \s* player |
        payout
    )\b
    """
)

# Likely key names around assignments ("ggr_split": 0.15, ggrRate=15% etc.)
KEYNAME_PATTERN = re.compile(
    r"""(?ix)
    \b(
        ggr[_\-]?(split|share|rate|percent|pct)? |
        revshare |
        revenue[_\-]?share |
        rev[_\-]?share |
        rev[_\-]?split |
        take[_\-]?rate |
        margin[_\-]?(rate|percent|pct)?
    )\b
    """
)

# Numeric patterns
PERCENT_PATTERN = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d+)?)[ ]*%")
DECIMAL_PATTERN = re.compile(r"\b0\.(\d{1,4})\b")
FRACTION_100_PATTERN = re.compile(r"(?<!\d)(\d{1,3})\s*/\s*100\b")
WORD_PERCENT_PATTERN = re.compile(r"(?i)\b(\d{1,3}(?:\.\d+)?)\s*percent\b")

# Simple binary sniff (avoid reading huge binaries)
PRINTABLE_BYTES = set(range(32, 127)) | {9, 10, 13}

# ----- dataclass for findings -----
@dataclass
class Finding:
    file: str
    line: int
    col: int
    context: str
    raw_number: str
    normalized_percent: float
    number_form: str  # "percent" | "decimal" | "fraction" | "word_percent"
    signal: str       # "keyword+number" | "keyname+number" | "number_only"
    confidence: str   # "high" | "medium" | "low"

# ----- logger setup helper -----
def ensure_utf8_io():
    """
    Try to ensure stdout/stderr use UTF-8 so messages display correctly in Windows CMD.
    Falls back gracefully if not possible.
    """
    try:
        # Python 3.7+
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        try:
            # Fallback: wrap the buffer
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            # give up silently if we can't reconfigure
            pass

def setup_logger(level: int = logging.DEBUG) -> logging.Logger:
    """
    Configure a logger that writes to stdout (so it is visible in CMD).
    Default level is DEBUG to "show everything" as requested.
    """
    logger = logging.getLogger("scan_ggr")
    logger.setLevel(level)
    # Clear existing handlers to avoid duplicate output in some environments
    logger.handlers.clear()
    handler = logging.StreamHandler(stream=sys.stdout)
    fmt = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.propagate = False
    return logger

# Create module-level logger (will be reconfigured in main())
logger = logging.getLogger("scan_ggr")

# ----- utility functions -----
def is_probably_text(sample: bytes) -> bool:
    if b"\x00" in sample:
        return False
    if not sample:
        return True
    nonprint = sum(b not in PRINTABLE_BYTES for b in sample)
    ratio = nonprint / len(sample)
    logger.debug(f"text sniff: nonprint={nonprint}, len={len(sample)}, ratio={ratio:.3f}")
    return ratio < 0.10

def iter_files(root: Path, include_exts: set[str], exclude_dirs: set[str], follow_symlinks: bool) -> Iterable[Path]:
    """
    Iterate files under root, applying extension and exclude rules, and skip probable binaries.
    Logs skip/accept decisions to help trace what the scanner is doing.
    """
    logger.debug(f"iter_files: walking root={root}, follow_symlinks={follow_symlinks}")
    for path in root.rglob("*"):
        try:
            if not path.exists():
                logger.debug(f"skip (not exists): {path}")
                continue
        except PermissionError:
            logger.warning(f"permission denied while stat'ing: {path}")
            continue

        if path.is_dir():
            if path.name in exclude_dirs:
                logger.info(f"skipping excluded dir: {path}")
                # Can't prevent rglob descending into this directory directly; continue is the best we can do
                continue
            if path.is_symlink() and not follow_symlinks:
                logger.debug(f"skipping symlinked dir: {path}")
                continue
            continue

        # Skip symlinked files unless allowed
        if path.is_symlink() and not follow_symlinks:
            logger.debug(f"skipping symlinked file: {path}")
            continue

        if include_exts and path.suffix.lower() not in include_exts:
            logger.debug(f"skip (ext filter): {path} (suffix={path.suffix})")
            continue

        # Quick binary sniff
        try:
            with path.open("rb") as fh:
                sample = fh.read(4096)
            if not is_probably_text(sample):
                logger.info(f"skipping binary-like file: {path}")
                continue
        except Exception as ex:
            logger.warning(f"failed to read sample from {path}: {ex}")
            continue

        logger.debug(f"yielding file: {path}")
        yield path

def read_text(path: Path) -> Optional[str]:
    """
    Read file text with utf-8 then latin-1 fallback. Logs which encoding was used or if read failed.
    """
    try:
        content = path.read_text(encoding="utf-8")
        logger.debug(f"read_text: {path} (utf-8) size={len(content)}")
        return content
    except UnicodeDecodeError:
        try:
            content = path.read_text(encoding="latin-1")
            logger.debug(f"read_text: {path} (latin-1) size={len(content)}")
            return content
        except Exception as ex:
            logger.warning(f"read_text failed for {path} with latin-1: {ex}")
            return None
    except Exception as ex:
        logger.warning(f"read_text failed for {path}: {ex}")
        return None

def clamp_context(text: str, start: int, end: int, max_chars: int) -> Tuple[str, int, int]:
    left = max(0, start - max_chars // 2)
    right = min(len(text), end + max_chars // 2)
    context = text[left:right].replace("\n", " ")
    # recompute line, col from start
    line = text.count("\n", 0, start) + 1
    col = start - (text.rfind("\n", 0, start) + 1)
    return context, line, col

def extract_numbers(window: str) -> List[Tuple[str, float, str]]:
    """Return list of (raw, normalized_percent, form)."""
    results: List[Tuple[str, float, str]] = []

    for m in PERCENT_PATTERN.finditer(window):
        raw = m.group(1) + "%"
        val = float(m.group(1))
        results.append((raw, val, "percent"))

    for m in WORD_PERCENT_PATTERN.finditer(window):
        raw = m.group(1) + " percent"
        val = float(m.group(1))
        results.append((raw, val, "word_percent"))

    for m in DECIMAL_PATTERN.finditer(window):
        frac = float("0." + m.group(1))
        val = round(frac * 100.0, 6)
        results.append((m.group(0), val, "decimal"))

    for m in FRACTION_100_PATTERN.finditer(window):
        val = float(m.group(1))
        results.append((m.group(0), val, "fraction"))

    return results

def score_signal(window: str, had_keyword: bool, had_keyname: bool) -> Tuple[str, str]:
    # Confidence rules
    if had_keyword and had_keyname:
        return "keyword+number", "high"
    if had_keyname:
        return "keyname+number", "high"
    if had_keyword:
        return "keyword+number", "medium"
    return "number_only", "low"

def scan_text(path: Path, text: str, max_context: int) -> List[Finding]:
    """
    Scan the text content of a file and return any findings.
    Logs internal decisions so you can see what's being matched.
    """
    findings: List[Finding] = []

    logger.debug(f"scan_text: scanning {path}")

    # First pass: keyword windows
    kw_count = 0
    for kw in re.finditer(KEYWORD_PATTERN, text):
        kw_count += 1
        start, end = kw.span()
        context, line, col = clamp_context(text, start, end, max_context)
        numbers = extract_numbers(context)
        had_keyname = bool(KEYNAME_PATTERN.search(context))
        logger.debug(f"keyword match at {path}:{line}:{col}, had_keyname={had_keyname}, numbers_found={len(numbers)}")
        for raw, norm, form in numbers:
            signal, confidence = score_signal(context, True, had_keyname)
            f = Finding(str(path), line, col, context, raw, norm, form, signal, confidence)
            findings.append(f)
            logger.info(f"found: {f.file}:{f.line}:{f.col} raw={f.raw_number} norm={f.normalized_percent}% form={f.number_form} ({f.signal}, {f.confidence})")

    logger.debug(f"scan_text: keyword matches processed: {kw_count}")

    # Second pass: keyname assignments even without generic keywords
    kn_count = 0
    for kn in re.finditer(KEYNAME_PATTERN, text):
        kn_count += 1
        start, end = kn.span()
        context, line, col = clamp_context(text, start, end, max_context)
        numbers = extract_numbers(context)
        if not numbers:
            logger.debug(f"keyname at {path} (no numbers nearby): {text[start:end]}")
            continue
        for raw, norm, form in numbers:
            signal, confidence = score_signal(context, False, True)
            f = Finding(str(path), line, col, context, raw, norm, form, signal, confidence)
            findings.append(f)
            logger.info(f"found (keyname): {f.file}:{f.line}:{f.col} raw={f.raw_number} norm={f.normalized_percent}% form={f.number_form} ({f.signal}, {f.confidence})")

    logger.debug(f"scan_text: keyname matches processed: {kn_count}")

    # Third pass: narrow fallback for numbers near short keywords if no findings yet
    if not findings:
        fallback_count = 0
        for num in re.finditer(r"(?:(\d{1,3}(?:\.\d+)?\s*%)|\b0\.\d{1,4}\b)", text):
            start, end = num.span()
            left = max(0, start - 120)
            right = min(len(text), end + 120)
            window = text[left:right]
            if re.search(r"(?i)\b(ggr|revshare|revenue\s*share|gross\s*gaming\s*revenue)\b", window):
                fallback_count += 1
                context, line, col = clamp_context(text, left, right, max_context)
                raw_txt = num.group(0)
                if raw_txt.strip().endswith("%"):
                    val = float(re.sub(r"[^\d.]", "", raw_txt))
                    form = "percent"
                else:
                    val = float(raw_txt) * 100.0
                    form = "decimal"
                f = Finding(str(path), line, col, context, raw_txt, val, form, "keyword+number", "medium")
                findings.append(f)
                logger.info(f"found (fallback): {f.file}:{f.line}:{f.col} raw={f.raw_number} norm={f.normalized_percent}% form={f.number_form} ({f.signal}, {f.confidence})")
        logger.debug(f"scan_text: fallback checks done, count={fallback_count}")

    logger.debug(f"scan_text: total findings for {path}: {len(findings)}")
    return findings

def aggregate(findings: List[Finding], target: float, tolerance: float) -> dict:
    by_percent: dict[str, int] = {}
    hits_target: List[Finding] = []
    for f in findings:
        key = f"{round(f.normalized_percent, 4)}%"
        by_percent[key] = by_percent.get(key, 0) + 1
        if abs(f.normalized_percent - target) <= tolerance:
            hits_target.append(f)

    top = sorted(by_percent.items(), key=lambda kv: (-kv[1], kv[0]))
    return {
        "counts_by_percent": top,
        "target_hits_count": len(hits_target),
        "target_hits_first5": [asdict(x) for x in hits_target[:5]],
    }

def print_summary(findings: List[Finding], target: float, tolerance: float):
    logger.info("=" * 80)
    logger.info(f"Total findings: {len(findings)}")
    agg = aggregate(findings, target, tolerance)
    logger.info(f"Target ≈ {target:.2f}% (±{tolerance:.2f} pp) hits: {agg['target_hits_count']}")
    logger.info("-" * 80)
    logger.info("Counts by percent (descending):")
    for pct, cnt in agg["counts_by_percent"][:20]:
        logger.info(f"  {pct:>8}  — {cnt} occurrences")
    logger.info("-" * 80)
    logger.info("Top findings:")
    for f in findings[:20]:
        logger.info(f"[{f.confidence.upper():>6}] {f.file}:{f.line}:{f.col}  val={f.normalized_percent:.4f}%  ({f.number_form}, {f.signal})")
        ctx = f.context
        if len(ctx) > 240:
            ctx = ctx[:240] + "…"
        logger.info(f"   … {ctx}")
    logger.info("=" * 80)

def write_json(findings: List[Finding], json_path: str, target: float, tolerance: float):
    payload = {
        "summary": aggregate(findings, target, tolerance),
        "findings": [asdict(f) for f in findings],
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    logger.info(f"Wrote JSON report to: {json_path}")

def write_csv(findings: List[Finding], csv_path: str):
    fieldnames = ["file", "line", "col", "raw_number", "normalized_percent", "number_form", "signal", "confidence", "context"]
    try:
        with open(csv_path, "w", encoding="utf-8", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for fi in findings:
                row = asdict(fi)
                writer.writerow(row)
        logger.info(f"Wrote CSV report to: {csv_path}")
    except Exception as ex:
        logger.error(f"Failed to write CSV to {csv_path}: {ex}")

# ----- main entrypoint -----
def main():
    ensure_utf8_io()
    # set up logger early so all messages are visible
    global logger
    logger = setup_logger(level=logging.DEBUG)  # show everything by default as requested

    parser = argparse.ArgumentParser(description="Scan codebase for GGR/revenue-share values (verbose).")
    parser.add_argument("--path", default=".", help="Root directory to scan (default: '.')")
    parser.add_argument("--target", type=float, default=15.0, help="Target percent to highlight (default 15.0)")
    parser.add_argument("--tolerance", type=float, default=0.5, help="± percent points tolerance (default 0.5)")
    parser.add_argument("--max-context", type=int, default=240, help="Max chars around each hit (default 240)")
    parser.add_argument("--json", dest="json_path", default=None, help="Optional path to write JSON report")
    parser.add_argument("--csv", dest="csv_path", default=None, help="Optional path to write CSV report")
    parser.add_argument("--include-ext", default=None, help="Comma-separated list of file extensions to include")
    parser.add_argument("--exclude-dir", default=None, help="Comma-separated list of directory names to exclude")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks")
    args = parser.parse_args()

    start_time = time.time()
    root = Path(args.path).resolve()
    logger.info(f"Starting scan at root: {root}")
    if not root.exists() or not root.is_dir():
        logger.error(f"Error: path not found or not a directory: {root}")
        sys.exit(2)

    include_exts = DEFAULT_EXTS.copy()
    if args.include_ext:
        include_exts = {e.lower().strip() if e.startswith(".") else "." + e.lower().strip()
                        for e in args.include_ext.split(",") if e.strip()}
    logger.debug(f"include_exts count={len(include_exts)}")

    exclude_dirs = DEFAULT_EXCLUDE_DIRS.copy()
    if args.exclude_dir:
        exclude_dirs = {d.strip() for d in args.exclude_dir.split(",") if d.strip()}
    logger.debug(f"exclude_dirs count={len(exclude_dirs)}")

    findings: List[Finding] = []

    scanned_files = 0
    unreadable_files = 0
    files_with_findings = 0

    try:
        for file_path in iter_files(root, include_exts, exclude_dirs, args.follow_symlinks):
            scanned_files += 1
            logger.info(f"processing file [{scanned_files}]: {file_path}")
            text = read_text(file_path)
            if text is None:
                unreadable_files += 1
                logger.debug(f"could not read file (skipping): {file_path}")
                continue
            file_findings = scan_text(file_path, text, args.max_context)
            if file_findings:
                files_with_findings += 1
                logger.info(f"  -> {len(file_findings)} findings in {file_path}")
            else:
                logger.debug(f"  -> no findings in {file_path}")
            findings.extend(file_findings)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user (KeyboardInterrupt). Proceeding to summary...")

    # De-duplicate identical entries (path+line+col+raw_number) to be safe
    uniq = {}
    for f in findings:
        key = (f.file, f.line, f.col, f.raw_number, round(f.normalized_percent, 6))
        if key not in uniq:
            uniq[key] = f
    findings = list(uniq.values())
    logger.debug(f"deduplicated findings: {len(findings)} unique items")

    # Sort by confidence, then by closeness to target, then path+line
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (conf_rank.get(f.confidence, 3), abs(f.normalized_percent - args.target), f.file, f.line, f.col))

    # Print summary to console (logger ensures stdout visibility)
    print_summary(findings, args.target, args.tolerance)

    # Additional runtime summary
    elapsed = time.time() - start_time
    logger.info(f"scanned_files={scanned_files}, unreadable_files={unreadable_files}, files_with_findings={files_with_findings}, total_findings={len(findings)}")
    logger.info(f"elapsed_time={elapsed:.2f}s")

    if args.json_path:
        try:
            write_json(findings, args.json_path, args.target, args.tolerance)
        except Exception as ex:
            logger.error(f"Failed to write JSON report: {ex}")

    if args.csv_path:
        try:
            write_csv(findings, args.csv_path)
        except Exception as ex:
            logger.error(f"Failed to write CSV report: {ex}")

if __name__ == "__main__":
    main()
