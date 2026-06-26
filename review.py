#!/usr/bin/env python3
import os
import re
import json
import csv
import argparse
import subprocess
import shutil
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from collections import defaultdict

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# === Enhanced constants ===
REQ_VARS = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)"
SQL_KW = r"(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|UNION\s+SELECT)"
DANGEROUS_FUNCS = ["eval", "assert", "system", "exec", "shell_exec", "passthru",
                   "popen", "proc_open", "create_function", "pcntl_exec"]
DEPRECATED_MYSQL_FUNCS = [
    "mysql_connect", "mysql_pconnect", "mysql_query", "mysql_fetch_array",
    "mysql_fetch_assoc", "mysql_fetch_row", "mysql_fetch_object", "mysql_num_rows",
    "mysql_real_escape_string", "mysql_close", "mysql_error", "mysql_select_db",
    "mysql_insert_id", "mysql_affected_rows", "mysql_result", "mysql_free_result",
]
DEBUG_FUNCS = ["var_dump", "print_r", "var_export"]
WEAK_RANDOM_FUNCS = ["rand", "mt_rand", "uniqid"]           # Insecure for tokens
REMOVED_FUNCTIONS = {                                       # PHP 7 / 8 removed
    "each": "7.2",
    "create_function": "7.2",
    "ereg": "7.0",
    "split": "7.0",
    "mysql_": "7.0",   # handled separately
}

# ===========================
#  Helper functions
# ===========================
def line_of(content, pos):
    return content.count("\n", 0, pos) + 1

def get_snippet(lines, lineno, width=300):
    idx = lineno - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()[:width]
    return ""

# ===========================
#  Finding data class
# ===========================
class Finding:
    __slots__ = ("file", "line", "severity", "category", "message", "snippet", "fix")
    def __init__(self, file, line, severity, category, message, snippet, fix):
        self.file = file
        self.line = line
        self.severity = severity
        self.category = category
        self.message = message
        self.snippet = snippet
        self.fix = fix
    def to_dict(self):
        return {
            "file": self.file, "line": self.line, "severity": self.severity,
            "category": self.category, "message": self.message,
            "snippet": self.snippet, "fix": self.fix,
        }

# ===========================
#  Core Reviewer class (enhanced)
# ===========================
class PHPReviewer:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.findings = []
        self.php_available = shutil.which("php") is not None
        self.function_defs = defaultdict(list)
        self.file_count = 0
        self.loc_count = 0
        self._stop_event = threading.Event()   # for GUI cancellation

    def stop(self):
        self._stop_event.set()

    def add(self, relpath, line, severity, category, message, snippet, fix):
        self.findings.append(Finding(relpath, line, severity, category, message, snippet, fix))

    def iter_php_files(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            if self._stop_event.is_set():
                return
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", "node_modules", "vendor", "uploads")]
            for fn in filenames:
                if fn.lower().endswith(".php"):
                    yield os.path.join(dirpath, fn)

    def run(self):
        for path in self.iter_php_files():
            if self._stop_event.is_set():
                break
            self.file_count += 1
            rel = os.path.relpath(path, self.root)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                self.add(rel, 0, "HIGH", "Read Error",
                         f"Could not read file: {e}", "", "Check file encoding/permissions.")
                continue
            self.loc_count += content.count("\n") + 1
            lines = content.split("\n")

            # === Run all checks ===
            self.check_syntax(rel, path)
            self.check_sql_injection(rel, content, lines)
            self.check_xss(rel, content, lines)
            self.check_dangerous_funcs(rel, content, lines)
            self.check_command_injection(rel, content, lines)        # NEW
            self.check_deprecated_mysql(rel, content, lines)
            self.check_removed_functions(rel, content, lines)        # NEW
            self.check_file_inclusion(rel, content, lines)
            self.check_open_redirect(rel, content, lines)            # NEW
            self.check_path_traversal(rel, content, lines)           # NEW
            self.check_weak_hash(rel, content, lines)
            self.check_plaintext_password_compare(rel, content, lines)
            self.check_error_suppression(rel, content, lines)
            self.check_debug_leftovers(rel, content, lines)
            self.check_hardcoded_secrets(rel, content, lines)
            self.check_hardcoded_encryption_keys(rel, content, lines) # NEW
            self.check_weak_random(rel, content, lines)               # NEW
            self.check_extract_unserialize(rel, content, lines)
            self.check_csrf(rel, content, lines)
            self.check_file_upload(rel, content, lines)
            self.check_missing_exit_after_header(rel, content, lines) # NEW
            self.collect_function_defs(rel, content)

        self.check_duplicate_functions()
        self.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))

    # ---------- Syntax ----------
    def check_syntax(self, rel, path):
        if not self.php_available:
            return
        try:
            r = subprocess.run(["php", "-l", path], capture_output=True, text=True, timeout=15)
            if r.returncode != 0:
                msg = r.stdout.strip() or r.stderr.strip()
                m = re.search(r"on line (\d+)", msg)
                lineno = int(m.group(1)) if m else 0
                self.add(rel, lineno, "CRITICAL", "Syntax Error",
                         msg.splitlines()[0] if msg else "Parse error",
                         "", "Fix the syntax error reported by PHP before deploying this file.")
        except Exception:
            pass

    # ---------- SQL Injection ----------
    def check_sql_injection(self, rel, content, lines):
        # Direct request data in SQL
        pattern_direct = re.compile(SQL_KW + r"\b[^;\"'`]{0,500}?" + REQ_VARS + r"\s*\[", re.IGNORECASE | re.DOTALL)
        seen = set()
        for m in pattern_direct.finditer(content):
            ln = line_of(content, m.start())
            if ln in seen: continue
            seen.add(ln)
            self.add(rel, ln, "CRITICAL", "SQL Injection",
                     "Request superglobal concatenated/interpolated directly into SQL query.",
                     get_snippet(lines, ln),
                     "Use parameterized queries (PDO prepare/bind or mysqli prepare/bind).")
        # Dynamic SQL with variables (medium)
        pattern_dynamic = re.compile(SQL_KW + r"\b[^;\"'`]{0,300}?\$[A-Za-z_][A-Za-z0-9_]*", re.IGNORECASE | re.DOTALL)
        for m in pattern_dynamic.finditer(content):
            ln = line_of(content, m.start())
            if ln in seen: continue
            # Exclude if already using prepare/bind nearby
            nearby = content[max(0,m.start()-200):m.start()+400]
            if "prepare(" in nearby and "bind_param" in nearby: continue
            seen.add(ln)
            self.add(rel, ln, "MEDIUM", "Dynamic SQL Query",
                     "SQL query built with a variable. Verify it's sanitized or use prepared statements.",
                     get_snippet(lines, ln),
                     "Switch to parameterized queries to avoid SQL injection.")

    # ---------- XSS ----------
    def check_xss(self, rel, content, lines):
        pattern = re.compile(r"(?:echo|print)\s+[^;]{0,80}?" + REQ_VARS + r"\s*\[[^\]]*\][^;]{0,80}?;", re.IGNORECASE)
        for m in pattern.finditer(content):
            ln = line_of(content, m.start())
            snippet = m.group(0)
            if re.search(r"htmlspecialchars|htmlentities|intval|\(int\)|filter_var", snippet, re.IGNORECASE):
                continue
            self.add(rel, ln, "HIGH", "Reflected XSS",
                     "Request data echoed without escaping.",
                     get_snippet(lines, ln),
                     "Use htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before output.")
        short_echo = re.compile(r"<\?=\s*" + REQ_VARS + r"\s*\[", re.IGNORECASE)
        for m in short_echo.finditer(content):
            ln = line_of(content, m.start())
            self.add(rel, ln, "HIGH", "Reflected XSS",
                     "Short echo tag outputs request data without escaping.",
                     get_snippet(lines, ln),
                     "Wrap in htmlspecialchars().")

    # ---------- Dangerous Functions ----------
    def check_dangerous_funcs(self, rel, content, lines):
        for fn in DANGEROUS_FUNCS:
            for m in re.finditer(r"(?<![A-Za-z0-9_])" + fn + r"\s*\(", content):
                ln = line_of(content, m.start())
                self.add(rel, ln, "CRITICAL", "Dangerous Function",
                         f"Use of {fn}() can lead to remote code execution.",
                         get_snippet(lines, ln),
                         f"Remove {fn}() or replace with a safe alternative.")

    # ---------- Command Injection (NEW) ----------
    def check_command_injection(self, rel, content, lines):
        cmd_funcs = ["exec", "system", "shell_exec", "passthru", "popen", "proc_open"]
        for fn in cmd_funcs:
            pattern = re.compile(r"(?<![A-Za-z0-9_])" + fn + r"\s*\(.*" + REQ_VARS + r".*\)", re.IGNORECASE | re.DOTALL)
            for m in pattern.finditer(content):
                ln = line_of(content, m.start())
                self.add(rel, ln, "CRITICAL", "Command Injection",
                         f"{fn}() receives request data, enabling command injection if not properly escaped.",
                         get_snippet(lines, ln),
                         "Avoid passing user input to shell commands. Use escapeshellarg() and escapeshellcmd(), or better, use PHP's built-in APIs.")

    # ---------- Deprecated MySQL ----------
    def check_deprecated_mysql(self, rel, content, lines):
        for fn in DEPRECATED_MYSQL_FUNCS:
            for m in re.finditer(r"(?<![A-Za-z0-9_])" + fn + r"\s*\(", content):
                ln = line_of(content, m.start())
                self.add(rel, ln, "CRITICAL", "Removed PHP Function",
                         f"{fn}() was removed in PHP 7+. Fatal error on PHP 7/8.",
                         get_snippet(lines, ln),
                         "Migrate to mysqli_* or PDO with prepared statements.")

    # ---------- Removed Functions (NEW) ----------
    def check_removed_functions(self, rel, content, lines):
        for fn, version in REMOVED_FUNCTIONS.items():
            if fn.endswith("_"):
                # mysql_* handled separately
                if fn == "mysql_": continue
            pattern = re.compile(r"(?<![A-Za-z0-9_])" + fn + r"\s*\(", re.IGNORECASE)
            for m in pattern.finditer(content):
                ln = line_of(content, m.start())
                self.add(rel, ln, "CRITICAL", "Removed PHP Function",
                         f"{fn}() was removed in PHP {version}. Code will break on newer PHP versions.",
                         get_snippet(lines, ln),
                         f"Replace {fn}() with its modern counterpart.")

    # ---------- File Inclusion ----------
    def check_file_inclusion(self, rel, content, lines):
        pattern = re.compile(r"(include|include_once|require|require_once)\s*\(?\s*[^;]{0,120}?" + REQ_VARS + r"\s*\[", re.IGNORECASE)
        for m in pattern.finditer(content):
            ln = line_of(content, m.start())
            self.add(rel, ln, "CRITICAL", "File Inclusion Vulnerability",
                     f"{m.group(1)} uses request data to build the included file path (LFI/RFI risk).",
                     get_snippet(lines, ln),
                     "Map request values to allowed file paths using a whitelist, never build the path directly from input.")

    # ---------- Open Redirect (NEW) ----------
    def check_open_redirect(self, rel, content, lines):
        pattern = re.compile(r"(header\s*\(\s*['\"]Location:\s*|header\s*\(\s*\"Location:\s*)" + REQ_VARS + r"\s*\[", re.IGNORECASE)
        for m in pattern.finditer(content):
            ln = line_of(content, m.start())
            self.add(rel, ln, "MEDIUM", "Open Redirect",
                     "header('Location: ...') uses request data without validation, allowing open redirect.",
                     get_snippet(lines, ln),
                     "Validate the redirect target against a whitelist of allowed domains/paths.")

    # ---------- Path Traversal (NEW) ----------
    def check_path_traversal(self, rel, content, lines):
        # file_get_contents, fopen, etc. with REQ_VARS and possibly ".." or dirname concatenation
        funcs = ["file_get_contents", "fopen", "readfile", "include", "require"]
        for fn in funcs:
            pattern = re.compile(r"(?<![A-Za-z0-9_])" + fn + r"\s*\([^)]*" + REQ_VARS + r"[^)]*\)", re.IGNORECASE)
            for m in pattern.finditer(content):
                window = content[m.start():m.start()+150]
                if ".." in window or "dirname" in window:
                    ln = line_of(content, m.start())
                    self.add(rel, ln, "MEDIUM", "Path Traversal",
                             f"{fn}() uses request data and may be vulnerable to path traversal.",
                             get_snippet(lines, ln),
                             "Sanitize the path by removing '..', use realpath() validation, or restrict to a base directory.")

    # ---------- Weak Hash ----------
    def check_weak_hash(self, rel, content, lines):
        for m in re.finditer(r"\b(md5|sha1)\s*\(", content, re.IGNORECASE):
            window = content[m.start():m.start()+120]
            if re.search(r"pass|pwd", window, re.IGNORECASE):
                ln = line_of(content, m.start())
                self.add(rel, ln, "HIGH", "Weak Password Hashing",
                         f"{m.group(1)}() used near a password-related value. {m.group(1)} is fast and unsalted.",
                         get_snippet(lines, ln),
                         "Use password_hash() with PASSWORD_DEFAULT/BCRYPT/ARGON2ID.")

    # ---------- Plaintext Password Compare ----------
    def check_plaintext_password_compare(self, rel, content, lines):
        pattern = re.compile(r"(==|===)\s*\$row\s*\[\s*['\"](pass|password|pwd)['\"]\s*\]|\$row\s*\[\s*['\"](pass|password|pwd)['\"]\s*\]\s*(==|===)", re.IGNORECASE)
        for m in pattern.finditer(content):
            ln = line_of(content, m.start())
            self.add(rel, ln, "CRITICAL", "Insecure Password Verification",
                     "Password compared directly with == / === instead of password_verify().",
                     get_snippet(lines, ln),
                     "Store passwords with password_hash() and verify with password_verify().")

    # ---------- Error Suppression ----------
    def check_error_suppression(self, rel, content, lines):
        for m in re.finditer(r"@(mysqli_|mysql_|pg_|fopen|file_get_contents|unlink|include|require|\$)", content):
            ln = line_of(content, m.start())
            self.add(rel, ln, "LOW", "Error Suppression",
                     "The @ operator silently discards errors.",
                     get_snippet(lines, ln),
                     "Remove @ and handle errors explicitly (try/catch, check return values).")

    # ---------- Debug Leftovers ----------
    def check_debug_leftovers(self, rel, content, lines):
        for fn in DEBUG_FUNCS:
            for m in re.finditer(r"(?<![A-Za-z0-9_])" + fn + r"\s*\(", content):
                ln = line_of(content, m.start())
                self.add(rel, ln, "MEDIUM", "Debug Statement Left In Code",
                         f"{fn}() looks like leftover debugging code.",
                         get_snippet(lines, ln),
                         f"Remove {fn}() or replace with conditional logging.")

    # ---------- Hardcoded Secrets ----------
    def check_hardcoded_secrets(self, rel, content, lines):
        pattern = re.compile(r"\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token)\b\s*=>?\s*['\"]([^'\"]{3,})['\"]", re.IGNORECASE)
        for m in pattern.finditer(content):
            val = m.group(2)
            if val.lower() in ("", "changeme", "your_password_here", "password", "secret", "xxxx"):
                sev = "LOW"
            else:
                sev = "MEDIUM"
            ln = line_of(content, m.start())
            self.add(rel, ln, sev, "Hardcoded Credential",
                     f"Hardcoded value for '{m.group(1)}' found in source.",
                     get_snippet(lines, ln),
                     "Move credentials to environment variables or a non-committed config file. Rotate the secret if ever committed.")

    # ---------- Hardcoded Encryption Keys (NEW) ----------
    def check_hardcoded_encryption_keys(self, rel, content, lines):
        # Looks for define('ENCRYPTION_KEY', '...') or $key = '...' near openssl encrypt/decrypt
        pattern = re.compile(r"(?:define\(['\"]|^\s*\$[a-zA-Z_]+\s*=\s*['\"])(?:encrypt(?:ion)?[_-]?key|secret[_-]?key)['\"],?\s*['\"]([^'\"]{4,})['\"]", re.IGNORECASE | re.MULTILINE)
        for m in pattern.finditer(content):
            ln = line_of(content, m.start())
            self.add(rel, ln, "MEDIUM", "Hardcoded Encryption Key",
                     "Encryption key appears hardcoded. If the source code is exposed, encryption is broken.",
                     get_snippet(lines, ln),
                     "Store encryption keys outside the codebase (env var, secure vault).")

    # ---------- Weak Random Functions (NEW) ----------
    def check_weak_random(self, rel, content, lines):
        for fn in WEAK_RANDOM_FUNCS:
            for m in re.finditer(r"(?<![A-Za-z0-9_])" + fn + r"\s*\(", content):
                # Check if used for token/password/secret generation
                window = content[max(0,m.start()-80):m.start()+80]
                if re.search(r"token|password|secret|api[_-]?key|auth", window, re.IGNORECASE):
                    ln = line_of(content, m.start())
                    self.add(rel, ln, "MEDIUM", "Insecure Random Generator",
                             f"{fn}() is used in a security context. It is predictable and not suitable.",
                             get_snippet(lines, ln),
                             "Use random_bytes() or random_int() for cryptographic randomness.")

    # ---------- extract / unserialize ----------
    def check_extract_unserialize(self, rel, content, lines):
        for m in re.finditer(r"extract\s*\(\s*" + REQ_VARS, content, re.IGNORECASE):
            ln = line_of(content, m.start())
            self.add(rel, ln, "CRITICAL", "Variable Injection",
                     "extract() on a request superglobal allows overwriting arbitrary variables.",
                     get_snippet(lines, ln),
                     "Never extract() request data. Read specific expected keys instead.")
        for m in re.finditer(r"unserialize\s*\(\s*[^)]*" + REQ_VARS, content, re.IGNORECASE):
            ln = line_of(content, m.start())
            self.add(rel, ln, "CRITICAL", "Insecure Deserialization",
                     "unserialize() on request data can lead to object injection / RCE.",
                     get_snippet(lines, ln),
                     "Use json_decode()/json_encode() for data interchange instead of serialize/unserialize on untrusted input.")

    # ---------- CSRF ----------
    def check_csrf(self, rel, content, lines):
        if not re.search(r"<form\b[^>]*method\s*=\s*['\"]post['\"]", content, re.IGNORECASE):
            return
        if re.search(r"csrf", content, re.IGNORECASE):
            return
        m = re.search(r"<form\b[^>]*method\s*=\s*['\"]post['\"][^>]*>", content, re.IGNORECASE)
        ln = line_of(content, m.start()) if m else 1
        self.add(rel, ln, "MEDIUM", "Missing CSRF Protection",
                 "A POST form was found with no reference to a CSRF token in this file.",
                 get_snippet(lines, ln),
                 "Add a per-session CSRF token as a hidden field and verify it server-side.")

    # ---------- File Upload ----------
    def check_file_upload(self, rel, content, lines):
        for m in re.finditer(r"move_uploaded_file\s*\(", content):
            ln = line_of(content, m.start())
            window = content[max(0,m.start()-600):m.start()+200]
            if re.search(r"pathinfo|getimagesize|mime_content_type|finfo_|exif_imagetype|in_array\s*\(\s*\$.*ext", window, re.IGNORECASE):
                continue
            self.add(rel, ln, "MEDIUM", "Unvalidated File Upload",
                     "move_uploaded_file() called without visible extension/MIME validation.",
                     get_snippet(lines, ln),
                     "Validate file type (finfo/getimagesize), enforce size limit, and use a whitelist of extensions.")

    # ---------- Missing exit after header (NEW) ----------
    def check_missing_exit_after_header(self, rel, content, lines):
        # header(...) not followed by exit/die within next ~3 lines
        header_lines = []
        for i, line in enumerate(lines):
            if re.search(r"header\s*\(\s*['\"]Location:", line, re.IGNORECASE):
                header_lines.append(i)   # 0-based index
        for hline in header_lines:
            # check next lines (non-empty, non-comment) for exit or die
            found_exit = False
            for j in range(hline+1, min(hline+4, len(lines))):
                next_line = lines[j].strip()
                if not next_line or next_line.startswith("//") or next_line.startswith("#"):
                    continue
                if re.match(r"(exit|die)\s*[;(]", next_line):
                    found_exit = True
                    break
                # If we hit any other statement, stop looking
                break
            if not found_exit:
                self.add(rel, hline+1, "LOW", "Missing exit After Header Redirect",
                         "A Location header redirect is not immediately followed by exit/die.",
                         get_snippet(lines, hline+1),
                         "Add 'exit;' after header('Location: ...') to stop further script execution.")

    # ---------- Duplicate function detection ----------
    def collect_function_defs(self, rel, content):
        for m in re.finditer(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", content):
            self.function_defs[m.group(1)].append(rel)

    def check_duplicate_functions(self):
        for name, files in self.function_defs.items():
            uniq = sorted(set(files))
            if len(uniq) > 1 and not name.startswith("__"):
                self.add(uniq[0], 0, "LOW", "Duplicate Function Name",
                         f"function {name}() defined in {len(uniq)} files: {', '.join(uniq)}.",
                         "", "Rename or namespace these functions to avoid 'Cannot redeclare' error.")

    # ========== Report generation ==========
    def summary(self):
        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        by_file = defaultdict(int)
        for f in self.findings:
            by_sev[f.severity] += 1
            by_cat[f.category] += 1
            by_file[f.file] += 1
        return {
            "files_scanned": self.file_count,
            "lines_scanned": self.loc_count,
            "total_findings": len(self.findings),
            "by_severity": dict(sorted(by_sev.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))),
            "by_category": dict(sorted(by_cat.items(), key=lambda x: -x[1])),
            "top_files": sorted(by_file.items(), key=lambda x: -x[1])[:20],
        }

    def write_json(self, path):
        data = {"summary": self.summary(), "findings": [f.to_dict() for f in self.findings]}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def write_csv(self, path):
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["severity", "category", "file", "line", "message", "snippet", "fix"])
            for finding in self.findings:
                w.writerow([finding.severity, finding.category, finding.file, finding.line,
                            finding.message, finding.snippet, finding.fix])

    def write_text(self, path):
        """Plain text report."""
        s = self.summary()
        lines = []
        lines.append("=== PHP CODE REVIEW REPORT (Text) ===\n")
        lines.append(f"Files scanned: {s['files_scanned']}")
        lines.append(f"Lines scanned: {s['lines_scanned']}")
        lines.append(f"Total findings: {s['total_findings']}\n")
        lines.append("-- Findings by severity --")
        for sev, count in s["by_severity"].items():
            lines.append(f"  {sev}: {count}")
        lines.append("\n-- Findings by category --")
        for cat, count in s["by_category"].items():
            lines.append(f"  {cat}: {count}")
        lines.append("\n-- Top files with most issues --")
        for fn, count in s["top_files"]:
            lines.append(f"  {fn}: {count}")
        lines.append("\n-- Detailed findings --\n")
        for finding in self.findings:
            lines.append(f"[{finding.severity}] {finding.file}:{finding.line}")
            lines.append(f"  Category: {finding.category}")
            lines.append(f"  Message : {finding.message}")
            if finding.snippet:
                lines.append(f"  Code    : {finding.snippet}")
            lines.append(f"  Fix     : {finding.fix}")
            lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def write_markdown(self, path, max_examples=15):
        s = self.summary()
        lines = []
        lines.append("# PHP Codebase Review Report\n")
        lines.append(f"Files scanned: {s['files_scanned']}  ")
        lines.append(f"Lines scanned: {s['lines_scanned']}  ")
        lines.append(f"Total findings: {s['total_findings']}\n")
        lines.append("## Findings by severity\n")
        for sev, count in s["by_severity"].items():
            lines.append(f"- **{sev}**: {count}")
        lines.append("\n## Findings by category\n")
        for cat, count in s["by_category"].items():
            lines.append(f"- {cat}: {count}")
        lines.append("\n## Files with the most findings\n")
        for fn, count in s["top_files"]:
            lines.append(f"- {fn}: {count}")
        lines.append("\n## Detailed findings (sample per category)\n")
        by_cat = defaultdict(list)
        for f in self.findings:
            by_cat[f.category].append(f)
        cat_order = sorted(by_cat.keys(),
                           key=lambda c: min(SEVERITY_ORDER.get(x.severity,9) for x in by_cat[c]))
        for cat in cat_order:
            items = sorted(by_cat[cat], key=lambda x: SEVERITY_ORDER.get(x.severity,9))
            lines.append(f"\n### {cat} ({len(items)} found)\n")
            for finding in items[:max_examples]:
                lines.append(f"**[{finding.severity}] {finding.file}:{finding.line}**")
                lines.append(f"- Issue: {finding.message}")
                if finding.snippet:
                    lines.append(f"- Code: `{finding.snippet}`")
                lines.append(f"- Fix: {finding.fix}\n")
            if len(items) > max_examples:
                lines.append(f"...and {len(items)-max_examples} more instance(s).\n")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


# ========================
#  GUI Application
# ========================
class PHPReviewerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PHP Codebase Reviewer")
        self.geometry("900x650")
        self.minsize(700, 500)
        self.reviewer = None
        self.scan_thread = None
        self._stop_requested = False

        # Menu bar
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Text Report...", command=self.save_text_report)
        file_menu.add_command(label="Save CSV Report...", command=self.save_csv_report)
        file_menu.add_command(label="Save JSON Report...", command=self.save_json_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        self.config(menu=menubar)

        # Top frame: directory selection
        top_frame = tk.Frame(self)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(top_frame, text="PHP Codebase Root:").pack(side=tk.LEFT)
        self.dir_var = tk.StringVar()
        dir_entry = tk.Entry(top_frame, textvariable=self.dir_var, width=60)
        dir_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        browse_btn = tk.Button(top_frame, text="Browse...", command=self.browse_directory)
        browse_btn.pack(side=tk.LEFT, padx=5)

        # Action buttons
        action_frame = tk.Frame(self)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        self.scan_btn = tk.Button(action_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk.Button(action_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.progress = ttk.Progressbar(action_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # Output area
        self.output = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 10))
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_var.set(directory)

    def start_scan(self):
        root = self.dir_var.get().strip()
        if not root or not os.path.isdir(root):
            messagebox.showerror("Error", "Please select a valid directory.")
            return
        self.output.delete(1.0, tk.END)
        self.status_var.set("Scanning...")
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self._stop_requested = False

        # Run scan in separate thread
        self.reviewer = PHPReviewer(root)
        self.scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scan_thread.start()

    def _run_scan(self):
        try:
            self.reviewer.run()
            if not self._stop_requested:
                self.after(0, self._scan_finished)
        except Exception as e:
            self.after(0, lambda: self._scan_error(str(e)))

    def _scan_finished(self):
        self.progress.stop()
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        if self.reviewer:
            self._display_summary()
            self.status_var.set(f"Scan complete: {self.reviewer.summary()['total_findings']} findings")

    def _scan_error(self, msg):
        self.progress.stop()
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        messagebox.showerror("Scan Error", msg)
        self.status_var.set("Error during scan")

    def stop_scan(self):
        self._stop_requested = True
        if self.reviewer:
            self.reviewer.stop()
        self.status_var.set("Stopping...")
        self.stop_btn.config(state=tk.DISABLED)

    def _display_summary(self):
        s = self.reviewer.summary()
        text = f"=== SCAN SUMMARY ===\n"
        text += f"Files scanned: {s['files_scanned']}\n"
        text += f"Lines scanned: {s['lines_scanned']}\n"
        text += f"Total findings: {s['total_findings']}\n\n"
        text += "Findings by severity:\n"
        for sev, cnt in s['by_severity'].items():
            text += f"  {sev}: {cnt}\n"
        text += "\nFindings by category:\n"
        for cat, cnt in s['by_category'].items():
            text += f"  {cat}: {cnt}\n"
        text += "\nTop 10 files with most issues:\n"
        for fn, cnt in s['top_files'][:10]:
            text += f"  {fn}: {cnt}\n"
        text += "\n--- Detailed findings ---\n"
        for f in self.reviewer.findings:
            text += f"\n[{f.severity}] {f.file}:{f.line}\n"
            text += f"  Category: {f.category}\n"
            text += f"  Message: {f.message}\n"
            if f.snippet:
                text += f"  Code: {f.snippet}\n"
            text += f"  Fix: {f.fix}\n"
        self.output.insert(tk.END, text)

    def save_text_report(self):
        if not self.reviewer:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            self.reviewer.write_text(file_path)
            messagebox.showinfo("Saved", f"Text report saved to {file_path}")

    def save_csv_report(self):
        if not self.reviewer:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            self.reviewer.write_csv(file_path)
            messagebox.showinfo("Saved", f"CSV report saved to {file_path}")

    def save_json_report(self):
        if not self.reviewer:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            self.reviewer.write_json(file_path)
            messagebox.showinfo("Saved", f"JSON report saved to {file_path}")


# ========================
#  Main entry point
# ========================
def main():
    parser = argparse.ArgumentParser(description="Advanced static review tool for PHP codebases.")
    parser.add_argument("path", nargs="?", help="Path to the PHP codebase root directory")
    parser.add_argument("--out", default=".", help="Output directory for reports (CLI mode)")
    parser.add_argument("--gui", action="store_true", help="Launch the GUI")
    args = parser.parse_args()

    if args.gui:
        app = PHPReviewerGUI()
        app.mainloop()
        return

    if not args.path:
        print("Please provide a directory path or use --gui to launch the GUI.")
        return

    os.makedirs(args.out, exist_ok=True)
    reviewer = PHPReviewer(args.path)
    reviewer.run()
    reviewer.write_json(os.path.join(args.out, "findings.json"))
    reviewer.write_csv(os.path.join(args.out, "findings.csv"))
    reviewer.write_text(os.path.join(args.out, "findings.txt"))
    reviewer.write_markdown(os.path.join(args.out, "REVIEW_REPORT.md"))

    s = reviewer.summary()
    print(f"Scanned {s['files_scanned']} files / {s['lines_scanned']} lines")
    print(f"Total findings: {s['total_findings']}")
    for sev, count in s["by_severity"].items():
        print(f"  {sev}: {count}")

if __name__ == "__main__":
    main()