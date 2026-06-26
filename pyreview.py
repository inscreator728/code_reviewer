#!/usr/bin/env python3
"""
Advanced Code Auditor – Multi‑language review & vulnerability scanner.
Supports: Python, Django, Java, C, C++, PHP, JavaScript, HTML, CSS.
Run:  python advanced_code_auditor.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import subprocess
import json
import os
import re
from pathlib import Path
from datetime import datetime
from html import escape

# --------------------------- Rule Engine ---------------------------

class Rule:
    """A pattern‑based rule for code review or vulnerability detection."""
    def __init__(self, pattern: str, message: str, severity: str,
                 languages: list, is_vuln: bool = False):
        self.pattern = re.compile(pattern)
        self.message = message
        self.severity = severity   # "HIGH", "MEDIUM", "LOW"
        self.languages = languages  # e.g. ["Python", "Java"]
        self.is_vuln = is_vuln      # True = vulnerability, False = code review

# ------- Rule Definitions -------
RULES = [
    # ========== Python ==========
    Rule(r'\bexec\s*\(', "Avoid exec() – arbitrary code execution risk. Use safe alternatives.",
         "HIGH", ["Python"], True),
    Rule(r'\beval\s*\(', "eval() can execute malicious input. Use ast.literal_eval or avoid.",
         "HIGH", ["Python"], True),
    Rule(r'pickle\.loads?\b', "Unsafe deserialization with pickle. Use JSON instead.",
         "HIGH", ["Python"], True),
    Rule(r'os\.system\s*\(', "Use subprocess.run() with shell=False instead of os.system().",
         "MEDIUM", ["Python"], True),
    Rule(r'assert\s', "Do not use assert for data validation – it is removed with -O.",
         "LOW", ["Python"], False),
    Rule(r'print\s*\(', "Consider using logging instead of print() in production code.",
         "LOW", ["Python"], False),
    Rule(r'def\s+\w+\s*\([^)]*\)\s*:\s*$', "Empty function body – add implementation or docstring.",
         "LOW", ["Python"], False),

    # ========== Django / Python web ==========
    Rule(r'HttpResponse\s*\(.*request\.GET', "Potential XSS – escaping missing. Use render().",
         "HIGH", ["Python"], True),
    Rule(r'\.raw\s*\(', "Avoid raw SQL; use Django ORM to prevent SQL injection.",
         "HIGH", ["Python"], True),
    Rule(r'SECRET_KEY\s*=\s*[\'"].*[\'"]', "Hardcoded SECRET_KEY – move to environment variable.",
         "HIGH", ["Python"], True),
    Rule(r'DEBUG\s*=\s*True', "DEBUG=True in production exposes sensitive data.",
         "HIGH", ["Python"], True),

    # ========== Java ==========
    Rule(r'System\.out\.println', "Use a logging framework (SLF4J, Log4j) instead.",
         "LOW", ["Java"], False),
    Rule(r'Runtime\.getRuntime\(\)\.exec', "Command injection risk. Validate input or use ProcessBuilder.",
         "HIGH", ["Java"], True),
    Rule(r'\.executeQuery\s*\(\s*".*\+', "SQL injection – use PreparedStatement.",
         "HIGH", ["Java"], True),
    Rule(r'\.executeUpdate\s*\(\s*".*\+', "SQL injection in executeUpdate. Use parameterized queries.",
         "HIGH", ["Java"], True),
    Rule(r'catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}', "Empty catch block hides errors.",
         "MEDIUM", ["Java"], False),

    # ========== C / C++ ==========
    Rule(r'\bgets\s*\(', "gets() is unsafe – use fgets() instead.", "HIGH", ["C", "C++"], True),
    Rule(r'\bsprintf\s*\(', "sprintf() may overflow buffer. Prefer snprintf().",
         "HIGH", ["C", "C++"], True),
    Rule(r'scanf\s*\(\s*"%s"', "Unbounded scanf(\"%s\") – limit width or use fgets.",
         "HIGH", ["C", "C++"], True),
    Rule(r'malloc\s*\([^;]*;\s*$', "Check malloc() return value for NULL.",
         "MEDIUM", ["C", "C++"], False),
    Rule(r'free\s*\([^;]+;\s*$', "Set pointer to NULL after free() to avoid dangling pointer.",
         "LOW", ["C", "C++"], False),
    Rule(r'\bstrcpy\s*\(', "strcpy() is unsafe – use strncpy() or safer variant.",
         "HIGH", ["C", "C++"], True),

    # ========== PHP ==========
    Rule(r'\bmysql_query\s*\(', "Deprecated mysql_* functions. Use MySQLi or PDO.",
         "HIGH", ["PHP"], True),
    Rule(r'echo\s+.*\$_GET', "Reflected XSS – use htmlspecialchars() for output.",
         "HIGH", ["PHP"], True),
    Rule(r'\beval\s*\(', "eval() in PHP is dangerous – find an alternative.",
         "HIGH", ["PHP"], True),
    Rule(r'\bexec\s*\(', "exec() can lead to command injection. Use escapeshellarg().",
         "HIGH", ["PHP"], True),
    Rule(r'include\s*\(.*\$', "Dynamic includes may allow LFI. Whitelist files.",
         "HIGH", ["PHP"], True),

    # ========== JavaScript ==========
    Rule(r'\beval\s*\(', "eval() is a security risk and slows performance.",
         "HIGH", ["JavaScript"], True),
    Rule(r'document\.write\s*\(', "document.write() can be used for XSS. Prefer safe DOM methods.",
         "MEDIUM", ["JavaScript"], True),
    Rule(r'innerHTML\s*=\s*.*\+', "Potential XSS via innerHTML concatenation. Use textContent.",
         "HIGH", ["JavaScript"], True),
    Rule(r'localStorage\.setItem\s*\(', "Data stored in localStorage is accessible by any script.",
         "MEDIUM", ["JavaScript"], True),
    Rule(r'console\.log\s*\(', "Remove console.log() before production deployment.",
         "LOW", ["JavaScript"], False),

    # ========== HTML ==========
    Rule(r'<script\s.*>\s*<!--', "HTML comment inside script tag is unnecessary.",
         "LOW", ["HTML"], False),
    Rule(r'on\w+\s*=\s*["\']?\s*javascript:', "Inline event with javascript: URI is a security risk.",
         "HIGH", ["HTML"], True),
    Rule(r'<a\s+href\s*=\s*["\']javascript:', "javascript: link detected – avoid for security.",
         "HIGH", ["HTML"], True),

    # ========== CSS ==========
    Rule(r'expression\s*\(', "CSS expressions are obsolete and a security risk.",
         "LOW", ["CSS"], True),
    Rule(r'!important', "Overuse of !important reduces maintainability.",
         "LOW", ["CSS"], False),
]

# File extension -> language name mapping
LANG_MAP = {
    ".py": "Python",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".php": "PHP",
    ".js": "JavaScript",
    ".html": "HTML",
    ".css": "CSS",
}

# --------------------------- Scanner Core ---------------------------

class ScannerEngine:
    """Handles file discovery, rule matching, and external tool invocation."""

    def __init__(self, root_folder, progress_callback=None, cancel_flag=None):
        self.root = Path(root_folder)
        self.progress_callback = progress_callback  # called with int(0-100)
        self.cancel_flag = cancel_flag or (lambda: False)
        self.findings = []

    def scan(self):
        """Main scan entry point. Returns list of finding dicts."""
        if not self.root.is_dir():
            return []

        files = list(self.root.rglob("*"))
        total = len(files)
        for idx, file_path in enumerate(files):
            if self.cancel_flag():
                break
            if self.progress_callback:
                self.progress_callback(int((idx+1)/total * 80))  # 0-80% for rule scan
            if file_path.is_file():
                suffix = file_path.suffix.lower()
                lang = LANG_MAP.get(suffix)
                if lang:
                    self._scan_file(file_path, lang)

        # External tools run for Python (20% of progress)
        if not self.cancel_flag():
            self._run_pylint()
        if not self.cancel_flag():
            self._run_bandit()
        if self.progress_callback:
            self.progress_callback(100)

        return self.findings

    def _scan_file(self, file_path: Path, language: str):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return

        for rule in RULES:
            if language not in rule.languages:
                continue
            for lineno, line in enumerate(lines, 1):
                if self.cancel_flag():
                    return
                if rule.pattern.search(line):
                    self.findings.append({
                        "file": str(file_path),
                        "line": lineno,
                        "language": language,
                        "type": "Vulnerability" if rule.is_vuln else "Code Review",
                        "severity": rule.severity,
                        "message": rule.message,
                        "code_snippet": line.rstrip()
                    })

    def _run_pylint(self):
        """Run pylint if available, append results."""
        try:
            subprocess.run(["pylint", "--version"], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            return  # not installed

        try:
            result = subprocess.run(
                ["pylint", str(self.root), "--output-format=json"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode in (0, 32) and result.stdout.strip():
                pylint_findings = json.loads(result.stdout)
                for item in pylint_findings:
                    self.findings.append({
                        "file": item.get("path", ""),
                        "line": item.get("line", 0),
                        "language": "Python",
                        "type": "Code Review (pylint)",
                        "severity": "MEDIUM",
                        "message": f"{item.get('symbol', '')}: {item.get('message', '')}",
                        "code_snippet": ""
                    })
        except Exception:
            pass  # fail silently

    def _run_bandit(self):
        """Run bandit if available, append results."""
        try:
            subprocess.run(["bandit", "--version"], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            return

        try:
            result = subprocess.run(
                ["bandit", "-r", str(self.root), "-f", "json"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode in (0, 1) and result.stdout.strip():
                data = json.loads(result.stdout)
                for issue in data.get("results", []):
                    self.findings.append({
                        "file": issue.get("filename", ""),
                        "line": issue.get("line_number", 0),
                        "language": "Python",
                        "type": "Vulnerability (bandit)",
                        "severity": issue.get("issue_severity", "MEDIUM"),
                        "message": f"{issue.get('test_name', '')}: {issue.get('issue_text', '')}",
                        "code_snippet": issue.get("code", "")
                    })
        except Exception:
            pass

# --------------------------- GUI Application ---------------------------

class CodeAuditorApp:
    """Main graphical interface."""

    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Code Auditor – Multi‑Language & Vulnerability Scanner")
        self.root.geometry("1400x850")
        self.root.minsize(1100, 600)
        self._configure_styles()

        self.folder_path = tk.StringVar()
        self.findings = []
        self.scan_thread = None
        self.cancel_requested = False

        self._build_ui()

    # ---------- Styling ----------
    def _configure_styles(self):
        self.root.configure(bg="#2b2b2b")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="#dcdcdc")
        style.configure("TButton", background="#3c3c3c", foreground="#dcdcdc",
                        borderwidth=1, focusthickness=3)
        style.map("TButton", background=[("active", "#505050")])
        style.configure("TLabelframe", background="#2b2b2b", foreground="#dcdcdc")
        style.configure("TLabelframe.Label", background="#2b2b2b", foreground="#dcdcdc")
        style.configure("TProgressbar", troughcolor="#444444", background="#007acc")
        style.configure("Treeview", background="#1e1e1e", foreground="#dcdcdc",
                        fieldbackground="#1e1e1e", borderwidth=1)
        style.map("Treeview", background=[("selected", "#264f78")])
        style.configure("Treeview.Heading", background="#3c3c3c", foreground="#dcdcdc",
                        relief="flat")

    # ---------- UI Construction ----------
    def _build_ui(self):
        # Top toolbar
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=8, pady=5)

        ttk.Label(toolbar, text="Root folder:").pack(side=tk.LEFT, padx=4)
        self.folder_entry = ttk.Entry(toolbar, textvariable=self.folder_path, width=70)
        self.folder_entry.pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Browse", command=self._browse).pack(side=tk.LEFT, padx=4)
        self.scan_btn = ttk.Button(toolbar, text="Start Scan", command=self._start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=4)
        self.stop_btn = ttk.Button(toolbar, text="Stop", command=self._stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Export HTML", command=self._export_html).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Export Text", command=self._export_text).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=4)

        # Progress bar + status
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=8, pady=2)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, expand=True, side=tk.LEFT, padx=(0, 8))
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.RIGHT)

        # Main paned window (left: issues, right: details + preview)
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=5)

        # ----- Left pane: Findings tree -----
        left_frame = ttk.LabelFrame(paned, text="Findings")
        paned.add(left_frame, weight=1)

        tree_columns = ("file", "line", "lang", "type", "severity", "message")
        self.tree = ttk.Treeview(left_frame, columns=tree_columns, show="headings",
                                 selectmode="browse")
        self.tree.heading("file", text="File", command=lambda: self._sort_column("file"))
        self.tree.heading("line", text="Line", command=lambda: self._sort_column("line", numeric=True))
        self.tree.heading("lang", text="Language", command=lambda: self._sort_column("lang"))
        self.tree.heading("type", text="Type", command=lambda: self._sort_column("type"))
        self.tree.heading("severity", text="Severity", command=lambda: self._sort_column("severity"))
        self.tree.heading("message", text="Message", command=lambda: self._sort_column("message"))

        self.tree.column("file", width=180)
        self.tree.column("line", width=50, anchor=tk.CENTER)
        self.tree.column("lang", width=80, anchor=tk.CENTER)
        self.tree.column("type", width=100)
        self.tree.column("severity", width=80, anchor=tk.CENTER)
        self.tree.column("message", width=350)

        scrollbar_y = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar_y.set)
        scrollbar_x = ttk.Scrollbar(left_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(xscrollcommand=scrollbar_x.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")
        left_frame.rowconfigure(0, weight=1)
        left_frame.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # ----- Right pane: Details + Preview -----
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)

        # Issue detail
        detail_frame = ttk.LabelFrame(right_frame, text="Issue Detail")
        detail_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 4))
        self.detail_text = tk.Text(detail_frame, height=7, bg="#1e1e1e", fg="#dcdcdc",
                                   wrap=tk.WORD, relief=tk.FLAT)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # Code preview
        preview_frame = ttk.LabelFrame(right_frame, text="Code Preview (surrounding lines)")
        preview_frame.pack(fill=tk.BOTH, expand=True)
        self.preview_text = tk.Text(preview_frame, bg="#1e1e1e", fg="#dcdcdc",
                                    font=("Consolas", 10), relief=tk.FLAT, state=tk.DISABLED)
        self.preview_text.pack(fill=tk.BOTH, expand=True)

        # Tag for highlighted line
        self.preview_text.tag_configure("highlight", background="#aa3333", foreground="white")

        # Status bar at bottom
        self.statusbar_var = tk.StringVar(value="Ready")
        statusbar = ttk.Label(self.root, textvariable=self.statusbar_var, relief=tk.SUNKEN)
        statusbar.pack(side=tk.BOTTOM, fill=tk.X)

    # ---------- Actions ----------
    def _browse(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)

    def _start_scan(self):
        folder = self.folder_path.get().strip()
        if not folder:
            messagebox.showerror("Error", "Please select a root folder.")
            return
        if not os.path.isdir(folder):
            messagebox.showerror("Error", "Invalid directory path.")
            return

        # Reset state
        self._clear()
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.cancel_requested = False
        self.status_var.set("Scanning...")
        self.statusbar_var.set("Scan in progress...")

        # Start background thread
        self.scan_thread = threading.Thread(target=self._run_scan, args=(folder,), daemon=True)
        self.scan_thread.start()

    def _run_scan(self, folder):
        engine = ScannerEngine(
            folder,
            progress_callback=self._update_progress,
            cancel_flag=lambda: self.cancel_requested
        )
        self.findings = engine.scan()
        # After scan, update GUI in main thread
        self.root.after(0, self._scan_finished)

    def _scan_finished(self):
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set(100)
        self.status_var.set(f"Scan complete – {len(self.findings)} issues found.")
        self.statusbar_var.set("Ready")
        self._populate_tree()

    def _populate_tree(self):
        for i, finding in enumerate(self.findings):
            self.tree.insert("", tk.END, iid=str(i),
                             values=(os.path.basename(finding["file"]),
                                     finding["line"],
                                     finding["language"],
                                     finding["type"],
                                     finding["severity"],
                                     finding["message"]))

    def _stop_scan(self):
        self.cancel_requested = True
        self.status_var.set("Stopping scan...")
        self.stop_btn.config(state=tk.DISABLED)

    def _clear(self):
        self.tree.delete(*self.tree.get_children())
        self.detail_text.delete("1.0", tk.END)
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.config(state=tk.DISABLED)
        self.findings.clear()
        self.progress_var.set(0)
        self.status_var.set("")
        self.statusbar_var.set("Ready")

    def _update_progress(self, value):
        # Called from worker thread, schedule GUI update
        self.root.after(0, lambda: self.progress_var.set(value))

    # ---------- Selection handling ----------
    def _on_select(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        idx = int(selection[0])
        if idx >= len(self.findings):
            return
        issue = self.findings[idx]

        # Update detail
        detail = (
            f"File:   {issue['file']}\n"
            f"Line:   {issue['line']}   Language: {issue['language']}\n"
            f"Type:   {issue['type']}   Severity: {issue['severity']}\n"
            f"Message: {issue['message']}\n"
            f"Code:   {issue.get('code_snippet', '')}"
        )
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", detail)

        # Show code preview (context)
        self._show_preview(issue["file"], issue["line"])

    def _show_preview(self, file_path, line_num):
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            self.preview_text.insert("1.0", "[Unable to read file]")
            self.preview_text.config(state=tk.DISABLED)
            return

        start = max(0, line_num - 6)
        end = min(len(lines), line_num + 5)
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            self.preview_text.insert(tk.END, f"{i+1:4d} {prefix}{lines[i]}")
            if i == line_num - 1:
                self.preview_text.tag_add("highlight", f"{i-start+1}.0", f"{i-start+1}.end")
        self.preview_text.see(f"{line_num - start}.0")
        self.preview_text.config(state=tk.DISABLED)

    # ---------- Column sorting ----------
    def _sort_column(self, col, numeric=False):
        # Get all items with their values
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        # Sort appropriately
        if numeric:
            data.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0)
        else:
            data.sort(key=lambda x: x[0].lower())
        # Reorder
        for index, (_, iid) in enumerate(data):
            self.tree.move(iid, "", index)

    # ---------- Export ----------
    def _export_html(self):
        if not self.findings:
            messagebox.showinfo("Nothing to export", "No findings to export.")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".html",
                                                filetypes=[("HTML", "*.html")])
        if not filepath:
            return

        html_parts = [
            "<html><head><meta charset='utf-8'><title>Code Audit Report</title>",
            "<style>",
            "body { font-family: Arial; background: #f9f9f9; }",
            "table { border-collapse: collapse; width: 100%; }",
            "th { background: #007acc; color: white; padding: 8px; }",
            "td { border: 1px solid #ccc; padding: 6px; }",
            "tr:nth-child(even) { background: #f2f2f2; }",
            "</style></head><body>",
            f"<h1>Code Audit Report – {datetime.now().strftime('%Y-%m-%d %H:%M')}</h1>",
            "<table><tr><th>File</th><th>Line</th><th>Language</th><th>Type</th><th>Severity</th><th>Message</th></tr>"
        ]
        for f in self.findings:
            html_parts.append(
                f"<tr><td>{escape(f['file'])}</td><td>{f['line']}</td>"
                f"<td>{f['language']}</td><td>{f['type']}</td>"
                f"<td>{f['severity']}</td><td>{escape(f['message'])}</td></tr>"
            )
        html_parts.append("</table></body></html>")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("".join(html_parts))
        messagebox.showinfo("Export", f"HTML report saved to:\n{filepath}")

    def _export_text(self):
        if not self.findings:
            messagebox.showinfo("Nothing to export", "No findings to export.")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text", "*.txt")])
        if not filepath:
            return
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"Code Audit Report – {datetime.now()}\n")
            f.write("=" * 80 + "\n\n")
            for issue in self.findings:
                f.write(f"{issue['file']}:{issue['line']} [{issue['language']}] "
                        f"{issue['type']} ({issue['severity']})\n")
                f.write(f"  {issue['message']}\n\n")
        messagebox.showinfo("Export", f"Text report saved to:\n{filepath}")

# --------------------------- Main ---------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = CodeAuditorApp(root)
    root.mainloop()