#!/usr/bin/env python3
"""
CyberScan Pro - Advanced Multi‑Language Code Review & Vulnerability Scanner
GUI: PySide6 - Ultra Tech / Cyber Theme with Matrix Rain Background
Features:
- Context‑aware rule engine with severity scoring
- Smart deduplication and language detection
- Intelligent summary insights and actionable recommendations
- Background scanning with live progress and exportable reports
- Full‑screen mode, language breakdown, and rich HTML export
- Matrix rain background animation
- Dashboard with summary cards and language bar chart
- Advanced filtering and search
- Professional cyber‑themed HTML export
"""

import math
import os
import re
import sys
import time
import traceback
import random
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import (
    Qt, QThread, Signal, QObject, QTimer, QSortFilterProxyModel,
    QAbstractTableModel, QModelIndex, QItemSelectionModel, QRectF,
    QPointF, QSize
)
from PySide6.QtGui import (
    QAction, QFont, QColor, QPalette, QIcon, QKeySequence,
    QStandardItemModel, QStandardItem, QTextCursor, QPainter,
    QPen, QBrush, QFontMetrics, QLinearGradient, QTransform,
    QPixmap, QMovie
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QTreeView, QPushButton, QLineEdit, QComboBox,
    QLabel, QProgressBar, QStatusBar, QFileDialog, QMessageBox,
    QTextEdit, QFrame, QToolBar, QGroupBox, QCheckBox, QSpinBox,
    QStyledItemDelegate, QStyle, QStyleOptionViewItem,
    QMenu, QMenuBar, QSizePolicy, QGraphicsView, QGraphicsScene,
    QGraphicsProxyWidget, QGraphicsTextItem, QGraphicsItem,
    QGridLayout, QScrollArea
)

# =============================================================================
# Core scanning logic (unchanged from original)
# =============================================================================

EXCLUDED_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "node_modules",
    "vendor", "dist", "build", "uploads", "cache", "tmp", "temp"
}

LANGUAGE_RULES = {
    "Python": {
        "exts": [".py"],
        "rules": [
            (r"\beval\s*\(", "Use of eval() can execute attacker-controlled code.", "critical", "vulnerability", "Replace eval() with safe parsing or explicit logic.", "Code injection"),
            (r"\bexec\s*\(", "Use of exec() creates arbitrary code execution risk.", "critical", "vulnerability", "Avoid exec() and use safer alternatives.", "Code execution"),
            (r"\bsubprocess\.(call|Popen)\s*\(.*shell\s*=\s*True", "Shell=True enables command injection in subprocess calls.", "critical", "vulnerability", "Set shell=False and pass arguments safely.", "Command injection"),
            (r"\bpickle\.loads?\s*\(", "Unsafe deserialization with pickle can lead to code execution.", "critical", "vulnerability", "Use JSON or a safer serialization format.", "Deserialization"),
            (r"\byaml\.load\s*\(", "yaml.load() without SafeLoader can deserialize untrusted data unsafely.", "high", "vulnerability", "Use yaml.safe_load() or yaml.load(..., Loader=SafeLoader).", "Deserialization"),
            (r"DEBUG\s*=\s*True", "Debug mode is enabled in a likely production configuration.", "high", "vulnerability", "Set DEBUG=False in production and hide sensitive output.", "Configuration"),
            (r"SECRET_KEY\s*=\s*[\'\"].*[\'\"]", "A hardcoded secret key was detected.", "high", "vulnerability", "Move secrets to environment variables or a secure vault.", "Secret exposure"),
            (r"\binput\s*\(", "The input() function is not suitable for untrusted runtime input in production.", "medium", "review", "Prefer explicit CLI parsing or validated user input.", "Input handling"),
            (r"except\s*:", "A bare except clause can hide important faults.", "medium", "review", "Catch specific exceptions instead of broad exceptions.", "Error handling"),
            (r"#\s*TODO", "A TODO comment was left in the codebase.", "low", "review", "Resolve or document the task before deployment.", "Maintainability"),
        ],
    },
    "PHP": {
        "exts": [".php", ".phtml"],
        "rules": [
            (r"\beval\s*\(", "eval() in PHP enables code injection.", "critical", "vulnerability", "Remove eval() and use explicit code paths.", "Code injection"),
            (r"\b(exec|system|shell_exec|passthru|popen|proc_open)\s*\(", "Command execution via shell functions is risky.", "critical", "vulnerability", "Avoid shell execution on user-controlled input.", "Command injection"),
            (r"\bmysql_query\s*\(", "Deprecated mysql_* functions are insecure and not supported in modern PHP.", "high", "vulnerability", "Migrate to PDO or mysqli with prepared statements.", "Database security"),
            (r"\$_(?:GET|POST|REQUEST|COOKIE)\b.*\b(query|SELECT|UPDATE|DELETE|INSERT)", "User-controlled data appears in a SQL statement.", "critical", "vulnerability", "Use prepared statements and bind variables.", "SQL injection"),
            (r"\b(include|include_once|require|require_once)\s*\(.*\$", "Dynamic include paths may allow local or remote file inclusion.", "critical", "vulnerability", "Restrict includes to a strict whitelist of safe files.", "File inclusion"),
            (r"error_reporting\s*\(0\)", "Error reporting is disabled, which can hide deployment issues.", "medium", "review", "Keep error reporting enabled in development and log issues carefully in production.", "Observability"),
        ],
    },
    "JavaScript": {
        "exts": [".js", ".mjs"],
        "rules": [
            (r"\beval\s*\(", "eval() can execute arbitrary code from strings.", "critical", "vulnerability", "Avoid eval() and prefer structured data handling.", "Code injection"),
            (r"\.innerHTML\s*=", "Assigning to innerHTML can expose the app to XSS.", "high", "vulnerability", "Use textContent or DOM APIs instead of innerHTML.", "Cross-site scripting"),
            (r"\bdocument\.write\s*\(", "document.write() is unsafe for dynamic content injection.", "medium", "vulnerability", "Prefer DOM manipulation libraries or safe insertion methods.", "Cross-site scripting"),
            (r"console\.log\s*\(", "A console.log() statement was left in the code.", "low", "review", "Remove debug logging before shipping production code.", "Maintainability"),
        ],
    },
    "Java": {
        "exts": [".java"],
        "rules": [
            (r"Runtime\.getRuntime\(\)\.exec", "Runtime.exec() allows command execution with possible injection risk.", "critical", "vulnerability", "Validate input and avoid direct command execution.", "Command injection"),
            (r"Statement\s+.*=\s*\".*\+", "SQL text appears to be built via string concatenation.", "high", "vulnerability", "Use PreparedStatement and parameterized queries.", "SQL injection"),
            (r"catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}", "An empty catch block can swallow important failures.", "medium", "review", "Log the exception or handle it explicitly.", "Error handling"),
        ],
    },
    "C/C++": {
        "exts": [".c", ".h", ".cpp", ".cc", ".hpp", ".cxx", ".hxx"],
        "rules": [
            (r"\bgets\s*\(", "gets() is unsafe and can overflow the destination buffer.", "critical", "vulnerability", "Use fgets() or a bounded input function.", "Buffer overflow"),
            (r"\bstrcpy\s*\(", "strcpy() is unsafe because it does not check bounds.", "critical", "vulnerability", "Use strncpy(), snprintf(), or std::string.", "Buffer overflow"),
            (r"\bsprintf\s*\(", "sprintf() may overflow the destination buffer.", "high", "vulnerability", "Prefer snprintf() or bounded APIs.", "Buffer overflow"),
            (r"\bsystem\s*\(", "Calling system() exposes command injection risks.", "high", "vulnerability", "Avoid shell execution and prefer direct APIs.", "Command injection"),
        ],
    },
    "HTML": {
        "exts": [".html", ".htm"],
        "rules": [
            (r"on\w+\s*=\s*[\"\']", "Inline event handlers can weaken CSP protections.", "medium", "vulnerability", "Move behavior to external scripts and sanitize inputs.", "Client-side security"),
            (r"<script\s+src", "An external script tag was detected; trust and integrity should be verified.", "medium", "review", "Use SRI and only include trusted scripts.", "Supply chain"),
            (r"<!--\s*TODO", "A TODO comment is present in HTML.", "low", "review", "Resolve or document outstanding work.", "Maintainability"),
        ],
    },
    "CSS": {
        "exts": [".css"],
        "rules": [
            (r"expression\s*\(", "CSS expressions are obsolete and risky in legacy browsers.", "medium", "vulnerability", "Avoid expression() and use modern CSS techniques.", "Legacy security"),
            (r"!important", "!important is used heavily; this can make styling harder to maintain.", "low", "review", "Use it sparingly and refactor when possible.", "Maintainability"),
        ],
    },
}


def detect_language(file_path: str, content: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    if ext in LANGUAGE_RULES:
        return ext
    if ".py" in ext:
        return "Python"
    if ext in {".php", ".phtml"}:
        return "PHP"
    if "<?php" in content or "<?=" in content:
        return "PHP"
    if "<script" in content.lower() or "</html" in content.lower():
        return "HTML"
    return "Unknown"


def normalize_severity(severity: str) -> str:
    mapping = {"critical": "critical", "error": "critical", "high": "high",
               "warning": "medium", "medium": "medium", "info": "low", "low": "low"}
    return mapping.get(severity.lower(), "low")


def smart_recommendation(message: str, language: str) -> str:
    message_lower = message.lower()
    if "eval" in message_lower or "exec" in message_lower:
        return "Replace dynamic execution with explicit logic and validated input."
    if "sql" in message_lower:
        return "Use parameterized queries and avoid concatenating user input."
    if "xss" in message_lower or "innerhtml" in message_lower:
        return "Escape or sanitize all user-controlled output before rendering it."
    if "secret" in message_lower or "key" in message_lower:
        return "Move secrets into environment variables or a dedicated secrets manager."
    if "command" in message_lower or "shell" in message_lower:
        return "Avoid passing untrusted input into shell commands."
    if language == "Python" and "debug" in message_lower:
        return "Disable debug mode in production and log safely."
    return "Review the context and apply the least-privilege fix."


class Finding(dict):
    pass


def analyze_file(file_path: str) -> List[Finding]:
    ext = os.path.splitext(file_path)[1].lower()
    issues: List[Finding] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
            lines = content.splitlines()
    except Exception as e:
        issues.append(Finding({
            "file": file_path,
            "line": 0,
            "type": "error",
            "severity": "critical",
            "message": f"Could not read file: {str(e)}",
            "code": "",
            "language": detect_language(file_path, ""),
            "category": "File access",
            "recommendation": "Confirm file readability and permissions.",
            "confidence": 95,
        }))
        return issues

    language = detect_language(file_path, content)
    if language == "Unknown":
        return []

    for lang_name, data in LANGUAGE_RULES.items():
        if language == lang_name or ext in data["exts"]:
            for pattern, msg, severity, issue_type, recommendation, category in data["rules"]:
                for line_no, line in enumerate(lines, start=1):
                    if re.search(pattern, line, re.IGNORECASE):
                        severity_value = normalize_severity(severity)
                        confidence = 90 if severity_value in {"critical", "high"} else 75
                        if "$_" in line or "request" in line.lower() or "user" in line.lower():
                            confidence += 5
                        if "TODO" in line:
                            confidence = max(60, confidence - 10)
                        issue = Finding({
                            "file": file_path,
                            "line": line_no,
                            "type": issue_type,
                            "severity": severity_value,
                            "message": msg,
                            "code": line.strip(),
                            "language": language,
                            "category": category,
                            "recommendation": recommendation or smart_recommendation(msg, language),
                            "confidence": confidence,
                        })
                        issues.append(issue)
            break

    if language == "Python":
        if re.search(r"\b(os|subprocess)\.(system|popen|call|Popen)\s*\(", content):
            issues.append(Finding({
                "file": file_path,
                "line": 1,
                "type": "vulnerability",
                "severity": "high",
                "message": "Command execution helpers were found; verify arguments and shell usage.",
                "code": "",
                "language": language,
                "category": "Command execution",
                "recommendation": "Avoid shell execution on untrusted input and prefer structured APIs.",
                "confidence": 82,
            }))

    deduped: List[Finding] = []
    seen = set()
    for issue in issues:
        key = (issue["file"], issue["line"], issue["message"], issue["type"])
        if key not in seen:
            seen.add(key)
            deduped.append(issue)
    return deduped


# =============================================================================
# Matrix Rain Background Animation
# =============================================================================

class MatrixRain(QGraphicsScene):
    """A QGraphicsScene that displays a Matrix‑style falling code rain."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.drops = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_rain)
        self.timer.start(50)  # 20 fps

        self.characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?/~"
        self.font = QFont("Consolas", 10, QFont.Bold)
        self.font.setStyleHint(QFont.Monospace)

        # We'll create drops on the fly as the scene resizes
        self.sceneRectChanged.connect(self.init_drops)

        self.setBackgroundBrush(QColor(8, 16, 24))  # dark background

    def init_drops(self):
        """Create drops to fill the scene."""
        rect = self.sceneRect()
        if rect.width() <= 0 or rect.height() <= 0:
            return
        # Number of columns based on font width
        fm = QFontMetrics(self.font)
        char_width = fm.horizontalAdvance("W")
        char_height = fm.height()
        cols = max(1, int(rect.width() / char_width))
        rows = max(1, int(rect.height() / char_height))

        # Clear existing drops
        for drop in self.drops:
            for item in drop["items"]:
                self.removeItem(item)
        self.drops = []

        # Create new drops
        for col in range(cols):
            speed = random.uniform(2, 6)
            length = random.randint(5, 15)
            # Start at random y position (off-screen or partly on)
            start_y = random.uniform(-rect.height(), 0)
            drop = {
                "col": col,
                "x": col * char_width + char_width/2,
                "y": start_y,
                "speed": speed,
                "length": length,
                "items": []
            }
            # Create text items for this drop (we'll update them later)
            for i in range(length):
                char = random.choice(self.characters)
                item = QGraphicsTextItem(char)
                item.setFont(self.font)
                item.setDefaultTextColor(QColor(0, 255, 200, 180 - i*12))
                # Position will be updated in update_rain
                item.setPos(drop["x"], drop["y"] - i * char_height)
                self.addItem(item)
                drop["items"].append(item)
            self.drops.append(drop)

    def update_rain(self):
        """Move drops down and reset when off‑screen."""
        rect = self.sceneRect()
        if rect.width() <= 0 or rect.height() <= 0:
            return
        fm = QFontMetrics(self.font)
        char_height = fm.height()

        for drop in self.drops:
            # Move down
            drop["y"] += drop["speed"]
            # Update positions of all characters in this drop
            for i, item in enumerate(drop["items"]):
                y_pos = drop["y"] - i * char_height
                item.setPos(drop["x"], y_pos)
                # Fade out characters that are too far off-screen
                alpha = max(0, min(255, 255 - (abs(y_pos) / rect.height()) * 255))
                color = QColor(0, 255, 200, int(alpha))
                item.setDefaultTextColor(color)

            # Reset drop if it has completely left the screen
            if drop["y"] > rect.height() + drop["length"] * char_height:
                drop["y"] = -random.randint(5, 30) * char_height
                drop["speed"] = random.uniform(2, 6)
                drop["length"] = random.randint(5, 15)
                # Recreate items with new length
                for item in drop["items"]:
                    self.removeItem(item)
                drop["items"] = []
                for i in range(drop["length"]):
                    char = random.choice(self.characters)
                    item = QGraphicsTextItem(char)
                    item.setFont(self.font)
                    item.setDefaultTextColor(QColor(0, 255, 200, 180 - i*12))
                    item.setPos(drop["x"], drop["y"] - i * char_height)
                    self.addItem(item)
                    drop["items"].append(item)


# =============================================================================
# Models
# =============================================================================

class FindingsModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._findings: List[Finding] = []
        self._headers = ["File", "Line", "Severity", "Message", "Language", "Category", "Confidence"]

    def rowCount(self, parent=QModelIndex()):
        return len(self._findings)

    def columnCount(self, parent=QModelIndex()):
        return len(self._headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        finding = self._findings[row]
        if role == Qt.DisplayRole:
            if col == 0:
                return finding["file"]
            elif col == 1:
                return str(finding["line"])
            elif col == 2:
                return finding["severity"].upper()
            elif col == 3:
                return finding["message"]
            elif col == 4:
                return finding["language"]
            elif col == 5:
                return finding["category"]
            elif col == 6:
                return f"{finding['confidence']}%"
        elif role == Qt.TextAlignmentRole:
            if col in (1, 2, 6):
                return Qt.AlignCenter
        elif role == Qt.ForegroundRole:
            sev = finding["severity"].lower()
            if sev == "critical":
                return QColor("#ff5c7a")
            elif sev == "high":
                return QColor("#ff8a5b")
            elif sev == "medium":
                return QColor("#ffb347")
            elif sev == "low":
                return QColor("#5bc0de")
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._headers[section]
        return None

    def add_finding(self, finding: Finding):
        self.beginInsertRows(QModelIndex(), self.rowCount(), self.rowCount())
        self._findings.append(finding)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._findings.clear()
        self.endResetModel()

    def get_finding(self, row: int) -> Optional[Finding]:
        if 0 <= row < len(self._findings):
            return self._findings[row]
        return None

    def get_all(self) -> List[Finding]:
        return self._findings[:]


class LanguageStatsModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._data: List[Tuple[str, int, int, int, int, int]] = []  # lang, total, critical, high, medium, low
        self._headers = ["Language", "Total", "Critical", "High", "Medium", "Low"]

    def update_from_findings(self, findings: List[Finding]):
        lang_counts = Counter(f["language"] for f in findings)
        sev_counts = {}
        for f in findings:
            lang = f["language"]
            sev = f["severity"]
            sev_counts.setdefault(lang, Counter())[sev] += 1

        rows = []
        for lang in sorted(lang_counts.keys()):
            total = lang_counts[lang]
            sev = sev_counts.get(lang, {})
            rows.append((
                lang,
                total,
                sev.get("critical", 0),
                sev.get("high", 0),
                sev.get("medium", 0),
                sev.get("low", 0)
            ))
        self.beginResetModel()
        self._data = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._data)

    def columnCount(self, parent=QModelIndex()):
        return len(self._headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        if role == Qt.DisplayRole:
            return str(self._data[row][col])
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._headers[section]
        return None

    def get_data(self):
        return self._data


# =============================================================================
# Scan Worker
# =============================================================================

class ScanWorker(QObject):
    progress = Signal(int, int)           # current, total
    finding_detected = Signal(dict)
    status_message = Signal(str)
    scan_finished = Signal()
    error_occurred = Signal(str)

    def __init__(self, folder: str):
        super().__init__()
        self.folder = folder
        self._is_running = True
        self._total_files = 0
        self._processed = 0

    def stop(self):
        self._is_running = False

    def run(self):
        try:
            all_files = []
            for root, dirs, files in os.walk(self.folder):
                dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
                for filename in files:
                    path = os.path.join(root, filename)
                    if os.path.isfile(path):
                        all_files.append(path)

            self._total_files = len(all_files)
            self.progress.emit(0, self._total_files)

            for idx, file_path in enumerate(all_files, 1):
                if not self._is_running:
                    break
                self.status_message.emit(f"Scanning: {os.path.basename(file_path)}")
                try:
                    issues = analyze_file(file_path)
                    for issue in issues:
                        self.finding_detected.emit(issue)
                except Exception as e:
                    self.error_occurred.emit(f"Error processing {file_path}: {str(e)}\n{traceback.format_exc()}")
                self._processed = idx
                self.progress.emit(idx, self._total_files)
                QThread.msleep(10)

            self.status_message.emit("Scan completed.")
        except Exception as e:
            self.error_occurred.emit(f"Fatal error: {str(e)}\n{traceback.format_exc()}")
        finally:
            self.scan_finished.emit()


# =============================================================================
# Proxy Model for Filtering
# =============================================================================

class FindingsProxyModel(QSortFilterProxyModel):
    def __init__(self, source_model):
        super().__init__()
        self.setSourceModel(source_model)
        self._search = ""
        self._severity = "all"
        self._language = "all"

    def set_search_pattern(self, pattern):
        self._search = pattern.lower()
        self.invalidateFilter()

    def set_severity_filter(self, severity):
        self._severity = severity
        self.invalidateFilter()

    def set_language_filter(self, language):
        self._language = language
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        finding = model.get_finding(source_row)
        if not finding:
            return False

        if self._severity != "all" and finding["severity"] != self._severity:
            return False

        if self._language != "all" and finding["language"] != self._language:
            return False

        if self._search:
            haystack = " ".join([
                finding["file"], str(finding["line"]), finding["message"],
                finding["category"], finding["language"]
            ]).lower()
            if self._search not in haystack:
                return False
        return True


# =============================================================================
# Dashboard Widget (Summary Cards + Language Bar Chart)
# =============================================================================

class DashboardWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        # Summary cards in a grid
        card_layout = QGridLayout()
        card_layout.setSpacing(15)

        self.total_label = self._create_card("Total Findings", "0", "#7fffd4")
        self.critical_label = self._create_card("Critical", "0", "#ff5c7a")
        self.high_label = self._create_card("High", "0", "#ff8a5b")
        self.medium_label = self._create_card("Medium", "0", "#ffb347")
        self.low_label = self._create_card("Low", "0", "#5bc0de")

        card_layout.addWidget(self.total_label, 0, 0)
        card_layout.addWidget(self.critical_label, 0, 1)
        card_layout.addWidget(self.high_label, 0, 2)
        card_layout.addWidget(self.medium_label, 0, 3)
        card_layout.addWidget(self.low_label, 0, 4)

        layout.addLayout(card_layout)

        # Language breakdown bar chart
        chart_group = QGroupBox("Findings by Language")
        chart_group.setStyleSheet("QGroupBox { color: #7fffd4; font-weight: bold; border: 1px solid #1a3a4a; border-radius: 6px; margin-top: 10px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        chart_layout = QVBoxLayout(chart_group)
        self.chart_widget = LanguageBarChart()
        chart_layout.addWidget(self.chart_widget)
        layout.addWidget(chart_group)

        layout.addStretch()

    def _create_card(self, title, value, color):
        widget = QFrame()
        widget.setStyleSheet(f"""
            QFrame {{
                background-color: #0d1720;
                border: 1px solid {color};
                border-radius: 8px;
                padding: 10px;
            }}
            QLabel {{
                color: #e8f6f3;
            }}
        """)
        layout = QVBoxLayout(widget)
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 14px; color: #a0c4e8;")
        value_label = QLabel(value)
        value_label.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")
        value_label.setObjectName("value")
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        return widget

    def update_dashboard(self, findings: List[Finding]):
        total = len(findings)
        sev_counts = Counter(f["severity"] for f in findings)

        self.total_label.findChild(QLabel, "value").setText(str(total))
        self.critical_label.findChild(QLabel, "value").setText(str(sev_counts.get("critical", 0)))
        self.high_label.findChild(QLabel, "value").setText(str(sev_counts.get("high", 0)))
        self.medium_label.findChild(QLabel, "value").setText(str(sev_counts.get("medium", 0)))
        self.low_label.findChild(QLabel, "value").setText(str(sev_counts.get("low", 0)))

        # Update bar chart
        lang_counts = Counter(f["language"] for f in findings)
        self.chart_widget.update_data(lang_counts)


class LanguageBarChart(QWidget):
    """A simple bar chart showing findings per language."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = {}
        self.setMinimumHeight(150)
        self.setStyleSheet("background-color: transparent;")

    def update_data(self, data: Counter):
        self.data = data
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = self.rect()
        if not self.data:
            painter.drawText(rect, Qt.AlignCenter, "No data")
            return

        # Margins
        left_margin = 40
        right_margin = 20
        top_margin = 20
        bottom_margin = 30
        chart_rect = rect.adjusted(left_margin, top_margin, -right_margin, -bottom_margin)

        # Colors for bars
        colors = ["#7fffd4", "#ff5c7a", "#ff8a5b", "#ffb347", "#5bc0de", "#a78bfa", "#f472b6", "#34d399"]

        # Sort languages by total
        items = sorted(self.data.items(), key=lambda x: x[1], reverse=True)
        max_value = max(self.data.values()) if self.data else 1

        bar_width = min(50, chart_rect.width() / len(items) * 0.6)
        spacing = chart_rect.width() / len(items) if len(items) > 0 else 1
        x_start = chart_rect.left()

        # Draw axes
        painter.setPen(QColor(100, 200, 255, 100))
        painter.drawLine(chart_rect.bottomLeft(), chart_rect.bottomRight())
        painter.drawLine(chart_rect.bottomLeft(), chart_rect.topLeft())

        for i, (lang, count) in enumerate(items):
            x = x_start + i * spacing + (spacing - bar_width) / 2
            height = (count / max_value) * chart_rect.height()
            y = chart_rect.bottom() - height

            # Draw bar
            color = colors[i % len(colors)]
            painter.setBrush(QColor(color))
            painter.setPen(Qt.NoPen)
            painter.drawRect(QRectF(x, y, bar_width, height))

            # Draw label (language name)
            painter.setPen(QColor("#e8f6f3"))
            font = painter.font()
            font.setPointSize(9)
            painter.setFont(font)
            painter.drawText(QRectF(x, chart_rect.bottom() + 5, bar_width, 20), Qt.AlignHCenter, lang[:4])

            # Draw count on top of bar
            if count > 0:
                painter.drawText(QRectF(x, y - 20, bar_width, 20), Qt.AlignHCenter, str(count))

        # Draw max value label on top-left
        painter.setPen(QColor("#7fffd4"))
        painter.drawText(QRectF(0, top_margin, left_margin - 5, 20), Qt.AlignRight | Qt.AlignTop, str(max_value))


# =============================================================================
# Main Window
# =============================================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ CYBER SCAN PROTOCOL v3.0 - J.A.R.V.I.S.")
        self.setMinimumSize(1300, 850)

        # Central widget: QGraphicsView with Matrix Rain background
        self.graphics_view = QGraphicsView()
        self.graphics_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.graphics_view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.graphics_view.setFrameShape(QFrame.NoFrame)
        self.graphics_view.setRenderHint(QPainter.Antialiasing)
        self.setCentralWidget(self.graphics_view)

        # Scene for background rain
        self.scene = MatrixRain()
        self.graphics_view.setScene(self.scene)

        # Create UI container as a QGraphicsProxyWidget
        self.ui_container = QWidget()
        self.ui_container.setAttribute(Qt.WA_TranslucentBackground)
        self.ui_container.setStyleSheet("background: transparent;")
        self.proxy = QGraphicsProxyWidget()
        self.proxy.setWidget(self.ui_container)
        self.proxy.setZValue(10)  # above rain
        self.scene.addItem(self.proxy)

        # Build UI inside ui_container
        self._setup_ui()
        self._setup_connections()
        self._status_bar()
        self._update_ui_state()

        # Initialize dashboard with empty data
        self.dashboard.update_dashboard([])

        # Resize proxy to match view
        self.graphics_view.resizeEvent = self._on_resize

        # Set initial size
        self._on_resize(None)

    def _on_resize(self, event):
        # Resize the proxy widget to fill the view
        view_rect = self.graphics_view.rect()
        self.proxy.setGeometry(QRectF(0, 0, view_rect.width(), view_rect.height()))
        self.ui_container.resize(view_rect.width(), view_rect.height())

        # Update rain scene rect
        self.scene.setSceneRect(0, 0, view_rect.width(), view_rect.height())
        self.scene.init_drops()

    def _setup_ui(self):
        layout = QVBoxLayout(self.ui_container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Toolbar
        self._create_toolbar(layout)

        # Main content: splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: #1a3a4a; width: 2px; }")
        layout.addWidget(splitter)

        # Left: Findings tree with filters
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Filters
        filter_layout = QHBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍 Search findings...")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.setStyleSheet("background-color: #0d1720; color: #e8f6f3; border: 1px solid #1a3a4a; border-radius: 4px; padding: 6px 10px;")
        filter_layout.addWidget(self.search_box)

        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_combo.setStyleSheet("background-color: #0d1720; color: #e8f6f3; border: 1px solid #1a3a4a; border-radius: 4px; padding: 6px;")
        filter_layout.addWidget(QLabel("Severity:"))
        filter_layout.addWidget(self.severity_combo)

        self.language_combo = QComboBox()
        self.language_combo.addItems(["All"] + list(LANGUAGE_RULES.keys()))
        self.language_combo.setStyleSheet("background-color: #0d1720; color: #e8f6f3; border: 1px solid #1a3a4a; border-radius: 4px; padding: 6px;")
        filter_layout.addWidget(QLabel("Language:"))
        filter_layout.addWidget(self.language_combo)

        left_layout.addLayout(filter_layout)

        self.findings_view = QTreeView()
        self.findings_view.setAlternatingRowColors(True)
        self.findings_view.setSortingEnabled(True)
        self.findings_view.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.findings_view.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self.findings_view.setSelectionBehavior(QTreeView.SelectRows)
        self.findings_view.setStyleSheet("QTreeView::item { padding: 6px; }")
        left_layout.addWidget(self.findings_view)

        splitter.addWidget(left_widget)

        # Right: Tabs (Details, Language Stats, Dashboard)
        right_tabs = QTabWidget()
        right_tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #1a3a4a; background-color: #0d1720; }
            QTabBar::tab { background-color: #13212e; color: #a0c4e8; padding: 8px 16px; border: 1px solid #1a3a4a; border-bottom: none; border-top-left-radius: 4px; border-top-right-radius: 4px; font-weight: bold; }
            QTabBar::tab:selected { background-color: #0d1720; color: #7fffd4; }
            QTabBar::tab:hover { background-color: #1a3a4a; }
        """)

        # Details tab
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setPlaceholderText("Select a finding to see details...")
        self.detail_text.setStyleSheet("background-color: #0d1720; color: #e8f6f3; border: 1px solid #1a3a4a; border-radius: 4px; font-size: 14px;")
        details_layout.addWidget(QLabel("Issue Details"))
        details_layout.addWidget(self.detail_text)

        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setPlaceholderText("Code preview will appear here...")
        self.preview_text.setFont(QFont("Courier New", 12))
        self.preview_text.setStyleSheet("background-color: #0d1720; color: #e8f6f3; border: 1px solid #1a3a4a; border-radius: 4px;")
        details_layout.addWidget(QLabel("Code Preview"))
        details_layout.addWidget(self.preview_text)

        right_tabs.addTab(details_widget, "🔍 Details")

        # Language stats tab
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        self.stats_view = QTreeView()
        self.stats_view.setAlternatingRowColors(True)
        self.stats_view.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.stats_view.setStyleSheet("background-color: #0d1720; color: #e8f6f3; border: 1px solid #1a3a4a;")
        stats_layout.addWidget(QLabel("Findings per Language & Severity"))
        stats_layout.addWidget(self.stats_view)
        right_tabs.addTab(stats_widget, "📊 Language Stats")

        # Dashboard tab
        self.dashboard = DashboardWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.dashboard)
        scroll.setStyleSheet("background-color: transparent; border: none;")
        right_tabs.addTab(scroll, "📈 Dashboard")

        splitter.addWidget(right_tabs)
        splitter.setSizes([600, 400])

        # Progress bar and status
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("QProgressBar { background-color: #0d1720; border: 1px solid #1a3a4a; border-radius: 4px; height: 22px; color: #e8f6f3; } QProgressBar::chunk { background-color: #7fffd4; border-radius: 4px; }")
        progress_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #7fffd4; font-size: 14px; font-weight: bold;")
        progress_layout.addWidget(self.status_label)

        layout.addLayout(progress_layout)

        # Set models
        self.findings_model = FindingsModel()
        self.proxy_model = FindingsProxyModel(self.findings_model)
        self.findings_view.setModel(self.proxy_model)
        self.language_model = LanguageStatsModel()
        self.stats_view.setModel(self.language_model)

        # Register global shortcuts
        self.fullscreen_action = QAction("Full Screen", self, checkable=True, triggered=self.toggle_fullscreen)
        self.fullscreen_action.setShortcut(QKeySequence("F11"))
        self.addAction(self.fullscreen_action)

        # Store references
        self.scan_folder = ""
        self.worker_thread = None
        self.scanning = False

    def _create_toolbar(self, parent_layout):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setStyleSheet("""
            QToolBar { background-color: #0d1720; border: none; spacing: 10px; padding: 5px; }
            QToolButton { background-color: transparent; border: none; padding: 8px 14px; font-size: 14px; font-weight: bold; color: #7fffd4; }
            QToolButton:hover { background-color: #1a3a4a; border-radius: 4px; }
            QToolButton:pressed { background-color: #0a1a22; }
        """)
        parent_layout.insertWidget(0, toolbar)

        self.browse_action = QAction("📁 Browse", self)
        toolbar.addAction(self.browse_action)

        self.scan_action = QAction("▶ Scan", self)
        toolbar.addAction(self.scan_action)

        self.stop_action = QAction("⏹ Abort", self)
        self.stop_action.setEnabled(False)
        toolbar.addAction(self.stop_action)

        self.export_action = QAction("📄 Export HTML", self)
        self.export_action.setEnabled(False)
        toolbar.addAction(self.export_action)

        toolbar.addSeparator()

        self.fullscreen_toggle = QAction("⛶ Full Screen", self, checkable=True, triggered=self.toggle_fullscreen)
        toolbar.addAction(self.fullscreen_toggle)

        toolbar.addSeparator()

        # Spacer to push following items to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(spacer)

        self.folder_label = QLabel("Target: ")
        self.folder_label.setStyleSheet("color: #7fffd4; font-weight: bold; font-size: 14px;")
        toolbar.addWidget(self.folder_label)
        self.folder_path_label = QLabel("Not selected")
        self.folder_path_label.setStyleSheet("color: #a0c4e8; font-size: 14px;")
        toolbar.addWidget(self.folder_path_label)

        self.file_count_label = QLabel("Files: 0")
        self.file_count_label.setStyleSheet("color: #a0c4e8; font-size: 13px;")
        toolbar.addWidget(self.file_count_label)

    def _setup_connections(self):
        self.browse_action.triggered.connect(self.browse_folder)
        self.scan_action.triggered.connect(self.start_scan)
        self.stop_action.triggered.connect(self.stop_scan)
        self.export_action.triggered.connect(self.export_html)
        self.findings_view.selectionModel().selectionChanged.connect(self.on_finding_selected)
        self.search_box.textChanged.connect(self._apply_filters)
        self.severity_combo.currentTextChanged.connect(self._apply_filters)
        self.language_combo.currentTextChanged.connect(self._apply_filters)

    def _status_bar(self):
        self.statusBar().showMessage("Welcome to CyberScan Pro")
        self.statusBar().setStyleSheet("background-color: #081018; color: #7fffd4;")

    def _update_ui_state(self):
        scanning = self.scanning
        self.scan_action.setEnabled(not scanning and bool(self.scan_folder))
        self.stop_action.setEnabled(scanning)
        self.browse_action.setEnabled(not scanning)
        self.export_action.setEnabled(not scanning and self.findings_model.rowCount() > 0)

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Target Directory")
        if folder:
            self.scan_folder = folder
            self.folder_path_label.setText(folder)
            self.statusBar().showMessage(f"Selected: {folder}")
            self._update_ui_state()

    def start_scan(self):
        if not self.scan_folder or not os.path.isdir(self.scan_folder):
            QMessageBox.warning(self, "Invalid Directory", "Please select a valid target directory.")
            return

        self.findings_model.clear()
        self.language_model.update_from_findings([])
        self.dashboard.update_dashboard([])
        self.detail_text.clear()
        self.preview_text.clear()
        self.progress_bar.setValue(0)
        self.export_action.setEnabled(False)
        self.file_count_label.setText("Files: 0")

        self.scanning = True
        self._update_ui_state()
        self.statusBar().showMessage("Scanning in progress...")

        self.worker_thread = QThread()
        self.worker = ScanWorker(self.scan_folder)
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.finding_detected.connect(self._on_finding)
        self.worker.status_message.connect(lambda msg: self.statusBar().showMessage(msg))
        self.worker.error_occurred.connect(self._on_error)
        self.worker.scan_finished.connect(self._on_scan_finished)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.worker_thread.start()

    def stop_scan(self):
        if self.worker and self.scanning:
            self.worker.stop()
            self.statusBar().showMessage("Aborting scan...")
        self._update_ui_state()

    def _on_progress(self, current, total):
        if total > 0:
            percent = int((current / total) * 100)
            self.progress_bar.setValue(percent)
            self.status_label.setText(f"Files: {current}/{total}")
            self.file_count_label.setText(f"Files: {current}")
        else:
            self.progress_bar.setValue(0)
            self.status_label.setText("Preparing...")

    def _on_finding(self, finding: Finding):
        self.findings_model.add_finding(finding)
        self.language_model.update_from_findings(self.findings_model.get_all())
        self.dashboard.update_dashboard(self.findings_model.get_all())
        self.export_action.setEnabled(True)

    def _on_error(self, error_msg):
        self.statusBar().showMessage("Error occurred (see details)")

    def _on_scan_finished(self):
        self.scanning = False
        self.worker_thread.quit()
        self.worker_thread.wait()
        self.worker = None
        self.worker_thread = None
        self.progress_bar.setValue(100)
        self.status_label.setText("Scan complete")
        self.statusBar().showMessage("Scan finished")
        self._update_ui_state()
        self._update_summary()
        self.file_count_label.setText(f"Files: {self.findings_model.rowCount()}")

    def _update_summary(self):
        total = self.findings_model.rowCount()
        if total == 0:
            self.statusBar().showMessage("Scan complete: no issues detected.")
        else:
            sev_counts = Counter(f["severity"] for f in self.findings_model.get_all())
            msg = f"Total findings: {total} | Critical: {sev_counts.get('critical', 0)} | High: {sev_counts.get('high', 0)} | Medium: {sev_counts.get('medium', 0)} | Low: {sev_counts.get('low', 0)}"
            self.statusBar().showMessage(msg)

    def on_finding_selected(self, selected, deselected):
        indexes = selected.indexes()
        if not indexes:
            self.detail_text.clear()
            self.preview_text.clear()
            return
        row = indexes[0].row()
        # Map through proxy model
        source_row = self.proxy_model.mapToSource(self.proxy_model.index(row, 0)).row()
        finding = self.findings_model.get_finding(source_row)
        if not finding:
            return

        detail = (
            f"File: {finding['file']}\n"
            f"Line: {finding['line']}\n"
            f"Severity: {finding['severity'].upper()}\n"
            f"Category: {finding['category']}\n"
            f"Type: {finding['type'].upper()}\n"
            f"Confidence: {finding['confidence']}%\n"
            f"Language: {finding['language']}\n\n"
            f"Message: {finding['message']}\n\n"
            f"Recommendation: {finding['recommendation']}"
        )
        self.detail_text.setText(detail)

        try:
            with open(finding['file'], 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            line_no = finding['line']
            start = max(0, line_no - 3)
            end = min(len(lines), line_no + 2)
            preview = ''.join(f"{i+1}: {lines[i]}" for i in range(start, end))
            self.preview_text.setText(preview)
        except Exception:
            self.preview_text.setText("Preview unavailable")

    def _apply_filters(self):
        self.proxy_model.set_search_pattern(self.search_box.text())
        self.proxy_model.set_severity_filter(self.severity_combo.currentText().lower())
        self.proxy_model.set_language_filter(self.language_combo.currentText())

    def toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
            self.fullscreen_toggle.setChecked(False)
        else:
            self.showFullScreen()
            self.fullscreen_toggle.setChecked(True)

    def export_html(self):
        if self.findings_model.rowCount() == 0:
            QMessageBox.information(self, "No Data", "No findings to export.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"cyberscan_report_{timestamp}.html"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report", default_name, "HTML Files (*.html)"
        )
        if not file_path:
            return

        try:
            self._generate_html_report(file_path)
            QMessageBox.information(self, "Export Successful", f"Report saved to:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Error: {str(e)}")

    def _generate_html_report(self, file_path: str):
        findings = self.findings_model.get_all()
        lang_sev = {}
        for f in findings:
            lang = f["language"]
            sev = f["severity"]
            lang_sev.setdefault(lang, {}).setdefault(sev, 0)
            lang_sev[lang][sev] += 1

        sev_total = Counter(f["severity"] for f in findings)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CyberScan Pro Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap');
        body {{
            background: #0a0f1a;
            color: #e0f2fe;
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            margin: 40px;
            line-height: 1.5;
            background-image: radial-gradient(circle at 10% 20%, rgba(0,255,200,0.03) 0%, transparent 50%);
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(13, 23, 32, 0.9);
            padding: 30px;
            border-radius: 16px;
            border: 1px solid #1a3a4a;
            box-shadow: 0 0 60px rgba(0, 255, 200, 0.15);
            backdrop-filter: blur(4px);
        }}
        h1 {{
            color: #7fffd4;
            font-family: 'Orbitron', sans-serif;
            font-size: 3.2rem;
            border-bottom: 2px solid #1a3a4a;
            padding-bottom: 15px;
            text-shadow: 0 0 30px rgba(127, 255, 212, 0.4);
            letter-spacing: 2px;
        }}
        .summary {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            background: #0d1720;
            padding: 20px;
            border-radius: 12px;
            border: 1px solid #1a3a4a;
            margin: 20px 0;
        }}
        .summary-item {{
            background: #13212e;
            padding: 12px 30px;
            border-radius: 8px;
            border-left: 4px solid #7fffd4;
            flex: 1 1 auto;
            min-width: 100px;
        }}
        .summary-item .label {{
            color: #a0c4e8;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .summary-item .value {{
            font-size: 2.2rem;
            font-weight: bold;
            color: #e8f6f3;
        }}
        .badge-critical {{ background: #ff5c7a; color: #fff; padding: 4px 10px; border-radius: 12px; }}
        .badge-high {{ background: #ff8a5b; color: #fff; padding: 4px 10px; border-radius: 12px; }}
        .badge-medium {{ background: #ffb347; color: #000; padding: 4px 10px; border-radius: 12px; }}
        .badge-low {{ background: #5bc0de; color: #000; padding: 4px 10px; border-radius: 12px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }}
        th, td {{
            padding: 12px 14px;
            border: 1px solid #1a3a4a;
            text-align: left;
        }}
        th {{
            background: #13212e;
            color: #7fffd4;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        tr:nth-child(even) {{ background: #0d1720; }}
        tr:hover {{ background: #1a2a3a; }}
        .severity-cell {{
            font-weight: bold;
            text-align: center;
        }}
        .footer {{
            margin-top: 40px;
            color: #4a6a7a;
            font-size: 0.9rem;
            text-align: center;
            border-top: 1px solid #1a3a4a;
            padding-top: 20px;
        }}
        .glow {{ text-shadow: 0 0 12px currentColor; }}
        .language-badge {{
            display: inline-block;
            background: #1a3a4a;
            padding: 2px 12px;
            border-radius: 12px;
            color: #7fffd4;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ CyberScan Pro – Security Report</h1>
        <p><strong>Target:</strong> {self.scan_folder}</p>
        <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>

        <div class="summary">
            <div class="summary-item"><span class="label">Critical</span><br><span class="value" style="color:#ff5c7a;">{sev_total.get('critical',0)}</span></div>
            <div class="summary-item"><span class="label">High</span><br><span class="value" style="color:#ff8a5b;">{sev_total.get('high',0)}</span></div>
            <div class="summary-item"><span class="label">Medium</span><br><span class="value" style="color:#ffb347;">{sev_total.get('medium',0)}</span></div>
            <div class="summary-item"><span class="label">Low</span><br><span class="value" style="color:#5bc0de;">{sev_total.get('low',0)}</span></div>
        </div>

        <h2>📊 Findings by Language</h2>
        <table>
            <tr><th>Language</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>
"""
        for lang, sev_dict in lang_sev.items():
            total = sum(sev_dict.values())
            html += f"<tr><td><span class='language-badge'>{lang}</span></td><td>{sev_dict.get('critical',0)}</td><td>{sev_dict.get('high',0)}</td><td>{sev_dict.get('medium',0)}</td><td>{sev_dict.get('low',0)}</td><td><strong>{total}</strong></td></tr>"

        html += """
        </table>

        <h2>🔍 Detailed Findings</h2>
        <table>
            <tr><th>File</th><th>Line</th><th>Severity</th><th>Message</th><th>Language</th><th>Category</th><th>Recommendation</th></tr>
"""
        for f in findings:
            sev = f['severity'].upper()
            html += f"""<tr>
                <td>{f['file']}</td>
                <td style="text-align:center;">{f['line']}</td>
                <td class="severity-cell"><span class="badge-{f['severity']}">{sev}</span></td>
                <td>{f['message']}</td>
                <td>{f['language']}</td>
                <td>{f['category']}</td>
                <td>{f['recommendation']}</td>
            </tr>"""

        html += f"""
        </table>
        <div class="footer">Generated by CyberScan Pro • J.A.R.V.I.S. v3.0 • Matrix Rain Edition</div>
    </div>
</body>
</html>
"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)


# =============================================================================
# Main
# =============================================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()